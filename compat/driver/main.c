/*
 * main.c - DriverEntry and control device for the monitoring driver.
 *
 * This is the observation half of the original combined driver: syscall
 * tracing, the event ring, the summary table and the access guard.  The
 * identity half (registry/BIOS/disk/volume rewriting) is a separate image in
 * the sysinfo repository, and the two communicate with nothing but shared
 * knowledge of the event format - there is no link-time dependency either way.
 *
 * Device and service are named SysInfoMon so both drivers can be loaded at
 * once.  Control is over IOCTL only; this driver persists no configuration of
 * its own.
 */
#include <ntddk.h>
#include <wdmsec.h>
#include <sddl.h>
#include "../shared/sysinfo.h"
#include "hooks.h"
#include "syscall.h"
#include "monitor.h"
#include "trace.h"
#include "guard.h"

#define MON_TAG 'nMoM'
static const GUID MON_DEVICE_GUID = { 0x6f55f21a, 0x7a47, 0x4f5a, { 0x9a, 0x7e, 0x45, 0x11, 0xab, 0x32, 0x81, 0x99 } };

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DriverUnload;

static PDEVICE_OBJECT g_Device;
static UNICODE_STRING g_DeviceName;
static UNICODE_STRING g_SymLink;
static ULONG          g_FlagsAtEntry;
static volatile LONG  g_Stopped;

/* -------------------------------------------------------------- control device */

static NTSTATUS
DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
DispatchPass(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS
DispatchControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG    code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG    inLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG    outLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID    buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG    information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (code) {
    case SYSINFO_IOCTL_STATUS: {
        PSYSINFO_STATUS out = (PSYSINFO_STATUS)buffer;

        if (out == NULL || outLength < sizeof(SYSINFO_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlZeroMemory(out, sizeof(SYSINFO_STATUS));
        out->AbiVersion = SYSINFO_ABI_VERSION;
        out->HooksInstalled = TraceHookCount();
        out->HasConfig = 0;                       /* no identity config here */
        out->CiOptions = SysinfoCiOptions();
        out->HvciEnforced = SysinfoHvciEnforced() ? 1u : 0u;
        out->CetEnabled = SysinfoCetEnabled() ? 1u : 0u;
        out->PatchMethod = SysinfoPatchMethod();
        out->UnsafeHooksImplemented = 1;
        out->UnsafeHooksEnabled = TraceUnsafeHooksEnabled() ? 1u : 0u;
        out->Reserved = SysinfoSyscallCalibrated() ? 1u : 0u;

        MonDiag(out->Diag);
        out->Diag[SYSINFO_DIAG_TRACE_HOOKS] = TraceHookCount();

        information = sizeof(SYSINFO_STATUS);
        status = STATUS_SUCCESS;
        break;
    }

    case SYSINFO_IOCTL_MON_CONFIG:
        if (buffer == NULL || inLength < sizeof(SYSINFO_MON_CONFIG)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = MonConfigure((PSYSINFO_MON_CONFIG)buffer);
        break;

    case SYSINFO_IOCTL_MON_READ:
        status = MonRead(buffer, outLength);
        if (NT_SUCCESS(status)) information = outLength;
        break;

    case SYSINFO_IOCTL_MON_SUMMARY:
        status = MonSummary(buffer, inLength, buffer, outLength);
        if (NT_SUCCESS(status)) information = outLength;
        break;

    case SYSINFO_IOCTL_GUARD_CONFIG:
        if (buffer == NULL || inLength < sizeof(SYSINFO_GUARD_CONFIG)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = GuardConfigure((PSYSINFO_GUARD_CONFIG)buffer);
        break;

    case SYSINFO_IOCTL_GUARD_STATUS:
        if (buffer == NULL || outLength < sizeof(SYSINFO_GUARD_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = GuardGetStatus((PSYSINFO_GUARD_STATUS)buffer);
        if (NT_SUCCESS(status)) information = sizeof(SYSINFO_GUARD_STATUS);
        break;

    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ---------------------------------------------------------------- entry/exit */

/*
 * Restore every patched byte, then wait for the detours that were already in
 * flight before freeing anything they read.  Same ordering rule as the
 * identity driver: restore -> quiesce -> free.
 */
static VOID
MonitorStopHooks(VOID)
{
    LARGE_INTEGER delay;

    if (InterlockedCompareExchange(&g_Stopped, 1, 0) != 0) return;

    GuardShutdown();
    TraceShutdown();

    HookQuiesce(15000);
    delay.QuadPart = -5000000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    MonShutdown();
}

static NTSTATUS
DispatchShutdown(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    /* Do not unload at shutdown: Windows calls DriverUnload while threads may
     * still be inside a detour.  Keeping the image mapped until halt is the
     * lesser evil; `sc stop` still goes through DriverUnload with a quiesce. */
    if (DeviceObject != NULL && DeviceObject->DriverObject != NULL) {
        DeviceObject->DriverObject->DriverUnload = NULL;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&g_DeviceName, SYSINFO_DEVICE_NAME);
    RtlInitUnicodeString(&g_SymLink, SYSINFO_DOS_NAME);

    DriverObject->DriverUnload = DriverUnload;

    g_FlagsAtEntry = DriverObject->Flags;
    DriverObject->Flags |= DRVO_LEGACY_DRIVER;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = DispatchPass;
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = DispatchShutdown;

    status = IoCreateDeviceSecure(DriverObject, 0, &g_DeviceName, FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN, FALSE,
                                  &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
                                  &MON_DEVICE_GUID, &g_Device);
    if (!NT_SUCCESS(status)) return status;
    g_Device->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&g_SymLink, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_Device);
        return status;
    }

    g_Device->Flags &= ~DO_DEVICE_INITIALIZING;
    if (!NT_SUCCESS(IoRegisterShutdownNotification(g_Device))) {
        DbgPrint("SysInfoMon: shutdown notification failed\n");
    }

    GuardInit();
    MonInit();
    TraceInit();

    DbgPrint("SysInfoMon: DriverEntry hooks=%lu\n", TraceHookCount());
    return STATUS_SUCCESS;
}

VOID
DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    MonitorStopHooks();

    if (g_Device != NULL) {
        IoUnregisterShutdownNotification(g_Device);
        IoDeleteSymbolicLink(&g_SymLink);
        IoDeleteDevice(g_Device);
        g_Device = NULL;
    }
    DbgPrint("SysInfoMon: unloaded\n");
}
