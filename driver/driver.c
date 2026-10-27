#include "msmon.h"
#include <wdmsec.h>

static const GUID MSMON_DEVICE_GUID = { 0xdb6a8ad5, 0xc08e, 0x4f95, { 0x8d, 0x15, 0x11, 0x5a, 0x72, 0x13, 0x6d, 0x40 } };

static NTSTATUS MsMonCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS MsMonStartSession(PMSMON_SESSION_CONFIG Config)
{
    UNICODE_STRING root;
    NTSTATUS status;
    SIZE_T length = wcsnlen(Config->ClientRoot, MSMON_CLIENT_PATH_CHARS);
    if (length == 0 || length == MSMON_CLIENT_PATH_CHARS) return STATUS_INVALID_PARAMETER;
    root.Buffer = Config->ClientRoot;
    root.Length = (USHORT)(length * sizeof(WCHAR));
    root.MaximumLength = root.Length;
    MsMonProcessStopSession();
    MsMonEventsStop();
    status = MsMonEventsStart(Config->SessionId, Config->QueueRecords, Config->QueueBytes, Config->PayloadMode);
    if (!NT_SUCCESS(status)) return status;
    status = MsMonProcessStartSession(&root);
    if (!NT_SUCCESS(status)) MsMonEventsStop();
    return status;
}

static NTSTATUS MsMonDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);
    switch (code) {
    case MSMON_IOCTL_START_SESSION:
        if (inputLength < sizeof(MSMON_SESSION_CONFIG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = MsMonStartSession((PMSMON_SESSION_CONFIG)Irp->AssociatedIrp.SystemBuffer);
        break;
    case MSMON_IOCTL_STOP_SESSION:
        MsMonProcessStopSession();
        MsMonEventsStop();
        status = STATUS_SUCCESS;
        break;
    case MSMON_IOCTL_STOP_TRACKING:
        MsMonProcessStopSession();
        status = STATUS_SUCCESS;
        break;
    case MSMON_IOCTL_TRACK_PID: {
        PMSMON_TRACK_REQUEST request = (PMSMON_TRACK_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        if (inputLength < sizeof(*request)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = MsMonTrackProcess(UlongToHandle(request->ProcessId),
                                   request->Flags != 0 ? request->Flags : MsMonFlagExplicitTrack);
        if (NT_SUCCESS(status)) {
            (VOID)MsMonLogEvent(MsMonProcessStart, UlongToHandle(request->ProcessId), NULL, NULL,
                                NULL, 0, request->Flags, STATUS_SUCCESS, 0,
                                MsMonCategoryExternalProcess, request->ProcessStartTime, 0, NULL, NULL);
        }
        break;
    }
    case MSMON_IOCTL_READ_EVENTS: {
        PMSMON_READ_REQUEST request = (PMSMON_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        ULONG maximum = min(outputLength, MSMON_READ_MAX_BYTES);
        ULONG timeout = 500;
        ULONG bytes = 0;
        if (inputLength >= sizeof(*request)) timeout = request->TimeoutMilliseconds;
        if (timeout > 1000) timeout = 1000;
        if (maximum < MSMON_MAX_EVENT_RECORD_BYTES) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = MsMonReadEvents(Irp->AssociatedIrp.SystemBuffer, maximum, timeout, &bytes);
        information = bytes;
        break;
    }
    case MSMON_IOCTL_STATISTICS:
        if (outputLength < sizeof(MSMON_STATISTICS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        MsMonGetStatistics((PMSMON_STATISTICS)Irp->AssociatedIrp.SystemBuffer);
        information = sizeof(MSMON_STATISTICS);
        status = STATUS_SUCCESS;
        break;
    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID MsMonDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING dosName;
    MsMonNetworkUninitialize();
    MsMonRegistryUninitialize();
    MsMonFileFilterUninitialize();
    MsMonObjectUninitialize();
    MsMonProcessUninitialize();
    MsMonEventsUninitialize();
    RtlInitUnicodeString(&dosName, MSMON_DOS_DEVICE_NAME);
    (VOID)IoDeleteSymbolicLink(&dosName);
    if (DriverObject->DeviceObject != NULL) IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING dosName;
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = MsMonDriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = MsMonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = MsMonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MsMonDeviceControl;

    RtlInitUnicodeString(&deviceName, MSMON_DEVICE_NAME);
    RtlInitUnicodeString(&dosName, MSMON_DOS_DEVICE_NAME);
    status = IoCreateDeviceSecure(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN, FALSE,
                                  &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
                                  &MSMON_DEVICE_GUID, &deviceObject);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&dosName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    status = MsMonEventsInitialize();
    if (NT_SUCCESS(status)) status = MsMonProcessInitialize();
    if (NT_SUCCESS(status)) status = MsMonObjectInitialize(DriverObject);
    if (NT_SUCCESS(status)) status = MsMonFileFilterInitialize(DriverObject);
    if (NT_SUCCESS(status)) status = MsMonRegistryInitialize(DriverObject);
    if (NT_SUCCESS(status)) status = MsMonNetworkInitialize(deviceObject);
    if (!NT_SUCCESS(status)) {
        MsMonNetworkUninitialize();
        MsMonRegistryUninitialize();
        MsMonFileFilterUninitialize();
        MsMonObjectUninitialize();
        MsMonProcessUninitialize();
        MsMonEventsUninitialize();
        (VOID)IoDeleteSymbolicLink(&dosName);
        IoDeleteDevice(deviceObject);
        return status;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
