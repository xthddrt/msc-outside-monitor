/*
 * trace.c - the syscall-level part of the activity monitor.
 *
 * monitor.c records what the kernel tells us for free (image loads, process and
 * thread creation) plus the operations the spoofing hooks already see.  This
 * file adds the operations a program is most likely to be judged by:
 *
 *   FILE  - NtCreateFile            (what it opens/creates, and how)
 *   KEY   - NtOpenKey/CreateKey/SetValueKey/DeleteValueKey/DeleteKey
 *   MEM   - NtProtectVirtualMemory / NtMapViewOfSection / NtCreateSection
 *   KCB   - PsSet*NotifyRoutine, ObRegisterCallbacks, CmRegisterCallbackEx
 *           (the kernel callbacks another driver installs - its defences)
 *   DEV   - IoCreateDevice          (the device its user-mode part talks to)
 *
 * Every event goes through MonEvent(), so it carries the caller's PID/image and
 * the "[kernel]" marker plus caller address when the call came from a driver.
 *
 * The hooks are inert (one call through the trampoline) until `mon on`.
 */
#include "trace.h"
#include "monitor.h"
#include "hooks.h"
#include "syscall.h"
#include "guard.h"
#include "util.h"
#include "../shared/sysinfo.h"

/* PatchGuard (0x109, type 1) caught nt!PsSetCreateProcessNotifyRoutineEx and
 * nt!NtOpenThread on this machine.  The extended monitor is therefore compiled
 * but not armed: the four spoofing detours and the notification callbacks patch
 * nothing.  Set to 1 for a bounded debugging session, at your own risk. */
/* Monitoring detours are OFF in the shipping build.
 *
 * PatchGuard caught three of them on this machine (KeStackAttachProcess,
 * NtSetInformationFile, PsSetCreateThreadNotifyRoutine).  A detour is an
 * unvalidated bet on an undocumented list, and the cost of losing is a bugcheck
 * on a machine that is being used.  Set to 1 only for a short, supervised
 * monitoring session. */
#ifndef SYSINFO_ENABLE_TRACE_HOOKS
#define SYSINFO_ENABLE_TRACE_HOOKS 1
#endif

static volatile LONG g_UnsafeHooksEnabled;

/* --------------------------------------------------------------- prototypes */

typedef NTSTATUS (NTAPI *PFN_NtCreateFile)(
    _Out_ PHANDLE, _In_ ACCESS_MASK, _In_ POBJECT_ATTRIBUTES, _Out_ PIO_STATUS_BLOCK,
    _In_opt_ PLARGE_INTEGER, _In_ ULONG, _In_ ULONG, _In_ ULONG, _In_ ULONG,
    _In_opt_ PVOID, _In_ ULONG);
typedef NTSTATUS (NTAPI *PFN_NtOpenKey)(
    _Out_ PHANDLE, _In_ ACCESS_MASK, _In_ POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_NtOpenKeyEx)(
    _Out_ PHANDLE, _In_ ACCESS_MASK, _In_ POBJECT_ATTRIBUTES, _In_ ULONG);
typedef NTSTATUS (NTAPI *PFN_NtCreateKey)(
    _Out_ PHANDLE, _In_ ACCESS_MASK, _In_ POBJECT_ATTRIBUTES, _In_ ULONG,
    _In_opt_ PUNICODE_STRING, _In_ ULONG, _Out_opt_ PULONG);
typedef NTSTATUS (NTAPI *PFN_NtSetValueKey)(
    _In_ HANDLE, _In_opt_ PUNICODE_STRING, _In_ ULONG, _In_ ULONG, _In_opt_ PVOID, _In_ ULONG);
typedef NTSTATUS (NTAPI *PFN_NtDeleteValueKey)(
    _In_ HANDLE, _In_opt_ PUNICODE_STRING);
typedef NTSTATUS (NTAPI *PFN_NtDeleteKey)(_In_ HANDLE);
typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(
    _In_ HANDLE, _Inout_ PVOID *, _Inout_ PSIZE_T, _In_ ULONG, _Out_opt_ PULONG);
typedef NTSTATUS (NTAPI *PFN_NtMapViewOfSection)(
    _In_ HANDLE, _In_ HANDLE, _Inout_ PVOID *, _In_ ULONG_PTR, _In_ SIZE_T,
    _In_opt_ PLARGE_INTEGER, _Inout_ PSIZE_T, _In_ ULONG, _In_ ULONG, _In_ ULONG);
typedef NTSTATUS (NTAPI *PFN_NtReadVirtualMemory)(
    _In_ HANDLE, _In_ PVOID, _Out_ PVOID, _In_ SIZE_T, _Out_opt_ PSIZE_T);
typedef NTSTATUS (NTAPI *PFN_NtWriteVirtualMemory)(
    _In_ HANDLE, _In_ PVOID, _In_ PVOID, _In_ SIZE_T, _Out_opt_ PSIZE_T);
typedef NTSTATUS (NTAPI *PFN_NtCreateSection)(
    _Out_ PHANDLE, _In_ ACCESS_MASK, _In_opt_ POBJECT_ATTRIBUTES, _In_opt_ PLARGE_INTEGER,
    _In_ ULONG, _In_ ULONG, _In_opt_ HANDLE);
typedef NTSTATUS (NTAPI *PFN_NtWriteFile)(
    _In_ HANDLE, _In_opt_ HANDLE, _In_opt_ PIO_APC_ROUTINE, _In_opt_ PVOID,
    _Out_ PIO_STATUS_BLOCK, _In_reads_bytes_opt_(Length) PVOID, _In_ ULONG,
    _In_opt_ PLARGE_INTEGER, _In_opt_ PULONG);
typedef NTSTATUS (NTAPI *PFN_NtSetInformationFile)(
    _In_ HANDLE, _Out_ PIO_STATUS_BLOCK, _In_reads_bytes_(Length) PVOID, _In_ ULONG,
    _In_ FILE_INFORMATION_CLASS);
typedef NTSTATUS (NTAPI *PFN_NtDeviceIoControlFile)(
    _In_ HANDLE, _In_opt_ HANDLE, _In_opt_ PIO_APC_ROUTINE, _In_opt_ PVOID,
    _Out_ PIO_STATUS_BLOCK, _In_ ULONG, _In_opt_ PVOID, _In_ ULONG,
    _Out_opt_ PVOID, _In_ ULONG);
typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    _In_ ULONG, PVOID, ULONG, PULONG);

/* FILE_RENAME_INFORMATION as the kernel sees it on x64. */
typedef struct _SYSINFO_RENAME_INFO {
    BOOLEAN ReplaceIfExists;
    HANDLE  RootDirectory;
    ULONG   FileNameLength;
    WCHAR   FileName[1];
} SYSINFO_RENAME_INFO, *PSYSINFO_RENAME_INFO;

#ifndef FileRenameInformationEx
#define FileRenameInformationEx ((FILE_INFORMATION_CLASS)65)
#endif
#ifndef FileDispositionInformationEx
#define FileDispositionInformationEx ((FILE_INFORMATION_CLASS)64)
#endif

/*
 * Ring-0 memory access that never calls an Nt* function.  These three are the
 * exported entry points a driver uses to read or write another process without
 * opening a handle, so they are the only way to see that work at all.
 */
typedef NTSTATUS (NTAPI *PFN_MmCopyVirtualMemory)(
    _In_ PEPROCESS, _In_ PVOID, _In_ PEPROCESS, _In_ PVOID, _In_ SIZE_T,
    _In_ KPROCESSOR_MODE, _Out_ PSIZE_T);
typedef VOID (NTAPI *PFN_KeStackAttachProcess)(_In_ PRKPROCESS, _Out_ PVOID);

typedef NTSTATUS (NTAPI *PFN_NtDuplicateObject)(
    _In_ HANDLE, _In_ HANDLE, _In_ HANDLE, _Out_opt_ PHANDLE,
    _In_ ACCESS_MASK, _In_ ULONG, _In_ ULONG);
typedef NTSTATUS (NTAPI *PFN_NtQueryDirectoryFile)(
    _In_ HANDLE, _In_opt_ HANDLE, _In_opt_ PIO_APC_ROUTINE, _In_opt_ PVOID,
    _Out_ PIO_STATUS_BLOCK, _Out_writes_bytes_(Length) PVOID, _In_ ULONG,
    _In_ FILE_INFORMATION_CLASS, _In_ BOOLEAN, _In_opt_ PUNICODE_STRING, _In_ BOOLEAN);
typedef NTSTATUS (NTAPI *PFN_NtEnumerateValueKey)(
    _In_ HANDLE, _In_ ULONG, _In_ KEY_VALUE_INFORMATION_CLASS,
    _Out_writes_bytes_(Length) PVOID, _In_ ULONG, _Out_opt_ PULONG);
typedef NTSTATUS (NTAPI *PFN_NtEnumerateKey)(
    _In_ HANDLE, _In_ ULONG, _In_ KEY_INFORMATION_CLASS,
    _Out_writes_bytes_(Length) PVOID, _In_ ULONG, _Out_opt_ PULONG);
typedef NTSTATUS (NTAPI *PFN_NtQueueApcThread)(
    _In_ HANDLE, _In_ PVOID, _In_opt_ PVOID, _In_opt_ PVOID, _In_opt_ PVOID);
typedef NTSTATUS (NTAPI *PFN_NtSetContextThread)(_In_ HANDLE, _In_ PVOID);

/* Enough of the two information layouts to read a name out of a query result. */
typedef struct _SYSINFO_KEY_VALUE_BASIC {
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} SYSINFO_KEY_VALUE_BASIC, *PSYSINFO_KEY_VALUE_BASIC;

typedef struct _SYSINFO_KEY_BASIC {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} SYSINFO_KEY_BASIC, *PSYSINFO_KEY_BASIC;

typedef NTSTATUS (NTAPI *PFN_PsSetNotify)(_In_ PVOID, _In_ BOOLEAN);
typedef NTSTATUS (NTAPI *PFN_PsSetNotify1)(_In_ PVOID);
typedef NTSTATUS (NTAPI *PFN_ObRegisterCallbacks)(
    _In_ POB_CALLBACK_REGISTRATION, _Out_ PVOID *);
typedef NTSTATUS (NTAPI *PFN_CmRegisterCallbackEx)(
    _In_ PVOID, _In_ PCUNICODE_STRING, _In_ PVOID, _In_opt_ PVOID, _Out_ PVOID *, _In_opt_ PVOID);
typedef NTSTATUS (NTAPI *PFN_IoCreateDevice)(
    _In_ PDRIVER_OBJECT, _In_ ULONG, _In_opt_ PUNICODE_STRING, _In_ DEVICE_TYPE,
    _In_ ULONG, _In_ BOOLEAN, _Out_ PDEVICE_OBJECT *);

NTSYSAPI NTSTATUS NTAPI ZwQueryKey(
    _In_ HANDLE, _In_ KEY_INFORMATION_CLASS, _In_opt_ PVOID, _In_ ULONG, _Out_opt_ PULONG);
NTSTATUS NTAPI PsLookupProcessByProcessId(_In_ HANDLE, _Out_ PEPROCESS *);
PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);
PEPROCESS NTAPI IoThreadToProcess(_In_ PETHREAD Thread);

/* ------------------------------------------------------------------ helpers */

static BOOLEAN KeyPath(_In_ HANDLE key, _Out_ PUNICODE_STRING path,
                       _Out_writes_(cch) PWCHAR buffer, _In_ ULONG cch);

/* Defined with the file hooks below; needed by the create hook's root prepend. */
static BOOLEAN FileHandlePath(_In_ HANDLE handle, _Out_ PUNICODE_STRING path,
                              _Out_writes_(cch) PWCHAR buffer, _In_ ULONG cch);
static BOOLEAN PrependFileRoot(_In_opt_ HANDLE root, _Inout_ PUNICODE_STRING path,
                               _Inout_updates_(cch) PWCHAR buffer, _In_ ULONG cch);

/*
 * Copy an OBJECT_ATTRIBUTES/ObjectName out of the caller's address space.
 * The Nt* entry points have not validated those pointers yet when our detour
 * runs, and for a user-mode caller they are user addresses - never touch them
 * without probing and an exception handler.
 */
static BOOLEAN
CaptureObjectName(_In_opt_ POBJECT_ATTRIBUTES attributes,
                  _Out_ PUNICODE_STRING path,
                  _Out_writes_(cch) PWCHAR buffer, _In_ ULONG cch,
                  _Out_opt_ PHANDLE rootOut)
{
    BOOLEAN ok = FALSE;
    KPROCESSOR_MODE mode;

    RtlZeroMemory(path, sizeof(*path));
    if (rootOut != NULL) *rootOut = NULL;
    if (attributes == NULL || cch == 0) return FALSE;

    mode = ExGetPreviousMode();
    __try {
        PUNICODE_STRING name;
        HANDLE root;

        if (mode != KernelMode) ProbeForRead(attributes, sizeof(*attributes), sizeof(PVOID));
        name = attributes->ObjectName;
        root = attributes->RootDirectory;
        if (rootOut != NULL) *rootOut = root;
        if (name != NULL) {
            UNICODE_STRING copy;
            ULONG chars;

            if (mode != KernelMode) {
                ProbeForRead(name, sizeof(*name), sizeof(ULONG));
            }
            copy = *name;
            if (copy.Buffer != NULL && copy.Length != 0) {
                chars = copy.Length / sizeof(WCHAR);
                if (chars > cch - 1) chars = cch - 1;
                if (mode != KernelMode) {
                    ProbeForRead(copy.Buffer, chars * sizeof(WCHAR), sizeof(WCHAR));
                }
                RtlCopyMemory(buffer, copy.Buffer, chars * sizeof(WCHAR));
                buffer[chars] = 0;
                path->Buffer = buffer;
                path->Length = (USHORT)(chars * sizeof(WCHAR));
                path->MaximumLength = (USHORT)((chars + 1) * sizeof(WCHAR));
                ok = TRUE;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }
    return ok;
}

/*
 * Same for a UNICODE_STRING argument the Nt* function has not validated yet.
 */
static BOOLEAN
CaptureUnicodeString(_In_opt_ PUNICODE_STRING text, _Out_ PUNICODE_STRING out,
                     _Out_writes_(cch) PWCHAR buffer, _In_ ULONG cch)
{
    KPROCESSOR_MODE mode;

    RtlZeroMemory(out, sizeof(*out));
    if (text == NULL || cch == 0) return FALSE;

    mode = ExGetPreviousMode();
    __try {
        UNICODE_STRING copy;
        ULONG chars;

        if (mode != KernelMode) ProbeForRead(text, sizeof(*text), sizeof(ULONG));
        copy = *text;
        if (copy.Buffer == NULL || copy.Length == 0) return FALSE;

        chars = copy.Length / sizeof(WCHAR);
        if (chars > cch - 1) chars = cch - 1;
        if (mode != KernelMode) ProbeForRead(copy.Buffer, chars * sizeof(WCHAR), sizeof(WCHAR));
        RtlCopyMemory(buffer, copy.Buffer, chars * sizeof(WCHAR));
        buffer[chars] = 0;

        out->Buffer = buffer;
        out->Length = (USHORT)(chars * sizeof(WCHAR));
        out->MaximumLength = (USHORT)((chars + 1) * sizeof(WCHAR));
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

/*
 * Relative key names are common (RegOpenKeyEx with a predefined root): the
 * OBJECT_ATTRIBUTES carries RootDirectory instead of a full path.  Prepend the
 * root key's own path so the event says which key was actually opened.
 */
static VOID
PrependRoot(_In_opt_ HANDLE root, _Inout_ PUNICODE_STRING path,
            _Inout_updates_(cch) PWCHAR buffer, _In_ ULONG cch)
{
    WCHAR rootBuffer[96];
    UNICODE_STRING rootPath;
    ULONG rootChars, pathChars, total;

    if (root == NULL || cch < 2) return;
    if (!KeyPath(root, &rootPath, rootBuffer, RTL_NUMBER_OF(rootBuffer))) return;

    rootChars = rootPath.Length / sizeof(WCHAR);
    pathChars = path->Length / sizeof(WCHAR);
    if (rootChars + 1 >= cch) return;

    total = rootChars + 1 + pathChars;
    if (total > cch - 1) total = cch - 1;

    if (pathChars > total - rootChars - 1) pathChars = total - rootChars - 1;
    RtlMoveMemory(buffer + rootChars + 1, path->Buffer, pathChars * sizeof(WCHAR));
    RtlCopyMemory(buffer, rootBuffer, rootChars * sizeof(WCHAR));
    buffer[rootChars] = L'\\';
    buffer[total] = 0;

    path->Buffer = buffer;
    path->Length = (USHORT)(total * sizeof(WCHAR));
}


static HOOK g_Hooks[30];
static ULONG g_HookCount;
static volatile LONG g_TraceHookCount;

static VOID
AppendChar(_Inout_updates_(cap) PCHAR out, _In_ ULONG cap, _Inout_ PULONG pos, _In_ CHAR c)
{
    if (*pos + 1 < cap) {
        out[*pos] = c;
        out[++(*pos)] = 0;
    }
}

static VOID
AppendStr(_Inout_updates_(cap) PCHAR out, _In_ ULONG cap, _Inout_ PULONG pos, _In_z_ PCSTR text)
{
    while (*text != 0) AppendChar(out, cap, pos, *text++);
}

static VOID
AppendHex(_Inout_updates_(cap) PCHAR out, _In_ ULONG cap, _Inout_ PULONG pos, _In_ ULONG64 value)
{
    CHAR  tmp[17];
    ULONG n = 0;

    do {
        tmp[n++] = "0123456789ABCDEF"[value & 0xF];
        value >>= 4;
    } while (value != 0 && n < 16);
    AppendStr(out, cap, pos, "0x");
    while (n > 0) AppendChar(out, cap, pos, tmp[--n]);
}

static VOID
AppendDec(_Inout_updates_(cap) PCHAR out, _In_ ULONG cap, _Inout_ PULONG pos, _In_ ULONG value)
{
    CHAR  tmp[11];
    ULONG n = 0;

    do {
        tmp[n++] = (CHAR)('0' + (value % 10));
        value /= 10;
    } while (value != 0);
    while (n > 0) AppendChar(out, cap, pos, tmp[--n]);
}

/* DOS path of an open file handle; used by the write and set-information hooks. */
NTSTATUS NTAPI IoQueryFileDosDeviceName(_In_ PFILE_OBJECT, _Out_ PUNICODE_STRING *);
extern POBJECT_TYPE *IoFileObjectType;

static BOOLEAN
FileHandlePath(_In_ HANDLE handle, _Out_ PUNICODE_STRING path,
               _Out_writes_(cch) PWCHAR buffer, _In_ ULONG cch)
{
    PVOID object = NULL;
    PUNICODE_STRING name = NULL;
    BOOLEAN ok = FALSE;

    path->Buffer = buffer;
    path->Length = 0;
    path->MaximumLength = (USHORT)(cch * sizeof(WCHAR));
    if (cch == 0) return FALSE;

    if (!NT_SUCCESS(ObReferenceObjectByHandle(handle, 0, *IoFileObjectType, KernelMode,
                                             &object, NULL)) || object == NULL) {
        return FALSE;
    }

    if (NT_SUCCESS(IoQueryFileDosDeviceName((PFILE_OBJECT)object, &name)) && name != NULL) {
        ULONG chars = name->Length / sizeof(WCHAR);
        ULONG i;

        if (chars > cch - 1) chars = cch - 1;
        for (i = 0; i < chars; i++) buffer[i] = name->Buffer[i];
        buffer[chars] = 0;
        path->Length = (USHORT)(chars * sizeof(WCHAR));
        ok = TRUE;
        ExFreePool(name);
    }
    ObDereferenceObject(object);
    return ok;
}

/* Full path of an open key handle, via the exported ZwQueryKey. */
static BOOLEAN
KeyPath(_In_ HANDLE key, _Out_ PUNICODE_STRING path, _Out_writes_(cch) PWCHAR buffer, _In_ ULONG cch)
{
    UCHAR  scratch[sizeof(KEY_NAME_INFORMATION) + 512 * sizeof(WCHAR)];
    PKEY_NAME_INFORMATION info = (PKEY_NAME_INFORMATION)scratch;
    ULONG  returned = 0;
    ULONG  chars;
    NTSTATUS status;

    path->Buffer = buffer;
    path->Length = 0;
    path->MaximumLength = (USHORT)(cch * sizeof(WCHAR));
    if (cch == 0) return FALSE;

    status = ZwQueryKey(key, KeyNameInformation, info, sizeof(scratch), &returned);
    if (!NT_SUCCESS(status) || info->NameLength == 0) return FALSE;

    chars = info->NameLength / sizeof(WCHAR);
    if (chars > cch - 1) chars = cch - 1;
    RtlCopyMemory(buffer, info->Name, chars * sizeof(WCHAR));
    buffer[chars] = 0;
    path->Length = (USHORT)(chars * sizeof(WCHAR));
    return TRUE;
}

static ULONG
PidFromProcessHandle(_In_ HANDLE process)
{
    PEPROCESS target = NULL;
    ULONG     pid = 0;

    if (process == NULL || process == NtCurrentProcess()) {
        return (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    }
    if (NT_SUCCESS(ObReferenceObjectByHandle(process, 0, *PsProcessType, KernelMode,
                                            (PVOID *)&target, NULL)) && target != NULL) {
        pid = (ULONG)(ULONG_PTR)PsGetProcessId(target);
        ObDereferenceObject(target);
    }
    return pid;
}

/* "pid <n>" for the target process. */
static VOID
AppendPid(_Inout_updates_(cap) PCHAR out, _In_ ULONG cap, _Inout_ PULONG pos, _In_ ULONG pid)
{
    AppendStr(out, cap, pos, "pid ");
    AppendDec(out, cap, pos, pid);
}

static const char *
DispositionName(_In_ ULONG disposition)
{
    switch (disposition) {
    case FILE_SUPERSEDE:     return "supersede";
    case FILE_OPEN:          return "open";
    case FILE_CREATE:        return "create";
    case FILE_OPEN_IF:       return "open/create";
    case FILE_OVERWRITE:     return "overwrite";
    case FILE_OVERWRITE_IF:  return "overwrite/create";
    default:                 return "?";
    }
}

/* --------------------------------------------------------------- file hooks */

static NTSTATUS NTAPI
HookNtCreateFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_opt_ PVOID EaBuffer,
    _In_ ULONG EaLength)
{
    PFN_NtCreateFile original = (PFN_NtCreateFile)g_Hooks[0].Trampoline;
    NTSTATUS status;
    WCHAR pathBuffer[SYSINFO_MON_MAX_PATH];
    WCHAR fullBuffer[SYSINFO_MON_MAX_PATH * 2];
    UNICODE_STRING path;
    HANDLE root = NULL;
    BOOLEAN havePath;

    HookEnter();
    havePath = FALSE;
    if (MonActive() || GuardIsTargetProcess()) {
        havePath = CaptureObjectName(ObjectAttributes, &path, pathBuffer,
                                     RTL_NUMBER_OF(pathBuffer), &root);
        /* Resolving the root costs a handle lookup, so only do it when the
         * guard is actually judging this process. */
        if (havePath && root != NULL && GuardIsTargetProcess()) {
            havePath = PrependFileRoot(root, &path, fullBuffer, RTL_NUMBER_OF(fullBuffer));
        }
    }

    if (havePath && GuardFileBlocked(&path, DesiredAccess)) {
        HookLeave();
        return STATUS_ACCESS_DENIED;
    }

    status = original(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                      AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                      CreateOptions, EaBuffer, EaLength);

    if (MonActive() && havePath) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, NT_SUCCESS(status) ? "" : "FAILED ");
        AppendStr(detail, sizeof(detail), &pos, DispositionName(CreateDisposition));

        MonEvent(SYSINFO_MON_FILE, (ULONG)DesiredAccess, &path, detail);
    }

    HookLeave();
    return status;
}

/* Resolve a relative open against its RootDirectory, like PrependRoot does for
 * registry keys.  Without this a target could open "Chrome\User Data\... "
 * relative to a directory handle and never match a protected path. */
static BOOLEAN
PrependFileRoot(_In_opt_ HANDLE root, _Inout_ PUNICODE_STRING path,
                _Inout_updates_(cch) PWCHAR buffer, _In_ ULONG cch)
{
    WCHAR rootBuffer[SYSINFO_MON_MAX_PATH];
    UNICODE_STRING rootPath;
    ULONG rootChars, pathChars, total, i;

    if (root == NULL || cch < 2) return FALSE;
    if (!FileHandlePath(root, &rootPath, rootBuffer, RTL_NUMBER_OF(rootBuffer))) return FALSE;

    rootChars = rootPath.Length / sizeof(WCHAR);
    pathChars = path->Length / sizeof(WCHAR);
    while (rootChars > 0 && rootBuffer[rootChars - 1] == L'\\') rootChars--;
    if (rootChars + 1 >= cch) return FALSE;

    total = rootChars + 1 + pathChars;
    if (total > cch - 1) total = cch - 1;
    if (pathChars > total - rootChars - 1) pathChars = total - rootChars - 1;

    /* Shift the leaf name right first: it lives in the same buffer. */
    RtlMoveMemory(buffer + rootChars + 1, path->Buffer, pathChars * sizeof(WCHAR));
    for (i = 0; i < rootChars; i++) buffer[i] = rootBuffer[i];
    buffer[rootChars] = L'\\';
    buffer[total] = 0;

    path->Buffer = buffer;
    path->Length = (USHORT)(total * sizeof(WCHAR));
    return TRUE;
}

/* ------------------------------------------------------- file write / delete */

static NTSTATUS NTAPI
HookNtWriteFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_opt_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key)
{
    PFN_NtWriteFile original = (PFN_NtWriteFile)g_Hooks[18].Trampoline;
    NTSTATUS status;

    HookEnter();
    status = original(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                      Buffer, Length, ByteOffset, Key);

    if (MonActive()) {
        WCHAR pathBuffer[SYSINFO_MON_MAX_PATH];
        UNICODE_STRING path;
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        if (FileHandlePath(FileHandle, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer))) {
            detail[0] = 0;
            AppendStr(detail, sizeof(detail), &pos, "write ");
            AppendDec(detail, sizeof(detail), &pos, Length);
            if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
            MonEvent(SYSINFO_MON_FILE, (ULONG)Length, &path, detail);
        }
    }

    HookLeave();
    return status;
}

static NTSTATUS NTAPI
HookNtSetInformationFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass)
{
    PFN_NtSetInformationFile original = (PFN_NtSetInformationFile)g_Hooks[19].Trampoline;
    WCHAR pathBuffer[SYSINFO_MON_MAX_PATH];
    UNICODE_STRING path;
    BOOLEAN havePath = FALSE;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FileInformation);
    UNREFERENCED_PARAMETER(Length);

    /*
     * Resolved before the call on purpose: a successful rename updates the file
     * object's name, so afterwards this would report "<new> -> <new>".
     */
    if (MonActive() &&
        (FileInformationClass == FileRenameInformation ||
         FileInformationClass == FileRenameInformationEx ||
         FileInformationClass == FileDispositionInformation ||
         FileInformationClass == FileDispositionInformationEx)) {
        havePath = FileHandlePath(FileHandle, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer));
    }

    HookEnter();
    status = original(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);

    if (havePath) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos,
                  (FileInformationClass == FileRenameInformation ||
                   FileInformationClass == FileRenameInformationEx) ? "rename" : "delete");

        if (FileInformationClass == FileRenameInformation ||
            FileInformationClass == FileRenameInformationEx) {
            /* The new name is a UNICODE_STRING at the end of the caller's
             * buffer; copy it out defensively. */
            __try {
                PSYSINFO_RENAME_INFO info = (PSYSINFO_RENAME_INFO)FileInformation;
                ULONG chars = info->FileNameLength / sizeof(WCHAR);

                if (info->ReplaceIfExists || info->RootDirectory != NULL || chars != 0) {
                    AppendStr(detail, sizeof(detail), &pos, " -> ");
                    if (chars > 96) chars = 96;
                    for (ULONG i = 0; i < chars && pos + 1 < sizeof(detail); i++) {
                        WCHAR c = info->FileName[i];
                        AppendChar(detail, sizeof(detail), &pos, (c < 0x80) ? (CHAR)c : '?');
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                detail[0] = 0;
                AppendStr(detail, sizeof(detail), &pos, "rename");
            }
        }

        if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
        MonEvent(SYSINFO_MON_FILE, 0, &path, detail);
    }

    HookLeave();
    return status;
}

/* ------------------------------------------------- ring-0 memory access */

static PCSTR
ProcessImageName(_In_opt_ PEPROCESS process)
{
    PCHAR name;

    if (process == NULL) return "(none)";
    name = PsGetProcessImageFileName(process);
    return (name != NULL && name[0] != 0) ? name : "(none)";
}

static NTSTATUS NTAPI
HookMmCopyVirtualMemory(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _In_ PEPROCESS TargetProcess,
    _In_ PVOID TargetAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T ReturnSize)
{
    PFN_MmCopyVirtualMemory original = (PFN_MmCopyVirtualMemory)g_Hooks[20].Trampoline;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(TargetAddress);

    HookEnter();
    status = original(SourceProcess, SourceAddress, TargetProcess, TargetAddress,
                      BufferSize, PreviousMode, ReturnSize);

    if (MonActive() && BufferSize != 0) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, "copy ");
        AppendStr(detail, sizeof(detail), &pos, ProcessImageName(SourceProcess));
        AppendStr(detail, sizeof(detail), &pos, " -> ");
        AppendStr(detail, sizeof(detail), &pos, ProcessImageName(TargetProcess));
        AppendStr(detail, sizeof(detail), &pos, " sz ");
        AppendDec(detail, sizeof(detail), &pos, (ULONG)BufferSize);
        AppendStr(detail, sizeof(detail), &pos, " ");
        AppendHex(detail, sizeof(detail), &pos, (ULONG64)(ULONG_PTR)SourceAddress);
        if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");

        MonEventForced(SYSINFO_MON_MEM, (ULONG)BufferSize, NULL, detail);
    }

    HookLeave();
    return status;
}

/*
 * Attaching is the other way to touch another process without a handle.  The
 * operating system calls this constantly for its own work, so the caller is
 * checked first: anything called from inside ntoskrnl is ignored.
 */
static VOID NTAPI
HookKeStackAttachProcess(_In_ PRKPROCESS Process, _Out_ PVOID ApcState)
{
    PFN_KeStackAttachProcess original = (PFN_KeStackAttachProcess)g_Hooks[21].Trampoline;

    HookEnter();

    {
        ULONG_PTR ret = (ULONG_PTR)_ReturnAddress();
        ULONG_PTR ntBase = (ULONG_PTR)SysinfoNtImageBase();

        /* Without a calibrated ntoskrnl range every address would look like a
         * driver and this would log the operating system's own attaches. */
        if (ntBase != 0) {
            ULONG_PTR ntEnd = ntBase + SysinfoNtImageSize();

            if (ret < ntBase || ret >= ntEnd) {
                CHAR detail[SYSINFO_MON_MAX_DETAIL];
                ULONG pos = 0;

                detail[0] = 0;
                AppendStr(detail, sizeof(detail), &pos, "attach ");
                AppendStr(detail, sizeof(detail), &pos, ProcessImageName((PEPROCESS)Process));
                MonEventForced(SYSINFO_MON_MEM, 0, NULL, detail);
            }
        }
    }

    original(Process, ApcState);
    HookLeave();
}

/* ------------------------------------------------- discovery / handle passing */

/* Copy a target process's image name next to its pid, for the detail column. */
static VOID
TargetImage(_In_ HANDLE process, _Out_ PULONG pid,
            _Out_writes_(chars) PCHAR image, _In_ ULONG chars)
{
    PEPROCESS target = NULL;
    ULONG i = 0;

    *pid = 0;
    if (image != NULL && chars != 0) image[0] = 0;

    if (!NT_SUCCESS(ObReferenceObjectByHandle(process, 0, *PsProcessType, KernelMode,
                                             (PVOID *)&target, NULL)) || target == NULL) {
        return;
    }

    *pid = (ULONG)(ULONG_PTR)PsGetProcessId(target);
    if (image != NULL && chars != 0) {
        PCHAR name = PsGetProcessImageFileName(target);

        if (name != NULL) {
            while (name[i] != 0 && i + 1 < chars) { image[i] = name[i]; i++; }
        }
        image[i] = 0;
    }
    ObDereferenceObject(target);
}

static NTSTATUS NTAPI
HookNtDuplicateObject(
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _In_ HANDLE TargetProcessHandle,
    _Out_opt_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options)
{
    PFN_NtDuplicateObject original = (PFN_NtDuplicateObject)g_Hooks[26].Trampoline;
    NTSTATUS status;

    HookEnter();
    status = original(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle,
                      DesiredAccess, HandleAttributes, Options);

    if (MonActive()) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        CHAR image[SYSINFO_MON_IMAGE_CHARS];
        ULONG pos = 0, pid = 0;

        TargetImage(TargetProcessHandle, &pid, image, RTL_NUMBER_OF(image));
        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, "duplicate ");
        AppendHex(detail, sizeof(detail), &pos, (ULONG64)(ULONG_PTR)SourceHandle);
        AppendStr(detail, sizeof(detail), &pos, " -> pid ");
        AppendDec(detail, sizeof(detail), &pos, pid);
        if (image[0] != 0) {
            AppendStr(detail, sizeof(detail), &pos, " ");
            AppendStr(detail, sizeof(detail), &pos, image);
        }
        if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
        MonEvent(SYSINFO_MON_HANDLE, DesiredAccess, NULL, detail);
    }

    HookLeave();
    return status;
}

/* Reading a directory is how a program finds files; the handle open alone does
 * not say which pattern it asked for or what came back. */
static NTSTATUS NTAPI
HookNtQueryDirectoryFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_opt_ PUNICODE_STRING FileName,
    _In_ BOOLEAN RestartScan)
{
    PFN_NtQueryDirectoryFile original = (PFN_NtQueryDirectoryFile)g_Hooks[27].Trampoline;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FileInformation);
    UNREFERENCED_PARAMETER(ReturnSingleEntry);

    HookEnter();
    status = original(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                      FileInformation, Length, FileInformationClass, ReturnSingleEntry,
                      FileName, RestartScan);

    if (MonActive()) {
        WCHAR pathBuffer[SYSINFO_MON_MAX_PATH];
        UNICODE_STRING path;
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        if (FileHandlePath(FileHandle, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer))) {
            WCHAR patternBuffer[64];
            UNICODE_STRING pattern;

            detail[0] = 0;
            AppendStr(detail, sizeof(detail), &pos, "list");

            if (CaptureUnicodeString(FileName, &pattern, patternBuffer,
                                     RTL_NUMBER_OF(patternBuffer))) {
                ULONG i;

                AppendStr(detail, sizeof(detail), &pos, " ");
                for (i = 0; i < pattern.Length / sizeof(WCHAR) && pos + 1 < sizeof(detail); i++) {
                    WCHAR c = pattern.Buffer[i];
                    AppendChar(detail, sizeof(detail), &pos, (c < 0x80) ? (CHAR)c : '?');
                }
            }
            if (NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " ok");
            else                   AppendStr(detail, sizeof(detail), &pos, " end");
            MonEvent(SYSINFO_MON_FILE, (ULONG)Length, &path, detail);
        }
    }

    HookLeave();
    return status;
}

/* Enumerating values is how a program discovers what a key contains. */
static NTSTATUS NTAPI
HookNtEnumerateValueKey(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_(Length) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_opt_ PULONG ResultLength)
{
    PFN_NtEnumerateValueKey original = (PFN_NtEnumerateValueKey)g_Hooks[22].Trampoline;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(KeyValueInformation);
    UNREFERENCED_PARAMETER(Length);

    HookEnter();
    status = original(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation,
                      Length, ResultLength);

    if (MonActive()) {
        WCHAR pathBuffer[SYSINFO_MON_MAX_PATH];
        UNICODE_STRING path;
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        if (KeyPath(KeyHandle, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer))) {
            detail[0] = 0;
            AppendStr(detail, sizeof(detail), &pos, "enum value ");
            AppendDec(detail, sizeof(detail), &pos, Index);

            if (NT_SUCCESS(status) &&
                KeyValueInformationClass == KeyValueBasicInformation) {
                __try {
                    PSYSINFO_KEY_VALUE_BASIC info =
                        (PSYSINFO_KEY_VALUE_BASIC)KeyValueInformation;
                    ULONG chars = info->NameLength / sizeof(WCHAR);
                    ULONG i;

                    if (chars > 48) chars = 48;
                    AppendStr(detail, sizeof(detail), &pos, " ");
                    for (i = 0; i < chars && pos + 1 < sizeof(detail); i++) {
                        WCHAR c = info->Name[i];
                        AppendChar(detail, sizeof(detail), &pos, (c < 0x80) ? (CHAR)c : '?');
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    /* keep the index only */
                }
            }

            MonEvent(SYSINFO_MON_KEY, Index, &path, detail);
        }
    }

    HookLeave();
    return status;
}

/* Enumerating subkeys is the other half of registry discovery. */
static NTSTATUS NTAPI
HookNtEnumerateKey(
    _In_ HANDLE KeyHandle,
    _In_ ULONG Index,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_(Length) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_opt_ PULONG ResultLength)
{
    PFN_NtEnumerateKey original = (PFN_NtEnumerateKey)g_Hooks[23].Trampoline;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(KeyInformation);
    UNREFERENCED_PARAMETER(Length);

    HookEnter();
    status = original(KeyHandle, Index, KeyInformationClass, KeyInformation,
                      Length, ResultLength);

    if (MonActive()) {
        WCHAR pathBuffer[SYSINFO_MON_MAX_PATH];
        UNICODE_STRING path;
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        if (KeyPath(KeyHandle, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer))) {
            detail[0] = 0;
            AppendStr(detail, sizeof(detail), &pos, "enum key ");
            AppendDec(detail, sizeof(detail), &pos, Index);

            if (NT_SUCCESS(status) && KeyInformationClass == KeyBasicInformation) {
                __try {
                    PSYSINFO_KEY_BASIC info = (PSYSINFO_KEY_BASIC)KeyInformation;
                    ULONG chars = info->NameLength / sizeof(WCHAR);
                    ULONG i;

                    if (chars > 48) chars = 48;
                    AppendStr(detail, sizeof(detail), &pos, " ");
                    for (i = 0; i < chars && pos + 1 < sizeof(detail); i++) {
                        WCHAR c = info->Name[i];
                        AppendChar(detail, sizeof(detail), &pos, (c < 0x80) ? (CHAR)c : '?');
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    /* keep the index only */
                }
            }

            MonEvent(SYSINFO_MON_KEY, Index, &path, detail);
        }
    }

    HookLeave();
    return status;
}

/* --------------------------------------------------- injection primitives */

static VOID
ThreadTarget(_In_ HANDLE thread, _Out_ PULONG pid, _Out_ PULONG tid,
             _Out_writes_(chars) PCHAR image, _In_ ULONG chars)
{
    PETHREAD target = NULL;
    ULONG i = 0;

    *pid = 0;
    *tid = 0;
    if (image != NULL && chars != 0) image[0] = 0;

    if (!NT_SUCCESS(ObReferenceObjectByHandle(thread, 0, *PsThreadType, KernelMode,
                                             (PVOID *)&target, NULL)) || target == NULL) {
        return;
    }

    *tid = (ULONG)(ULONG_PTR)PsGetThreadId(target);
    {
        PEPROCESS process = IoThreadToProcess(target);

        if (process != NULL) {
            PCHAR name;

            *pid = (ULONG)(ULONG_PTR)PsGetProcessId(process);
            name = PsGetProcessImageFileName(process);
            if (name != NULL && image != NULL) {
                while (name[i] != 0 && i + 1 < chars) { image[i] = name[i]; i++; }
            }
        }
    }
    if (image != NULL && chars != 0) image[i] = 0;
    ObDereferenceObject(target);
}

static VOID
AppendThreadTarget(_Out_writes_(cap) PCHAR detail, _In_ ULONG cap, _Inout_ PULONG pos,
                   _In_ HANDLE thread)
{
    CHAR image[SYSINFO_MON_IMAGE_CHARS];
    ULONG pid = 0, tid = 0;

    ThreadTarget(thread, &pid, &tid, image, RTL_NUMBER_OF(image));
    AppendStr(detail, cap, pos, " pid ");
    AppendDec(detail, cap, pos, pid);
    AppendStr(detail, cap, pos, " tid ");
    AppendDec(detail, cap, pos, tid);
    if (image[0] != 0) {
        AppendStr(detail, cap, pos, " ");
        AppendStr(detail, cap, pos, image);
    }
}

static NTSTATUS NTAPI
HookNtQueueApcThread(
    _In_ HANDLE ThreadHandle,
    _In_ PVOID ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3)
{
    PFN_NtQueueApcThread original = (PFN_NtQueueApcThread)g_Hooks[24].Trampoline;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(ApcArgument1);
    UNREFERENCED_PARAMETER(ApcArgument2);
    UNREFERENCED_PARAMETER(ApcArgument3);

    HookEnter();
    status = original(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);

    if (MonActive()) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, "queue apc");
        AppendThreadTarget(detail, sizeof(detail), &pos, ThreadHandle);
        AppendStr(detail, sizeof(detail), &pos, " routine ");
        AppendHex(detail, sizeof(detail), &pos, (ULONG64)(ULONG_PTR)ApcRoutine);
        if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
        MonEvent(SYSINFO_MON_THREAD, 0, NULL, detail);
    }

    HookLeave();
    return status;
}

static NTSTATUS NTAPI
HookNtSetContextThread(_In_ HANDLE ThreadHandle, _In_ PVOID ThreadContext)
{
    PFN_NtSetContextThread original = (PFN_NtSetContextThread)g_Hooks[25].Trampoline;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(ThreadContext);

    HookEnter();
    status = original(ThreadHandle, ThreadContext);

    if (MonActive()) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, "set context");
        AppendThreadTarget(detail, sizeof(detail), &pos, ThreadHandle);
        if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
        MonEvent(SYSINFO_MON_THREAD, 0, NULL, detail);
    }

    HookLeave();
    return status;
}

/* ---------------------------------------------------------- registry hooks */

static NTSTATUS NTAPI
HookNtOpenKey(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes)
{
    PFN_NtOpenKey original = (PFN_NtOpenKey)g_Hooks[1].Trampoline;
    NTSTATUS status;
    WCHAR pathBuffer[SYSINFO_MON_MAX_PATH];
    UNICODE_STRING path;
    HANDLE root = NULL;
    BOOLEAN havePath;

    HookEnter();
    havePath = FALSE;
    if (MonActive() || GuardIsTargetProcess()) {
        havePath = CaptureObjectName(ObjectAttributes, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer), &root);
        if (havePath) PrependRoot(root, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer));
    }

    if (havePath && GuardRegistryBlocked(&path, DesiredAccess)) {
        HookLeave();
        return STATUS_ACCESS_DENIED;
    }

    status = original(KeyHandle, DesiredAccess, ObjectAttributes);

    if (MonActive() && havePath) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, NT_SUCCESS(status) ? "open" : "open FAILED");
        MonEvent(SYSINFO_MON_KEY, (ULONG)DesiredAccess, &path, detail);
    }

    HookLeave();
    return status;
}

static NTSTATUS NTAPI
HookNtOpenKeyEx(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG OpenOptions)
{
    PFN_NtOpenKeyEx original = (PFN_NtOpenKeyEx)g_Hooks[15].Trampoline;
    NTSTATUS status;
    WCHAR pathBuffer[SYSINFO_MON_MAX_PATH];
    UNICODE_STRING path;
    HANDLE root = NULL;
    BOOLEAN havePath;

    UNREFERENCED_PARAMETER(OpenOptions);

    HookEnter();
    havePath = FALSE;
    if (MonActive() || GuardIsTargetProcess()) {
        havePath = CaptureObjectName(ObjectAttributes, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer), &root);
        if (havePath) PrependRoot(root, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer));
    }

    if (havePath && GuardRegistryBlocked(&path, DesiredAccess)) {
        HookLeave();
        return STATUS_ACCESS_DENIED;
    }

    status = original(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);

    if (MonActive() && havePath) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, NT_SUCCESS(status) ? "open" : "open FAILED");
        MonEvent(SYSINFO_MON_KEY, (ULONG)DesiredAccess, &path, detail);
    }

    HookLeave();
    return status;
}

static NTSTATUS NTAPI
HookNtCreateKey(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG TitleIndex,
    _In_opt_ PUNICODE_STRING Class,
    _In_ ULONG CreateOptions,
    _Out_opt_ PULONG Disposition)
{
    PFN_NtCreateKey original = (PFN_NtCreateKey)g_Hooks[2].Trampoline;
    NTSTATUS status;
    WCHAR pathBuffer[SYSINFO_MON_MAX_PATH];
    UNICODE_STRING path;
    HANDLE root = NULL;
    BOOLEAN havePath;

    UNREFERENCED_PARAMETER(Class);
    UNREFERENCED_PARAMETER(CreateOptions);

    HookEnter();
    havePath = FALSE;
    if (MonActive() || GuardIsTargetProcess()) {
        havePath = CaptureObjectName(ObjectAttributes, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer), &root);
        if (havePath) PrependRoot(root, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer));
    }

    if (havePath && GuardRegistryBlocked(&path, DesiredAccess)) {
        HookLeave();
        return STATUS_ACCESS_DENIED;
    }

    status = original(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class,
                      CreateOptions, Disposition);

    if (MonActive() && havePath) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;
        ULONG disposition = 0;

        __try {
            if (Disposition != NULL) {
                if (ExGetPreviousMode() != KernelMode) ProbeForRead(Disposition, sizeof(ULONG), sizeof(ULONG));
                disposition = *Disposition;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            disposition = 0;
        }

        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos,
                  (disposition == REG_CREATED_NEW_KEY) ? "create new" : "create open");
        if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
        MonEvent(SYSINFO_MON_KEY, (ULONG)DesiredAccess, &path, detail);
    }

    HookLeave();
    return status;
}

static NTSTATUS NTAPI
HookNtSetValueKey(
    _In_ HANDLE KeyHandle,
    _In_opt_ PUNICODE_STRING ValueName,
    _In_ ULONG TitleIndex,
    _In_ ULONG Type,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize)
{
    PFN_NtSetValueKey original = (PFN_NtSetValueKey)g_Hooks[3].Trampoline;
    NTSTATUS status;
    WCHAR guardPathBuffer[128];
    UNICODE_STRING guardPath;
    BOOLEAN guardHavePath;

    UNREFERENCED_PARAMETER(Data);

    HookEnter();
    guardHavePath = FALSE;
    if (GuardIsTargetProcess()) {
        guardHavePath = KeyPath(KeyHandle, &guardPath, guardPathBuffer, RTL_NUMBER_OF(guardPathBuffer));
    }
    if (guardHavePath && GuardRegistryBlocked(&guardPath, Type)) {
        HookLeave();
        return STATUS_ACCESS_DENIED;
    }

    status = original(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);

    if (MonActive()) {
        WCHAR pathBuffer[128];
        UNICODE_STRING path;
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;
        ULONG i;

        if (KeyPath(KeyHandle, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer))) {
            UNICODE_STRING name;
            WCHAR nameBuffer[64];

            CaptureUnicodeString(ValueName, &name, nameBuffer, RTL_NUMBER_OF(nameBuffer));

            detail[0] = 0;
            AppendStr(detail, sizeof(detail), &pos, "set ");
            if (name.Buffer != NULL) {
                for (i = 0; i < name.Length / sizeof(WCHAR) && pos + 1 < sizeof(detail); i++) {
                    WCHAR c = name.Buffer[i];
                    AppendChar(detail, sizeof(detail), &pos, (c < 0x80) ? (CHAR)c : '?');
                }
            }
            AppendStr(detail, sizeof(detail), &pos, " type ");
            AppendDec(detail, sizeof(detail), &pos, Type);
            AppendStr(detail, sizeof(detail), &pos, " sz ");
            AppendDec(detail, sizeof(detail), &pos, DataSize);

            /* A short value is often the interesting part (a flag, a name, an id). */
            if (Data != NULL && DataSize != 0 && DataSize <= 8) {
                UCHAR copy[8];
                BOOLEAN ok = FALSE;

                __try {
                    if (ExGetPreviousMode() != KernelMode) ProbeForRead(Data, DataSize, 1);
                    RtlCopyMemory(copy, Data, DataSize);
                    ok = TRUE;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    ok = FALSE;
                }
                if (ok) {
                    ULONG j;

                    AppendStr(detail, sizeof(detail), &pos, " data ");
                    for (j = 0; j < DataSize && pos + 2 < sizeof(detail); j++) {
                        static const CHAR digits[] = "0123456789ABCDEF";

                        if (j != 0) AppendChar(detail, sizeof(detail), &pos, ' ');
                        AppendChar(detail, sizeof(detail), &pos, digits[copy[j] >> 4]);
                        AppendChar(detail, sizeof(detail), &pos, digits[copy[j] & 0xF]);
                    }
                }
            }

            if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
            MonEvent(SYSINFO_MON_KEY, Type, &path, detail);
        }
    }

    HookLeave();
    return status;
}

static NTSTATUS NTAPI
HookNtDeleteValueKey(
    _In_ HANDLE KeyHandle,
    _In_opt_ PUNICODE_STRING ValueName)
{
    PFN_NtDeleteValueKey original = (PFN_NtDeleteValueKey)g_Hooks[4].Trampoline;
    NTSTATUS status;
    WCHAR guardPathBuffer[128];
    UNICODE_STRING guardPath;
    BOOLEAN guardHavePath;

    HookEnter();
    guardHavePath = FALSE;
    if (GuardIsTargetProcess()) {
        guardHavePath = KeyPath(KeyHandle, &guardPath, guardPathBuffer, RTL_NUMBER_OF(guardPathBuffer));
    }
    if (guardHavePath && GuardRegistryBlocked(&guardPath, 0)) {
        HookLeave();
        return STATUS_ACCESS_DENIED;
    }

    status = original(KeyHandle, ValueName);

    if (MonActive()) {
        WCHAR pathBuffer[128];
        UNICODE_STRING path;
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;
        ULONG i;

        if (KeyPath(KeyHandle, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer))) {
            UNICODE_STRING name;
            WCHAR nameBuffer[64];

            CaptureUnicodeString(ValueName, &name, nameBuffer, RTL_NUMBER_OF(nameBuffer));

            detail[0] = 0;
            AppendStr(detail, sizeof(detail), &pos, "delete ");
            if (name.Buffer != NULL) {
                for (i = 0; i < name.Length / sizeof(WCHAR) && pos + 1 < sizeof(detail); i++) {
                    WCHAR c = name.Buffer[i];
                    AppendChar(detail, sizeof(detail), &pos, (c < 0x80) ? (CHAR)c : '?');
                }
            }
            if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
            MonEvent(SYSINFO_MON_KEY, 0, &path, detail);
        }
    }

    HookLeave();
    return status;
}

static NTSTATUS NTAPI
HookNtDeleteKey(_In_ HANDLE KeyHandle)
{
    PFN_NtDeleteKey original = (PFN_NtDeleteKey)g_Hooks[5].Trampoline;
    NTSTATUS status;
    WCHAR guardPathBuffer[128];
    UNICODE_STRING guardPath;
    BOOLEAN guardHavePath;

    HookEnter();
    guardHavePath = FALSE;
    if (GuardIsTargetProcess()) {
        guardHavePath = KeyPath(KeyHandle, &guardPath, guardPathBuffer, RTL_NUMBER_OF(guardPathBuffer));
    }
    if (guardHavePath && GuardRegistryBlocked(&guardPath, 0)) {
        HookLeave();
        return STATUS_ACCESS_DENIED;
    }

    status = original(KeyHandle);

    if (MonActive()) {
        WCHAR pathBuffer[128];
        UNICODE_STRING path;

        if (KeyPath(KeyHandle, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer))) {
            MonEvent(SYSINFO_MON_KEY, 0, &path, NT_SUCCESS(status) ? "delete key" : "delete key FAILED");
        }
    }

    HookLeave();
    return status;
}

/* --------------------------------------------------------------- memory ops */

static NTSTATUS NTAPI
HookNtProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T NumberOfBytesToProtect,
    _In_ ULONG NewAccessProtection,
    _Out_opt_ PULONG OldAccessProtection)
{
    PFN_NtProtectVirtualMemory original = (PFN_NtProtectVirtualMemory)g_Hooks[6].Trampoline;
    PVOID base = NULL;
    SIZE_T size = 0;
    KPROCESSOR_MODE mode = ExGetPreviousMode();
    NTSTATUS status;

    __try {
        if (BaseAddress != NULL) {
            if (mode != KernelMode) ProbeForRead(BaseAddress, sizeof(PVOID), sizeof(PVOID));
            base = *BaseAddress;
        }
        if (NumberOfBytesToProtect != NULL) {
            if (mode != KernelMode) ProbeForRead(NumberOfBytesToProtect, sizeof(SIZE_T), sizeof(SIZE_T));
            size = *NumberOfBytesToProtect;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        base = NULL;
        size = 0;
    }

    HookEnter();
    status = original(ProcessHandle, BaseAddress, NumberOfBytesToProtect,
                      NewAccessProtection, OldAccessProtection);

    if (MonActive()) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, "pid ");
        AppendDec(detail, sizeof(detail), &pos, PidFromProcessHandle(ProcessHandle));
        AppendStr(detail, sizeof(detail), &pos, " addr ");
        AppendHex(detail, sizeof(detail), &pos, (ULONG64)(ULONG_PTR)base);
        AppendStr(detail, sizeof(detail), &pos, " sz ");
        AppendHex(detail, sizeof(detail), &pos, (ULONG64)size);
        AppendStr(detail, sizeof(detail), &pos, " p ");
        AppendHex(detail, sizeof(detail), &pos, NewAccessProtection);
        if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
        MonEvent(SYSINFO_MON_MEM, NewAccessProtection, NULL, detail);
    }

    HookLeave();
    return status;
}

static NTSTATUS NTAPI
HookNtMapViewOfSection(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _In_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ ULONG InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect)
{
    PFN_NtMapViewOfSection original = (PFN_NtMapViewOfSection)g_Hooks[7].Trampoline;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(SectionHandle);
    UNREFERENCED_PARAMETER(ZeroBits);
    UNREFERENCED_PARAMETER(CommitSize);
    UNREFERENCED_PARAMETER(InheritDisposition);
    UNREFERENCED_PARAMETER(AllocationType);

    HookEnter();
    status = original(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
                      SectionOffset, ViewSize, InheritDisposition, AllocationType,
                      Win32Protect);

    if (MonActive()) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;
        PVOID mapped = NULL;
        SIZE_T viewSize = 0;

        __try {
            if (BaseAddress != NULL) {
                if (ExGetPreviousMode() != KernelMode) ProbeForRead(BaseAddress, sizeof(PVOID), sizeof(PVOID));
                mapped = *BaseAddress;
            }
            if (ViewSize != NULL) {
                if (ExGetPreviousMode() != KernelMode) ProbeForRead(ViewSize, sizeof(SIZE_T), sizeof(SIZE_T));
                viewSize = *ViewSize;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            mapped = NULL;
            viewSize = 0;
        }

        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, "pid ");
        AppendDec(detail, sizeof(detail), &pos, PidFromProcessHandle(ProcessHandle));
        AppendStr(detail, sizeof(detail), &pos, " map ");
        AppendHex(detail, sizeof(detail), &pos, (ULONG64)(ULONG_PTR)mapped);
        AppendStr(detail, sizeof(detail), &pos, " sz ");
        AppendHex(detail, sizeof(detail), &pos, (ULONG64)viewSize);
        AppendStr(detail, sizeof(detail), &pos, " p ");
        AppendHex(detail, sizeof(detail), &pos, Win32Protect);
        if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
        MonEvent(SYSINFO_MON_MEM, Win32Protect, NULL, detail);
    }

    HookLeave();
    return status;
}

static NTSTATUS NTAPI
HookNtCreateSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle)
{
    PFN_NtCreateSection original = (PFN_NtCreateSection)g_Hooks[8].Trampoline;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(AllocationAttributes);
    UNREFERENCED_PARAMETER(FileHandle);

    HookEnter();
    status = original(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize,
                      SectionPageProtection, AllocationAttributes, FileHandle);

    if (MonActive()) {
        WCHAR pathBuffer[SYSINFO_MON_MAX_PATH];
        UNICODE_STRING path;
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;
        ULONG64 maxSize = 0;

        CaptureObjectName(ObjectAttributes, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer), NULL);

        __try {
            if (MaximumSize != NULL) {
                if (ExGetPreviousMode() != KernelMode) ProbeForRead(MaximumSize, sizeof(*MaximumSize), sizeof(LARGE_INTEGER));
                maxSize = (ULONG64)MaximumSize->QuadPart;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            maxSize = 0;
        }

        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, "section sz ");
        AppendHex(detail, sizeof(detail), &pos, maxSize);
        AppendStr(detail, sizeof(detail), &pos, " p ");
        AppendHex(detail, sizeof(detail), &pos, SectionPageProtection);
        if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
        MonEvent(SYSINFO_MON_MEM, DesiredAccess, &path, detail);
    }

    HookLeave();
    return status;
}

/*
 * NtReadVirtualMemory / NtWriteVirtualMemory are not exported and have no Zw
 * stub, so they are resolved from the syscall numbers the user-mode tool reads
 * out of ntdll.  These two are how a program reads (or patches) another
 * process's memory.
 */
static NTSTATUS NTAPI
HookNtReadVirtualMemory(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress,
                        _Out_ PVOID Buffer, _In_ SIZE_T NumberOfBytesToRead,
                        _Out_opt_ PSIZE_T NumberOfBytesRead)
{
    PFN_NtReadVirtualMemory original = (PFN_NtReadVirtualMemory)g_Hooks[16].Trampoline;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Buffer);

    HookEnter();

    if (GuardMemoryBlocked(ProcessHandle, PROCESS_VM_READ)) {
        HookLeave();
        return STATUS_ACCESS_DENIED;
    }

    status = original(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);

    if (MonActive()) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        CHAR image[SYSINFO_MON_IMAGE_CHARS];
        ULONG pid = 0;
        ULONG pos = 0;

        TargetImage(ProcessHandle, &pid, image, RTL_NUMBER_OF(image));
        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, "pid ");
        AppendDec(detail, sizeof(detail), &pos, pid);
        if (image[0] != 0) {
            AppendStr(detail, sizeof(detail), &pos, " ");
            AppendStr(detail, sizeof(detail), &pos, image);
        }
        AppendStr(detail, sizeof(detail), &pos, " read ");
        AppendHex(detail, sizeof(detail), &pos, (ULONG64)(ULONG_PTR)BaseAddress);
        AppendStr(detail, sizeof(detail), &pos, " sz ");
        AppendHex(detail, sizeof(detail), &pos, (ULONG64)NumberOfBytesToRead);
        if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
        MonEvent(SYSINFO_MON_MEM, 0, NULL, detail);
    }

    HookLeave();
    return status;
}

static NTSTATUS NTAPI
HookNtWriteVirtualMemory(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress,
                         _In_ PVOID Buffer, _In_ SIZE_T NumberOfBytesToWrite,
                         _Out_opt_ PSIZE_T NumberOfBytesWritten)
{
    PFN_NtWriteVirtualMemory original = (PFN_NtWriteVirtualMemory)g_Hooks[17].Trampoline;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Buffer);

    HookEnter();

    if (GuardMemoryBlocked(ProcessHandle, PROCESS_VM_WRITE)) {
        HookLeave();
        return STATUS_ACCESS_DENIED;
    }

    status = original(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

    if (MonActive()) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        CHAR image[SYSINFO_MON_IMAGE_CHARS];
        ULONG pid = 0;
        ULONG pos = 0;

        TargetImage(ProcessHandle, &pid, image, RTL_NUMBER_OF(image));
        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, "pid ");
        AppendDec(detail, sizeof(detail), &pos, pid);
        if (image[0] != 0) {
            AppendStr(detail, sizeof(detail), &pos, " ");
            AppendStr(detail, sizeof(detail), &pos, image);
        }
        AppendStr(detail, sizeof(detail), &pos, " write ");
        AppendHex(detail, sizeof(detail), &pos, (ULONG64)(ULONG_PTR)BaseAddress);
        AppendStr(detail, sizeof(detail), &pos, " sz ");
        AppendHex(detail, sizeof(detail), &pos, (ULONG64)NumberOfBytesToWrite);
        if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
        MonEvent(SYSINFO_MON_MEM, 0, NULL, detail);
    }

    HookLeave();
    return status;
}

static NTSTATUS NTAPI
HookNtDeviceIoControlFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG IoControlCode,
    _In_opt_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength)
{
    PFN_NtDeviceIoControlFile original = (PFN_NtDeviceIoControlFile)g_Hooks[28].Trampoline;
    NTSTATUS status;

    HookEnter();
    status = original(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                      IoControlCode, InputBuffer, InputBufferLength,
                      OutputBuffer, OutputBufferLength);
    if (MonActive()) {
        WCHAR pathBuffer[SYSINFO_MON_MAX_PATH];
        UNICODE_STRING path;
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, "in ");
        AppendDec(detail, sizeof(detail), &pos, InputBufferLength);
        AppendStr(detail, sizeof(detail), &pos, " out ");
        AppendDec(detail, sizeof(detail), &pos, OutputBufferLength);
        if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
        if (FileHandlePath(FileHandle, &path, pathBuffer, RTL_NUMBER_OF(pathBuffer))) {
            MonEvent(SYSINFO_MON_IOCTL, IoControlCode, &path, detail);
        } else {
            MonEvent(SYSINFO_MON_IOCTL, IoControlCode, NULL, detail);
        }
    }
    HookLeave();
    return status;
}

static NTSTATUS NTAPI
HookNtQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    PFN_NtQuerySystemInformation original = (PFN_NtQuerySystemInformation)g_Hooks[29].Trampoline;
    ULONG bytes = 0;
    NTSTATUS status;

    HookEnter();
    status = original(SystemInformationClass, SystemInformation,
                      SystemInformationLength, ReturnLength != NULL ? ReturnLength : &bytes);
    if (MonActive()) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, "class ");
        AppendDec(detail, sizeof(detail), &pos, (ULONG)SystemInformationClass);
        AppendStr(detail, sizeof(detail), &pos, " bytes ");
        AppendDec(detail, sizeof(detail), &pos, ReturnLength != NULL ? *ReturnLength : bytes);
        if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
        MonEvent(SYSINFO_MON_SYSINFO, (ULONG)SystemInformationClass, NULL, detail);
    }
    HookLeave();
    return status;
}

/* ------------------------------------------------------- callback registry */

static VOID
LogCallback(_In_ PCSTR what, _In_ PVOID routine, _In_opt_ PCUNICODE_STRING altitude,
            _In_ BOOLEAN remove)
{
    CHAR detail[SYSINFO_MON_MAX_DETAIL];
    ULONG pos = 0;
    ULONG i;

    if (MonActive() == FALSE) return;

    detail[0] = 0;
    if (remove) AppendStr(detail, sizeof(detail), &pos, "remove ");
    AppendStr(detail, sizeof(detail), &pos, what);
    AppendChar(detail, sizeof(detail), &pos, ' ');
    AppendHex(detail, sizeof(detail), &pos, (ULONG64)(ULONG_PTR)routine);
    if (altitude != NULL && altitude->Buffer != NULL) {
        AppendStr(detail, sizeof(detail), &pos, " alt ");
        for (i = 0; i < altitude->Length / sizeof(WCHAR) && pos + 1 < sizeof(detail); i++) {
            WCHAR c = altitude->Buffer[i];
            AppendChar(detail, sizeof(detail), &pos, (c < 0x80) ? (CHAR)c : '?');
        }
    }
    MonEvent(SYSINFO_MON_KCB, 0, NULL, detail);
}

static NTSTATUS NTAPI
HookPsSetCreateThreadNotifyRoutine(_In_ PVOID NotifyRoutine)
{
    PFN_PsSetNotify1 original = (PFN_PsSetNotify1)g_Hooks[10].Trampoline;
    NTSTATUS status = original(NotifyRoutine);

    LogCallback("thread-notify", NotifyRoutine, NULL, FALSE);
    return status;
}

static NTSTATUS NTAPI
HookPsSetLoadImageNotifyRoutine(_In_ PVOID NotifyRoutine)
{
    PFN_PsSetNotify1 original = (PFN_PsSetNotify1)g_Hooks[11].Trampoline;
    NTSTATUS status = original(NotifyRoutine);

    LogCallback("image-notify", NotifyRoutine, NULL, FALSE);
    return status;
}

static NTSTATUS NTAPI
HookObRegisterCallbacks(_In_ POB_CALLBACK_REGISTRATION Registration,
                        _Out_ PVOID *RegistrationHandle)
{
    PFN_ObRegisterCallbacks original = (PFN_ObRegisterCallbacks)g_Hooks[12].Trampoline;
    PVOID routine = NULL;
    NTSTATUS status;

    if (Registration != NULL && Registration->OperationRegistrationCount > 0 &&
        Registration->OperationRegistration != NULL) {
        routine = (PVOID)Registration->OperationRegistration[0].PreOperation;
    }

    status = original(Registration, RegistrationHandle);
    LogCallback("ob-callbacks", routine,
                (Registration != NULL) ? &Registration->Altitude : NULL, FALSE);
    return status;
}

static NTSTATUS NTAPI
HookCmRegisterCallbackEx(_In_ PVOID Function, _In_ PCUNICODE_STRING Altitude,
                         _In_ PVOID Driver, _In_opt_ PVOID Context,
                         _Out_ PVOID *Cookie, _In_opt_ PVOID Reserved)
{
    PFN_CmRegisterCallbackEx original = (PFN_CmRegisterCallbackEx)g_Hooks[13].Trampoline;
    NTSTATUS status = original(Function, Altitude, Driver, Context, Cookie, Reserved);

    LogCallback("cm-callback", Function, Altitude, FALSE);
    return status;
}

static NTSTATUS NTAPI
HookIoCreateDevice(_In_ PDRIVER_OBJECT DriverObject, _In_ ULONG DeviceExtensionSize,
                   _In_opt_ PUNICODE_STRING DeviceName, _In_ DEVICE_TYPE DeviceType,
                   _In_ ULONG Characteristics, _In_ BOOLEAN Exclusive,
                   _Out_ PDEVICE_OBJECT *DeviceObject)
{
    PFN_IoCreateDevice original = (PFN_IoCreateDevice)g_Hooks[14].Trampoline;
    NTSTATUS status = original(DriverObject, DeviceExtensionSize, DeviceName, DeviceType,
                               Characteristics, Exclusive, DeviceObject);

    if (MonActive() && DeviceName != NULL) {
        CHAR detail[SYSINFO_MON_MAX_DETAIL];
        ULONG pos = 0;

        detail[0] = 0;
        AppendStr(detail, sizeof(detail), &pos, "device type ");
        AppendHex(detail, sizeof(detail), &pos, DeviceType);
        if (!NT_SUCCESS(status)) AppendStr(detail, sizeof(detail), &pos, " FAILED");
        MonEvent(SYSINFO_MON_DEV, (ULONG)DeviceType, DeviceName, detail);
    }

    return status;
}

/* ------------------------------------------------------------------- start */

static BOOLEAN
Install(_Inout_ PHOOK hook, _In_ PCWSTR name, _In_ PVOID detour)
{
    PVOID target = SysinfoResolveNt(name);

    if (target == NULL) {
        DbgPrint("SysInfo: trace: %ws not found\n", name);
        return FALSE;
    }
    if (!NT_SUCCESS(HookInstall(hook, target, detour, "trace"))) {
        DbgPrint("SysInfo: trace: cannot hook %ws\n", name);
        return FALSE;
    }
    InterlockedIncrement(&g_TraceHookCount);
    return TRUE;
}

VOID
TraceInit(VOID)
{
    static const struct {
        PCWSTR name;
        PVOID  detour;
    } hooks[] = {
        /*
         * Index-bound initialisers: each detour reads its trampoline from
         * g_Hooks[<index>], so a slot that is added or removed must never shift
         * the ones after it.  Leaving a gap zero-initialises it and the install
         * loop skips it.  (Removing five entries outright once shifted
         * NtOpenKeyEx onto a NULL trampoline: 0x1E, c0000005 at address 0.)
         */
        [0]  = { L"NtCreateFile",               (PVOID)HookNtCreateFile },
        [1]  = { L"NtOpenKey",                  (PVOID)HookNtOpenKey },
        [2]  = { L"NtCreateKey",                (PVOID)HookNtCreateKey },
        [3]  = { L"NtSetValueKey",              (PVOID)HookNtSetValueKey },
        [4]  = { L"NtDeleteValueKey",           (PVOID)HookNtDeleteValueKey },
        [5]  = { L"NtDeleteKey",                (PVOID)HookNtDeleteKey },
        [6]  = { L"NtProtectVirtualMemory",     (PVOID)HookNtProtectVirtualMemory },
        [7]  = { L"NtMapViewOfSection",         (PVOID)HookNtMapViewOfSection },
        [8]  = { L"NtCreateSection",            (PVOID)HookNtCreateSection },
        /* 9  : PsSetCreateProcessNotifyRoutineEx - 0x109 */
        /* 10 : PsSetCreateThreadNotifyRoutine     - 0x109 type 'a', 2026-10-25 20:44 */
        /* 11 : PsSetLoadImageNotifyRoutine        - same class, unvalidated */
        /* 12 : ObRegisterCallbacks                - same class, unvalidated */
        /* 13 : CmRegisterCallbackEx               - same class, unvalidated */
        /* 14 : IoCreateDevice                     - same class, unvalidated */
        [15] = { L"NtOpenKeyEx",                (PVOID)HookNtOpenKeyEx },
        /* 16/17: NtRead/NtWriteVirtualMemory, installed on demand by
         *        TraceInstallMemoryHooks once `mon on` supplies the SSNs. */
        /* 18-25: file write/rename, handle duplication, directory listing,
         *        key/value enumeration, APC and context - all unvalidated after
         *        NtSetInformationFile was caught (0x109, 2026-10-25 20:09). */
        [28] = { L"NtDeviceIoControlFile",       (PVOID)HookNtDeviceIoControlFile },
        [29] = { L"NtQuerySystemInformation",    (PVOID)HookNtQuerySystemInformation },
    };
    ULONG i;

    if (g_HookCount != 0) return;

#if !SYSINFO_ENABLE_TRACE_HOOKS
    DbgPrint("SysInfo: trace hooks disabled at compile time\n");
    return;
#else
    if (!TraceUnsafeHooksEnabled()) {
        DbgPrint("SysInfo: trace hooks disabled by runtime gate\n");
        return;
    }
    if (SysinfoPatchBlocked()) {
        DbgPrint("SysInfo: trace: inline hooks are blocked (HVCI/hypervisor)\n");
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(hooks); i++) {
        if (hooks[i].name == NULL) continue;
        if (Install(&g_Hooks[i], hooks[i].name, hooks[i].detour)) {
            g_HookCount++;
        }
    }
    DbgPrint("SysInfo: trace hooks %lu/%lu\n", g_HookCount, (ULONG)RTL_NUMBER_OF(hooks));
#endif
}

VOID
TraceInstallMemoryHooks(_In_ ULONG ssnRead, _In_ ULONG ssnWrite)
{
    ULONG_PTR base;
    ULONG     size;
    PVOID     target;

#if SYSINFO_ENABLE_TRACE_HOOKS
    if (!TraceUnsafeHooksEnabled()) return;

    base = (ULONG_PTR)SysinfoNtImageBase();
    size = SysinfoNtImageSize();
    if (base == 0 || size == 0) return;

    if (ssnRead != 0 && !g_Hooks[16].Installed) {
        target = SysinfoResolveSsn(ssnRead);
        if (target != NULL && (ULONG_PTR)target >= base && (ULONG_PTR)target < base + size) {
            if (NT_SUCCESS(HookInstall(&g_Hooks[16], target, (PVOID)HookNtReadVirtualMemory,
                                       "NtReadVirtualMemory"))) {
                InterlockedIncrement(&g_TraceHookCount);
            }
        }
    }

    if (ssnWrite != 0 && !g_Hooks[17].Installed) {
        target = SysinfoResolveSsn(ssnWrite);
        if (target != NULL && (ULONG_PTR)target >= base && (ULONG_PTR)target < base + size) {
            if (NT_SUCCESS(HookInstall(&g_Hooks[17], target, (PVOID)HookNtWriteVirtualMemory,
                                       "NtWriteVirtualMemory"))) {
                InterlockedIncrement(&g_TraceHookCount);
            }
        }
    }
#else
    UNREFERENCED_PARAMETER(base);
    UNREFERENCED_PARAMETER(size);
    UNREFERENCED_PARAMETER(target);
    UNREFERENCED_PARAMETER(ssnRead);
    UNREFERENCED_PARAMETER(ssnWrite);
#endif
}

VOID
TraceShutdown(VOID)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(g_Hooks); i++) {
        if (g_Hooks[i].Installed) HookRemove(&g_Hooks[i]);
    }
    g_HookCount = 0;
    InterlockedExchange(&g_TraceHookCount, 0);
}

ULONG
TraceHookCount(VOID)
{
    return (ULONG)g_TraceHookCount;
}

VOID
TraceSetUnsafeHooksEnabled(_In_ ULONG enabled)
{
    InterlockedExchange(&g_UnsafeHooksEnabled, enabled ? 1 : 0);
    if (enabled) TraceInit();
    else TraceShutdown();
}

BOOLEAN
TraceUnsafeHooksEnabled(VOID)
{
    return g_UnsafeHooksEnabled != 0;
}
