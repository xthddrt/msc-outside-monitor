/*
 * guard.c - policy-driven access guard.
 *
 * Targets are matched by process image name.  This build ships no built-in
 * targets: nothing is watched or denied until a policy names it, so the guard
 * cannot act on a program the operator did not ask about.  The protected
 * resources default to browser profile paths and registry subtrees, which are
 * the usual reason to want file and registry denial at all.
 *
 * This is deliberately substring based: it does not need to know the current
 * user's profile path, and it covers paths like
 *   \Device\HarddiskVolume3\Users\me\AppData\Local\Google\Chrome\User Data\...
 */
#include "guard.h"
#include "monitor.h"
#include "util.h"

PCHAR  PsGetProcessImageFileName(_In_ PEPROCESS Process);
NTSTATUS NTAPI PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Out_ PEPROCESS *Process);
PEPROCESS NTAPI IoThreadToProcess(_In_ PETHREAD Thread);

static SYSINFO_GUARD_CONFIG g_Config;
static volatile LONG   g_Mode = SYSINFO_GUARD_OFF;
static volatile LONG   g_Checks;
static volatile LONG   g_Denied;
static volatile LONG   g_Audited;

/* Empty: targets come from the policy, never from the build.  A compiled-in
 * target list is a decision made for the operator, and it is also the kind of
 * thing that goes stale silently. */
static const CHAR *g_DefaultTargets[] = {
    NULL
};

static const WCHAR *g_DefaultPaths[] = {
    L"\\Google\\Chrome\\User Data",
    L"\\Google\\Chrome\\Application",
    L"\\Microsoft\\Edge\\User Data",
    L"\\Microsoft\\Edge\\Application",
    L"\\Mozilla\\Firefox\\Profiles",
    L"\\BraveSoftware\\Brave-Browser\\User Data",
    L"\\Opera Software\\",
    L"\\Vivaldi\\User Data",
    L"\\Chromium\\User Data",
    NULL
};

static const WCHAR *g_DefaultRegistry[] = {
    L"\\Software\\Google\\Chrome",
    L"\\Software\\Microsoft\\Edge",
    L"\\Software\\Mozilla\\Firefox",
    L"\\Software\\BraveSoftware",
    L"\\Software\\Opera Software",
    L"\\Software\\Vivaldi",
    L"\\Software\\Chromium",
    NULL
};

static const CHAR *g_DefaultProcesses[] = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "chromium.exe",
    NULL
};

/* ------------------------------------------------------------------ helpers */

static VOID
CopyAscii(_Out_writes_(Chars) CHAR *Dst, _In_ ULONG Chars, _In_opt_ const CHAR *Src)
{
    ULONG i = 0;

    RtlZeroMemory(Dst, Chars);
    if (Src == NULL) return;
    while (i + 1 < Chars && Src[i] != 0) { Dst[i] = Src[i]; i++; }
}

static VOID
CopyWide(_Out_writes_(Chars) WCHAR *Dst, _In_ ULONG Chars, _In_opt_ const WCHAR *Src)
{
    ULONG i = 0;

    RtlZeroMemory(Dst, Chars * sizeof(WCHAR));
    if (Src == NULL) return;
    while (i + 1 < Chars && Src[i] != 0) { Dst[i] = Src[i]; i++; }
}

static CHAR
UpperAscii(_In_ CHAR c)
{
    if (c >= 'a' && c <= 'z') return (CHAR)(c - 32);
    return c;
}

static BOOLEAN
ImageMatches(_In_ const CHAR *Image, _In_ const CHAR *Target)
{
    ULONG i;

    if (Image == NULL || Target == NULL || Target[0] == 0 || Image[0] == 0) return FALSE;

    /*
     * PsGetProcessImageFileName truncates to 15 characters, so a caller with a
     * longer name ("some-long-image-name.exe") arrives here as a prefix of the
     * configured name.  Compare until either string ends, and only accept the
     * result when enough characters lined up to be meaningful.
     */
    for (i = 0; i < SYSINFO_GUARD_TARGET_CHARS; i++) {
        CHAR a = Image[i];
        CHAR b = Target[i];

        if (a == 0 || b == 0) return i >= 6;
        if (UpperAscii(a) != UpperAscii(b)) return FALSE;
    }
    return TRUE;
}

static BOOLEAN
ContainsWideNoCase(_In_ PCUNICODE_STRING Path, _In_ const WCHAR *Needle)
{
    ULONG pathChars, needleChars, i, j;

    if (Path == NULL || Path->Buffer == NULL || Needle == NULL || Needle[0] == 0) return FALSE;
    pathChars = Path->Length / sizeof(WCHAR);
    needleChars = 0;
    while (Needle[needleChars] != 0) needleChars++;
    if (needleChars == 0 || pathChars < needleChars) return FALSE;

    for (i = 0; i + needleChars <= pathChars; i++) {
        for (j = 0; j < needleChars; j++) {
            WCHAR a = Path->Buffer[i + j];
            WCHAR b = Needle[j];
            if (RtlUpcaseUnicodeChar(a) != RtlUpcaseUnicodeChar(b)) break;
        }
        if (j == needleChars) return TRUE;
    }
    return FALSE;
}

static BOOLEAN
CurrentImage(_Out_writes_(SYSINFO_GUARD_TARGET_CHARS) CHAR *Image)
{
    PCHAR name = PsGetProcessImageFileName(PsGetCurrentProcess());
    CopyAscii(Image, SYSINFO_GUARD_TARGET_CHARS, name);
    return Image[0] != 0;
}

static BOOLEAN
TargetByName(_In_ const CHAR *Image)
{
    ULONG i;

    for (i = 0; i < g_Config.TargetCount && i < SYSINFO_GUARD_MAX_TARGETS; i++) {
        if (ImageMatches(Image, g_Config.Targets[i])) return TRUE;
    }
    return FALSE;
}

static BOOLEAN
ProtectedByName(_In_ const CHAR *Image)
{
    ULONG i;

    for (i = 0; i < g_Config.ProcessCount && i < SYSINFO_GUARD_MAX_PROCS; i++) {
        if (ImageMatches(Image, g_Config.Processes[i])) return TRUE;
    }
    return FALSE;
}

static VOID
Record(_In_ BOOLEAN AuditOnly)
{
    InterlockedIncrement(&g_Checks);
    if (AuditOnly) InterlockedIncrement(&g_Audited);
    else           InterlockedIncrement(&g_Denied);
}

static VOID
LogEvent(_In_ ULONG Type, _In_ ACCESS_MASK Access, _In_opt_ PCUNICODE_STRING Path,
         _In_ const CHAR *Action)
{
    CHAR detail[SYSINFO_MON_MAX_DETAIL];
    UNREFERENCED_PARAMETER(Access);

    CopyAscii(detail, sizeof(detail), Action);
    if (MonActive()) {
        MonEvent(Type, (ULONG)Access, Path, detail);
    }
    {
        UNICODE_STRING none;
        PCUNICODE_STRING shown = Path;

        if (shown == NULL) {
            RtlInitUnicodeString(&none, L"(none)");
            shown = &none;
        }
        DbgPrint("SysInfo guard: %s pid=%lu image=%s path=%wZ\n",
                 Action, (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                 PsGetProcessImageFileName(PsGetCurrentProcess()), shown);
    }
}

/* ------------------------------------------------------------------- init */

NTSTATUS
GuardInit(VOID)
{
    ULONG i, n;

    RtlZeroMemory(&g_Config, sizeof(g_Config));
    g_Config.Mode = SYSINFO_GUARD_AUDIT;
    g_Mode = SYSINFO_GUARD_AUDIT;

    for (n = 0; g_DefaultTargets[n] != NULL && n < SYSINFO_GUARD_MAX_TARGETS; n++) {
        CopyAscii(g_Config.Targets[n], SYSINFO_GUARD_TARGET_CHARS, g_DefaultTargets[n]);
    }
    g_Config.TargetCount = n;

    for (n = 0; g_DefaultPaths[n] != NULL && n < SYSINFO_GUARD_MAX_PATHS; n++) {
        CopyWide(g_Config.Paths[n], SYSINFO_GUARD_PATH_CHARS, g_DefaultPaths[n]);
    }
    g_Config.PathCount = n;

    for (n = 0; g_DefaultProcesses[n] != NULL && n < SYSINFO_GUARD_MAX_PROCS; n++) {
        CopyAscii(g_Config.Processes[n], SYSINFO_GUARD_TARGET_CHARS, g_DefaultProcesses[n]);
    }
    g_Config.ProcessCount = n;

    /* Keep the registry patterns in the remaining path slots. */
    for (i = 0, n = g_Config.PathCount;
         g_DefaultRegistry[i] != NULL && n < SYSINFO_GUARD_MAX_PATHS; i++, n++) {
        CopyWide(g_Config.Paths[n], SYSINFO_GUARD_PATH_CHARS, g_DefaultRegistry[i]);
    }
    g_Config.PathCount = n;

    InterlockedExchange(&g_Checks, 0);
    InterlockedExchange(&g_Denied, 0);
    InterlockedExchange(&g_Audited, 0);
    DbgPrint("SysInfo guard: init targets=%lu paths=%lu procs=%lu mode=audit\n",
             (ULONG)g_Config.TargetCount, (ULONG)g_Config.PathCount,
             (ULONG)g_Config.ProcessCount);
    return STATUS_SUCCESS;
}

VOID
GuardShutdown(VOID)
{
    InterlockedExchange(&g_Mode, SYSINFO_GUARD_OFF);
}

NTSTATUS
GuardConfigure(_In_ const SYSINFO_GUARD_CONFIG *Config)
{
    ULONG i;

    if (Config == NULL || Config->Mode > SYSINFO_GUARD_ENFORCE) return STATUS_INVALID_PARAMETER;

    if (Config->TargetCount > 0) {
        ULONG count = Config->TargetCount;
        if (count > SYSINFO_GUARD_MAX_TARGETS) count = SYSINFO_GUARD_MAX_TARGETS;
        for (i = 0; i < count; i++) {
            CopyAscii(g_Config.Targets[i], SYSINFO_GUARD_TARGET_CHARS, Config->Targets[i]);
            g_Config.Targets[i][SYSINFO_GUARD_TARGET_CHARS - 1] = 0;
        }
        g_Config.TargetCount = count;
    }

    if (Config->PathCount > 0) {
        ULONG count = Config->PathCount;
        if (count > SYSINFO_GUARD_MAX_PATHS) count = SYSINFO_GUARD_MAX_PATHS;
        for (i = 0; i < count; i++) {
            CopyWide(g_Config.Paths[i], SYSINFO_GUARD_PATH_CHARS, Config->Paths[i]);
            g_Config.Paths[i][SYSINFO_GUARD_PATH_CHARS - 1] = 0;
        }
        g_Config.PathCount = count;
    }

    if (Config->ProcessCount > 0) {
        ULONG count = Config->ProcessCount;
        if (count > SYSINFO_GUARD_MAX_PROCS) count = SYSINFO_GUARD_MAX_PROCS;
        for (i = 0; i < count; i++) {
            CopyAscii(g_Config.Processes[i], SYSINFO_GUARD_TARGET_CHARS, Config->Processes[i]);
            g_Config.Processes[i][SYSINFO_GUARD_TARGET_CHARS - 1] = 0;
        }
        g_Config.ProcessCount = count;
    }

    g_Config.Mode = Config->Mode;
    InterlockedExchange(&g_Mode, (LONG)Config->Mode);
    DbgPrint("SysInfo guard: mode=%lu targets=%lu paths=%lu procs=%lu\n",
             (ULONG)g_Config.Mode, (ULONG)g_Config.TargetCount,
             (ULONG)g_Config.PathCount, (ULONG)g_Config.ProcessCount);
    return STATUS_SUCCESS;
}

NTSTATUS
GuardGetStatus(_Out_ PSYSINFO_GUARD_STATUS Status)
{
    if (Status == NULL) return STATUS_INVALID_PARAMETER;

    Status->AbiVersion = SYSINFO_ABI_VERSION;
    Status->Mode = (ULONG)g_Mode;
    Status->Targets = g_Config.TargetCount;
    Status->Paths = g_Config.PathCount;
    Status->Processes = g_Config.ProcessCount;
    Status->Checks = (ULONG)g_Checks;
    Status->Denied = (ULONG)g_Denied;
    Status->Audited = (ULONG)g_Audited;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ policy */

BOOLEAN
GuardIsTargetProcess(VOID)
{
    CHAR image[SYSINFO_GUARD_TARGET_CHARS];
    if (g_Mode == SYSINFO_GUARD_OFF) return FALSE;
    if (!CurrentImage(image)) return FALSE;
    return TargetByName(image);
}

BOOLEAN
GuardFileBlocked(_In_ PCUNICODE_STRING Path, _In_ ACCESS_MASK Access)
{
    CHAR image[SYSINFO_GUARD_TARGET_CHARS];
    ULONG i;

    if (g_Mode == SYSINFO_GUARD_OFF || Path == NULL) return FALSE;
    if (!CurrentImage(image) || !TargetByName(image)) return FALSE;

    for (i = 0; i < g_Config.PathCount && i < SYSINFO_GUARD_MAX_PATHS; i++) {
        if (ContainsWideNoCase(Path, g_Config.Paths[i])) {
            Record(g_Mode == SYSINFO_GUARD_AUDIT);
            LogEvent(SYSINFO_MON_FILE, Access, Path,
                     g_Mode == SYSINFO_GUARD_ENFORCE ? "DENY file" : "AUDIT file");
            return g_Mode == SYSINFO_GUARD_ENFORCE;
        }
    }
    return FALSE;
}

BOOLEAN
GuardRegistryBlocked(_In_ PCUNICODE_STRING Path, _In_ ACCESS_MASK Access)
{
    CHAR image[SYSINFO_GUARD_TARGET_CHARS];
    ULONG i;

    if (g_Mode == SYSINFO_GUARD_OFF || Path == NULL) return FALSE;
    if (!CurrentImage(image) || !TargetByName(image)) return FALSE;

    for (i = 0; i < g_Config.PathCount && i < SYSINFO_GUARD_MAX_PATHS; i++) {
        if (ContainsWideNoCase(Path, g_Config.Paths[i])) {
            Record(g_Mode == SYSINFO_GUARD_AUDIT);
            LogEvent(SYSINFO_MON_KEY, Access, Path,
                     g_Mode == SYSINFO_GUARD_ENFORCE ? "DENY key" : "AUDIT key");
            return g_Mode == SYSINFO_GUARD_ENFORCE;
        }
    }
    return FALSE;
}

static BOOLEAN
ProtectedProcessImage(_In_ PEPROCESS Process)
{
    CHAR image[SYSINFO_GUARD_TARGET_CHARS];
    PCHAR name;

    if (Process == NULL) return FALSE;
    name = PsGetProcessImageFileName(Process);
    CopyAscii(image, SYSINFO_GUARD_TARGET_CHARS, name);
    return image[0] != 0 && ProtectedByName(image);
}

/* "<action> <target image>", so the event says which browser was touched. */
static VOID
AppendPart(_Out_writes_(cap) CHAR *out, _In_ ULONG cap, _Inout_ PULONG pos, _In_opt_ const CHAR *text)
{
    if (text == NULL) return;
    while (*text != 0 && *pos + 1 < cap) out[(*pos)++] = *text++;
    out[*pos] = 0;
}

static VOID
HandleAction(_In_ const CHAR *Action, _In_opt_ PEPROCESS Target,
             _Out_writes_(SYSINFO_MON_MAX_DETAIL) CHAR *out)
{
    CHAR image[SYSINFO_GUARD_TARGET_CHARS];
    ULONG pos = 0;

    out[0] = 0;
    AppendPart(out, SYSINFO_MON_MAX_DETAIL, &pos, Action);
    CopyAscii(image, SYSINFO_GUARD_TARGET_CHARS,
              Target != NULL ? PsGetProcessImageFileName(Target) : NULL);
    if (image[0] != 0) {
        AppendPart(out, SYSINFO_MON_MAX_DETAIL, &pos, " ");
        AppendPart(out, SYSINFO_MON_MAX_DETAIL, &pos, image);
    }
}

BOOLEAN
GuardProcessHandleBlocked(_In_ HANDLE TargetPid, _In_ ACCESS_MASK Access)
{
    PEPROCESS process = NULL;
    CHAR caller[SYSINFO_GUARD_TARGET_CHARS];
    BOOLEAN blocked = FALSE;

    if (g_Mode == SYSINFO_GUARD_OFF) return FALSE;
    if (!CurrentImage(caller) || !TargetByName(caller)) return FALSE;
    if (NT_SUCCESS(PsLookupProcessByProcessId(TargetPid, &process)) && process != NULL) {
        if (ProtectedProcessImage(process) &&
            (Access & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |
                       PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME)) != 0) {
            CHAR action[SYSINFO_MON_MAX_DETAIL];

            HandleAction(g_Mode == SYSINFO_GUARD_ENFORCE ? "DENY handle" : "AUDIT handle",
                         process, action);
            Record(g_Mode == SYSINFO_GUARD_AUDIT);
            LogEvent(SYSINFO_MON_HANDLE, Access, NULL, action);
            blocked = (g_Mode == SYSINFO_GUARD_ENFORCE);
        }
        ObDereferenceObject(process);
    }
    return blocked;
}

BOOLEAN
GuardMemoryBlocked(_In_ HANDLE ProcessHandle, _In_ ACCESS_MASK Access)
{
    PVOID object = NULL;
    NTSTATUS status;
    BOOLEAN blocked = FALSE;

    UNREFERENCED_PARAMETER(Access);

    /* Cheap gate first: the common case is a non-target caller. */
    if (!GuardIsTargetProcess()) return FALSE;

    status = ObReferenceObjectByHandle(ProcessHandle, 0,
                                       *PsProcessType, KernelMode, &object, NULL);
    if (NT_SUCCESS(status) && object != NULL) {
        PEPROCESS process = (PEPROCESS)object;
        blocked = GuardProcessHandleBlocked(PsGetProcessId(process), PROCESS_VM_READ);
        ObDereferenceObject(object);
    }
    return blocked;
}

VOID
GuardPreHandle(_Inout_ POB_PRE_OPERATION_INFORMATION Info)
{
    ACCESS_MASK *access = NULL;
    ACCESS_MASK mask = 0;
    PEPROCESS target = NULL;
    CHAR caller[SYSINFO_GUARD_TARGET_CHARS];

    if (g_Mode == SYSINFO_GUARD_OFF || Info == NULL || Info->Object == NULL) return;
    if (!CurrentImage(caller) || !TargetByName(caller)) return;

    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        access = &Info->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        access = &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        return;
    }
    if (access == NULL) return;

    if (Info->ObjectType == *PsProcessType) {
        target = (PEPROCESS)Info->Object;
        mask = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |
               PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME;
    } else if (Info->ObjectType == *PsThreadType) {
        target = IoThreadToProcess((PETHREAD)Info->Object);
        mask = THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME |
               THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE;
    } else {
        return;
    }
    if (target == NULL || !ProtectedProcessImage(target)) return;
    if ((*access & mask) == 0) return;

    {
        CHAR action[SYSINFO_MON_MAX_DETAIL];

        HandleAction(g_Mode == SYSINFO_GUARD_ENFORCE ? "DENY handle" : "AUDIT handle",
                     target, action);
        Record(g_Mode == SYSINFO_GUARD_AUDIT);
        LogEvent(SYSINFO_MON_HANDLE, *access, NULL, action);
    }

    if (g_Mode == SYSINFO_GUARD_ENFORCE) {
        *access &= ~mask;
    }
}
