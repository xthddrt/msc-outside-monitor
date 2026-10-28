/*
 * monitor.c - "what is that program actually doing?"
 *
 * Two sources:
 *   - documented kernel notifications: image loads (user and kernel) and
 *     process create/exit, registered once with PsSetLoadImageNotifyRoutine /
 *     PsSetCreateProcessNotifyRoutineEx;
 *   - the driver's existing Nt* detours, which call MonEvent() for registry
 *     value reads, device IOCTLs and system-information classes.
 *
 * Records go into a lock-protected ring; `sysinfoctl mon dump` drains it.
 * Nothing here patches code, so it is compatible with HVCI/VBS.
 */
#include "monitor.h"
#include "util.h"
#include "hooks.h"
#include "syscall.h"
#include "trace.h"
#include "guard.h"
#include <intrin.h>
#include "../shared/sysinfo.h"

#define SYSINFO_TAG_MON 'nMoS'
#define MON_RING_EVENTS 8192

/* PatchGuard (0x109, type 1) has caught the NtOpenThread page on this machine.
 * Handle tracking is monitor-only, so it is compiled but not armed by default;
 * the notifications and the four spoofing detours still feed the ring. */
/* Handle tracking detours are OFF in the shipping build: same reason as the
 * trace hooks.  Set to 1 only for a supervised session. */
#define SYSINFO_ENABLE_HANDLE_HOOKS 0

/* ObRegisterCallbacks is the supported way to see handle grants: no text is
 * patched, so PatchGuard has nothing to complain about.  It needs a properly
 * signed image; if this build is only test-signed the call fails harmlessly and
 * callbacks stay 0x7. */
#define SYSINFO_ENABLE_OB_CALLBACKS 1

static KSPIN_LOCK        g_Lock;
static SYSINFO_MON_EVENT *g_Ring;
static ULONG             g_Cap;
static volatile LONG     g_Head;      /* next write */
static volatile LONG     g_Tail;      /* next read  */
static volatile LONG     g_Enabled;
static volatile LONG     g_PidFilter;
static volatile LONG     g_KernelImages = 1;
static volatile LONG     g_ImageCount;
static CHAR              g_Images[4][SYSINFO_MON_IMAGE_CHARS];
static volatile LONG     g_Dropped;
static BOOLEAN           g_Registered;
static BOOLEAN           g_ProcessNotify;
static BOOLEAN           g_ProcessNotifyEx;
static BOOLEAN           g_ThreadNotify;
static BOOLEAN           g_HandleCallbacks;
static HOOK              g_OpenProcessHook;
static HOOK              g_OpenThreadHook;
static PVOID             g_HandleRegistration;
static NTSTATUS          g_ObStatus;
static volatile LONG     g_OpenCalls;
static volatile LONG     g_OpenEvents;

/* Not in ntddk.h for WDM drivers; exported by ntoskrnl. */
PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);
NTSTATUS NTAPI PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Out_ PEPROCESS *Process);
PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID *BaseOfImage);
NTSYSAPI NTSTATUS NTAPI ObRegisterCallbacks(_In_ POB_CALLBACK_REGISTRATION Registration,
                                            _Out_ PVOID *RegistrationHandle);
NTSYSAPI VOID NTAPI ObUnRegisterCallbacks(_In_ PVOID RegistrationHandle);
PEPROCESS NTAPI IoThreadToProcess(_In_ PETHREAD Thread);
PVOID NTAPI PsGetThreadTeb(_In_ PETHREAD Thread);

/* ---------------------------------------------------------------- helpers */

static VOID
CopyImageName(_Out_writes_(SYSINFO_MON_IMAGE_CHARS) CHAR *out)
{
    PCHAR name = PsGetProcessImageFileName(PsGetCurrentProcess());
    ULONG i;

    RtlZeroMemory(out, SYSINFO_MON_IMAGE_CHARS);
    if (name == NULL) return;
    for (i = 0; i + 1 < SYSINFO_MON_IMAGE_CHARS && name[i] != 0; i++) out[i] = name[i];
}

static VOID
CopyAscii(_Out_writes_(chars) CHAR *out, _In_ ULONG chars, _In_opt_ PCSTR text)
{
    ULONG i;

    RtlZeroMemory(out, chars);
    if (text == NULL) return;
    for (i = 0; i + 1 < chars && text[i] != 0; i++) out[i] = text[i];
}

static VOID
CopyPath(_Out_writes_(SYSINFO_MON_MAX_PATH) WCHAR *out, _In_opt_ PCUNICODE_STRING path)
{
    ULONG chars;

    RtlZeroMemory(out, SYSINFO_MON_MAX_PATH * sizeof(WCHAR));
    if (path == NULL || path->Buffer == NULL) return;

    chars = path->Length / sizeof(WCHAR);
    if (chars > SYSINFO_MON_MAX_PATH - 1) chars = SYSINFO_MON_MAX_PATH - 1;
    RtlCopyMemory(out, path->Buffer, chars * sizeof(WCHAR));
}

/* ------------------------------------------------------------- ring buffer */

/*
 * Was this call made from kernel mode (a driver calling Zw or Nt), and can we
 * name the driver that made it?
 *
 * ExGetPreviousMode() is exact: it says whether the syscall came from user or
 * kernel mode.  For a kernel-mode caller the return address into that driver is
 * still on this stack (a kernel-mode syscall runs on the caller's stack), so a
 * short, bounded scan finds the first frame that lives outside ntoskrnl and
 * outside this driver.  We deliberately do not scan for user-mode calls: the
 * only return addresses there belong to ntoskrnl and the caller's user stack.
 */
static ULONG64 g_NtBase;
static ULONG64 g_NtEnd;
static ULONG64 g_SelfBase;

static ULONG64 CaptureKernelCaller(_Out_ BOOLEAN *fromKernel);

static VOID
InitCallerBases(VOID)
{
    PVOID base = NULL;

    if (g_NtBase == 0) {
        /* Calibration already found ntoskrnl; fall back to the loader. */
        g_NtBase = (ULONG64)(ULONG_PTR)SysinfoNtImageBase();
        if (g_NtBase != 0) {
            g_NtEnd = g_NtBase + SysinfoNtImageSize();
        } else if (RtlPcToFileHeader((PVOID)PsLookupProcessByProcessId, &base) && base != NULL) {
            g_NtBase = (ULONG64)(ULONG_PTR)base;
            g_NtEnd = g_NtBase + 0x2000000;      /* generous bound */
        }
    }
    base = NULL;
    if (g_SelfBase == 0 &&
        RtlPcToFileHeader((PVOID)CaptureKernelCaller, &base) && base != NULL) {
        g_SelfBase = (ULONG64)(ULONG_PTR)base;
    }
}

static ULONG64
CaptureKernelCaller(_Out_ BOOLEAN *fromKernel)
{
    PULONG_PTR slot, limit;
    ULONG i;
    PVOID base;
    ULONG64 found = 0;
    ULONG_PTR low = 0, high = 0;

    *fromKernel = (ExGetPreviousMode() == KernelMode);

    InitCallerBases();

    /*
     * Bounded by the real stack limits: the kernel stack ends in a guard page,
     * and walking into it raises an exception.  This runs for every event, so a
     * fault here would be both a bugcheck and a per-event cost.
     */
    IoGetStackLimits(&low, &high);
    slot = (PULONG_PTR)_AddressOfReturnAddress();
    if (slot == NULL || high <= (ULONG_PTR)slot) return 0;
    limit = (PULONG_PTR)(high - sizeof(ULONG_PTR));

    __try {
        for (i = 0; i < 0x800 / sizeof(ULONG_PTR); i++) {
            PULONG_PTR cur = slot + i;
            ULONG_PTR value;

            if (cur > limit) break;
            value = *cur;

            if (value < 0xFFFF800000000000ULL) continue;      /* user address */
            if (value >= g_NtBase && value < g_NtEnd) continue;  /* ntoskrnl */
            base = NULL;
            if (!RtlPcToFileHeader((PVOID)value, &base) || base == NULL) continue;
            if ((ULONG_PTR)base == g_SelfBase) continue;
            found = (ULONG64)value;
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        found = 0;
    }
    return found;
}

/* ------------------------------------------------------- caller attribution */

/*
 * Which module did the call come from?
 *
 * A user->kernel transition leaves a KTRAP_FRAME at the top of this thread's
 * kernel stack, holding the user-mode RIP that made the syscall.  We do not
 * hard-code the frame offsets; instead we scan upward from the current stack
 * pointer for the frame's unmistakable tail - a user RIP followed by SegCs
 * 0x33 and, four slots later, SegSs 0x2b.
 *
 * The owning module comes from the current process's PEB load list, which is
 * the only way to tell a DLL inside a host process (grap64.dll, say) from the
 * process image itself.
 */

typedef struct _SYSINFO_TRAP_TAIL {
    ULONG64 Rip;
    ULONG64 SegCs;
    ULONG64 EFlags;
    ULONG64 Rsp;
    ULONG64 SegSs;
} SYSINFO_TRAP_TAIL;

typedef struct _SYSINFO_LDR_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    ULONG          Pad;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} SYSINFO_LDR_ENTRY, *PSYSINFO_LDR_ENTRY;

typedef struct _SYSINFO_LDR_DATA {
    ULONG      Length;
    ULONG      Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} SYSINFO_LDR_DATA, *PSYSINFO_LDR_DATA;

#define SYSINFO_PEB_LDR_OFFSET 0x18
#define SYSINFO_TEB_PEB_OFFSET 0x60
#define SYSINFO_USER_LIMIT     0x0000800000000000ULL

static ULONG64
CaptureUserRip(VOID)
{
    ULONG_PTR low = 0, high = 0;
    PULONG_PTR slot, floor;
    ULONG steps = 0;
    ULONG64 rip = 0;

    /*
     * The trap frame sits at the top of the kernel stack, so search downward
     * from there instead of walking the whole stack up from here: the first
     * few slots usually hit.  The cap covers a stack that has been extended by
     * nested interrupts.
     */
    IoGetStackLimits(&low, &high);
    floor = (PULONG_PTR)_AddressOfReturnAddress();
    if (floor == NULL || high <= sizeof(SYSINFO_TRAP_TAIL)) return 0;

    slot = (PULONG_PTR)(high - sizeof(SYSINFO_TRAP_TAIL));
    if (slot < floor) slot = floor;

    __try {
        for (; slot >= floor && steps < 512; slot--, steps++) {
            ULONG64 pc = (ULONG64)slot[0];

            if (pc < 0x10000ULL || pc >= SYSINFO_USER_LIMIT) continue;
            if (slot[1] != 0x33ULL) continue;      /* user code selector */
            if (slot[4] != 0x2bULL) continue;      /* user stack selector */
            rip = pc;
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        rip = 0;
    }
    return rip;
}

static VOID
ModuleNameFor(_In_ ULONG64 Rip, _Out_writes_(SYSINFO_MON_MODULE_CHARS) CHAR *out)
{
    PVOID teb;
    PVOID peb;
    PSYSINFO_LDR_DATA ldr;
    PLIST_ENTRY head, link;
    ULONG guard = 0;

    RtlZeroMemory(out, SYSINFO_MON_MODULE_CHARS);
    if (Rip == 0) return;

    teb = PsGetThreadTeb((PETHREAD)KeGetCurrentThread());
    if (teb == NULL) return;

    __try {
        peb = *(PVOID *)((PUCHAR)teb + SYSINFO_TEB_PEB_OFFSET);
        if (peb == NULL) return;
        ldr = *(PSYSINFO_LDR_DATA *)((PUCHAR)peb + SYSINFO_PEB_LDR_OFFSET);
        if (ldr == NULL) return;

        head = &ldr->InLoadOrderModuleList;
        for (link = head->Flink; link != head && guard++ < 512; link = link->Flink) {
            PSYSINFO_LDR_ENTRY entry = (PSYSINFO_LDR_ENTRY)link;
            ULONG_PTR base = (ULONG_PTR)entry->DllBase;
            ULONG imageSize = entry->SizeOfImage;
            UNICODE_STRING name;
            ULONG i, chars;

            if (base == 0 || imageSize == 0) continue;
            if ((ULONG_PTR)Rip < base || (ULONG_PTR)Rip >= base + imageSize) continue;

            name = entry->BaseDllName;
            if (name.Buffer == NULL || name.Length == 0) return;
            chars = name.Length / sizeof(WCHAR);
            if (chars > SYSINFO_MON_MODULE_CHARS - 1) chars = SYSINFO_MON_MODULE_CHARS - 1;
            for (i = 0; i < chars; i++) out[i] = (CHAR)(name.Buffer[i] & 0x7F);
            return;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(out, SYSINFO_MON_MODULE_CHARS);
    }
}

/* --------------------------------------------------------------- summary */

static PSYSINFO_SUMMARY_ENTRY g_Sum;
static KSPIN_LOCK             g_SumLock;
static volatile LONG          g_SumTotal;
static volatile LONG          g_SumOverflow;
static volatile LONG          g_SumSuppressed;
static ULONG                  g_Types;
static ULONG                  g_IgnoreCount;
static ULONG                  g_IgnoreRelative;
static ULONG                  g_IoctlDump;
static WCHAR                  g_IoctlMatch[32];
static WCHAR                  g_Ignore[4][SYSINFO_MON_IGNORE_CHARS];
static ULONG                  g_LastHash;
static ULONG64                g_LastStamp;

#define SYSINFO_FOLD_WINDOW 2000000ULL   /* 200 ms, in 100 ns units */

static BOOLEAN
ContainsWideNoCase(_In_ const WCHAR *text, _In_ const WCHAR *needle)
{
    ULONG i, j;

    if (text == NULL || needle == NULL || needle[0] == 0) return FALSE;
    for (i = 0; text[i] != 0; i++) {
        for (j = 0; needle[j] != 0; j++) {
            WCHAR a = text[i + j];
            if (a == 0) return FALSE;
            if (RtlUpcaseUnicodeChar(a) != RtlUpcaseUnicodeChar(needle[j])) break;
        }
        if (needle[j] == 0) return TRUE;
    }
    return FALSE;
}

/*
 * Should this subject stay out of the summary?  Configured with substrings that
 * do not depend on the drive letter, because the same file arrives as \??\C:\...,
 * \Device\HarddiskVolume3\... and relative to the program's directory.
 */
static BOOLEAN
SummaryIgnored(_In_ const WCHAR *subject)
{
    ULONG i;

    if (subject[0] == 0) return TRUE;

    for (i = 0; i < g_IgnoreCount && i < RTL_NUMBER_OF(g_Ignore); i++) {
        if (ContainsWideNoCase(subject, g_Ignore[i])) return TRUE;
    }
    return FALSE;
}

/*
 * A name relative to the program's directory is the program's own file.  Keep
 * the information but collapse the tail: "Data\Packs\Skill_00001.ms" becomes
 * "Data\..." and a debug-symbol probe "ntdll.pdb" becomes "*.pdb".  Names with
 * neither a separator nor a .pdb suffix are short and unique enough to keep.
 */
static VOID
FoldRelative(_Inout_updates_(chars) WCHAR *subject, _In_ ULONG chars)
{
    ULONG i, n;

    if (subject[0] == L'\\') return;
    if (subject[0] != 0 && subject[1] == L':') return;

    for (i = 0; subject[i] != 0; i++) {
        if (subject[i] == L'\\') {
            if (i + 4 < chars) {
                subject[i]     = L'\\';
                subject[i + 1] = L'.';
                subject[i + 2] = L'.';
                subject[i + 3] = L'.';
                subject[i + 4] = 0;
            } else {
                subject[i] = 0;
            }
            return;
        }
    }

    if (i < 4) return;
    if (RtlUpcaseUnicodeChar(subject[i - 4]) != L'.') return;
    if (RtlUpcaseUnicodeChar(subject[i - 3]) != L'P') return;
    if (RtlUpcaseUnicodeChar(subject[i - 2]) != L'D') return;
    if (RtlUpcaseUnicodeChar(subject[i - 1]) != L'B') return;

    for (n = 0; n < 5 && n + 1 < chars; n++) subject[n] = L"*.pdb"[n];
    subject[n] = 0;
}

static ULONG
SumHash(_In_ ULONG Type, _In_ ULONG Pid, _In_ const WCHAR *Subject)
{
    ULONG hash = 2166136261u;
    ULONG i;

    hash = (hash ^ Type) * 16777619u;
    hash = (hash ^ Pid) * 16777619u;
    for (i = 0; Subject[i] != 0 && i < SYSINFO_SUMMARY_SUBJECT; i++) {
        hash = (hash ^ (ULONG)(USHORT)Subject[i]) * 16777619u;
    }
    return hash | 1u;      /* 0 means empty */
}

static VOID
SumAppend(_Inout_updates_(chars) WCHAR *out, _In_ ULONG chars, _Inout_ PULONG pos, _In_ const WCHAR *text)
{
    while (text != NULL && *text != 0 && *pos + 1 < chars) out[(*pos)++] = *text++;
    out[*pos] = 0;
}

static VOID
SumAppendAscii(_Inout_updates_(chars) WCHAR *out, _In_ ULONG chars, _Inout_ PULONG pos, _In_opt_ PCSTR text)
{
    while (text != NULL && *text != 0 && *pos + 1 < chars) out[(*pos)++] = (WCHAR)(UCHAR)*text++;
    out[*pos] = 0;
}

static VOID
SumAppendDec(_Inout_updates_(chars) WCHAR *out, _In_ ULONG chars, _Inout_ PULONG pos, _In_ ULONG value)
{
    WCHAR tmp[12];
    ULONG n = 0;

    if (value == 0) { tmp[n++] = L'0'; }
    while (value != 0 && n < RTL_NUMBER_OF(tmp)) { tmp[n++] = (WCHAR)(L'0' + (value % 10)); value /= 10; }
    while (n > 0 && *pos + 1 < chars) out[(*pos)++] = tmp[--n];
    out[*pos] = 0;
}

static VOID
SumAppendHex(_Inout_updates_(chars) WCHAR *out, _In_ ULONG chars, _Inout_ PULONG pos, _In_ ULONG value)
{
    static const WCHAR digits[] = L"0123456789ABCDEF";
    WCHAR tmp[10];
    ULONG n = 0;

    do { tmp[n++] = digits[value & 0xF]; value >>= 4; } while (value != 0 && n < RTL_NUMBER_OF(tmp));
    while (n > 0 && *pos + 1 < chars) out[(*pos)++] = tmp[--n];
    out[*pos] = 0;
}

static BOOLEAN
ContainsAscii(_In_opt_ PCSTR haystack, _In_ PCSTR needle)
{
    ULONG i, j;

    if (haystack == NULL || needle == NULL || needle[0] == 0) return FALSE;
    for (i = 0; haystack[i] != 0; i++) {
        for (j = 0; needle[j] != 0; j++) {
            CHAR a = haystack[i + j];
            if (a == 0) return FALSE;
            if (a >= 'a' && a <= 'z') a = (CHAR)(a - 32);
            if (a != needle[j]) break;
        }
        if (needle[j] == 0) return TRUE;
    }
    return FALSE;
}

static BOOLEAN
AsciiPrefixNoCase(_In_opt_ PCSTR text, _In_ PCSTR prefix)
{
    ULONG i;

    if (text == NULL || prefix == NULL) return FALSE;
    for (i = 0; prefix[i] != 0; i++) {
        CHAR a = text[i];
        if (a >= 'a' && a <= 'z') a = (CHAR)(a - 32);
        if (a != prefix[i]) return FALSE;
    }
    return TRUE;
}

/*
 * Turn an event into the thing it is worth remembering: a path, plus the part
 * that changes the meaning (which value was read, which target process).
 */
static VOID
SumSubject(_In_ const SYSINFO_MON_EVENT *event, _Out_writes_(chars) WCHAR *out, _In_ ULONG chars)
{
    ULONG type = event->Type & 0x0FFFFFFFu;
    ULONG pos = 0;

    RtlZeroMemory(out, chars * sizeof(WCHAR));

    if (type == SYSINFO_MON_MEM) {
        /* detail is "pid 9304 read 0x...": keep everything before the address */
        ULONG i;

        for (i = 0; event->Detail[i] != 0 && i + 1 < chars; i++) {
            if (event->Detail[i] == '0' && event->Detail[i + 1] == 'x') break;
            out[pos++] = (WCHAR)(UCHAR)event->Detail[i];
        }
        while (pos > 0 && out[pos - 1] == L' ') pos--;
        out[pos] = 0;
        return;
    }

    if (event->Path[0] != 0) {
        ULONG i = 0;

        while (event->Path[i] != 0 && pos + 1 < chars) out[pos++] = event->Path[i++];
        out[pos] = 0;

        if (type == SYSINFO_MON_REG) {
            SumAppend(out, chars, &pos, L" | value ");
            SumAppendAscii(out, chars, &pos, event->Detail);
        } else if (type == SYSINFO_MON_KEY) {
            SumAppend(out, chars, &pos, L" | ");
            SumAppendAscii(out, chars, &pos, event->Detail);   /* open/create/set/delete */
        } else if (event->Detail[0] != 0) {
            SumAppend(out, chars, &pos, L" | ");
            SumAppendAscii(out, chars, &pos, event->Detail);
        }
        return;
    }

    if (type == SYSINFO_MON_HANDLE) {
        /* "AUDIT handle chrome.exe" and "DENY handle chrome.exe" are the same
         * observation; the action belongs to the guard counter, not the key. */
        PCSTR detail = event->Detail;

        if (AsciiPrefixNoCase(detail, "AUDIT ")) detail += 6;
        else if (AsciiPrefixNoCase(detail, "DENY ")) detail += 5;

        SumAppend(out, chars, &pos, L"handle ");
        SumAppendAscii(out, chars, &pos, detail);
        return;
    }

    if (type == SYSINFO_MON_SYSINFO) {
        SumAppend(out, chars, &pos, L"class ");
        SumAppendDec(out, chars, &pos, event->Op);
        return;
    }
    if (type == SYSINFO_MON_IOCTL) {
        SumAppend(out, chars, &pos, L"code 0x");
        SumAppendHex(out, chars, &pos, event->Op);
        return;
    }

    SumAppendAscii(out, chars, &pos, event->Detail);
}

static VOID
SummaryAdd(_In_ const SYSINFO_MON_EVENT *event, _In_ const WCHAR *subject)
{
    ULONG type = event->Type & 0x0FFFFFFFu;
    ULONG maxProbe = SYSINFO_SUMMARY_SLOTS;
    ULONG hash, slot, probe;

    if (g_Sum == NULL || subject[0] == 0) return;

    /* Only real paths are subject to the fold rules; "pid 9304 read" is not. */
    if ((type == SYSINFO_MON_FILE || type == SYSINFO_MON_KEY || type == SYSINFO_MON_REG) &&
        SummaryIgnored(subject)) {
        InterlockedIncrement(&g_SumSuppressed);
        return;
    }

    /*
     * A full table cannot take a new subject anyway.  Probing all 8192 slots for
     * one would take and release the lock 8192 times per event, which is a lock
     * storm at exactly the moment the system is busiest - so once full, probe a
     * bounded window and count the rest as overflow.
     */
    if ((ULONG)g_SumTotal >= SYSINFO_SUMMARY_SLOTS) maxProbe = 64;

    hash = SumHash(type, event->Pid, subject);

    for (probe = 0; probe < maxProbe; probe++) {
        KIRQL irql;
        PSYSINFO_SUMMARY_ENTRY entry;

        slot = (hash + probe) % SYSINFO_SUMMARY_SLOTS;
        KeAcquireSpinLock(&g_SumLock, &irql);
        entry = &g_Sum[slot];

        if (entry->Count == 0) {
            ULONG i;

            RtlZeroMemory(entry, sizeof(*entry));
            entry->First = event->Stamp;
            entry->Last = event->Stamp;
            entry->Pid = event->Pid;
            entry->Type = event->Type & 0x0FFFFFFFu;
            entry->Access = event->Op;
            RtlCopyMemory(entry->Image, event->Image, sizeof(entry->Image));
            RtlCopyMemory(entry->Module, event->Module, sizeof(entry->Module));
            for (i = 0; i + 1 < SYSINFO_SUMMARY_SUBJECT && subject[i] != 0; i++) {
                entry->Subject[i] = subject[i];
            }
            entry->Subject[i] = 0;
            entry->Count = 1;
            InterlockedIncrement(&g_SumTotal);
            KeReleaseSpinLock(&g_SumLock, irql);
            return;
        }

        if ((entry->Type == (event->Type & 0x0FFFFFFFu)) &&
            entry->Pid == event->Pid &&
            entry->Subject[0] == subject[0] &&
            RtlEqualMemory(entry->Subject, subject, sizeof(subject))) {
            entry->Count++;
            entry->Last = event->Stamp;
            entry->Access = event->Op;
            KeReleaseSpinLock(&g_SumLock, irql);
            return;
        }
        KeReleaseSpinLock(&g_SumLock, irql);
    }

    InterlockedIncrement(&g_SumOverflow);
}

NTSTATUS
MonSummary(_In_reads_bytes_(inLen) PVOID inBuffer, _In_ ULONG inLen,
           _Out_writes_bytes_(outLength) PVOID outBuffer, _In_ ULONG outLength)
{
    PSYSINFO_SUMMARY_REQ req = (PSYSINFO_SUMMARY_REQ)inBuffer;
    PSYSINFO_SUMMARY_HEAD head = (PSYSINFO_SUMMARY_HEAD)outBuffer;
    PSYSINFO_SUMMARY_ENTRY entries;
    ULONG start, max, room, i, count = 0;

    if (inBuffer == NULL || inLen < sizeof(*req)) return STATUS_INVALID_PARAMETER;
    if (outBuffer == NULL || outLength < sizeof(*head)) return STATUS_BUFFER_TOO_SMALL;

    start = req->Start;
    max = req->Max;
    if (max == 0 || max > SYSINFO_SUMMARY_BATCH) max = SYSINFO_SUMMARY_BATCH;
    if (start >= SYSINFO_SUMMARY_SLOTS) start = 0;

    room = (outLength - sizeof(*head)) / sizeof(SYSINFO_SUMMARY_ENTRY);
    if (max > room) max = room;

    entries = (PSYSINFO_SUMMARY_ENTRY)(head + 1);
    for (i = start; i < SYSINFO_SUMMARY_SLOTS && count < max; i++) {
        if (g_Sum != NULL && g_Sum[i].Count != 0) {
            entries[count++] = g_Sum[i];
        }
    }

    head->AbiVersion = SYSINFO_ABI_VERSION;
    head->Total = (ULONG)g_SumTotal;
    head->Overflow = (ULONG)g_SumOverflow;
    head->Suppressed = (ULONG)g_SumSuppressed;
    head->Count = count;
    head->Next = (i >= SYSINFO_SUMMARY_SLOTS) ? 0 : i;
    return STATUS_SUCCESS;
}

/* pid/tid of 0 means "the current process/thread". */
static VOID
PushEvent(_In_ ULONG type, _In_ ULONG op, _In_opt_ PCUNICODE_STRING path,
          _In_opt_ PCSTR detail, _In_ ULONG pidOverride, _In_ ULONG tidOverride,
          _In_ ULONG64 caller, _In_opt_ PCSTR imageOverride)
{
    SYSINFO_MON_EVENT event;
    WCHAR subject[SYSINFO_SUMMARY_SUBJECT];
    ULONG hash = 0;
    KIRQL irql;
    ULONG head, next;

    if (g_Ring == NULL) return;

    RtlZeroMemory(&event, sizeof(event));
    {
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);
        event.Stamp = (ULONG64)now.QuadPart;
    }
    event.Type = type;
    event.Pid = (pidOverride != 0) ? pidOverride : (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    event.Tid = (tidOverride != 0) ? tidOverride : (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    event.Op = op;
    event.Caller = caller;
    event.UserCaller = CaptureUserRip();
    ModuleNameFor(event.UserCaller, event.Module);
    if (imageOverride != NULL) {
        CopyAscii(event.Image, SYSINFO_MON_IMAGE_CHARS, imageOverride);
    } else {
        CopyImageName(event.Image);
    }
    CopyAscii(event.Detail, SYSINFO_MON_MAX_DETAIL, detail);
    CopyPath(event.Path, path);

    /* The summary sees every type and every occurrence. */
    SumSubject(&event, subject, RTL_NUMBER_OF(subject));
    if (g_IgnoreRelative != 0 &&
        (type == SYSINFO_MON_FILE || type == SYSINFO_MON_KEY || type == SYSINFO_MON_REG)) {
        FoldRelative(subject, RTL_NUMBER_OF(subject));
    }
    SummaryAdd(&event, subject);

    if (g_Types != 0 && (g_Types & (1u << ((type & 0x0FFFFFFFu) - 1))) == 0) return;
    if (subject[0] != 0) hash = SumHash(type & 0x0FFFFFFFu, event.Pid, subject);

    KeAcquireSpinLock(&g_Lock, &irql);

    /*
     * Fold a burst of the same thing into one row with a repeat count instead
     * of letting it evict everything else from the ring.
     */
    if (hash != 0 && hash == g_LastHash && g_Head != g_Tail &&
        (event.Stamp - g_LastStamp) < SYSINFO_FOLD_WINDOW) {
        ULONG prev = ((ULONG)g_Head + g_Cap - 1) % g_Cap;

        if (g_Ring[prev].Repeat < 0x00FFFFFF) {
            g_Ring[prev].Repeat++;
            g_LastStamp = event.Stamp;
            KeReleaseSpinLock(&g_Lock, irql);
            return;
        }
    }

    head = (ULONG)g_Head;
    next = (head + 1) % g_Cap;
    if (next == (ULONG)g_Tail) {
        /* full: drop the oldest */
        g_Tail = ((ULONG)g_Tail + 1) % g_Cap;
        InterlockedIncrement(&g_Dropped);
    }
    g_Ring[head] = event;
    g_Head = (LONG)next;
    g_LastHash = hash;
    g_LastStamp = event.Stamp;
    KeReleaseSpinLock(&g_Lock, irql);
}

/* Case-insensitive prefix match, tolerant of the kernel's 15-char truncation. */
static BOOLEAN
ImageMatch(_In_opt_ PCSTR image)
{
    ULONG i, n;

    if (image == NULL || image[0] == 0) return FALSE;
    for (n = 0; n < (ULONG)g_ImageCount && n < RTL_NUMBER_OF(g_Images); n++) {
        for (i = 0; i < SYSINFO_MON_IMAGE_CHARS; i++) {
            CHAR a = image[i];
            CHAR b = g_Images[n][i];

            if (a == 0 || b == 0) {
                if (i >= 6) return TRUE;
                break;
            }
            if (a >= 'a' && a <= 'z') a = (CHAR)(a - 32);
            if (b >= 'a' && b <= 'z') b = (CHAR)(b - 32);
            if (a != b) break;
        }
    }
    return FALSE;
}

/* Should events for this process id be recorded? */
static BOOLEAN
MonWantsPid(_In_ HANDLE ProcessId)
{
    PEPROCESS process = NULL;
    BOOLEAN wanted = FALSE;

    if (g_PidFilter != 0) return (ULONG)(ULONG_PTR)ProcessId == (ULONG)g_PidFilter;
    if (g_ImageCount == 0) return TRUE;

    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process)) && process != NULL) {
        wanted = ImageMatch(PsGetProcessImageFileName(process));
        ObDereferenceObject(process);
    }
    return wanted;
}

VOID
MonEvent(_In_ ULONG type, _In_ ULONG op, _In_opt_ PCUNICODE_STRING path,
         _In_opt_ PCSTR detail)
{
    BOOLEAN fromKernel;
    ULONG64 caller;

    if (!MonActive()) return;

    /*
     * Scanned even for user-mode calls: a driver can dispatch an IOCTL in this
     * thread and call Nt* directly, which leaves PreviousMode == User.  A frame
     * inside a driver image below us is the only evidence of that.
     */
    caller = CaptureKernelCaller(&fromKernel);
    if (fromKernel) {
        type |= SYSINFO_MON_KCALL;
    } else if (caller != 0) {
        type |= SYSINFO_MON_KSTACK;
    }

    PushEvent(type, op, path, detail, 0, 0, caller, NULL);
}

VOID
MonDiag(_Out_writes_(SYSINFO_DIAG_COUNT) PULONG64 diag)
{
    ULONG pending = 0;

    if (g_Ring != NULL) pending = ((ULONG)g_Head + g_Cap - (ULONG)g_Tail) % g_Cap;

    diag[SYSINFO_DIAG_MON_ENABLED] = (ULONG64)(ULONG)g_Enabled;
    diag[SYSINFO_DIAG_MON_EVENTS] = pending;
    diag[SYSINFO_DIAG_MON_DROPPED] = (ULONG64)(ULONG)g_Dropped;
    diag[SYSINFO_DIAG_OB_STATUS] = (ULONG)g_ObStatus;
    diag[SYSINFO_DIAG_MON_HOOKS] = (ULONG)((g_Registered ? 1u : 0u) |
                                            (g_ProcessNotify ? 2u : 0u) |
                                            (g_ThreadNotify ? 4u : 0u) |
                                            (g_HandleCallbacks ? 8u : 0u));
    diag[SYSINFO_DIAG_MON_OPEN] = (ULONG64)(ULONG)g_OpenCalls;
    diag[SYSINFO_DIAG_MON_OPEN_EV] = (ULONG64)(ULONG)g_OpenEvents;
}

/* IOCTL payload capture: which devices, and how many bytes. */
BOOLEAN
MonIoctlWanted(_In_opt_ PCUNICODE_STRING device)
{
    ULONG i, j;

    if (g_IoctlDump == 0) return FALSE;
    if (g_IoctlMatch[0] == 0) return TRUE;
    if (device == NULL || device->Buffer == NULL) return FALSE;

    for (i = 0; i + 1 <= device->Length / sizeof(WCHAR); i++) {
        for (j = 0; g_IoctlMatch[j] != 0; j++) {
            if (i + j >= device->Length / sizeof(WCHAR)) break;
            if (RtlUpcaseUnicodeChar(device->Buffer[i + j]) !=
                RtlUpcaseUnicodeChar(g_IoctlMatch[j])) break;
        }
        if (g_IoctlMatch[j] == 0) return TRUE;
    }
    return FALSE;
}

ULONG
MonIoctlBytes(VOID)
{
    return g_IoctlDump;
}

BOOLEAN
MonActive(VOID)
{
    if (g_Enabled == 0 || g_Ring == NULL) return FALSE;
    if (g_PidFilter != 0) {
        return (ULONG)(ULONG_PTR)PsGetCurrentProcessId() == (ULONG)g_PidFilter;
    }
    if (g_ImageCount != 0) {
        return ImageMatch(PsGetProcessImageFileName(PsGetCurrentProcess()));
    }
    return TRUE;
}

/*
 * Ring-0 memory work has no dependable process context: an IOCTL can be
 * queued to a system thread.  These events are therefore recorded whenever
 * monitoring is on, without the pid/image filter - they are rare, and losing
 * them is exactly the blind spot the hooks were added to close.
 */
VOID
MonEventForced(_In_ ULONG type, _In_ ULONG op, _In_opt_ PCUNICODE_STRING path,
               _In_opt_ PCSTR detail)
{
    BOOLEAN fromKernel;
    ULONG64 caller;

    if (g_Enabled == 0 || g_Ring == NULL) return;

    caller = CaptureKernelCaller(&fromKernel);
    if (fromKernel) {
        type |= SYSINFO_MON_KCALL;
    } else if (caller != 0) {
        type |= SYSINFO_MON_KSTACK;
    }

    PushEvent(type, op, path, detail, 0, 0, caller, NULL);
}

/* ------------------------------------------------------------ notifications */

static VOID
ImageNotify(_In_opt_ PUNICODE_STRING fullImageName, _In_ HANDLE processId,
            _In_ PIMAGE_INFO imageInfo)
{
    CHAR detail[40];
    ULONG len = 0;
    ULONG type = SYSINFO_MON_IMAGE;
    ULONG op = 0;

    if (g_Enabled == 0 || g_Ring == NULL) return;

    if (imageInfo != NULL && imageInfo->SystemModeImage) {
        /* Kernel images have no user process, so the image filter cannot apply:
         * a driver the target loads is exactly what we must not miss. */
        if (g_KernelImages == 0) return;
        op |= SYSINFO_MON_KERNEL;
    } else if (!MonWantsPid(processId)) {
        return;
    }

    /* base/size are the useful part for a driver: lets you map it later */
    detail[len++] = 'b'; detail[len++] = '=';
    {
        ULONG_PTR base = (imageInfo != NULL) ? (ULONG_PTR)imageInfo->ImageBase : 0;
        const char hex[] = "0123456789ABCDEF";
        int shift;
        for (shift = (int)(sizeof(base) * 8) - 4; shift >= 0; shift -= 4) {
            detail[len++] = hex[(base >> shift) & 0xF];
            if (len >= 19) break;
        }
    }
    detail[len] = 0;

    /* Image loads can be at PASSIVE or DISPATCH; Push only needs a spinlock. */
    PushEvent(type, op, fullImageName, detail, 0, 0, 0, NULL);
}

/* Only compiled in if the WDK exposes the Ex routine; see MonInit(). */
static VOID
ProcessNotifyEx(_In_ PEPROCESS Process, _In_ HANDLE ProcessId,
                _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    PCHAR image;

    if (g_Enabled == 0 || g_Ring == NULL) return;
    if (g_PidFilter != 0) {
        if ((ULONG)(ULONG_PTR)ProcessId != (ULONG)g_PidFilter) return;
    } else if (g_ImageCount != 0 && !ImageMatch(PsGetProcessImageFileName(Process))) {
        return;
    }

    image = PsGetProcessImageFileName(Process);
    if (CreateInfo == NULL) {
        PushEvent(SYSINFO_MON_PROCESS, 0, NULL, "exit", (ULONG)(ULONG_PTR)ProcessId, 0, 0, image);
    } else {
        PushEvent(SYSINFO_MON_PROCESS, 1, CreateInfo->ImageFileName, "create",
                  (ULONG)(ULONG_PTR)ProcessId, 0, 0, image);
    }
}

/*
 * Process/thread handle grants: this is how a program gets at another
 * process's memory (PROCESS_VM_READ / PROCESS_VM_WRITE / CREATE_THREAD ...).
 * The event shows the *caller* in Pid/Image and the target in Tid/Detail.
 */
static VOID
LogHandleGrant(_In_ NTSTATUS status, _In_ ACCESS_MASK access, _In_ ULONG targetPid)
{
    CHAR      detail[SYSINFO_MON_MAX_DETAIL];
    CHAR      image[64];
    PEPROCESS target = NULL;
    ULONG     n = 0, i = 0, v;

    RtlZeroMemory(image, sizeof(image));
    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)targetPid, &target)) &&
        target != NULL) {
        CopyAscii(image, sizeof(image), PsGetProcessImageFileName(target));
        ObDereferenceObject(target);
    }
    if (image[0] == 0) CopyAscii(image, sizeof(image), "?");

    /* "<image> (pid <n>)" in the detail field, prefixed with "failed " if the
     * open was refused - a program probing for access shows up that way too. */
    if (!NT_SUCCESS(status)) {
        detail[n++] = 'f'; detail[n++] = 'a'; detail[n++] = 'i';
        detail[n++] = 'l'; detail[n++] = 'e'; detail[n++] = 'd'; detail[n++] = ' ';
    }
    while (image[i] != 0 && n + 5 < sizeof(detail)) detail[n++] = image[i++];
    detail[n++] = ' ';
    detail[n++] = '(';
    {
        char num[12];
        int  k, len = 0;

        v = targetPid;
        if (v == 0) num[len++] = '0';
        while (v > 0) { num[len++] = (char)('0' + (v % 10)); v /= 10; }
        for (k = len - 1; k >= 0 && n + 1 < sizeof(detail); k--) detail[n++] = num[k];
    }
    if (n + 1 < sizeof(detail)) detail[n++] = ')';
    detail[n] = 0;

    PushEvent(SYSINFO_MON_HANDLE, (ULONG)access, NULL, detail, 0, targetPid, 0, NULL);
}

typedef NTSTATUS (NTAPI *PFN_NtOpenProcess)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId);

/*
 * ObRegisterCallbacks() needs a properly signed image, so hook NtOpenProcess
 * instead.  It is the documented choke point for a program reaching into
 * another process, it runs at PASSIVE_LEVEL, and it needs no privilege.
 * NtOpenThread is covered as well - thread handles give suspend/context
 * control, which is how injection starts.
 */
static NTSTATUS NTAPI
OpenProcessHook(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId)
{
    PFN_NtOpenProcess original = (PFN_NtOpenProcess)g_OpenProcessHook.Trampoline;
    NTSTATUS status;

    HookEnter();
    InterlockedIncrement(&g_OpenCalls);

    if (ClientId != NULL && GuardProcessHandleBlocked(ClientId->UniqueProcess, DesiredAccess)) {
        HookLeave();
        return STATUS_ACCESS_DENIED;
    }

    status = original(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

    if (MonActive()) {
        ULONG targetPid = 0;

        if (ClientId != NULL) targetPid = (ULONG)(ULONG_PTR)ClientId->UniqueProcess;
        InterlockedIncrement(&g_OpenEvents);
        LogHandleGrant(status, DesiredAccess, targetPid);
    }

    HookLeave();
    return status;
}

typedef NTSTATUS (NTAPI *PFN_NtOpenThread)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId);

static NTSTATUS NTAPI
OpenThreadHook(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId)
{
    PFN_NtOpenThread original = (PFN_NtOpenThread)g_OpenThreadHook.Trampoline;
    NTSTATUS status;

    HookEnter();
    InterlockedIncrement(&g_OpenCalls);

    if (ClientId != NULL && GuardProcessHandleBlocked(ClientId->UniqueProcess, DesiredAccess)) {
        HookLeave();
        return STATUS_ACCESS_DENIED;
    }

    status = original(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);

    if (MonActive()) {
        ULONG targetPid = 0;

        if (ClientId != NULL) targetPid = (ULONG)(ULONG_PTR)ClientId->UniqueProcess;
        InterlockedIncrement(&g_OpenEvents);
        LogHandleGrant(status, DesiredAccess, targetPid);
    }

    HookLeave();
    return status;
}

/* Legacy routine: no image name, but the image-load event fills that in. */
static VOID
ProcessNotifyLegacy(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentId);

    if (g_Enabled == 0 || g_Ring == NULL) return;
    if (!MonWantsPid(ProcessId)) return;

    PushEvent(SYSINFO_MON_PROCESS, Create ? 1 : 0, NULL, Create ? "create" : "exit",
              (ULONG)(ULONG_PTR)ProcessId, 0, 0, NULL);
}

static VOID
ThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
    CHAR detail[32];

    if (g_Enabled == 0 || g_Ring == NULL) return;
    if (!MonWantsPid(ProcessId)) return;

    CopyAscii(detail, sizeof(detail), Create ? "create" : "exit");
    PushEvent(SYSINFO_MON_THREAD, (ULONG)(ULONG_PTR)ThreadId, NULL, detail,
              (ULONG)(ULONG_PTR)ProcessId, (ULONG)(ULONG_PTR)ThreadId, 0, NULL);
}

/* ------------------------------------------------------------------- API */

/*
 * Supported handle tracking (no text patching): the object manager calls this
 * before a process/thread handle is granted or duplicated.  The event shows the
 * caller in Pid/Image and the target in Tid/Detail.
 */
static OB_PREOP_CALLBACK_STATUS
HandlePreOp(_In_ PVOID RegistrationContext, _In_ POB_PRE_OPERATION_INFORMATION Info)
{
    ULONG targetPid = 0;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (Info == NULL || Info->Object == NULL || Info->Parameters == NULL) {
        return OB_PREOP_SUCCESS;
    }

    GuardPreHandle(Info);

    if (!MonActive()) return OB_PREOP_SUCCESS;

    if (Info->Operation != OB_OPERATION_HANDLE_CREATE &&
        Info->Operation != OB_OPERATION_HANDLE_DUPLICATE) {
        return OB_PREOP_SUCCESS;
    }

    if (Info->ObjectType == *PsProcessType) {
        targetPid = (ULONG)(ULONG_PTR)PsGetProcessId((PEPROCESS)Info->Object);
    } else if (Info->ObjectType == *PsThreadType) {
        PEPROCESS process = IoThreadToProcess((PETHREAD)Info->Object);
        if (process != NULL) {
            targetPid = (ULONG)(ULONG_PTR)PsGetProcessId(process);
        }
    } else {
        return OB_PREOP_SUCCESS;
    }

    Info->CallContext = (PVOID)(ULONG_PTR)targetPid;
    return OB_PREOP_SUCCESS;
}

static VOID
HandlePostOp(_In_ PVOID RegistrationContext, _In_ POB_POST_OPERATION_INFORMATION Info)
{
    ULONG access = 0;
    ULONG targetPid;
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (Info == NULL) return;
    targetPid = (ULONG)(ULONG_PTR)Info->CallContext;
    if (targetPid == 0) return;
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        access = Info->Parameters->CreateHandleInformation.GrantedAccess;
    } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        access = Info->Parameters->DuplicateHandleInformation.GrantedAccess;
    } else {
        return;
    }
    LogHandleGrant(Info->ReturnStatus, access, targetPid);
}

static NTSTATUS
StartObCallbacks(VOID)
{
    OB_CALLBACK_REGISTRATION registration;
    OB_OPERATION_REGISTRATION operations[2];
    UNICODE_STRING altitude;
    NTSTATUS status;

    RtlZeroMemory(&registration, sizeof(registration));
    RtlZeroMemory(operations, sizeof(operations));
    RtlInitUnicodeString(&altitude, L"321000");

    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = HandlePreOp;
    operations[0].PostOperation = HandlePostOp;

    operations[1].ObjectType = PsThreadType;
    operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[1].PreOperation = HandlePreOp;
    operations[1].PostOperation = HandlePostOp;

    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = 2;
    registration.OperationRegistration = operations;
    registration.Altitude = altitude;

    status = ObRegisterCallbacks(&registration, &g_HandleRegistration);
    g_ObStatus = status;
    if (NT_SUCCESS(status)) {
        g_HandleCallbacks = TRUE;
    } else {
        g_HandleRegistration = NULL;
        DbgPrint("SysInfo: ObRegisterCallbacks failed 0x%08X\n", status);
    }
    return status;
}

static VOID
StartOpenHooks(VOID)
{
    UNICODE_STRING name;
    PVOID target;
    NTSTATUS hookStatus;

    if (g_OpenProcessHook.Installed && g_OpenThreadHook.Installed) return;
    g_HandleCallbacks = TRUE;
    RtlInitUnicodeString(&name, L"NtOpenProcess");
    target = MmGetSystemRoutineAddress(&name);
    if (target == NULL) {
        g_HandleCallbacks = FALSE;
        DbgPrint("SysInfo: NtOpenProcess not found\n");
    } else if (!g_OpenProcessHook.Installed) {
        hookStatus = HookInstall(&g_OpenProcessHook, target, (PVOID)OpenProcessHook,
                                 "NtOpenProcess");
        if (!NT_SUCCESS(hookStatus)) {
            g_HandleCallbacks = FALSE;
            DbgPrint("SysInfo: NtOpenProcess hook failed 0x%08X\n", hookStatus);
        }
    }
    RtlInitUnicodeString(&name, L"NtOpenThread");
    target = MmGetSystemRoutineAddress(&name);
    if (target != NULL && !g_OpenThreadHook.Installed) {
        hookStatus = HookInstall(&g_OpenThreadHook, target, (PVOID)OpenThreadHook,
                                 "NtOpenThread");
        if (!NT_SUCCESS(hookStatus)) {
            DbgPrint("SysInfo: NtOpenThread hook failed 0x%08X\n", hookStatus);
        }
    }
}

static VOID
StopOpenHooks(VOID)
{
    if (g_OpenThreadHook.Installed) HookRemove(&g_OpenThreadHook);
    if (g_OpenProcessHook.Installed) HookRemove(&g_OpenProcessHook);
}

NTSTATUS
MonInit(VOID)
{
    NTSTATUS status;

    if (g_Registered) return STATUS_SUCCESS;

    KeInitializeSpinLock(&g_Lock);

    status = PsSetLoadImageNotifyRoutine(ImageNotify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("SysInfo: PsSetLoadImageNotifyRoutine failed 0x%08X\n", status);
        return status;
    }

    /*
     * The Ex variant is only accepted for drivers with a proper signature, so
     * fall back to the legacy routine when it is refused.
     */
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyEx, FALSE);
    if (NT_SUCCESS(status)) {
        g_ProcessNotify = TRUE;
        g_ProcessNotifyEx = TRUE;
    } else {
        DbgPrint("SysInfo: process notify Ex refused (0x%08X), trying legacy\n", status);
        status = PsSetCreateProcessNotifyRoutine(ProcessNotifyLegacy, FALSE);
        g_ProcessNotify = NT_SUCCESS(status);
        if (!g_ProcessNotify) {
            DbgPrint("SysInfo: process notify unavailable (0x%08X)\n", status);
        }
    }

    status = PsSetCreateThreadNotifyRoutine(ThreadNotify);
    g_ThreadNotify = NT_SUCCESS(status);
    if (!g_ThreadNotify) {
        DbgPrint("SysInfo: thread notify unavailable (0x%08X)\n", status);
    }

    if (SYSINFO_ENABLE_OB_CALLBACKS) {
        StartObCallbacks();
    }

    /*
     * Handle grants.  ObRegisterCallbacks() needs a properly signed image
     * too, so hook the two Nt* open routines instead - they cover the
     * interesting cases (a program opening another process with
     * VM_READ/VM_WRITE, or a thread handle for suspend/injection) and need
     * no special privilege.
     */
#if SYSINFO_ENABLE_HANDLE_HOOKS
    if (TraceUnsafeHooksEnabled()) StartOpenHooks();
#endif

    g_Registered = TRUE;
    return STATUS_SUCCESS;
}

VOID
MonShutdown(VOID)
{
    KIRQL irql;

    if (SYSINFO_ENABLE_HANDLE_HOOKS) {
        if (g_OpenThreadHook.Installed) HookRemove(&g_OpenThreadHook);
        if (g_OpenProcessHook.Installed) HookRemove(&g_OpenProcessHook);
    }
    if (g_HandleRegistration != NULL) {
        ObUnRegisterCallbacks(g_HandleRegistration);
        g_HandleRegistration = NULL;
    }
    g_HandleCallbacks = FALSE;
    if (g_ThreadNotify) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotify);
        g_ThreadNotify = FALSE;
    }
    if (g_ProcessNotify) {
        if (g_ProcessNotifyEx) {
            PsSetCreateProcessNotifyRoutineEx(ProcessNotifyEx, TRUE);
        } else {
            PsSetCreateProcessNotifyRoutine(ProcessNotifyLegacy, TRUE);
        }
        g_ProcessNotify = FALSE;
        g_ProcessNotifyEx = FALSE;
    }
    if (g_Registered) {
        PsRemoveLoadImageNotifyRoutine(ImageNotify);
        g_Registered = FALSE;
    }

    InterlockedExchange(&g_Enabled, 0);

    if (g_Ring != NULL) {
        KeAcquireSpinLock(&g_Lock, &irql);
        {
            SYSINFO_MON_EVENT *ring = g_Ring;
            g_Ring = NULL;
            KeReleaseSpinLock(&g_Lock, irql);
            ExFreePoolWithTag(ring, SYSINFO_TAG_MON);
        }
        g_Cap = 0;
        g_Head = 0;
        g_Tail = 0;
    }

    if (g_Sum != NULL) {
        PSYSINFO_SUMMARY_ENTRY sum = g_Sum;

        KeAcquireSpinLock(&g_SumLock, &irql);
        g_Sum = NULL;
        KeReleaseSpinLock(&g_SumLock, irql);
        ExFreePoolWithTag(sum, SYSINFO_TAG_MON);
        g_Types = 0;
    }
}

NTSTATUS
MonConfigure(_In_ const SYSINFO_MON_CONFIG *config)
{
    SYSINFO_MON_EVENT *ring;

    if (config->Enable == 0) {
        InterlockedExchange(&g_Enabled, 0);
        return STATUS_SUCCESS;
    }

    if (g_Ring == NULL) {
        ring = (SYSINFO_MON_EVENT *)ExAllocatePool2(POOL_FLAG_NON_PAGED, MON_RING_EVENTS * sizeof(SYSINFO_MON_EVENT), SYSINFO_TAG_MON);
        if (ring == NULL) return STATUS_INSUFFICIENT_RESOURCES;

        RtlZeroMemory(ring, MON_RING_EVENTS * sizeof(SYSINFO_MON_EVENT));
        KeInitializeSpinLock(&g_Lock);
        g_Ring = ring;
        g_Cap = MON_RING_EVENTS;
        g_Head = 0;
        g_Tail = 0;
        InterlockedExchange(&g_Dropped, 0);
    }

    if (g_Sum == NULL) {
        PSYSINFO_SUMMARY_ENTRY sum = (PSYSINFO_SUMMARY_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, SYSINFO_SUMMARY_SLOTS * sizeof(SYSINFO_SUMMARY_ENTRY), SYSINFO_TAG_MON);
        if (sum == NULL) return STATUS_INSUFFICIENT_RESOURCES;

        RtlZeroMemory(sum, SYSINFO_SUMMARY_SLOTS * sizeof(SYSINFO_SUMMARY_ENTRY));
        KeInitializeSpinLock(&g_SumLock);
        g_Sum = sum;
        InterlockedExchange(&g_SumTotal, 0);
        InterlockedExchange(&g_SumOverflow, 0);
    }

    /*
     * Fresh session: drop whatever the previous one left queued.  Without
     * this, `mon on <pid>` dumps the old session's events first and the
     * filter looks broken.
     */
    if (g_Enabled == 0) {
        KIRQL irql;

        KeAcquireSpinLock(&g_Lock, &irql);
        g_Head = 0;
        g_Tail = 0;
        InterlockedExchange(&g_Dropped, 0);
        KeReleaseSpinLock(&g_Lock, irql);

        /* A fresh session starts with a fresh summary as well. */
        if (g_Sum != NULL) {
            KeAcquireSpinLock(&g_SumLock, &irql);
            RtlZeroMemory(g_Sum, SYSINFO_SUMMARY_SLOTS * sizeof(SYSINFO_SUMMARY_ENTRY));
            InterlockedExchange(&g_SumTotal, 0);
            InterlockedExchange(&g_SumOverflow, 0);
            InterlockedExchange(&g_SumSuppressed, 0);
            KeReleaseSpinLock(&g_SumLock, irql);
        }

        /* ... and with no folded event to compare against. */
        g_LastHash = 0;
        g_LastStamp = 0;
    }

    {
        ULONG n = config->IgnoreCount;
        ULONG i, j;

        if (n > RTL_NUMBER_OF(g_Ignore)) n = RTL_NUMBER_OF(g_Ignore);
        g_IgnoreCount = 0;
        RtlZeroMemory(g_Ignore, sizeof(g_Ignore));
        for (i = 0; i < n; i++) {
            for (j = 0; j + 1 < SYSINFO_MON_IGNORE_CHARS && config->SummaryIgnore[i][j] != 0; j++) {
                g_Ignore[i][j] = config->SummaryIgnore[i][j];
            }
            g_Ignore[i][j] = 0;
        }
        g_IgnoreCount = n;
        g_IgnoreRelative = config->IgnoreRelative ? 1 : 0;
    }

    {
        ULONG n = config->IoctlDump;
        ULONG i;

        if (n > 32) n = 32;
        g_IoctlDump = n;
        RtlZeroMemory(g_IoctlMatch, sizeof(g_IoctlMatch));
        for (i = 0; i < RTL_NUMBER_OF(g_IoctlMatch) - 1 &&
                    i < config->IoctlMatchChars && config->IoctlMatch[i] != 0; i++) {
            g_IoctlMatch[i] = config->IoctlMatch[i];
        }
    }

    {
        ULONG n = config->ImageCount;

        if (n > RTL_NUMBER_OF(g_Images)) n = RTL_NUMBER_OF(g_Images);
        InterlockedExchange(&g_ImageCount, 0);
        RtlZeroMemory(g_Images, sizeof(g_Images));
        for (ULONG i = 0; i < n; i++) {
            CopyAscii(g_Images[i], SYSINFO_MON_IMAGE_CHARS, config->Images[i]);
        }
        InterlockedExchange(&g_ImageCount, (LONG)n);
    }

    InterlockedExchange(&g_PidFilter, (LONG)config->PidFilter);
    InterlockedExchange(&g_KernelImages, config->KernelImages ? 1 : 0);
    g_Types = config->Types & SYSINFO_MON_BITS_ALL;
    InterlockedExchange(&g_Enabled, 1);

    if (!config->Enable) {
        TraceSetUnsafeHooksEnabled(0);
    } else if (config->UnsafeHooksEnabled) {
        TraceSetUnsafeHooksEnabled(1);
    }
#if SYSINFO_ENABLE_HANDLE_HOOKS
    if (TraceUnsafeHooksEnabled()) StartOpenHooks();
#endif
#if SYSINFO_ENABLE_HANDLE_HOOKS
    if (!TraceUnsafeHooksEnabled()) StopOpenHooks();
#endif
    /* The two memory hooks have no exported name; the CLI supplies their
     * syscall numbers so they can be installed on first enable. */
    TraceInstallMemoryHooks(config->SsnRead, config->SsnWrite);
    return STATUS_SUCCESS;
}

VOID
MonQuery(_Out_ PSYSINFO_MON_CONFIG config, _Out_ PULONG dropped)
{
    config->Enable = (ULONG)g_Enabled;
    config->PidFilter = (ULONG)g_PidFilter;
    config->KernelImages = (ULONG)g_KernelImages;
    config->ImageCount = (ULONG)g_ImageCount;
    config->Types = g_Types;
    RtlZeroMemory(config->Images, sizeof(config->Images));
    for (ULONG i = 0; i < (ULONG)g_ImageCount && i < RTL_NUMBER_OF(g_Images); i++) {
        RtlCopyMemory(config->Images[i], g_Images[i], SYSINFO_MON_IMAGE_CHARS);
    }
    if (dropped != NULL) *dropped = (ULONG)g_Dropped;
}

NTSTATUS
MonRead(_Out_writes_bytes_(outLength) PVOID outBuffer, _In_ ULONG outLength)
{
    PSYSINFO_MON_BATCH batch = (PSYSINFO_MON_BATCH)outBuffer;
    PUCHAR events;
    ULONG room, count = 0;
    KIRQL irql;

    if (outBuffer == NULL || outLength < sizeof(SYSINFO_MON_BATCH)) return STATUS_BUFFER_TOO_SMALL;

    events = (PUCHAR)outBuffer + sizeof(SYSINFO_MON_BATCH);
    room = (outLength - sizeof(SYSINFO_MON_BATCH)) / sizeof(SYSINFO_MON_EVENT);
    if (room > SYSINFO_MON_BATCH_MAX) room = SYSINFO_MON_BATCH_MAX;

    batch->Enabled = (ULONG)g_Enabled;
    batch->PidFilter = (ULONG)g_PidFilter;
    batch->Dropped = (ULONG)g_Dropped;

    if (g_Ring == NULL || room == 0) {
        batch->Count = 0;
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&g_Lock, &irql);
    while (count < room && (ULONG)g_Tail != (ULONG)g_Head) {
        RtlCopyMemory(events + count * sizeof(SYSINFO_MON_EVENT),
                      &g_Ring[(ULONG)g_Tail], sizeof(SYSINFO_MON_EVENT));
        g_Tail = (LONG)(((ULONG)g_Tail + 1) % g_Cap);
        count++;
    }
    KeReleaseSpinLock(&g_Lock, irql);

    batch->Count = count;
    return STATUS_SUCCESS;
}
