/*
 * syscall.c - find nt!Nt* functions that ntoskrnl keeps out of its export table.
 *
 * NtQueryValueKey and NtQueryKey (and a few others) are reachable only through
 * the system service table: user-mode ntdll stubs do `syscall`, KiSystemCall64
 * indexes the table, and kernel-mode Zw* stubs dispatch into the very same
 * entry.  Hook the table entry and both rings are covered.
 *
 * Neither KeServiceDescriptorTable nor KiServiceTable is exported either, so the
 * table is located in two phases: first by scanning ntoskrnl's .text for any
 * `lea r64,[rip+disp32]` that could address it, then - because this kernel loads
 * it some other way - by walking every 4-byte-aligned image offset.  A candidate
 * is only accepted when it *proves* itself: two entries we can obtain
 * independently (the exported NtQuerySystemInformation / NtDeviceIoControlFile
 * addresses versus the syscall numbers read out of their Zw* stubs) must both
 * resolve correctly.  A wrong guess fails both checks.
 */
#include "syscall.h"
#include "../shared/sysinfo.h"
#include "util.h"

typedef struct _SYSINFO_IMAGE {
    PUCHAR Base;
    ULONG  Size;
    PUCHAR Text;
    ULONG  TextSize;
} SYSINFO_IMAGE;

static SYSINFO_IMAGE g_Nt;
static PVOID      g_ImageBase;      /* ntoskrnl base, for the "absolute RVA" encoding */
static PVOID      g_Table;          /* system service table                          */
static ULONG      g_Stride;         /* bytes per entry: 4 or 8                       */
static ULONG      g_Mode;           /* entry encoding, see TableTarget()             */
static BOOLEAN    g_Tried;
static BOOLEAN    g_Ok;
static ULONG      g_Stage = SYSINFO_STAGE_NONE;
static ULONG      g_SsnA, g_SsnB;
static PVOID      g_NtA, g_NtB;      /* resolved anchors (for diagnostics) */
static PVOID      g_ZwA, g_ZwB;

/* Service-table entry encodings worth trying. */
#define SYSINFO_MODE_BASE_REL   0       /* table  + (LONG)entry   */
#define SYSINFO_MODE_ENTRY_REL  1       /* &entry + (LONG)entry   */
#define SYSINFO_MODE_ABS_RVA32  2       /* imagebase + (ULONG)entry */
#define SYSINFO_MODE_ABS_VA     3       /* entry is the address   */
#define SYSINFO_MODE_SHIFT4     4       /* table + ((LONG)entry >> 4) */

#define SYSINFO_MAX_SSN 0x400

static PVOID
TableTarget(_In_ ULONG ssn)
{
    ULONG_PTR base = (ULONG_PTR)g_Table;

    if (ssn >= SYSINFO_MAX_SSN) return NULL;

    if (g_Stride == 8) {
        LONG_PTR v = *(LONG_PTR *)(base + 8 * ssn);

        switch (g_Mode) {
        case SYSINFO_MODE_BASE_REL:  return (PVOID)(base + v);
        case SYSINFO_MODE_ENTRY_REL: return (PVOID)(base + 8 * ssn + v);
        case SYSINFO_MODE_ABS_VA:    return (PVOID)v;
        default:                  return NULL;
        }
    } else {
        LONG v = *(LONG *)(base + 4 * ssn);

        switch (g_Mode) {
        case SYSINFO_MODE_BASE_REL:  return (PVOID)(base + (LONG_PTR)v);
        case SYSINFO_MODE_ENTRY_REL: return (PVOID)(base + 4 * ssn + (LONG_PTR)v);
        case SYSINFO_MODE_ABS_RVA32: return (PVOID)((ULONG_PTR)g_ImageBase + (ULONG)v);
        /* Windows 11 24H2 stores KiServiceTable entries as
         *   (target - table) << 4 | flags
         * so the target is recovered by an arithmetic shift right by four. */
        case SYSINFO_MODE_SHIFT4:    return (PVOID)(base + ((LONG_PTR)v >> 4));
        default:                  return NULL;
        }
    }
}

/* True when `candidate` with this layout maps both calibration ssns correctly. */
static BOOLEAN
TryLayout(_In_ ULONG_PTR candidate, _In_ ULONG stride, _In_ ULONG mode,
          _In_ PVOID ntA, _In_ ULONG ssnA, _In_ PVOID ntB, _In_ ULONG ssnB)
{
    g_Table  = (PVOID)candidate;
    g_Stride = stride;
    g_Mode   = mode;

    if (TableTarget(ssnA) != ntA) return FALSE;
    if (TableTarget(ssnB) != ntB) return FALSE;
    return TRUE;
}

static BOOLEAN
TryAllLayouts(_In_ ULONG_PTR candidate,
              _In_ PVOID ntA, _In_ ULONG ssnA, _In_ PVOID ntB, _In_ ULONG ssnB)
{
    static const ULONG strides[2] = { 4, 8 };
    ULONG s, m;

    for (s = 0; s < 2; s++) {
        for (m = 0; m <= SYSINFO_MODE_SHIFT4; m++) {
            if (strides[s] == 4 && m == SYSINFO_MODE_ABS_VA)    continue;
            if (strides[s] == 8 && m == SYSINFO_MODE_ABS_RVA32) continue;
            if (strides[s] == 8 && m == SYSINFO_MODE_SHIFT4)    continue;
            if (TryLayout(candidate, strides[s], m, ntA, ssnA, ntB, ssnB)) return TRUE;
        }
    }
    return FALSE;
}

/* Walk down from a known address inside the image to its 'MZ' header. */
static PVOID
FindImageBase(_In_ PVOID inside, _Out_ PULONG imageSize)
{
    ULONG_PTR p = (ULONG_PTR)inside & ~(ULONG_PTR)0xFFF;
    ULONG     i;

    for (i = 0; i < 0x8000; i++) {
        ULONG  e_lfanew;
        ULONG  size;

        if (p < 0x1000) break;
        p -= 0x1000;

        if (*(USHORT *)p != 0x5A4D) continue;                    /* 'MZ'    */
        e_lfanew = *(ULONG *)(p + 0x3C);
        if (e_lfanew < 0x40 || e_lfanew > 0x400) continue;
        if (*(ULONG *)(p + e_lfanew) != 0x00004550) continue;     /* 'PE\0\0' */
        if (*(USHORT *)(p + e_lfanew + 4) != 0x8664) continue;    /* amd64   */

        size = *(ULONG *)(p + e_lfanew + 0x18 + 0x38);            /* SizeOfImage */
        if (size < 0x1000) continue;
        if ((ULONG_PTR)inside < p || (ULONG_PTR)inside >= p + size) continue;

        *imageSize = size;
        return (PVOID)p;
    }
    return NULL;
}

static BOOLEAN
FindTextSection(_In_ PVOID base, _Out_ PUCHAR *text, _Out_ PULONG textSize)
{
    PUCHAR nt     = (PUCHAR)base + *(ULONG *)((PUCHAR)base + 0x3C);
    USHORT nsec   = *(USHORT *)(nt + 6);
    USHORT optLen = *(USHORT *)(nt + 20);
    PUCHAR sec    = nt + 24 + optLen;
    ULONG  i;

    if (nsec > 96) nsec = 96;

    for (i = 0; i < nsec; i++, sec += 40) {
        if (RtlCompareMemory(sec, ".text", 5) == 5) {
            ULONG vsize = *(ULONG *)(sec + 8);
            ULONG rva   = *(ULONG *)(sec + 12);
            ULONG raw   = *(ULONG *)(sec + 16);

            if (vsize == 0 || raw == 0) return FALSE;
            *text     = (PUCHAR)base + rva;
            *textSize = min(vsize, raw);
            return TRUE;
        }
    }
    return FALSE;
}

/* A Zw* stub is `... B8 <ssn> E9 <rel32> ...` - pull the syscall number out. */
static BOOLEAN
SsnFromStub(_In_ PVOID stub, _Out_ PULONG ssn)
{
    PUCHAR p = (PUCHAR)stub;
    ULONG  i;

    for (i = 0; i < 0x40; i++) {
        if (p[i] == 0xB8 && p[i + 5] == 0xE9) {
            *ssn = *(ULONG *)(p + i + 1);
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS
Calibrate(VOID)
{
    PVOID ntA, zwA, ntB, zwB;
    ULONG ssnA = 0, ssnB = 0;
    ULONG i;
    UNICODE_STRING us;

    RtlInitUnicodeString(&us, L"NtQuerySystemInformation");
    ntA = MmGetSystemRoutineAddress(&us);
    RtlInitUnicodeString(&us, L"ZwQuerySystemInformation");
    zwA = MmGetSystemRoutineAddress(&us);
    RtlInitUnicodeString(&us, L"NtDeviceIoControlFile");
    ntB = MmGetSystemRoutineAddress(&us);
    RtlInitUnicodeString(&us, L"ZwDeviceIoControlFile");
    zwB = MmGetSystemRoutineAddress(&us);

    if (ntA == NULL || zwA == NULL || ntB == NULL || zwB == NULL) {
        DbgPrint("SysInfo: syscall calibration anchors missing\n");
        g_Stage = SYSINFO_STAGE_NO_ANCHOR;
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    g_NtA = ntA; g_ZwA = zwA; g_NtB = ntB; g_ZwB = zwB;
    if (!SsnFromStub(zwA, &ssnA) || !SsnFromStub(zwB, &ssnB)) {
        DbgPrint("SysInfo: syscall calibration could not read ssn\n");
        g_Stage = SYSINFO_STAGE_NO_SSN;
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    g_SsnA = ssnA;
    g_SsnB = ssnB;

    g_Nt.Base = (PUCHAR)FindImageBase(ntA, &g_Nt.Size);
    if (g_Nt.Base == NULL) {
        DbgPrint("SysInfo: ntoskrnl base not found\n");
        g_Stage = SYSINFO_STAGE_NO_IMAGE;
        return STATUS_NOT_FOUND;
    }
    g_ImageBase = g_Nt.Base;

    if (!FindTextSection(g_Nt.Base, &g_Nt.Text, &g_Nt.TextSize)) {
        DbgPrint("SysInfo: ntoskrnl .text not found\n");
        g_Stage = SYSINFO_STAGE_NO_TEXT;
        return STATUS_NOT_FOUND;
    }

    DbgPrint("SysInfo: calibrating syscall table (ssnA=%lu ssnB=%lu, .text %p+%lu)\n",
             ssnA, ssnB, g_Nt.Text, g_Nt.TextSize);

    /* phase 1: candidates offered by rip-relative loads in .text */
    for (i = 0; i + 7 < g_Nt.TextSize; i++) {
        ULONG_PTR candidate;
        LONG      disp;
        UCHAR    *p = g_Nt.Text + i;

        /* lea r64, [rip + disp32] */
        if ((p[0] & 0xF8) != 0x48 || p[1] != 0x8D || (p[2] & 0xC7) != 0x05) continue;

        disp      = *(LONG *)(p + 3);
        candidate = (ULONG_PTR)(p + 7) + (LONG_PTR)disp;
        if (candidate < (ULONG_PTR)g_Nt.Base) continue;
        if (candidate + 8 * SYSINFO_MAX_SSN >= (ULONG_PTR)g_Nt.Base + g_Nt.Size) continue;

        if (TryAllLayouts(candidate, ntA, ssnA, ntB, ssnB)) {
            g_Stage = SYSINFO_STAGE_OK;
            DbgPrint("SysInfo: syscall table %p via lea (stride=%lu mode=%lu)\n",
                     g_Table, g_Stride, g_Mode);
            return STATUS_SUCCESS;
        }
    }

    /* phase 2: this kernel addresses the table some other way - sweep the image.
     * The calibration makes a false positive essentially impossible. */
    for (i = 0x1000; i + 8 * SYSINFO_MAX_SSN < g_Nt.Size; i += 4) {
        if (TryAllLayouts((ULONG_PTR)g_Nt.Base + i, ntA, ssnA, ntB, ssnB)) {
            g_Stage = SYSINFO_STAGE_OK;
            DbgPrint("SysInfo: syscall table %p via sweep (stride=%lu mode=%lu)\n",
                     g_Table, g_Stride, g_Mode);
            return STATUS_SUCCESS;
        }
    }

    g_Table = NULL;
    g_Stage = SYSINFO_STAGE_NO_TABLE;
    return STATUS_NOT_FOUND;
}

static BOOLEAN
EnsureCalibrated(VOID)
{
    if (g_Tried) return g_Ok;
    g_Tried = TRUE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        /* MmGetSystemRoutineAddress must not be called above APC. */
        g_Tried = FALSE;
        g_Stage = SYSINFO_STAGE_IRQL;
        return FALSE;
    }

    g_Ok = NT_SUCCESS(Calibrate());
    if (!g_Ok) DbgPrint("SysInfo: syscall table calibration failed\n");
    return g_Ok;
}

BOOLEAN
SysinfoSyscallCalibrated(VOID)
{
    return g_Ok;
}

VOID
SysinfoSetStage(_In_ ULONG stage)
{
    g_Stage = stage;
    g_Tried = TRUE;          /* do not let a later call overwrite this reason */
    g_Ok    = FALSE;
}

VOID
SysinfoSyscallDiag(_Out_opt_ PULONG stage, _Out_opt_ PULONG ssnA,
                _Out_opt_ PULONG ssnB, _Out_opt_ PULONG64 table,
                _Out_opt_ PULONG mode, _Out_opt_ PULONG stride)
{
    if (stage  != NULL) *stage  = g_Stage;
    if (ssnA   != NULL) *ssnA   = g_SsnA;
    if (ssnB   != NULL) *ssnB   = g_SsnB;
    if (table  != NULL) *table  = (ULONG64)(ULONG_PTR)g_Table;
    if (mode   != NULL) *mode   = g_Mode;
    if (stride != NULL) *stride = g_Stride;
}

VOID
SysinfoSyscallMore(_Out_writes_(count) PULONG64 out, _In_ ULONG count)
{
    ULONG i;
    for (i = 0; i < count; i++) out[i] = 0;

    if (count > 0) out[0] = (ULONG64)(ULONG_PTR)g_NtA;
    if (count > 1) out[1] = (ULONG64)(ULONG_PTR)g_NtB;
    if (count > 2) out[2] = (ULONG64)(ULONG_PTR)g_ZwA;
    if (count > 3) out[3] = (ULONG64)(ULONG_PTR)g_ZwB;
    if (count > 4) out[4] = (ULONG64)(ULONG_PTR)g_Nt.Base;
    if (count > 5) out[5] = (ULONG64)g_Nt.Size;
    if (count > 6) out[6] = (ULONG64)((ULONG_PTR)g_NtA - (ULONG_PTR)g_Nt.Base);
    if (count > 7) out[7] = (ULONG64)((ULONG_PTR)g_NtB - (ULONG_PTR)g_Nt.Base);

    /* Window of qwords around the RVA the offline analysis identified, so the
     * runtime bytes can be compared with the on-disk image. */
    if (g_Nt.Base != NULL) {
        for (i = 0; i + 8 < count && i < 16; i++) {
            out[8 + i] = *(ULONG64 *)(g_Nt.Base + 0xDB6E0 + 8 * i);
        }
    }
}

static PVOID
ResolveZw(_In_ PCWSTR zwName)
{
    UNICODE_STRING us;
    PVOID          stub;
    ULONG          ssn;

    if (!EnsureCalibrated()) return NULL;

    RtlInitUnicodeString(&us, zwName);
    stub = MmGetSystemRoutineAddress(&us);
    if (stub == NULL || !SsnFromStub(stub, &ssn)) return NULL;

    return TableTarget(ssn);
}

PVOID
SysinfoResolveNt(_In_ PCWSTR ntName)
{
    WCHAR          zw[64];
    UNICODE_STRING us;
    PVOID          found;
    size_t         len, i;

    if (ntName == NULL) return NULL;

    /* normal path: ntoskrnl exports it */
    RtlInitUnicodeString(&us, ntName);
    found = MmGetSystemRoutineAddress(&us);
    if (found != NULL) return found;

    if (ntName[0] != L'N' || ntName[1] != L't') return NULL;

    /* fall back: Zw<same suffix>, dispatched to the same service table entry */
    len = SysinfoStrLenW(ntName);
    if (len + 1 > RTL_NUMBER_OF(zw)) return NULL;

    zw[0] = L'Z';
    zw[1] = L'w';
    for (i = 2; i <= len; i++) zw[i] = ntName[i];

    found = ResolveZw(zw);
    if (found != NULL) {
        DbgPrint("SysInfo: %wZ not exported -> service table %p\n", &us, found);
    } else {
        DbgPrint("SysInfo: %wZ unresolved\n", &us);
    }
    return found;
}

PVOID
SysinfoNtImageBase(VOID)
{
    return g_Nt.Base;
}

ULONG
SysinfoNtImageSize(VOID)
{
    return g_Nt.Size;
}

PVOID
SysinfoResolveSsn(_In_ ULONG ssn)
{
    if (!g_Ok || g_Table == NULL) return NULL;
    return TableTarget(ssn);
}
