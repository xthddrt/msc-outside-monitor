/*
 * hooks.c - x64 inline hook engine.
 *
 * Patch shape at the target (14 bytes, clobbers no register):
 *      FF 25 00 00 00 00       jmp qword ptr [rip+0]
 *      <8 byte absolute address>
 *
 * The stolen prologue is copied to a trampoline that ends with the same jump
 * shape back to target+stolen.  Because a pool trampoline can be more than 2GB
 * away from ntoskrnl (which breaks rel32 and RIP-relative encodings), the
 * trampolines live in an executable section of *our own image*, which the
 * loader places next to ntoskrnl.
 */
#include "hooks.h"
#include "disasm.h"
#include "util.h"
#include "../shared/sysinfo.h"
#include <intrin.h>

/* This WDK's km headers declare neither SYSTEM_INFORMATION_CLASS nor
 * ZwQuerySystemInformation, so spell the one call we need ourselves. */
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(_In_ ULONG SystemInformationClass,
                                                 _Out_writes_bytes_(SystemInformationLength) PVOID SystemInformation,
                                                 _In_ ULONG SystemInformationLength,
                                                 _Out_opt_ PULONG ReturnLength);

/*
 * The section is EXECUTE+READ, deliberately *not* writable.
 *
 * HVCI (Memory Integrity) only tolerates a writable+executable image section if
 * the image carries page hashes, and page hashes live in a signed catalog - a
 * test-signed driver has only the embedded signature, so it has none.  A plain
 * RX section needs no page hashes and always loads, so the trampolines are
 * written into it at install time with CR0.WP cleared.
 */
#pragma section("TRAMP", read, execute)
#pragma comment(linker, "/SECTION:TRAMP,ER")
__declspec(allocate("TRAMP")) static UCHAR g_TrampPool[8192];
static ULONG g_TrampUsed;

#define PATCH_LEN   14
#define TRAMP_ALIGN 16
#define TRAMP_SLOT  128

static BOOLEAN
IsLegacyPrefix(_In_ UCHAR b)
{
    return (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 ||
            b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65 || b == 0x66 ||
            b == 0x67);
}

static VOID
WriteRel32(_Inout_ UCHAR *p, _In_ LONG_PTR value)
{
    *(LONG *)p = (LONG)value;
}

/* Emit an absolute indirect jump. */
static VOID
EmitAbsJump(_Out_writes_bytes_(PATCH_LEN) UCHAR *p, _In_ PVOID destination)
{
    p[0] = 0xFF;
    p[1] = 0x25;
    p[2] = 0x00;
    p[3] = 0x00;
    p[4] = 0x00;
    p[5] = 0x00;
    *(PVOID *)(p + 6) = destination;
}

static ULONG_PTR NTAPI
IpiNop(_In_ ULONG_PTR Argument)
{
    return Argument;
}

/* x86 needs a serializing event on every core for the new code to be seen. */
static VOID
SyncCores(VOID)
{
    SysinfoSerializeCore();
    KeIpiGenericCall(IpiNop, 0);
}

static PVOID
AllocTrampoline(_In_ ULONG bytes)
{
    ULONG off = (g_TrampUsed + (TRAMP_ALIGN - 1)) & ~(TRAMP_ALIGN - 1);

    if (off + bytes <= sizeof(g_TrampPool)) {
        g_TrampUsed = off + bytes;
        return g_TrampPool + off;
    }
    return NULL;
}

/*
 * Copy whole instructions to the trampoline until at least PATCH_LEN bytes are
 * covered, relocating RIP-relative operands and relative branches:
 *   - rel32                  -> rewritten in place
 *   - jmp rel8 / jcc rel8    -> widened to the rel32 form
 *   - loop/jrcxz rel8        -> kept (range checked, warns when too far)
 */
static NTSTATUS
BuildTrampoline(_Inout_ PHOOK hook, _Out_writes_(TRAMP_SLOT) UCHAR *emit, _Out_ PULONG built)
{
    const UCHAR *src = (const UCHAR *)hook->Target;
    const UCHAR *dst = (const UCHAR *)hook->Trampoline;   /* final address */
    ULONG i = 0, o = 0;
    NTSTATUS status = STATUS_SUCCESS;

    *built = 0;

    while (i < PATCH_LEN) {
        LD_INSN insn;
        LONG_PTR srcAddr, dstAddr, delta;
        UCHAR opcode;
        ULONG pfx = 0;

        if (!LdDecode(src + i, 32, &insn) || insn.Length == 0) {
            DbgPrint("SysInfo: cannot decode at %p\n", src + i);
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        if (i + insn.Length > sizeof(hook->Saved)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlCopyMemory(emit + o, src + i, insn.Length);

        srcAddr = (LONG_PTR)(src + i);
        dstAddr = (LONG_PTR)(dst + o);
        delta   = srcAddr - dstAddr;

        if (insn.HasRipRel) {
            LONG_PTR disp = *(LONG *)(src + i + insn.DispOffset);
            LONG_PTR newDisp = disp + delta;
            if (newDisp != (LONG_PTR)(LONG)newDisp) {
                DbgPrint("SysInfo: rip-rel disp out of range\n");
                return STATUS_INTEGER_OVERFLOW;
            }
            WriteRel32(emit + o + insn.DispOffset, newDisp);
        } else if (insn.HasRel) {
            while (pfx < insn.Length && IsLegacyPrefix(src[i + pfx])) pfx++;
            opcode = src[i + pfx];

            if (insn.RelSize == 4) {
                LONG_PTR rel = *(LONG *)(src + i + insn.RelOffset);
                LONG_PTR newRel = rel + delta;
                if (newRel != (LONG_PTR)(LONG)newRel) {
                    DbgPrint("SysInfo: rel32 out of range\n");
                    return STATUS_INTEGER_OVERFLOW;
                }
                WriteRel32(emit + o + insn.RelOffset, newRel);
            } else if (opcode == 0xEB) {
                /* jmp rel8 -> jmp rel32 */
                LONG_PTR rel = *(SCHAR *)(src + i + insn.RelOffset);
                LONG_PTR target = srcAddr + insn.Length + rel;
                LONG_PTR newRel = target - (dstAddr + (LONG_PTR)pfx + 5);
                if (newRel != (LONG_PTR)(LONG)newRel) return STATUS_INTEGER_OVERFLOW;
                emit[o + pfx] = 0xE9;
                WriteRel32(emit + o + pfx + 1, newRel);
                o += 3;                 /* 2 -> 5 bytes, the rest comes below */
            } else if (opcode >= 0x70 && opcode <= 0x7F) {
                /* jcc rel8 -> jcc rel32 */
                LONG_PTR rel = *(SCHAR *)(src + i + insn.RelOffset);
                LONG_PTR target = srcAddr + insn.Length + rel;
                LONG_PTR newRel = target - (dstAddr + (LONG_PTR)pfx + 6);
                if (newRel != (LONG_PTR)(LONG)newRel) return STATUS_INTEGER_OVERFLOW;
                emit[o + pfx] = 0x0F;
                emit[o + pfx + 1] = (UCHAR)(0x80 | (opcode - 0x70));
                WriteRel32(emit + o + pfx + 2, newRel);
                o += 4;                 /* 2 -> 6 bytes, the rest comes below */
            } else {
                /* loop / loope / loopne / jrcxz : no rel32 form */
                LONG_PTR rel = *(SCHAR *)(src + i + insn.RelOffset);
                LONG_PTR newRel = rel + delta;
                if (newRel < -128 || newRel > 127) {
                    DbgPrint("SysInfo: warning, loop rel8 out of range\n");
                }
                *(SCHAR *)(emit + o + insn.RelOffset) = (SCHAR)newRel;
            }
        }

        i += insn.Length;
        o += insn.Length;
    }

    hook->Stolen = i;

    if (o + PATCH_LEN > TRAMP_SLOT) {
        DbgPrint("SysInfo: trampoline needs %lu bytes\n", o + PATCH_LEN);
        return STATUS_BUFFER_TOO_SMALL;
    }
    EmitAbsJump(emit + o, (PVOID)(src + i));
    o += PATCH_LEN;

    *built = o;
    return status;
}

static BOOLEAN
InRel32Range(_In_ PVOID a, _In_ PVOID b)
{
    LONG_PTR d = (LONG_PTR)a - (LONG_PTR)b;
    return d >= -0x7FFF0000LL && d <= 0x7FFF0000LL;
}

/* ---------------------------------------------------------- patch environment */

/*
 * Memory Integrity (HVCI) enforces W^X in the hypervisor, below CR0.WP and
 * below PTE permissions.  Writing to ntoskrnl .text then raises an EPT
 * violation the CPU cannot recover from - it is a bugcheck, not an exception
 * we could catch - so the environment must be checked *before* the first
 * write, not discovered by trying.
 */
#define SYSINFO_CI_QUERY 103u          /* SystemCodeIntegrityInformation */

typedef struct _SYSINFO_CI_INFO {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSINFO_CI_INFO;

#define SYSINFO_CI_TESTSIGNING       0x00000002u
#define SYSINFO_CI_HVCI_KMCI_ENABLED 0x00000400u   /* OPTION_HVCI_KMCI_ENABLED      */
#define SYSINFO_CI_HVCI_KMCI_AUDIT   0x00000800u   /* OPTION_HVCI_KMCI_AUDITMODE    */
#define SYSINFO_CI_HVCI_KMCI_STRICT  0x00001000u   /* OPTION_HVCI_KMCI_STRICTMODE   */
#define SYSINFO_CI_HVCI_IUM          0x00002000u   /* OPTION_HVCI_IUM_ENABLED       */

static ULONG   g_CiOptions;
static ULONG   g_Hvci;             /* 0 no, 1 via CI options, 2 via registry */
static BOOLEAN g_Probed;

static BOOLEAN
RegistryDwordTrue(_In_ PCWSTR keyName, _In_ PCWSTR valueName)
{
    UNICODE_STRING    key, value;
    OBJECT_ATTRIBUTES attributes;
    HANDLE            handle;
    UCHAR             buffer[FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    ULONG             length = 0;
    BOOLEAN           result = FALSE;

    RtlInitUnicodeString(&key, keyName);
    RtlInitUnicodeString(&value, valueName);
    InitializeObjectAttributes(&attributes, &key,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (!NT_SUCCESS(ZwOpenKey(&handle, KEY_READ, &attributes))) return FALSE;
    if (NT_SUCCESS(ZwQueryValueKey(handle, &value, KeyValuePartialInformation,
                                   buffer, sizeof(buffer), &length)) &&
        info->Type == REG_DWORD && info->DataLength >= sizeof(ULONG)) {
        result = (*(PULONG)info->Data != 0);
    }
    ZwClose(handle);
    return result;
}

static BOOLEAN
HypervisorPresent(VOID)
{
    int registers[4];
    __cpuid(registers, 1);
    return (registers[2] & (1 << 31)) != 0;
}

static VOID
ProbePatchEnvironment(VOID)
{
    SYSINFO_CI_INFO info;

    if (g_Probed) return;
    g_Probed = TRUE;

    info.Length = sizeof(info);
    info.CodeIntegrityOptions = 0;
    if (NT_SUCCESS(ZwQuerySystemInformation(SYSINFO_CI_QUERY,
                                            &info, sizeof(info), NULL))) {
        g_CiOptions = info.CodeIntegrityOptions;
    }

    if ((g_CiOptions & SYSINFO_CI_HVCI_KMCI_ENABLED) != 0 &&
        (g_CiOptions & SYSINFO_CI_HVCI_KMCI_AUDIT) == 0) {
        g_Hvci = 1;
    } else if ((g_CiOptions & SYSINFO_CI_HVCI_KMCI_STRICT) != 0) {
        g_Hvci = 1;
    } else if (HypervisorPresent() &&
               RegistryDwordTrue(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control"
                                 L"\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                                 L"Enabled")) {
        /* CI options may not surface the state on every build - the
         * DeviceGuard scenario is the setting the UI toggles. */
        g_Hvci = 2;
    }

    DbgPrint("SysInfo: patch environment: CiOptions=0x%08X hvci=%lu cet=%lu\n",
             g_CiOptions, g_Hvci, SysinfoCetEnabled() ? 1u : 0u);
}

ULONG
SysinfoCiOptions(VOID)
{
    ProbePatchEnvironment();
    return g_CiOptions;
}

BOOLEAN
SysinfoHvciEnforced(VOID)
{
    ProbePatchEnvironment();
    return g_Hvci != 0;
}

BOOLEAN
SysinfoHypervisorPresent(VOID)
{
    return HypervisorPresent();
}

BOOLEAN
SysinfoPatchBlocked(VOID)
{
    return SysinfoHvciEnforced() || SysinfoHypervisorPresent();
}

/* ------------------------------------------------- writing read-only text */

/*
 * ntoskrnl's .text and the trampoline section are both mapped read-only, so a
 * plain store faults.  There are two ways to get a writable view of the page:
 *
 * 1. Map it again through an MDL.  The second mapping has its own, writable
 *    PTE, so no control register has to be touched at all.  This is the path
 *    that works on every current CPU, including ones running with kernel
 *    shadow stacks (CR4.CET).
 *
 * 2. Clear CR0.WP.  Simple, but illegal while CET is on: the SDM forbids
 *    CR0.WP == 0 when CR4.CET == 1, so `mov cr0` raises #GP and the machine
 *    bugchecks with 0x7E / STATUS_PRIVILEGED_INSTRUCTION.  Taking CR4.CET down
 *    first does not help either - Windows keeps IA32_S_CET.SH_STK_EN set, and
 *    clearing CR4.CET while shadow stacks are enabled raises #GP as well.  So
 *    this path is only used as a fallback on CPUs without CET.
 *
 * Note that neither trick defeats Memory Integrity (HVCI): the hypervisor
 * enforces W^X below the OS, so such a write is an unrecoverable EPT
 * violation.  The driver refuses to install hooks when HVCI is active (see
 * main.c) instead of bugchecking.
 */
#define SYSINFO_CR0_WP  (1ULL << 16)
#define SYSINFO_CR4_CET (1ULL << 23)

static ULONG g_WriteMethod;

/* Detours currently executing.  Kept separate from g_WriteMethod so the
 * accounting is always available, even before the first write. */
static volatile LONG g_InHook;

VOID
HookEnter(VOID)
{
    InterlockedIncrement(&g_InHook);
}

VOID
HookLeave(VOID)
{
    InterlockedDecrement(&g_InHook);
}

VOID
HookQuiesce(_In_ ULONG maxMilliseconds)
{
    ULONG waited = 0;

    while (g_InHook != 0 && waited < maxMilliseconds) {
        LARGE_INTEGER interval;

        interval.QuadPart = -10000;             /* 1 ms */
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        waited++;
    }
    if (g_InHook != 0) {
        DbgPrint("SysInfo: %ld detour(s) still running at unload\n", g_InHook);
    }
}

ULONG
SysinfoPatchMethod(VOID)
{
    return g_WriteMethod;
}

BOOLEAN
SysinfoCetEnabled(VOID)
{
    return (__readcr4() & (ULONG_PTR)SYSINFO_CR4_CET) != 0;
}

/* A second, writable mapping of the pages that hold `destination`. */
static NTSTATUS
WriteViaMdl(_In_ PVOID destination, _In_reads_bytes_(length) const VOID *source, _In_ ULONG length)
{
    PMDL  mdl;
    PVOID alias;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    mdl = IoAllocateMdl(destination, length, FALSE, FALSE, NULL);
    if (mdl == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    MmBuildMdlForNonPagedPool(mdl);
    alias = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE,
                                         NormalPagePriority | MdlMappingNoExecute);
    if (alias == NULL) {
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(alias, source, length);

    MmUnmapLockedPages(alias, mdl);
    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}

/* The old CR0.WP window.  Caller must have established that CET is off. */
static NTSTATUS
WriteViaCr0(_In_ PVOID destination, _In_reads_bytes_(length) const VOID *source, _In_ ULONG length)
{
    ULONG_PTR cr0 = __readcr0();

    if (SysinfoCetEnabled()) return STATUS_ACCESS_DENIED;

    _disable();
    __writecr0(cr0 & ~(ULONG_PTR)SYSINFO_CR0_WP);
    RtlCopyMemory(destination, source, length);
    __writecr0(cr0);
    _enable();

    return STATUS_SUCCESS;
}

/*
 * Write `length` bytes over read-only kernel text and make every core pick the
 * new code up.  Returns an NTSTATUS instead of bugchecking when the write is
 * not possible - callers turn that into SYSINFO_STAGE_WRITE.
 */
static NTSTATUS
WriteKernelText(_In_ PVOID destination, _In_reads_bytes_(length) const VOID *source, _In_ ULONG length)
{
    NTSTATUS status = WriteViaMdl(destination, source, length);

    if (NT_SUCCESS(status)) {
        g_WriteMethod = SYSINFO_WRITE_MDL;
    } else {
        if (SysinfoCetEnabled()) {
            /* CR0.WP is out of reach - never trade a failed hook for a BSOD. */
            DbgPrint("SysInfo: writable alias failed (0x%08X), CR4.CET set, CR0.WP untouched\n", status);
            return status;
        }
        DbgPrint("SysInfo: writable alias failed (0x%08X), falling back to CR0.WP\n", status);
        status = WriteViaCr0(destination, source, length);
        if (!NT_SUCCESS(status)) return status;
        g_WriteMethod = SYSINFO_WRITE_CR0;
    }

    KeInvalidateAllCaches();
    SyncCores();
    return STATUS_SUCCESS;
}

NTSTATUS
HookInstall(_Inout_ PHOOK hook, _In_ PVOID target, _In_ PVOID detour, _In_ PCSTR name)
{
    UCHAR    patch[PATCH_LEN];
    UCHAR    build[TRAMP_SLOT];
    ULONG    built = 0;
    NTSTATUS status;

    RtlZeroMemory(hook, sizeof(*hook));
    hook->Target = target;
    hook->Detour = detour;

    /* Preferred: a trampoline inside our (nearby) image. */
    hook->Trampoline = AllocTrampoline(TRAMP_SLOT);
    if (hook->Trampoline == NULL || !InRel32Range(hook->Trampoline, target)) {
        PUCHAR pool;

        /* Non-Nx pool: the trampoline is executed, so it must not be NX. */
        pool = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, PAGE_SIZE, 'pTrH');
        if (pool == NULL) return STATUS_INSUFFICIENT_RESOURCES;
        if (!InRel32Range(pool, target)) {
            DbgPrint("SysInfo: %s: trampoline too far even from pool (%p vs %p)\n",
                     name, pool, target);
            ExFreePoolWithTag(pool, 'pTrH');
            return STATUS_INTEGER_OVERFLOW;
        }
        hook->PoolBase = pool;
        hook->PoolTramp = TRUE;
        hook->Trampoline = pool;
    }

    /*
     * Build the trampoline in a scratch buffer first: the TRAMP section is
     * mapped read-only, so the finished bytes go there in a single write
     * instead of instruction by instruction.
     */
    status = BuildTrampoline(hook, build, &built);
    if (!NT_SUCCESS(status)) {
        if (hook->PoolTramp) ExFreePoolWithTag(hook->PoolBase, 'pTrH');
        return status;
    }

    if (hook->PoolTramp) {
        RtlCopyMemory(hook->Trampoline, build, built);    /* plain pool, writable */
        KeInvalidateAllCaches();
        SyncCores();
    } else {
        status = WriteKernelText(hook->Trampoline, build, built);
        if (!NT_SUCCESS(status)) {
            DbgPrint("SysInfo: cannot write the trampoline (%s)\n", name);
            return status;
        }
    }

    RtlCopyMemory(hook->Saved, target, hook->Stolen);
    EmitAbsJump(patch, detour);
    status = WriteKernelText(target, patch, PATCH_LEN);
    if (!NT_SUCCESS(status)) {
        DbgPrint("SysInfo: cannot patch %s (0x%08X)\n", name, status);
        return status;
    }

    hook->Installed = TRUE;
    return STATUS_SUCCESS;
}

VOID
HookRemove(_Inout_ PHOOK hook)
{
    if (hook->Installed) {
        NTSTATUS status = WriteKernelText(hook->Target, hook->Saved, hook->Stolen);

        if (!NT_SUCCESS(status)) {
            /* The target still jumps to our trampoline - keep both alive. */
            DbgPrint("SysInfo: could not restore the hooked prologue (0x%08X)\n", status);
            return;
        }
        hook->Installed = FALSE;
    }
    if (hook->PoolTramp && hook->PoolBase) {
        ExFreePoolWithTag(hook->PoolBase, 'pTrH');
        hook->PoolBase = NULL;
        hook->PoolTramp = FALSE;
    }
}
