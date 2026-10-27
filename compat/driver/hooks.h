/* hooks.h - x64 inline hook engine (trampoline based). */
#pragma once
#include <ntddk.h>

typedef struct _HOOK {
    PVOID   Target;
    PVOID   Detour;
    PVOID   Trampoline;      /* executes the stolen bytes, then jumps back */
    UCHAR   Saved[32];
    ULONG   Stolen;
    BOOLEAN Installed;
    BOOLEAN PoolTramp;       /* trampoline came from pool, free it on remove */
    PVOID   PoolBase;
} HOOK, *PHOOK;

/*
 * Patches the first bytes of `target` with an absolute jump to `detour`.
 * `hook->Trampoline` is then callable exactly like the original function.
 */
NTSTATUS HookInstall(_Inout_ PHOOK hook, _In_ PVOID target, _In_ PVOID detour, _In_ PCSTR name);
VOID     HookRemove(_Inout_ PHOOK hook);

/* Which mechanism actually managed to write read-only kernel text
 * (SYSINFO_WRITE_* from shared/sysinfo.h). */
ULONG   SysinfoPatchMethod(VOID);

/* CR4.CET: kernel shadow stacks are on, so CR0.WP cannot be cleared. */
BOOLEAN SysinfoCetEnabled(VOID);

/* Memory Integrity (HVCI): kernel text is write-protected below the OS, so
 * hooking cannot work at all.  Cached probe; never triggers the patch path. */
BOOLEAN SysinfoHvciEnforced(VOID);

/* A hypervisor is running (CPUID leaf 1, ECX bit 31).  With VBS/HyperGuard
 * this means kernel code pages are hash-verified, so *any* inline hook is
 * eventually a 0x18B SECURE_KERNEL_ERROR.  Plain Hyper-V also sets the bit;
 * either way this driver must not patch text while it is set. */
BOOLEAN SysinfoHypervisorPresent(VOID);

/* TRUE when installing an inline hook would be unsafe or impossible:
 * HVCI, or a running hypervisor (VBS/HyperGuard). */
BOOLEAN SysinfoPatchBlocked(VOID);

/* Raw SystemCodeIntegrityInformation options (for the status IOCTL). */
ULONG   SysinfoCiOptions(VOID);

/*
 * A driver must not disappear while a thread is still executing inside one of
 * its detours - the unload check turns that into
 * 0xCE DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS.  Every detour
 * brackets its body with HookEnter()/HookLeave(); DriverUnload removes the
 * hooks first (so nothing new can enter) and then waits with HookQuiesce().
 */
VOID    HookEnter(VOID);
VOID    HookLeave(VOID);
VOID    HookQuiesce(_In_ ULONG maxMilliseconds);
