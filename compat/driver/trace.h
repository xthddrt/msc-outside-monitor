/* trace.h - syscall-level activity hooks for the monitor. */
#pragma once
#include <ntddk.h>

/* Installs the file / registry / memory / kernel-callback hooks.  Inert until
 * `mon on`. */
VOID  TraceInit(VOID);
VOID  TraceShutdown(VOID);

/* How many of them actually installed (for the status IOCTL). */
ULONG TraceHookCount(VOID);

/* Install the two memory hooks that have no exported name: resolve them from the
 * syscall numbers the user-mode tool read out of ntdll.  Repeat calls are safe. */
VOID  TraceInstallMemoryHooks(_In_ ULONG ssnRead, _In_ ULONG ssnWrite);
VOID  TraceSetUnsafeHooksEnabled(_In_ ULONG enabled);
BOOLEAN TraceUnsafeHooksEnabled(VOID);
