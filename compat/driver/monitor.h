/* monitor.h - record what processes and drivers actually do. */
#pragma once
#include <ntddk.h>
#include "../shared/sysinfo.h"

/* Registers the kernel notifications.  Cheap; no events are recorded until the
 * configuration enables it. */
NTSTATUS MonInit(VOID);
VOID     MonShutdown(VOID);

/* Enable/disable and set the PID filter. */
NTSTATUS MonConfigure(_In_ const SYSINFO_MON_CONFIG *config);
VOID     MonQuery(_Out_ PSYSINFO_MON_CONFIG config, _Out_ PULONG dropped);

/* Drain up to `max` events into the caller's IOCTL buffer. */
NTSTATUS MonRead(_Out_writes_bytes_(outLength) PVOID outBuffer, _In_ ULONG outLength);

/* Page through the never-dropping summary table. */
NTSTATUS MonSummary(_In_reads_bytes_(inLen) PVOID inBuffer, _In_ ULONG inLen,
                    _Out_writes_bytes_(outLength) PVOID outBuffer, _In_ ULONG outLength);

/* Used by the Nt* detours.  No-op when monitoring is off or the PID is
 * filtered out.  `path` may be NULL. */
VOID MonEvent(_In_ ULONG type, _In_ ULONG op, _In_opt_ PCUNICODE_STRING path,
              _In_opt_ PCSTR detail);

/* TRUE when an event from the current process would actually be recorded -
 * use it to skip expensive work (opening handles, formatting paths). */
BOOLEAN MonActive(VOID);

/* IOCTL payload capture: does this device match, and how many bytes. */
BOOLEAN MonIoctlWanted(_In_opt_ PCUNICODE_STRING device);
ULONG   MonIoctlBytes(VOID);

/* Same as MonEvent but ignores the pid/image filter, for ring-0 memory work. */
VOID MonEventForced(_In_ ULONG type, _In_ ULONG op, _In_opt_ PCUNICODE_STRING path,
                    _In_opt_ PCSTR detail);

/* Monitor state for the status IOCTL. */
VOID    MonDiag(_Out_writes_(SYSINFO_DIAG_COUNT) PULONG64 diag);
