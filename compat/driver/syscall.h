/* syscall.h - reach the nt!Nt* entry points that ntoskrnl does not export. */
#pragma once
#include <ntddk.h>

/*
 * Some Nt* entry points (NtQueryValueKey, NtQueryKey, ...) are not in
 * ntoskrnl's export table - only the matching Zw* stubs are.  Resolving by name
 * therefore returns NULL, while user-mode callers still reach the Nt* function
 * through the syscall table.  SysinfoResolveNt() falls back to the syscall table
 * entry that the exported Zw* stub for the same operation dispatches to.
 */
PVOID SysinfoResolveNt(_In_ PCWSTR ntName);

/* TRUE once the syscall table layout has been positively identified. */
BOOLEAN SysinfoSyscallCalibrated(VOID);

/* Pin the stage code when hooking stops for a reason other than calibration
 * (HVCI, a failed read-only write, ...).  Also stops further retries. */
VOID SysinfoSetStage(_In_ ULONG stage);

/* Diagnostics for the driver's status IOCTL.  Any out pointer may be NULL. */
VOID SysinfoSyscallDiag(_Out_opt_ PULONG stage, _Out_opt_ PULONG ssnA,
                     _Out_opt_ PULONG ssnB, _Out_opt_ PULONG64 table,
                     _Out_opt_ PULONG mode, _Out_opt_ PULONG stride);

/* Extra raw facts for the status IOCTL (anchors, image base/size, ...). */
VOID SysinfoSyscallMore(_Out_writes_(count) PULONG64 out, _In_ ULONG count);
/* ntoskrnl image base/size, for bounding kernel return addresses.  Base is
 * NULL until calibration has run. */
PVOID SysinfoNtImageBase(VOID);
ULONG SysinfoNtImageSize(VOID);
/* Resolve the Nt* entry for a raw syscall number (from a user-mode stub).
 * NULL when calibration has not succeeded or the number is out of range. */
PVOID SysinfoResolveSsn(_In_ ULONG ssn);
