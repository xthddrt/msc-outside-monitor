#pragma once
/*
 * guard.h - policy-driven access guard for the activity monitor.
 *
 * Target processes: supplied by the policy.  This build has no compiled-in
 * target list, so nothing is watched until a policy names it.
 * Protected resources: browser profile paths, browser registry subtrees and
 * browser process handles.  Policy matching is substring based, so it does not
 * depend on the current user's profile path.
 *
 * Mode is OFF, AUDIT (log only) or ENFORCE (return access denied).
 */
#include <ntddk.h>
#include "../shared/sysinfo.h"

#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD       0x0002
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ             0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE            0x0020
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE          0x0040
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME      0x0800
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME       0x0002
#endif
#ifndef THREAD_GET_CONTEXT
#define THREAD_GET_CONTEXT          0x0008
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT          0x0010
#endif
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN     0x0080
#endif
#ifndef THREAD_IMPERSONATE
#define THREAD_IMPERSONATE          0x0100
#endif

NTSTATUS GuardInit(VOID);
VOID     GuardShutdown(VOID);
NTSTATUS GuardConfigure(_In_ const SYSINFO_GUARD_CONFIG *Config);
NTSTATUS GuardGetStatus(_Out_ PSYSINFO_GUARD_STATUS Status);

/* Current process is one of the target images. */
BOOLEAN GuardIsTargetProcess(VOID);

/* Pre-operation checks.  Return TRUE when the caller should be denied. */
BOOLEAN GuardFileBlocked(_In_ PCUNICODE_STRING Path, _In_ ACCESS_MASK Access);
BOOLEAN GuardRegistryBlocked(_In_ PCUNICODE_STRING Path, _In_ ACCESS_MASK Access);
BOOLEAN GuardProcessHandleBlocked(_In_ HANDLE TargetPid, _In_ ACCESS_MASK Access);
BOOLEAN GuardMemoryBlocked(_In_ HANDLE ProcessHandle, _In_ ACCESS_MASK Access);

/* Object-manager pre-op: strip rights in enforce mode, log in audit mode. */
VOID GuardPreHandle(_Inout_ POB_PRE_OPERATION_INFORMATION Info);
