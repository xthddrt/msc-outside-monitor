#pragma once

/*
 * Records shared by agent/linux/bpf/monitor.bpf.c (kernel) and agent/linux/bpf.cpp
 * (agent). Plain fixed-width fields only: the same layout on both sides.
 */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define MM_PATH 256        /* bytes kept per path; longer ones are flagged truncated */
#define MM_FRAMES 8        /* user return addresses per syscall record */
#define MM_SYSCALLS 512    /* x86_64 syscall numbers covered by mm_sysinfo */
#define MM_ARGV_SLOTS 8    /* execve: first 8 arguments, 32 bytes each, in path_b */
#define MM_ARGV_SLOT 32

enum mm_kind {
    MM_SYSCALL = 1,      /* one completed syscall of a tracked thread */
    MM_FORK = 2,         /* a tracked process forked a new process */
    MM_EXEC = 3,         /* a tracked process exec'd (path_a = new image, path_b = argv) */
    MM_EXIT = 4,         /* a tracked process exited */
    MM_THREAD_START = 5,
    MM_THREAD_EXIT = 6,
    MM_SCOPE = 7,        /* an untracked process mapped an executable file under the root */
    MM_DENIED = 8,       /* self-protection refused ptrace/bpf/perf_event_open (nr = which) */
    /* Records that are not struct mm_event; each starts with __u32 kind (bpf.cpp OnRing). */
    MM_TCP = 9,          /* struct mm_tcp_event (tcp_bpf.h): one TCP lifecycle fact */
    MM_WS_REQUEST = 10,  /* struct mm_ws_event (ws_bpf.h): a Wine client's request to wineserver */
    MM_WS_REPLY = 11,    /* struct mm_ws_event: wineserver's reply to it */
};

/* MM_DENIED.nr */
#define MM_DENY_PTRACE 1
#define MM_DENY_BPF 2
#define MM_DENY_PERF 3

/* mm_event.flags */
#define MM_F_TRUNC_A 0x01
#define MM_F_TRUNC_B 0x02
#define MM_F_TRUNC_K 0x04
#define MM_F_KPATH 0x08      /* kpath holds the fd's (or returned fd's) kernel path */
#define MM_F_KDIR_A 0x10     /* kdir_a holds the directory a relative path_a is under */
#define MM_F_KDIR_B 0x20
#define MM_F_SOCK 0x40       /* path_b holds sock_len bytes of a sockaddr */
#define MM_F_ARGV 0x80       /* path_b holds MM_ARGV_SLOTS argv slots */
#define MM_F_SOCKID 0x100    /* sk_* hold the identity of the resolved fd's socket (payload.bpf.h) */
#define MM_F_PAYLOAD 0x200   /* the call's bytes went to payload_ring; cap_* are valid (payload.bpf.h) */

/* mm_sysinfo.dir_* */
#define MM_DIR_NONE 0
#define MM_DIR_CWD 0xFE      /* a relative path is under the cwd */
/* 1..6: argument index + 1 that holds a dirfd (AT_FDCWD means the cwd) */

/* mm_sysinfo.sock */
#define MM_SOCK_NONE 0
#define MM_SOCK_IN_1 1       /* sockaddr in arg1, length arg2 (connect, bind) */
#define MM_SOCK_IN_4 2       /* sockaddr in arg4, length arg5 (sendto) */
#define MM_SOCK_OUT_1 3      /* sockaddr out in arg1, length pointer arg2 (accept, accept4) */
#define MM_SOCK_OUT_4 4      /* sockaddr out in arg4, length pointer arg5 (recvfrom) */
#define MM_SOCK_MSG_IN_1 5   /* msghdr in arg1, msg_name read at entry (sendmsg) */
#define MM_SOCK_MSG_OUT_1 6  /* msghdr in arg1, msg_name read at exit (recvmsg) */

/* What sys_enter captures for one syscall number; filled by the agent. */
struct mm_sysinfo {
    __u8 want;           /* 0: not recorded */
    __u8 path_a;         /* argument index + 1 of a user path, 0 = none */
    __u8 dir_a;          /* MM_DIR_* or argument index + 1 of its dirfd */
    __u8 path_b;
    __u8 dir_b;
    __u8 fd;             /* argument index + 1 of an fd whose file is resolved at entry */
    __u8 retfd;          /* 1: the return value is a new fd, resolved at exit */
    __u8 sock;           /* MM_SOCK_* */
    __u8 argv;           /* argument index + 1 of an argv array */
    __u8 data;           /* MM_DATA_* (payload_bpf.h): where the call's bytes are, captured on network sockets */
    __u8 flags_arg;      /* argument index + 1 of a MSG_* flags argument (MSG_PEEK calls are not captured) */
    __u8 pad[5];
};

#define MM_PE_BYTES 512     /* PE stack copied from TEB->syscall_frame->rsp (pe.bpf.h) */

/* The PE (Windows) side of the Wine syscall a thread is in (pe.bpf.h read_pe); rip 0 = none. 544 bytes. */
struct mm_pe {
    __u64 rip;           /* syscall_frame->rip */
    __u64 rsp;           /* syscall_frame->rsp: stack[0] is the qword at rsp */
    __u64 rbp;           /* syscall_frame->rbp */
    __u32 bytes;         /* bytes copied into stack (0..MM_PE_BYTES) */
    __u32 pad;
    __u8 stack[MM_PE_BYTES];
};

struct mm_event {
    __u32 kind;
    __u32 tgid;
    __u32 tid;
    __u32 ppid;
    __u64 start_ns;      /* group leader start_boottime: /proc/<pid>/stat starttime in ns */
    __u64 ts_ns;         /* CLOCK_BOOTTIME at the record */
    __u64 dur_ns;
    __s64 ret;
    __u64 args[6];
    __u32 nr;
    __u32 frames;
    __u32 mode;          /* i_mode of the resolved file */
    __u32 flags;         /* MM_F_* */
    __u64 pos;           /* f_pos of the fd at entry */
    __u64 ino;           /* inode number of the resolved file */
    __u64 stack[MM_FRAMES];
    __u32 target_tgid;   /* MM_FORK: the child; MM_DENIED: the target */
    __u32 sock_len;
    char path_a[MM_PATH];
    char path_b[MM_PATH];
    char kpath[MM_PATH];
    char kdir_a[MM_PATH];
    char kdir_b[MM_PATH];
    /* The resolved fd's socket (MM_F_SOCKID) and the call's byte capture (MM_F_PAYLOAD): payload.bpf.h. */
    __u16 sk_family;
    __u16 sk_type;
    __u16 sk_protocol;
    __u16 sk_lport;      /* host order */
    __u16 sk_rport;      /* host order */
    __u16 sk_pad;
    __u32 cap_bytes;     /* bytes sent to payload_ring */
    __u8 sk_laddr[16];   /* network order; IPv4 in the first 4 bytes */
    __u8 sk_raddr[16];
    __u32 cap_stop;      /* MM_CAP_* (payload_bpf.h) */
    __u32 cap_pad;
    struct mm_pe pe;     /* must stay last: a record without a PE context ends before it (MM_EVENT_SHORT) */
};

/* Ring bytes of an mm_event whose pe.rip is 0 (mm_sys_exit reserves only these). */
#define MM_EVENT_SHORT __builtin_offsetof(struct mm_event, pe)

/* config map, key 0: written by the agent after load, before attach. */
struct mm_config {
    __u32 agent_tgid;
    __u32 root_len;      /* 0: no in-kernel scope check */
    char root[MM_PATH];  /* the scope root, no trailing '/' */
    __u32 flags;         /* MM_CFG_* */
    __u32 pad;
};
#define MM_CFG_PAYLOAD 0x1   /* capture socket bytes (payload.bpf.h); off with --no-payloads */

/* tracked map value */
struct mm_tracked {
    __u64 start_ns;
    __u32 flags;         /* MsMonFlagExplicitTrack / MsMonFlagInheritedTrack */
    __u32 pad;
};

/* Records and constants each upgrade shares between its BPF code and its agent code. */
#include "payload_bpf.h"
#include "tcp_bpf.h"
#include "pkt_bpf.h"
#include "ws_bpf.h"
