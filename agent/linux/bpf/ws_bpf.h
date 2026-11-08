#pragma once
/*
 * Wineserver requests (ws.bpf.h captures, agent/linux/wineserver.cpp decodes). Included by
 * monitor_bpf.h after struct mm_pe; MM_WS_REQUEST / MM_WS_REPLY are its kinds. No protocol numbers
 * here: the agent writes the wanted requests into ws_cfg (WsCaptureConfig).
 */

#define MM_WS_FIXED 64       /* every request and reply starts with a 64-byte fixed part */
#define MM_WS_DATA 8192      /* bytes kept of the request vararg / of the reply data (one payload chunk) */
#define MM_WS_F_COMPAT 0x1   /* the client is a 32-bit (ia32) Wine process */

struct mm_ws_event {
    __u32 kind;          /* MM_WS_REQUEST or MM_WS_REPLY */
    __u32 tgid;
    __u32 tid;
    __u32 req;           /* request number; a reply carries the number of the request it answers */
    __u32 total;         /* request: request_header.request_size; reply: reply_header.reply_size */
    __u32 data_len;      /* bytes of data[] filled, <= MM_WS_DATA */
    __u32 win_pid;       /* request: TEB ClientId (Windows process and thread id) */
    __u32 win_tid;
    __u32 frames;        /* request: user return addresses in stack[] */
    __u32 flags;         /* MM_WS_F_* */
    __u64 start_ns;      /* group leader start_boottime */
    __u64 ts_ns;         /* CLOCK_BOOTTIME */
    __u64 stack[MM_FRAMES];
    __u8 fixed[MM_WS_FIXED];
    struct mm_pe pe;     /* request: the PE side of the Nt* call (pe.bpf.h); rip 0 = none, replies too */
    /* Only MM_WS_DATA bytes are used; the upper half keeps every copy's end in bounds for the verifier.
     * The ring record ends after data_len bytes of it. */
    __u8 data[2 * MM_WS_DATA];
};

/* ws_inflight value, key tid: a wanted request whose reply has not been read yet. */
struct mm_ws_inflight {
    __u32 req;
    __s32 reply_fd;
    __u32 compat;
    __u32 phase;         /* 0: the 64-byte reply is next; 1: its data is next */
    __u32 data;          /* 1: capture the reply data (else the reply is sent after its 64 bytes) */
    __u32 pad;
    __u8 header[MM_WS_FIXED];
};

/* ws_cfg value, key 0: written by the agent from its protocol table before attach. */
struct mm_ws_config {
    __u64 want[8];           /* bit n: capture request number n */
    __u64 data[8];           /* bit n: also capture the reply data of request n */
    __u32 ioctl_req;         /* the 'ioctl' request; captured only for ioctl_codes */
    __u32 ioctl_codes[8];    /* 0 = unused */
    __u32 pad;
};

#ifdef __cplusplus
static_assert(__builtin_offsetof(struct mm_ws_event, fixed) == 120, "mm_ws_event.fixed");
static_assert(__builtin_offsetof(struct mm_ws_event, pe) == 184, "mm_ws_event.pe");
static_assert(__builtin_offsetof(struct mm_ws_event, data) == 728, "mm_ws_event.data");
static_assert(sizeof(struct mm_ws_event) == 728 + 2 * MM_WS_DATA, "mm_ws_event size");
static_assert(sizeof(struct mm_ws_config) == 168, "mm_ws_config size");
#else
_Static_assert(__builtin_offsetof(struct mm_ws_event, data) == 728, "mm_ws_event.data");
_Static_assert(sizeof(struct mm_ws_event) == 728 + 2 * MM_WS_DATA, "mm_ws_event size");
_Static_assert(sizeof(struct mm_ws_config) == 168, "mm_ws_config size");
#endif
