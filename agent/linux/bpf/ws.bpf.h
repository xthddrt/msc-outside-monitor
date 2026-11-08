/*
 * Wineserver requests (wineserver upgrade; agent/linux/wineserver.cpp decodes them, docs/LINUX.md
 * "Wineserver requests"). A Wine thread sends each request to wineserver over its own request pipe:
 * write(request_fd, req, 64) without variable data, else writev(request_fd, {req[64], data...}); it
 * reads the reply from its reply pipe: read(reply_fd, reply, 64), then read(reply_fd, data, n). Both
 * fds sit in the thread's TEB (ntdll_thread_data). mm_ws_enter copies the wanted requests (ws_cfg) to
 * the events ring as MM_WS_REQUEST; mm_ws_exit copies their replies as MM_WS_REPLY.
 *
 * Optional group "wineserver" (programs mm_ws_*): if the verifier refuses it, only these records are
 * lost. Reuses events, count_drop, current_tracked, fd_file, compat_syscall and read_pe.
 */

#define WS_S_IFIFO 0010000
/* TEB layout of Wine 11 (unix_private.h ntdll_thread_data in TEB.GdiTebBatch; winternl.h TEB). The
 * fd offsets are computed, not asserted by Wine, so the request fd is also checked to be a pipe. */
#define WS_TEB64_SELF 0x30        /* NT_TIB.Self */
#define WS_TEB64_CLIENT_ID 0x40   /* ClientId: u64 UniqueProcess, UniqueThread */
#define WS_TEB64_FDS 0x384        /* request_fd, reply_fd */
#define WS_TEB32_SELF 0x18
#define WS_TEB32_CLIENT_ID 0x20
#define WS_TEB32_FDS 0x220
#define WS_DATA_MASK (MM_WS_DATA - 1)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mm_ws_config);
} ws_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct mm_ws_inflight);
} ws_inflight SEC(".maps");

/* One event per CPU (about 17 KB: too big for the stack). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mm_ws_event);
} ws_scratch SEC(".maps");

/* The thread's Wine TEB or 0. 64-bit: the GS base, whose Tib.Self (+0x30) points at itself (Wine sets
 * it once per thread with arch_prctl(ARCH_SET_GS)). ia32: the GDT TLS descriptor Wine loads FS with
 * (set_thread_area), found as the one whose base has Tib.Self (+0x18) == base.
 * Verifier-safe: no loop beyond three unrolled steps; constant offsets and constant-size probe reads. */
static __always_inline __u64 ws_teb(struct task_struct* task, int compat)
{
    if (!compat) {
        __u64 teb = BPF_CORE_READ(task, thread.gsbase), self = 0;
        if (!teb || bpf_probe_read_user(&self, sizeof(self), (void*)(teb + WS_TEB64_SELF))) return 0;
        return self == teb ? teb : 0;
    }
#pragma unroll
    for (int i = 0; i < 3; i++) {
        __u64 raw = 0;
        __u32 self = 0;
        bpf_probe_read_kernel(&raw, sizeof(raw), __builtin_preserve_access_index(&task->thread.tls_array[i]));
        __u64 base = ((raw >> 16) & 0xffffff) | ((raw >> 56) << 24);
        if (base && bpf_probe_read_user(&self, sizeof(self), (void*)(base + WS_TEB32_SELF)) == 0 && self == base)
            return base;
    }
    return 0;
}

struct ws_copy {
    __u64 iov;      /* the writev iovec array */
    __u32 count;    /* iovcnt */
    __u32 compat;   /* compat_iovec (8 bytes) instead of iovec (16) */
    __u32 pos;      /* bytes copied into data[] */
    __u32 total;    /* bytes the data iovecs hold */
    __u32 stop;     /* a chunk could not be read: copy nothing more, keep summing lengths */
};

/* bpf_loop callback: appends iovec index + 1 (iovec 0 is the fixed part) to data[].
 * Verifier-safe: checked once as a callback; the offset is masked below MM_WS_DATA and the length is
 * re-checked <= MM_WS_DATA after a barrier, so every write ends inside data[2 * MM_WS_DATA]. */
static long ws_chunk(__u32 index, struct ws_copy* c)
{
    __u32 zero = 0;
    struct mm_ws_event* e = bpf_map_lookup_elem(&ws_scratch, &zero);
    if (!e || index + 1 >= c->count) return 1;
    __u64 base = 0, len = 0;
    if (c->compat) {
        __u32 v[2] = {};
        if (bpf_probe_read_user(v, sizeof(v), (void*)(c->iov + (__u64)(index + 1) * 8))) return 1;
        base = v[0];
        len = v[1];
    } else {
        __u64 v[2] = {};
        if (bpf_probe_read_user(v, sizeof(v), (void*)(c->iov + (__u64)(index + 1) * 16))) return 1;
        base = v[0];
        len = v[1];
    }
    c->total += (__u32)len;
    if (len == 0 || c->pos >= MM_WS_DATA || c->stop) return 0;   /* past the cap: keep summing lengths */
    __u32 off = c->pos;
    barrier_var(off);
    off &= WS_DATA_MASK;
    __u32 take = len < MM_WS_DATA ? (__u32)len : MM_WS_DATA;
    if (take > MM_WS_DATA - off) take = MM_WS_DATA - off;
    barrier_var(take);
    if (take > MM_WS_DATA) return 1;
    /* A page not faulted in yet (non-sleepable program): keep the request with the bytes so far; the
     * agent sees data_len < total and reports payload_truncated / truncated_path. */
    if (bpf_probe_read_user(&e->data[off], take, (void*)base)) {
        c->stop = 1;
        return 0;
    }
    c->pos = off + take;
    return 0;
}

/* Verifier-safe: straight-line helper calls and constant-offset stores into a map value. */
static __always_inline void ws_ids(struct mm_ws_event* e, struct task_struct* task)
{
    __u64 id = bpf_get_current_pid_tgid();
    e->tgid = id >> 32;
    e->tid = (__u32)id;
    e->start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    e->ts_ns = bpf_ktime_get_boot_ns();
}

/* A tracked Wine thread writes a request to its request pipe.
 * Verifier-safe: straight-line apart from ws_teb's 3 unrolled steps, the 8 unrolled early-exit ioctl-code compares
 * and one bpf_loop of at most 5 (ws_chunk); the want bitmap index is masked to 0..7; every copy has a
 * constant size or one clamped to MM_WS_DATA; read_pe is pe.bpf.h's bounded copy; one ring output whose
 * size is clamped to offsetof(data) + MM_WS_DATA. */
SEC("tp_btf/sys_enter")
int BPF_PROG(mm_ws_enter, struct pt_regs* regs, long id)
{
    if (id != 1 && id != 20 && id != 4 && id != 146) return 0;   /* write, writev; ia32 write, writev */
    struct task_struct* task = bpf_get_current_task_btf();
    int compat = compat_syscall(task);
    __u32 vec = id == (compat ? 146 : 20);
    if (!vec && id != (compat ? 4 : 1)) return 0;
    if (!current_tracked()) return 0;
    __u64 teb = ws_teb(task, compat);
    if (!teb) return 0;
    __s32 fds[2] = {};   /* request_fd, reply_fd */
    if (bpf_probe_read_user(fds, sizeof(fds), (void*)(teb + (compat ? WS_TEB32_FDS : WS_TEB64_FDS)))) return 0;
    __u64 fd = compat ? BPF_CORE_READ(regs, bx) : BPF_CORE_READ(regs, di);
    __u64 buf = compat ? BPF_CORE_READ(regs, cx) : BPF_CORE_READ(regs, si);
    __u64 count = BPF_CORE_READ(regs, dx);
    if (fds[0] < 0 || (__s32)fd != fds[0]) return 0;
    /* request_fd is a computed TEB offset: insist that it is a pipe. */
    struct file* file = fd_file(task, fds[0]);
    if (!file || (BPF_CORE_READ(file, f_inode, i_mode) & S_IFMT) != WS_S_IFIFO) return 0;
    __u32 zero = 0;
    struct mm_ws_event* e = bpf_map_lookup_elem(&ws_scratch, &zero);
    struct mm_ws_config* c = bpf_map_lookup_elem(&ws_cfg, &zero);
    if (!e || !c) return 0;
    __u64 fixed = buf;
    if (vec) {
        if (count < 2 || count > 6) return 0;   /* the fixed part and 1..5 data chunks */
        __u64 first[2] = {};
        if (bpf_probe_read_user(first, compat ? 8 : 16, (void*)buf)) return 0;
        fixed = compat ? (__u32)first[0] : first[0];
        __u64 len0 = compat ? first[0] >> 32 : first[1];
        if (len0 != MM_WS_FIXED) return 0;     /* a resumed partial writev starts inside a request */
    } else if (count != MM_WS_FIXED) {
        return 0;
    }
    if (bpf_probe_read_user(e->fixed, MM_WS_FIXED, (void*)fixed)) return 0;
    __u32 req = *(__u32*)&e->fixed[0];
    __u32 size = *(__u32*)&e->fixed[4];
    if (vec != (size != 0)) return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&ws_inflight, &tid);    /* a new request ends any unanswered one */
    if (req >= 512 || !(c->want[(req >> 6) & 7] & (1ull << (req & 63)))) return 0;
    __u32 data = (c->data[(req >> 6) & 7] >> (req & 63)) & 1;
    if (req == c->ioctl_req) {
        /* Early exit: every match reaches the same state, so the verifier walks at most 9 paths here
         * (an OR of 8 data-dependent compares would keep up to 2^8 apart). A code 0 matching an unused
         * slot is harmless: the agent decodes nothing from it. */
        __u32 code = *(__u32*)&e->fixed[12], hit = 0;
#pragma unroll
        for (int i = 0; i < 8; i++) {
            if (c->ioctl_codes[i] == code) {
                hit = 1;
                break;
            }
        }
        if (!hit) return 0;
    }
    e->kind = MM_WS_REQUEST;
    e->req = req;
    e->total = size;
    e->flags = compat ? MM_WS_F_COMPAT : 0;
    e->data_len = 0;
    ws_ids(e, task);
    if (compat) {
        __u32 ids[2] = {};
        bpf_probe_read_user(ids, sizeof(ids), (void*)(teb + WS_TEB32_CLIENT_ID));
        e->win_pid = ids[0];
        e->win_tid = ids[1];
    } else {
        __u64 ids[2] = {};
        bpf_probe_read_user(ids, sizeof(ids), (void*)(teb + WS_TEB64_CLIENT_ID));
        e->win_pid = (__u32)ids[0];
        e->win_tid = (__u32)ids[1];
    }
    if (vec) {
        struct ws_copy copy = {.iov = buf, .count = (__u32)count, .compat = (__u32)compat};
        bpf_loop(5, ws_chunk, &copy, 0);
        if (copy.total != size) return 0;       /* not a request after all */
        e->data_len = copy.pos;
    }
    long bytes = bpf_get_stack(ctx, e->stack, sizeof(e->stack), BPF_F_USER_STACK);
    e->frames = bytes > 0 ? (__u32)(bytes / sizeof(__u64)) : 0;
    e->pe.rip = 0;
    e->pe.bytes = 0;
    /* The request runs inside an Nt* call, so TEB->syscall_frame is valid. shortcut: no PE frames for
     * ia32 clients (read_pe reads the 64-bit TEB); add an ia32 reader with the pecaller upgrade's. */
    if (!compat) read_pe(&e->pe, task, regs);
    __u32 len = e->data_len;
    barrier_var(len);
    if (len > MM_WS_DATA) len = MM_WS_DATA;
    if (bpf_ringbuf_output(&events, e, __builtin_offsetof(struct mm_ws_event, data) + len, 0)) {
        count_drop();
        return 0;
    }
    struct mm_ws_inflight f = {.req = req, .reply_fd = fds[1], .compat = (__u32)compat, .data = data};
    bpf_map_update_elem(&ws_inflight, &tid, &f, BPF_ANY);
    return 0;
}

/* The reply to an in-flight wanted request: read(reply_fd, reply, 64), then read(reply_fd, data, n).
 * Verifier-safe: straight-line; constant 64-byte copies and one copy whose size is clamped to
 * MM_WS_DATA after a barrier, at offset 0 of data[]; one ring output of at most offsetof(data) +
 * MM_WS_DATA. Cheap for every other syscall exit: one compare of ret and nr, one hash lookup. */
SEC("tp_btf/sys_exit")
int BPF_PROG(mm_ws_exit, struct pt_regs* regs, long ret)
{
    if (ret <= 0) return 0;
    long nr = BPF_CORE_READ(regs, orig_ax);
    if (nr != 0 && nr != 3) return 0;          /* read; ia32 read */
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mm_ws_inflight* f = bpf_map_lookup_elem(&ws_inflight, &tid);
    if (!f || nr != (f->compat ? 3 : 0)) return 0;
    __u64 fd = f->compat ? BPF_CORE_READ(regs, bx) : BPF_CORE_READ(regs, di);
    __u64 buf = f->compat ? BPF_CORE_READ(regs, cx) : BPF_CORE_READ(regs, si);
    if ((__s32)fd != f->reply_fd) return 0;
    if (!f->phase) {
        if (ret != MM_WS_FIXED || bpf_probe_read_user(f->header, MM_WS_FIXED, (void*)buf)) {
            bpf_map_delete_elem(&ws_inflight, &tid);
            return 0;
        }
        if (*(__u32*)&f->header[4] && f->data) {   /* reply_size: its data is read next */
            f->phase = 1;
            return 0;
        }
    }
    __u32 zero = 0;
    struct mm_ws_event* e = bpf_map_lookup_elem(&ws_scratch, &zero);
    if (!e) {
        bpf_map_delete_elem(&ws_inflight, &tid);
        return 0;
    }
    __builtin_memcpy(e->fixed, f->header, MM_WS_FIXED);
    __u32 take = 0;
    if (f->phase) {
        take = ret > MM_WS_DATA ? MM_WS_DATA : (__u32)ret;
        barrier_var(take);
        if (take > MM_WS_DATA) take = MM_WS_DATA;
        if (bpf_probe_read_user(e->data, take, (void*)buf)) take = 0;
    }
    e->kind = MM_WS_REPLY;
    e->req = f->req;
    e->total = *(__u32*)&f->header[4];
    e->data_len = take;
    e->flags = f->compat ? MM_WS_F_COMPAT : 0;
    e->win_pid = e->win_tid = e->frames = 0;
    e->pe.rip = 0;
    e->pe.bytes = 0;
    ws_ids(e, bpf_get_current_task_btf());
    bpf_map_delete_elem(&ws_inflight, &tid);
    if (bpf_ringbuf_output(&events, e, __builtin_offsetof(struct mm_ws_event, data) + take, 0)) count_drop();
    return 0;
}
