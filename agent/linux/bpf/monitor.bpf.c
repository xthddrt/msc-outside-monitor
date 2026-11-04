// SPDX-License-Identifier: GPL-2.0
/*
 * msmon kernel sensors (see docs/LINUX.md): every recorded syscall of a tracked
 * process with its arguments, result, duration, kernel-resolved paths and an 8-frame
 * user stack; process/thread lifetime from the scheduler tracepoints; in-kernel
 * inheritance so a child is tracked before it runs; and three LSM hooks that refuse
 * the tracked tree ptrace, bpf() and perf_event_open against the agent.
 *
 * Paths are rebuilt from dentries (no bpf_d_path: it is refused in tracepoints and in
 * non-sleepable LSM hooks), so a path is the name in the task's mount namespace.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "monitor_bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define AT_FDCWD -100
#define PROT_EXEC 0x4
#define EPERM 1
#define WALK_LEN 4096
#define WALK_MASK (WALK_LEN - 1)
#define WALK_DEPTH 64

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mm_config);
} mm_cfg SEC(".maps");

static __always_inline struct mm_config* cfg(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&mm_cfg, &zero);
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct mm_tracked);
} tracked SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MM_SYSCALLS);
    __type(key, __u32);
    __type(value, struct mm_sysinfo);
} sysinfo SEC(".maps");

/* One in-flight syscall per thread; LRU so a thread that vanished mid-call is reclaimed. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct mm_event);
} pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mm_event);
} scratch SEC(".maps");

struct walk_buf {
    char data[WALK_LEN + 256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct walk_buf);
} walkbuf SEC(".maps");

/* Records lost because the ring was full; the agent turns increases into sequence gaps. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");

static __always_inline void count_drop(void)
{
    __u32 zero = 0;
    __u64* value = bpf_map_lookup_elem(&drops, &zero);
    if (value) __sync_fetch_and_add(value, 1);
}

struct walk_ctx {
    struct dentry* d;
    struct vfsmount* vfs;
    struct mount* mnt;
    __u32 off;
};

static long walk_step(__u32 index, struct walk_ctx* c)
{
    __u32 zero = 0;
    struct walk_buf* buf = bpf_map_lookup_elem(&walkbuf, &zero);
    if (!buf) return 1;
    /* Locals, so CO-RE relocates the kernel structs and not walk_ctx. */
    struct dentry* d = c->d;
    struct vfsmount* vfs = c->vfs;
    struct mount* mnt = c->mnt;
    struct dentry* root = BPF_CORE_READ(vfs, mnt_root);
    if (d == root) {
        struct mount* parent = BPF_CORE_READ(mnt, mnt_parent);
        if (!parent || parent == mnt) return 1;
        c->d = BPF_CORE_READ(mnt, mnt_mountpoint);
        c->mnt = parent;
        c->vfs = (struct vfsmount*)((void*)parent + bpf_core_field_offset(struct mount, mnt));
        return 0;
    }
    struct dentry* up = BPF_CORE_READ(d, d_parent);
    if (!up || up == d) return 1;
    __u32 len = BPF_CORE_READ(d, d_name.len) & 255;
    const unsigned char* name = BPF_CORE_READ(d, d_name.name);
    __u32 off = c->off;
    if (len == 0 || off <= len + 1) return 1;
    off -= len;
    bpf_probe_read_kernel(&buf->data[off & WALK_MASK], len, name);
    off -= 1;
    buf->data[off & WALK_MASK] = '/';
    c->off = off;
    c->d = up;
    return 0;
}

/* Absolute path of Path into Out (MM_PATH bytes). Returns 1 when Out was truncated,
 * -1 when nothing could be resolved. */
static __noinline int walk_path(const struct path* path, char* out)
{
    __u32 zero = 0;
    struct walk_buf* buf = bpf_map_lookup_elem(&walkbuf, &zero);
    if (!buf || !path || !out) return -1;
    struct walk_ctx c = {};
    c.d = BPF_CORE_READ(path, dentry);
    c.vfs = BPF_CORE_READ(path, mnt);
    if (!c.d || !c.vfs) return -1;
    c.mnt = (struct mount*)((void*)c.vfs - bpf_core_field_offset(struct mount, mnt));
    c.off = WALK_LEN - 1;
    buf->data[WALK_LEN - 1] = 0;
    bpf_loop(WALK_DEPTH, walk_step, &c, 0);
    if (c.off == WALK_LEN - 1) {
        c.off -= 1;
        buf->data[c.off & WALK_MASK] = '/';
    }
    bpf_probe_read_kernel_str(out, MM_PATH, &buf->data[c.off & WALK_MASK]);
    return (WALK_LEN - 1 - c.off) >= MM_PATH ? 1 : 0;
}

static __always_inline struct file* fd_file(struct task_struct* task, int fd)
{
    struct file* file = 0;
    if (fd < 0) return 0;
    struct fdtable* table = BPF_CORE_READ(task, files, fdt);
    if (!table) return 0;
    unsigned int max = BPF_CORE_READ(table, max_fds);
    if ((unsigned int)fd >= max) return 0;
    struct file** array = BPF_CORE_READ(table, fd);
    bpf_probe_read_kernel(&file, sizeof(file), &array[fd]);
    return file;
}

/* The fd's file into kpath/mode/ino/pos. */
static __always_inline void resolve_fd(struct mm_event* e, struct task_struct* task, int fd)
{
    struct file* file = fd_file(task, fd);
    if (!file) return;
    e->mode = BPF_CORE_READ(file, f_inode, i_mode);
    e->ino = BPF_CORE_READ(file, f_inode, i_ino);
    e->pos = BPF_CORE_READ(file, f_pos);
    int result = walk_path(__builtin_preserve_access_index(&file->f_path), e->kpath);
    if (result >= 0) e->flags |= MM_F_KPATH | (result ? MM_F_TRUNC_K : 0);
}

/* The directory a relative path is resolved against: a dirfd's file, or the cwd. */
static __always_inline int resolve_dir(struct task_struct* task, int dirfd, char* out)
{
    if (dirfd == AT_FDCWD) {
        struct fs_struct* fs = BPF_CORE_READ(task, fs);
        if (!fs) return -1;
        return walk_path(__builtin_preserve_access_index(&fs->pwd), out);
    }
    struct file* file = fd_file(task, dirfd);
    if (!file) return -1;
    return walk_path(__builtin_preserve_access_index(&file->f_path), out);
}

static __always_inline __u64 arg_at(struct mm_event* e, __u8 index)
{
    /* index is argument index + 1 */
    switch (index) {
    case 1: return e->args[0];
    case 2: return e->args[1];
    case 3: return e->args[2];
    case 4: return e->args[3];
    case 5: return e->args[4];
    case 6: return e->args[5];
    default: return 0;
    }
}

static __always_inline int read_user_path(struct mm_event* e, __u8 index, char* out, __u32 trunc)
{
    const char* pointer = (const char*)arg_at(e, index);
    out[0] = 0;
    if (!pointer) return -1;
    long length = bpf_probe_read_user_str(out, MM_PATH, pointer);
    if (length <= 0) {
        out[0] = 0;
        return -1;
    }
    if (length == MM_PATH) e->flags |= trunc;
    return 0;
}

static __always_inline void dir_for(struct mm_event* e, struct task_struct* task, __u8 dir, const char* path,
                                    char* out, __u32 flag)
{
    out[0] = 0;
    if (dir == MM_DIR_NONE || path[0] == '/' || path[0] == 0) return;
    int dirfd = dir == MM_DIR_CWD ? AT_FDCWD : (int)arg_at(e, dir);
    if (resolve_dir(task, dirfd, out) >= 0) e->flags |= flag;
}

static __always_inline void fill_identity(struct mm_event* e, struct task_struct* task)
{
    __u64 id = bpf_get_current_pid_tgid();
    e->tgid = id >> 32;
    e->tid = (__u32)id;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    e->ts_ns = bpf_ktime_get_boot_ns();
}

static __always_inline struct mm_event* fresh_scratch(void)
{
    __u32 zero = 0;
    struct mm_event* e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e) return 0;
    e->kind = 0;
    e->flags = 0;
    e->mode = 0;
    e->ino = 0;
    e->pos = 0;
    e->frames = 0;
    e->ret = 0;
    e->dur_ns = 0;
    e->target_tgid = 0;
    e->sock_len = 0;
    e->path_a[0] = 0;
    e->path_b[0] = 0;
    e->kpath[0] = 0;
    e->kdir_a[0] = 0;
    e->kdir_b[0] = 0;
    return e;
}

static __always_inline int current_tracked(void)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&tracked, &tgid) != 0;
}

static __always_inline void read_sockaddr(struct mm_event* e, const void* pointer, __u32 length)
{
    if (!pointer || length == 0) return;
    if (length > MM_PATH) length = MM_PATH;
    length &= 0x1ff;
    if (length > MM_PATH) return;
    if (bpf_probe_read_user(e->path_b, length, pointer) == 0) {
        e->sock_len = length;
        e->flags |= MM_F_SOCK;
    }
}

static __always_inline void read_argv(struct mm_event* e, const char* const* argv)
{
    e->flags |= MM_F_ARGV;
#pragma unroll
    for (int slot = 0; slot < MM_ARGV_SLOTS; slot++) {
        const char* arg = 0;
        e->path_b[slot * MM_ARGV_SLOT] = 0;
        if (!argv || bpf_probe_read_user(&arg, sizeof(arg), &argv[slot]) != 0 || !arg) break;
        bpf_probe_read_user_str(&e->path_b[slot * MM_ARGV_SLOT], MM_ARGV_SLOT, arg);
    }
}

SEC("tp_btf/sys_enter")
int BPF_PROG(mm_sys_enter, struct pt_regs* regs, long id)
{
    if (!current_tracked()) return 0;
    if (id < 0 || id >= MM_SYSCALLS) return 0;
    __u32 nr = (__u32)id;
    struct mm_sysinfo* info = bpf_map_lookup_elem(&sysinfo, &nr);
    if (!info || !info->want) return 0;
    struct mm_event* e = fresh_scratch();
    if (!e) return 0;
    struct task_struct* task = bpf_get_current_task_btf();
    e->kind = MM_SYSCALL;
    e->nr = nr;
    fill_identity(e, task);
    e->args[0] = BPF_CORE_READ(regs, di);
    e->args[1] = BPF_CORE_READ(regs, si);
    e->args[2] = BPF_CORE_READ(regs, dx);
    e->args[3] = BPF_CORE_READ(regs, r10);
    e->args[4] = BPF_CORE_READ(regs, r8);
    e->args[5] = BPF_CORE_READ(regs, r9);
    if (info->path_a && read_user_path(e, info->path_a, e->path_a, MM_F_TRUNC_A) == 0)
        dir_for(e, task, info->dir_a, e->path_a, e->kdir_a, MM_F_KDIR_A);
    if (info->path_b && read_user_path(e, info->path_b, e->path_b, MM_F_TRUNC_B) == 0)
        dir_for(e, task, info->dir_b, e->path_b, e->kdir_b, MM_F_KDIR_B);
    if (info->fd) resolve_fd(e, task, (int)arg_at(e, info->fd));
    if (info->sock == MM_SOCK_IN_1) read_sockaddr(e, (const void*)e->args[1], (__u32)e->args[2]);
    else if (info->sock == MM_SOCK_IN_4) read_sockaddr(e, (const void*)e->args[4], (__u32)e->args[5]);
    if (info->argv) read_argv(e, (const char* const*)arg_at(e, info->argv));
    __u32 tid = e->tid;
    bpf_map_update_elem(&pending, &tid, e, BPF_ANY);
    return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(mm_sys_exit, struct pt_regs* regs, long ret)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mm_event* p = bpf_map_lookup_elem(&pending, &tid);
    if (!p) return 0;
    __u32 nr = p->nr;
    struct mm_sysinfo* info = bpf_map_lookup_elem(&sysinfo, &nr);
    if (!info) {
        bpf_map_delete_elem(&pending, &tid);
        return 0;
    }
    /* execve/execveat are logged by sched_process_exec when they succeed. */
    if (info->want == 2 && ret == 0) {
        bpf_map_delete_elem(&pending, &tid);
        return 0;
    }
    struct task_struct* task = bpf_get_current_task_btf();
    __u64 now = bpf_ktime_get_boot_ns();
    p->ret = ret;
    p->dur_ns = now - p->ts_ns;
    p->ts_ns = now;
    if (info->retfd && ret >= 0) resolve_fd(p, task, (int)ret);
    if (ret >= 0 && (info->sock == MM_SOCK_OUT_1 || info->sock == MM_SOCK_OUT_4)) {
        const void* address = (const void*)(info->sock == MM_SOCK_OUT_1 ? p->args[1] : p->args[4]);
        const int* lengthPointer = (const int*)(info->sock == MM_SOCK_OUT_1 ? p->args[2] : p->args[5]);
        int length = 0;
        if (lengthPointer && bpf_probe_read_user(&length, sizeof(length), lengthPointer) == 0 && length > 0)
            read_sockaddr(p, address, (__u32)length);
    }
    long bytes = bpf_get_stack(ctx, p->stack, sizeof(p->stack), BPF_F_USER_STACK);
    p->frames = bytes > 0 ? (__u32)(bytes / sizeof(__u64)) : 0;
    struct mm_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_drop();
    } else {
        bpf_probe_read_kernel(e, sizeof(*e), p);
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&pending, &tid);
    return 0;
}

/* Tracking is copied inside copy_process, before the child can run. */
SEC("tp_btf/task_newtask")
int BPF_PROG(mm_newtask, struct task_struct* task, __u64 clone_flags)
{
    __u32 parent = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&tracked, &parent)) return 0;
    __u32 pid = BPF_CORE_READ(task, pid);
    __u32 tgid = BPF_CORE_READ(task, tgid);
    if (pid != tgid) return 0;   /* a thread shares its process's entry */
    struct mm_tracked entry = {};
    entry.start_ns = BPF_CORE_READ(task, start_boottime);
    entry.flags = 2;             /* MsMonFlagInheritedTrack */
    bpf_map_update_elem(&tracked, &tgid, &entry, BPF_ANY);
    return 0;
}

static __always_inline void emit_task(__u32 kind, struct task_struct* task, __u32 target)
{
    struct mm_event* s = fresh_scratch();
    if (!s) return;
    s->kind = kind;
    s->tgid = BPF_CORE_READ(task, tgid);
    s->tid = BPF_CORE_READ(task, pid);
    s->ppid = BPF_CORE_READ(task, real_parent, tgid);
    s->start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    s->ts_ns = bpf_ktime_get_boot_ns();
    s->target_tgid = target;
    struct mm_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_drop();
        return;
    }
    bpf_probe_read_kernel(e, sizeof(*e), s);
    bpf_ringbuf_submit(e, 0);
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(mm_fork, struct task_struct* parent, struct task_struct* child)
{
    __u32 tgid = BPF_CORE_READ(parent, tgid);
    if (!bpf_map_lookup_elem(&tracked, &tgid)) return 0;
    __u32 childPid = BPF_CORE_READ(child, pid);
    __u32 childTgid = BPF_CORE_READ(child, tgid);
    if (childPid == childTgid) {
        struct mm_event* s = fresh_scratch();
        if (!s) return 0;
        s->kind = MM_FORK;
        s->tgid = childTgid;
        s->tid = childPid;
        s->ppid = tgid;
        s->start_ns = BPF_CORE_READ(child, start_boottime);
        s->ts_ns = bpf_ktime_get_boot_ns();
        s->target_tgid = childTgid;
        struct mm_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            count_drop();
            return 0;
        }
        bpf_probe_read_kernel(e, sizeof(*e), s);
        bpf_ringbuf_submit(e, 0);
    } else {
        emit_task(MM_THREAD_START, child, 0);
    }
    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(mm_exec, struct task_struct* task, pid_t old_pid, struct linux_binprm* bprm)
{
    __u32 tgid = BPF_CORE_READ(task, tgid);
    if (!bpf_map_lookup_elem(&tracked, &tgid)) return 0;
    struct mm_event* s = fresh_scratch();
    if (!s) return 0;
    s->kind = MM_EXEC;
    fill_identity(s, task);
    bpf_probe_read_kernel_str(s->path_a, MM_PATH, BPF_CORE_READ(bprm, filename));
    struct file* file = BPF_CORE_READ(bprm, file);
    if (file && walk_path(__builtin_preserve_access_index(&file->f_path), s->kpath) >= 0) s->flags |= MM_F_KPATH;
    /* The argv the execve entry captured, keyed by the thread that called it. */
    __u32 tid = (__u32)old_pid;
    struct mm_event* p = bpf_map_lookup_elem(&pending, &tid);
    if (p && (p->flags & MM_F_ARGV)) {
        bpf_probe_read_kernel(s->path_b, sizeof(s->path_b), p->path_b);
        s->flags |= MM_F_ARGV;
    }
    struct mm_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_drop();
        return 0;
    }
    bpf_probe_read_kernel(e, sizeof(*e), s);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(mm_exit, struct task_struct* task, bool group_dead)
{
    __u32 tgid = BPF_CORE_READ(task, tgid);
    if (!bpf_map_lookup_elem(&tracked, &tgid)) return 0;
    emit_task(group_dead ? MM_EXIT : MM_THREAD_EXIT, task, 0);
    if (group_dead) bpf_map_delete_elem(&tracked, &tgid);
    return 0;
}

/* Scope: an untracked process that maps an executable file under the root is the client. */
SEC("lsm/mmap_file")
int BPF_PROG(mm_mmap_file, struct file* file, unsigned long reqprot, unsigned long prot, unsigned long flags, int ret)
{
    struct mm_config* c = cfg();
    if (ret != 0 || !file || (prot & PROT_EXEC) == 0 || !c) return 0;
    __u32 rootLength = c->root_len;
    if (rootLength == 0 || rootLength >= MM_PATH) return 0;
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (tgid == c->agent_tgid || bpf_map_lookup_elem(&tracked, &tgid)) return 0;
    struct mm_event* s = fresh_scratch();
    if (!s) return 0;
    if (walk_path(__builtin_preserve_access_index(&file->f_path), s->kpath) < 0) return 0;
    for (__u32 index = 0; index < MM_PATH; index++) {
        if (index >= rootLength) break;
        if (s->kpath[index] != c->root[index]) return 0;
    }
    if (s->kpath[rootLength & (MM_PATH - 1)] != '/') return 0;
    struct task_struct* task = bpf_get_current_task_btf();
    struct mm_tracked entry = {};
    entry.start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    entry.flags = 1;             /* MsMonFlagExplicitTrack */
    bpf_map_update_elem(&tracked, &tgid, &entry, BPF_NOEXIST);
    s->kind = MM_SCOPE;
    s->flags = MM_F_KPATH;
    fill_identity(s, task);
    struct mm_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_drop();
        return 0;
    }
    bpf_probe_read_kernel(e, sizeof(*e), s);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int deny(__u32 what, __u32 target)
{
    struct task_struct* task = bpf_get_current_task_btf();
    struct mm_event* s = fresh_scratch();
    if (s) {
        s->kind = MM_DENIED;
        s->nr = what;
        s->target_tgid = target;
        fill_identity(s, task);
        struct mm_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            bpf_probe_read_kernel(e, sizeof(*e), s);
            bpf_ringbuf_submit(e, 0);
        } else {
            count_drop();
        }
    }
    return -EPERM;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(mm_ptrace, struct task_struct* child, unsigned int mode, int ret)
{
    struct mm_config* c = cfg();
    if (ret != 0) return ret;
    if (!c || c->agent_tgid == 0 || BPF_CORE_READ(child, tgid) != c->agent_tgid || !current_tracked()) return 0;
    return deny(MM_DENY_PTRACE, c->agent_tgid);
}

SEC("lsm/bpf")
int BPF_PROG(mm_bpf, int cmd, union bpf_attr* attr, unsigned int size, bool kernel, int ret)
{
    if (ret != 0) return ret;
    if (kernel || !current_tracked()) return 0;
    return deny(MM_DENY_BPF, 0);
}

SEC("lsm/perf_event_open")
int BPF_PROG(mm_perf, int type, int ret)
{
    if (ret != 0) return ret;
    if (!current_tracked()) return 0;
    return deny(MM_DENY_PERF, 0);
}
