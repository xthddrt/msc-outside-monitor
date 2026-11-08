/* The PE (Windows-side) context of the Wine syscall the current thread is in (docs/LINUX.md "PE frames").
 *
 * Wine 11.0 x64: GS base is the thread's TEB for the thread's whole life (arch_prctl(ARCH_SET_GS) once),
 * so task->thread.gsbase is the TEB. A thread inside a Wine syscall runs on Wine's per-thread kernel stack
 * (TEB+0x3a8) below its syscall_frame (TEB+0x378); the frame holds the PE side's rip (inside the NtXxx stub
 * of ntdll.dll), rsp (the qword there returns into the caller of NtXxx) and rbp. The agent unwinds the
 * copied PE stack with the images' .pdata (bpf_pe.inc, pe.cpp). Offsets: WINE_FACTS / signal_x86_64.c. */
#define MM_TEB_SELF 0x30          /* NT_TIB.Self (NT_TIB.StackBase at 0x08) */
#define MM_TEB_SYSCALL_FRAME 0x378
#define MM_FRAME_RIP 0x70         /* syscall_frame: rip 0x70, cs, eflags, rsp 0x88, ss, rbp 0x98 */

/* Fills pe->rip/rsp/rbp and up to MM_PE_BYTES of the PE stack at rsp (bounded by the TEB's StackBase), or
 * leaves pe->rip 0 when the thread has no TEB or is not inside a Wine syscall. The caller zeroed rip and bytes.
 * Verifier-safe: no loop; four bpf_probe_read_user calls, three of constant size into stack buffers and one
 * into pe->stack whose size is clamped to [0, MM_PE_BYTES] on the register passed (pe->stack is MM_PE_BYTES
 * long in both callers' buffers). gsbase and regs->sp are direct BTF reads (no helper). */
static __always_inline void read_pe(struct mm_pe* pe, struct task_struct* task, struct pt_regs* regs)
{
    __u64 teb = task->thread.gsbase;
    if (!teb) return;
    __u64 tib[7];   /* ExceptionList, StackBase, StackLimit, SubSystemTib, FiberData, ArbitraryUserPointer, Self */
    if (bpf_probe_read_user(tib, sizeof(tib), (const void*)teb) != 0 || tib[MM_TEB_SELF / 8] != teb) return;
    __u64 wine[7];  /* TEB+0x378 syscall_frame ... TEB+0x3a8 kernel_stack */
    if (bpf_probe_read_user(wine, sizeof(wine), (const void*)(teb + MM_TEB_SYSCALL_FRAME)) != 0) return;
    __u64 frame = wine[0];
    __u64 sp = regs->sp;
    /* Wine's is_inside_syscall(): a thread on the PE stack (or a unix thread) is not in a Wine syscall. */
    if (!frame || sp < wine[6] || sp > frame) return;
    /* shortcut: a WoW64 thread (TEB+0x320 pthread_teb != 0) reports its 64-bit side (wow64*.dll), not the
     * 32-bit caller; read the I386_CONTEXT at *(TEB+0x1488)+4 (Eip, Esp) when 32-bit PE games under new
     * WoW64 must be attributed. */
    __u64 saved[6];  /* rip, cs, eflags, rsp, ss, rbp */
    if (bpf_probe_read_user(saved, sizeof(saved), (const void*)(frame + MM_FRAME_RIP)) != 0 || !saved[0]) return;
    __u64 rsp = saved[3];
    pe->rip = saved[0];
    pe->rsp = rsp;
    pe->rbp = saved[5];
    __u64 n = tib[1] > rsp ? tib[1] - rsp : MM_PE_BYTES;   /* a fiber's stack lies outside the TEB's */
    if (n > MM_PE_BYTES) n = MM_PE_BYTES;
    n &= 2 * MM_PE_BYTES - 1;
    if (n > MM_PE_BYTES) n = MM_PE_BYTES;
    if (n && bpf_probe_read_user(pe->stack, n, (const void*)rsp) == 0) pe->bytes = n;
}
