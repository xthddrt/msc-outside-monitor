/*
 * disasm.h - minimal x64 instruction length decoder.
 *
 * Only needs to be exact for the instruction subset found in ntoskrnl function
 * prologues: prefixes, mov/movzx/movsx/lea/test/cmp/xor/sub/add/and/or,
 * push/pop, call/jmp/jcc, nop (incl. multi-byte 0F 1F), int3.
 * VEX/EVEX are handled well enough not to misparse.
 */
#pragma once
#include <ntddk.h>

typedef struct _LD_INSN {
    ULONG   Length;      /* total instruction length in bytes            */
    BOOLEAN HasRel;      /* instruction ends in a rel8/rel32 field       */
    ULONG   RelOffset;   /* offset of that field inside the instruction  */
    ULONG   RelSize;     /* 1 or 4                                       */
    BOOLEAN HasRipRel;   /* has a mod=00 rm=101 disp32 operand           */
    ULONG   DispOffset;  /* offset of that disp32 inside the instruction */
} LD_INSN, *PLD_INSN;

/* Returns FALSE when the encoding is unknown or runs past maxLen. */
BOOLEAN LdDecode(_In_reads_bytes_(maxLen) const UCHAR *code, _In_ ULONG maxLen, _Out_ PLD_INSN out);
