/* disasm.c - see disasm.h */
#include "disasm.h"

#define IMM16OR32 (has66 ? 2u : 4u)

BOOLEAN
LdDecode(_In_reads_bytes_(maxLen) const UCHAR *code, _In_ ULONG maxLen, _Out_ PLD_INSN out)
{
    ULONG   i = 0;
    UCHAR   b, op, op2;
    BOOLEAN hasModrm = FALSE;
    BOOLEAN has66 = FALSE;
    BOOLEAN immIsRel8 = FALSE, immIsRel32 = FALSE;
    BOOLEAN ripRel = FALSE;
    BOOLEAN imm01 = FALSE;
    BOOLEAN hasRexW = FALSE;
    ULONG   immSize = 0;
    ULONG   dispOff = 0;

    if (out == NULL) return FALSE;
    RtlZeroMemory(out, sizeof(*out));
    if (code == NULL || maxLen < 1) return FALSE;

    /* ---- legacy prefixes ---- */
    for (;;) {
        if (i >= maxLen) return FALSE;
        b = code[i];
        if (b == 0xF0 || b == 0xF2 || b == 0xF3) { i++; continue; }
        if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) { i++; continue; }
        if (b == 0x66) { has66 = TRUE; i++; continue; }
        if (b == 0x67) { i++; continue; }
        break;
    }

    /* ---- REX ---- */
    if ((code[i] & 0xF0) == 0x40) {
        hasRexW = (code[i] & 0x08) != 0;
        i++;
        if (i >= maxLen) return FALSE;
    }

    op = code[i++];

    if (op == 0x0F) {
        if (i >= maxLen) return FALSE;
        op2 = code[i++];

        if (op2 == 0x38 || op2 == 0x3A) {
            UCHAR op3;
            if (i >= maxLen) return FALSE;
            op3 = code[i++];
            hasModrm = TRUE;
            if (op2 == 0x3A) immSize = 1;
            else if (op3 == 0xF0) immSize = 1;      /* crc32 r32, r/m8,  imm8  */
            else if (op3 == 0xF1) immSize = 4;      /* crc32 r32, r/m32, imm32 */
        } else {
            hasModrm = TRUE;
            switch (op2) {
            case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0B:
            case 0x0E: case 0x30: case 0x31: case 0x32: case 0x33:
            case 0x34: case 0x35: case 0x37: case 0x77: case 0xA0: case 0xA1:
            case 0xA2: case 0xA8: case 0xA9: case 0xAA:
                hasModrm = FALSE;
                break;
            case 0x0F:  /* 3DNow!: modrm + opcode byte */
                immSize = 1;
                break;
            case 0x01:  /* sgdt/sidt/...: modrm, +imm8 only when reg==7 */
                imm01 = TRUE;
                break;
            case 0x70: case 0x71: case 0x72: case 0x73: case 0xA4: case 0xAC:
            case 0xBA: case 0xC2: case 0xC4: case 0xC5: case 0xC6:
                immSize = 1;
                break;
            default:
                if (op2 >= 0xC8 && op2 <= 0xCF) hasModrm = FALSE;   /* bswap */
                else if (op2 >= 0x80 && op2 <= 0x8F) { immIsRel32 = TRUE; hasModrm = FALSE; }
                break;
            }
        }
        goto operands;
    }

    /* ---- one byte opcodes ---- */
    switch (op) {
    /* no operands at all */
    case 0x06: case 0x07: case 0x0E: case 0x16: case 0x17: case 0x1E: case 0x1F:
    case 0x27: case 0x2F: case 0x37: case 0x3F:
    case 0x60: case 0x61:
    case 0x90: case 0x98: case 0x99: case 0x9C: case 0x9D: case 0x9E: case 0x9F:
    case 0xA4: case 0xA5: case 0xA6: case 0xA7:
    case 0xAA: case 0xAB: case 0xAC: case 0xAD: case 0xAE: case 0xAF:
    case 0xC3: case 0xC9: case 0xCC: case 0xCE:
    case 0xEC: case 0xED: case 0xEE: case 0xEF:
    case 0xF4: case 0xF5: case 0xF8: case 0xF9: case 0xFA: case 0xFB: case 0xFC: case 0xFD:
        break;

    /* opcode + imm8 (AL/eAX form only for the 0x04 family) */
    case 0x04: case 0x0C: case 0x14: case 0x1C: case 0x24: case 0x2C: case 0x34: case 0x3C:
    case 0x6A: case 0xA8: case 0xCD:
    case 0xE4: case 0xE5: case 0xE6: case 0xE7:
        immSize = 1;
        break;

    /* opcode + imm16/32 */
    case 0x05: case 0x0D: case 0x15: case 0x1D: case 0x25: case 0x2D: case 0x35: case 0x3D:
    case 0x68: case 0xA9:
        immSize = IMM16OR32;
        break;

    case 0xC2: case 0xCA:
        immSize = 2;
        break;
    case 0xC8:
        immSize = 3;            /* enter: imm16 + imm8 */
        break;

    /* push/pop r64, xchg eax, r64 */
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
    case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
    case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
    case 0x9B:
        break;

    /* mov r8, imm8 */
    case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        immSize = 1;
        break;

    /* mov r32/64, imm32/64 */
    case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        immSize = hasRexW ? 8 : IMM16OR32;   /* mov r64, imm64 */
        break;

    /* moffs */
    case 0xA0: case 0xA1: case 0xA2: case 0xA3:
        immSize = 8;
        break;

    case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xEB:
        immIsRel8 = TRUE;
        break;
    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        immIsRel8 = TRUE;
        break;
    case 0xE8: case 0xE9:
        immIsRel32 = TRUE;
        break;

    /* opcode + modrm + imm */
    case 0x69: hasModrm = TRUE; immSize = IMM16OR32; break;
    case 0x6B: hasModrm = TRUE; immSize = 1; break;
    case 0x80: case 0x82: case 0x83: case 0xC0: case 0xC1: case 0xC6:
        hasModrm = TRUE; immSize = 1; break;    /* 83: group1 r/m, imm8 */
    case 0x81: case 0xC7:
        hasModrm = TRUE; immSize = IMM16OR32; break;
    case 0xF6:
        hasModrm = TRUE; immSize = 1; break;
    case 0xF7:
        hasModrm = TRUE; immSize = IMM16OR32; break;

    /* 3-byte VEX / EVEX: prefix bytes, then modrm */
    case 0xC4: immSize = 2; hasModrm = TRUE; break;   /* VEX3 */
    case 0xC5: immSize = 1; hasModrm = TRUE; break;   /* VEX2 */
    case 0x62: immSize = 3; hasModrm = TRUE; break;   /* EVEX  */
    case 0x63: immSize = 0; hasModrm = TRUE; break;

    case 0xD4: case 0xD5:
        immSize = 1; break;

    default:
        hasModrm = TRUE;
        break;
    }

operands:
    if (hasModrm) {
        UCHAR modrm, mod, rm;
        ULONG disp = 0;
        BOOLEAN viaSib = FALSE;
        UCHAR sib = 0;

        /* VEX/EVEX: prefix bytes, then the real opcode, then modrm. */
        if (op == 0xC4 || op == 0xC5 || op == 0x62) {
            if (i + immSize + 1 > maxLen) return FALSE;
            i += immSize + 1;
            immSize = 0;
        }

        if (i >= maxLen) return FALSE;
        modrm = code[i++];
        mod = (UCHAR)(modrm >> 6);
        rm  = (UCHAR)(modrm & 7);

        /* A SIB byte only follows when the operand is memory.  With mod == 3
         * rm == 4 is plain RSP (e.g. `sub rsp,280h` = 48 81 EC ...), and
         * consuming the next byte as a SIB silently steals one byte too many -
         * which makes the trampoline resume in the middle of the following
         * instruction. */
        if (mod != 3 && rm == 4) {
            if (i >= maxLen) return FALSE;
            sib = code[i++];
            viaSib = TRUE;
        }
        if (mod == 0) {
            if (rm == 5) {
                /* mod=00, rm=101: RIP + disp32 - but only without a SIB. */
                disp = 4;
                if (!viaSib) ripRel = TRUE;
            } else if (viaSib && (sib & 7) == 5) {
                /*
                 * mod=00, SIB with base=101 is absolute disp32 (no base, no
                 * index), NOT RIP-relative - e.g. `mov rax, gs:[0]` is
                 * 65 48 8B 04 25 00000000.  Relocating that disp corrupts it
                 * into a wild GS-relative read.
                 */
                disp = 4;
            }
        } else if (mod == 1) {
            disp = 1;
        } else if (mod == 2) {
            disp = 4;
        }
        if (disp == 4 && mod == 0 && rm == 5 && !viaSib) {
            ripRel = TRUE;
        }
        if (disp) {
            if (i + disp > maxLen) return FALSE;
            dispOff = i;
            i += disp;
        }
        if (imm01 && ((modrm >> 3) & 7) == 7) immSize += 1;

        /* F6/F7 are a group: only /0 and /1 (test) carry an immediate. */
        if (op == 0xF6 || op == 0xF7) {
            UCHAR reg = (UCHAR)((modrm >> 3) & 7);
            immSize = (reg <= 1) ? (op == 0xF6 ? 1 : IMM16OR32) : 0;
        }
    }

    if (immSize) {
        if (i + immSize > maxLen) return FALSE;
        i += immSize;
    }

    if (immIsRel8) {
        out->HasRel = TRUE; out->RelOffset = i; out->RelSize = 1;
        if (i + 1 > maxLen) return FALSE;
        i += 1;
    } else if (immIsRel32) {
        out->HasRel = TRUE; out->RelOffset = i; out->RelSize = 4;
        if (i + 4 > maxLen) return FALSE;
        i += 4;
    }

    out->Length = i;
    out->HasRipRel = ripRel;
    out->DispOffset = dispOff;
    return TRUE;
}
