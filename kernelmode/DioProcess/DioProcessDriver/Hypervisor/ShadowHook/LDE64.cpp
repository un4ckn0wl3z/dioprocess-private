//
// Simple x64 Length Disassembler Engine (LDE)
// Calculates instruction length without needing Capstone library
//

#include "LDE64.h"

// Prefix flags
#define PREFIX_LOCK     0x0001
#define PREFIX_REPNZ    0x0002
#define PREFIX_REPZ     0x0004
#define PREFIX_SEG_CS   0x0008
#define PREFIX_SEG_SS   0x0010
#define PREFIX_SEG_DS   0x0020
#define PREFIX_SEG_ES   0x0040
#define PREFIX_SEG_FS   0x0080
#define PREFIX_SEG_GS   0x0100
#define PREFIX_OP_SIZE  0x0200
#define PREFIX_ADDR_SIZE 0x0400
#define PREFIX_REX      0x0800

// ModR/M byte helpers
#define MODRM_MOD(x) (((x) >> 6) & 0x3)
#define MODRM_REG(x) (((x) >> 3) & 0x7)
#define MODRM_RM(x)  ((x) & 0x7)

// SIB byte helpers
#define SIB_SCALE(x) (((x) >> 6) & 0x3)
#define SIB_INDEX(x) (((x) >> 3) & 0x7)
#define SIB_BASE(x)  ((x) & 0x7)

// Opcode table flags
#define OP_NONE      0x00
#define OP_MODRM     0x01  // Has ModR/M byte
#define OP_IMM8      0x02  // 8-bit immediate
#define OP_IMM16     0x04  // 16-bit immediate
#define OP_IMM32     0x08  // 32-bit immediate (or 64 with REX.W in some cases)
#define OP_IMM64     0x10  // 64-bit immediate (mov reg, imm64)
#define OP_REL8      0x20  // 8-bit relative
#define OP_REL32     0x40  // 32-bit relative
#define OP_PREFIX    0x80  // This is a prefix, not an opcode

// One-byte opcode table (simplified for common instructions)
static const UCHAR g_OpcodeTable1[256] = {
    // 0x00-0x0F: ADD, OR with ModR/M
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_NONE, OP_NONE,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_NONE, OP_NONE,
    // 0x10-0x1F: ADC, SBB with ModR/M
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_NONE, OP_NONE,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_NONE, OP_NONE,
    // 0x20-0x2F: AND, SUB with ModR/M
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_PREFIX, OP_NONE,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_PREFIX, OP_NONE,
    // 0x30-0x3F: XOR, CMP with ModR/M
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_PREFIX, OP_NONE,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM32, OP_PREFIX, OP_NONE,
    // 0x40-0x4F: REX prefixes in x64 (INC/DEC in x86)
    OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX,
    OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX,
    // 0x50-0x5F: PUSH/POP reg
    OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    // 0x60-0x6F: PUSHA/POPA (invalid x64), BOUND, ARPL, prefixes, PUSH/POP imm
    OP_NONE, OP_NONE, OP_MODRM, OP_MODRM, OP_PREFIX, OP_PREFIX, OP_PREFIX, OP_PREFIX,
    OP_IMM32, OP_MODRM|OP_IMM32, OP_IMM8, OP_MODRM|OP_IMM8, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    // 0x70-0x7F: Jcc short
    OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8,
    OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8,
    // 0x80-0x8F: Grp1, TEST, XCHG, MOV, LEA, MOV seg, POP
    OP_MODRM|OP_IMM8, OP_MODRM|OP_IMM32, OP_MODRM|OP_IMM8, OP_MODRM|OP_IMM8,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x90-0x9F: NOP/XCHG, CBW, CWD, CALLF, WAIT, PUSHF, POPF, SAHF, LAHF
    OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    OP_NONE, OP_NONE, OP_IMM32|OP_IMM16, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    // 0xA0-0xAF: MOV moffs, MOVS, CMPS, TEST, STOS, LODS, SCAS
    OP_IMM64, OP_IMM64, OP_IMM64, OP_IMM64, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    OP_IMM8, OP_IMM32, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    // 0xB0-0xBF: MOV reg, imm8/imm32/imm64
    OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8,
    OP_IMM64, OP_IMM64, OP_IMM64, OP_IMM64, OP_IMM64, OP_IMM64, OP_IMM64, OP_IMM64,
    // 0xC0-0xCF: Grp2 imm8, RET, LES/LDS, MOV imm, ENTER, LEAVE, RETF, INT, IRET
    OP_MODRM|OP_IMM8, OP_MODRM|OP_IMM8, OP_IMM16, OP_NONE,
    OP_MODRM, OP_MODRM, OP_MODRM|OP_IMM8, OP_MODRM|OP_IMM32,
    OP_IMM16|OP_IMM8, OP_NONE, OP_IMM16, OP_NONE, OP_NONE, OP_IMM8, OP_NONE, OP_NONE,
    // 0xD0-0xDF: Grp2, AAM, AAD, XLAT, FPU
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMM8, OP_NONE, OP_NONE,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0xE0-0xEF: LOOP, JCXZ, IN, OUT, CALL, JMP
    OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_IMM8, OP_IMM32, OP_IMM8, OP_IMM32,
    OP_REL32, OP_REL32, OP_IMM32|OP_IMM16, OP_REL8, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    // 0xF0-0xFF: LOCK, INT1, REPNZ, REPZ, HLT, CMC, Grp3, Grp4, Grp5
    OP_PREFIX, OP_NONE, OP_PREFIX, OP_PREFIX, OP_NONE, OP_NONE, OP_MODRM, OP_MODRM,
    OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_MODRM, OP_MODRM,
};

// Two-byte opcode table (0F xx)
static const UCHAR g_OpcodeTable2[256] = {
    // 0x00-0x0F: Grp6, Grp7, LAR, LSL, SYSCALL, CLTS, SYSRET, etc
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_MODRM, OP_NONE, OP_NONE,
    // 0x10-0x1F: SSE MOV, UNPCKLPS, etc
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x20-0x2F: MOV CR/DR, SSE
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x30-0x3F: WRMSR, RDTSC, RDMSR, RDPMC, etc
    OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    OP_MODRM, OP_NONE, OP_MODRM, OP_NONE, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x40-0x4F: CMOVcc
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x50-0x5F: SSE
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x60-0x6F: SSE/MMX
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x70-0x7F: SSE/MMX with imm8
    OP_MODRM|OP_IMM8, OP_MODRM|OP_IMM8, OP_MODRM|OP_IMM8, OP_MODRM|OP_IMM8,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_NONE,
    OP_MODRM, OP_MODRM, OP_NONE, OP_NONE, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0x80-0x8F: Jcc near
    OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32,
    OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32, OP_REL32,
    // 0x90-0x9F: SETcc
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0xA0-0xAF: PUSH/POP FS/GS, various
    OP_NONE, OP_NONE, OP_NONE, OP_MODRM, OP_MODRM|OP_IMM8, OP_MODRM, OP_NONE, OP_NONE,
    OP_NONE, OP_NONE, OP_NONE, OP_MODRM, OP_MODRM|OP_IMM8, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0xB0-0xBF: CMPXCHG, LSS, BTR, LFS, LGS, MOVZX, etc
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_NONE, OP_MODRM|OP_IMM8, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0xC0-0xCF: XADD, CMPSS, etc
    OP_MODRM, OP_MODRM, OP_MODRM|OP_IMM8, OP_MODRM, OP_MODRM|OP_IMM8, OP_MODRM|OP_IMM8, OP_MODRM|OP_IMM8, OP_MODRM,
    OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE, OP_NONE,
    // 0xD0-0xDF: SSE/MMX
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0xE0-0xEF: SSE/MMX
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    // 0xF0-0xFF: SSE/MMX
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
    OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_NONE,
};

// Calculate ModR/M displacement size
static SIZE_T GetModRMDispSize(UCHAR modrm, BOOLEAN hasAddressPrefix, BOOLEAN hasSIB)
{
    UCHAR mod = MODRM_MOD(modrm);
    UCHAR rm = MODRM_RM(modrm);

    // In 64-bit mode without address prefix
    if (!hasAddressPrefix) {
        switch (mod) {
        case 0:
            // [reg] or [disp32] (RIP-relative) or [SIB]
            if (rm == 5) return 4;  // RIP-relative [disp32]
            if (rm == 4 && hasSIB) {
                // Check SIB base
                return 0;  // Handled by SIB logic
            }
            return 0;
        case 1:
            return 1;  // [reg + disp8]
        case 2:
            return 4;  // [reg + disp32]
        case 3:
            return 0;  // reg (no memory reference)
        }
    }

    return 0;
}

// Calculate SIB displacement size
static SIZE_T GetSIBDispSize(UCHAR modrm, UCHAR sib)
{
    UCHAR mod = MODRM_MOD(modrm);
    UCHAR base = SIB_BASE(sib);

    if (mod == 0 && base == 5) {
        return 4;  // [disp32 + index*scale]
    }

    return 0;  // Displacement determined by ModR/M
}

SIZE_T LDE64_GetInstructionLength(const void* address)
{
    if (address == NULL)
        return 0;

    const UCHAR* p = (const UCHAR*)address;
    SIZE_T length = 0;
    USHORT prefixes = 0;
    BOOLEAN hasREXW = FALSE;
    BOOLEAN hasOperandPrefix = FALSE;
    BOOLEAN hasAddressPrefix = FALSE;

    // Parse prefixes (up to 15 bytes max for any instruction)
    while (length < 15) {
        UCHAR b = p[length];

        // Legacy prefixes
        if (b == 0xF0) { prefixes |= PREFIX_LOCK; length++; continue; }
        if (b == 0xF2) { prefixes |= PREFIX_REPNZ; length++; continue; }
        if (b == 0xF3) { prefixes |= PREFIX_REPZ; length++; continue; }
        if (b == 0x2E) { prefixes |= PREFIX_SEG_CS; length++; continue; }
        if (b == 0x36) { prefixes |= PREFIX_SEG_SS; length++; continue; }
        if (b == 0x3E) { prefixes |= PREFIX_SEG_DS; length++; continue; }
        if (b == 0x26) { prefixes |= PREFIX_SEG_ES; length++; continue; }
        if (b == 0x64) { prefixes |= PREFIX_SEG_FS; length++; continue; }
        if (b == 0x65) { prefixes |= PREFIX_SEG_GS; length++; continue; }
        if (b == 0x66) { prefixes |= PREFIX_OP_SIZE; hasOperandPrefix = TRUE; length++; continue; }
        if (b == 0x67) { prefixes |= PREFIX_ADDR_SIZE; hasAddressPrefix = TRUE; length++; continue; }

        // REX prefix (0x40-0x4F in 64-bit mode)
        if (b >= 0x40 && b <= 0x4F) {
            prefixes |= PREFIX_REX;
            if (b & 0x08) hasREXW = TRUE;  // REX.W
            length++;
            continue;
        }

        break;  // Not a prefix
    }

    if (length >= 15)
        return 0;  // Invalid: too many prefixes

    // Get opcode
    UCHAR opcode = p[length++];
    UCHAR flags;

    // Two-byte opcode?
    if (opcode == 0x0F) {
        if (length >= 15)
            return 0;
        opcode = p[length++];

        // Three-byte opcode (0F 38 xx or 0F 3A xx)?
        if (opcode == 0x38 || opcode == 0x3A) {
            if (length >= 15)
                return 0;
            UCHAR thirdByte = opcode;
            opcode = p[length++];

            // Most 0F 38/3A opcodes have ModR/M
            flags = OP_MODRM;
            if (thirdByte == 0x3A) {
                flags |= OP_IMM8;  // 0F 3A opcodes have imm8
            }
        } else {
            flags = g_OpcodeTable2[opcode];
        }
    } else {
        flags = g_OpcodeTable1[opcode];

        // Special handling for MOV with moffs (A0-A3)
        // In 64-bit mode, moffs is 8 bytes by default
        if (opcode >= 0xA0 && opcode <= 0xA3) {
            if (hasAddressPrefix) {
                length += 4;  // 32-bit address with 67 prefix
            } else {
                length += 8;  // 64-bit address
            }
            return length;
        }

        // Special handling for MOV reg, imm64 (B8-BF with REX.W)
        if (opcode >= 0xB8 && opcode <= 0xBF) {
            if (hasREXW) {
                length += 8;  // 64-bit immediate with REX.W
            } else {
                length += 4;  // 32-bit immediate
            }
            return length;
        }
    }

    // Handle ModR/M byte if present
    if (flags & OP_MODRM) {
        if (length >= 15)
            return 0;
        UCHAR modrm = p[length++];
        UCHAR mod = MODRM_MOD(modrm);
        UCHAR rm = MODRM_RM(modrm);

        // Check for SIB byte (rm == 4 and mod != 3)
        BOOLEAN hasSIB = (rm == 4 && mod != 3);
        UCHAR sib = 0;

        if (hasSIB) {
            if (length >= 15)
                return 0;
            sib = p[length++];

            // SIB with base == 5 and mod == 0 means [disp32 + index*scale]
            if (mod == 0 && SIB_BASE(sib) == 5) {
                length += 4;
            }
        }

        // Calculate displacement based on ModR/M
        switch (mod) {
        case 0:
            // Special case: rm == 5 means RIP-relative [disp32]
            if (rm == 5) {
                length += 4;
            }
            break;
        case 1:
            length += 1;  // disp8
            break;
        case 2:
            length += 4;  // disp32
            break;
        case 3:
            // No displacement (register)
            break;
        }

        // Special handling for Group 3 (F6/F7) - TEST has immediate
        if ((opcode == 0xF6 || opcode == 0xF7) && (MODRM_REG(modrm) == 0 || MODRM_REG(modrm) == 1)) {
            if (opcode == 0xF6) {
                length += 1;  // imm8
            } else {
                length += hasOperandPrefix ? 2 : 4;  // imm16/imm32
            }
        }
    }

    // Add immediate bytes
    if (flags & OP_IMM8) {
        length += 1;
    }
    if (flags & OP_IMM16) {
        length += 2;
    }
    if (flags & OP_IMM32) {
        // With 66 prefix, it's imm16
        if (hasOperandPrefix) {
            length += 2;
        } else {
            length += 4;
        }
    }
    if (flags & OP_REL8) {
        length += 1;
    }
    if (flags & OP_REL32) {
        length += 4;
    }

    if (length > 15)
        return 0;  // Invalid instruction

    return length;
}
