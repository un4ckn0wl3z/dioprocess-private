/** @file
  DSE (Driver Signature Enforcement) bypass.

  Patches ntoskrnl.exe to disable driver signature verification at boot time.

  Strategy (EfiGuard-derived):
  1. Find ntoskrnl's IAT entry for CI.dll!CiInitialize
  2. In the PAGE section, find the CALL to CiInitialize
  3. Find the MOV ECX that sets the CI options parameter before the CALL
  4. Patch MOV ECX to XOR ECX, ECX (pass 0 = no enforcement)
  5. Patch SeValidateImageData to return STATUS_SUCCESS instead of STATUS_INVALID_IMAGE_HASH
**/

#ifndef DIOPROCESS_PATCH_DSE_H_
#define DIOPROCESS_PATCH_DSE_H_

#include <Uefi.h>

/**
  Patch DSE initialization in ntoskrnl.exe.

  Must be called after ntoskrnl.exe is loaded but before ExitBootServices
  transfers control to the kernel.

  @param[in] NtoskrnlBase  Base address of ntoskrnl.exe in memory.
  @param[in] NtoskrnlSize  Size of the ntoskrnl.exe image.

  @retval TRUE   Patch applied successfully.
  @retval FALSE  Pattern not found or patch failed.
**/
BOOLEAN
PatchDse(
    IN VOID  *NtoskrnlBase,
    IN UINTN NtoskrnlSize
    );

#endif // DIOPROCESS_PATCH_DSE_H_
