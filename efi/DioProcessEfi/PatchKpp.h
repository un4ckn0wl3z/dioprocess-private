/** @file
  PatchGuard / KPP (Kernel Patch Protection) bypass.

  Patches PatchGuard initialization routines in ntoskrnl.exe to prevent
  PatchGuard from being armed at boot time.
**/

#ifndef DIOPROCESS_PATCH_KPP_H_
#define DIOPROCESS_PATCH_KPP_H_

#include <Uefi.h>

/**
  Patch PatchGuard initialization in ntoskrnl.exe.

  Scans the loaded ntoskrnl.exe image for PatchGuard initialization
  functions and patches them to return immediately, preventing PatchGuard
  from being armed.

  Target functions:
  1. KiFilterFiberContext — Main PG initialization entry point
  2. ExpLicenseWatchInitWorker — Secondary PG trigger via license check

  Must be called after ntoskrnl.exe is loaded but before ExitBootServices
  transfers control to the kernel.

  @param[in] NtoskrnlBase  Base address of ntoskrnl.exe in memory.
  @param[in] NtoskrnlSize  Size of the ntoskrnl.exe image.

  @retval TRUE   At least one PG init function was patched.
  @retval FALSE  No patterns found or all patches failed.
**/
BOOLEAN
PatchKpp(
    IN VOID  *NtoskrnlBase,
    IN UINTN NtoskrnlSize
    );

#endif // DIOPROCESS_PATCH_KPP_H_
