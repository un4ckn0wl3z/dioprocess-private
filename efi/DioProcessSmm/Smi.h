/** @file
  DioProcess SMM — SMI handler registration.
**/

#ifndef _DIOPROCESS_SMM_SMI_H_
#define _DIOPROCESS_SMM_SMI_H_

#include <Uefi.h>

EFI_STATUS
EFIAPI
SmiRegisterHandler(
    VOID
    );

#endif
