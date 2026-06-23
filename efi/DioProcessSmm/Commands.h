/** @file
  DioProcess SMM — Command handler.
**/

#ifndef _DIOPROCESS_SMM_COMMANDS_H_
#define _DIOPROCESS_SMM_COMMANDS_H_

#include <Uefi.h>
#include "Defs.h"

EFI_STATUS
EFIAPI
CmdMainHandler(
    IN PDIOPROCESS_COMMUNICATION SmiCommCtx
    );

#endif
