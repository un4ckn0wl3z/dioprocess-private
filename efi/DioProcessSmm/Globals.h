/** @file
  DioProcess SMM — Global variables.
**/

#ifndef _DIOPROCESS_SMM_GLOBALS_H_
#define _DIOPROCESS_SMM_GLOBALS_H_

#include <Uefi.h>
#include <Library/SmmServicesTableLib.h>

extern EFI_SMM_SYSTEM_TABLE2  *gSmst2;
extern EFI_PHYSICAL_ADDRESS    gRemapPage;

#endif
