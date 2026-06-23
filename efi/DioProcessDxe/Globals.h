/** @file
  DioProcess DXE — Global variables.
**/

#ifndef _DIOPROCESS_DXE_GLOBALS_H_
#define _DIOPROCESS_DXE_GLOBALS_H_

#include <Uefi.h>
#include <Protocol/MmCommunication2.h>

extern EFI_MM_COMMUNICATION2_PROTOCOL *gMmCommunicate2;
extern VOID                           *gCommBuf;
extern VOID                           *gPhysCommBuf;
extern UINTN                           gCommSize;
extern EFI_EVENT                       gExitBs;
extern EFI_EVENT                       gGoneVirtual;
extern EFI_EVENT                       gRegNotify;

#endif
