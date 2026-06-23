/** @file
  DioProcess SMM — Serial debug output.
**/

#ifndef _DIOPROCESS_SMM_SERIAL_H_
#define _DIOPROCESS_SMM_SERIAL_H_

#include <Uefi.h>

#define SERIAL_PORT_ADDRESS 0x3F8

VOID
EFIAPI
SerialPrint(
    IN CONST CHAR8 *String
    );

#endif
