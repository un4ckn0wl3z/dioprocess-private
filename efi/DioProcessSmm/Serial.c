/** @file
  DioProcess SMM — Serial debug output implementation.
**/

#include <Uefi.h>
#include <Library/IoLib.h>

#include "Serial.h"

VOID
EFIAPI
SerialPrint(
    IN CONST CHAR8 *String
    )
{
    while (*String != '\0') {
        while ((IoRead8(SERIAL_PORT_ADDRESS + 5) & 0x20) == 0);
        IoWrite8(SERIAL_PORT_ADDRESS, (UINT8)*String);
        String++;
    }
}
