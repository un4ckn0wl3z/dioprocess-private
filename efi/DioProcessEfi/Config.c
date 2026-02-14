/** @file
  DioProcess UEFI bootkit - NVRAM configuration reader.
**/

#include "Config.h"

STATIC EFI_GUID gDioProcessVarGuid = DIOPROCESS_UEFI_GUID;

/**
  Read a single NVRAM boolean variable (1 byte).

  @param[in]  Name      Variable name.
  @param[out] Value     Pointer to boolean result.

  @retval EFI_SUCCESS           Variable read successfully.
  @retval EFI_NOT_FOUND         Variable does not exist (Value set to FALSE).
  @retval EFI_BUFFER_TOO_SMALL  Unexpected size.
**/
STATIC
EFI_STATUS
ReadNvramBool(
    IN  CHAR16  *Name,
    OUT BOOLEAN *Value
    )
{
    UINT8      Buffer;
    UINTN      DataSize = sizeof(Buffer);
    EFI_STATUS Status;

    Status = gRT->GetVariable(
        Name,
        &gDioProcessVarGuid,
        NULL,
        &DataSize,
        &Buffer
    );

    if (EFI_ERROR(Status)) {
        // Variable not found — default to FALSE (bypass disabled)
        *Value = FALSE;
        if (Status == EFI_NOT_FOUND) {
            return EFI_SUCCESS;
        }
        return Status;
    }

    *Value = (Buffer != 0);
    return EFI_SUCCESS;
}

EFI_STATUS
ReadDioProcessConfig(
    OUT DIOPROCESS_CONFIG *Config
    )
{
    EFI_STATUS Status;

    if (Config == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    // Initialize defaults
    Config->DseBypass = FALSE;
    Config->KppBypass = FALSE;

    // Read DSE bypass setting
    Status = ReadNvramBool(DIOPROCESS_VAR_DSE_BYPASS, &Config->DseBypass);
    if (EFI_ERROR(Status) && Status != EFI_NOT_FOUND) {
        // Non-fatal — continue with default
    }

    // Read KPP bypass setting
    Status = ReadNvramBool(DIOPROCESS_VAR_KPP_BYPASS, &Config->KppBypass);
    if (EFI_ERROR(Status) && Status != EFI_NOT_FOUND) {
        // Non-fatal — continue with default
    }

    return EFI_SUCCESS;
}
