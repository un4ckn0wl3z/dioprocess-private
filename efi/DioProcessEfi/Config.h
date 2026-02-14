/** @file
  DioProcess UEFI bootkit configuration - NVRAM variable definitions.

  Defines the GUID and variable names used to communicate boot-time
  configuration between the DioProcess UI (usermode) and the UEFI DXE driver.
**/

#ifndef DIOPROCESS_CONFIG_H_
#define DIOPROCESS_CONFIG_H_

#include <Uefi.h>
#include <Library/UefiRuntimeServicesTableLib.h>

//
// DioProcess UEFI variable vendor GUID
// Must match the GUID used in crates/uefi/src/nvram.rs
//
#define DIOPROCESS_UEFI_GUID \
    { 0xD100C0C5, 0x1337, 0x4242, { 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01 } }

//
// NVRAM variable names
//
#define DIOPROCESS_VAR_DSE_BYPASS   L"DioProcessDseBypass"
#define DIOPROCESS_VAR_KPP_BYPASS   L"DioProcessKppBypass"

//
// Boot patch configuration read from NVRAM
//
typedef struct _DIOPROCESS_CONFIG {
    BOOLEAN DseBypass;    // Bypass Driver Signature Enforcement
    BOOLEAN KppBypass;    // Bypass PatchGuard / Kernel Patch Protection
} DIOPROCESS_CONFIG;

/**
  Read DioProcess configuration from UEFI NVRAM variables.

  @param[out] Config    Pointer to config structure to fill.

  @retval EFI_SUCCESS   Configuration read successfully.
  @retval other         One or more variables could not be read (defaults applied).
**/
EFI_STATUS
ReadDioProcessConfig(
    OUT DIOPROCESS_CONFIG *Config
    );

#endif // DIOPROCESS_CONFIG_H_
