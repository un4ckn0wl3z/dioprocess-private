/** @file
  Byte pattern scanner with wildcard support.

  Scans memory regions for byte patterns using an 'x'/'?' mask format,
  commonly used for finding code signatures in PE images.
**/

#ifndef DIOPROCESS_PATTERN_SCAN_H_
#define DIOPROCESS_PATTERN_SCAN_H_

#include <Uefi.h>

/**
  Scan a memory region for a byte pattern with wildcards.

  @param[in] Base       Start address of memory region to scan.
  @param[in] Size       Size of memory region in bytes.
  @param[in] Pattern    Byte pattern to search for.
  @param[in] Mask       Mask string: 'x' = must match, '?' = wildcard.
  @param[in] PatternLen Length of pattern/mask in bytes.

  @retval Pointer to first match, or NULL if not found.
**/
VOID *
PatternScan(
    IN VOID       *Base,
    IN UINTN      Size,
    IN CONST UINT8 *Pattern,
    IN CONST CHAR8 *Mask,
    IN UINTN      PatternLen
    );

/**
  Scan a memory region for a byte pattern (multiple attempts).
  Returns all matches up to MaxMatches.

  @param[in]  Base       Start address of memory region.
  @param[in]  Size       Size of memory region in bytes.
  @param[in]  Pattern    Byte pattern to search for.
  @param[in]  Mask       Mask string.
  @param[in]  PatternLen Length of pattern/mask.
  @param[out] Matches    Array to receive match pointers.
  @param[in]  MaxMatches Maximum number of matches to return.

  @retval Number of matches found.
**/
UINTN
PatternScanAll(
    IN  VOID       *Base,
    IN  UINTN      Size,
    IN  CONST UINT8 *Pattern,
    IN  CONST CHAR8 *Mask,
    IN  UINTN      PatternLen,
    OUT VOID       **Matches,
    IN  UINTN      MaxMatches
    );

#endif // DIOPROCESS_PATTERN_SCAN_H_
