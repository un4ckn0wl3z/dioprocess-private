/** @file
  Byte pattern scanner with wildcard support.
**/

#include "PatternScan.h"

VOID *
PatternScan(
    IN VOID       *Base,
    IN UINTN      Size,
    IN CONST UINT8 *Pattern,
    IN CONST CHAR8 *Mask,
    IN UINTN      PatternLen
    )
{
    UINT8 *BasePtr;
    UINTN  i;
    UINTN  j;
    BOOLEAN Found;

    if (Base == NULL || Pattern == NULL || Mask == NULL || PatternLen == 0) {
        return NULL;
    }

    if (Size < PatternLen) {
        return NULL;
    }

    BasePtr = (UINT8 *)Base;

    for (i = 0; i <= Size - PatternLen; i++) {
        Found = TRUE;
        for (j = 0; j < PatternLen; j++) {
            if (Mask[j] == 'x' && BasePtr[i + j] != Pattern[j]) {
                Found = FALSE;
                break;
            }
            // Mask[j] == '?' means wildcard — always matches
        }
        if (Found) {
            return (VOID *)(BasePtr + i);
        }
    }

    return NULL;
}

UINTN
PatternScanAll(
    IN  VOID       *Base,
    IN  UINTN      Size,
    IN  CONST UINT8 *Pattern,
    IN  CONST CHAR8 *Mask,
    IN  UINTN      PatternLen,
    OUT VOID       **Matches,
    IN  UINTN      MaxMatches
    )
{
    UINT8 *BasePtr;
    UINT8 *Current;
    UINTN  Remaining;
    UINTN  MatchCount;
    VOID  *Found;

    if (Base == NULL || Matches == NULL || MaxMatches == 0) {
        return 0;
    }

    BasePtr = (UINT8 *)Base;
    Current = BasePtr;
    Remaining = Size;
    MatchCount = 0;

    while (MatchCount < MaxMatches && Remaining >= PatternLen) {
        Found = PatternScan(Current, Remaining, Pattern, Mask, PatternLen);
        if (Found == NULL) {
            break;
        }

        Matches[MatchCount++] = Found;

        // Advance past this match
        Current = (UINT8 *)Found + 1;
        Remaining = Size - (UINTN)(Current - BasePtr);
    }

    return MatchCount;
}
