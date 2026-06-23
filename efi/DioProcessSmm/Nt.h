/** @file
  DioProcess SMM — NT kernel structure operations.
**/

#ifndef _DIOPROCESS_SMM_NT_H_
#define _DIOPROCESS_SMM_NT_H_

#include <Uefi.h>

#define EPROCESS_DIR_BASE_OFFSET     0x28
#define EPROCESS_PID_OFFSET          0x440
#define EPROCESS_FLINK_OFFSET        0x448
#define EPROCESS_TOKEN_OFFSET        0x4B8

UINT64
EFIAPI
NtGetDirBaseByPid(
    IN  UINT64  Pid,
    IN  VOID   *SysEprocess,
    IN  UINT64  SysDirBase,
    OUT VOID  **TargetEprocess
    );

EFI_STATUS
EFIAPI
NtExchangeProcessToken(
    IN VOID *SourceEprocess,
    IN VOID *TargetEprocess
    );

#endif
