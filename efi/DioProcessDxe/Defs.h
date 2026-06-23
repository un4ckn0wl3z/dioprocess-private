/** @file
  DioProcess DXE — Data structure definitions.
**/

#ifndef _DIOPROCESS_DXE_DEFS_H_
#define _DIOPROCESS_DXE_DEFS_H_

#include <Uefi.h>

#define CMD_DIOPROCESS_PING_SMI             0xD700DEADULL
#define CMD_DIOPROCESS_READ_PHYS            0xD800AAABULL
#define CMD_DIOPROCESS_WRITE_PHYS           0xD800BBCDULL
#define CMD_DIOPROCESS_VIRT_TO_PHYS         0xD800FF11ULL
#define CMD_DIOPROCESS_READ_VIRTUAL         0xD900CCEFULL
#define CMD_DIOPROCESS_WRITE_VIRTUAL        0xD900DDAFULL
#define CMD_DIOPROCESS_PRIV_ESC             0xD100AC91ULL
#define CMD_DIOPROCESS_CACHE_SESSION_INFO   0xD110A110ULL

typedef struct _DIOPROCESS_COMMUNICATION {
    UINT32      Command;
    EFI_STATUS  SmiRetStatus;
    UINT64      CommBufSize;

    struct {
        UINT64  TargetProcessId;
        VOID   *PhysReadAddress;
        VOID   *VaReadAddress;
        VOID   *ReadResult;
        UINT64  ReadLength;
    } Read;

    struct {
        UINT64  TargetProcessId;
        VOID   *PhysWriteAddress;
        VOID   *VaWriteAddress;
        VOID   *DataToWrite;
        UINT64  WriteLength;
    } Write;

    struct {
        UINT64  ControllerProcessId;
        VOID   *VaPsInitialSysProcess;
        UINT64  DirBase;
    } Cache;

    struct {
        UINT64  TargetPid;
        VOID   *AddressToTranslate;
        VOID   *Translated;
    } Vtop;
} DIOPROCESS_COMMUNICATION, *PDIOPROCESS_COMMUNICATION;

typedef struct _DIOPROCESS_TRANSFER {
    struct {
        VOID  *CommBufVirtual;
        VOID  *CommBufPhys;
        UINTN  BufSize;
    } Buffer;

    struct {
        VOID  *SetupBufFunction;
        VOID  *SmmCommunicateFunction;
    } API;
} DIOPROCESS_TRANSFER, *PDIOPROCESS_TRANSFER;

STATIC CONST EFI_GUID gDioProcessTransferVarGuid = { 0xD100C0C5, 0x1337, 0x4242, { 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x03 } };
STATIC CONST EFI_GUID gDioProcessSmiHandlerGuid = { 0x2BFADA50, 0xAF38, 0x49A1, { 0x85, 0x34, 0x08, 0xF6, 0xAE, 0x1B, 0x4C, 0x96 } };

#endif
