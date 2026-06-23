/** @file
  DioProcess SMM — Data structure definitions.
  Based on Deadwing SMM driver architecture.
**/

#ifndef _DIOPROCESS_SMM_DEFS_H_
#define _DIOPROCESS_SMM_DEFS_H_

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

typedef struct _DIOPROCESS_LIVE_SESSION_INFO {
    struct {
        VOID   *VaPsInitialSysProcess;
        VOID   *PhysPsInitialSysProcess;
        UINT64  DirBase;
    } SysProcess;

    struct {
        VOID   *PhysUmControllerEprocess;
        UINT64  UmControllerDirBase;
    } UmController;
} DIOPROCESS_LIVE_SESSION_INFO, *PDIOPROCESS_LIVE_SESSION_INFO;

typedef enum _DIOPROCESS_PAGE_TRANSLATION_SIZE {
    EDioprocessPage4Kb = 0,
    EDioprocessPage2Mb,
    EDioprocessPage1Gb
} DIOPROCESS_PAGE_TRANSLATION_SIZE;

#endif
