#pragma once

#include <ntddk.h>
#include "../DioProcessCommon.h"

// UEFI runtime variable GUID for SMM transfer info
// {D100C0C5-1337-4242-BEEF-CAFEBABE0003}
#define DIOPROCESS_SMM_TRANSFER_GUID \
    { 0xD100C0C5, 0x1337, 0x4242, { 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x03 } }

// SMM communication function types
typedef NTSTATUS(*SETUP_COMMUNICATION_BUFFER)(
    SmmCommunication* CommPacket,
    SIZE_T DataSize
    );

typedef SmmCommunication* (*SMM_COMMUNICATE)(VOID);

// Initialize SMM communication by reading UEFI runtime variable
NTSTATUS SmmInitialize();

// Check if SMM communication is available
BOOLEAN SmmIsAvailable();

// Ping SMI handler to verify it's alive
NTSTATUS SmmPing();

// Cache session info (must be called before other operations)
NTSTATUS SmmCacheSession(ULONG ControllerPid);

// Physical memory read
NTSTATUS SmmPhysRead(
    ULONG64 PhysicalAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesRead
);

// Physical memory write
NTSTATUS SmmPhysWrite(
    ULONG64 PhysicalAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesWritten
);

// Virtual memory read (requires target process ID)
NTSTATUS SmmVirtualRead(
    ULONG ProcessId,
    ULONG64 VirtualAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesRead
);

// Virtual memory write (requires target process ID)
NTSTATUS SmmVirtualWrite(
    ULONG ProcessId,
    ULONG64 VirtualAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesWritten
);

// Virtual to physical address translation
NTSTATUS SmmVirtToPhys(
    ULONG ProcessId,
    ULONG64 VirtualAddress,
    PULONG64 PhysicalAddress
);

// Privilege escalation (give calling process SYSTEM token)
NTSTATUS SmmEscalatePrivileges();
