#include "../pch.h"
#include "SmmCommunication.h"
#include <ntstrsafe.h>

// Global state
static BOOLEAN g_SmmInitialized = FALSE;
static SmmTransferInfo g_TransferInfo = { 0 };
static SETUP_COMMUNICATION_BUFFER g_SetupBuffer = NULL;
static SMM_COMMUNICATE g_SmmCommunicate = NULL;
static PVOID g_IntermediateBuffer = NULL;

NTSTATUS SmmInitialize()
{
    if (g_SmmInitialized)
        return STATUS_SUCCESS;

    UNICODE_STRING VarName;
    RtlInitUnicodeString(&VarName, L"DioProcessSmmTransfer");

    GUID TransferGuid = DIOPROCESS_SMM_TRANSFER_GUID;
    ULONG BufferSize = sizeof(SmmTransferInfo);
    ULONG Attributes = 0;

    NTSTATUS Status = ExGetFirmwareEnvironmentVariable(
        &VarName,
        &TransferGuid,
        &g_TransferInfo,
        &BufferSize,
        &Attributes
    );

    if (!NT_SUCCESS(Status)) {
        KdPrint(("[SMM] Failed to read UEFI variable: 0x%08X\n", Status));
        return Status;
    }

    // Validate transfer info
    if (!g_TransferInfo.API.SetupBufFunction ||
        !g_TransferInfo.API.SmmCommunicateFunction ||
        !g_TransferInfo.Buffer.CommBufVirtual ||
        g_TransferInfo.Buffer.BufSize == 0) {
        KdPrint(("[SMM] Invalid transfer info from UEFI\n"));
        return STATUS_INVALID_PARAMETER;
    }

    g_SetupBuffer = (SETUP_COMMUNICATION_BUFFER)g_TransferInfo.API.SetupBufFunction;
    g_SmmCommunicate = (SMM_COMMUNICATE)g_TransferInfo.API.SmmCommunicateFunction;

    // Allocate intermediate buffer for data transfers
    g_IntermediateBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, SMM_MAX_TRANSFER_SIZE, 'MMSD');
    if (!g_IntermediateBuffer) {
        KdPrint(("[SMM] Failed to allocate intermediate buffer\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_SmmInitialized = TRUE;
    KdPrint(("[SMM] Initialized successfully\n"));
    KdPrint(("[SMM] CommBuf: %p, Size: %llu\n",
        g_TransferInfo.Buffer.CommBufVirtual,
        (ULONG64)g_TransferInfo.Buffer.BufSize));

    return STATUS_SUCCESS;
}

BOOLEAN SmmIsAvailable()
{
    return g_SmmInitialized;
}

// Helper to fire SMI and get result
static NTSTATUS FireSmi(SmmCommunication* Packet)
{
    if (!g_SmmInitialized)
        return STATUS_NOT_SUPPORTED;

    // Setup communication buffer (this is a runtime services call)
    NTSTATUS Status = g_SetupBuffer(Packet, sizeof(SmmCommunication));
    if (!NT_SUCCESS(Status)) {
        KdPrint(("[SMM] SetupBuffer failed: 0x%08X\n", Status));
        return Status;
    }

    // Fire SMI and get response
    SmmCommunication* Response = g_SmmCommunicate();
    if (!Response) {
        KdPrint(("[SMM] SmmCommunicate returned NULL\n"));
        return STATUS_UNSUCCESSFUL;
    }

    // Copy response back
    RtlCopyMemory(Packet, Response, sizeof(SmmCommunication));

    return Packet->SmiRetStatus;
}

NTSTATUS SmmPing()
{
    SmmCommunication Packet = { 0 };
    Packet.Command = SMM_CMD_PING;
    Packet.SmiRetStatus = STATUS_UNSUCCESSFUL;

    NTSTATUS Status = FireSmi(&Packet);
    KdPrint(("[SMM] Ping result: 0x%08X\n", Status));
    return Status;
}

NTSTATUS SmmCacheSession(ULONG ControllerPid)
{
    if (!g_SmmInitialized)
        return STATUS_NOT_SUPPORTED;

    // Get PsInitialSystemProcess and its DirBase
    PEPROCESS SystemProcess = PsInitialSystemProcess;
    if (!SystemProcess)
        return STATUS_UNSUCCESSFUL;

    // Get DirBase (CR3) from EPROCESS
    // DirectoryTableBase is at offset 0x28 in EPROCESS (Windows 10+)
    ULONG64 DirBase = *(ULONG64*)((UCHAR*)SystemProcess + 0x28);

    SmmCommunication Packet = { 0 };
    Packet.Command = SMM_CMD_CACHE_SESSION;
    Packet.SmiRetStatus = STATUS_UNSUCCESSFUL;
    Packet.Cache.ControllerProcessId = ControllerPid;
    Packet.Cache.VaPsInitialSysProcess = SystemProcess;
    Packet.Cache.DirBase = DirBase;

    NTSTATUS Status = FireSmi(&Packet);
    KdPrint(("[SMM] CacheSession result: 0x%08X (Pid=%d, SysProc=%p, DirBase=0x%llX)\n",
        Status, ControllerPid, SystemProcess, DirBase));
    return Status;
}

NTSTATUS SmmPhysRead(
    ULONG64 PhysicalAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesRead
)
{
    if (!g_SmmInitialized)
        return STATUS_NOT_SUPPORTED;

    if (!Buffer || Size == 0 || Size > SMM_MAX_TRANSFER_SIZE)
        return STATUS_INVALID_PARAMETER;

    SmmCommunication Packet = { 0 };
    Packet.Command = SMM_CMD_READ_PHYS;
    Packet.SmiRetStatus = STATUS_UNSUCCESSFUL;
    Packet.Read.PhysReadAddress = (VOID*)PhysicalAddress;
    Packet.Read.ReadResult = g_IntermediateBuffer;
    Packet.Read.ReadLength = Size;

    NTSTATUS Status = FireSmi(&Packet);
    if (NT_SUCCESS(Status)) {
        RtlCopyMemory(Buffer, g_IntermediateBuffer, Size);
        if (BytesRead)
            *BytesRead = Size;
    }

    return Status;
}

NTSTATUS SmmPhysWrite(
    ULONG64 PhysicalAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesWritten
)
{
    if (!g_SmmInitialized)
        return STATUS_NOT_SUPPORTED;

    if (!Buffer || Size == 0 || Size > SMM_MAX_TRANSFER_SIZE)
        return STATUS_INVALID_PARAMETER;

    // Copy data to intermediate buffer first
    RtlCopyMemory(g_IntermediateBuffer, Buffer, Size);

    SmmCommunication Packet = { 0 };
    Packet.Command = SMM_CMD_WRITE_PHYS;
    Packet.SmiRetStatus = STATUS_UNSUCCESSFUL;
    Packet.Write.PhysWriteAddress = (VOID*)PhysicalAddress;
    Packet.Write.DataToWrite = g_IntermediateBuffer;
    Packet.Write.WriteLength = Size;

    NTSTATUS Status = FireSmi(&Packet);
    if (NT_SUCCESS(Status) && BytesWritten)
        *BytesWritten = Size;

    return Status;
}

NTSTATUS SmmVirtualRead(
    ULONG ProcessId,
    ULONG64 VirtualAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesRead
)
{
    if (!g_SmmInitialized)
        return STATUS_NOT_SUPPORTED;

    if (!Buffer || Size == 0 || Size > SMM_MAX_TRANSFER_SIZE || ProcessId == 0)
        return STATUS_INVALID_PARAMETER;

    SmmCommunication Packet = { 0 };
    Packet.Command = SMM_CMD_READ_VIRTUAL;
    Packet.SmiRetStatus = STATUS_UNSUCCESSFUL;
    Packet.Read.TargetProcessId = ProcessId;
    Packet.Read.VaReadAddress = (VOID*)VirtualAddress;
    Packet.Read.ReadResult = g_IntermediateBuffer;
    Packet.Read.ReadLength = Size;

    NTSTATUS Status = FireSmi(&Packet);
    if (NT_SUCCESS(Status)) {
        RtlCopyMemory(Buffer, g_IntermediateBuffer, Size);
        if (BytesRead)
            *BytesRead = Size;
    }

    return Status;
}

NTSTATUS SmmVirtualWrite(
    ULONG ProcessId,
    ULONG64 VirtualAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesWritten
)
{
    if (!g_SmmInitialized)
        return STATUS_NOT_SUPPORTED;

    if (!Buffer || Size == 0 || Size > SMM_MAX_TRANSFER_SIZE || ProcessId == 0)
        return STATUS_INVALID_PARAMETER;

    // Copy data to intermediate buffer first
    RtlCopyMemory(g_IntermediateBuffer, Buffer, Size);

    SmmCommunication Packet = { 0 };
    Packet.Command = SMM_CMD_WRITE_VIRTUAL;
    Packet.SmiRetStatus = STATUS_UNSUCCESSFUL;
    Packet.Write.TargetProcessId = ProcessId;
    Packet.Write.VaWriteAddress = (VOID*)VirtualAddress;
    Packet.Write.DataToWrite = g_IntermediateBuffer;
    Packet.Write.WriteLength = Size;

    NTSTATUS Status = FireSmi(&Packet);
    if (NT_SUCCESS(Status) && BytesWritten)
        *BytesWritten = Size;

    return Status;
}

NTSTATUS SmmVirtToPhys(
    ULONG ProcessId,
    ULONG64 VirtualAddress,
    PULONG64 PhysicalAddress
)
{
    if (!g_SmmInitialized)
        return STATUS_NOT_SUPPORTED;

    if (!PhysicalAddress || ProcessId == 0)
        return STATUS_INVALID_PARAMETER;

    SmmCommunication Packet = { 0 };
    Packet.Command = SMM_CMD_VIRT_TO_PHYS;
    Packet.SmiRetStatus = STATUS_UNSUCCESSFUL;
    Packet.Vtop.TargetPid = ProcessId;
    Packet.Vtop.AddressToTranslate = (VOID*)VirtualAddress;

    NTSTATUS Status = FireSmi(&Packet);
    if (NT_SUCCESS(Status))
        *PhysicalAddress = (ULONG64)Packet.Vtop.Translated;

    return Status;
}

NTSTATUS SmmEscalatePrivileges()
{
    if (!g_SmmInitialized)
        return STATUS_NOT_SUPPORTED;

    SmmCommunication Packet = { 0 };
    Packet.Command = SMM_CMD_PRIV_ESC;
    Packet.SmiRetStatus = STATUS_UNSUCCESSFUL;

    NTSTATUS Status = FireSmi(&Packet);
    KdPrint(("[SMM] EscalatePrivileges result: 0x%08X\n", Status));
    return Status;
}
