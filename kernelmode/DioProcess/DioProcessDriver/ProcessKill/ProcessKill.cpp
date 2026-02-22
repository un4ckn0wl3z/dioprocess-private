#include "../pch.h"
#include "../DioProcessGlobals.h"
#include "ProcessKill.h"

// Kernel-mode declaration for ZwQueryInformationProcess
extern "C" NTSTATUS NTAPI ZwQueryInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);

// PROCESS_TERMINATE is not defined in WDK kernel headers
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

// ============== Dynamic Function Types ==============

typedef PVOID(NTAPI* PFN_PsGetProcessSectionBaseAddress)(PEPROCESS Process);
typedef NTSTATUS(NTAPI* PFN_MmUnmapViewOfSection)(PEPROCESS Process, PVOID BaseAddress);

// ============== Method 1: ZwTerminateProcess ==============
// Direct kernel API termination - cleanest approach

NTSTATUS HandleKillTerminate(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(TargetProcessRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (TargetProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	ULONG pid = request->ProcessId;
	KdPrint((DRIVER_PREFIX "Kill (ZwTerminate) — PID %d\n", pid));

	CLIENT_ID clientId = { 0 };
	clientId.UniqueProcess = UlongToHandle(pid);
	clientId.UniqueThread = NULL;

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE processHandle = NULL;
	NTSTATUS status = ZwOpenProcess(&processHandle, PROCESS_TERMINATE, &objAttr, &clientId);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "ZwOpenProcess failed for PID %d (0x%X)\n", pid, status));
		return status;
	}

	status = ZwTerminateProcess(processHandle, 0);
	ZwClose(processHandle);

	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "ZwTerminateProcess failed for PID %d (0x%X)\n", pid, status));
		return status;
	}

	KdPrint((DRIVER_PREFIX "Kill (ZwTerminate) — PID %d terminated successfully\n", pid));
	return STATUS_SUCCESS;
}

// ============== Method 2: MmUnmapViewOfSection ==============
// Unmap PE image section from process memory causing crash

NTSTATUS HandleKillUnmap(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(TargetProcessRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (TargetProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	ULONG pid = request->ProcessId;
	KdPrint((DRIVER_PREFIX "Kill (UnmapSection) — PID %d\n", pid));

	// Dynamically resolve undocumented functions
	UNICODE_STRING funcName1;
	RtlInitUnicodeString(&funcName1, L"PsGetProcessSectionBaseAddress");
	auto PsGetProcessSectionBaseAddress = (PFN_PsGetProcessSectionBaseAddress)MmGetSystemRoutineAddress(&funcName1);

	UNICODE_STRING funcName2;
	RtlInitUnicodeString(&funcName2, L"MmUnmapViewOfSection");
	auto MmUnmapViewOfSection = (PFN_MmUnmapViewOfSection)MmGetSystemRoutineAddress(&funcName2);

	if (!PsGetProcessSectionBaseAddress || !MmUnmapViewOfSection)
	{
		KdPrint((DRIVER_PREFIX "Failed to resolve undocumented functions\n"));
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	// Get EPROCESS
	PEPROCESS eProcess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(UlongToHandle(pid), &eProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "PsLookupProcessByProcessId failed for PID %d (0x%X)\n", pid, status));
		return status;
	}

	// Get image base address
	PVOID baseAddress = PsGetProcessSectionBaseAddress(eProcess);
	if (!baseAddress)
	{
		ObDereferenceObject(eProcess);
		KdPrint((DRIVER_PREFIX "PsGetProcessSectionBaseAddress returned NULL for PID %d\n", pid));
		return STATUS_UNSUCCESSFUL;
	}

	KdPrint((DRIVER_PREFIX "Unmapping section at 0x%p for PID %d\n", baseAddress, pid));

	// Unmap the image section
	status = MmUnmapViewOfSection(eProcess, baseAddress);
	ObDereferenceObject(eProcess);

	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "MmUnmapViewOfSection failed for PID %d (0x%X)\n", pid, status));
		return status;
	}

	KdPrint((DRIVER_PREFIX "Kill (UnmapSection) — PID %d section unmapped successfully\n", pid));
	return STATUS_SUCCESS;
}

// ============== Method 3: PEB Corruption ==============
// Fill PEB with INT3 (0xCC) via MDL memory mapping

NTSTATUS HandleKillPebCorrupt(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(TargetProcessRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (TargetProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	ULONG pid = request->ProcessId;
	KdPrint((DRIVER_PREFIX "Kill (PEB Corrupt) — PID %d\n", pid));

	// Get EPROCESS
	PEPROCESS eProcess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(UlongToHandle(pid), &eProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "PsLookupProcessByProcessId failed for PID %d (0x%X)\n", pid, status));
		return status;
	}

	// Open process handle from EPROCESS
	HANDLE processHandle = NULL;
	status = ObOpenObjectByPointer(eProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS,
		*PsProcessType, KernelMode, &processHandle);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(eProcess);
		KdPrint((DRIVER_PREFIX "ObOpenObjectByPointer failed for PID %d (0x%X)\n", pid, status));
		return status;
	}

	// Attach to target process context
	KAPC_STATE apcState;
	KeStackAttachProcess(eProcess, &apcState);

	// Query PEB address
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	ULONG returnLength = 0;
	status = ZwQueryInformationProcess(processHandle, ProcessBasicInformation,
		&pbi, sizeof(pbi), &returnLength);

	if (!NT_SUCCESS(status) || !pbi.PebBaseAddress)
	{
		KeUnstackDetachProcess(&apcState);
		ZwClose(processHandle);
		ObDereferenceObject(eProcess);
		KdPrint((DRIVER_PREFIX "ZwQueryInformationProcess failed for PID %d (0x%X)\n", pid, status));
		return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
	}

	KdPrint((DRIVER_PREFIX "PEB at 0x%p for PID %d\n", pbi.PebBaseAddress, pid));

	// Allocate MDL for PEB region
	PMDL mdl = IoAllocateMdl(pbi.PebBaseAddress, 4096, FALSE, FALSE, NULL);
	if (!mdl)
	{
		KeUnstackDetachProcess(&apcState);
		ZwClose(processHandle);
		ObDereferenceObject(eProcess);
		KdPrint((DRIVER_PREFIX "IoAllocateMdl failed for PID %d\n", pid));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try
	{
		// Lock pages in memory
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(mdl);
		KeUnstackDetachProcess(&apcState);
		ZwClose(processHandle);
		ObDereferenceObject(eProcess);
		KdPrint((DRIVER_PREFIX "MmProbeAndLockPages failed for PID %d\n", pid));
		return STATUS_ACCESS_VIOLATION;
	}

	// Map locked pages to kernel space with non-cached access
	PVOID mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode,
		MmNonCached, NULL, FALSE, NormalPagePriority);
	if (!mappedAddress)
	{
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		KeUnstackDetachProcess(&apcState);
		ZwClose(processHandle);
		ObDereferenceObject(eProcess);
		KdPrint((DRIVER_PREFIX "MmMapLockedPagesSpecifyCache failed for PID %d\n", pid));
		return STATUS_UNSUCCESSFUL;
	}

	// Corrupt PEB with INT3 (0xCC)
	RtlFillMemory(mappedAddress, 4096, 0xCC);
	KdPrint((DRIVER_PREFIX "PEB corrupted with 0xCC for PID %d\n", pid));

	// Cleanup
	MmUnmapLockedPages(mappedAddress, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
	KeUnstackDetachProcess(&apcState);
	ZwClose(processHandle);
	ObDereferenceObject(eProcess);

	KdPrint((DRIVER_PREFIX "Kill (PEB Corrupt) — PID %d corrupted successfully\n", pid));
	return STATUS_SUCCESS;
}
