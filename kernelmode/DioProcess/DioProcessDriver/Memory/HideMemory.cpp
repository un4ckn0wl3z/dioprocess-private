#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include "HideMemory.h"
#include "hde/hde64.h"

// ============== MmPfnDataBase Resolution ==============

/// Dynamically resolve MmPfnDataBase by disassembling MmGetVirtualForPhysical.
/// The function contains a 10-byte instruction with the MmPfnDataBase address embedded.
/// We scan instructions using HDE64 until we find a 10-byte instruction,
/// then extract the address from bytes [2..10] and subtract 8.
static _MMPFN* get_MmPfnDataBase()
{
	UNICODE_STRING funcName = { 0 };
	RtlInitUnicodeString(&funcName, L"MmGetVirtualForPhysical");

	auto start = (unsigned char*)MmGetSystemRoutineAddress(&funcName);
	if (!start)
	{
		KdPrint(("DioProcess: Failed to resolve MmGetVirtualForPhysical\n"));
		return nullptr;
	}

	int index = 0;
	hde64s hde = { 0 };

	while (hde64_disasm(&start[index], &hde))
	{
		if (hde.len == 10)
			break;
		index += hde.len;

		// Safety: don't scan too far
		if (index > 256)
		{
			KdPrint(("DioProcess: Failed to find 10-byte instruction in MmGetVirtualForPhysical\n"));
			return nullptr;
		}
	}

	ULONG64 tmp = *(PULONG64)(&start[index + 2]);
	return (_MMPFN*)(tmp - 8);
}

// ============== Hide Memory Implementation ==============

NTSTATUS HideMemorySetProtection(ULONG ProcessId, ULONG64 VirtualAddress, ULONG Protection)
{
	PEPROCESS eProcess = NULL;
	KAPC_STATE apcState = { 0 };

	// Validate protection value (5-bit field, max 0x1F)
	if (Protection > 0x1F)
	{
		KdPrint(("DioProcess: HideMemory invalid protection value 0x%X\n", Protection));
		return STATUS_INVALID_PARAMETER;
	}

	// Resolve MmPfnDataBase
	auto MmPfnDataBase = get_MmPfnDataBase();
	if (!MmPfnDataBase)
	{
		KdPrint(("DioProcess: HideMemory failed to resolve MmPfnDataBase\n"));
		return STATUS_NOT_FOUND;
	}

	KdPrint(("DioProcess: HideMemory MmPfnDataBase=0x%llx\n", (ULONG64)MmPfnDataBase));

	// Look up target process
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &eProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("DioProcess: HideMemory PsLookupProcessByProcessId failed for PID %d (0x%X)\n",
			ProcessId, status));
		return status;
	}

	// Attach to target process address space
	KeStackAttachProcess(eProcess, &apcState);

	// Page-align the virtual address
	void* alignedVa = PAGE_ALIGN((void*)VirtualAddress);

	// Translate VA to PA
	PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(alignedVa);
	if (pa.QuadPart == 0)
	{
		KdPrint(("DioProcess: HideMemory MmGetPhysicalAddress failed for VA 0x%llx\n", VirtualAddress));
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(eProcess);
		return STATUS_INVALID_ADDRESS;
	}

	// Calculate PFN (Page Frame Number)
	ULONG64 pfn = pa.QuadPart >> 12;

	// Access the PFN entry
	auto mmpfn = &MmPfnDataBase[pfn];

	// Log current and new protection
	KdPrint(("DioProcess: HideMemory PID=%d VA=0x%llx PA=0x%llx PFN=0x%llx\n",
		ProcessId, VirtualAddress, pa.QuadPart, pfn));
	KdPrint(("DioProcess: HideMemory Old Protection=%d, New Protection=%d\n",
		(ULONG)mmpfn->OriginalPte.Protection, Protection));

	// Modify the OriginalPte.Protection bitfield
	mmpfn->OriginalPte.Protection = Protection;

	KdPrint(("DioProcess: HideMemory protection changed successfully\n"));

	// Cleanup
	KeUnstackDetachProcess(&apcState);
	ObDereferenceObject(eProcess);

	return STATUS_SUCCESS;
}
