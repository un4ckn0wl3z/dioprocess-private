#include "../pch.h"
#include "PhysicalMemory.h"
#include "../DioProcessGlobals.h"
#include <intrin.h>

#define DRIVER_PREFIX "DioProcess: "

// ============== CR3 Retrieval ==============

ULONG64 PhysMemGetProcessCR3(ULONG ProcessId)
{
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "PhysMemGetProcessCR3: PsLookupProcessByProcessId failed for PID %u (0x%08X)\n", ProcessId, status));
		return 0;
	}

	KAPC_STATE apcState;
	KeStackAttachProcess(process, &apcState);

	ULONG64 cr3 = __readcr3();

	KeUnstackDetachProcess(&apcState);
	ObDereferenceObject(process);

	KdPrint((DRIVER_PREFIX "PhysMemGetProcessCR3: PID %u -> CR3 = 0x%llX\n", ProcessId, cr3));
	return cr3;
}

// ============== Physical Memory Read ==============

NTSTATUS PhysMemReadPhysical(ULONG64 PhysAddr, PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead)
{
	if (!Buffer || !Size || !PhysAddr)
		return STATUS_INVALID_PARAMETER;

	MM_COPY_ADDRESS addr;
	addr.PhysicalAddress.QuadPart = (LONGLONG)PhysAddr;

	return MmCopyMemory(Buffer, addr, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

// ============== Physical Memory Write ==============

NTSTATUS PhysMemWritePhysical(ULONG64 PhysAddr, PVOID Buffer, SIZE_T Size, PSIZE_T BytesWritten)
{
	if (!Buffer || !Size || !PhysAddr)
		return STATUS_INVALID_PARAMETER;

	PHYSICAL_ADDRESS pa;
	pa.QuadPart = (LONGLONG)PhysAddr;

	PVOID mapped = MmMapIoSpace(pa, Size, MmNonCached);
	if (!mapped)
		return STATUS_INSUFFICIENT_RESOURCES;

	__try
	{
		RtlCopyMemory(mapped, Buffer, Size);
		if (BytesWritten)
			*BytesWritten = Size;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		MmUnmapIoSpace(mapped, Size);
		return GetExceptionCode();
	}

	MmUnmapIoSpace(mapped, Size);
	return STATUS_SUCCESS;
}

// ============== PTE Decoding ==============

void PhysMemDecodePte(ULONG64 RawPte, ULONG64 EntryVirtualAddr, PageTableEntryResult* Result)
{
	RtlZeroMemory(Result, sizeof(PageTableEntryResult));

	Result->VirtualAddress = EntryVirtualAddr;
	Result->RawValue = RawPte;
	Result->PhysicalAddress = RawPte & PTE_PHYS_MASK;
	Result->Present = (RawPte & PTE_PRESENT) ? 1 : 0;
	Result->ReadWrite = (RawPte & PTE_READWRITE) ? 1 : 0;
	Result->UserSupervisor = (RawPte & PTE_USER) ? 1 : 0;
	Result->WriteThrough = (RawPte & PTE_WRITETHROUGH) ? 1 : 0;
	Result->CacheDisable = (RawPte & PTE_CACHEDISABLE) ? 1 : 0;
	Result->Accessed = (RawPte & PTE_ACCESSED) ? 1 : 0;
	Result->Dirty = (RawPte & PTE_DIRTY) ? 1 : 0;
	Result->LargePage = (RawPte & PTE_LARGE_PAGE) ? 1 : 0;
	Result->Global = (RawPte & PTE_GLOBAL) ? 1 : 0;
	Result->NoExecute = (RawPte & PTE_NX) ? 1 : 0;
}

// ============== 4-Level Page Table Walk ==============

NTSTATUS PhysMemTranslateVA(ULONG64 Cr3, ULONG64 VirtualAddress, TranslateVaResponse* Response)
{
	if (!Cr3 || !Response)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(Response, sizeof(TranslateVaResponse));
	Response->Cr3 = Cr3;

	ULONG64 pml4_idx = (VirtualAddress >> 39) & 0x1FF;
	ULONG64 pdpt_idx = (VirtualAddress >> 30) & 0x1FF;
	ULONG64 pd_idx = (VirtualAddress >> 21) & 0x1FF;
	ULONG64 pt_idx = (VirtualAddress >> 12) & 0x1FF;
	ULONG64 offset = VirtualAddress & PAGE_OFFSET_MASK;

	ULONG64 pte = 0;
	SIZE_T bytesRead = 0;
	NTSTATUS status;

	// Level 1: PML4
	ULONG64 pml4eAddr = (Cr3 & PTE_PHYS_MASK) + pml4_idx * 8;
	status = PhysMemReadPhysical(pml4eAddr, &pte, sizeof(pte), &bytesRead);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "TranslateVA: Failed to read PML4E at phys 0x%llX\n", pml4eAddr));
		return status;
	}

	PhysMemDecodePte(pte, pml4eAddr, &Response->Pml4e);
	Response->WalkDepth = 1;

	if (!(pte & PTE_PRESENT))
	{
		Response->Success = 0;
		return STATUS_SUCCESS; // Walk completed but page not present
	}

	// Level 2: PDPT
	ULONG64 pdpteAddr = (pte & PTE_PHYS_MASK) + pdpt_idx * 8;
	status = PhysMemReadPhysical(pdpteAddr, &pte, sizeof(pte), &bytesRead);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "TranslateVA: Failed to read PDPTE at phys 0x%llX\n", pdpteAddr));
		return status;
	}

	PhysMemDecodePte(pte, pdpteAddr, &Response->Pdpte);
	Response->WalkDepth = 2;

	if (!(pte & PTE_PRESENT))
	{
		Response->Success = 0;
		return STATUS_SUCCESS;
	}

	// Check for 1GB large page
	if (pte & PTE_LARGE_PAGE)
	{
		Response->PhysicalAddress = (pte & 0xFFFFC0000000ULL) + (VirtualAddress & 0x3FFFFFFFULL);
		Response->PageSize = 0x40000000; // 1GB
		Response->Success = 1;
		return STATUS_SUCCESS;
	}

	// Level 3: PD
	ULONG64 pdeAddr = (pte & PTE_PHYS_MASK) + pd_idx * 8;
	status = PhysMemReadPhysical(pdeAddr, &pte, sizeof(pte), &bytesRead);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "TranslateVA: Failed to read PDE at phys 0x%llX\n", pdeAddr));
		return status;
	}

	PhysMemDecodePte(pte, pdeAddr, &Response->Pde);
	Response->WalkDepth = 3;

	if (!(pte & PTE_PRESENT))
	{
		Response->Success = 0;
		return STATUS_SUCCESS;
	}

	// Check for 2MB large page
	if (pte & PTE_LARGE_PAGE)
	{
		Response->PhysicalAddress = (pte & 0xFFFFFE00000ULL) + (VirtualAddress & 0x1FFFFFULL);
		Response->PageSize = 0x200000; // 2MB
		Response->Success = 1;
		return STATUS_SUCCESS;
	}

	// Level 4: PT
	ULONG64 pteAddr = (pte & PTE_PHYS_MASK) + pt_idx * 8;
	status = PhysMemReadPhysical(pteAddr, &pte, sizeof(pte), &bytesRead);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "TranslateVA: Failed to read PTE at phys 0x%llX\n", pteAddr));
		return status;
	}

	PhysMemDecodePte(pte, pteAddr, &Response->Pte);
	Response->WalkDepth = 4;

	if (!(pte & PTE_PRESENT))
	{
		Response->Success = 0;
		return STATUS_SUCCESS;
	}

	Response->PhysicalAddress = (pte & PTE_PHYS_MASK) + offset;
	Response->PageSize = 0x1000; // 4KB
	Response->Success = 1;

	KdPrint((DRIVER_PREFIX "TranslateVA: VA 0x%llX -> PA 0x%llX (depth=%u, pageSize=0x%X)\n",
		VirtualAddress, Response->PhysicalAddress, Response->WalkDepth, Response->PageSize));

	return STATUS_SUCCESS;
}

// ============== Bulk Virtual Memory Read via CR3 Walk ==============

// Helper: translate a single VA to PA using CR3 (lightweight, no full response)
static ULONG64 TranslateVaToPA(ULONG64 Cr3, ULONG64 VirtualAddress)
{
	ULONG64 pml4_idx = (VirtualAddress >> 39) & 0x1FF;
	ULONG64 pdpt_idx = (VirtualAddress >> 30) & 0x1FF;
	ULONG64 pd_idx = (VirtualAddress >> 21) & 0x1FF;
	ULONG64 pt_idx = (VirtualAddress >> 12) & 0x1FF;
	ULONG64 offset = VirtualAddress & 0xFFF;

	ULONG64 pte = 0;
	SIZE_T bytesRead = 0;

	// PML4
	ULONG64 addr = (Cr3 & PTE_PHYS_MASK) + pml4_idx * 8;
	if (!NT_SUCCESS(PhysMemReadPhysical(addr, &pte, sizeof(pte), &bytesRead)) || !(pte & PTE_PRESENT))
		return 0;

	// PDPT
	addr = (pte & PTE_PHYS_MASK) + pdpt_idx * 8;
	if (!NT_SUCCESS(PhysMemReadPhysical(addr, &pte, sizeof(pte), &bytesRead)) || !(pte & PTE_PRESENT))
		return 0;

	if (pte & PTE_LARGE_PAGE) // 1GB page
		return (pte & 0xFFFFC0000000ULL) + (VirtualAddress & 0x3FFFFFFFULL);

	// PD
	addr = (pte & PTE_PHYS_MASK) + pd_idx * 8;
	if (!NT_SUCCESS(PhysMemReadPhysical(addr, &pte, sizeof(pte), &bytesRead)) || !(pte & PTE_PRESENT))
		return 0;

	if (pte & PTE_LARGE_PAGE) // 2MB page
		return (pte & 0xFFFFFE00000ULL) + (VirtualAddress & 0x1FFFFFULL);

	// PT
	addr = (pte & PTE_PHYS_MASK) + pt_idx * 8;
	if (!NT_SUCCESS(PhysMemReadPhysical(addr, &pte, sizeof(pte), &bytesRead)) || !(pte & PTE_PRESENT))
		return 0;

	return (pte & PTE_PHYS_MASK) + offset;
}

// ============== VM Region Enumeration via ZwQueryVirtualMemory ==============

NTSTATUS PhysMemEnumVmRegions(ULONG ProcessId, VmRegionEntry* Entries, ULONG MaxEntries, PULONG Count)
{
	if (!Entries || !Count || MaxEntries == 0)
		return STATUS_INVALID_PARAMETER;

	*Count = 0;

	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "PhysMemEnumVmRegions: PsLookupProcessByProcessId failed for PID %u (0x%08X)\n", ProcessId, status));
		return status;
	}

	KAPC_STATE apcState;
	KeStackAttachProcess(process, &apcState);

	ULONG count = 0;
	PVOID address = NULL;

	while (count < MaxEntries)
	{
		MEMORY_BASIC_INFORMATION mbi = {};
		SIZE_T returnLen = 0;

		status = ZwQueryVirtualMemory(
			ZwCurrentProcess(),
			address,
			MemoryBasicInformation,
			&mbi,
			sizeof(mbi),
			&returnLen
		);

		if (!NT_SUCCESS(status))
			break;

		Entries[count].BaseAddress = (ULONG64)mbi.BaseAddress;
		Entries[count].RegionSize  = (ULONG64)mbi.RegionSize;
		Entries[count].State       = mbi.State;
		Entries[count].Protect     = mbi.Protect;
		Entries[count].Type        = mbi.Type;
		Entries[count]._pad        = 0;
		count++;

		// Advance past this region
		ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
		if (next <= (ULONG_PTR)address)
			break; // overflow / wrap protection

		address = (PVOID)next;

		// Stop at top of 64-bit usermode address space
		if (next >= (ULONG_PTR)0x00007FFFFFFFFFFF)
			break;
	}

	KeUnstackDetachProcess(&apcState);
	ObDereferenceObject(process);

	*Count = count;
	KdPrint((DRIVER_PREFIX "PhysMemEnumVmRegions: PID %u -> %u regions\n", ProcessId, count));
	return STATUS_SUCCESS;
}

NTSTATUS PhysMemReadVirtualMemory(ULONG ProcessId, ULONG64 VirtualAddress, PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead)
{
	if (!Buffer || !Size || !BytesRead)
		return STATUS_INVALID_PARAMETER;

	*BytesRead = 0;

	ULONG64 cr3 = PhysMemGetProcessCR3(ProcessId);
	if (!cr3)
		return STATUS_NOT_FOUND;

	PUCHAR outBuf = (PUCHAR)Buffer;
	SIZE_T remaining = Size;
	ULONG64 currentVA = VirtualAddress;

	while (remaining > 0)
	{
		// Calculate how many bytes until the next page boundary
		ULONG64 pageOffset = currentVA & 0xFFF;
		SIZE_T chunkSize = min(remaining, 0x1000 - (SIZE_T)pageOffset);

		ULONG64 pa = TranslateVaToPA(cr3, currentVA);
		if (pa != 0)
		{
			SIZE_T chunkRead = 0;
			NTSTATUS status = PhysMemReadPhysical(pa, outBuf, chunkSize, &chunkRead);
			if (NT_SUCCESS(status))
			{
				outBuf += chunkRead;
				*BytesRead += chunkRead;
			}
			else
			{
				// Fill zeros for unreadable pages
				RtlZeroMemory(outBuf, chunkSize);
				outBuf += chunkSize;
				*BytesRead += chunkSize;
			}
		}
		else
		{
			// Page not mapped - fill zeros
			RtlZeroMemory(outBuf, chunkSize);
			outBuf += chunkSize;
			*BytesRead += chunkSize;
		}

		currentVA += chunkSize;
		remaining -= chunkSize;
	}

	return STATUS_SUCCESS;
}
