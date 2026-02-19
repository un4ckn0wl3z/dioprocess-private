#include "../pch.h"
#include <ia32.hpp>
#include "../Hypervisor/hv.h"
#include "../Hypervisor/HvProtection.h"
#include "../Hypervisor/hypercalls.h"
#include "../Hypervisor/vcpu.h"
#include "RegisterChange.h"

#define DRIVER_PREFIX "DioProcess: "

// ============== Global State ==============

static RegChangeTrackingEntry g_RegChanges[MAX_REG_CHANGE_ENTRIES] = { 0 };
static ULONG g_RegChangeCount = 0;

// ============== Helpers ==============

// Get DirectoryTableBase (CR3) from EPROCESS
static ULONG64 GetProcessCr3(PEPROCESS Process)
{
	// KPROCESS.DirectoryTableBase is at offset 0x28 on all modern Windows versions
	return *(ULONG64*)((UCHAR*)Process + 0x28);
}

// ============== Install ==============

NTSTATUS RegisterChange_Install(
	ULONG ProcessId,
	ULONG64 TargetVirtualAddress,
	ULONG RegIndex,
	ULONG64 NewValue,
	PULONG OutEntryIndex)
{
	if (!OutEntryIndex || RegIndex > 15)
		return STATUS_INVALID_PARAMETER;

	if (!HvIsHypervisorRunning())
	{
		KdPrint((DRIVER_PREFIX "RegisterChange: Hypervisor not running\n"));
		return STATUS_HV_NOT_PRESENT;
	}

	// Find free slot
	ULONG slotIndex = MAXULONG;
	for (ULONG i = 0; i < MAX_REG_CHANGE_ENTRIES; i++)
	{
		if (!g_RegChanges[i].Active)
		{
			slotIndex = i;
			break;
		}
	}

	if (slotIndex == MAXULONG)
	{
		KdPrint((DRIVER_PREFIX "RegisterChange: No free slots (max %u)\n", MAX_REG_CHANGE_ENTRIES));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Lookup target process
	PEPROCESS targetProcess = nullptr;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &targetProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "RegisterChange: PsLookupProcessByProcessId failed: 0x%X\n", status));
		return status;
	}

	// Get CR3
	ULONG64 processCr3 = GetProcessCr3(targetProcess);

	// Get PFN by attaching to process and querying physical address
	PHYSICAL_ADDRESS physAddr = { 0 };
	ULONG64 pagePfn = 0;

	KAPC_STATE apcState;
	KeStackAttachProcess(targetProcess, &apcState);

	__try
	{
		PVOID pageAlignedVa = (PVOID)(TargetVirtualAddress & ~0xFFFull);
		ProbeForRead(pageAlignedVa, 0x1000, 1);

		physAddr = MmGetPhysicalAddress(pageAlignedVa);
		if (physAddr.QuadPart == 0)
		{
			KdPrint((DRIVER_PREFIX "RegisterChange: MmGetPhysicalAddress returned 0\n"));
			status = STATUS_INVALID_ADDRESS;
			__leave;
		}

		pagePfn = physAddr.QuadPart >> 12;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
		KdPrint((DRIVER_PREFIX "RegisterChange: Exception probing page: 0x%X\n", status));
	}

	KeUnstackDetachProcess(&apcState);
	ObDereferenceObject(targetProcess);

	if (!NT_SUCCESS(status))
		return status;

	// Install on all CPUs via VMCALL
	KdPrint((DRIVER_PREFIX "RegisterChange: Installing - PID=%u, VA=0x%llX, Reg=%u, Value=0x%llX, PFN=0x%llX, CR3=0x%llX\n",
		ProcessId, TargetVirtualAddress, RegIndex, NewValue, pagePfn, processCr3));

	for (ULONG i = 0; i < KeQueryActiveProcessorCount(nullptr); ++i)
	{
		auto origAffinity = KeSetSystemAffinityThreadEx(1ull << i);

		hv::hypercall_input input = {};
		input.code = hv::hypercall_install_reg_change;
		input.key = hv::hypercall_key;
		input.args[0] = TargetVirtualAddress;  // RCX = target_rip
		input.args[1] = processCr3;            // RDX = process_cr3
		input.args[2] = pagePfn;               // R8  = page_pfn
		input.args[3] = RegIndex;              // R9  = reg_index
		input.args[4] = NewValue;              // R10 = new_value
		hv::vmx_vmcall(input);

		KeRevertToUserAffinityThreadEx(origAffinity);
	}

	// Record in tracking array
	g_RegChanges[slotIndex].ProcessId = ProcessId;
	g_RegChanges[slotIndex].TargetVirtualAddress = TargetVirtualAddress;
	g_RegChanges[slotIndex].ProcessCr3 = processCr3;
	g_RegChanges[slotIndex].PagePfn = pagePfn;
	g_RegChanges[slotIndex].RegIndex = RegIndex;
	g_RegChanges[slotIndex].NewValue = NewValue;
	g_RegChanges[slotIndex].Active = TRUE;
	g_RegChangeCount++;

	*OutEntryIndex = slotIndex;

	KdPrint((DRIVER_PREFIX "RegisterChange: Installed entry #%u for PID %u at VA 0x%llX\n",
		slotIndex, ProcessId, TargetVirtualAddress));

	return STATUS_SUCCESS;
}

// ============== Remove ==============

NTSTATUS RegisterChange_Remove(ULONG EntryIndex)
{
	if (EntryIndex >= MAX_REG_CHANGE_ENTRIES)
		return STATUS_INVALID_PARAMETER;

	if (!g_RegChanges[EntryIndex].Active)
		return STATUS_NOT_FOUND;

	RegChangeTrackingEntry* entry = &g_RegChanges[EntryIndex];

	KdPrint((DRIVER_PREFIX "RegisterChange: Removing entry #%u (PID %u, VA 0x%llX)\n",
		EntryIndex, entry->ProcessId, entry->TargetVirtualAddress));

	// Remove on all CPUs via VMCALL
	if (HvIsHypervisorRunning())
	{
		for (ULONG i = 0; i < KeQueryActiveProcessorCount(nullptr); ++i)
		{
			auto origAffinity = KeSetSystemAffinityThreadEx(1ull << i);

			hv::hypercall_input input = {};
			input.code = hv::hypercall_remove_reg_change;
			input.key = hv::hypercall_key;
			input.args[0] = entry->TargetVirtualAddress;  // RCX = target_rip
			input.args[1] = entry->ProcessCr3;            // RDX = process_cr3
			hv::vmx_vmcall(input);

			KeRevertToUserAffinityThreadEx(origAffinity);
		}
	}

	// Clear the entry
	RtlZeroMemory(entry, sizeof(RegChangeTrackingEntry));
	g_RegChangeCount--;

	KdPrint((DRIVER_PREFIX "RegisterChange: Entry #%u removed\n", EntryIndex));

	return STATUS_SUCCESS;
}

// ============== Remove All ==============

NTSTATUS RegisterChange_RemoveAll()
{
	KdPrint((DRIVER_PREFIX "RegisterChange: Removing all entries (%u active)\n", g_RegChangeCount));

	if (HvIsHypervisorRunning())
	{
		for (ULONG i = 0; i < KeQueryActiveProcessorCount(nullptr); ++i)
		{
			auto origAffinity = KeSetSystemAffinityThreadEx(1ull << i);

			hv::hypercall_input input = {};
			input.code = hv::hypercall_remove_all_reg_changes;
			input.key = hv::hypercall_key;
			hv::vmx_vmcall(input);

			KeRevertToUserAffinityThreadEx(origAffinity);
		}
	}

	RtlZeroMemory(g_RegChanges, sizeof(g_RegChanges));
	g_RegChangeCount = 0;

	return STATUS_SUCCESS;
}

// ============== Get List ==============

NTSTATUS RegisterChange_GetList(
	RegChangeTrackingEntry* OutEntries,
	ULONG* OutSlotIndices,
	ULONG* Count,
	ULONG MaxEntries)
{
	if (!OutEntries || !OutSlotIndices || !Count)
		return STATUS_INVALID_PARAMETER;

	ULONG found = 0;
	for (ULONG i = 0; i < MAX_REG_CHANGE_ENTRIES && found < MaxEntries; i++)
	{
		if (g_RegChanges[i].Active)
		{
			RtlCopyMemory(&OutEntries[found], &g_RegChanges[i], sizeof(RegChangeTrackingEntry));
			OutSlotIndices[found] = i;
			found++;
		}
	}

	*Count = found;
	return STATUS_SUCCESS;
}
