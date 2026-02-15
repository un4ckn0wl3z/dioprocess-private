#include "../pch.h"
#include <ia32.hpp>
#include "../Hypervisor/hv.h"
#include "../Hypervisor/HvProtection.h"
#include "../Hypervisor/hypercalls.h"
#include "../Hypervisor/vcpu.h"
#include "UsermodeEptHook.h"

#define DRIVER_PREFIX "DioProcess: "

// ============== Global State ==============

static UsermodeEptHookEntry g_UsermodeEptHooks[MAX_USERMODE_EPT_HOOKS] = { 0 };
static ULONG g_UsermodeEptHookCount = 0;

// ============== Install ==============

NTSTATUS UsermodeEptHook_Install(
	ULONG ProcessId,
	ULONG64 TargetVirtualAddress,
	PVOID PatchBytes,
	ULONG PatchSize,
	PULONG OutHookIndex)
{
	if (!PatchBytes || PatchSize == 0 || PatchSize > 256 || !OutHookIndex)
		return STATUS_INVALID_PARAMETER;

	if (!HvIsHypervisorRunning())
	{
		KdPrint((DRIVER_PREFIX "UsermodeEptHook: Hypervisor not running\n"));
		return STATUS_HV_NOT_PRESENT;
	}

	// Find free slot
	ULONG slotIndex = MAXULONG;
	for (ULONG i = 0; i < MAX_USERMODE_EPT_HOOKS; i++)
	{
		if (!g_UsermodeEptHooks[i].Active)
		{
			slotIndex = i;
			break;
		}
	}

	if (slotIndex == MAXULONG)
	{
		KdPrint((DRIVER_PREFIX "UsermodeEptHook: No free slots (max %u)\n", MAX_USERMODE_EPT_HOOKS));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Validate patch doesn't cross page boundary
	ULONG pageOffset = (ULONG)(TargetVirtualAddress & 0xFFF);
	if (pageOffset + PatchSize > 0x1000)
	{
		KdPrint((DRIVER_PREFIX "UsermodeEptHook: Patch crosses page boundary (offset=0x%X, size=%u)\n",
			pageOffset, PatchSize));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status = STATUS_SUCCESS;

	// Step 1: Lookup target process
	PEPROCESS targetProcess = nullptr;
	status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &targetProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "UsermodeEptHook: PsLookupProcessByProcessId failed: 0x%X\n", status));
		return status;
	}

	// Step 2: Allocate exec page in NonPagedPool (kernel space, always paged in)
	PVOID execPage = ExAllocatePoolWithTag(NonPagedPool, 0x1000, USERMODE_EPT_HOOK_TAG);
	if (!execPage)
	{
		ObDereferenceObject(targetProcess);
		KdPrint((DRIVER_PREFIX "UsermodeEptHook: Failed to allocate exec page\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	PHYSICAL_ADDRESS origPhysAddr = { 0 };
	ULONG64 origPfn = 0;

	// Step 3: Attach to target process and read the original page
	KAPC_STATE apcState;
	KeStackAttachProcess(targetProcess, &apcState);

	__try
	{
		// Get the page-aligned virtual address
		PVOID pageAlignedVa = (PVOID)(TargetVirtualAddress & ~0xFFFull);

		// Probe the page to ensure it's paged in and accessible
		ProbeForRead(pageAlignedVa, 0x1000, 1);

		// Get the physical address of the original page
		origPhysAddr = MmGetPhysicalAddress(pageAlignedVa);
		if (origPhysAddr.QuadPart == 0)
		{
			KdPrint((DRIVER_PREFIX "UsermodeEptHook: MmGetPhysicalAddress returned 0\n"));
			status = STATUS_INVALID_ADDRESS;
			__leave;
		}

		origPfn = origPhysAddr.QuadPart >> 12;

		// Copy the entire original page content to exec page
		RtlCopyMemory(execPage, pageAlignedVa, 0x1000);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
		KdPrint((DRIVER_PREFIX "UsermodeEptHook: Exception reading target page: 0x%X\n", status));
	}

	KeUnstackDetachProcess(&apcState);

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(execPage, USERMODE_EPT_HOOK_TAG);
		ObDereferenceObject(targetProcess);
		return status;
	}

	// Step 4: Apply patch bytes to the exec page copy
	RtlCopyMemory((PUCHAR)execPage + pageOffset, PatchBytes, PatchSize);

	// Step 5: Install EPT hook on all CPUs via VMCALL
	// Original PFN = read/write page (clean bytes, passes integrity checks)
	// Exec PFN = execute page (patched bytes, custom behavior)
	PHYSICAL_ADDRESS execPhysAddr = MmGetPhysicalAddress(execPage);
	ULONG64 execPfn = execPhysAddr.QuadPart >> 12;

	KdPrint((DRIVER_PREFIX "UsermodeEptHook: Installing EPT hook - origPFN=0x%llX, execPFN=0x%llX\n",
		origPfn, execPfn));

	for (ULONG i = 0; i < KeQueryActiveProcessorCount(nullptr); ++i)
	{
		auto origAffinity = KeSetSystemAffinityThreadEx(1ull << i);

		hv::hypercall_input input = {};
		input.code = hv::hypercall_install_ept_hook;
		input.key = hv::hypercall_key;
		input.args[0] = origPfn;
		input.args[1] = execPfn;
		hv::vmx_vmcall(input);

		KeRevertToUserAffinityThreadEx(origAffinity);
	}

	// Step 6: Record in tracking array
	g_UsermodeEptHooks[slotIndex].ProcessId = ProcessId;
	g_UsermodeEptHooks[slotIndex].TargetVirtualAddress = TargetVirtualAddress;
	g_UsermodeEptHooks[slotIndex].OriginalPagePfn = origPfn;
	g_UsermodeEptHooks[slotIndex].ExecPage = execPage;
	g_UsermodeEptHooks[slotIndex].PatchOffset = pageOffset;
	g_UsermodeEptHooks[slotIndex].PatchSize = PatchSize;
	g_UsermodeEptHooks[slotIndex].Active = TRUE;
	g_UsermodeEptHookCount++;

	*OutHookIndex = slotIndex;

	ObDereferenceObject(targetProcess);

	KdPrint((DRIVER_PREFIX "UsermodeEptHook: Installed hook #%u for PID %u at VA 0x%llX (PFN 0x%llX)\n",
		slotIndex, ProcessId, TargetVirtualAddress, origPfn));

	return STATUS_SUCCESS;
}

// ============== Remove ==============

NTSTATUS UsermodeEptHook_Remove(ULONG HookIndex)
{
	if (HookIndex >= MAX_USERMODE_EPT_HOOKS)
		return STATUS_INVALID_PARAMETER;

	if (!g_UsermodeEptHooks[HookIndex].Active)
		return STATUS_NOT_FOUND;

	UsermodeEptHookEntry* entry = &g_UsermodeEptHooks[HookIndex];

	KdPrint((DRIVER_PREFIX "UsermodeEptHook: Removing hook #%u (PID %u, PFN 0x%llX)\n",
		HookIndex, entry->ProcessId, entry->OriginalPagePfn));

	// Remove EPT hook on all CPUs via VMCALL
	if (HvIsHypervisorRunning())
	{
		for (ULONG i = 0; i < KeQueryActiveProcessorCount(nullptr); ++i)
		{
			auto origAffinity = KeSetSystemAffinityThreadEx(1ull << i);

			hv::hypercall_input input = {};
			input.code = hv::hypercall_remove_ept_hook;
			input.key = hv::hypercall_key;
			input.args[0] = entry->OriginalPagePfn;
			hv::vmx_vmcall(input);

			KeRevertToUserAffinityThreadEx(origAffinity);
		}
	}

	// Free the allocated exec page
	if (entry->ExecPage)
	{
		ExFreePoolWithTag(entry->ExecPage, USERMODE_EPT_HOOK_TAG);
	}

	// Clear the entry
	RtlZeroMemory(entry, sizeof(UsermodeEptHookEntry));
	g_UsermodeEptHookCount--;

	KdPrint((DRIVER_PREFIX "UsermodeEptHook: Hook #%u removed\n", HookIndex));

	return STATUS_SUCCESS;
}

// ============== Remove All ==============

NTSTATUS UsermodeEptHook_RemoveAll()
{
	KdPrint((DRIVER_PREFIX "UsermodeEptHook: Removing all hooks (%u active)\n", g_UsermodeEptHookCount));

	for (ULONG i = 0; i < MAX_USERMODE_EPT_HOOKS; i++)
	{
		if (g_UsermodeEptHooks[i].Active)
		{
			UsermodeEptHook_Remove(i);
		}
	}

	return STATUS_SUCCESS;
}

// ============== Get List ==============

NTSTATUS UsermodeEptHook_GetList(
	UsermodeEptHookEntry* OutEntries,
	ULONG* OutSlotIndices,
	ULONG* Count,
	ULONG MaxEntries)
{
	if (!OutEntries || !OutSlotIndices || !Count)
		return STATUS_INVALID_PARAMETER;

	ULONG found = 0;
	for (ULONG i = 0; i < MAX_USERMODE_EPT_HOOKS && found < MaxEntries; i++)
	{
		if (g_UsermodeEptHooks[i].Active)
		{
			RtlCopyMemory(&OutEntries[found], &g_UsermodeEptHooks[i], sizeof(UsermodeEptHookEntry));
			OutSlotIndices[found] = i;
			found++;
		}
	}

	*Count = found;
	return STATUS_SUCCESS;
}
