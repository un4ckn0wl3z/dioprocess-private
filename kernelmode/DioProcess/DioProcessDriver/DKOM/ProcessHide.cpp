#include "../pch.h"
#include "../DioProcessGlobals.h"
#include "ProcessHide.h"

// ============== Undocumented Kernel APIs ==============
// These are exported by ntoskrnl but not declared in WDK headers.

extern "C" {
	NTKERNELAPI VOID KeGenericCallDpc(
		_In_ PKDEFERRED_ROUTINE Routine,
		_In_opt_ PVOID Context);

	NTKERNELAPI VOID KeSignalCallDpcDone(
		_In_ PVOID SystemArgument1);

	NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(
		_In_ PVOID SystemArgument2);
}

// ============== Global Variable Definitions ==============

PHIDDEN_PROCESS_ENTRY g_ProcessHideListHead = NULL;
ULONG g_ProcessHideCount = 0;
BOOLEAN g_ProcessHideInitialized = FALSE;

// ============== DPC Synchronization ==============
// KeGenericCallDpc freezes ALL CPUs in a DPC, ensuring no CPU can run
// list integrity checks (RtlpCheckListEntry) during our modification.

enum DKOM_OPERATION { DKOM_UNLINK, DKOM_RELINK };

typedef struct _DKOM_DPC_CONTEXT {
	DKOM_OPERATION Operation;
	PLIST_ENTRY TargetEntry;
	PLIST_ENTRY InsertAfter;     // Only for DKOM_RELINK
	volatile LONG WorkDone;
} DKOM_DPC_CONTEXT, *PDKOM_DPC_CONTEXT;

_IRQL_requires_(DISPATCH_LEVEL)
static VOID DkomDpcRoutine(
	_In_ PKDPC Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);

	PDKOM_DPC_CONTEXT ctx = (PDKOM_DPC_CONTEXT)DeferredContext;

	// Wait for ALL processors to enter this DPC before proceeding
	KeSignalCallDpcSynchronize(SystemArgument2);

	// Only one processor does the actual list modification
	if (InterlockedCompareExchange(&ctx->WorkDone, 1, 0) == 0)
	{
		if (ctx->Operation == DKOM_UNLINK)
		{
			// Unlink from doubly-linked list
			ctx->TargetEntry->Blink->Flink = ctx->TargetEntry->Flink;
			ctx->TargetEntry->Flink->Blink = ctx->TargetEntry->Blink;

			// Self-reference for stability
			ctx->TargetEntry->Flink = ctx->TargetEntry;
			ctx->TargetEntry->Blink = ctx->TargetEntry;
		}
		else // DKOM_RELINK
		{
			// Insert after InsertAfter: InsertAfter <-> [us] <-> next
			PLIST_ENTRY next = ctx->InsertAfter->Flink;
			ctx->TargetEntry->Flink = next;
			ctx->TargetEntry->Blink = ctx->InsertAfter;
			ctx->InsertAfter->Flink = ctx->TargetEntry;
			next->Blink = ctx->TargetEntry;
		}
	}

	// Signal this processor is done
	KeSignalCallDpcDone(SystemArgument1);
}

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

	WINDOWS_VERSION ver = GetWindowsVersion();
	ULONG aplOffset = (ver != WINDOWS_UNSUPPORTED) ? EPROCESS_ACTIVEPROCESSLINKS_OFFSET[ver] : 0;

	// Re-link all hidden processes back into ActiveProcessLinks before unloading
	while (g_ProcessHideListHead)
	{
		PHIDDEN_PROCESS_ENTRY current = g_ProcessHideListHead;
		ULONG pid = current->Pid;

		__try
		{
			if (current->ProcessListEntry && MmIsAddressValid(current->ProcessListEntry) && aplOffset != 0)
			{
				PEPROCESS currentProcess = PsGetCurrentProcess();
				PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)currentProcess + aplOffset);

				if (MmIsAddressValid(head) && MmIsAddressValid(head->Flink))
				{
					// Use DPC synchronization for safe re-link
					DKOM_DPC_CONTEXT dpcCtx = { 0 };
					dpcCtx.Operation = DKOM_RELINK;
					dpcCtx.TargetEntry = current->ProcessListEntry;
					dpcCtx.InsertAfter = head;
					dpcCtx.WorkDone = 0;
					KeGenericCallDpc(DkomDpcRoutine, &dpcCtx);

					KdPrint((DRIVER_PREFIX "ProcessHide cleanup: restored PID %lu\n", pid));
				}
				else
				{
					KdPrint((DRIVER_PREFIX "ProcessHide cleanup: list head invalid, skipping PID %lu\n", pid));
				}
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

	// Pre-allocate tracking entry (can't allocate pool at DISPATCH_LEVEL)
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

	__try
	{
		// Walk ActiveProcessLinks to find the target PID
		PEPROCESS currentProcess = PsGetCurrentProcess();
		PLIST_ENTRY listEntry = (PLIST_ENTRY)((PUCHAR)currentProcess + aplOffset);
		PLIST_ENTRY head = listEntry;
		ULONG safetyCounter = 0;
		const ULONG MAX_WALK = 65536;

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

				// Insert into tracking list BEFORE the DPC unlink
				hidden->Next = g_ProcessHideListHead;
				g_ProcessHideListHead = hidden;
				g_ProcessHideCount++;

				// Unlink via DPC synchronization (freezes all CPUs)
				DKOM_DPC_CONTEXT dpcCtx = { 0 };
				dpcCtx.Operation = DKOM_UNLINK;
				dpcCtx.TargetEntry = listEntry;
				dpcCtx.WorkDone = 0;
				KeGenericCallDpc(DkomDpcRoutine, &dpcCtx);

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

	WINDOWS_VERSION ver = GetWindowsVersion();
	if (ver == WINDOWS_UNSUPPORTED)
		return STATUS_NOT_SUPPORTED;

	ULONG aplOffset = EPROCESS_ACTIVEPROCESSLINKS_OFFSET[ver];

	NTSTATUS status = STATUS_NOT_FOUND;

	__try
	{
		PHIDDEN_PROCESS_ENTRY prev = NULL;
		PHIDDEN_PROCESS_ENTRY current = g_ProcessHideListHead;

		while (current)
		{
			if (current->Pid == Pid)
			{
				if (!current->ProcessListEntry || !MmIsAddressValid(current->ProcessListEntry))
				{
					KdPrint((DRIVER_PREFIX "ProcessHide: ProcessListEntry invalid for PID %lu\n", Pid));
					status = STATUS_INVALID_ADDRESS;
					break;
				}

				// Insert after current process's list head (always valid)
				PEPROCESS currentProcess = PsGetCurrentProcess();
				PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)currentProcess + aplOffset);

				if (!MmIsAddressValid(head) || !MmIsAddressValid(head->Flink))
				{
					KdPrint((DRIVER_PREFIX "ProcessHide: list head invalid, cannot unhide PID %lu\n", Pid));
					status = STATUS_INVALID_ADDRESS;
					break;
				}

				// Re-link via DPC synchronization (freezes all CPUs)
				DKOM_DPC_CONTEXT dpcCtx = { 0 };
				dpcCtx.Operation = DKOM_RELINK;
				dpcCtx.TargetEntry = current->ProcessListEntry;
				dpcCtx.InsertAfter = head;
				dpcCtx.WorkDone = 0;
				KeGenericCallDpc(DkomDpcRoutine, &dpcCtx);

				// Remove from tracking list
				if (prev)
					prev->Next = current->Next;
				else
					g_ProcessHideListHead = current->Next;

				g_ProcessHideCount--;

				KdPrint((DRIVER_PREFIX "ProcessHide: PID %lu (%s) restored via DPC sync\n", Pid, current->ImageFileName));

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
