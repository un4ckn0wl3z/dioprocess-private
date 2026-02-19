#pragma once

#include <ntifs.h>

// ============== EPT Register Change Management ==============
// Modify guest registers when execution reaches a specific RIP.
// Uses EPT execute-deny + MTF single-stepping (no code patching).

#define MAX_REG_CHANGE_ENTRIES 32
#define REG_CHANGE_TAG 'rgcH'

struct RegChangeTrackingEntry
{
	ULONG ProcessId;
	ULONG64 TargetVirtualAddress;
	ULONG64 ProcessCr3;
	ULONG64 PagePfn;
	ULONG RegIndex;          // 0=RAX..15=R15, 16=RFLAGS
	ULONG64 NewValue;
	BOOLEAN Active;
};

// Install a register change hook
NTSTATUS RegisterChange_Install(
	ULONG ProcessId,
	ULONG64 TargetVirtualAddress,
	ULONG RegIndex,
	ULONG64 NewValue,
	PULONG OutEntryIndex
);

// Remove a register change hook by index
NTSTATUS RegisterChange_Remove(ULONG EntryIndex);

// Remove all register change hooks
NTSTATUS RegisterChange_RemoveAll();

// Get the list of active register change entries
NTSTATUS RegisterChange_GetList(
	struct RegChangeTrackingEntry* OutEntries,
	ULONG* OutSlotIndices,
	ULONG* Count,
	ULONG MaxEntries
);
