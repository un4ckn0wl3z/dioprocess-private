#pragma once

#include <ntifs.h>

// ============== Usermode EPT Hook Management ==============
// Allows installing EPT split-page hooks on usermode process pages.
// Read/write access sees the original page (passes integrity checks).
// Execute access routes to the patched page (custom behavior).

#define MAX_USERMODE_EPT_HOOKS 32
#define USERMODE_EPT_HOOK_TAG 'ephU'
#define MAX_EPT_HOOK_DETOUR_SIZE 3800

struct UsermodeEptHookEntry
{
	ULONG ProcessId;
	ULONG64 TargetVirtualAddress;	// VA in target process (page-aligned for EPT)
	ULONG64 OriginalPagePfn;		// PFN of original page (read/write page)
	PVOID ExecPage;					// Allocated exec page (to free on cleanup)
	ULONG PatchOffset;				// Offset within page where patch was applied
	ULONG PatchSize;				// Size of patch bytes
	BOOLEAN Active;
};

// Install an EPT hook on a usermode page in a target process
// PatchBytes are written at TargetVirtualAddress on the execute-only copy
// Reads/writes still see the original bytes
NTSTATUS UsermodeEptHook_Install(
	ULONG ProcessId,
	ULONG64 TargetVirtualAddress,
	PVOID PatchBytes,
	ULONG PatchSize,
	PULONG OutHookIndex
);

// Install an EPT hook with a detour (JMP at hook point -> code cave on same page)
// StolenBytes must be >= 5; DetourCode is written at DetourPageOffset on the exec page
NTSTATUS UsermodeEptHook_InstallDetour(
	ULONG ProcessId,
	ULONG64 TargetVirtualAddress,
	ULONG StolenBytes,
	ULONG DetourPageOffset,
	PVOID DetourCode,
	ULONG DetourCodeSize,
	PULONG OutHookIndex
);

// Remove a single EPT hook by index
NTSTATUS UsermodeEptHook_Remove(ULONG HookIndex);

// Remove all usermode EPT hooks (called during driver unload)
NTSTATUS UsermodeEptHook_RemoveAll();

// Get the list of active hooks (entries copied sequentially, OutSlotIndices contains the slot index for each)
NTSTATUS UsermodeEptHook_GetList(
	struct UsermodeEptHookEntry* OutEntries,
	ULONG* OutSlotIndices,
	ULONG* Count,
	ULONG MaxEntries
);
