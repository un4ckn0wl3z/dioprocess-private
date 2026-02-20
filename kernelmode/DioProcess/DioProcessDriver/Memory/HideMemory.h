#pragma once

#include "../DioProcessDriver.h"

// ============== MM Protection Constants ==============
// These match the kernel's internal MM_PROTECT_* values used in _MMPTE.Protection

#define MM_ZERO_ACCESS         0
#define MM_READONLY            1
#define MM_EXECUTE             2
#define MM_EXECUTE_READ        3
#define MM_READWRITE           4
#define MM_WRITECOPY           5
#define MM_EXECUTE_READWRITE   6
#define MM_EXECUTE_WRITECOPY   7
#define MM_NOCACHE            0x8
#define MM_GUARD_PAGE         0x10
#define MM_DECOMMIT           0x10
#define MM_NOACCESS           0x18

// ============== PFN Database Structures ==============

struct _MMPTE
{
	ULONGLONG Valid : 1;
	ULONGLONG PageFileReserved : 1;
	ULONGLONG PageFileAllocated : 1;
	ULONGLONG ColdPage : 1;
	ULONGLONG SwizzleBit : 1;
	ULONGLONG Protection : 5;
	ULONGLONG Prototype : 1;
	ULONGLONG Transition : 1;
	ULONGLONG PageFileLow : 4;
	ULONGLONG UsedPageTableEntries : 10;
	ULONGLONG ShadowStack : 1;
	ULONGLONG Unused : 5;
	ULONGLONG PageFileHigh : 32;
};

struct _MMPFN
{
	void* padding1;
	void* pte_address;
	struct _MMPTE OriginalPte;     // 0x10
	char padding2[0x18];
};

// ============== Functions ==============

/// Modify the OriginalPte.Protection field of a memory page in the PFN database.
/// This changes how the page's protection appears to the OS memory manager
/// without modifying the live PTE — useful for hiding memory protection attributes.
///
/// @param ProcessId   Target process PID
/// @param VirtualAddress  Virtual address of the page to modify
/// @param Protection  New MM protection value (MM_READONLY, MM_READWRITE, etc.)
/// @return NTSTATUS
NTSTATUS HideMemorySetProtection(ULONG ProcessId, ULONG64 VirtualAddress, ULONG Protection);
