#pragma once

#include "../pch.h"
#include "../DioProcessDriver.h"

// ============== DKOM Process Hiding ==============
// Hides processes from enumeration by unlinking from EPROCESS.ActiveProcessLinks
// WARNING: Requires KPP/PatchGuard disabled - modifies kernel linked list

#define DKOM_POOL_TAG 'DKPH'
#define MAX_HIDDEN_PROCESSES 64

// Internal tracking structure for hidden processes
typedef struct _HIDDEN_PROCESS_ENTRY {
	ULONG Pid;
	PLIST_ENTRY ProcessListEntry;
	PLIST_ENTRY OriginalFlink;
	PLIST_ENTRY OriginalBlink;
	CHAR ImageFileName[16];
	struct _HIDDEN_PROCESS_ENTRY* Next;
} HIDDEN_PROCESS_ENTRY, *PHIDDEN_PROCESS_ENTRY;

// Globals
extern PHIDDEN_PROCESS_ENTRY g_ProcessHideListHead;
extern ULONG g_ProcessHideCount;
extern BOOLEAN g_ProcessHideInitialized;

// ActiveProcessLinks offset in EPROCESS (indexed by WINDOWS_VERSION)
const ULONG EPROCESS_ACTIVEPROCESSLINKS_OFFSET[] =
{
	0x00,   // WINDOWS_UNSUPPORTED
	0x2e8,  // WINDOWS_10_1507  (10240)
	0x2e8,  // WINDOWS_10_1511  (10586)
	0x2f0,  // WINDOWS_10_1607  (14393)
	0x2e8,  // WINDOWS_10_1703  (15063)
	0x2e8,  // WINDOWS_10_1709  (16299)
	0x2e8,  // WINDOWS_10_1803  (17134)
	0x2e8,  // WINDOWS_10_1809  (17763)
	0x2f0,  // WINDOWS_10_1903  (18362)
	0x2f0,  // WINDOWS_10_1909  (18363)
	0x448,  // WINDOWS_10_2004  (19041)
	0x448,  // WINDOWS_10_20H2  (19042)
	0x448,  // WINDOWS_10_21H1  (19043)
	0x448,  // WINDOWS_10_21H2  (19044)
	0x448,  // WINDOWS_10_22H2  (19045)
	0x448,  // WINDOWS_11_21H2  (22000)
	0x448,  // WINDOWS_11_22H2  (22621)
	0x448,  // WINDOWS_11_23H2  (22631)
	0x448   // WINDOWS_11_24H2  (26100)
};

// UniqueProcessId offset in EPROCESS (indexed by WINDOWS_VERSION)
const ULONG EPROCESS_UNIQUEPROCESSID_OFFSET[] =
{
	0x00,   // WINDOWS_UNSUPPORTED
	0x2e0,  // WINDOWS_10_1507  (10240)
	0x2e0,  // WINDOWS_10_1511  (10586)
	0x2e8,  // WINDOWS_10_1607  (14393)
	0x2e0,  // WINDOWS_10_1703  (15063)
	0x2e0,  // WINDOWS_10_1709  (16299)
	0x2e0,  // WINDOWS_10_1803  (17134)
	0x2e0,  // WINDOWS_10_1809  (17763)
	0x2e8,  // WINDOWS_10_1903  (18362)
	0x2e8,  // WINDOWS_10_1909  (18363)
	0x440,  // WINDOWS_10_2004  (19041)
	0x440,  // WINDOWS_10_20H2  (19042)
	0x440,  // WINDOWS_10_21H1  (19043)
	0x440,  // WINDOWS_10_21H2  (19044)
	0x440,  // WINDOWS_10_22H2  (19045)
	0x440,  // WINDOWS_11_21H2  (22000)
	0x440,  // WINDOWS_11_22H2  (22621)
	0x440,  // WINDOWS_11_23H2  (22631)
	0x440   // WINDOWS_11_24H2  (26100)
};

// Functions
VOID ProcessHide_Init();
VOID ProcessHide_Cleanup();
NTSTATUS ProcessHide_Hide(ULONG Pid);
NTSTATUS ProcessHide_Unhide(ULONG Pid);
NTSTATUS ProcessHide_List(HiddenProcessEntry* Entries, ULONG* Count, ULONG MaxEntries);
