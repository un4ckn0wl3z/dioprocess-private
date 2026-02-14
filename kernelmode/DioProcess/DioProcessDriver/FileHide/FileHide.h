#pragma once

#include <fltkernel.h>
#include <ntstrsafe.h>

// Pool tag for FileHide allocations
#define FILEHIDE_POOL_TAG 'dHiF'

// Maximum number of hidden file entries
#define MAX_HIDDEN_FILES 128

// Maximum path length (in WCHARs)
#define FILEHIDE_MAX_PATH 260

// ============== Structures ==============

// Hidden file entry (stored in doubly-linked list)
typedef struct _HIDDEN_FILE_ENTRY {
    LIST_ENTRY ListEntry;
    WCHAR FilePath[FILEHIDE_MAX_PATH];
} HIDDEN_FILE_ENTRY, *PHIDDEN_FILE_ENTRY;

// FILE_INFORMATION_DEFINITION and the per-class macros (e.g., FileFullDirectoryInformationDefinition)
// are provided by <ntifs.h> (included via <fltkernel.h>) on WDK 26100+.

// ============== Globals (defined in FileHide.cpp) ==============

extern PFLT_FILTER g_FileHideFilter;
extern ERESOURCE g_FileHideLock;
extern LIST_ENTRY g_FileHideListHead;
extern ULONG g_FileHideCount;
extern BOOLEAN g_FileHideInitialized;

// ============== Functions ==============

// Initialize the minifilter (register + start filtering)
NTSTATUS FileHide_Init(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

// Cleanup the minifilter (unregister + free list)
VOID FileHide_Cleanup();

// Add a file path to the hidden list (idempotent - returns success if already present)
NTSTATUS FileHide_AddPath(
    _In_ const WCHAR* FilePath
);

// Remove a file path from the hidden list
NTSTATUS FileHide_RemovePath(
    _In_ const WCHAR* FilePath
);

// List all hidden paths into the provided buffer
NTSTATUS FileHide_ListPaths(
    _Out_ WCHAR(*Entries)[FILEHIDE_MAX_PATH],
    _Out_ ULONG* Count,
    _In_ ULONG MaxEntries
);
