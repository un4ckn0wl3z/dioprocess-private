#pragma once

#include "../pch.h"
#include "../DioProcessGlobals.h"

// ============== Manual Map Injection ==============
// Kernel-mode manual mapping: maps DLL directly into target process memory
// without using LoadLibrary, avoiding detection by API hooks.
//
// Features:
// - Maps PE sections with correct permissions
// - Processes base relocations
// - Resolves imports from target process modules
// - Calls DllMain with DLL_PROCESS_ATTACH

// ============== Manual Map Structures ==============

// DllMain function prototype (kernel-mode compatible)
// Uses NTAPI calling convention instead of WINAPI for kernel compatibility
typedef BOOLEAN(NTAPI* DllMain_t)(PVOID hinstDLL, ULONG fdwReason, PVOID lpvReserved);

// Manual map flags
#define MANUAL_MAP_FLAG_NONE            0x00000000
#define MANUAL_MAP_FLAG_ERASE_HEADERS   0x00000001  // Erase PE headers after mapping
#define MANUAL_MAP_FLAG_NO_ENTRY_POINT  0x00000002  // Don't call DllMain
#define MANUAL_MAP_FLAG_NO_IMPORTS      0x00000004  // Don't resolve imports (for shellcode-like DLLs)

// Manual map result structure
struct ManualMapResult
{
	PVOID MappedBase;           // Base address where DLL was mapped
	SIZE_T MappedSize;          // Total size of mapped image
	PVOID EntryPoint;           // DllMain address (if called)
	BOOLEAN Success;            // Overall success
	NTSTATUS Status;            // Detailed status code
};

// ============== Manual Map Functions ==============

// Main manual map function - maps DLL from file bytes into target process
// DllBuffer: Raw DLL file bytes (read from disk)
// DllSize: Size of DLL buffer
// ProcessId: Target process PID
// Flags: MANUAL_MAP_FLAG_* options
// Result: Output result structure
NTSTATUS KernelManualMapDll(
	_In_ PVOID DllBuffer,
	_In_ SIZE_T DllSize,
	_In_ ULONG ProcessId,
	_In_ ULONG Flags,
	_Out_ ManualMapResult* Result
);

// ============== Internal Helper Functions ==============

// Validate PE headers
BOOLEAN MmValidatePeHeaders(
	_In_ PVOID DllBuffer,
	_In_ SIZE_T DllSize,
	_Out_ PIMAGE_NT_HEADERS* NtHeaders
);

// Map PE sections into target process
NTSTATUS MmMapSections(
	_In_ PEPROCESS Process,
	_In_ PVOID DllBuffer,
	_In_ PIMAGE_NT_HEADERS NtHeaders,
	_In_ PVOID MappedBase,
	_In_ SIZE_T MappedSize
);

// Process base relocations
NTSTATUS MmProcessRelocations(
	_In_ PEPROCESS Process,
	_In_ PVOID MappedBase,
	_In_ PIMAGE_NT_HEADERS NtHeaders,
	_In_ ULONG_PTR DeltaBase
);

// Resolve imports from target process modules
NTSTATUS MmResolveImports(
	_In_ PEPROCESS Process,
	_In_ PVOID MappedBase,
	_In_ PIMAGE_NT_HEADERS NtHeaders,
	_In_ WINDOWS_VERSION WindowsVersion
);

// Call DllMain entry point via shellcode
NTSTATUS MmCallEntryPoint(
	_In_ PEPROCESS Process,
	_In_ PVOID MappedBase,
	_In_ PVOID EntryPoint
);

// Erase PE headers from mapped image
NTSTATUS MmEraseHeaders(
	_In_ PEPROCESS Process,
	_In_ PVOID MappedBase,
	_In_ SIZE_T HeaderSize
);

