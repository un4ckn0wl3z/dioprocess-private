#pragma once

#include "../pch.h"
#include "../DioProcessDriver.h"

// ============== Early Injection State ==============

struct EarlyInjectionState
{
	BOOLEAN Armed;
	WCHAR TargetProcessName[MAX_TARGET_PROCESS_NAME];
	WCHAR DllPath[MAX_DLL_PATH_LENGTH];
	EarlyInjectionMethod Method;
	BOOLEAN OneShot;
	ULONG InjectionCount;
	ULONG LastInjectedPid;
	NTSTATUS LastStatus;
	FAST_MUTEX Lock;
};

// Global early injection state
extern EarlyInjectionState g_EarlyInjectionState;

// ============== Early Injection Functions ==============

// Initialize early injection subsystem
VOID EarlyInjectionInit();

// Arm early injection with given parameters
NTSTATUS EarlyInjectionArm(
	_In_ PCWSTR TargetProcessName,
	_In_ PCWSTR DllPath,
	_In_ EarlyInjectionMethod Method,
	_In_ BOOLEAN OneShot
);

// Disarm early injection
NTSTATUS EarlyInjectionDisarm();

// Get current status
VOID EarlyInjectionGetStatus(_Out_ EarlyInjectionStatusResponse* Status);

// Check if process name matches target
BOOLEAN EarlyInjectionMatchesTarget(_In_ PUNICODE_STRING ProcessName);

// ============== Injection Technique Functions ==============
// NOTE: Trampoline method removed due to stability issues. Only APC is supported.

// APC injection: queues APC when kernel32.dll loads
// Called from image load callback with kernel32.dll base address
BOOLEAN EarlyInjectApc_Execute(
	_In_ HANDLE ProcessId,
	_In_ PVOID Kernel32Base
);

// ============== Helper Functions ==============

// Get export address from a module
PVOID GetProcAddressFromModule(
	_In_ PVOID ModuleBase,
	_In_ PCSTR FunctionName
);

// Find main thread of a process
PETHREAD FindMainThread(_In_ HANDLE ProcessId);
