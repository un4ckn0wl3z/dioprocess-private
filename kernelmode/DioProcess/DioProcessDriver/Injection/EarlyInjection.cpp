#include "pch.h"
#include "EarlyInjection.h"
#include "../DioProcessGlobals.h"

// ============== Internal Structures ==============

// Undocumented structures for PEB access
typedef struct _PEB_LDR_DATA_INTERNAL {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_INTERNAL, *PPEB_LDR_DATA_INTERNAL;

typedef struct _LDR_DATA_TABLE_ENTRY_INTERNAL {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY_INTERNAL, *PLDR_DATA_TABLE_ENTRY_INTERNAL;

// System information structures for ZwQuerySystemInformation
typedef enum _SYSTEM_INFORMATION_CLASS_INTERNAL {
	SystemProcessInformationInternal = 5
} SYSTEM_INFORMATION_CLASS_INTERNAL;

typedef struct _SYSTEM_THREAD_INFORMATION_INTERNAL {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION_INTERNAL, *PSYSTEM_THREAD_INFORMATION_INTERNAL;

typedef struct _SYSTEM_PROCESS_INFORMATION_INTERNAL {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION_INTERNAL Threads[1];
} SYSTEM_PROCESS_INFORMATION_INTERNAL, *PSYSTEM_PROCESS_INFORMATION_INTERNAL;

// ZwQuerySystemInformation declaration
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS_INTERNAL SystemInformationClass,
	_Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

// ZwProtectVirtualMemory declaration
extern "C" NTSTATUS NTAPI ZwProtectVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtect,
	_Out_ PULONG OldProtect
);

// APC types and functions
typedef VOID (NTAPI *PKNORMAL_ROUTINE)(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
);

typedef VOID (NTAPI *PKKERNEL_ROUTINE)(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
);

typedef VOID (NTAPI *PKRUNDOWN_ROUTINE)(
	_In_ PKAPC Apc
);

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

extern "C" VOID NTAPI KeInitializeApc(
	_Out_ PKAPC Apc,
	_In_ PKTHREAD Thread,
	_In_ KAPC_ENVIRONMENT Environment,
	_In_ PKKERNEL_ROUTINE KernelRoutine,
	_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
	_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
	_In_ KPROCESSOR_MODE ApcMode,
	_In_opt_ PVOID NormalContext
);

extern "C" BOOLEAN NTAPI KeInsertQueueApc(
	_Inout_ PKAPC Apc,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2,
	_In_ KPRIORITY Increment
);

// Global early injection state
EarlyInjectionState g_EarlyInjectionState = { 0 };

// ============== Initialization ==============

VOID EarlyInjectionInit()
{
	RtlZeroMemory(&g_EarlyInjectionState, sizeof(g_EarlyInjectionState));
	ExInitializeFastMutex(&g_EarlyInjectionState.Lock);
	KdPrint((DRIVER_PREFIX "Early injection subsystem initialized\n"));
}

// ============== Arm/Disarm Functions ==============

NTSTATUS EarlyInjectionArm(
	_In_ PCWSTR TargetProcessName,
	_In_ PCWSTR DllPath,
	_In_ EarlyInjectionMethod Method,
	_In_ BOOLEAN OneShot
)
{
	if (!TargetProcessName || !DllPath)
	{
		return STATUS_INVALID_PARAMETER;
	}

	ExAcquireFastMutex(&g_EarlyInjectionState.Lock);

	if (g_EarlyInjectionState.Armed)
	{
		ExReleaseFastMutex(&g_EarlyInjectionState.Lock);
		KdPrint((DRIVER_PREFIX "Early injection already armed\n"));
		return STATUS_DEVICE_BUSY;
	}

	// Copy target process name
	RtlZeroMemory(g_EarlyInjectionState.TargetProcessName, sizeof(g_EarlyInjectionState.TargetProcessName));
	wcsncpy(g_EarlyInjectionState.TargetProcessName, TargetProcessName, MAX_TARGET_PROCESS_NAME - 1);

	// Copy DLL path
	RtlZeroMemory(g_EarlyInjectionState.DllPath, sizeof(g_EarlyInjectionState.DllPath));
	wcsncpy(g_EarlyInjectionState.DllPath, DllPath, MAX_DLL_PATH_LENGTH - 1);

	g_EarlyInjectionState.Method = Method;
	g_EarlyInjectionState.OneShot = OneShot;
	g_EarlyInjectionState.InjectionCount = 0;
	g_EarlyInjectionState.LastInjectedPid = 0;
	g_EarlyInjectionState.LastStatus = STATUS_SUCCESS;
	g_EarlyInjectionState.Armed = TRUE;

	ExReleaseFastMutex(&g_EarlyInjectionState.Lock);

	KdPrint((DRIVER_PREFIX "Early injection armed: Target=%ws, DLL=%ws, Method=%d, OneShot=%d\n",
		TargetProcessName, DllPath, Method, OneShot));

	return STATUS_SUCCESS;
}

NTSTATUS EarlyInjectionDisarm()
{
	ExAcquireFastMutex(&g_EarlyInjectionState.Lock);

	BOOLEAN wasArmed = g_EarlyInjectionState.Armed;
	g_EarlyInjectionState.Armed = FALSE;

	ExReleaseFastMutex(&g_EarlyInjectionState.Lock);

	if (wasArmed)
	{
		KdPrint((DRIVER_PREFIX "Early injection disarmed\n"));
	}
	else
	{
		KdPrint((DRIVER_PREFIX "Early injection already disarmed\n"));
	}

	// Always return success - disarming an already-disarmed state is fine
	return STATUS_SUCCESS;
}

VOID EarlyInjectionGetStatus(_Out_ EarlyInjectionStatusResponse* Status)
{
	ExAcquireFastMutex(&g_EarlyInjectionState.Lock);

	Status->Armed = g_EarlyInjectionState.Armed;
	RtlCopyMemory(Status->TargetProcessName, g_EarlyInjectionState.TargetProcessName, sizeof(Status->TargetProcessName));
	RtlCopyMemory(Status->DllPath, g_EarlyInjectionState.DllPath, sizeof(Status->DllPath));
	Status->Method = g_EarlyInjectionState.Method;
	Status->InjectionCount = g_EarlyInjectionState.InjectionCount;
	Status->LastInjectedPid = g_EarlyInjectionState.LastInjectedPid;
	Status->LastStatus = g_EarlyInjectionState.LastStatus;
	Status->OneShot = g_EarlyInjectionState.OneShot;

	ExReleaseFastMutex(&g_EarlyInjectionState.Lock);
}

// ============== Target Matching ==============

BOOLEAN EarlyInjectionMatchesTarget(_In_ PUNICODE_STRING ProcessName)
{
	if (!ProcessName || !ProcessName->Buffer)
	{
		return FALSE;
	}

	ExAcquireFastMutex(&g_EarlyInjectionState.Lock);

	if (!g_EarlyInjectionState.Armed)
	{
		ExReleaseFastMutex(&g_EarlyInjectionState.Lock);
		return FALSE;
	}

	// Convert target to UNICODE_STRING for comparison
	UNICODE_STRING targetName;
	RtlInitUnicodeString(&targetName, g_EarlyInjectionState.TargetProcessName);

	// Check if process name ends with target (case-insensitive)
	BOOLEAN matches = FALSE;

	if (ProcessName->Length >= targetName.Length)
	{
		// Get the suffix of the process name
		UNICODE_STRING suffix;
		suffix.Buffer = (PWCH)((PUCHAR)ProcessName->Buffer + ProcessName->Length - targetName.Length);
		suffix.Length = targetName.Length;
		suffix.MaximumLength = targetName.Length;

		// Compare case-insensitively
		matches = RtlEqualUnicodeString(&suffix, &targetName, TRUE);
	}

	ExReleaseFastMutex(&g_EarlyInjectionState.Lock);
	return matches;
}

// ============== Helper Functions ==============

PVOID GetProcAddressFromModule(
	_In_ PVOID ModuleBase,
	_In_ PCSTR FunctionName
)
{
	if (!ModuleBase || !FunctionName)
	{
		return NULL;
	}

	__try
	{
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return NULL;
		}

		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			return NULL;
		}

		// Get export directory
		ULONG exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (exportDirRva == 0)
		{
			return NULL;
		}

		PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + exportDirRva);

		PULONG nameRvas = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfNames);
		PUSHORT ordinals = (PUSHORT)((PUCHAR)ModuleBase + exportDir->AddressOfNameOrdinals);
		PULONG funcRvas = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfFunctions);

		for (ULONG i = 0; i < exportDir->NumberOfNames; i++)
		{
			PCSTR name = (PCSTR)((PUCHAR)ModuleBase + nameRvas[i]);
			if (strcmp(name, FunctionName) == 0)
			{
				USHORT ordinal = ordinals[i];
				ULONG funcRva = funcRvas[ordinal];
				return (PUCHAR)ModuleBase + funcRva;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception in GetProcAddressFromModule\n"));
	}

	return NULL;
}

PETHREAD FindMainThread(_In_ HANDLE ProcessId)
{
	PETHREAD mainThread = NULL;
	PVOID buffer = NULL;
	ULONG bufferSize = 0x10000;
	NTSTATUS status;

	// Query system process information
	buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, DRIVER_TAG);
	if (!buffer)
	{
		return NULL;
	}

	status = ZwQuerySystemInformation(SystemProcessInformationInternal, buffer, bufferSize, NULL);
	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		ExFreePoolWithTag(buffer, DRIVER_TAG);
		bufferSize *= 2;
		buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, DRIVER_TAG);
		if (!buffer)
		{
			return NULL;
		}
		status = ZwQuerySystemInformation(SystemProcessInformationInternal, buffer, bufferSize, NULL);
	}

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(buffer, DRIVER_TAG);
		return NULL;
	}

	__try
	{
		PSYSTEM_PROCESS_INFORMATION_INTERNAL processInfo = (PSYSTEM_PROCESS_INFORMATION_INTERNAL)buffer;

		while (TRUE)
		{
			if (processInfo->UniqueProcessId == ProcessId)
			{
				// Found the process, get the first thread
				if (processInfo->NumberOfThreads > 0)
				{
					// Threads array is at the end of SYSTEM_PROCESS_INFORMATION_INTERNAL
					PSYSTEM_THREAD_INFORMATION_INTERNAL threadInfo = &processInfo->Threads[0];

					// Get thread object from TID
					status = PsLookupThreadByThreadId(threadInfo->ClientId.UniqueThread, &mainThread);
					if (!NT_SUCCESS(status))
					{
						mainThread = NULL;
					}
				}
				break;
			}

			if (processInfo->NextEntryOffset == 0)
			{
				break;
			}

			processInfo = (PSYSTEM_PROCESS_INFORMATION_INTERNAL)((PUCHAR)processInfo + processInfo->NextEntryOffset);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		mainThread = NULL;
	}

	ExFreePoolWithTag(buffer, DRIVER_TAG);
	return mainThread;
}

// ============== APC Injection ==============
// NOTE: Trampoline injection method was removed due to stability issues.
// Only APC injection is supported.

// Kernel APC routine - runs in kernel context when APC is delivered
// This is needed to free the APC object after the user-mode routine runs
VOID ApcKernelRoutine(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	// Free the APC object
	ExFreePoolWithTag(Apc, DRIVER_TAG);
}

BOOLEAN EarlyInjectApc_Execute(
	_In_ HANDLE ProcessId,
	_In_ PVOID Kernel32Base
)
{
	NTSTATUS status;
	BOOLEAN result = FALSE;

	KdPrint((DRIVER_PREFIX "APC injection for PID %u\n", HandleToULong(ProcessId)));

	// Get process object
	PEPROCESS process = NULL;
	status = PsLookupProcessByProcessId(ProcessId, &process);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "Failed to lookup process: 0x%X\n", status));
		return FALSE;
	}

	// Find main thread
	PETHREAD mainThread = FindMainThread(ProcessId);
	if (!mainThread)
	{
		KdPrint((DRIVER_PREFIX "Failed to find main thread\n"));
		ObDereferenceObject(process);
		return FALSE;
	}

	KAPC_STATE apcState;
	KeStackAttachProcess(process, &apcState);

	__try
	{
		// Get LoadLibraryW from kernel32.dll (which just loaded)
		PVOID pLoadLibraryW = GetProcAddressFromModule(Kernel32Base, "LoadLibraryW");
		if (!pLoadLibraryW)
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve LoadLibraryW\n"));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(mainThread);
			ObDereferenceObject(process);
			return FALSE;
		}
		KdPrint((DRIVER_PREFIX "LoadLibraryW at 0x%p\n", pLoadLibraryW));

		// Allocate memory for DLL path string in target process
		SIZE_T pathSize = MAX_DLL_PATH_LENGTH * sizeof(WCHAR);
		PVOID pathAddr = NULL;

		status = ZwAllocateVirtualMemory(
			ZwCurrentProcess(),
			&pathAddr,
			0,
			&pathSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to allocate DLL path: 0x%X\n", status));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(mainThread);
			ObDereferenceObject(process);
			return FALSE;
		}
		KdPrint((DRIVER_PREFIX "DLL path allocated at 0x%p\n", pathAddr));

		// Copy DLL path to target process
		ExAcquireFastMutex(&g_EarlyInjectionState.Lock);
		RtlCopyMemory(pathAddr, g_EarlyInjectionState.DllPath, MAX_DLL_PATH_LENGTH * sizeof(WCHAR));
		ExReleaseFastMutex(&g_EarlyInjectionState.Lock);

		KeUnstackDetachProcess(&apcState);

		// Allocate and initialize kernel APC
		PKAPC apc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), DRIVER_TAG);
		if (!apc)
		{
			KdPrint((DRIVER_PREFIX "Failed to allocate APC\n"));
			ObDereferenceObject(mainThread);
			ObDereferenceObject(process);
			return FALSE;
		}

		// Use LoadLibraryW directly as the APC normal routine
		// APC signature: void (PVOID NormalContext, PVOID Arg1, PVOID Arg2)
		// LoadLibraryW signature: HMODULE (LPCWSTR lpLibFileName)
		// First param (DLL path) matches, extra params ignored
		KeInitializeApc(
			apc,
			mainThread,
			OriginalApcEnvironment,
			ApcKernelRoutine,
			NULL,                          // Rundown routine
			(PKNORMAL_ROUTINE)pLoadLibraryW,  // LoadLibraryW as normal routine
			UserMode,
			pathAddr                       // DLL path as NormalContext
		);

		// Queue the APC
		if (!KeInsertQueueApc(apc, NULL, NULL, 0))
		{
			KdPrint((DRIVER_PREFIX "Failed to insert APC\n"));
			ExFreePoolWithTag(apc, DRIVER_TAG);
		}
		else
		{
			KdPrint((DRIVER_PREFIX "APC queued successfully with LoadLibraryW at 0x%p, path at 0x%p\n",
				pLoadLibraryW, pathAddr));
			result = TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception during APC injection\n"));
	}

	ObDereferenceObject(mainThread);
	ObDereferenceObject(process);
	return result;
}
