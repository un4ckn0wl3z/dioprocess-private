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

PVOID GetNtdllBaseAddress(_In_ PEPROCESS Process)
{
	KAPC_STATE apcState;
	PVOID ntdllBase = NULL;
	PPEB peb = NULL;
	WINDOWS_VERSION version = GetWindowsVersion();

	if (version == WINDOWS_UNSUPPORTED)
	{
		return NULL;
	}

	// Get PEB from EPROCESS
	peb = *(PPEB*)((ULONG_PTR)Process + PROCESS_PEB_OFFSET[version]);
	if (!peb || (ULONG_PTR)peb < 0x1000)
	{
		return NULL;
	}

	KeStackAttachProcess(Process, &apcState);

	__try
	{
		// PEB.Ldr at offset 0x18 (x64)
		PPEB_LDR_DATA_INTERNAL ldr = *(PPEB_LDR_DATA_INTERNAL*)((ULONG_PTR)peb + 0x18);
		if (!ldr || !MmIsAddressValid(ldr))
		{
			KeUnstackDetachProcess(&apcState);
			return NULL;
		}

		// Walk InLoadOrderModuleList to find ntdll.dll
		PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
		PLIST_ENTRY entry = head->Flink;

		while (entry != head && MmIsAddressValid(entry))
		{
			PLDR_DATA_TABLE_ENTRY_INTERNAL module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_INTERNAL, InLoadOrderLinks);

			if (MmIsAddressValid(module) && module->BaseDllName.Buffer && MmIsAddressValid(module->BaseDllName.Buffer))
			{
				UNICODE_STRING ntdllName;
				RtlInitUnicodeString(&ntdllName, L"ntdll.dll");

				if (RtlEqualUnicodeString(&module->BaseDllName, &ntdllName, TRUE))
				{
					ntdllBase = module->DllBase;
					break;
				}
			}

			entry = entry->Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception while finding ntdll.dll base\n"));
	}

	KeUnstackDetachProcess(&apcState);
	return ntdllBase;
}

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

// ============== Trampoline Injection ==============

// Position-independent shellcode for LdrLoadDll hook
// This shellcode:
// 1. Saves registers
// 2. Restores original LdrLoadDll bytes
// 3. Calls original LdrLoadDll
// 4. Loads our DLL
// 5. Restores registers and returns

// Hook context structure (placed in allocated memory)
typedef struct _HOOK_CONTEXT
{
	UCHAR OriginalBytes[12];              // Original bytes from LdrLoadDll
	PVOID LdrLoadDllAddr;                 // Address of LdrLoadDll
	PVOID RtlInitUnicodeStringAddr;       // Address of RtlInitUnicodeString
	PVOID NtProtectVirtualMemoryAddr;     // Address of NtProtectVirtualMemory
	WCHAR DllPath[MAX_DLL_PATH_LENGTH];   // DLL path to load
	UCHAR Shellcode[256];                 // Actual shellcode
} HOOK_CONTEXT, *PHOOK_CONTEXT;

// 12-byte trampoline: MOV RAX, addr; JMP RAX
static UCHAR TrampolineBytes[] = {
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // MOV RAX, imm64
	0xFF, 0xE0                                                    // JMP RAX
};

BOOLEAN EarlyInjectTrampoline_Execute(
	_In_ PEPROCESS Process,
	_In_ HANDLE ProcessId
)
{
	KAPC_STATE apcState;
	NTSTATUS status = STATUS_SUCCESS;
	BOOLEAN result = FALSE;

	KdPrint((DRIVER_PREFIX "Trampoline injection for PID %u\n", HandleToULong(ProcessId)));

	// NOTE: At process creation time (PsSetCreateProcessNotifyRoutineEx), the PEB.Ldr
	// is not yet populated because ntdll.dll's initialization hasn't run.
	// The Trampoline method requires finding ntdll via memory scanning instead of PEB.
	// For now, this method may fail - use APC method (Method=1) instead for reliable injection.

	// Get ntdll base
	PVOID ntdllBase = GetNtdllBaseAddress(Process);
	if (!ntdllBase)
	{
		KdPrint((DRIVER_PREFIX "Failed to find ntdll.dll base - PEB.Ldr not initialized yet at process creation. Use APC method instead.\n"));
		return FALSE;
	}

	KeStackAttachProcess(Process, &apcState);

	__try
	{
		// Resolve required functions
		PVOID pLdrLoadDll = GetProcAddressFromModule(ntdllBase, "LdrLoadDll");
		PVOID pRtlInitUnicodeString = GetProcAddressFromModule(ntdllBase, "RtlInitUnicodeString");
		PVOID pNtProtectVirtualMemory = GetProcAddressFromModule(ntdllBase, "NtProtectVirtualMemory");

		if (!pLdrLoadDll || !pRtlInitUnicodeString || !pNtProtectVirtualMemory)
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve ntdll functions: LdrLoadDll=%p, RtlInit=%p, NtProtect=%p\n",
				pLdrLoadDll, pRtlInitUnicodeString, pNtProtectVirtualMemory));
			KeUnstackDetachProcess(&apcState);
			return FALSE;
		}

		KdPrint((DRIVER_PREFIX "Resolved functions: LdrLoadDll=%p, RtlInit=%p, NtProtect=%p\n",
			pLdrLoadDll, pRtlInitUnicodeString, pNtProtectVirtualMemory));

		// Allocate memory for hook context
		SIZE_T contextSize = sizeof(HOOK_CONTEXT);
		PVOID contextAddr = NULL;

		status = ZwAllocateVirtualMemory(
			ZwCurrentProcess(),
			&contextAddr,
			0,
			&contextSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to allocate hook context: 0x%X\n", status));
			KeUnstackDetachProcess(&apcState);
			return FALSE;
		}

		KdPrint((DRIVER_PREFIX "Allocated hook context at %p\n", contextAddr));

		// Initialize hook context
		PHOOK_CONTEXT context = (PHOOK_CONTEXT)contextAddr;
		RtlZeroMemory(context, sizeof(HOOK_CONTEXT));

		// Save original bytes
		RtlCopyMemory(context->OriginalBytes, pLdrLoadDll, 12);

		// Store function pointers
		context->LdrLoadDllAddr = pLdrLoadDll;
		context->RtlInitUnicodeStringAddr = pRtlInitUnicodeString;
		context->NtProtectVirtualMemoryAddr = pNtProtectVirtualMemory;

		// Copy DLL path
		ExAcquireFastMutex(&g_EarlyInjectionState.Lock);
		RtlCopyMemory(context->DllPath, g_EarlyInjectionState.DllPath, sizeof(context->DllPath));
		ExReleaseFastMutex(&g_EarlyInjectionState.Lock);

		// Build the shellcode
		// The shellcode will:
		// 1. Save all registers
		// 2. Make LdrLoadDll writable via NtProtectVirtualMemory
		// 3. Restore original bytes
		// 4. Call original LdrLoadDll with passed arguments
		// 5. Save return value
		// 6. Initialize UNICODE_STRING for our DLL
		// 7. Call LdrLoadDll for our DLL
		// 8. Restore registers
		// 9. Return original result

		// Simplified shellcode - we'll use a wrapper that:
		// - Restores original bytes first
		// - Loads our DLL
		// - Jumps back to original function

		UCHAR shellcode[] = {
			// Save registers
			0x41, 0x57,                                     // push r15
			0x41, 0x56,                                     // push r14
			0x41, 0x55,                                     // push r13
			0x41, 0x54,                                     // push r12
			0x55,                                           // push rbp
			0x57,                                           // push rdi
			0x56,                                           // push rsi
			0x53,                                           // push rbx
			0x48, 0x83, 0xEC, 0x68,                         // sub rsp, 0x68 (shadow space + locals)

			// Save original arguments for later call
			0x48, 0x89, 0x4C, 0x24, 0x30,                   // mov [rsp+0x30], rcx (PathToFile)
			0x48, 0x89, 0x54, 0x24, 0x38,                   // mov [rsp+0x38], rdx (Flags)
			0x4C, 0x89, 0x44, 0x24, 0x40,                   // mov [rsp+0x40], r8 (ModuleFileName)
			0x4C, 0x89, 0x4C, 0x24, 0x48,                   // mov [rsp+0x48], r9 (ModuleHandle)

			// Get context base (our code is in context->Shellcode, so context is at code - offset)
			// Context structure:
			// +0x000: OriginalBytes[12]
			// +0x00C: LdrLoadDllAddr (8)
			// +0x014: RtlInitUnicodeStringAddr (8) - actually at +0x010 aligned
			// For simplicity, use absolute addresses stored at known offsets

			// Note: This is complex position-independent code
			// For now, use a simpler approach: the trampoline directly loads our DLL
			// then restores bytes and calls original

			// Load our DLL path address into rcx
			0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, DllPathAddr

			// Set up UNICODE_STRING on stack
			// UNICODE_STRING: Length (2) + MaxLength (2) + Buffer (8)
			0x48, 0x31, 0xD2,                               // xor rdx, rdx
			0x48, 0x89, 0x4C, 0x24, 0x20,                   // mov [rsp+0x20], rcx (save path addr)

			// Calculate string length (simplified - assume max length)
			0x48, 0xC7, 0x44, 0x24, 0x50, 0x08, 0x02, 0x00, 0x00, // mov qword [rsp+0x50], 0x208 (MaxLength<<16 | Length)
			0x48, 0x8B, 0x4C, 0x24, 0x20,                   // mov rcx, [rsp+0x20]
			0x48, 0x89, 0x4C, 0x24, 0x58,                   // mov [rsp+0x58], rcx

			// Prepare LdrLoadDll call for our DLL
			// rcx = PathToFile (NULL)
			// rdx = Flags (0)
			// r8 = ModuleFileName (UNICODE_STRING ptr at rsp+0x50)
			// r9 = ModuleHandle (local var at rsp+0x60)
			0x48, 0x31, 0xC9,                               // xor rcx, rcx
			0x48, 0x31, 0xD2,                               // xor rdx, rdx
			0x4C, 0x8D, 0x44, 0x24, 0x50,                   // lea r8, [rsp+0x50]
			0x4C, 0x8D, 0x4C, 0x24, 0x60,                   // lea r9, [rsp+0x60]

			// Restore original bytes first (we need to unhook before calling)
			// This part needs the addresses patched in
			0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, LdrLoadDllAddr
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, OriginalBytesAddr

			// Copy 8 bytes then 4 bytes
			0x48, 0x8B, 0x08,                               // mov rcx, [rax]
			0x48, 0x89, 0x0B,                               // mov [rbx], rcx
			0x8B, 0x48, 0x08,                               // mov ecx, [rax+8]
			0x89, 0x4B, 0x08,                               // mov [rbx+8], ecx

			// Now restore rcx for LdrLoadDll call
			0x48, 0x31, 0xC9,                               // xor rcx, rcx
			0x48, 0x31, 0xD2,                               // xor rdx, rdx
			0x4C, 0x8D, 0x44, 0x24, 0x50,                   // lea r8, [rsp+0x50]
			0x4C, 0x8D, 0x4C, 0x24, 0x60,                   // lea r9, [rsp+0x60]

			// Call LdrLoadDll (now unhooked)
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, LdrLoadDllAddr
			0xFF, 0xD0,                                     // call rax

			// Now call original function with original arguments
			0x48, 0x8B, 0x4C, 0x24, 0x30,                   // mov rcx, [rsp+0x30]
			0x48, 0x8B, 0x54, 0x24, 0x38,                   // mov rdx, [rsp+0x38]
			0x4C, 0x8B, 0x44, 0x24, 0x40,                   // mov r8, [rsp+0x40]
			0x4C, 0x8B, 0x4C, 0x24, 0x48,                   // mov r9, [rsp+0x48]

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, LdrLoadDllAddr
			0xFF, 0xD0,                                     // call rax

			// Restore stack and registers
			0x48, 0x83, 0xC4, 0x68,                         // add rsp, 0x68
			0x5B,                                           // pop rbx
			0x5E,                                           // pop rsi
			0x5F,                                           // pop rdi
			0x5D,                                           // pop rbp
			0x41, 0x5C,                                     // pop r12
			0x41, 0x5D,                                     // pop r13
			0x41, 0x5E,                                     // pop r14
			0x41, 0x5F,                                     // pop r15
			0xC3                                            // ret
		};

		// Patch in addresses
		// DllPathAddr at offset 0x20 (after the movs for saving args)
		*(PVOID*)&shellcode[0x22] = context->DllPath;

		// LdrLoadDllAddr at multiple locations
		*(PVOID*)&shellcode[0x5E] = pLdrLoadDll;           // For restoring bytes
		*(PVOID*)&shellcode[0x68] = context->OriginalBytes; // Original bytes location
		*(PVOID*)&shellcode[0x92] = pLdrLoadDll;           // For our DLL call
		*(PVOID*)&shellcode[0xAF] = pLdrLoadDll;           // For original call

		// Copy shellcode to context
		RtlCopyMemory(context->Shellcode, shellcode, sizeof(shellcode));

		// Now install the trampoline
		// Make LdrLoadDll writable
		PVOID protectAddr = pLdrLoadDll;
		SIZE_T protectSize = 12;
		ULONG oldProtect = 0;

		status = ZwProtectVirtualMemory(
			ZwCurrentProcess(),
			&protectAddr,
			&protectSize,
			PAGE_EXECUTE_READWRITE,
			&oldProtect
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to make LdrLoadDll writable: 0x%X\n", status));
			SIZE_T freeSize = 0;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &contextAddr, &freeSize, MEM_RELEASE);
			KeUnstackDetachProcess(&apcState);
			return FALSE;
		}

		// Build and install trampoline
		UCHAR trampoline[12];
		RtlCopyMemory(trampoline, TrampolineBytes, sizeof(TrampolineBytes));
		*(PVOID*)&trampoline[2] = context->Shellcode;

		// Write trampoline to LdrLoadDll
		RtlCopyMemory(pLdrLoadDll, trampoline, 12);

		// Restore protection
		protectAddr = pLdrLoadDll;
		protectSize = 12;
		ZwProtectVirtualMemory(ZwCurrentProcess(), &protectAddr, &protectSize, oldProtect, &oldProtect);

		KdPrint((DRIVER_PREFIX "Trampoline installed at LdrLoadDll (%p) -> Shellcode (%p)\n",
			pLdrLoadDll, context->Shellcode));

		result = TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception during trampoline injection\n"));
	}

	KeUnstackDetachProcess(&apcState);
	return result;
}

// ============== APC Injection ==============

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
