#include "pch.h"
#include "DioProcessGlobals.h"

// ============== Kernel Injection Implementation ==============

// Undocumented structures for PEB access
typedef struct _PEB_LDR_DATA_INTERNAL {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_INTERNAL, * PPEB_LDR_DATA_INTERNAL;

// Minimal PEB structure (only fields we need)
typedef struct _PEB_INTERNAL {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN SpareBool;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA_INTERNAL Ldr;
	// ... other fields omitted for brevity
} PEB_INTERNAL, * PPEB_INTERNAL;

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
} LDR_DATA_TABLE_ENTRY_INTERNAL, * PLDR_DATA_TABLE_ENTRY_INTERNAL;

// RtlCreateUserThread function pointer type
typedef NTSTATUS(NTAPI* PfnRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientID
	);

// Helper: Get PEB from EPROCESS (version-aware)
PPEB GetProcessPeb(PEPROCESS Process, WINDOWS_VERSION WindowsVersion)
{
	if (WindowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Unsupported Windows version for PEB access\n"));
		return NULL;
	}

	PPEB pPeb = NULL;
	ULONG pebOffset = PROCESS_PEB_OFFSET[WindowsVersion];

	if (pebOffset == 0)
	{
		KdPrint((DRIVER_PREFIX "Invalid PEB offset for this Windows version\n"));
		return NULL;
	}

	__try
	{
		// Get PEB pointer using version-specific offset
		pPeb = (PPEB)*(PVOID*)((PUCHAR)Process + pebOffset);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception accessing PEB at offset 0x%X\n", pebOffset));
		return NULL;
	}

	return pPeb;
}

// Helper: Get module base address in target process (following reference implementation)
PVOID GetUserModuleBaseAddress(PEPROCESS Process, PUNICODE_STRING ModuleName, WINDOWS_VERSION WindowsVersion)
{
	PPEB_INTERNAL pPeb = (PPEB_INTERNAL)GetProcessPeb(Process, WindowsVersion);
	if (!pPeb || !MmIsAddressValid(pPeb))
	{
		KdPrint((DRIVER_PREFIX "Failed to get valid PEB\n"));
		return NULL;
	}

	__try
	{
		// Get PEB_LDR_DATA
		PPEB_LDR_DATA_INTERNAL pLdr = pPeb->Ldr;
		if (!pLdr || !MmIsAddressValid(pLdr))
		{
			return NULL;
		}

		// Iterate through InLoadOrderModuleList
		for (PLIST_ENTRY pListEntry = pLdr->InLoadOrderModuleList.Flink;
			pListEntry != &pLdr->InLoadOrderModuleList;
			pListEntry = pListEntry->Flink)
		{
			if (!MmIsAddressValid(pListEntry))
			{
				continue;
			}

			PLDR_DATA_TABLE_ENTRY_INTERNAL pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY_INTERNAL, InLoadOrderLinks);
			if (!MmIsAddressValid(pEntry))
			{
				continue;
			}

			// Compare module names (case-insensitive)
			if (RtlEqualUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE))
			{
				return pEntry->DllBase;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}

	return NULL;
}

// Helper: Get exported function address from module (PE parsing)
PVOID GetModuleExportAddress(PVOID ModuleBase, PCCHAR FunctionName)
{
	if (!ModuleBase || !MmIsAddressValid(ModuleBase))
	{
		return NULL;
	}

	__try
	{
		// Parse PE headers
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return NULL;
		}

		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + pDosHeader->e_lfanew);
		if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			return NULL;
		}

		// Get export directory
		PIMAGE_DATA_DIRECTORY pExportDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (pExportDataDir->VirtualAddress == 0)
		{
			return NULL;
		}

		PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + pExportDataDir->VirtualAddress);
		if (!MmIsAddressValid(pExportDir))
		{
			return NULL;
		}

		// Get export tables
		PULONG pAddressOfFunctions = (PULONG)((PUCHAR)ModuleBase + pExportDir->AddressOfFunctions);
		PULONG pAddressOfNames = (PULONG)((PUCHAR)ModuleBase + pExportDir->AddressOfNames);
		PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PUCHAR)ModuleBase + pExportDir->AddressOfNameOrdinals);

		// Search for function by name
		for (ULONG i = 0; i < pExportDir->NumberOfNames; i++)
		{
			if (!MmIsAddressValid(&pAddressOfNames[i]))
			{
				continue;
			}

			PCCHAR pName = (PCCHAR)((PUCHAR)ModuleBase + pAddressOfNames[i]);
			if (!MmIsAddressValid(pName))
			{
				continue;
			}

			if (strcmp(pName, FunctionName) == 0)
			{
				USHORT ordinal = pAddressOfNameOrdinals[i];
				ULONG functionRva = pAddressOfFunctions[ordinal];
				return (PVOID)((PUCHAR)ModuleBase + functionRva);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}

	return NULL;
}

// Helper: Get LoadLibraryW address in target process (following reference implementation)
PVOID GetLoadLibraryWAddress(ULONG ProcessId, WINDOWS_VERSION WindowsVersion)
{
	if (WindowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Unsupported Windows version for kernel injection\n"));
		return NULL;
	}

	PEPROCESS pEProcess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &pEProcess);
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}

	KAPC_STATE apcState;
	PVOID loadLibraryAddress = NULL;

	__try
	{
		// Attach to target process
		KeStackAttachProcess(pEProcess, &apcState);

		// Find kernel32.dll base address
		UNICODE_STRING kernel32Name;
		RtlInitUnicodeString(&kernel32Name, L"kernel32.dll");
		PVOID kernel32Base = GetUserModuleBaseAddress(pEProcess, &kernel32Name, WindowsVersion);

		if (kernel32Base && MmIsAddressValid(kernel32Base))
		{
			// Get LoadLibraryW export address
			loadLibraryAddress = GetModuleExportAddress(kernel32Base, "LoadLibraryW");
			KdPrint((DRIVER_PREFIX "Windows version: %d, kernel32.dll base: 0x%p, LoadLibraryW: 0x%p\n",
				WindowsVersion, kernel32Base, loadLibraryAddress));
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Failed to find kernel32.dll base address\n"));
		}

		KeUnstackDetachProcess(&apcState);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception while getting LoadLibraryW address\n"));
		KeUnstackDetachProcess(&apcState);
	}

	ObDereferenceObject(pEProcess);
	return loadLibraryAddress;
}

// Kernel DLL injection function (following reference implementation)
NTSTATUS KernelInjectDll(ULONG ProcessId, PCWSTR DllPath, PVOID* AllocatedAddress, PVOID* LoadLibraryAddress)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = NULL;
	KAPC_STATE apcState = { 0 };
	PfnRtlCreateUserThread RtlCreateUserThread = NULL;
	HANDLE hThread = NULL;
	PVOID pDllPathMemory = NULL;
	PVOID pLoadLibraryW = NULL;

	// Get Windows version
	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Unsupported Windows version for kernel DLL injection\n"));
		return STATUS_NOT_SUPPORTED;
	}

	KdPrint((DRIVER_PREFIX "Kernel DLL injection - Windows version: %d\n", windowsVersion));

	__try
	{
		// Get RtlCreateUserThread function address
		UNICODE_STRING ustrRtlCreateUserThread;
		RtlInitUnicodeString(&ustrRtlCreateUserThread, L"RtlCreateUserThread");
		RtlCreateUserThread = (PfnRtlCreateUserThread)MmGetSystemRoutineAddress(&ustrRtlCreateUserThread);
		if (!RtlCreateUserThread)
		{
			KdPrint((DRIVER_PREFIX "Failed to get RtlCreateUserThread\n"));
			return STATUS_NOT_FOUND;
		}

		// Get LoadLibraryW address in target process
		pLoadLibraryW = GetLoadLibraryWAddress(ProcessId, windowsVersion);
		if (!pLoadLibraryW)
		{
			KdPrint((DRIVER_PREFIX "Failed to get LoadLibraryW address\n"));
			return STATUS_NOT_FOUND;
		}

		*LoadLibraryAddress = pLoadLibraryW;

		// Lookup process by PID
		status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &pEProcess);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to lookup process %u\n", ProcessId));
			return status;
		}

		// Attach to target process
		KeStackAttachProcess(pEProcess, &apcState);

		// Allocate memory for DLL path (wide string)
		SIZE_T dllPathSize = (wcslen(DllPath) + 1) * sizeof(WCHAR);
		SIZE_T allocSize = dllPathSize;
		status = ZwAllocateVirtualMemory(
			ZwCurrentProcess(),
			&pDllPathMemory,
			0,
			&allocSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to allocate memory for DLL path\n"));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return status;
		}

		// Write DLL path to allocated memory
		__try
		{
			RtlCopyMemory(pDllPathMemory, DllPath, dllPathSize);
			KdPrint((DRIVER_PREFIX "DLL path written to 0x%p\n", pDllPathMemory));
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			KdPrint((DRIVER_PREFIX "Failed to write DLL path\n"));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return STATUS_ACCESS_VIOLATION;
		}

		// Validate address
		if (!MmIsAddressValid(pDllPathMemory))
		{
			KdPrint((DRIVER_PREFIX "DLL path address is not valid\n"));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return STATUS_INVALID_ADDRESS;
		}

		// Create thread with LoadLibraryW(DllPath)
		// StartAddress = LoadLibraryW, StartParameter = DLL path
		status = RtlCreateUserThread(
			ZwCurrentProcess(),
			NULL,
			FALSE,
			0,
			0,
			0,
			pLoadLibraryW,       // LoadLibraryW address
			pDllPathMemory,      // DLL path as parameter
			&hThread,
			NULL
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "RtlCreateUserThread failed: 0x%X\n", status));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return status;
		}

		// Close thread handle
		if (hThread)
		{
			ZwClose(hThread);
		}

		*AllocatedAddress = pDllPathMemory;
		KdPrint((DRIVER_PREFIX "DLL injection successful - PID: %u, DLL Path Address: 0x%p, LoadLibraryW: 0x%p\n",
			ProcessId, pDllPathMemory, pLoadLibraryW));

		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(pEProcess);
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception during DLL injection\n"));
		if (pEProcess)
		{
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
		}
		return STATUS_UNSUCCESSFUL;
	}
}

// Kernel shellcode injection function based on reference implementation
NTSTATUS KernelInjectShellcode(ULONG ProcessId, PVOID Shellcode, SIZE_T ShellcodeSize, PVOID* AllocatedAddress)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = NULL;
	KAPC_STATE apcState = { 0 };
	PfnRtlCreateUserThread RtlCreateUserThread = NULL;
	HANDLE hThread = NULL;
	PVOID pShellcodeMemory = NULL;

	// Get Windows version for logging/verification
	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Unsupported Windows version for kernel shellcode injection\n"));
		return STATUS_NOT_SUPPORTED;
	}

	KdPrint((DRIVER_PREFIX "Kernel shellcode injection - Windows version: %d\n", windowsVersion));

	__try
	{
		// Get RtlCreateUserThread function address dynamically
		UNICODE_STRING ustrRtlCreateUserThread;
		RtlInitUnicodeString(&ustrRtlCreateUserThread, L"RtlCreateUserThread");
		RtlCreateUserThread = (PfnRtlCreateUserThread)MmGetSystemRoutineAddress(&ustrRtlCreateUserThread);
		if (RtlCreateUserThread == NULL)
		{
			KdPrint((DRIVER_PREFIX "Failed to get RtlCreateUserThread address\n"));
			return STATUS_NOT_FOUND;
		}

		// Lookup process by PID
		status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &pEProcess);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to lookup process %u: 0x%X\n", ProcessId, status));
			return status;
		}

		// Attach to target process
		KeStackAttachProcess(pEProcess, &apcState);

		// Allocate memory in target process for shellcode
		SIZE_T allocSize = ShellcodeSize;
		status = ZwAllocateVirtualMemory(
			ZwCurrentProcess(),
			&pShellcodeMemory,
			0,
			&allocSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to allocate memory: 0x%X\n", status));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return status;
		}

		// Write shellcode to allocated memory
		__try
		{
			RtlCopyMemory(pShellcodeMemory, Shellcode, ShellcodeSize);
			KdPrint((DRIVER_PREFIX "Shellcode written to 0x%p, size %zu\n", pShellcodeMemory, ShellcodeSize));
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			KdPrint((DRIVER_PREFIX "Failed to write shellcode\n"));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return STATUS_ACCESS_VIOLATION;
		}

		// Validate address is accessible
		if (!MmIsAddressValid(pShellcodeMemory))
		{
			KdPrint((DRIVER_PREFIX "Shellcode address is not valid\n"));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return STATUS_INVALID_ADDRESS;
		}

		// Create thread at shellcode address using RtlCreateUserThread
		status = RtlCreateUserThread(
			ZwCurrentProcess(),
			NULL,
			FALSE,
			0,
			0,
			0,
			pShellcodeMemory,
			NULL,
			&hThread,
			NULL
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "RtlCreateUserThread failed: 0x%X\n", status));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return status;
		}

		// Close thread handle
		if (hThread)
		{
			ZwClose(hThread);
		}

		*AllocatedAddress = pShellcodeMemory;
		KdPrint((DRIVER_PREFIX "Shellcode injection successful - PID: %u, Address: 0x%p\n", ProcessId, pShellcodeMemory));

		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(pEProcess);
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception during shellcode injection\n"));
		if (pEProcess)
		{
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
		}
		return STATUS_UNSUCCESSFUL;
	}
}
