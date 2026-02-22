#include "pch.h"
#include "ManualMap.h"

// ============== Manual Map Implementation ==============

// Validate PE headers and return NT headers pointer
BOOLEAN MmValidatePeHeaders(
	_In_ PVOID DllBuffer,
	_In_ SIZE_T DllSize,
	_Out_ PIMAGE_NT_HEADERS* NtHeaders
)
{
	*NtHeaders = NULL;

	if (!DllBuffer || DllSize < sizeof(IMAGE_DOS_HEADER))
	{
		return FALSE;
	}

	__try
	{
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)DllBuffer;

		// Validate DOS signature
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			KdPrint((DRIVER_PREFIX "ManualMap: Invalid DOS signature\n"));
			return FALSE;
		}

		// Validate e_lfanew is within bounds
		if ((SIZE_T)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > DllSize)
		{
			KdPrint((DRIVER_PREFIX "ManualMap: e_lfanew out of bounds\n"));
			return FALSE;
		}

		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)DllBuffer + dosHeader->e_lfanew);

		// Validate NT signature
		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			KdPrint((DRIVER_PREFIX "ManualMap: Invalid NT signature\n"));
			return FALSE;
		}

		// Validate machine type (x64)
		if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
		{
			KdPrint((DRIVER_PREFIX "ManualMap: Not x64 PE (machine: 0x%X)\n", ntHeaders->FileHeader.Machine));
			return FALSE;
		}

		// Validate it's a DLL
		if (!(ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL))
		{
			KdPrint((DRIVER_PREFIX "ManualMap: Not a DLL\n"));
			return FALSE;
		}

		*NtHeaders = ntHeaders;
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "ManualMap: Exception validating PE headers\n"));
		return FALSE;
	}
}

// Map PE sections into target process
NTSTATUS MmMapSections(
	_In_ PEPROCESS Process,
	_In_ PVOID DllBuffer,
	_In_ PIMAGE_NT_HEADERS NtHeaders,
	_In_ PVOID MappedBase,
	_In_ SIZE_T MappedSize
)
{
	UNREFERENCED_PARAMETER(MappedSize);

	KAPC_STATE apcState;
	NTSTATUS status = STATUS_SUCCESS;

	KeStackAttachProcess(Process, &apcState);

	__try
	{
		// Copy headers first
		SIZE_T headerSize = NtHeaders->OptionalHeader.SizeOfHeaders;
		RtlCopyMemory(MappedBase, DllBuffer, headerSize);
		KdPrint((DRIVER_PREFIX "ManualMap: Copied %zu bytes of headers\n", headerSize));

		// Map each section
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(NtHeaders);
		for (USHORT i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
		{
			if (section[i].SizeOfRawData == 0)
			{
				continue;
			}

			PVOID sectionDest = (PUCHAR)MappedBase + section[i].VirtualAddress;
			PVOID sectionSrc = (PUCHAR)DllBuffer + section[i].PointerToRawData;
			SIZE_T sectionSize = min(section[i].SizeOfRawData, section[i].Misc.VirtualSize);

			RtlCopyMemory(sectionDest, sectionSrc, sectionSize);

			KdPrint((DRIVER_PREFIX "ManualMap: Mapped section %.8s at RVA 0x%X, size 0x%X\n",
				section[i].Name, section[i].VirtualAddress, (ULONG)sectionSize));
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "ManualMap: Exception mapping sections\n"));
		status = STATUS_ACCESS_VIOLATION;
	}

	KeUnstackDetachProcess(&apcState);
	return status;
}

// Process base relocations
NTSTATUS MmProcessRelocations(
	_In_ PEPROCESS Process,
	_In_ PVOID MappedBase,
	_In_ PIMAGE_NT_HEADERS NtHeaders,
	_In_ ULONG_PTR DeltaBase
)
{
	if (DeltaBase == 0)
	{
		KdPrint((DRIVER_PREFIX "ManualMap: No relocation needed (loaded at preferred base)\n"));
		return STATUS_SUCCESS;
	}

	PIMAGE_DATA_DIRECTORY relocDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (relocDir->VirtualAddress == 0 || relocDir->Size == 0)
	{
		KdPrint((DRIVER_PREFIX "ManualMap: No relocation directory\n"));
		return STATUS_SUCCESS;
	}

	KAPC_STATE apcState;
	NTSTATUS status = STATUS_SUCCESS;

	KeStackAttachProcess(Process, &apcState);

	__try
	{
		PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)MappedBase + relocDir->VirtualAddress);
		PIMAGE_BASE_RELOCATION relocEnd = (PIMAGE_BASE_RELOCATION)((PUCHAR)reloc + relocDir->Size);

		ULONG relocCount = 0;

		while (reloc < relocEnd && reloc->SizeOfBlock > 0)
		{
			ULONG numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
			PUSHORT entries = (PUSHORT)((PUCHAR)reloc + sizeof(IMAGE_BASE_RELOCATION));

			for (ULONG i = 0; i < numEntries; i++)
			{
				USHORT type = entries[i] >> 12;
				USHORT offset = entries[i] & 0xFFF;

				if (type == IMAGE_REL_BASED_DIR64)
				{
					PULONG_PTR patchAddr = (PULONG_PTR)((PUCHAR)MappedBase + reloc->VirtualAddress + offset);
					*patchAddr += DeltaBase;
					relocCount++;
				}
				else if (type == IMAGE_REL_BASED_ABSOLUTE)
				{
					// Padding, skip
				}
				else
				{
					KdPrint((DRIVER_PREFIX "ManualMap: Unknown relocation type %u\n", type));
				}
			}

			reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)reloc + reloc->SizeOfBlock);
		}

		KdPrint((DRIVER_PREFIX "ManualMap: Processed %u relocations (delta: 0x%llX)\n", relocCount, DeltaBase));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "ManualMap: Exception processing relocations\n"));
		status = STATUS_ACCESS_VIOLATION;
	}

	KeUnstackDetachProcess(&apcState);
	return status;
}

// Helper: Get module base from target process PEB
static PVOID MmGetModuleBase(
	_In_ PEPROCESS Process,
	_In_ PCWSTR ModuleName,
	_In_ WINDOWS_VERSION WindowsVersion
)
{
	UNICODE_STRING moduleName;
	RtlInitUnicodeString(&moduleName, ModuleName);
	return GetUserModuleBaseAddress(Process, &moduleName, WindowsVersion);
}

// Helper: Get export address from module in target process
static PVOID MmGetProcAddress(
	_In_ PVOID ModuleBase,
	_In_ PCSTR FunctionName
)
{
	return GetModuleExportAddress(ModuleBase, (PCCHAR)FunctionName);
}

// Helper: Get export address by ordinal
static PVOID MmGetProcAddressByOrdinal(
	_In_ PVOID ModuleBase,
	_In_ USHORT Ordinal
)
{
	if (!ModuleBase || !MmIsAddressValid(ModuleBase))
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

		PIMAGE_DATA_DIRECTORY exportDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (exportDir->VirtualAddress == 0)
		{
			return NULL;
		}

		PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + exportDir->VirtualAddress);
		if (!MmIsAddressValid(exports))
		{
			return NULL;
		}

		PULONG addressOfFunctions = (PULONG)((PUCHAR)ModuleBase + exports->AddressOfFunctions);

		ULONG ordinalIndex = Ordinal - (USHORT)exports->Base;
		if (ordinalIndex >= exports->NumberOfFunctions)
		{
			return NULL;
		}

		ULONG funcRva = addressOfFunctions[ordinalIndex];
		return (PVOID)((PUCHAR)ModuleBase + funcRva);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}
}

// Resolve imports from target process modules
NTSTATUS MmResolveImports(
	_In_ PEPROCESS Process,
	_In_ PVOID MappedBase,
	_In_ PIMAGE_NT_HEADERS NtHeaders,
	_In_ WINDOWS_VERSION WindowsVersion
)
{
	PIMAGE_DATA_DIRECTORY importDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDir->VirtualAddress == 0 || importDir->Size == 0)
	{
		KdPrint((DRIVER_PREFIX "ManualMap: No import directory\n"));
		return STATUS_SUCCESS;
	}

	KAPC_STATE apcState;
	NTSTATUS status = STATUS_SUCCESS;

	KeStackAttachProcess(Process, &apcState);

	__try
	{
		PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)MappedBase + importDir->VirtualAddress);

		ULONG moduleCount = 0;
		ULONG importCount = 0;

		while (importDesc->Name != 0)
		{
			PCSTR moduleName = (PCSTR)((PUCHAR)MappedBase + importDesc->Name);
			
			// Convert to wide string for module lookup
			WCHAR moduleNameW[256] = { 0 };
			for (int i = 0; i < 255 && moduleName[i]; i++)
			{
				moduleNameW[i] = (WCHAR)moduleName[i];
			}

			// Get module base from target process
			PVOID moduleBase = MmGetModuleBase(Process, moduleNameW, WindowsVersion);
			if (!moduleBase)
			{
				KdPrint((DRIVER_PREFIX "ManualMap: Failed to find module %s\n", moduleName));
				status = STATUS_DLL_NOT_FOUND;
				break;
			}

			KdPrint((DRIVER_PREFIX "ManualMap: Resolving imports from %s (base: 0x%p)\n", moduleName, moduleBase));
			moduleCount++;

			// Get thunk arrays
			PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((PUCHAR)MappedBase + importDesc->OriginalFirstThunk);
			PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((PUCHAR)MappedBase + importDesc->FirstThunk);

			// If OriginalFirstThunk is 0, use FirstThunk
			if (importDesc->OriginalFirstThunk == 0)
			{
				origThunk = firstThunk;
			}

			while (origThunk->u1.AddressOfData != 0)
			{
				PVOID funcAddr = NULL;

				if (IMAGE_SNAP_BY_ORDINAL64(origThunk->u1.Ordinal))
				{
					// Import by ordinal
					USHORT ordinal = (USHORT)IMAGE_ORDINAL64(origThunk->u1.Ordinal);
					funcAddr = MmGetProcAddressByOrdinal(moduleBase, ordinal);
					if (!funcAddr)
					{
						KdPrint((DRIVER_PREFIX "ManualMap: Failed to resolve ordinal %u from %s\n", ordinal, moduleName));
						status = STATUS_ENTRYPOINT_NOT_FOUND;
						break;
					}
				}
				else
				{
					// Import by name
					PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)MappedBase + origThunk->u1.AddressOfData);
					funcAddr = MmGetProcAddress(moduleBase, (PCSTR)importByName->Name);
					if (!funcAddr)
					{
						KdPrint((DRIVER_PREFIX "ManualMap: Failed to resolve %s from %s\n", importByName->Name, moduleName));
						status = STATUS_ENTRYPOINT_NOT_FOUND;
						break;
					}
				}

				// Write resolved address to IAT
				firstThunk->u1.Function = (ULONG_PTR)funcAddr;
				importCount++;

				origThunk++;
				firstThunk++;
			}

			if (!NT_SUCCESS(status))
			{
				break;
			}

			importDesc++;
		}

		if (NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "ManualMap: Resolved %u imports from %u modules\n", importCount, moduleCount));
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "ManualMap: Exception resolving imports\n"));
		status = STATUS_ACCESS_VIOLATION;
	}

	KeUnstackDetachProcess(&apcState);
	return status;
}

// Shellcode to call DllMain(hModule, DLL_PROCESS_ATTACH, NULL) then RtlExitUserThread(0)
// This shellcode is position-independent and properly terminates the thread
// 
// Stack alignment: RtlCreateUserThread starts with RSP 8-byte aligned
// sub 0x28 makes it 16-byte aligned for the call
// add 0x28 restores it before calling RtlExitUserThread
static const UCHAR g_DllMainShellcode[] = {
	// sub rsp, 0x28                    ; 40 bytes: 32 shadow + 8 alignment
	0x48, 0x83, 0xEC, 0x28,             // offset 0-3
	// mov rcx, <hModule>               ; First param: hModule
	0x48, 0xB9,                         // offset 4-5
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // offset 6-13 (patch hModule here)
	// mov edx, 1                       ; Second param: DLL_PROCESS_ATTACH
	0xBA, 0x01, 0x00, 0x00, 0x00,       // offset 14-18
	// xor r8d, r8d                     ; Third param: NULL
	0x45, 0x31, 0xC0,                   // offset 19-21
	// mov rax, <DllMain>               ; Entry point address
	0x48, 0xB8,                         // offset 22-23
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // offset 24-31 (patch DllMain here)
	// call rax                         ; Call DllMain
	0xFF, 0xD0,                         // offset 32-33
	// add rsp, 0x28                    ; Restore stack
	0x48, 0x83, 0xC4, 0x28,             // offset 34-37
	// xor ecx, ecx                     ; Exit code = 0
	0x31, 0xC9,                         // offset 38-39
	// mov rax, <RtlExitUserThread>     ; RtlExitUserThread address
	0x48, 0xB8,                         // offset 40-41
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // offset 42-49 (patch exit here)
	// jmp rax                          ; Jump to RtlExitUserThread (doesn't return)
	0xFF, 0xE0                          // offset 50-51
};

#define SHELLCODE_HMODULE_OFFSET 6
#define SHELLCODE_DLLMAIN_OFFSET 24
#define SHELLCODE_EXIT_OFFSET 42
#define SHELLCODE_SIZE sizeof(g_DllMainShellcode)

// Call DllMain entry point via RtlCreateUserThread
// Shellcode calls RtlExitUserThread to properly terminate
NTSTATUS MmCallEntryPoint(
	_In_ PEPROCESS Process,
	_In_ PVOID MappedBase,
	_In_ PVOID EntryPoint
)
{
	NTSTATUS status = STATUS_SUCCESS;
	KAPC_STATE apcState;
	PVOID shellcodeAddr = NULL;
	HANDLE threadHandle = NULL;

	// Resolve RtlCreateUserThread
	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, L"RtlCreateUserThread");

	typedef NTSTATUS(NTAPI* RtlCreateUserThread_t)(
		HANDLE ProcessHandle,
		PSECURITY_DESCRIPTOR SecurityDescriptor,
		BOOLEAN CreateSuspended,
		ULONG StackZeroBits,
		PULONG StackReserved,
		PULONG StackCommit,
		PVOID StartAddress,
		PVOID StartParameter,
		PHANDLE ThreadHandle,
		PVOID ClientId
	);

	RtlCreateUserThread_t pfnRtlCreateUserThread = (RtlCreateUserThread_t)MmGetSystemRoutineAddress(&funcName);
	if (!pfnRtlCreateUserThread)
	{
		KdPrint((DRIVER_PREFIX "ManualMap: Failed to resolve RtlCreateUserThread\n"));
		return STATUS_NOT_FOUND;
	}

	// Get RtlExitUserThread address from ntdll in target process
	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	PVOID rtlExitUserThread = NULL;

	KeStackAttachProcess(Process, &apcState);

	__try
	{
		// Find ntdll.dll and get RtlExitUserThread
		UNICODE_STRING ntdllName;
		RtlInitUnicodeString(&ntdllName, L"ntdll.dll");
		PVOID ntdllBase = GetUserModuleBaseAddress(Process, &ntdllName, windowsVersion);
		if (ntdllBase)
		{
			rtlExitUserThread = GetModuleExportAddress(ntdllBase, (PCCHAR)"RtlExitUserThread");
		}

		if (!rtlExitUserThread)
		{
			KdPrint((DRIVER_PREFIX "ManualMap: Failed to find RtlExitUserThread\n"));
			KeUnstackDetachProcess(&apcState);
			return STATUS_NOT_FOUND;
		}

		KdPrint((DRIVER_PREFIX "ManualMap: RtlExitUserThread at 0x%p\n", rtlExitUserThread));

		// Allocate memory for shellcode
		SIZE_T shellcodeSize = SHELLCODE_SIZE;
		status = ZwAllocateVirtualMemory(
			ZwCurrentProcess(),
			&shellcodeAddr,
			0,
			&shellcodeSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "ManualMap: Failed to allocate shellcode memory: 0x%X\n", status));
			KeUnstackDetachProcess(&apcState);
			return status;
		}

		// Copy and patch shellcode
		UCHAR shellcode[SHELLCODE_SIZE];
		RtlCopyMemory(shellcode, g_DllMainShellcode, SHELLCODE_SIZE);

		// Patch hModule address
		*(PULONG_PTR)(shellcode + SHELLCODE_HMODULE_OFFSET) = (ULONG_PTR)MappedBase;

		// Patch DllMain address
		*(PULONG_PTR)(shellcode + SHELLCODE_DLLMAIN_OFFSET) = (ULONG_PTR)EntryPoint;

		// Patch RtlExitUserThread address
		*(PULONG_PTR)(shellcode + SHELLCODE_EXIT_OFFSET) = (ULONG_PTR)rtlExitUserThread;

		// Write shellcode to target
		RtlCopyMemory(shellcodeAddr, shellcode, SHELLCODE_SIZE);

		KdPrint((DRIVER_PREFIX "ManualMap: Shellcode at 0x%p, calling DllMain at 0x%p, RtlExitUserThread at 0x%p\n", 
			shellcodeAddr, EntryPoint, rtlExitUserThread));

		// Create thread to execute shellcode
		status = pfnRtlCreateUserThread(
			ZwCurrentProcess(),
			NULL,
			FALSE,
			0,
			NULL,
			NULL,
			shellcodeAddr,
			NULL,
			&threadHandle,
			NULL
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "ManualMap: Failed to create thread: 0x%X\n", status));
			KeUnstackDetachProcess(&apcState);
			return status;
		}

		KeUnstackDetachProcess(&apcState);

		// Wait for thread to complete
		LARGE_INTEGER timeout;
		timeout.QuadPart = -100000000LL; // 10 seconds

		PETHREAD thread = NULL;
		status = ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&thread, NULL);
		if (NT_SUCCESS(status))
		{
			KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, &timeout);
			ObDereferenceObject(thread);
		}

		ZwClose(threadHandle);

		KdPrint((DRIVER_PREFIX "ManualMap: DllMain executed successfully\n"));
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "ManualMap: Exception calling entry point\n"));
		status = STATUS_ACCESS_VIOLATION;
	}

	KeUnstackDetachProcess(&apcState);
	return status;
}

// Erase PE headers from mapped image
NTSTATUS MmEraseHeaders(
	_In_ PEPROCESS Process,
	_In_ PVOID MappedBase,
	_In_ SIZE_T HeaderSize
)
{
	KAPC_STATE apcState;
	NTSTATUS status = STATUS_SUCCESS;

	KeStackAttachProcess(Process, &apcState);

	__try
	{
		RtlZeroMemory(MappedBase, HeaderSize);
		KdPrint((DRIVER_PREFIX "ManualMap: Erased %zu bytes of headers\n", HeaderSize));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "ManualMap: Exception erasing headers\n"));
		status = STATUS_ACCESS_VIOLATION;
	}

	KeUnstackDetachProcess(&apcState);
	return status;
}

// Main manual map function
NTSTATUS KernelManualMapDll(
	_In_ PVOID DllBuffer,
	_In_ SIZE_T DllSize,
	_In_ ULONG ProcessId,
	_In_ ULONG Flags,
	_Out_ ManualMapResult* Result
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process = NULL;
	PVOID mappedBase = NULL;
	PIMAGE_NT_HEADERS ntHeaders = NULL;

	// Initialize result
	RtlZeroMemory(Result, sizeof(ManualMapResult));

	KdPrint((DRIVER_PREFIX "ManualMap: Starting manual map for PID %u, DLL size %zu\n", ProcessId, DllSize));

	// Validate PE headers
	if (!MmValidatePeHeaders(DllBuffer, DllSize, &ntHeaders))
	{
		KdPrint((DRIVER_PREFIX "ManualMap: Invalid PE headers\n"));
		Result->Status = STATUS_INVALID_IMAGE_FORMAT;
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
	PVOID preferredBase = (PVOID)ntHeaders->OptionalHeader.ImageBase;

	KdPrint((DRIVER_PREFIX "ManualMap: Image size: 0x%zX, preferred base: 0x%p\n", imageSize, preferredBase));

	// Get Windows version for import resolution
	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "ManualMap: Unsupported Windows version\n"));
		Result->Status = STATUS_NOT_SUPPORTED;
		return STATUS_NOT_SUPPORTED;
	}

	// Lookup target process
	status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "ManualMap: Failed to lookup process %u: 0x%X\n", ProcessId, status));
		Result->Status = status;
		return status;
	}

	// Allocate memory in target process
	KAPC_STATE apcState;
	KeStackAttachProcess(process, &apcState);

	SIZE_T allocSize = imageSize;
	status = ZwAllocateVirtualMemory(
		ZwCurrentProcess(),
		&mappedBase,
		0,
		&allocSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	KeUnstackDetachProcess(&apcState);

	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "ManualMap: Failed to allocate memory: 0x%X\n", status));
		ObDereferenceObject(process);
		Result->Status = status;
		return status;
	}

	KdPrint((DRIVER_PREFIX "ManualMap: Allocated 0x%zX bytes at 0x%p\n", allocSize, mappedBase));

	// Calculate relocation delta
	ULONG_PTR deltaBase = (ULONG_PTR)mappedBase - (ULONG_PTR)preferredBase;

	// Map sections
	status = MmMapSections(process, DllBuffer, ntHeaders, mappedBase, imageSize);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "ManualMap: Failed to map sections: 0x%X\n", status));
		goto Cleanup;
	}

	// Process relocations
	status = MmProcessRelocations(process, mappedBase, ntHeaders, deltaBase);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "ManualMap: Failed to process relocations: 0x%X\n", status));
		goto Cleanup;
	}

	// Resolve imports (unless disabled)
	if (!(Flags & MANUAL_MAP_FLAG_NO_IMPORTS))
	{
		status = MmResolveImports(process, mappedBase, ntHeaders, windowsVersion);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "ManualMap: Failed to resolve imports: 0x%X\n", status));
			goto Cleanup;
		}
	}

	// Calculate entry point
	PVOID entryPoint = NULL;
	if (ntHeaders->OptionalHeader.AddressOfEntryPoint != 0)
	{
		entryPoint = (PUCHAR)mappedBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
	}

	// Call DllMain (unless disabled)
	if (!(Flags & MANUAL_MAP_FLAG_NO_ENTRY_POINT) && entryPoint)
	{
		status = MmCallEntryPoint(process, mappedBase, entryPoint);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "ManualMap: Failed to call entry point: 0x%X\n", status));
			// Don't fail the whole operation if DllMain fails
			// The DLL is still mapped and may be usable
		}
	}

	// Erase headers if requested
	if (Flags & MANUAL_MAP_FLAG_ERASE_HEADERS)
	{
		MmEraseHeaders(process, mappedBase, ntHeaders->OptionalHeader.SizeOfHeaders);
	}

	// Success
	Result->MappedBase = mappedBase;
	Result->MappedSize = imageSize;
	Result->EntryPoint = entryPoint;
	Result->Success = TRUE;
	Result->Status = STATUS_SUCCESS;

	KdPrint((DRIVER_PREFIX "ManualMap: Successfully mapped DLL at 0x%p\n", mappedBase));

	ObDereferenceObject(process);
	return STATUS_SUCCESS;

Cleanup:
	// Free allocated memory on failure
	if (mappedBase)
	{
		KeStackAttachProcess(process, &apcState);
		SIZE_T freeSize = 0;
		ZwFreeVirtualMemory(ZwCurrentProcess(), &mappedBase, &freeSize, MEM_RELEASE);
		KeUnstackDetachProcess(&apcState);
	}

	ObDereferenceObject(process);
	Result->Status = status;
	return status;
}
