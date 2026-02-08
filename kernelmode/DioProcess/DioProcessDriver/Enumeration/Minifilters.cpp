#include "pch.h"
#include "DioProcessGlobals.h"

// ============== Minifilter Enumeration ==============

// Find fltmgr.sys base address using AuxKlib
PVOID GetFltMgrBaseAddress(PULONG pSize)
{
	ULONG modulesSize = 0;
	NTSTATUS status;
	PAUX_MODULE_EXTENDED_INFO modules = NULL;
	PVOID fltmgrBase = NULL;

	// Get required buffer size
	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
	if (!NT_SUCCESS(status) || modulesSize == 0)
	{
		KdPrint((DRIVER_PREFIX "AuxKlibQueryModuleInformation failed: 0x%08X\n", status));
		return NULL;
	}

	modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePool2(POOL_FLAG_NON_PAGED, modulesSize, DRIVER_TAG);
	if (!modules)
	{
		KdPrint((DRIVER_PREFIX "Failed to allocate module buffer\n"));
		return NULL;
	}

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "AuxKlibQueryModuleInformation second call failed: 0x%08X\n", status));
		ExFreePoolWithTag(modules, DRIVER_TAG);
		return NULL;
	}

	ULONG numModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);
	for (ULONG i = 0; i < numModules; i++)
	{
		// Get just the filename part
		PCHAR fileName = (PCHAR)(modules[i].FullPathName + modules[i].FileNameOffset);
		if (_stricmp(fileName, "fltmgr.sys") == 0)
		{
			fltmgrBase = modules[i].BasicInfo.ImageBase;
			if (pSize)
				*pSize = modules[i].ImageSize;
			KdPrint((DRIVER_PREFIX "Found fltmgr.sys at: %p, size: 0x%X\n", fltmgrBase, modules[i].ImageSize));
			break;
		}
	}

	ExFreePoolWithTag(modules, DRIVER_TAG);
	return fltmgrBase;
}

// Find FltGlobals by pattern scanning fltmgr.sys
// We look for the pattern that references FltGlobals.FrameList
PVOID FindFltGlobals(PVOID fltmgrBase, ULONG fltmgrSize)
{
	if (!fltmgrBase || fltmgrSize == 0)
		return NULL;

	PUCHAR searchBase = (PUCHAR)fltmgrBase;
	PUCHAR searchEnd = searchBase + fltmgrSize - 0x100;

	// Pattern: LEA reg, [rip+offset] pointing to FltGlobals
	// We search for references to FltpFrameList or FltGlobals.FrameList
	// Common pattern: 48 8D 0D/05/15/1D/25/2D/35/3D [offset] - LEA rcx/rax/rdx/rbx/r8-r15, [rip+offset]

	for (PUCHAR p = searchBase; p < searchEnd; p++)
	{
		__try
		{
			// Look for LEA instruction with RIP-relative addressing
			// 48 8D 0D xx xx xx xx - LEA rcx, [rip+offset]
			// 4C 8D 05 xx xx xx xx - LEA r8, [rip+offset]
			if ((p[0] == 0x48 || p[0] == 0x4C) && p[1] == 0x8D)
			{
				UCHAR modRM = p[2];
				// Check if it's RIP-relative addressing (mod=00, r/m=101)
				if ((modRM & 0x07) == 0x05)
				{
					// Calculate the target address
					INT offset = *(INT*)(p + 3);
					PVOID targetAddr = (PVOID)(p + 7 + offset);

					// Verify the target address is within fltmgr.sys data section
					if (targetAddr > fltmgrBase && targetAddr < (PVOID)(searchBase + fltmgrSize))
					{
						// Check if this looks like FltGlobals by examining the structure
						// FltGlobals.FrameList should be a valid LIST_ENTRY
						PLIST_ENTRY frameList = (PLIST_ENTRY)((PUCHAR)targetAddr + FLTGLOBALS_FRAMELIST_OFFSET);

						if (MmIsAddressValid(frameList) &&
							MmIsAddressValid(frameList->Flink) &&
							MmIsAddressValid(frameList->Blink))
						{
							// Verify it's a valid circular list
							if (frameList->Flink->Blink == frameList &&
								frameList->Blink->Flink == frameList)
							{
								KdPrint((DRIVER_PREFIX "Potential FltGlobals found at: %p\n", targetAddr));
								return targetAddr;
							}
						}
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			continue;
		}
	}

	KdPrint((DRIVER_PREFIX "FltGlobals not found via pattern scan\n"));
	return NULL;
}

// Resolve export from a module by parsing its PE export table
PVOID GetModuleExport(PVOID moduleBase, PCSTR exportName)
{
	if (!moduleBase || !exportName)
		return NULL;

	__try
	{
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return NULL;

		PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)moduleBase + dosHeader->e_lfanew);
		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
			return NULL;

		ULONG exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (exportDirRva == 0)
			return NULL;

		PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)moduleBase + exportDirRva);
		PULONG nameRvas = (PULONG)((PUCHAR)moduleBase + exportDir->AddressOfNames);
		PUSHORT ordinals = (PUSHORT)((PUCHAR)moduleBase + exportDir->AddressOfNameOrdinals);
		PULONG funcRvas = (PULONG)((PUCHAR)moduleBase + exportDir->AddressOfFunctions);

		for (ULONG i = 0; i < exportDir->NumberOfNames; i++)
		{
			PCSTR name = (PCSTR)((PUCHAR)moduleBase + nameRvas[i]);
			if (strcmp(name, exportName) == 0)
			{
				USHORT ordinal = ordinals[i];
				ULONG funcRva = funcRvas[ordinal];
				return (PVOID)((PUCHAR)moduleBase + funcRva);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception in GetModuleExport\n"));
	}

	return NULL;
}

// Alternative: Use FltEnumerateFilters if available (documented API approach)
// This is safer but requires linking to fltmgr.lib
typedef NTSTATUS(*FltEnumerateFiltersFunc)(
	_Out_writes_bytes_to_opt_(FilterListSize, *NumberFiltersReturned * sizeof(PFLT_FILTER)) PFLT_FILTER* FilterList,
	_In_ ULONG FilterListSize,
	_Out_ PULONG NumberFiltersReturned
);

// Get filter information using FltMgr APIs (if resolvable)
BOOLEAN EnumerateMinifiltersViaApi(MinifilterInfo* entries, ULONG* count, ULONG maxEntries)
{
	// First try MmGetSystemRoutineAddress (works on some systems)
	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, L"FltEnumerateFilters");
	FltEnumerateFiltersFunc pFltEnumerateFilters = (FltEnumerateFiltersFunc)MmGetSystemRoutineAddress(&funcName);

	// If not found, resolve from fltmgr.sys export table
	if (!pFltEnumerateFilters)
	{
		KdPrint((DRIVER_PREFIX "FltEnumerateFilters not in ntoskrnl, trying fltmgr.sys exports...\n"));

		ULONG fltmgrSize = 0;
		PVOID fltmgrBase = GetFltMgrBaseAddress(&fltmgrSize);
		if (fltmgrBase)
		{
			pFltEnumerateFilters = (FltEnumerateFiltersFunc)GetModuleExport(fltmgrBase, "FltEnumerateFilters");
			if (pFltEnumerateFilters)
			{
				KdPrint((DRIVER_PREFIX "Found FltEnumerateFilters at %p\n", pFltEnumerateFilters));
			}
		}
	}

	if (!pFltEnumerateFilters)
	{
		KdPrint((DRIVER_PREFIX "FltEnumerateFilters not found\n"));
		return FALSE;
	}

	// Note: FltGetFilterInformation could be used for additional info, but we read structures directly

	// First call to get count
	ULONG numFilters = 0;
	NTSTATUS status = pFltEnumerateFilters(NULL, 0, &numFilters);
	if (status != STATUS_BUFFER_TOO_SMALL || numFilters == 0)
	{
		KdPrint((DRIVER_PREFIX "No minifilters registered or error: 0x%08X\n", status));
		return FALSE;
	}

	KdPrint((DRIVER_PREFIX "Found %u minifilters\n", numFilters));

	// Allocate buffer for filter pointers
	ULONG filterListSize = numFilters * sizeof(PFLT_FILTER);
	PFLT_FILTER* filterList = (PFLT_FILTER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, filterListSize, DRIVER_TAG);
	if (!filterList)
	{
		KdPrint((DRIVER_PREFIX "Failed to allocate filter list\n"));
		return FALSE;
	}

	status = pFltEnumerateFilters(filterList, filterListSize, &numFilters);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "FltEnumerateFilters failed: 0x%08X\n", status));
		ExFreePoolWithTag(filterList, DRIVER_TAG);
		return FALSE;
	}

	*count = 0;
	for (ULONG i = 0; i < numFilters && *count < maxEntries; i++)
	{
		PFLT_FILTER filter = filterList[i];
		if (!filter || !MmIsAddressValid(filter))
			continue;

		MinifilterInfo* info = &entries[*count];
		RtlZeroMemory(info, sizeof(MinifilterInfo));
		info->Index = *count;
		info->FilterAddress = (ULONG64)filter;

		__try
		{
			// Debug: Scan for UNICODE_STRING pattern (look for valid Length/MaxLength/Buffer)
			// A valid UNICODE_STRING has: Length <= MaxLength, both even, Buffer is valid kernel address
			KdPrint((DRIVER_PREFIX "Filter[%u] at %p - scanning for Name UNICODE_STRING...\n", i, filter));

			// Try multiple offsets to find the Name field
			BOOLEAN foundName = FALSE;
			for (ULONG offset = 0x30; offset <= 0x60 && !foundName; offset += 0x08)
			{
				PUNICODE_STRING testStr = (PUNICODE_STRING)((PUCHAR)filter + offset);
				if (MmIsAddressValid(testStr))
				{
					USHORT len = testStr->Length;
					USHORT maxLen = testStr->MaximumLength;
					PWCH buf = testStr->Buffer;

					// Check if this looks like a valid UNICODE_STRING
					if (len > 0 && len <= maxLen && len < 256 && (len & 1) == 0 &&
						buf != NULL && MmIsAddressValid(buf) && (ULONG64)buf > 0xFFFF000000000000ULL)
					{
						// Try to read first char
						WCHAR firstChar = buf[0];
						if (firstChar >= L'A' && firstChar <= L'z')
						{
							KdPrint((DRIVER_PREFIX "  Offset 0x%03X: Len=%u MaxLen=%u Buf=%p FirstChar='%C' <- LIKELY NAME\n",
								offset, len, maxLen, buf, firstChar));

							// Use this offset
							ANSI_STRING ansiName;
							ansiName.Buffer = info->FilterName;
							ansiName.Length = 0;
							ansiName.MaximumLength = MAX_FILTER_NAME_LENGTH - 1;
							RtlUnicodeStringToAnsiString(&ansiName, testStr, FALSE);
							foundName = TRUE;

							// Look for altitude at next UNICODE_STRING (typically +0x10)
							PUNICODE_STRING altStr = (PUNICODE_STRING)((PUCHAR)filter + offset + 0x10);
							if (MmIsAddressValid(altStr) && altStr->Length > 0 && altStr->Buffer && MmIsAddressValid(altStr->Buffer))
							{
								WCHAR altFirst = altStr->Buffer[0];
								if (altFirst >= L'0' && altFirst <= L'9')
								{
									KdPrint((DRIVER_PREFIX "  Offset 0x%03X: Altitude found, FirstChar='%C'\n", offset + 0x10, altFirst));
									ANSI_STRING ansiAlt;
									ansiAlt.Buffer = info->Altitude;
									ansiAlt.Length = 0;
									ansiAlt.MaximumLength = MAX_ALTITUDE_LENGTH - 1;
									RtlUnicodeStringToAnsiString(&ansiAlt, altStr, FALSE);
								}
							}
						}
					}
				}
			}

			if (!foundName)
			{
				KdPrint((DRIVER_PREFIX "  Could not find Name UNICODE_STRING\n"));
			}

			// Read flags
			info->Flags = *(PULONG)((PUCHAR)filter + FLT_FILTER_FLAGS_OFFSET);

			// Read frame ID from frame pointer
			PVOID framePtr = *(PVOID*)((PUCHAR)filter + FLT_FILTER_FRAME_OFFSET);
			if (framePtr && MmIsAddressValid(framePtr))
			{
				info->FrameId = *(PULONG)((PUCHAR)framePtr + FLTP_FRAME_FRAMEID_OFFSET);
			}

			// Get number of instances by walking instance list
			PLIST_ENTRY instanceListHead = (PLIST_ENTRY)((PUCHAR)filter + FLT_FILTER_INSTANCE_LIST_OFFSET);
			if (MmIsAddressValid(instanceListHead))
			{
				ULONG numInstances = 0;
				PLIST_ENTRY entry = instanceListHead->Flink;
				while (entry != instanceListHead && MmIsAddressValid(entry) && numInstances < 100)
				{
					numInstances++;
					entry = entry->Flink;
				}
				info->NumberOfInstances = numInstances;
			}

			// Read operation callbacks
			PFLT_OPERATION_REGISTRATION_INTERNAL ops = *(PFLT_OPERATION_REGISTRATION_INTERNAL*)((PUCHAR)filter + FLT_FILTER_OPERATIONS_OFFSET);
			if (ops && MmIsAddressValid(ops))
			{
				// Walk the operations array (terminated by IRP_MJ_OPERATION_END = 0x80)
				for (int j = 0; j < 50; j++)  // Limit iterations
				{
					if (!MmIsAddressValid(&ops[j]))
						break;
					if (ops[j].MajorFunction == 0x80)  // IRP_MJ_OPERATION_END
						break;

					ULONG64 preOp = (ULONG64)ops[j].PreOperation;
					ULONG64 postOp = (ULONG64)ops[j].PostOperation;

					switch (ops[j].MajorFunction)
					{
					case 0:  // IRP_MJ_CREATE
						info->Callbacks.PreCreate = preOp;
						info->Callbacks.PostCreate = postOp;
						break;
					case 3:  // IRP_MJ_READ
						info->Callbacks.PreRead = preOp;
						info->Callbacks.PostRead = postOp;
						break;
					case 4:  // IRP_MJ_WRITE
						info->Callbacks.PreWrite = preOp;
						info->Callbacks.PostWrite = postOp;
						break;
					case 6:  // IRP_MJ_SET_INFORMATION
						info->Callbacks.PreSetInfo = preOp;
						info->Callbacks.PostSetInfo = postOp;
						break;
					case 18: // IRP_MJ_CLEANUP
						info->Callbacks.PreCleanup = preOp;
						info->Callbacks.PostCleanup = postOp;
						break;
					}
				}
			}

			// Resolve owner module from filter address
			CallbackInformation tempInfo = { 0 };
			tempInfo.CallbackAddress = (ULONG64)filter;
			SearchLoadedModules(&tempInfo);
			RtlCopyMemory(info->OwnerModuleName, tempInfo.ModuleName, MAX_MODULE_NAME_LENGTH);

			KdPrint((DRIVER_PREFIX "Filter[%u]: %s (Alt: %s, Addr: 0x%llX, Instances: %u)\n",
				*count, info->FilterName, info->Altitude, info->FilterAddress, info->NumberOfInstances));

			(*count)++;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			KdPrint((DRIVER_PREFIX "Exception reading filter %u\n", i));
			continue;
		}
	}

	ExFreePoolWithTag(filterList, DRIVER_TAG);
	return TRUE;
}
