#include "pch.h"
#include "DioProcessGlobals.h"

// ============== Kernel Driver Enumeration ==============

// PsLoadedModuleList is exported but not declared in headers
extern "C" NTKERNELAPI PLIST_ENTRY PsLoadedModuleList;

// Enumerate loaded kernel drivers from PsLoadedModuleList
BOOLEAN EnumerateKernelDrivers(
	KernelDriverInfo* entries,
	ULONG* count,
	ULONG maxEntries
)
{
	*count = 0;

	if (!PsLoadedModuleList)
	{
		KdPrint((DRIVER_PREFIX "PsLoadedModuleList is NULL\n"));
		return FALSE;
	}

	// PsLoadedModuleList is a LIST_ENTRY that links KLDR_DATA_TABLE_ENTRY structures
	// We need to acquire the loader lock to safely walk this list
	// However, for read-only enumeration we can use __try/__except

	KdPrint((DRIVER_PREFIX "Enumerating kernel drivers from PsLoadedModuleList=%p\n", PsLoadedModuleList));

	__try
	{
		PLIST_ENTRY listHead = PsLoadedModuleList;
		PLIST_ENTRY entry = listHead->Flink;

		while (entry != listHead && *count < maxEntries)
		{
			if (!MmIsAddressValid(entry))
			{
				KdPrint((DRIVER_PREFIX "Invalid list entry at %p\n", entry));
				break;
			}

			// Get the KLDR_DATA_TABLE_ENTRY from the list entry
			PKLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (!MmIsAddressValid(ldrEntry))
			{
				entry = entry->Flink;
				continue;
			}

			KernelDriverInfo* info = &entries[*count];
			RtlZeroMemory(info, sizeof(KernelDriverInfo));
			info->Index = *count;

			__try
			{
				// Read basic info
				info->BaseAddress = (ULONG64)ldrEntry->DllBase;
				info->Size = ldrEntry->SizeOfImage;
				info->EntryPoint = (ULONG64)ldrEntry->EntryPoint;
				info->Flags = ldrEntry->Flags;
				info->LoadCount = ldrEntry->LoadCount;

				// Read driver name (BaseDllName)
				if (ldrEntry->BaseDllName.Buffer &&
					ldrEntry->BaseDllName.Length > 0 &&
					MmIsAddressValid(ldrEntry->BaseDllName.Buffer))
				{
					// Convert to ANSI for DriverName
					ANSI_STRING ansiName;
					ansiName.Buffer = info->DriverName;
					ansiName.Length = 0;
					ansiName.MaximumLength = MAX_DRIVER_NAME_LENGTH - 1;
					RtlUnicodeStringToAnsiString(&ansiName, &ldrEntry->BaseDllName, FALSE);
				}

				// Read full path (FullDllName)
				if (ldrEntry->FullDllName.Buffer &&
					ldrEntry->FullDllName.Length > 0 &&
					MmIsAddressValid(ldrEntry->FullDllName.Buffer))
				{
					USHORT copyLen = ldrEntry->FullDllName.Length;
					if (copyLen > (MAX_DRIVER_PATH_LENGTH - 1) * sizeof(WCHAR))
						copyLen = (MAX_DRIVER_PATH_LENGTH - 1) * sizeof(WCHAR);
					RtlCopyMemory(info->DriverPath, ldrEntry->FullDllName.Buffer, copyLen);
					info->DriverPath[copyLen / sizeof(WCHAR)] = L'\0';
				}

				if (*count < 5)
				{
					KdPrint((DRIVER_PREFIX "Driver[%u]: %s @ 0x%llX (size=0x%llX)\n",
						*count, info->DriverName, info->BaseAddress, info->Size));
				}

				(*count)++;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				KdPrint((DRIVER_PREFIX "Exception reading driver entry at %p\n", ldrEntry));
			}

			entry = entry->Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception walking PsLoadedModuleList (code=0x%X)\n", GetExceptionCode()));
		return FALSE;
	}

	KdPrint((DRIVER_PREFIX "Found %u loaded drivers\n", *count));
	return TRUE;
}
