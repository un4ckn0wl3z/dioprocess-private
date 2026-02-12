#include "pch.h"
#include "DioProcessDriver.h"
#include "DioProcessGlobals.h"
#include <fltKernel.h>

// ============== Minifilter Enumeration & Unlink ==============
// Based on MKC (Minifilter Callback Killer) approach

// Callback node structure for minifilter operations
typedef struct _CALLBACK_NODE {
	LIST_ENTRY CallbackLinks;
	PFLT_INSTANCE Instance;
	union {
		PVOID PreOperation;
		PVOID GenerateFileName;
		PVOID NormalizeNameComponent;
		PVOID NormalizeNameComponentEx;
	};
	union {
		PVOID NormalizeContextCleanup;
		PVOID PostOperation;
	};
	ULONG64 Flags;
} CALLBACK_NODE, *PCALLBACK_NODE;

// System information class for module enumeration
typedef enum _SYSTEM_INFORMATION_CLASS_MM {
	SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS_MM;

typedef struct _RTL_PROCESS_MODULE_INFORMATION_MM {
	ULONG Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION_MM, *PRTL_PROCESS_MODULE_INFORMATION_MM;

typedef struct _RTL_PROCESS_MODULES_MM {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION_MM Modules[1];
} RTL_PROCESS_MODULES_MM, *PRTL_PROCESS_MODULES_MM;

typedef NTSTATUS(*PROTOTYPE_ZWQUERYSYSTEMINFORMATION)(
	SYSTEM_INFORMATION_CLASS_MM SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

// ZwQuerySystemInformation function pointer (resolved dynamically)
static PROTOTYPE_ZWQUERYSYSTEMINFORMATION g_pZwQuerySystemInformation = NULL;
static BOOLEAN g_ZwQueryResolved = FALSE;

// Resolve ZwQuerySystemInformation (needed for unlink)
static BOOLEAN ResolveZwQuerySystemInformation()
{
	if (g_ZwQueryResolved)
		return TRUE;

	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, L"ZwQuerySystemInformation");
	g_pZwQuerySystemInformation = (PROTOTYPE_ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&funcName);

	if (g_pZwQuerySystemInformation)
	{
		g_ZwQueryResolved = TRUE;
		return TRUE;
	}

	return FALSE;
}

// Safely read kernel memory by mapping physical address
static BOOLEAN ReadMemorySafe(PVOID TargetAddress, PVOID AllocatedBuffer, SIZE_T LengthToRead)
{
	PHYSICAL_ADDRESS PhysicalAddr = MmGetPhysicalAddress(TargetAddress);

	if (PhysicalAddr.QuadPart)
	{
		PVOID NewVirtualAddr = MmMapIoSpace(PhysicalAddr, LengthToRead, MmNonCached);
		if (NewVirtualAddr)
		{
			for (SIZE_T i = 0; i < LengthToRead; i++)
			{
				*(PUCHAR)((ULONG_PTR)AllocatedBuffer + i) = *(PUCHAR)((ULONG_PTR)NewVirtualAddr + i);
			}
			MmUnmapIoSpace(NewVirtualAddr, LengthToRead);
			return TRUE;
		}
	}

	return FALSE;
}

// Validate if a callback node belongs to a specific filter instance and driver
static BOOLEAN ValidatePotentialCallbackNode(PCALLBACK_NODE PotentialNode, PFLT_INSTANCE FltInstance, ULONG_PTR DriverStartAddr, ULONG DriverSize)
{
	if (PotentialNode->Instance != FltInstance)
		return FALSE;

	if (PotentialNode->PreOperation)
	{
		if (!((ULONG_PTR)PotentialNode->PreOperation > DriverStartAddr &&
		      (ULONG_PTR)PotentialNode->PreOperation < (DriverStartAddr + DriverSize)))
		{
			return FALSE;
		}
	}

	if (PotentialNode->PostOperation)
	{
		if (!((ULONG_PTR)PotentialNode->PostOperation > DriverStartAddr &&
		      (ULONG_PTR)PotentialNode->PostOperation < (DriverStartAddr + DriverSize)))
		{
			return FALSE;
		}
	}

	if (!PotentialNode->PreOperation && !PotentialNode->PostOperation)
		return FALSE;

	return TRUE;
}

// Helper to extract callbacks from FLT_FILTER's operations array
static void ExtractFilterCallbacks(PFLT_FILTER filter, MinifilterCallbacks* callbacks)
{
	__try
	{
		// FLT_FILTER operations pointer is at offset 0x0D8
		PVOID* pOperations = (PVOID*)((PUCHAR)filter + FLT_FILTER_OPERATIONS_OFFSET);

		KdPrint((DRIVER_PREFIX "Filter: 0x%llX, pOperations addr: 0x%llX\n", (ULONG64)filter, (ULONG64)pOperations));

		if (!MmIsAddressValid(pOperations))
		{
			KdPrint((DRIVER_PREFIX "pOperations address not valid\n"));
			return;
		}

		PVOID opsPtr = *pOperations;
		KdPrint((DRIVER_PREFIX "Operations pointer value: 0x%llX\n", (ULONG64)opsPtr));

		if (!opsPtr || !MmIsAddressValid(opsPtr))
		{
			KdPrint((DRIVER_PREFIX "Operations pointer is NULL or invalid\n"));
			return;
		}

		PFLT_OPERATION_REGISTRATION_INTERNAL ops = (PFLT_OPERATION_REGISTRATION_INTERNAL)opsPtr;

		// Walk the operations array (terminated by IRP_MJ_OPERATION_END = 0x80)
		for (ULONG i = 0; i < 50 && MmIsAddressValid(&ops[i]); i++)
		{
			UCHAR majorFunc = ops[i].MajorFunction;

			KdPrint((DRIVER_PREFIX "  Op[%u]: MajorFunc=0x%02X, Pre=0x%llX, Post=0x%llX\n",
				i, majorFunc, (ULONG64)ops[i].PreOperation, (ULONG64)ops[i].PostOperation));

			// IRP_MJ_OPERATION_END marks end of array
			if (majorFunc == 0x80)
				break;

			switch (majorFunc)
			{
			case IRP_MJ_CREATE: // 0
				callbacks->PreCreate = (ULONG64)ops[i].PreOperation;
				callbacks->PostCreate = (ULONG64)ops[i].PostOperation;
				break;
			case IRP_MJ_READ: // 3
				callbacks->PreRead = (ULONG64)ops[i].PreOperation;
				callbacks->PostRead = (ULONG64)ops[i].PostOperation;
				break;
			case IRP_MJ_WRITE: // 4
				callbacks->PreWrite = (ULONG64)ops[i].PreOperation;
				callbacks->PostWrite = (ULONG64)ops[i].PostOperation;
				break;
			case IRP_MJ_SET_INFORMATION: // 6
				callbacks->PreSetInfo = (ULONG64)ops[i].PreOperation;
				callbacks->PostSetInfo = (ULONG64)ops[i].PostOperation;
				break;
			case IRP_MJ_CLEANUP: // 18
				callbacks->PreCleanup = (ULONG64)ops[i].PreOperation;
				callbacks->PostCleanup = (ULONG64)ops[i].PostOperation;
				break;
			}
		}

		KdPrint((DRIVER_PREFIX "Final callbacks: PreCreate=0x%llX, PostCreate=0x%llX\n",
			callbacks->PreCreate, callbacks->PostCreate));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception extracting filter callbacks\n"));
	}
}

// Enumerate minifilters using Filter Manager APIs (linked against fltMgr.lib)
BOOLEAN EnumerateMinifiltersViaApi(MinifilterInfo* entries, ULONG* count, ULONG maxEntries)
{
	PFLT_FILTER* filterList = NULL;
	ULONG filterCount = 0;
	ULONG bufferSize = 0;

	// Get filter count
	NTSTATUS status = FltEnumerateFilters(NULL, 0, &filterCount);
	if (status != STATUS_BUFFER_TOO_SMALL || filterCount == 0)
	{
		KdPrint((DRIVER_PREFIX "No minifilters registered or error: 0x%08X\n", status));
		return FALSE;
	}

	KdPrint((DRIVER_PREFIX "Found %u minifilters\n", filterCount));

	// Allocate filter list
	bufferSize = filterCount * sizeof(PFLT_FILTER);
	filterList = (PFLT_FILTER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, DRIVER_TAG);
	if (!filterList)
	{
		KdPrint((DRIVER_PREFIX "Failed to allocate filter list\n"));
		return FALSE;
	}

	status = FltEnumerateFilters(filterList, bufferSize, &filterCount);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "FltEnumerateFilters failed: 0x%08X\n", status));
		ExFreePoolWithTag(filterList, DRIVER_TAG);
		return FALSE;
	}

	*count = 0;
	for (ULONG i = 0; i < filterCount && *count < maxEntries; i++)
	{
		PFLT_FILTER filter = filterList[i];
		PFILTER_AGGREGATE_BASIC_INFORMATION filterInfo = NULL;
		ULONG filterInfoSize = 0;
		ULONG filterInfoBufferSize = 0;

		// Get required buffer size
		status = FltGetFilterInformation(filter, FilterAggregateBasicInformation, NULL, 0, &filterInfoBufferSize);
		if (status != STATUS_BUFFER_TOO_SMALL)
		{
			continue;
		}

		// Allocate filter info buffer
		filterInfo = (PFILTER_AGGREGATE_BASIC_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, filterInfoBufferSize, DRIVER_TAG);
		if (!filterInfo)
		{
			continue;
		}

		// Get filter information
		status = FltGetFilterInformation(filter, FilterAggregateBasicInformation, filterInfo, filterInfoBufferSize, &filterInfoSize);
		if (!NT_SUCCESS(status))
		{
			ExFreePoolWithTag(filterInfo, DRIVER_TAG);
			continue;
		}

		MinifilterInfo* info = &entries[*count];
		RtlZeroMemory(info, sizeof(MinifilterInfo));
		info->Index = *count;
		info->FilterAddress = (ULONG64)filter;

		// Extract filter name
		PWCHAR filterNameAddr = (PWCHAR)((PCHAR)filterInfo + filterInfo->Type.MiniFilter.FilterNameBufferOffset);
		ULONG nameLen = filterInfo->Type.MiniFilter.FilterNameLength / sizeof(WCHAR);
		if (nameLen > MAX_FILTER_NAME_LENGTH - 1)
			nameLen = MAX_FILTER_NAME_LENGTH - 1;

		// Convert WCHAR name to ANSI
		UNICODE_STRING unicodeName;
		unicodeName.Buffer = filterNameAddr;
		unicodeName.Length = (USHORT)filterInfo->Type.MiniFilter.FilterNameLength;
		unicodeName.MaximumLength = unicodeName.Length;

		ANSI_STRING ansiName;
		ansiName.Buffer = info->FilterName;
		ansiName.Length = 0;
		ansiName.MaximumLength = MAX_FILTER_NAME_LENGTH - 1;
		RtlUnicodeStringToAnsiString(&ansiName, &unicodeName, FALSE);

		// Extract altitude
		PWCHAR altitudeAddr = (PWCHAR)((PCHAR)filterInfo + filterInfo->Type.MiniFilter.FilterAltitudeBufferOffset);
		ULONG altLen = filterInfo->Type.MiniFilter.FilterAltitudeLength / sizeof(WCHAR);
		if (altLen > MAX_ALTITUDE_LENGTH - 1)
			altLen = MAX_ALTITUDE_LENGTH - 1;

		UNICODE_STRING unicodeAltitude;
		unicodeAltitude.Buffer = altitudeAddr;
		unicodeAltitude.Length = (USHORT)filterInfo->Type.MiniFilter.FilterAltitudeLength;
		unicodeAltitude.MaximumLength = unicodeAltitude.Length;

		ANSI_STRING ansiAltitude;
		ansiAltitude.Buffer = info->Altitude;
		ansiAltitude.Length = 0;
		ansiAltitude.MaximumLength = MAX_ALTITUDE_LENGTH - 1;
		RtlUnicodeStringToAnsiString(&ansiAltitude, &unicodeAltitude, FALSE);

		// Get frame ID
		info->FrameId = filterInfo->Type.MiniFilter.FrameID;
		info->NumberOfInstances = filterInfo->Type.MiniFilter.NumberOfInstances;
		info->Flags = filterInfo->Flags;

		// Extract Pre/Post operation callbacks from FLT_FILTER structure
		ExtractFilterCallbacks(filter, &info->Callbacks);

		// Resolve owner module using one of the callback addresses (code address, not data)
		CallbackInformation tempInfo = { 0 };
		// Try PreCreate first, then PostCreate, then other callbacks
		if (info->Callbacks.PreCreate)
			tempInfo.CallbackAddress = info->Callbacks.PreCreate;
		else if (info->Callbacks.PostCreate)
			tempInfo.CallbackAddress = info->Callbacks.PostCreate;
		else if (info->Callbacks.PreRead)
			tempInfo.CallbackAddress = info->Callbacks.PreRead;
		else if (info->Callbacks.PreWrite)
			tempInfo.CallbackAddress = info->Callbacks.PreWrite;
		else
			tempInfo.CallbackAddress = (ULONG64)filter; // Fallback to filter address

		SearchLoadedModules(&tempInfo);
		RtlCopyMemory(info->OwnerModuleName, tempInfo.ModuleName, MAX_MODULE_NAME_LENGTH);

		KdPrint((DRIVER_PREFIX "Filter[%u]: %s (Alt: %s, Addr: 0x%llX, Instances: %u, PreCreate: 0x%llX)\n",
			*count, info->FilterName, info->Altitude, info->FilterAddress, info->NumberOfInstances, info->Callbacks.PreCreate));

		ExFreePoolWithTag(filterInfo, DRIVER_TAG);
		(*count)++;
	}

	ExFreePoolWithTag(filterList, DRIVER_TAG);
	return TRUE;
}

// Unlink minifilter callbacks by filter name
NTSTATUS UnlinkMinifilterCallbacks(const WCHAR* filterName)
{
	// Resolve ZwQuerySystemInformation for module enumeration
	if (!ResolveZwQuerySystemInformation())
	{
		KdPrint((DRIVER_PREFIX "ZwQuerySystemInformation not available for unlink\n"));
		return STATUS_NOT_SUPPORTED;
	}

	PFLT_FILTER* filterList = NULL;
	ULONG filterCount = 0;
	ULONG bufferSize = 0;

	KdPrint((DRIVER_PREFIX "Starting filter enumeration for unlink\n"));

	// Get filter count
	NTSTATUS status = FltEnumerateFilters(NULL, 0, &filterCount);
	if (status != STATUS_BUFFER_TOO_SMALL)
	{
		KdPrint((DRIVER_PREFIX "FltEnumerateFilters failed: 0x%08X\n", status));
		return status;
	}

	// Allocate filter list
	bufferSize = filterCount * sizeof(PFLT_FILTER);
	filterList = (PFLT_FILTER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, DRIVER_TAG);
	if (!filterList)
	{
		KdPrint((DRIVER_PREFIX "Memory allocation for filterList failed\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = FltEnumerateFilters(filterList, bufferSize, &filterCount);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "FltEnumerateFilters failed on second call: 0x%08X\n", status));
		ExFreePoolWithTag(filterList, DRIVER_TAG);
		return status;
	}

	// Find target filter
	PFLT_FILTER targetFilter = NULL;

	for (ULONG i = 0; i < filterCount; i++)
	{
		PFLT_FILTER filter = filterList[i];
		PFILTER_AGGREGATE_BASIC_INFORMATION filterInfo = NULL;
		ULONG filterInfoBufferSize = 0;

		status = FltGetFilterInformation(filter, FilterAggregateBasicInformation, NULL, 0, &filterInfoBufferSize);
		if (status != STATUS_BUFFER_TOO_SMALL)
		{
			continue;
		}

		filterInfo = (PFILTER_AGGREGATE_BASIC_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, filterInfoBufferSize, DRIVER_TAG);
		if (!filterInfo)
		{
			continue;
		}

		ULONG filterInfoSize = 0;
		status = FltGetFilterInformation(filter, FilterAggregateBasicInformation, filterInfo, filterInfoBufferSize, &filterInfoSize);
		if (!NT_SUCCESS(status))
		{
			ExFreePoolWithTag(filterInfo, DRIVER_TAG);
			continue;
		}

		// Extract and compare filter name
		PWCHAR nameAddr = (PWCHAR)((PCHAR)filterInfo + filterInfo->Type.MiniFilter.FilterNameBufferOffset);
		WCHAR baseFilterName[256] = { 0 };
		ULONG nameLen = min(filterInfo->Type.MiniFilter.FilterNameLength / sizeof(WCHAR), 255);
		wcsncpy(baseFilterName, nameAddr, nameLen);
		baseFilterName[nameLen] = L'\0';

		KdPrint((DRIVER_PREFIX "Comparing %ws with %ws\n", baseFilterName, filterName));
		if (wcscmp(baseFilterName, filterName) == 0)
		{
			targetFilter = filter;
		}

		ExFreePoolWithTag(filterInfo, DRIVER_TAG);
		if (targetFilter)
		{
			break;
		}
	}

	if (!targetFilter)
	{
		KdPrint((DRIVER_PREFIX "Target filter not found: %ws\n", filterName));
		ExFreePoolWithTag(filterList, DRIVER_TAG);
		return STATUS_NOT_FOUND;
	}

	// Enumerate instances for target filter
	PFLT_INSTANCE* instanceList = NULL;
	ULONG instanceCount = 0;
	bufferSize = 0;

	KdPrint((DRIVER_PREFIX "Starting instance enumeration for filter: %ws\n", filterName));

	status = FltEnumerateInstances(NULL, targetFilter, NULL, 0, &instanceCount);
	if (status != STATUS_BUFFER_TOO_SMALL)
	{
		KdPrint((DRIVER_PREFIX "FltEnumerateInstances failed: 0x%08X\n", status));
		ExFreePoolWithTag(filterList, DRIVER_TAG);
		return status;
	}

	bufferSize = instanceCount * sizeof(PFLT_INSTANCE);
	instanceList = (PFLT_INSTANCE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, DRIVER_TAG);
	if (!instanceList)
	{
		KdPrint((DRIVER_PREFIX "Memory allocation for instanceList failed\n"));
		ExFreePoolWithTag(filterList, DRIVER_TAG);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = FltEnumerateInstances(NULL, targetFilter, instanceList, bufferSize, &instanceCount);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "FltEnumerateInstances failed on second call: 0x%08X\n", status));
		ExFreePoolWithTag(filterList, DRIVER_TAG);
		ExFreePoolWithTag(instanceList, DRIVER_TAG);
		return status;
	}

	KdPrint((DRIVER_PREFIX "Found %lu instances for filter: %ws\n", instanceCount, filterName));

	// Get system module information
	PRTL_PROCESS_MODULES_MM moduleInformation = NULL;
	ULONG sizeNeeded = 0;
	SIZE_T infoRegionSize = 0;

	status = g_pZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &sizeNeeded);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		ExFreePoolWithTag(filterList, DRIVER_TAG);
		ExFreePoolWithTag(instanceList, DRIVER_TAG);
		KdPrint((DRIVER_PREFIX "ZwQuerySystemInformation failed to get size: 0x%08X\n", status));
		return status;
	}

	infoRegionSize = sizeNeeded;
	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		infoRegionSize += 0x1000;
		moduleInformation = (PRTL_PROCESS_MODULES_MM)ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, infoRegionSize, DRIVER_TAG);
		if (!moduleInformation)
		{
			ExFreePoolWithTag(filterList, DRIVER_TAG);
			ExFreePoolWithTag(instanceList, DRIVER_TAG);
			KdPrint((DRIVER_PREFIX "Memory allocation for moduleInformation failed\n"));
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		status = g_pZwQuerySystemInformation(SystemModuleInformation, moduleInformation, (ULONG)infoRegionSize, &sizeNeeded);
		if (!NT_SUCCESS(status))
		{
			ExFreePoolWithTag(moduleInformation, DRIVER_TAG);
			moduleInformation = NULL;
		}
	}

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(filterList, DRIVER_TAG);
		ExFreePoolWithTag(instanceList, DRIVER_TAG);
		KdPrint((DRIVER_PREFIX "ZwQuerySystemInformation failed: 0x%08X\n", status));
		return status;
	}

	// Unlink callback nodes for each instance
	ULONG unlinkedCount = 0;
	for (ULONG i = 0; i < instanceCount; i++)
	{
		PFLT_INSTANCE currentInstance = instanceList[i];

		// Allocate buffer for instance memory
		PFLT_INSTANCE instanceVa = (PFLT_INSTANCE)ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x230, DRIVER_TAG);
		if (!instanceVa)
		{
			KdPrint((DRIVER_PREFIX "Memory allocation for instanceVa failed\n"));
			continue;
		}

		// Safely read instance memory
		if (!ReadMemorySafe((PVOID)currentInstance, (PVOID)instanceVa, 0x230))
		{
			KdPrint((DRIVER_PREFIX "ReadMemorySafe failed\n"));
			ExFreePoolWithTag(instanceVa, DRIVER_TAG);
			continue;
		}

		// Scan memory for potential callback nodes
		for (ULONG x = 0; x < 0x230; x++)
		{
			ULONG_PTR potentialPointer = *(PULONG_PTR)((ULONG_PTR)instanceVa + x);
			PCALLBACK_NODE potentialNode = (PCALLBACK_NODE)potentialPointer;

			if (MmIsAddressValid(potentialNode))
			{
				// Validate against each loaded module
				for (ULONG j = 0; j < moduleInformation->NumberOfModules; j++)
				{
					PRTL_PROCESS_MODULE_INFORMATION_MM driverModule = &moduleInformation->Modules[j];

					if (ValidatePotentialCallbackNode(potentialNode, currentInstance, (ULONG_PTR)driverModule->ImageBase, driverModule->ImageSize))
					{
						KdPrint((DRIVER_PREFIX "Found callback node for filter: %ws\n", filterName));

						// Unlink the callback node from the linked list
						ULONG_PTR prevNodeAddress = *(PULONG_PTR)((ULONG_PTR)&potentialNode->CallbackLinks + FIELD_OFFSET(LIST_ENTRY, Blink));
						ULONG_PTR nextNodeAddress = *(PULONG_PTR)((ULONG_PTR)&potentialNode->CallbackLinks + FIELD_OFFSET(LIST_ENTRY, Flink));
						*(PULONG_PTR)(nextNodeAddress + FIELD_OFFSET(LIST_ENTRY, Blink)) = prevNodeAddress;
						*(PULONG_PTR)(prevNodeAddress + FIELD_OFFSET(LIST_ENTRY, Flink)) = nextNodeAddress;

						KdPrint((DRIVER_PREFIX "Successfully unlinked callback for filter: %ws\n", filterName));
						unlinkedCount++;
					}
				}
			}
		}

		ExFreePoolWithTag(instanceVa, DRIVER_TAG);
	}

	KdPrint((DRIVER_PREFIX "Unlinked %lu callbacks for filter: %ws\n", unlinkedCount, filterName));

	// Cleanup
	ExFreePoolWithTag(filterList, DRIVER_TAG);
	ExFreePoolWithTag(instanceList, DRIVER_TAG);
	ExFreePoolWithTag(moduleInformation, DRIVER_TAG);

	return STATUS_SUCCESS;
}
