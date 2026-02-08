#include "pch.h"
#include "DioProcessGlobals.h"

// ============== Callback Enumeration Helper Functions ==============

//
// Helper function to resolve a callback address to its owning module
//
void SearchLoadedModules(CallbackInformation* CallbackInfo)
{
	if (!CallbackInfo || CallbackInfo->CallbackAddress == 0)
		return;

	NTSTATUS status = AuxKlibInitialize();
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "AuxKlibInitialize failed (0x%X)\n", status));
		return;
	}

	ULONG bufferSize = 0;

	// First call to get required buffer size
	status = AuxKlibQueryModuleInformation(&bufferSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
	if (!NT_SUCCESS(status) || bufferSize == 0)
	{
		KdPrint((DRIVER_PREFIX "AuxKlibQueryModuleInformation failed to get size (0x%X)\n", status));
		return;
	}

	// Allocate memory
	AUX_MODULE_EXTENDED_INFO* modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePool2(
		POOL_FLAG_PAGED,
		bufferSize,
		DRIVER_TAG);

	if (!modules)
	{
		KdPrint((DRIVER_PREFIX "Failed to allocate memory for module info\n"));
		return;
	}

	RtlZeroMemory(modules, bufferSize);

	// Second call to get the actual module info
	status = AuxKlibQueryModuleInformation(&bufferSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "AuxKlibQueryModuleInformation failed (0x%X)\n", status));
		ExFreePoolWithTag(modules, DRIVER_TAG);
		return;
	}

	// Iterate over each module
	ULONG numberOfModules = bufferSize / sizeof(AUX_MODULE_EXTENDED_INFO);

	// Suppress false positive: buffer size is correctly validated
#pragma warning(push)
#pragma warning(disable: 6385)
	for (ULONG i = 0; i < numberOfModules; i++)
	{
		ULONG64 startAddress = (ULONG64)modules[i].BasicInfo.ImageBase;
		ULONG imageSize = modules[i].ImageSize;
		ULONG64 endAddress = startAddress + imageSize;

		// Check if callback address falls within this module's range
		if (CallbackInfo->CallbackAddress >= startAddress && CallbackInfo->CallbackAddress < endAddress)
		{
			// Copy module name (just the filename part)
			const char* fullPath = (const char*)(modules[i].FullPathName + modules[i].FileNameOffset);
			strncpy_s(CallbackInfo->ModuleName, MAX_MODULE_NAME_LENGTH, fullPath, _TRUNCATE);

			KdPrint((DRIVER_PREFIX "Resolved 0x%llX to %s (base=0x%llX size=0x%X)\n",
				CallbackInfo->CallbackAddress, CallbackInfo->ModuleName, startAddress, imageSize));
			break;
		}
	}
#pragma warning(pop)

	ExFreePoolWithTag(modules, DRIVER_TAG);
}

//
// Generic pattern-matcher to find kernel callback arrays
// Uses the exported notify routine function to find the internal array
//
ULONG64 FindCallbackArray(const WCHAR* ExportedFunctionName)
{
	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, ExportedFunctionName);

	ULONG64 exportedFunction = (ULONG64)MmGetSystemRoutineAddress(&funcName);
	if (exportedFunction == 0)
	{
		KdPrint((DRIVER_PREFIX "Failed to find %wZ\n", &funcName));
		return 0;
	}

	KdPrint((DRIVER_PREFIX "%wZ found @ 0x%llX\n", &funcName, exportedFunction));

	const UCHAR OPCODE_CALL = 0xE8;
	const UCHAR OPCODE_JMP = 0xE9;
	const UCHAR OPCODE_LEA = 0x8D;

	ULONG64 internalFunction = 0;
	LONG offset = 0;

	// Search for CALL/JMP in first 0x50 bytes
	for (ULONG64 i = exportedFunction; i < exportedFunction + 0x50; i++)
	{
		UCHAR opcode = *(PUCHAR)i;
		if (opcode == OPCODE_CALL || opcode == OPCODE_JMP)
		{
			RtlCopyMemory(&offset, (PUCHAR)(i + 1), 4);
			internalFunction = i + offset + 5;
			break;
		}
	}

	if (internalFunction == 0)
	{
		KdPrint((DRIVER_PREFIX "Failed to find internal function for %wZ\n", &funcName));
		return 0;
	}

	// Search for LEA instruction referencing the callback array
	offset = 0;
	for (ULONG64 i = internalFunction; i < internalFunction + 0x100; i++)
	{
		if ((*(PUCHAR)i == 0x4C && *(PUCHAR)(i + 1) == OPCODE_LEA) ||
			(*(PUCHAR)i == 0x48 && *(PUCHAR)(i + 1) == OPCODE_LEA))
		{
			RtlCopyMemory(&offset, (PUCHAR)(i + 3), 4);
			ULONG64 arrayAddress = i + offset + 7;
			KdPrint((DRIVER_PREFIX "%wZ array found @ 0x%llX\n", &funcName, arrayAddress));
			return arrayAddress;
		}
	}

	KdPrint((DRIVER_PREFIX "Failed to find callback array for %wZ\n", &funcName));
	return 0;
}

//
// Pattern-match to find PspSetCreateProcessNotifyRoutine array
// WARNING: Version-specific, may fail on untested Windows versions
//
ULONG64 FindPspSetCreateProcessNotifyRoutine(WINDOWS_VERSION WindowsVersion)
{
	UNREFERENCED_PARAMETER(WindowsVersion);
	return FindCallbackArray(L"PsSetCreateProcessNotifyRoutineEx");
}

ULONG64 FindPspCreateThreadNotifyRoutine(WINDOWS_VERSION WindowsVersion)
{
	UNREFERENCED_PARAMETER(WindowsVersion);
	return FindCallbackArray(L"PsSetCreateThreadNotifyRoutine");
}

ULONG64 FindPspLoadImageNotifyRoutine(WINDOWS_VERSION WindowsVersion)
{
	UNREFERENCED_PARAMETER(WindowsVersion);
	return FindCallbackArray(L"PsSetLoadImageNotifyRoutine");
}
