#include "pch.h"
#include "DioProcessGlobals.h"
#include "../Injection/EarlyInjection.h"

// Helper function to check if image name ends with a pattern (case-insensitive)
static BOOLEAN ImageNameEndsWith(_In_ PUNICODE_STRING ImageName, _In_ PCWSTR Pattern)
{
	if (!ImageName || !ImageName->Buffer || !Pattern)
	{
		return FALSE;
	}

	UNICODE_STRING patternStr;
	RtlInitUnicodeString(&patternStr, Pattern);

	if (ImageName->Length < patternStr.Length)
	{
		return FALSE;
	}

	UNICODE_STRING suffix;
	suffix.Buffer = (PWCH)((PUCHAR)ImageName->Buffer + ImageName->Length - patternStr.Length);
	suffix.Length = patternStr.Length;
	suffix.MaximumLength = patternStr.Length;

	return RtlEqualUnicodeString(&suffix, &patternStr, TRUE);
}

// Helper function to check if process name matches target (for APC injection)
static BOOLEAN IsTargetProcess(_In_ HANDLE ProcessId)
{
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);
	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}

	WINDOWS_VERSION version = GetWindowsVersion();
	if (version == WINDOWS_UNSUPPORTED)
	{
		ObDereferenceObject(process);
		return FALSE;
	}

	// Get process name from EPROCESS.ImageFileName
	PCHAR imageName = (PCHAR)((ULONG_PTR)process + EPROCESS_IMAGEFILENAME_OFFSET[version]);

	// Get target name
	ExAcquireFastMutex(&g_EarlyInjectionState.Lock);
	BOOLEAN armed = g_EarlyInjectionState.Armed;
	WCHAR targetName[MAX_TARGET_PROCESS_NAME];
	RtlCopyMemory(targetName, g_EarlyInjectionState.TargetProcessName, sizeof(targetName));
	ExReleaseFastMutex(&g_EarlyInjectionState.Lock);

	if (!armed)
	{
		ObDereferenceObject(process);
		return FALSE;
	}

	// Convert target to ANSI for comparison
	CHAR targetAnsi[MAX_TARGET_PROCESS_NAME];
	UNICODE_STRING targetUnicode;
	ANSI_STRING targetAnsiStr;
	RtlInitUnicodeString(&targetUnicode, targetName);
	targetAnsiStr.Buffer = targetAnsi;
	targetAnsiStr.Length = 0;
	targetAnsiStr.MaximumLength = sizeof(targetAnsi);
	RtlUnicodeStringToAnsiString(&targetAnsiStr, &targetUnicode, FALSE);

	// Case-insensitive comparison
	BOOLEAN matches = (_stricmp(imageName, targetAnsi) == 0);

	ObDereferenceObject(process);
	return matches;
}

// ============== Image Load Callback ==============

VOID OnImageLoadCallback(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{
	// Check for early injection trigger (APC method) when kernel32.dll loads
	if (FullImageName && FullImageName->Buffer && !ImageInfo->SystemModeImage && ProcessId != 0)
	{
		// Check if this is kernel32.dll
		if (ImageNameEndsWith(FullImageName, L"\\kernel32.dll"))
		{
			// Check if we should inject
			ExAcquireFastMutex(&g_EarlyInjectionState.Lock);
			BOOLEAN armed = g_EarlyInjectionState.Armed;
			EarlyInjectionMethod method = g_EarlyInjectionState.Method;
			BOOLEAN oneShot = g_EarlyInjectionState.OneShot;
			ExReleaseFastMutex(&g_EarlyInjectionState.Lock);

			if (armed && method == EarlyInjectApcCallback)
			{
				// Check if this is our target process
				if (IsTargetProcess(ProcessId))
				{
					KdPrint((DRIVER_PREFIX "kernel32.dll loaded in target process PID %u, triggering APC injection\n",
						HandleToULong(ProcessId)));

					BOOLEAN success = EarlyInjectApc_Execute(ProcessId, ImageInfo->ImageBase);

					ExAcquireFastMutex(&g_EarlyInjectionState.Lock);
					if (success)
					{
						g_EarlyInjectionState.InjectionCount++;
						g_EarlyInjectionState.LastInjectedPid = HandleToULong(ProcessId);
						g_EarlyInjectionState.LastStatus = STATUS_SUCCESS;
						KdPrint((DRIVER_PREFIX "Early injection (APC) successful for PID %u\n",
							HandleToULong(ProcessId)));

						if (oneShot)
						{
							g_EarlyInjectionState.Armed = FALSE;
							KdPrint((DRIVER_PREFIX "One-shot mode: early injection disarmed\n"));
						}
					}
					else
					{
						g_EarlyInjectionState.LastStatus = STATUS_UNSUCCESSFUL;
						KdPrint((DRIVER_PREFIX "Early injection (APC) failed for PID %u\n",
							HandleToULong(ProcessId)));
					}
					ExReleaseFastMutex(&g_EarlyInjectionState.Lock);
				}
			}
		}
	}

	// Skip if no image name
	USHORT imageNameLength = 0;
	if (FullImageName && FullImageName->Buffer)
	{
		imageNameLength = FullImageName->Length;
	}

	auto size = sizeof(FullEventData) + imageNameLength;
	auto item = (FullEventData*)ExAllocatePool2(
		POOL_FLAG_PAGED,
		size,
		DRIVER_TAG
	);

	if (item == nullptr)
	{
		return;
	}

	auto& header = item->Data.Header;
	KeQuerySystemTimePrecise((PLARGE_INTEGER)&header.Timestamp);
	header.Size = sizeof(EventHeader) + sizeof(ImageLoadInfo) - sizeof(WCHAR) + imageNameLength;
	header.Type = EventType::ImageLoad;

	auto& data = item->Data.ImageLoad;
	data.ProcessId = HandleToULong(ProcessId);
	data.ImageBase = (ULONG64)ImageInfo->ImageBase;
	data.ImageSize = ImageInfo->ImageSize;
	data.IsSystemImage = ImageInfo->SystemModeImage ? TRUE : FALSE;
	data.IsKernelImage = (ProcessId == 0) ? TRUE : FALSE;
	data.ImageNameLength = imageNameLength / sizeof(WCHAR);

	if (imageNameLength > 0 && FullImageName->Buffer)
	{
		memcpy(data.ImageName, FullImageName->Buffer, imageNameLength);
	}

	AddItem(item);
}
