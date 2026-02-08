#include "pch.h"
#include "DioProcessGlobals.h"

// ============== Image Load Callback ==============

VOID OnImageLoadCallback(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{
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
