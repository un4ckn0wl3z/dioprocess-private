#include "pch.h"
#include "DioProcessGlobals.h"

// ============== Process Name Helper ==============

void GetProcessImageName(PEPROCESS Process, PUNICODE_STRING ImageName)
{
	// Use SeLocateProcessImageName if available (Windows Vista+)
	PUNICODE_STRING processName = nullptr;

	NTSTATUS status = SeLocateProcessImageName(Process, &processName);
	if (NT_SUCCESS(status) && processName)
	{
		// Copy just the filename portion
		PWCHAR lastSlash = wcsrchr(processName->Buffer, L'\\');
		if (lastSlash)
		{
			USHORT len = (USHORT)((processName->Length - ((PUCHAR)(lastSlash + 1) - (PUCHAR)processName->Buffer)));
			if (len <= ImageName->MaximumLength)
			{
				memcpy(ImageName->Buffer, lastSlash + 1, len);
				ImageName->Length = len;
			}
		}
		else
		{
			if (processName->Length <= ImageName->MaximumLength)
			{
				memcpy(ImageName->Buffer, processName->Buffer, processName->Length);
				ImageName->Length = processName->Length;
			}
		}
		ExFreePool(processName);
	}
}
