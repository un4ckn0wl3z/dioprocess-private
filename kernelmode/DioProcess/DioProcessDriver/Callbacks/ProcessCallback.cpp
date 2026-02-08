#include "pch.h"
#include "DioProcessGlobals.h"

// ============== Process Callback ==============

VOID OnProcessCallback(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);

	if (CreateInfo)
	{
		KdPrint((DRIVER_PREFIX "Process (%u) Created\n", HandleToUlong(ProcessId)));
		auto commandLineLength = 0;

		if (CreateInfo->CommandLine)
		{
			commandLineLength = CreateInfo->CommandLine->Length;
		}
		auto size = sizeof(FullEventData) + commandLineLength;
		auto item = (FullEventData*)ExAllocatePool2(
			POOL_FLAG_PAGED,
			size,
			DRIVER_TAG
		);

		if (item == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Out of memory\n"));
			return;
		}

		auto& header = item->Data.Header;
		KeQuerySystemTimePrecise((PLARGE_INTEGER)&header.Timestamp);
		header.Size = sizeof(EventHeader) + sizeof(ProcessCreateInfo) + commandLineLength;
		header.Type = EventType::ProcessCreate;

		auto& data = item->Data.ProcessCreate;
		data.ProcessId = HandleToULong(ProcessId);
		data.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
		data.CreatingProcessId = HandleToULong(CreateInfo->CreatingThreadId.UniqueProcess);
		data.CommandLineLength = commandLineLength / sizeof(WCHAR);
		if (commandLineLength)
		{
			memcpy(data.CommandLine, CreateInfo->CommandLine->Buffer, commandLineLength);
		}

		AddItem(item);
	}
	else
	{
		KdPrint((DRIVER_PREFIX "Process (%u) Exited\n", HandleToUlong(ProcessId)));
		auto size = sizeof(FullEventData);
		auto item = (FullEventData*)ExAllocatePool2(
			POOL_FLAG_PAGED | POOL_FLAG_UNINITIALIZED,
			size,
			DRIVER_TAG
		);

		if (item == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Out of memory\n"));
			return;
		}
		auto& header = item->Data.Header;
		KeQuerySystemTimePrecise((PLARGE_INTEGER)&header.Timestamp);
		header.Size = sizeof(EventHeader) + sizeof(ProcessExitInfo);
		header.Type = EventType::ProcessExit;

		auto& data = item->Data.ProcessExit;
		data.ProcessId = HandleToULong(ProcessId);
		data.ExitCode = PsGetProcessExitStatus(Process);

		AddItem(item);
	}
}
