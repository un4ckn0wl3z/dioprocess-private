#include "pch.h"
#include "DioProcessGlobals.h"

// ============== Thread Callback ==============

VOID OnThreadCallback(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
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

	if (Create)
	{
		header.Size = sizeof(EventHeader) + sizeof(ThreadCreateInfo);
		header.Type = EventType::ThreadCreate;

		auto& data = item->Data.ThreadCreate;
		data.ProcessId = HandleToULong(ProcessId);
		data.ThreadId = HandleToULong(ThreadId);
	}
	else
	{
		header.Size = sizeof(EventHeader) + sizeof(ThreadExitInfo);
		header.Type = EventType::ThreadExit;

		auto& data = item->Data.ThreadExit;
		data.ProcessId = HandleToULong(ProcessId);
		data.ThreadId = HandleToULong(ThreadId);

		PETHREAD thread;
		NTSTATUS status = PsLookupThreadByThreadId(ThreadId, &thread);

		if (NT_SUCCESS(status))
		{
			data.ExitCode = PsGetThreadExitStatus(thread);
			ObDereferenceObject(thread);
		}
	}

	AddItem(item);
}
