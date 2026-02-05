#include "pch.h"
#include "ProcessMonitorEx.h"
#include "Locker.h"

ProcessMonitorExState g_State;

VOID OnProcessCallback(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
	);


VOID OnThreadCallback(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
	);

void ProcessMonitorExUnload(PDRIVER_OBJECT DriverObject);

void AddItem(FullEventData* item);

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0);
NTSTATUS ProcessMonitorExCreateClose(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS ProcessMonitorExRead(PDEVICE_OBJECT, PIRP Irp);


extern "C" 
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
	NTSTATUS status;
	PDEVICE_OBJECT devObj = nullptr;
	bool symLinkCreated = false, procNotifyCreated = false, threadNotifyCreated = false;
	UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\ProcessMonitorEx");
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\ProcessMonitorEx");

	do
	{
		status = IoCreateDevice(
			DriverObject, 
			0, 
			&devName, 
			FILE_DEVICE_UNKNOWN, 
			0, 
			FALSE, 
			&devObj);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		devObj->Flags |= DO_DIRECT_IO;

		status = IoCreateSymbolicLink(&symName, &devName);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		symLinkCreated = true;

		status = PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, FALSE);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		procNotifyCreated = true;

		status = PsSetCreateThreadNotifyRoutine(OnThreadCallback);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		threadNotifyCreated = true;

	} while (false);

	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "ERROR in DriverEntry (0x%X)\n", status));
		if (devObj)
		{
			IoDeleteDevice(devObj);
		}
		if (symLinkCreated)
		{
			IoDeleteSymbolicLink(&symName);
		}
		if (procNotifyCreated)
		{
			PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, TRUE);
		}
		if (threadNotifyCreated)
		{
			PsRemoveCreateThreadNotifyRoutine(OnThreadCallback);
		}
		return status;
	}

	g_State.Lock.Init();
	InitializeListHead(&g_State.ItemsHead);

	DriverObject->DriverUnload = ProcessMonitorExUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = ProcessMonitorExCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = ProcessMonitorExRead;

	return status;
}

VOID OnProcessCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
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

	return VOID();
}

VOID OnThreadCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
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

void ProcessMonitorExUnload(PDRIVER_OBJECT DriverObject)
{
	PsRemoveCreateThreadNotifyRoutine(OnThreadCallback);
	PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, TRUE);
	UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\ProcessMonitorEx");
	IoDeleteSymbolicLink(&symName);
	IoDeleteDevice(DriverObject->DeviceObject);

	while (!IsListEmpty(&g_State.ItemsHead))
	{
		auto link = RemoveHeadList(&g_State.ItemsHead);
		ExFreePool(CONTAINING_RECORD(link, FullEventData, Link));
	}
}

void AddItem(FullEventData* item)
{
	Locker locker(g_State.Lock);
	InsertTailList(&g_State.ItemsHead, &item->Link);
	g_State.ItemCount++;
}

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR info)
{
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS ProcessMonitorExCreateClose(PDEVICE_OBJECT, PIRP Irp)
{
	return CompleteRequest(Irp);
}

NTSTATUS ProcessMonitorExRead(PDEVICE_OBJECT, PIRP Irp)
{
	auto irpSp = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;
	auto info = 0;
	do
	{
		auto len = irpSp->Parameters.Read.Length;
		if (len < sizeof(FullEventData))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		NT_ASSERT(Irp->MdlAddress);
		auto buffer = (PUCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		if (!buffer)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		Locker locker(g_State.Lock);
		while (!IsListEmpty(&g_State.ItemsHead))
		{
			auto link = g_State.ItemsHead.Flink;
			auto item = CONTAINING_RECORD(link, FullEventData, Link);
			auto size = item->Data.Header.Size;
			if (size > len)
			{
				break;
			}
			memcpy(buffer, &item->Data, size);
			buffer += size;
			len -= size;
			info += size;
			link = RemoveHeadList(&g_State.ItemsHead);
			ExFreePool(CONTAINING_RECORD(link, FullEventData, Link));
		}

	} while (false);

	return CompleteRequest(Irp, status, info);
}
