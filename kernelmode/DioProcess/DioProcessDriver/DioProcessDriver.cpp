#include "pch.h"
#include "DioProcessDriver.h"
#include "Locker.h"

DioProcessState g_State;
PVOID g_ObCallbackHandle = nullptr;
LARGE_INTEGER g_RegistryCookie = { 0 };

// Forward declarations
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

VOID OnImageLoadCallback(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
);

OB_PREOP_CALLBACK_STATUS OnPreProcessHandleOperation(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION OperationInfo
);

OB_PREOP_CALLBACK_STATUS OnPreThreadHandleOperation(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION OperationInfo
);

NTSTATUS OnRegistryCallback(
	_In_ PVOID CallbackContext,
	_In_opt_ PVOID Argument1,
	_In_opt_ PVOID Argument2
);

void DioProcessUnload(PDRIVER_OBJECT DriverObject);
void AddItem(FullEventData* item);

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0);
NTSTATUS DioProcessCreateClose(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS DioProcessRead(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS DioProcessDeviceControl(PDEVICE_OBJECT, PIRP Irp);

// Helper function to get process name
void GetProcessImageName(PEPROCESS Process, PUNICODE_STRING ImageName);

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;
	PDEVICE_OBJECT devObj = nullptr;
	bool symLinkCreated = false;
	bool procNotifyCreated = false;
	bool threadNotifyCreated = false;
	bool imageNotifyCreated = false;
	bool obCallbackCreated = false;
	bool registryCallbackCreated = false;

	UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\DioProcess");
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\DioProcess");

	do
	{
		// Create device
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
			KdPrint((DRIVER_PREFIX "Failed to create device (0x%X)\n", status));
			break;
		}
		devObj->Flags |= DO_DIRECT_IO;

		// Create symbolic link
		status = IoCreateSymbolicLink(&symName, &devName);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to create symbolic link (0x%X)\n", status));
			break;
		}
		symLinkCreated = true;

		// Register process callback
		status = PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, FALSE);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to register process callback (0x%X)\n", status));
			break;
		}
		procNotifyCreated = true;
		KdPrint((DRIVER_PREFIX "Process callback registered\n"));

		// Register thread callback
		status = PsSetCreateThreadNotifyRoutine(OnThreadCallback);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to register thread callback (0x%X)\n", status));
			break;
		}
		threadNotifyCreated = true;
		KdPrint((DRIVER_PREFIX "Thread callback registered\n"));

		// Register image load callback
		status = PsSetLoadImageNotifyRoutine(OnImageLoadCallback);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to register image load callback (0x%X)\n", status));
			break;
		}
		imageNotifyCreated = true;
		KdPrint((DRIVER_PREFIX "Image load callback registered\n"));

		// Register Object Manager callbacks for process and thread handle operations
		OB_CALLBACK_REGISTRATION obCallbackReg = { 0 };
		OB_OPERATION_REGISTRATION obOpReg[2] = { 0 };

		obOpReg[0].ObjectType = PsProcessType;
		obOpReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		obOpReg[0].PreOperation = OnPreProcessHandleOperation;
		obOpReg[0].PostOperation = nullptr;

		obOpReg[1].ObjectType = PsThreadType;
		obOpReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		obOpReg[1].PreOperation = OnPreThreadHandleOperation;
		obOpReg[1].PostOperation = nullptr;

		UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"321000");
		obCallbackReg.Version = OB_FLT_REGISTRATION_VERSION;
		obCallbackReg.OperationRegistrationCount = 2;
		obCallbackReg.Altitude = altitude;
		obCallbackReg.RegistrationContext = nullptr;
		obCallbackReg.OperationRegistration = obOpReg;

		status = ObRegisterCallbacks(&obCallbackReg, &g_ObCallbackHandle);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to register OB callbacks (0x%X)\n", status));
			// Don't fail driver load, just continue without OB callbacks
			status = STATUS_SUCCESS;
		}
		else
		{
			obCallbackCreated = true;
			KdPrint((DRIVER_PREFIX "Object Manager callbacks registered\n"));
		}

		// Register registry callback
		UNICODE_STRING regAltitude = RTL_CONSTANT_STRING(L"321001");
		status = CmRegisterCallbackEx(OnRegistryCallback, &regAltitude, DriverObject, nullptr, &g_RegistryCookie, nullptr);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to register registry callback (0x%X)\n", status));
			// Don't fail driver load, just continue without registry callbacks
			status = STATUS_SUCCESS;
		}
		else
		{
			registryCallbackCreated = true;
			KdPrint((DRIVER_PREFIX "Registry callback registered\n"));
		}

	} while (false);

	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "ERROR in DriverEntry (0x%X)\n", status));

		if (registryCallbackCreated)
		{
			CmUnRegisterCallback(g_RegistryCookie);
		}
		if (obCallbackCreated)
		{
			ObUnRegisterCallbacks(g_ObCallbackHandle);
		}
		if (imageNotifyCreated)
		{
			PsRemoveLoadImageNotifyRoutine(OnImageLoadCallback);
		}
		if (threadNotifyCreated)
		{
			PsRemoveCreateThreadNotifyRoutine(OnThreadCallback);
		}
		if (procNotifyCreated)
		{
			PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, TRUE);
		}
		if (symLinkCreated)
		{
			IoDeleteSymbolicLink(&symName);
		}
		if (devObj)
		{
			IoDeleteDevice(devObj);
		}
		return status;
	}

	g_State.Lock.Init();
	InitializeListHead(&g_State.ItemsHead);
	g_State.CollectionEnabled = FALSE;  // Collection disabled by default

	DriverObject->DriverUnload = DioProcessUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = DioProcessCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = DioProcessRead;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DioProcessDeviceControl;

	KdPrint((DRIVER_PREFIX "Driver loaded successfully\n"));
	return STATUS_SUCCESS;
}

// ============== Process Callback ==============

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
}

// ============== Thread Callback ==============

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

// ============== Object Manager Callbacks ==============

OB_PREOP_CALLBACK_STATUS OnPreProcessHandleOperation(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION OperationInfo
)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	// Skip kernel mode callers to reduce noise
	if (OperationInfo->KernelHandle)
	{
		return OB_PREOP_SUCCESS;
	}

	PEPROCESS targetProcess = (PEPROCESS)OperationInfo->Object;
	HANDLE targetPid = PsGetProcessId(targetProcess);
	HANDLE sourcePid = PsGetCurrentProcessId();

	// Skip self-access
	if (targetPid == sourcePid)
	{
		return OB_PREOP_SUCCESS;
	}

	// Get source process name
	PEPROCESS sourceProcess = PsGetCurrentProcess();
	UNICODE_STRING sourceName = { 0 };
	WCHAR sourceNameBuffer[260] = { 0 };
	sourceName.Buffer = sourceNameBuffer;
	sourceName.MaximumLength = sizeof(sourceNameBuffer);
	GetProcessImageName(sourceProcess, &sourceName);

	USHORT nameLength = sourceName.Length;
	auto size = sizeof(FullEventData) + nameLength;
	auto item = (FullEventData*)ExAllocatePool2(
		POOL_FLAG_PAGED,
		size,
		DRIVER_TAG
	);

	if (item == nullptr)
	{
		return OB_PREOP_SUCCESS;
	}

	auto& header = item->Data.Header;
	KeQuerySystemTimePrecise((PLARGE_INTEGER)&header.Timestamp);

	EventType eventType = (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE)
		? EventType::ProcessHandleCreate
		: EventType::ProcessHandleDuplicate;

	header.Size = sizeof(EventHeader) + sizeof(HandleOperationInfo) - sizeof(WCHAR) + nameLength;
	header.Type = eventType;

	auto& data = item->Data.HandleOperation;
	data.SourceProcessId = HandleToULong(sourcePid);
	data.SourceThreadId = HandleToULong(PsGetCurrentThreadId());
	data.TargetProcessId = HandleToULong(targetPid);
	data.TargetThreadId = 0;
	data.DesiredAccess = OperationInfo->Parameters->CreateHandleInformation.DesiredAccess;
	data.GrantedAccess = OperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess;
	data.IsKernelHandle = OperationInfo->KernelHandle;
	data.SourceImageNameLength = nameLength / sizeof(WCHAR);

	if (nameLength > 0)
	{
		memcpy(data.SourceImageName, sourceName.Buffer, nameLength);
	}

	AddItem(item);

	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS OnPreThreadHandleOperation(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION OperationInfo
)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	// Skip kernel mode callers to reduce noise
	if (OperationInfo->KernelHandle)
	{
		return OB_PREOP_SUCCESS;
	}

	PETHREAD targetThread = (PETHREAD)OperationInfo->Object;
	HANDLE targetTid = PsGetThreadId(targetThread);
	PEPROCESS targetProcess = IoThreadToProcess(targetThread);
	HANDLE targetPid = PsGetProcessId(targetProcess);
	HANDLE sourcePid = PsGetCurrentProcessId();

	// Skip self-access
	if (targetPid == sourcePid)
	{
		return OB_PREOP_SUCCESS;
	}

	// Get source process name
	PEPROCESS sourceProcess = PsGetCurrentProcess();
	UNICODE_STRING sourceName = { 0 };
	WCHAR sourceNameBuffer[260] = { 0 };
	sourceName.Buffer = sourceNameBuffer;
	sourceName.MaximumLength = sizeof(sourceNameBuffer);
	GetProcessImageName(sourceProcess, &sourceName);

	USHORT nameLength = sourceName.Length;
	auto size = sizeof(FullEventData) + nameLength;
	auto item = (FullEventData*)ExAllocatePool2(
		POOL_FLAG_PAGED,
		size,
		DRIVER_TAG
	);

	if (item == nullptr)
	{
		return OB_PREOP_SUCCESS;
	}

	auto& header = item->Data.Header;
	KeQuerySystemTimePrecise((PLARGE_INTEGER)&header.Timestamp);

	EventType eventType = (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE)
		? EventType::ThreadHandleCreate
		: EventType::ThreadHandleDuplicate;

	header.Size = sizeof(EventHeader) + sizeof(HandleOperationInfo) - sizeof(WCHAR) + nameLength;
	header.Type = eventType;

	auto& data = item->Data.HandleOperation;
	data.SourceProcessId = HandleToULong(sourcePid);
	data.SourceThreadId = HandleToULong(PsGetCurrentThreadId());
	data.TargetProcessId = HandleToULong(targetPid);
	data.TargetThreadId = HandleToULong(targetTid);
	data.DesiredAccess = OperationInfo->Parameters->CreateHandleInformation.DesiredAccess;
	data.GrantedAccess = OperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess;
	data.IsKernelHandle = OperationInfo->KernelHandle;
	data.SourceImageNameLength = nameLength / sizeof(WCHAR);

	if (nameLength > 0)
	{
		memcpy(data.SourceImageName, sourceName.Buffer, nameLength);
	}

	AddItem(item);

	return OB_PREOP_SUCCESS;
}

// ============== Registry Callback ==============

NTSTATUS OnRegistryCallback(
	_In_ PVOID CallbackContext,
	_In_opt_ PVOID Argument1,
	_In_opt_ PVOID Argument2
)
{
	UNREFERENCED_PARAMETER(CallbackContext);

	if (Argument1 == nullptr || Argument2 == nullptr)
	{
		return STATUS_SUCCESS;
	}

	REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
	EventType eventType;
	RegistryOperation regOp;
	PCUNICODE_STRING keyName = nullptr;
	PCUNICODE_STRING valueName = nullptr;

	// Only handle specific operations to reduce noise
	switch (notifyClass)
	{
	case RegNtPreCreateKeyEx:
	{
		auto info = (PREG_CREATE_KEY_INFORMATION)Argument2;
		eventType = EventType::RegistryCreate;
		regOp = RegistryOperation::CreateKey;
		keyName = info->CompleteName;
		break;
	}
	case RegNtPreOpenKeyEx:
	{
		auto info = (PREG_OPEN_KEY_INFORMATION)Argument2;
		eventType = EventType::RegistryOpen;
		regOp = RegistryOperation::OpenKey;
		keyName = info->CompleteName;
		break;
	}
	case RegNtPreSetValueKey:
	{
		auto info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
		eventType = EventType::RegistrySetValue;
		regOp = RegistryOperation::SetValue;
		valueName = info->ValueName;
		break;
	}
	case RegNtPreDeleteKey:
	{
		eventType = EventType::RegistryDeleteKey;
		regOp = RegistryOperation::DeleteKey;
		break;
	}
	case RegNtPreDeleteValueKey:
	{
		auto info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
		eventType = EventType::RegistryDeleteValue;
		regOp = RegistryOperation::DeleteValue;
		valueName = info->ValueName;
		break;
	}
	case RegNtPreRenameKey:
	{
		auto info = (PREG_RENAME_KEY_INFORMATION)Argument2;
		eventType = EventType::RegistryRenameKey;
		regOp = RegistryOperation::RenameKey;
		keyName = info->NewName;
		break;
	}
	default:
		// Skip other operations
		return STATUS_SUCCESS;
	}

	USHORT keyNameLen = (keyName && keyName->Buffer) ? keyName->Length : 0;
	USHORT valueNameLen = (valueName && valueName->Buffer) ? valueName->Length : 0;

	auto size = sizeof(FullEventData) + keyNameLen + valueNameLen;
	auto item = (FullEventData*)ExAllocatePool2(
		POOL_FLAG_PAGED,
		size,
		DRIVER_TAG
	);

	if (item == nullptr)
	{
		return STATUS_SUCCESS;
	}

	auto& header = item->Data.Header;
	KeQuerySystemTimePrecise((PLARGE_INTEGER)&header.Timestamp);
	header.Size = sizeof(EventHeader) + sizeof(RegistryOperationInfo) - sizeof(WCHAR) + keyNameLen + valueNameLen;
	header.Type = eventType;

	auto& data = item->Data.RegistryOperation;
	data.ProcessId = HandleToULong(PsGetCurrentProcessId());
	data.ThreadId = HandleToULong(PsGetCurrentThreadId());
	data.Operation = regOp;
	data.Status = STATUS_SUCCESS; // Pre-operation, status unknown
	data.KeyNameLength = keyNameLen / sizeof(WCHAR);
	data.ValueNameLength = valueNameLen / sizeof(WCHAR);

	PWCHAR destPtr = data.Names;
	if (keyNameLen > 0)
	{
		memcpy(destPtr, keyName->Buffer, keyNameLen);
		destPtr = (PWCHAR)((PUCHAR)destPtr + keyNameLen);
	}
	if (valueNameLen > 0)
	{
		memcpy(destPtr, valueName->Buffer, valueNameLen);
	}

	AddItem(item);

	return STATUS_SUCCESS;
}

// ============== Helper Functions ==============

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

// ============== Driver Unload ==============

void DioProcessUnload(PDRIVER_OBJECT DriverObject)
{
	KdPrint((DRIVER_PREFIX "Unloading driver\n"));

	// Unregister callbacks in reverse order
	if (g_RegistryCookie.QuadPart != 0)
	{
		CmUnRegisterCallback(g_RegistryCookie);
		KdPrint((DRIVER_PREFIX "Registry callback unregistered\n"));
	}

	if (g_ObCallbackHandle)
	{
		ObUnRegisterCallbacks(g_ObCallbackHandle);
		KdPrint((DRIVER_PREFIX "Object Manager callbacks unregistered\n"));
	}

	PsRemoveLoadImageNotifyRoutine(OnImageLoadCallback);
	KdPrint((DRIVER_PREFIX "Image load callback unregistered\n"));

	PsRemoveCreateThreadNotifyRoutine(OnThreadCallback);
	KdPrint((DRIVER_PREFIX "Thread callback unregistered\n"));

	PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, TRUE);
	KdPrint((DRIVER_PREFIX "Process callback unregistered\n"));

	UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\DioProcess");
	IoDeleteSymbolicLink(&symName);
	IoDeleteDevice(DriverObject->DeviceObject);

	// Free any remaining items
	while (!IsListEmpty(&g_State.ItemsHead))
	{
		auto link = RemoveHeadList(&g_State.ItemsHead);
		ExFreePool(CONTAINING_RECORD(link, FullEventData, Link));
	}

	KdPrint((DRIVER_PREFIX "Driver unloaded\n"));
}

// ============== IRP Handlers ==============

void AddItem(FullEventData* item)
{
	// Check if collection is enabled before acquiring lock
	if (!g_State.CollectionEnabled)
	{
		ExFreePool(item);
		return;
	}

	Locker locker(g_State.Lock);

	// Limit queue size to prevent memory exhaustion
	if (g_State.ItemCount >= 100000)
	{
		// Remove oldest item
		auto oldLink = RemoveHeadList(&g_State.ItemsHead);
		ExFreePool(CONTAINING_RECORD(oldLink, FullEventData, Link));
		g_State.ItemCount--;
	}

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

NTSTATUS DioProcessCreateClose(PDEVICE_OBJECT, PIRP Irp)
{
	return CompleteRequest(Irp);
}

NTSTATUS DioProcessRead(PDEVICE_OBJECT, PIRP Irp)
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
			g_State.ItemCount--;
			ExFreePool(CONTAINING_RECORD(link, FullEventData, Link));
		}

	} while (false);

	return CompleteRequest(Irp, status, info);
}

NTSTATUS DioProcessDeviceControl(PDEVICE_OBJECT, PIRP Irp)
{
	auto irpSp = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;
	ULONG_PTR info = 0;

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_DIOPROCESS_START_COLLECTION:
	{
		g_State.CollectionEnabled = TRUE;
		KdPrint((DRIVER_PREFIX "Collection started\n"));
		break;
	}

	case IOCTL_DIOPROCESS_STOP_COLLECTION:
	{
		g_State.CollectionEnabled = FALSE;
		KdPrint((DRIVER_PREFIX "Collection stopped\n"));
		break;
	}

	case IOCTL_DIOPROCESS_GET_COLLECTION_STATE:
	{
		auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
		if (outputLen < sizeof(CollectionStateResponse))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		auto response = (CollectionStateResponse*)Irp->AssociatedIrp.SystemBuffer;
		if (!response)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		response->IsCollecting = g_State.CollectionEnabled;
		response->ItemCount = g_State.ItemCount;
		info = sizeof(CollectionStateResponse);
		break;
	}

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	return CompleteRequest(Irp, status, info);
}
