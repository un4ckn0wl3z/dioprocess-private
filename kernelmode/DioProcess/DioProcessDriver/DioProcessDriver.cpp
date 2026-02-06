#include "pch.h"
#include "DioProcessDriver.h"
#include "Locker.h"

#pragma comment(lib, "aux_klib.lib")

DioProcessState g_State;
PVOID g_ObCallbackHandle = nullptr;
LARGE_INTEGER g_RegistryCookie = { 0 };
BOOLEAN g_CallbacksRegistered = FALSE;

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

// Security research helper functions
WINDOWS_VERSION GetWindowsVersion();

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;
	PDEVICE_OBJECT devObj = nullptr;
	bool symLinkCreated = false;

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

	} while (false);

	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "ERROR in DriverEntry (0x%X)\n", status));

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
	g_CallbacksRegistered = FALSE;      // Callbacks not registered by default

	DriverObject->DriverUnload = DioProcessUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = DioProcessCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = DioProcessRead;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DioProcessDeviceControl;

	KdPrint((DRIVER_PREFIX "Driver loaded successfully (callbacks NOT registered yet)\n"));
	return STATUS_SUCCESS;
}

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

// ============== Security Research Functions ==============

WINDOWS_VERSION GetWindowsVersion()
{
	RTL_OSVERSIONINFOW info;
	info.dwOSVersionInfoSize = sizeof(info);

	NTSTATUS status = RtlGetVersion(&info);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "RtlGetVersion failed (0x%X)\n", status));
		return WINDOWS_UNSUPPORTED;
	}

	KdPrint((DRIVER_PREFIX "Windows Build: %d.%d (Build %d)\n",
		info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber));

	// Only support Windows 10/11 (major version 10)
	if (info.dwMajorVersion != 10)
	{
		KdPrint((DRIVER_PREFIX "Unsupported Windows major version: %d\n", info.dwMajorVersion));
		return WINDOWS_UNSUPPORTED;
	}

	// Map build number to version
	switch (info.dwBuildNumber)
	{
	case 10240: return WINDOWS_10_1507;
	case 10586: return WINDOWS_10_1511;
	case 14393: return WINDOWS_10_1607;
	case 15063: return WINDOWS_10_1703;
	case 16299: return WINDOWS_10_1709;
	case 17134: return WINDOWS_10_1803;
	case 17763: return WINDOWS_10_1809;
	case 18362: return WINDOWS_10_1903;
	case 18363: return WINDOWS_10_1909;
	case 19041: return WINDOWS_10_2004;
	case 19042: return WINDOWS_10_20H2;
	case 19043: return WINDOWS_10_21H1;
	case 19044: return WINDOWS_10_21H2;
	case 19045: return WINDOWS_10_22H2;
	case 22000: return WINDOWS_11_21H2;
	case 22621: return WINDOWS_11_22H2;
	case 22631: return WINDOWS_11_23H2;
	case 26100: return WINDOWS_11_24H2;
	default:
		// For newer builds, try to use the closest known version
		if (info.dwBuildNumber > 26100)
		{
			return WINDOWS_11_24H2; // Use latest known offsets
		}
		else if (info.dwBuildNumber >= 22000)
		{
			return WINDOWS_11_21H2; // Windows 11 range
		}
		else if (info.dwBuildNumber >= 19041)
		{
			return WINDOWS_10_2004; // Windows 10 20H1+ range
		}
		return WINDOWS_UNSUPPORTED;
	}
}

// ============== Driver Unload ==============

void DioProcessUnload(PDRIVER_OBJECT DriverObject)
{
	KdPrint((DRIVER_PREFIX "Unloading driver\n"));

	// Unregister callbacks in reverse order if they were registered
	if (g_CallbacksRegistered)
	{
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

		g_CallbacksRegistered = FALSE;
	}

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
			if (!link)
				break;

#pragma warning(suppress: 6001)
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

// ============== Kernel Injection Implementation ==============

// Undocumented structures for PEB access
typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// Minimal PEB structure (only fields we need)
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN SpareBool;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	// ... other fields omitted for brevity
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// RtlCreateUserThread function pointer type
typedef NTSTATUS(NTAPI* PfnRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientID
	);

// Helper: Get PEB from EPROCESS (version-aware)
PPEB GetProcessPeb(PEPROCESS Process, WINDOWS_VERSION WindowsVersion)
{
	if (WindowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Unsupported Windows version for PEB access\n"));
		return NULL;
	}

	PPEB pPeb = NULL;
	ULONG pebOffset = PROCESS_PEB_OFFSET[WindowsVersion];

	if (pebOffset == 0)
	{
		KdPrint((DRIVER_PREFIX "Invalid PEB offset for this Windows version\n"));
		return NULL;
	}

	__try
	{
		// Get PEB pointer using version-specific offset
		pPeb = (PPEB)*(PVOID*)((PUCHAR)Process + pebOffset);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception accessing PEB at offset 0x%X\n", pebOffset));
		return NULL;
	}

	return pPeb;
}

// Helper: Get module base address in target process (following reference implementation)
PVOID GetUserModuleBaseAddress(PEPROCESS Process, PUNICODE_STRING ModuleName, WINDOWS_VERSION WindowsVersion)
{
	PPEB pPeb = GetProcessPeb(Process, WindowsVersion);
	if (!pPeb || !MmIsAddressValid(pPeb))
	{
		KdPrint((DRIVER_PREFIX "Failed to get valid PEB\n"));
		return NULL;
	}

	__try
	{
		// Get PEB_LDR_DATA
		PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
		if (!pLdr || !MmIsAddressValid(pLdr))
		{
			return NULL;
		}

		// Iterate through InLoadOrderModuleList
		for (PLIST_ENTRY pListEntry = pLdr->InLoadOrderModuleList.Flink;
			pListEntry != &pLdr->InLoadOrderModuleList;
			pListEntry = pListEntry->Flink)
		{
			if (!MmIsAddressValid(pListEntry))
			{
				continue;
			}

			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (!MmIsAddressValid(pEntry))
			{
				continue;
			}

			// Compare module names (case-insensitive)
			if (RtlEqualUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE))
			{
				return pEntry->DllBase;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}

	return NULL;
}

// Helper: Get exported function address from module (PE parsing)
PVOID GetModuleExportAddress(PVOID ModuleBase, PCCHAR FunctionName)
{
	if (!ModuleBase || !MmIsAddressValid(ModuleBase))
	{
		return NULL;
	}

	__try
	{
		// Parse PE headers
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return NULL;
		}

		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + pDosHeader->e_lfanew);
		if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			return NULL;
		}

		// Get export directory
		PIMAGE_DATA_DIRECTORY pExportDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (pExportDataDir->VirtualAddress == 0)
		{
			return NULL;
		}

		PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + pExportDataDir->VirtualAddress);
		if (!MmIsAddressValid(pExportDir))
		{
			return NULL;
		}

		// Get export tables
		PULONG pAddressOfFunctions = (PULONG)((PUCHAR)ModuleBase + pExportDir->AddressOfFunctions);
		PULONG pAddressOfNames = (PULONG)((PUCHAR)ModuleBase + pExportDir->AddressOfNames);
		PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PUCHAR)ModuleBase + pExportDir->AddressOfNameOrdinals);

		// Search for function by name
		for (ULONG i = 0; i < pExportDir->NumberOfNames; i++)
		{
			if (!MmIsAddressValid(&pAddressOfNames[i]))
			{
				continue;
			}

			PCCHAR pName = (PCCHAR)((PUCHAR)ModuleBase + pAddressOfNames[i]);
			if (!MmIsAddressValid(pName))
			{
				continue;
			}

			if (strcmp(pName, FunctionName) == 0)
			{
				USHORT ordinal = pAddressOfNameOrdinals[i];
				ULONG functionRva = pAddressOfFunctions[ordinal];
				return (PVOID)((PUCHAR)ModuleBase + functionRva);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}

	return NULL;
}

// Helper: Get LoadLibraryW address in target process (following reference implementation)
PVOID GetLoadLibraryWAddress(ULONG ProcessId, WINDOWS_VERSION WindowsVersion)
{
	if (WindowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Unsupported Windows version for kernel injection\n"));
		return NULL;
	}

	PEPROCESS pEProcess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &pEProcess);
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}

	KAPC_STATE apcState;
	PVOID loadLibraryAddress = NULL;

	__try
	{
		// Attach to target process
		KeStackAttachProcess(pEProcess, &apcState);

		// Find kernel32.dll base address
		UNICODE_STRING kernel32Name;
		RtlInitUnicodeString(&kernel32Name, L"kernel32.dll");
		PVOID kernel32Base = GetUserModuleBaseAddress(pEProcess, &kernel32Name, WindowsVersion);

		if (kernel32Base && MmIsAddressValid(kernel32Base))
		{
			// Get LoadLibraryW export address
			loadLibraryAddress = GetModuleExportAddress(kernel32Base, "LoadLibraryW");
			KdPrint((DRIVER_PREFIX "Windows version: %d, kernel32.dll base: 0x%p, LoadLibraryW: 0x%p\n",
				WindowsVersion, kernel32Base, loadLibraryAddress));
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Failed to find kernel32.dll base address\n"));
		}

		KeUnstackDetachProcess(&apcState);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception while getting LoadLibraryW address\n"));
		KeUnstackDetachProcess(&apcState);
	}

	ObDereferenceObject(pEProcess);
	return loadLibraryAddress;
}

// Kernel DLL injection function (following reference implementation)
NTSTATUS KernelInjectDll(ULONG ProcessId, PCWSTR DllPath, PVOID* AllocatedAddress, PVOID* LoadLibraryAddress)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = NULL;
	KAPC_STATE apcState = { 0 };
	PfnRtlCreateUserThread RtlCreateUserThread = NULL;
	HANDLE hThread = NULL;
	PVOID pDllPathMemory = NULL;
	PVOID pLoadLibraryW = NULL;

	// Get Windows version
	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Unsupported Windows version for kernel DLL injection\n"));
		return STATUS_NOT_SUPPORTED;
	}

	KdPrint((DRIVER_PREFIX "Kernel DLL injection - Windows version: %d\n", windowsVersion));

	__try
	{
		// Get RtlCreateUserThread function address
		UNICODE_STRING ustrRtlCreateUserThread;
		RtlInitUnicodeString(&ustrRtlCreateUserThread, L"RtlCreateUserThread");
		RtlCreateUserThread = (PfnRtlCreateUserThread)MmGetSystemRoutineAddress(&ustrRtlCreateUserThread);
		if (!RtlCreateUserThread)
		{
			KdPrint((DRIVER_PREFIX "Failed to get RtlCreateUserThread\n"));
			return STATUS_NOT_FOUND;
		}

		// Get LoadLibraryW address in target process
		pLoadLibraryW = GetLoadLibraryWAddress(ProcessId, windowsVersion);
		if (!pLoadLibraryW)
		{
			KdPrint((DRIVER_PREFIX "Failed to get LoadLibraryW address\n"));
			return STATUS_NOT_FOUND;
		}

		*LoadLibraryAddress = pLoadLibraryW;

		// Lookup process by PID
		status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &pEProcess);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to lookup process %u\n", ProcessId));
			return status;
		}

		// Attach to target process
		KeStackAttachProcess(pEProcess, &apcState);

		// Allocate memory for DLL path (wide string)
		SIZE_T dllPathSize = (wcslen(DllPath) + 1) * sizeof(WCHAR);
		SIZE_T allocSize = dllPathSize;
		status = ZwAllocateVirtualMemory(
			ZwCurrentProcess(),
			&pDllPathMemory,
			0,
			&allocSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to allocate memory for DLL path\n"));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return status;
		}

		// Write DLL path to allocated memory
		__try
		{
			RtlCopyMemory(pDllPathMemory, DllPath, dllPathSize);
			KdPrint((DRIVER_PREFIX "DLL path written to 0x%p\n", pDllPathMemory));
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			KdPrint((DRIVER_PREFIX "Failed to write DLL path\n"));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return STATUS_ACCESS_VIOLATION;
		}

		// Validate address
		if (!MmIsAddressValid(pDllPathMemory))
		{
			KdPrint((DRIVER_PREFIX "DLL path address is not valid\n"));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return STATUS_INVALID_ADDRESS;
		}

		// Create thread with LoadLibraryW(DllPath)
		// StartAddress = LoadLibraryW, StartParameter = DLL path
		status = RtlCreateUserThread(
			ZwCurrentProcess(),
			NULL,
			FALSE,
			0,
			0,
			0,
			pLoadLibraryW,       // LoadLibraryW address
			pDllPathMemory,      // DLL path as parameter
			&hThread,
			NULL
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "RtlCreateUserThread failed: 0x%X\n", status));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return status;
		}

		// Close thread handle
		if (hThread)
		{
			ZwClose(hThread);
		}

		*AllocatedAddress = pDllPathMemory;
		KdPrint((DRIVER_PREFIX "DLL injection successful - PID: %u, DLL Path Address: 0x%p, LoadLibraryW: 0x%p\n",
			ProcessId, pDllPathMemory, pLoadLibraryW));

		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(pEProcess);
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception during DLL injection\n"));
		if (pEProcess)
		{
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
		}
		return STATUS_UNSUCCESSFUL;
	}
}

// Kernel shellcode injection function based on reference implementation
NTSTATUS KernelInjectShellcode(ULONG ProcessId, PVOID Shellcode, SIZE_T ShellcodeSize, PVOID* AllocatedAddress)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = NULL;
	KAPC_STATE apcState = { 0 };
	PfnRtlCreateUserThread RtlCreateUserThread = NULL;
	HANDLE hThread = NULL;
	PVOID pShellcodeMemory = NULL;

	// Get Windows version for logging/verification
	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Unsupported Windows version for kernel shellcode injection\n"));
		return STATUS_NOT_SUPPORTED;
	}

	KdPrint((DRIVER_PREFIX "Kernel shellcode injection - Windows version: %d\n", windowsVersion));

	__try
	{
		// Get RtlCreateUserThread function address dynamically
		UNICODE_STRING ustrRtlCreateUserThread;
		RtlInitUnicodeString(&ustrRtlCreateUserThread, L"RtlCreateUserThread");
		RtlCreateUserThread = (PfnRtlCreateUserThread)MmGetSystemRoutineAddress(&ustrRtlCreateUserThread);
		if (RtlCreateUserThread == NULL)
		{
			KdPrint((DRIVER_PREFIX "Failed to get RtlCreateUserThread address\n"));
			return STATUS_NOT_FOUND;
		}

		// Lookup process by PID
		status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &pEProcess);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to lookup process %u: 0x%X\n", ProcessId, status));
			return status;
		}

		// Attach to target process
		KeStackAttachProcess(pEProcess, &apcState);

		// Allocate memory in target process for shellcode
		SIZE_T allocSize = ShellcodeSize;
		status = ZwAllocateVirtualMemory(
			ZwCurrentProcess(),
			&pShellcodeMemory,
			0,
			&allocSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to allocate memory: 0x%X\n", status));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return status;
		}

		// Write shellcode to allocated memory
		__try
		{
			RtlCopyMemory(pShellcodeMemory, Shellcode, ShellcodeSize);
			KdPrint((DRIVER_PREFIX "Shellcode written to 0x%p, size %zu\n", pShellcodeMemory, ShellcodeSize));
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			KdPrint((DRIVER_PREFIX "Failed to write shellcode\n"));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return STATUS_ACCESS_VIOLATION;
		}

		// Validate address is accessible
		if (!MmIsAddressValid(pShellcodeMemory))
		{
			KdPrint((DRIVER_PREFIX "Shellcode address is not valid\n"));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return STATUS_INVALID_ADDRESS;
		}

		// Create thread at shellcode address using RtlCreateUserThread
		status = RtlCreateUserThread(
			ZwCurrentProcess(),
			NULL,
			FALSE,
			0,
			0,
			0,
			pShellcodeMemory,
			NULL,
			&hThread,
			NULL
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "RtlCreateUserThread failed: 0x%X\n", status));
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
			return status;
		}

		// Close thread handle
		if (hThread)
		{
			ZwClose(hThread);
		}

		*AllocatedAddress = pShellcodeMemory;
		KdPrint((DRIVER_PREFIX "Shellcode injection successful - PID: %u, Address: 0x%p\n", ProcessId, pShellcodeMemory));

		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(pEProcess);
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception during shellcode injection\n"));
		if (pEProcess)
		{
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(pEProcess);
		}
		return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS DioProcessDeviceControl(PDEVICE_OBJECT, PIRP Irp)
{
	auto irpSp = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;
	ULONG_PTR info = 0;

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_DIOPROCESS_REGISTER_CALLBACKS:
	{
		if (g_CallbacksRegistered)
		{
			KdPrint((DRIVER_PREFIX "Callbacks already registered\n"));
			status = STATUS_ALREADY_REGISTERED;
			break;
		}

		// Register process callback
		status = PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, FALSE);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to register process callback (0x%X)\n", status));
			break;
		}
		KdPrint((DRIVER_PREFIX "Process callback registered\n"));

		// Register thread callback
		status = PsSetCreateThreadNotifyRoutine(OnThreadCallback);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to register thread callback (0x%X)\n", status));
			PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, TRUE);
			break;
		}
		KdPrint((DRIVER_PREFIX "Thread callback registered\n"));

		// Register image load callback
		status = PsSetLoadImageNotifyRoutine(OnImageLoadCallback);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to register image load callback (0x%X)\n", status));
			PsRemoveCreateThreadNotifyRoutine(OnThreadCallback);
			PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, TRUE);
			break;
		}
		KdPrint((DRIVER_PREFIX "Image load callback registered\n"));

		// Register Object Manager callbacks
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
			// Continue without OB callbacks
			status = STATUS_SUCCESS;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Object Manager callbacks registered\n"));
		}

		// Register registry callback
		UNICODE_STRING regAltitude = RTL_CONSTANT_STRING(L"321001");
		PDRIVER_OBJECT driverObj = IoGetCurrentIrpStackLocation(Irp)->DeviceObject->DriverObject;
		status = CmRegisterCallbackEx(OnRegistryCallback, &regAltitude, driverObj, nullptr, &g_RegistryCookie, nullptr);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to register registry callback (0x%X)\n", status));
			// Continue without registry callbacks
			status = STATUS_SUCCESS;
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Registry callback registered\n"));
		}

		g_CallbacksRegistered = TRUE;
		KdPrint((DRIVER_PREFIX "All callbacks registered successfully\n"));
		break;
	}

	case IOCTL_DIOPROCESS_UNREGISTER_CALLBACKS:
	{
		if (!g_CallbacksRegistered)
		{
			KdPrint((DRIVER_PREFIX "Callbacks not registered\n"));
			break;
		}

		// Unregister in reverse order
		if (g_RegistryCookie.QuadPart != 0)
		{
			CmUnRegisterCallback(g_RegistryCookie);
			g_RegistryCookie.QuadPart = 0;
			KdPrint((DRIVER_PREFIX "Registry callback unregistered\n"));
		}

		if (g_ObCallbackHandle)
		{
			ObUnRegisterCallbacks(g_ObCallbackHandle);
			g_ObCallbackHandle = nullptr;
			KdPrint((DRIVER_PREFIX "Object Manager callbacks unregistered\n"));
		}

		PsRemoveLoadImageNotifyRoutine(OnImageLoadCallback);
		KdPrint((DRIVER_PREFIX "Image load callback unregistered\n"));

		PsRemoveCreateThreadNotifyRoutine(OnThreadCallback);
		KdPrint((DRIVER_PREFIX "Thread callback unregistered\n"));

		PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, TRUE);
		KdPrint((DRIVER_PREFIX "Process callback unregistered\n"));

		g_CallbacksRegistered = FALSE;
		g_State.CollectionEnabled = FALSE;
		KdPrint((DRIVER_PREFIX "All callbacks unregistered\n"));
		break;
	}

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

	// ============== Security Research IOCTLs ==============

	case IOCTL_DIOPROCESS_PROTECT_PROCESS:
	{
		WINDOWS_VERSION windowsVersion = GetWindowsVersion();
		if (windowsVersion == WINDOWS_UNSUPPORTED)
		{
			status = STATUS_NOT_SUPPORTED;
			KdPrint((DRIVER_PREFIX "Windows version unsupported for process protection\n"));
			break;
		}

		auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
		if (inputLen < sizeof(TargetProcessRequest))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		auto request = (TargetProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
		if (!request)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// Get EPROCESS
		PEPROCESS eProcess = NULL;
		status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->ProcessId, &eProcess);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "PsLookupProcessByProcessId failed for PID %d (0x%X)\n",
				request->ProcessId, status));
			break;
		}

		KdPrint((DRIVER_PREFIX "Protecting process PID %d (EPROCESS=0x%p, Offset=0x%X)\n",
			request->ProcessId, eProcess, PROCESS_PROTECTION_OFFSET[windowsVersion]));

		// Get protection structure pointer
		PROCESS_PROTECTION_INFO* psProtection =
			(PROCESS_PROTECTION_INFO*)(((ULONG_PTR)eProcess) + PROCESS_PROTECTION_OFFSET[windowsVersion]);

		// Read current protection values for logging
		KdPrint((DRIVER_PREFIX "Current Protection: SigLvl=0x%02X, SectSigLvl=0x%02X, Type=%d, Signer=%d\n",
			psProtection->SignatureLevel, psProtection->SectionSignatureLevel,
			psProtection->Protection.Type, psProtection->Protection.Signer));

		// Set protection values (PPL WinTcb-Light)
		psProtection->SignatureLevel = 0x3E;          // SE_SIGNING_LEVEL_WINDOWS_TCB
		psProtection->SectionSignatureLevel = 0x3C;   // SE_SIGNING_LEVEL_WINDOWS
		psProtection->Protection.Type = 2;            // PsProtectedTypeProtectedLight
		psProtection->Protection.Signer = 6;          // PsProtectedSignerWinTcb

		KdPrint((DRIVER_PREFIX "New Protection: SigLvl=0x%02X, SectSigLvl=0x%02X, Type=%d, Signer=%d\n",
			psProtection->SignatureLevel, psProtection->SectionSignatureLevel,
			psProtection->Protection.Type, psProtection->Protection.Signer));

		ObDereferenceObject(eProcess);
		KdPrint((DRIVER_PREFIX "Process PID %d protected successfully\n", request->ProcessId));
		break;
	}

	case IOCTL_DIOPROCESS_UNPROTECT_PROCESS:
	{
		WINDOWS_VERSION windowsVersion = GetWindowsVersion();
		if (windowsVersion == WINDOWS_UNSUPPORTED)
		{
			status = STATUS_NOT_SUPPORTED;
			KdPrint((DRIVER_PREFIX "Windows version unsupported for process unprotection\n"));
			break;
		}

		auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
		if (inputLen < sizeof(TargetProcessRequest))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		auto request = (TargetProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
		if (!request)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// Get EPROCESS
		PEPROCESS eProcess = NULL;
		status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->ProcessId, &eProcess);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "PsLookupProcessByProcessId failed for PID %d (0x%X)\n",
				request->ProcessId, status));
			break;
		}

		KdPrint((DRIVER_PREFIX "Removing protection from process PID %d\n", request->ProcessId));

		// Get protection structure pointer
		PROCESS_PROTECTION_INFO* psProtection =
			(PROCESS_PROTECTION_INFO*)(((ULONG_PTR)eProcess) + PROCESS_PROTECTION_OFFSET[windowsVersion]);

		// Zero out protection
		psProtection->SignatureLevel = 0;
		psProtection->SectionSignatureLevel = 0;
		psProtection->Protection.Type = 0;
		psProtection->Protection.Signer = 0;
		psProtection->Protection.Audit = 0;

		ObDereferenceObject(eProcess);
		KdPrint((DRIVER_PREFIX "Process PID %d unprotected successfully\n", request->ProcessId));
		break;
	}

	case IOCTL_DIOPROCESS_ENABLE_PRIVILEGES:
	{
		WINDOWS_VERSION windowsVersion = GetWindowsVersion();
		if (windowsVersion == WINDOWS_UNSUPPORTED)
		{
			status = STATUS_NOT_SUPPORTED;
			KdPrint((DRIVER_PREFIX "Windows version unsupported for privilege manipulation\n"));
			break;
		}

		auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
		if (inputLen < sizeof(TargetProcessRequest))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		auto request = (TargetProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
		if (!request)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// Get EPROCESS
		PEPROCESS eProcess = NULL;
		status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->ProcessId, &eProcess);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "PsLookupProcessByProcessId failed for PID %d (0x%X)\n",
				request->ProcessId, status));
			break;
		}

		KdPrint((DRIVER_PREFIX "Enabling all privileges for process PID %d\n", request->ProcessId));

		// Get primary token
		PACCESS_TOKEN pToken = PsReferencePrimaryToken(eProcess);
		if (!pToken)
		{
			ObDereferenceObject(eProcess);
			status = STATUS_UNSUCCESSFUL;
			KdPrint((DRIVER_PREFIX "PsReferencePrimaryToken failed\n"));
			break;
		}

		// Get privileges structure pointer
		PPROCESS_PRIVILEGES tokenPrivs =
			(PPROCESS_PRIVILEGES)((ULONG_PTR)pToken + PROCESS_PRIVILEGE_OFFSET[windowsVersion]);

		// Enable all privileges
		tokenPrivs->Present[0] = tokenPrivs->Enabled[0] = tokenPrivs->EnabledByDefault[0] = 0xff;
		tokenPrivs->Present[1] = tokenPrivs->Enabled[1] = tokenPrivs->EnabledByDefault[1] = 0xff;
		tokenPrivs->Present[2] = tokenPrivs->Enabled[2] = tokenPrivs->EnabledByDefault[2] = 0xff;
		tokenPrivs->Present[3] = tokenPrivs->Enabled[3] = tokenPrivs->EnabledByDefault[3] = 0xff;
		tokenPrivs->Present[4] = tokenPrivs->Enabled[4] = tokenPrivs->EnabledByDefault[4] = 0xff;

		PsDereferencePrimaryToken(pToken);
		ObDereferenceObject(eProcess);
		KdPrint((DRIVER_PREFIX "All privileges enabled for PID %d\n", request->ProcessId));
		break;
	}

	case IOCTL_DIOPROCESS_CLEAR_DEBUG_FLAGS:
	{
		WINDOWS_VERSION windowsVersion = GetWindowsVersion();
		if (windowsVersion == WINDOWS_UNSUPPORTED)
		{
			status = STATUS_NOT_SUPPORTED;
			KdPrint((DRIVER_PREFIX "Windows version unsupported for anti-debug\n"));
			break;
		}

		auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
		if (inputLen < sizeof(TargetProcessRequest))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		auto request = (TargetProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
		if (!request)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// Get EPROCESS
		PEPROCESS eProcess = NULL;
		status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->ProcessId, &eProcess);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "PsLookupProcessByProcessId failed for PID %d (0x%X)\n",
				request->ProcessId, status));
			break;
		}

		KdPrint((DRIVER_PREFIX "Clearing debug flags for process PID %d\n", request->ProcessId));

		// 1. Clear DebugPort in EPROCESS (kernel debugger detection)
		PVOID* pDebugPort = (PVOID*)((ULONG_PTR)eProcess + PROCESS_DEBUGPORT_OFFSET[windowsVersion]);
		PVOID oldDebugPort = *pDebugPort;
		*pDebugPort = NULL;
		KdPrint((DRIVER_PREFIX "DebugPort cleared (was: 0x%p, now: NULL)\n", oldDebugPort));

		// 2. Get PEB from EPROCESS
		PVOID pPeb = *(PVOID*)((ULONG_PTR)eProcess + PROCESS_PEB_OFFSET[windowsVersion]);
		if (pPeb && (ULONG_PTR)pPeb > 0x1000 && (ULONG_PTR)pPeb < 0x7FFFFFFFFFFF)  // Sanity check: valid usermode address
		{
			// Attach to target process context to safely access PEB
			KAPC_STATE apcState;
			KeStackAttachProcess(eProcess, &apcState);

			__try
			{
				// PEB.BeingDebugged is at offset 0x002
				PUCHAR pBeingDebugged = (PUCHAR)((ULONG_PTR)pPeb + 0x002);
				UCHAR oldBeingDebugged = *pBeingDebugged;
				*pBeingDebugged = FALSE;
				KdPrint((DRIVER_PREFIX "PEB.BeingDebugged cleared (was: %d, now: 0)\n", oldBeingDebugged));

				// PEB.NtGlobalFlag is at offset 0x0BC (x64) or 0x068 (x86)
				// Clearing heap debugging flags
#ifdef _WIN64
				PULONG pNtGlobalFlag = (PULONG)((ULONG_PTR)pPeb + 0x0BC);
#else
				PULONG pNtGlobalFlag = (PULONG)((ULONG_PTR)pPeb + 0x068);
#endif
				ULONG oldNtGlobalFlag = *pNtGlobalFlag;
				// Clear heap debug flags (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
				*pNtGlobalFlag &= ~(0x10 | 0x20 | 0x40);
				KdPrint((DRIVER_PREFIX "PEB.NtGlobalFlag cleared (was: 0x%X, now: 0x%X)\n",
					oldNtGlobalFlag, *pNtGlobalFlag));
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				KdPrint((DRIVER_PREFIX "Exception while accessing PEB (0x%08X)\n", GetExceptionCode()));
				status = STATUS_ACCESS_VIOLATION;
			}

			KeUnstackDetachProcess(&apcState);
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Warning: Invalid PEB address (0x%p)\n", pPeb));
		}

		ObDereferenceObject(eProcess);
		KdPrint((DRIVER_PREFIX "Anti-debug completed for PID %d\n", request->ProcessId));
		break;
	}

	case IOCTL_DIOPROCESS_ENUM_PROCESS_CALLBACKS:
	{
		KdPrint((DRIVER_PREFIX "Enumerating process callbacks\n"));

		WINDOWS_VERSION windowsVersion = GetWindowsVersion();
		if (windowsVersion == WINDOWS_UNSUPPORTED)
		{
			status = STATUS_NOT_SUPPORTED;
			KdPrint((DRIVER_PREFIX "Windows version unsupported for callback enumeration\n"));
			break;
		}

		auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
		ULONG requiredSize = sizeof(CallbackInformation) * MAX_CALLBACK_ENTRIES;

		if (outputLen < requiredSize)
		{
			status = STATUS_BUFFER_TOO_SMALL;
			KdPrint((DRIVER_PREFIX "Buffer too small (need %d bytes, got %d)\n", requiredSize, outputLen));
			break;
		}

		auto userBuffer = (CallbackInformation*)Irp->AssociatedIrp.SystemBuffer;
		if (!userBuffer)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// Find the callback array
		ULONG64 pspSetCreateProcessNotifyArray = FindPspSetCreateProcessNotifyRoutine(windowsVersion);
		if (pspSetCreateProcessNotifyArray == 0)
		{
			status = STATUS_NOT_FOUND;
			KdPrint((DRIVER_PREFIX "Failed to locate callback array\n"));
			break;
		}

		// Zero the output buffer
		RtlZeroMemory(userBuffer, requiredSize);

		// Enumerate all 64 callback slots
		ULONG validCallbackCount = 0;
		for (ULONG i = 0; i < MAX_CALLBACK_ENTRIES; i++)
		{
			// Each callback is 8 bytes (pointer) on x64
			ULONG64 pCallbackSlot = pspSetCreateProcessNotifyArray + (i * 8);
			ULONG64 callbackEntry = 0;

			__try
			{
				callbackEntry = *(PULONG64)(pCallbackSlot);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				KdPrint((DRIVER_PREFIX "Exception reading callback slot %d\n", i));
				continue;
			}

			// Skip null entries
			if (callbackEntry == 0)
			{
				userBuffer[i].CallbackAddress = 0;
				userBuffer[i].Index = i;
				continue;
			}

			// Windows stores callbacks with flags in low 3 bits
			// Clear the flags to get the actual structure pointer
			ULONG64 callbackStructure = callbackEntry & 0xFFFFFFFFFFFFFFF8;

			// The structure points to an EX_CALLBACK_ROUTINE_BLOCK
			// The actual function pointer is at offset 0x0 in this structure
			ULONG64 actualCallbackFunction = 0;

			__try
			{
				// Dereference the structure to get the actual callback function
				actualCallbackFunction = *(PULONG64)(callbackStructure);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				KdPrint((DRIVER_PREFIX "Exception dereferencing callback structure at 0x%llX\n", callbackStructure));
				// Store the structure address as fallback
				actualCallbackFunction = callbackStructure;
			}

			// Store the actual function address
			userBuffer[i].CallbackAddress = actualCallbackFunction;
			userBuffer[i].Index = i;

			// Resolve which driver owns this callback
			SearchLoadedModules(&userBuffer[i]);

			validCallbackCount++;
			KdPrint((DRIVER_PREFIX "Callback[%d]: Entry=0x%llX Struct=0x%llX Function=0x%llX -> %s\n",
				i, callbackEntry, callbackStructure, actualCallbackFunction, userBuffer[i].ModuleName));
		}

		KdPrint((DRIVER_PREFIX "Found %d active process callbacks\n", validCallbackCount));
		info = requiredSize;
		break;
	}

	case IOCTL_DIOPROCESS_ENUM_THREAD_CALLBACKS:
	{
		KdPrint((DRIVER_PREFIX "Enumerating thread callbacks\n"));

		WINDOWS_VERSION windowsVersion = GetWindowsVersion();
		if (windowsVersion == WINDOWS_UNSUPPORTED)
		{
			status = STATUS_NOT_SUPPORTED;
			break;
		}

		auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
		ULONG requiredSize = sizeof(CallbackInformation) * MAX_CALLBACK_ENTRIES;

		if (outputLen < requiredSize)
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		auto userBuffer = (CallbackInformation*)Irp->AssociatedIrp.SystemBuffer;
		if (!userBuffer)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		ULONG64 callbackArray = FindPspCreateThreadNotifyRoutine(windowsVersion);
		if (callbackArray == 0)
		{
			status = STATUS_NOT_FOUND;
			break;
		}

		RtlZeroMemory(userBuffer, requiredSize);

		ULONG validCount = 0;
		for (ULONG i = 0; i < MAX_CALLBACK_ENTRIES; i++)
		{
			ULONG64 callbackEntry = 0;
			__try { callbackEntry = *(PULONG64)(callbackArray + (i * 8)); }
			__except (EXCEPTION_EXECUTE_HANDLER) { continue; }

			if (callbackEntry == 0)
			{
				userBuffer[i].Index = i;
				continue;
			}

			ULONG64 actualFunction = 0;
			__try { actualFunction = *(PULONG64)(callbackEntry & 0xFFFFFFFFFFFFFFF8); }
			__except (EXCEPTION_EXECUTE_HANDLER) { actualFunction = callbackEntry & 0xFFFFFFFFFFFFFFF8; }

			userBuffer[i].CallbackAddress = actualFunction;
			userBuffer[i].Index = i;
			SearchLoadedModules(&userBuffer[i]);
			validCount++;
		}

		KdPrint((DRIVER_PREFIX "Found %d active thread callbacks\n", validCount));
		info = requiredSize;
		break;
	}

	case IOCTL_DIOPROCESS_ENUM_IMAGE_CALLBACKS:
	{
		KdPrint((DRIVER_PREFIX "Enumerating image load callbacks\n"));

		WINDOWS_VERSION windowsVersion = GetWindowsVersion();
		if (windowsVersion == WINDOWS_UNSUPPORTED)
		{
			status = STATUS_NOT_SUPPORTED;
			break;
		}

		auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
		ULONG requiredSize = sizeof(CallbackInformation) * MAX_CALLBACK_ENTRIES;

		if (outputLen < requiredSize)
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		auto userBuffer = (CallbackInformation*)Irp->AssociatedIrp.SystemBuffer;
		if (!userBuffer)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		ULONG64 callbackArray = FindPspLoadImageNotifyRoutine(windowsVersion);
		if (callbackArray == 0)
		{
			status = STATUS_NOT_FOUND;
			break;
		}

		RtlZeroMemory(userBuffer, requiredSize);

		ULONG validCount = 0;
		for (ULONG i = 0; i < MAX_CALLBACK_ENTRIES; i++)
		{
			ULONG64 callbackEntry = 0;
			__try { callbackEntry = *(PULONG64)(callbackArray + (i * 8)); }
			__except (EXCEPTION_EXECUTE_HANDLER) { continue; }

			if (callbackEntry == 0)
			{
				userBuffer[i].Index = i;
				continue;
			}

			ULONG64 actualFunction = 0;
			__try { actualFunction = *(PULONG64)(callbackEntry & 0xFFFFFFFFFFFFFFF8); }
			__except (EXCEPTION_EXECUTE_HANDLER) { actualFunction = callbackEntry & 0xFFFFFFFFFFFFFFF8; }

			userBuffer[i].CallbackAddress = actualFunction;
			userBuffer[i].Index = i;
			SearchLoadedModules(&userBuffer[i]);
			validCount++;
		}

		KdPrint((DRIVER_PREFIX "Found %d active image load callbacks\n", validCount));
		info = requiredSize;
		break;
	}

	// ============== Kernel Shellcode Injection IOCTL ==============

	case IOCTL_DIOPROCESS_KERNEL_INJECT_SHELLCODE:
	{
		KdPrint((DRIVER_PREFIX "Kernel shellcode injection request\n"));

		auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
		auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

		if (inputLen < sizeof(KernelInjectShellcodeRequest))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		if (outputLen < sizeof(KernelInjectShellcodeResponse))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		auto request = (KernelInjectShellcodeRequest*)Irp->AssociatedIrp.SystemBuffer;
		auto response = (KernelInjectShellcodeResponse*)Irp->AssociatedIrp.SystemBuffer;

		if (!request || request->ShellcodeSize == 0)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// Validate buffer size
		SIZE_T expectedSize = FIELD_OFFSET(KernelInjectShellcodeRequest, Shellcode) + request->ShellcodeSize;
		if (inputLen < expectedSize)
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		KdPrint((DRIVER_PREFIX "Injecting %u bytes of shellcode into PID %u\n",
			request->ShellcodeSize, request->TargetProcessId));

		PVOID allocatedAddress = nullptr;
		status = KernelInjectShellcode(
			request->TargetProcessId,
			request->Shellcode,
			request->ShellcodeSize,
			&allocatedAddress
		);

		if (NT_SUCCESS(status))
		{
			response->Success = TRUE;
			response->AllocatedAddress = (ULONG64)allocatedAddress;
			info = sizeof(KernelInjectShellcodeResponse);
			KdPrint((DRIVER_PREFIX "Kernel shellcode injection successful\n"));
		}
		else
		{
			response->Success = FALSE;
			response->AllocatedAddress = 0;
			info = sizeof(KernelInjectShellcodeResponse);
			KdPrint((DRIVER_PREFIX "Kernel shellcode injection failed: 0x%X\n", status));
		}

		break;
	}

	// ============== Kernel DLL Injection IOCTL ==============

	case IOCTL_DIOPROCESS_KERNEL_INJECT_DLL:
	{
		KdPrint((DRIVER_PREFIX "Kernel DLL injection request\n"));

		auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
		auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

		if (inputLen < sizeof(KernelInjectDllRequest))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		if (outputLen < sizeof(KernelInjectDllResponse))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		auto request = (KernelInjectDllRequest*)Irp->AssociatedIrp.SystemBuffer;
		auto response = (KernelInjectDllResponse*)Irp->AssociatedIrp.SystemBuffer;

		if (!request)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// Ensure DLL path is null-terminated
		request->DllPath[MAX_DLL_PATH_LENGTH - 1] = L'\0';

		KdPrint((DRIVER_PREFIX "Injecting DLL into PID %u: %ws\n",
			request->TargetProcessId, request->DllPath));

		PVOID allocatedAddress = nullptr;
		PVOID loadLibraryAddress = nullptr;
		status = KernelInjectDll(
			request->TargetProcessId,
			request->DllPath,
			&allocatedAddress,
			&loadLibraryAddress
		);

		if (NT_SUCCESS(status))
		{
			response->Success = TRUE;
			response->AllocatedAddress = (ULONG64)allocatedAddress;
			response->LoadLibraryAddress = (ULONG64)loadLibraryAddress;
			info = sizeof(KernelInjectDllResponse);
			KdPrint((DRIVER_PREFIX "Kernel DLL injection successful\n"));
		}
		else
		{
			response->Success = FALSE;
			response->AllocatedAddress = 0;
			response->LoadLibraryAddress = 0;
			info = sizeof(KernelInjectDllResponse);
			KdPrint((DRIVER_PREFIX "Kernel DLL injection failed: 0x%X\n", status));
		}

		break;
	}

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	return CompleteRequest(Irp, status, info);
}
