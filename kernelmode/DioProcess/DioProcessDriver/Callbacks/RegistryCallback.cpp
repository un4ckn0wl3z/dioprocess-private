#include "pch.h"
#include "DioProcessGlobals.h"

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
