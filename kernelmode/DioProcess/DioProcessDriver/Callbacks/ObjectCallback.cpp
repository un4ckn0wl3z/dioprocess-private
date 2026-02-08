#include "pch.h"
#include "DioProcessGlobals.h"

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
