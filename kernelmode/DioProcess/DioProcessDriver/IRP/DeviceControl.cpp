#include "pch.h"
#include "DioProcessGlobals.h"
#include "Locker.h"

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

	case IOCTL_DIOPROCESS_ENUM_DRIVERS:
		status = HandleEnumDrivers(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_ENUM_PSPCIDTABLE:
		status = HandleEnumPspCidTable(Irp, irpSp, &info);
		break;

	// Kernel Injection IOCTLs
	case IOCTL_DIOPROCESS_KERNEL_INJECT_SHELLCODE:
		status = HandleKernelInjectShellcode(Irp, irpSp, &info);
		break;

	case IOCTL_DIOPROCESS_KERNEL_INJECT_DLL:
		status = HandleKernelInjectDll(Irp, irpSp, &info);
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
	*info = requiredSize;
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

					// Resolve module name for pre-operation callback
					if (cbInfo->PreOperationCallback)
					{
						CallbackInformation tempInfo = { 0 };
						tempInfo.CallbackAddress = cbInfo->PreOperationCallback;
						SearchLoadedModules(&tempInfo);
						RtlCopyMemory(cbInfo->ModuleName, tempInfo.ModuleName, MAX_MODULE_NAME_LENGTH);
					}
					else if (cbInfo->PostOperationCallback)
					{
						CallbackInformation tempInfo = { 0 };
						tempInfo.CallbackAddress = cbInfo->PostOperationCallback;
						SearchLoadedModules(&tempInfo);
						RtlCopyMemory(cbInfo->ModuleName, tempInfo.ModuleName, MAX_MODULE_NAME_LENGTH);
					}

					KdPrint((DRIVER_PREFIX "Process callback[%d]: Pre=0x%llX Post=0x%llX Ops=0x%X -> %s (Alt: %s)\n",
						callbackCount, cbInfo->PreOperationCallback, cbInfo->PostOperationCallback,
						cbInfo->Operations, cbInfo->ModuleName, cbInfo->Altitude));

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

					if (cbInfo->PreOperationCallback)
					{
						CallbackInformation tempInfo = { 0 };
						tempInfo.CallbackAddress = cbInfo->PreOperationCallback;
						SearchLoadedModules(&tempInfo);
						RtlCopyMemory(cbInfo->ModuleName, tempInfo.ModuleName, MAX_MODULE_NAME_LENGTH);
					}
					else if (cbInfo->PostOperationCallback)
					{
						CallbackInformation tempInfo = { 0 };
						tempInfo.CallbackAddress = cbInfo->PostOperationCallback;
						SearchLoadedModules(&tempInfo);
						RtlCopyMemory(cbInfo->ModuleName, tempInfo.ModuleName, MAX_MODULE_NAME_LENGTH);
					}

					KdPrint((DRIVER_PREFIX "Thread callback[%d]: Pre=0x%llX Post=0x%llX Ops=0x%X -> %s (Alt: %s)\n",
						callbackCount, cbInfo->PreOperationCallback, cbInfo->PostOperationCallback,
						cbInfo->Operations, cbInfo->ModuleName, cbInfo->Altitude));

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

	// Try to enumerate using FltMgr APIs first (documented approach)
	BOOLEAN success = EnumerateMinifiltersViaApi(response->Entries, &filterCount, MAX_MINIFILTER_ENTRIES);

	if (!success)
	{
		KdPrint((DRIVER_PREFIX "API enumeration failed, trying pattern scan...\n"));

		// Fallback: Find fltmgr.sys and pattern scan for FltGlobals
		ULONG fltmgrSize = 0;
		PVOID fltmgrBase = GetFltMgrBaseAddress(&fltmgrSize);
		if (fltmgrBase)
		{
			PVOID fltGlobals = FindFltGlobals(fltmgrBase, fltmgrSize);
			if (fltGlobals)
			{
				__try
				{
					// Get FrameList from FltGlobals
					PLIST_ENTRY frameListHead = (PLIST_ENTRY)((PUCHAR)fltGlobals + FLTGLOBALS_FRAMELIST_OFFSET);

					if (MmIsAddressValid(frameListHead) && MmIsAddressValid(frameListHead->Flink))
					{
						// Walk frames
						PLIST_ENTRY frameEntry = frameListHead->Flink;
						while (frameEntry != frameListHead && MmIsAddressValid(frameEntry) && filterCount < MAX_MINIFILTER_ENTRIES)
						{
							// Get frame from Links entry
							PUCHAR frame = (PUCHAR)frameEntry - FLTP_FRAME_LINKS_OFFSET;
							if (!MmIsAddressValid(frame))
							{
								frameEntry = frameEntry->Flink;
								continue;
							}

							ULONG frameId = *(PULONG)(frame + FLTP_FRAME_FRAMEID_OFFSET);
							KdPrint((DRIVER_PREFIX "Frame ID: %u at %p\n", frameId, frame));

							// Get filter list from frame
							PLIST_ENTRY filterListHead = (PLIST_ENTRY)(frame + FLTP_FRAME_FILTERLIST_OFFSET);
							if (MmIsAddressValid(filterListHead) && MmIsAddressValid(filterListHead->Flink))
							{
								PLIST_ENTRY filterEntry = filterListHead->Flink;
								while (filterEntry != filterListHead && MmIsAddressValid(filterEntry) && filterCount < MAX_MINIFILTER_ENTRIES)
								{
									// Get FLT_FILTER from PrimaryLink (FLT_OBJECT.PrimaryLink at +0x10)
									PUCHAR filter = (PUCHAR)filterEntry - FLT_FILTER_PRIMARYLINK_OFFSET;
									if (!MmIsAddressValid(filter))
									{
										filterEntry = filterEntry->Flink;
										continue;
									}

									MinifilterInfo* filterInfo = &response->Entries[filterCount];
									filterInfo->Index = filterCount;
									filterInfo->FilterAddress = (ULONG64)filter;
									filterInfo->FrameId = frameId;
									filterInfo->Flags = *(PULONG)(filter + FLT_FILTER_FLAGS_OFFSET);

									// Read filter name
									PUNICODE_STRING filterName = (PUNICODE_STRING)(filter + FLT_FILTER_NAME_OFFSET);
									if (MmIsAddressValid(filterName) && filterName->Buffer && MmIsAddressValid(filterName->Buffer))
									{
										ANSI_STRING ansiName;
										ansiName.Buffer = filterInfo->FilterName;
										ansiName.Length = 0;
										ansiName.MaximumLength = MAX_FILTER_NAME_LENGTH - 1;
										RtlUnicodeStringToAnsiString(&ansiName, filterName, FALSE);
									}

									// Read altitude
									PUNICODE_STRING altitude = (PUNICODE_STRING)(filter + FLT_FILTER_ALTITUDE_OFFSET);
									if (MmIsAddressValid(altitude) && altitude->Buffer && MmIsAddressValid(altitude->Buffer))
									{
										ANSI_STRING ansiAlt;
										ansiAlt.Buffer = filterInfo->Altitude;
										ansiAlt.Length = 0;
										ansiAlt.MaximumLength = MAX_ALTITUDE_LENGTH - 1;
										RtlUnicodeStringToAnsiString(&ansiAlt, altitude, FALSE);
									}

									// Resolve owner module
									CallbackInformation tempInfo = { 0 };
									tempInfo.CallbackAddress = (ULONG64)filter;
									SearchLoadedModules(&tempInfo);
									RtlCopyMemory(filterInfo->OwnerModuleName, tempInfo.ModuleName, MAX_MODULE_NAME_LENGTH);

									KdPrint((DRIVER_PREFIX "Filter[%u]: %s (Alt: %s)\n",
										filterCount, filterInfo->FilterName, filterInfo->Altitude));

									filterCount++;
									filterEntry = filterEntry->Flink;
								}
							}

							frameEntry = frameEntry->Flink;
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					KdPrint((DRIVER_PREFIX "Exception during pattern-based minifilter enumeration\n"));
				}
			}
		}
	}

	response->Count = filterCount;
	KdPrint((DRIVER_PREFIX "Found %u total minifilters\n", filterCount));
	*info = requiredSize;
	return STATUS_SUCCESS;
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
