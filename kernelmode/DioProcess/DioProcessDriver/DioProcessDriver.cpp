#include "pch.h"
#include "DioProcessGlobals.h"
#include "Locker.h"
#include "Hypervisor/HvProtection.h"
#include "Injection/EarlyInjection.h"
#include "FileHide/FileHide.h"
#include "DKOM/ProcessHide.h"
#include "NSI/PortHide.h"
#include "EptHook/UsermodeEptHook.h"
#include "WFP/WfpCapture.h"

#pragma comment(lib, "aux_klib.lib")
#pragma comment(lib, "fltMgr.lib")

// ============== Global Variable Definitions ==============

DioProcessState g_State;
PVOID g_ObCallbackHandle = nullptr;
LARGE_INTEGER g_RegistryCookie = { 0 };
BOOLEAN g_CallbacksRegistered = FALSE;
PDRIVER_OBJECT g_DriverObject = nullptr;

// Registry path storage for minifilter initialization
UNICODE_STRING g_RegistryPath = { 0 };
WCHAR g_RegistryPathBuffer[512] = { 0 };

// Removed callback storage for restoration
RemovedArrayCallback g_RemovedProcessCallbacks[MAX_REMOVED_CALLBACKS] = { 0 };
RemovedArrayCallback g_RemovedThreadCallbacks[MAX_REMOVED_CALLBACKS] = { 0 };
RemovedArrayCallback g_RemovedImageCallbacks[MAX_REMOVED_CALLBACKS] = { 0 };
RemovedObjectCallback g_RemovedProcessObjectCallbacks[MAX_REMOVED_CALLBACKS] = { 0 };
RemovedObjectCallback g_RemovedThreadObjectCallbacks[MAX_REMOVED_CALLBACKS] = { 0 };
RemovedRegistryCallback g_RemovedRegistryCallbacks[MAX_REMOVED_CALLBACKS] = { 0 };

// Dynamic registry callback offsets (initialized with defaults, updated via IOCTL)
RegistryCallbackOffsets g_RegistryCallbackOffsets = {
	0x18,  // CookieOffset - default for Windows 10 22H2
	0x28,  // FunctionOffset
	0x20,  // ContextOffset
	0x30,  // AltitudeOffset
	FALSE  // IsInitialized
};

// Dynamic ETHREAD offsets (initialized with defaults, updated via IOCTL)
EthreadOffsets g_EthreadOffsets = {
	0x620,  // Win32StartAddressOffset - default for Windows 10 22H2
	0x184,  // StateOffset
	0x185,  // WaitReasonOffset
	FALSE   // IsInitialized
};

// ============== Helper Function Implementations ==============

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

// ============== Driver Unload ==============

void DioProcessUnload(PDRIVER_OBJECT DriverObject)
{
	KdPrint((DRIVER_PREFIX "Unloading driver\n"));

	// Clean up usermode EPT hooks BEFORE hypervisor shutdown (needs VMCALLs)
	UsermodeEptHook_RemoveAll();

	// CRITICAL: Clean up hypervisor FIRST before anything else
	// This must happen before callback unregistration to prevent BSOD
	// (DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS)
	if (HvAreHooksInstalled())
	{
		KdPrint((DRIVER_PREFIX "Removing hypervisor protection hooks...\n"));
		HvRemoveProtectionHooks();
	}
	if (HvIsHypervisorRunning())
	{
		KdPrint((DRIVER_PREFIX "Stopping hypervisor...\n"));
		HvStopHypervisor();
	}
	KdPrint((DRIVER_PREFIX "Hypervisor cleanup complete\n"));

	// Clean up DKOM process hiding (unhide all before unload)
	ProcessHide_Cleanup();

	// Clean up NSI port hiding
	PortHide_Cleanup();

	// Clean up file hiding minifilter
	FileHide_Cleanup();

	// Clean up WFP packet capture
	WfpCaptureCleanup();

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

// ============== Driver Entry ==============

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	// Save RegistryPath for minifilter initialization (it's only valid during DriverEntry)
	g_RegistryPath.Buffer = g_RegistryPathBuffer;
	g_RegistryPath.MaximumLength = sizeof(g_RegistryPathBuffer);
	RtlCopyUnicodeString(&g_RegistryPath, RegistryPath);

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

	g_DriverObject = DriverObject;
	g_State.Lock.Init();
	InitializeListHead(&g_State.ItemsHead);
	g_State.CollectionEnabled = FALSE;  // Collection disabled by default
	g_CallbacksRegistered = FALSE;      // Callbacks not registered by default

	// Initialize early injection subsystem
	EarlyInjectionInit();

	// Initialize DKOM process hiding (non-fatal)
	ProcessHide_Init();

	// Initialize WFP packet capture (non-fatal if it fails)
	status = WfpCaptureInit(devObj);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "WFP Packet Capture init failed (0x%X) - feature disabled\n", status));
		// Continue anyway, packet capture just won't work
	}

	// FileHide and PortHide are NOT initialized here.
	// They require the NSI dispatch hook / minifilter to be active, which causes a
	// SYSTEM_SERVICE_EXCEPTION (0x3b) BSOD if the driver is unloaded while any
	// background IRP has our completion routine set.
	// Both subsystems are initialized lazily on first use via their respective IOCTLs.

	DriverObject->DriverUnload = DioProcessUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = DioProcessCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = DioProcessRead;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DioProcessDeviceControl;

	KdPrint((DRIVER_PREFIX "Driver loaded successfully (callbacks NOT registered yet)\n"));
	return STATUS_SUCCESS;
}