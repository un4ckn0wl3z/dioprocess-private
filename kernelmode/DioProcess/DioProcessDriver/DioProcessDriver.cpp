#include "pch.h"
#include "DioProcessGlobals.h"
#include "Locker.h"

#pragma comment(lib, "aux_klib.lib")

// ============== Global Variable Definitions ==============

DioProcessState g_State;
PVOID g_ObCallbackHandle = nullptr;
LARGE_INTEGER g_RegistryCookie = { 0 };
BOOLEAN g_CallbacksRegistered = FALSE;

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
