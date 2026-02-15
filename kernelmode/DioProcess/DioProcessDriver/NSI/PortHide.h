#pragma once

#include "../pch.h"
#include "../DioProcessCommon.h"

// Pool tag for PortHide allocations
#define PORTHIDE_POOL_TAG 'dHtP'

// Maximum number of hidden ports
#define MAX_HIDDEN_PORTS 64

// IOCTL code used by NSI to query all TCP connection entries
#define IOCTL_NSI_GETALLPARAM 0x12001B

// Byte order helpers
#define PORTHIDE_HTONS(x) ((USHORT)((((x) & 0xFF) << 8) | (((x) & 0xFF00) >> 8)))
#define PORTHIDE_NTOHS(x) PORTHIDE_HTONS(x)

// ============== NSI Structures ==============

typedef struct _NSI_TCP_SUBENTRY {
	UCHAR Reserved1[2];
	USHORT Port;
	ULONG IpAddress;
	UCHAR IpAddress6[16];
	UCHAR Reserved2[4];
} NSI_TCP_SUBENTRY, *PNSI_TCP_SUBENTRY;

typedef struct _NSI_TCP_ENTRY {
	NSI_TCP_SUBENTRY Local;
	NSI_TCP_SUBENTRY Remote;
} NSI_TCP_ENTRY, *PNSI_TCP_ENTRY;

typedef struct _NSI_PARAM {
	SIZE_T Reserved1;
	SIZE_T Reserved2;
	PVOID  ModuleId;
	ULONG  Type;
	ULONG  Reserved3;
	ULONG  Reserved4;
	PVOID  Entries;
	SIZE_T EntrySize;
	PVOID  Reserved5;
	SIZE_T Reserved6;
	PVOID  StatusEntries;
	SIZE_T Reserved7;
	PVOID  ProcessEntries;
	SIZE_T ProcessEntrySize;
	SIZE_T Count;
} NSI_PARAM, *PNSI_PARAM;

// ============== Globals (defined in PortHide.cpp) ==============

extern PDEVICE_OBJECT g_NsiPreviousDevice;
extern PDRIVER_DISPATCH g_NsiPreviousDispatch;
extern USHORT g_HiddenPorts[MAX_HIDDEN_PORTS];
extern ULONG g_HiddenPortCount;
extern KSPIN_LOCK g_HiddenPortLock;
extern BOOLEAN g_PortHideInitialized;

// ============== Functions ==============

// Initialize NSI hook (attach to \Device\Nsi)
NTSTATUS PortHide_Init(
	_In_ PDRIVER_OBJECT DriverObject
);

// Cleanup NSI hook (detach, restore original dispatch)
VOID PortHide_Cleanup();

// Add a port to the hidden list
NTSTATUS PortHide_AddPort(
	_In_ USHORT Port
);

// Remove a port from the hidden list by index
NTSTATUS PortHide_RemovePort(
	_In_ ULONG Index
);

// Get the list of hidden ports
NTSTATUS PortHide_GetList(
	_Out_ HiddenPortEntry* Entries,
	_Out_ ULONG* Count,
	_In_ ULONG MaxEntries
);
