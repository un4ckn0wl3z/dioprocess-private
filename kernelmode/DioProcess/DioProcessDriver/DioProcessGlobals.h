#pragma once

#include "pch.h"
#include "DioProcessDriver.h"

// ============== Global Variables ==============
// Defined in DioProcessDriver.cpp, used across all modules

extern DioProcessState g_State;
extern PVOID g_ObCallbackHandle;
extern LARGE_INTEGER g_RegistryCookie;
extern BOOLEAN g_CallbacksRegistered;
extern PDRIVER_OBJECT g_DriverObject;

// ============== Removed Callback Storage ==============
// Storage for callback data that was removed, allowing restoration

#define MAX_REMOVED_CALLBACKS 64

// Storage for removed array-based callbacks (Process, Thread, Image)
struct RemovedArrayCallback
{
	BOOLEAN IsRemoved;                           // TRUE if this slot contains removed data
	ULONG64 OriginalValue;                       // Original callback slot value
	ULONG64 SlotAddress;                         // Address of the slot in the callback array
};

extern RemovedArrayCallback g_RemovedProcessCallbacks[MAX_REMOVED_CALLBACKS];
extern RemovedArrayCallback g_RemovedThreadCallbacks[MAX_REMOVED_CALLBACKS];
extern RemovedArrayCallback g_RemovedImageCallbacks[MAX_REMOVED_CALLBACKS];

// Storage for removed object callbacks
struct RemovedObjectCallback
{
	BOOLEAN IsRemoved;                           // TRUE if this entry contains removed data
	PVOID PreOperation;                          // Original PreOperation callback
	PVOID PostOperation;                         // Original PostOperation callback
	PVOID CallbackEntryItem;                     // Pointer to CALLBACK_ENTRY_ITEM
};

extern RemovedObjectCallback g_RemovedProcessObjectCallbacks[MAX_REMOVED_CALLBACKS];
extern RemovedObjectCallback g_RemovedThreadObjectCallbacks[MAX_REMOVED_CALLBACKS];

// Storage for removed registry callbacks
struct RemovedRegistryCallback
{
	BOOLEAN IsRemoved;                           // TRUE if this entry contains removed data
	ULONG64 OriginalFunction;                    // Original callback function address
	PVOID CallbackItem;                          // Pointer to REGISTRY_CALLBACK_ITEM
	LIST_ENTRY OriginalLinks;                    // Original Flink/Blink for re-linking
};

extern RemovedRegistryCallback g_RemovedRegistryCallbacks[MAX_REMOVED_CALLBACKS];

// Dynamic registry callback offsets (from PDB resolution)
struct RegistryCallbackOffsets
{
	ULONG CookieOffset;                          // Offset of Cookie field in _CM_CALLBACK_CONTEXT_BLOCK
	ULONG FunctionOffset;                        // Offset of Function field
	ULONG ContextOffset;                         // Offset of CallerContext field
	ULONG AltitudeOffset;                        // Offset of Altitude field
	BOOLEAN IsInitialized;                       // TRUE if offsets have been set
};

extern RegistryCallbackOffsets g_RegistryCallbackOffsets;

// ============== Forward Declarations - Callbacks ==============

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

// ============== Forward Declarations - Helpers ==============

WINDOWS_VERSION GetWindowsVersion();
void GetProcessImageName(PEPROCESS Process, PUNICODE_STRING ImageName);
void AddItem(FullEventData* item);
NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0);

// ============== Forward Declarations - Enumeration ==============

void SearchLoadedModules(CallbackInformation* CallbackInfo);
ULONG64 FindCallbackArray(const WCHAR* ExportedFunctionName);
ULONG64 FindPspSetCreateProcessNotifyRoutine(WINDOWS_VERSION WindowsVersion);
ULONG64 FindPspCreateThreadNotifyRoutine(WINDOWS_VERSION WindowsVersion);
ULONG64 FindPspLoadImageNotifyRoutine(WINDOWS_VERSION WindowsVersion);
ULONG64 FindCmCallbackListHead();

// PspCidTable enumeration
PVOID64 GetPspCidTableAddress();
ULONG64 DecryptCidEntry(ULONG64 encryptedValue);
VOID ParseCidTable1(ULONG64 baseAddr, INT index1, INT index2, CidEntry* entries, ULONG* count, ULONG maxEntries);
VOID ParseCidTable2(ULONG64 baseAddr, INT index2, CidEntry* entries, ULONG* count, ULONG maxEntries);
VOID ParseCidTable3(ULONG64 baseAddr, CidEntry* entries, ULONG* count, ULONG maxEntries);

// Minifilter enumeration (using Filter Manager APIs)
BOOLEAN EnumerateMinifiltersViaApi(MinifilterInfo* entries, ULONG* count, ULONG maxEntries);
NTSTATUS UnlinkMinifilterCallbacks(const WCHAR* filterName);

// Kernel driver enumeration
extern "C" NTKERNELAPI PLIST_ENTRY PsLoadedModuleList;
BOOLEAN EnumerateKernelDrivers(KernelDriverInfo* entries, ULONG* count, ULONG maxEntries);

// ============== Forward Declarations - Injection ==============

PPEB GetProcessPeb(PEPROCESS Process, WINDOWS_VERSION WindowsVersion);
PVOID GetUserModuleBaseAddress(PEPROCESS Process, PUNICODE_STRING ModuleName, WINDOWS_VERSION WindowsVersion);
PVOID GetModuleExportAddress(PVOID ModuleBase, PCCHAR FunctionName);
PVOID GetLoadLibraryWAddress(ULONG ProcessId, WINDOWS_VERSION WindowsVersion);
NTSTATUS KernelInjectDll(ULONG ProcessId, PCWSTR DllPath, PVOID* AllocatedAddress, PVOID* LoadLibraryAddress);
NTSTATUS KernelInjectShellcode(ULONG ProcessId, PVOID Shellcode, SIZE_T ShellcodeSize, PVOID* AllocatedAddress);

// ============== Forward Declarations - FileHide ==============

// Stored copy of RegistryPath for minifilter initialization
extern UNICODE_STRING g_RegistryPath;
extern WCHAR g_RegistryPathBuffer[512];
extern BOOLEAN g_FileHideInitialized;

NTSTATUS HandleFileHideHide(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleFileHideUnhide(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleFileHideList(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// ============== Forward Declarations - IRP Handlers ==============

NTSTATUS DioProcessCreateClose(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS DioProcessRead(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS DioProcessDeviceControl(PDEVICE_OBJECT, PIRP Irp);

// ============== Forward Declarations - IOCTL Handlers ==============

NTSTATUS HandleRegisterCallbacks(PIRP Irp);
NTSTATUS HandleUnregisterCallbacks(PIRP Irp);
NTSTATUS HandleStartCollection(PIRP Irp);
NTSTATUS HandleStopCollection(PIRP Irp);
NTSTATUS HandleGetCollectionState(PIRP Irp, PULONG_PTR info);

NTSTATUS HandleProtectProcess(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleUnprotectProcess(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleEnablePrivileges(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleClearDebugFlags(PIRP Irp, PIO_STACK_LOCATION irpSp);

NTSTATUS HandleEnumProcessCallbacks(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleEnumThreadCallbacks(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleEnumImageCallbacks(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleEnumObjectCallbacks(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleEnumMinifilters(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleUnlinkMinifilter(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleEnumDrivers(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleEnumPspCidTable(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// Callback removal handlers
NTSTATUS HandleRemoveProcessCallback(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleRemoveThreadCallback(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleRemoveImageCallback(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleRemoveObjectCallback(PIRP Irp, PIO_STACK_LOCATION irpSp);

// Registry callback handlers (RCK style)
NTSTATUS HandleEnumRegistryCallbacks(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleRemoveRegistryCallback(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleSetRegistryCallbackOffsets(PIRP Irp, PIO_STACK_LOCATION irpSp);

// Callback restore handlers
NTSTATUS HandleRestoreProcessCallback(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleRestoreThreadCallback(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleRestoreImageCallback(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleRestoreObjectCallback(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleRestoreRegistryCallback(PIRP Irp, PIO_STACK_LOCATION irpSp);

NTSTATUS HandleKernelInjectShellcode(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleKernelInjectDll(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// Hypervisor Control Handlers
NTSTATUS HandleHvStart(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvStop(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvPing(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvInstallHooks(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvRemoveHooks(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvProtectProcess(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvUnprotectProcess(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvIsProcessProtected(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvListProtected(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvHideDriver(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvUnhideDriver(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvIsDriverHidden(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvRemoveHiddenDriver(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvClearHiddenDrivers(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvListHiddenDrivers(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// Ring -1 Injection Handlers
NTSTATUS HandleHvInjectShellcode(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvInjectDll(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// Ring -1 Memory Read/Write Handlers (HV Scanner)
NTSTATUS HandleHvReadVm(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvWriteVm(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleHvAllocWriteNear(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// Early Injection Handlers
NTSTATUS HandleEarlyInjectArm(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleEarlyInjectDisarm(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleEarlyInjectStatus(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// DKOM Process Hiding Handlers
NTSTATUS HandleProcessHide(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleProcessUnhide(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleProcessHideList(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// Physical Memory Handlers
NTSTATUS HandleTranslateVA(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleReadPhysical(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleWritePhysical(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandlePhysReadVm(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// NSI Port Hiding Handlers
NTSTATUS HandlePortHide(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandlePortUnhide(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandlePortHideList(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

// Process Kill Handlers
NTSTATUS HandleKillTerminate(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleKillUnmap(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleKillPebCorrupt(PIRP Irp, PIO_STACK_LOCATION irpSp);
