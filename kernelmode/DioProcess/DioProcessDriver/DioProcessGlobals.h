#pragma once

#include "pch.h"
#include "DioProcessDriver.h"

// ============== Global Variables ==============
// Defined in DioProcessDriver.cpp, used across all modules

extern DioProcessState g_State;
extern PVOID g_ObCallbackHandle;
extern LARGE_INTEGER g_RegistryCookie;
extern BOOLEAN g_CallbacksRegistered;

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

// PspCidTable enumeration
PVOID64 GetPspCidTableAddress();
ULONG64 DecryptCidEntry(ULONG64 encryptedValue);
VOID ParseCidTable1(ULONG64 baseAddr, INT index1, INT index2, CidEntry* entries, ULONG* count, ULONG maxEntries);
VOID ParseCidTable2(ULONG64 baseAddr, INT index2, CidEntry* entries, ULONG* count, ULONG maxEntries);
VOID ParseCidTable3(ULONG64 baseAddr, CidEntry* entries, ULONG* count, ULONG maxEntries);

// Minifilter enumeration
PVOID GetFltMgrBaseAddress(PULONG pSize);
PVOID FindFltGlobals(PVOID fltmgrBase, ULONG fltmgrSize);
PVOID GetModuleExport(PVOID moduleBase, PCSTR exportName);
BOOLEAN EnumerateMinifiltersViaApi(MinifilterInfo* entries, ULONG* count, ULONG maxEntries);

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
NTSTATUS HandleEnumDrivers(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleEnumPspCidTable(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);

NTSTATUS HandleKernelInjectShellcode(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
NTSTATUS HandleKernelInjectDll(PIRP Irp, PIO_STACK_LOCATION irpSp, PULONG_PTR info);
