/**
 * @file DioProcessSDK.h
 * @brief DioProcess Driver SDK - Usermode interface for kernel driver communication
 * 
 * This SDK provides a clean C/C++ interface for communicating with the DioProcess
 * kernel driver. It includes all IOCTL codes, structures, and inline wrapper functions.
 * 
 * @usage
 *   #include "DioProcessSDK.h"
 *   
 *   DioProcessSDK sdk;
 *   if (sdk.Open()) {
 *       sdk.ProtectProcess(GetCurrentProcessId());
 *       // ... use other functions
 *       sdk.Close();
 *   }
 */

#pragma once

#ifndef DIOPROCESS_SDK_H
#define DIOPROCESS_SDK_H

// ============================================================================
// Windows Headers
// ============================================================================

#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <winioctl.h>
#include <cstdint>

// ============================================================================
// Driver Device Name
// ============================================================================

#define DIOPROCESS_DEVICE_NAME L"\\\\.\\DioProcess"

// ============================================================================
// IOCTL Code Definitions
// ============================================================================

// Collection control IOCTLs
#define IOCTL_DIOPROCESS_START_COLLECTION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_STOP_COLLECTION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_GET_COLLECTION_STATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_REGISTER_CALLBACKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_UNREGISTER_CALLBACKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Security research IOCTLs
#define IOCTL_DIOPROCESS_PROTECT_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_UNPROTECT_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_ENABLE_PRIVILEGES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_CLEAR_DEBUG_FLAGS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Callback enumeration IOCTLs
#define IOCTL_DIOPROCESS_ENUM_PROCESS_CALLBACKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_ENUM_THREAD_CALLBACKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_ENUM_IMAGE_CALLBACKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Kernel injection IOCTLs
#define IOCTL_DIOPROCESS_KERNEL_INJECT_SHELLCODE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_KERNEL_INJECT_DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_KERNEL_MANUAL_MAP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)

// PspCidTable enumeration IOCTL
#define IOCTL_DIOPROCESS_ENUM_PSPCIDTABLE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Object callback enumeration IOCTL
#define IOCTL_DIOPROCESS_ENUM_OBJECT_CALLBACKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Minifilter enumeration IOCTL
#define IOCTL_DIOPROCESS_ENUM_MINIFILTERS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Callback removal IOCTLs
#define IOCTL_DIOPROCESS_REMOVE_PROCESS_CALLBACK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_ENUM_DRIVERS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_REMOVE_THREAD_CALLBACK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_REMOVE_IMAGE_CALLBACK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_REMOVE_OBJECT_CALLBACK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_UNLINK_MINIFILTER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Callback restore IOCTLs
#define IOCTL_DIOPROCESS_RESTORE_PROCESS_CALLBACK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_RESTORE_THREAD_CALLBACK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_RESTORE_IMAGE_CALLBACK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_RESTORE_OBJECT_CALLBACK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_RESTORE_REGISTRY_CALLBACK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81D, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Registry callback IOCTLs
#define IOCTL_DIOPROCESS_ENUM_REGISTRY_CALLBACKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_REMOVE_REGISTRY_CALLBACK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81F, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Hypervisor control IOCTLs
#define IOCTL_DIOPROCESS_HV_START \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_STOP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_PING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_INSTALL_HOOKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_REMOVE_HOOKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Hypervisor process protection IOCTLs
#define IOCTL_DIOPROCESS_HV_PROTECT_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_UNPROTECT_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_IS_PROCESS_PROTECTED \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_LIST_PROTECTED \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x833, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Hypervisor driver hiding IOCTLs
#define IOCTL_DIOPROCESS_HV_HIDE_DRIVER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x834, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_UNHIDE_DRIVER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x835, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_IS_DRIVER_HIDDEN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x836, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_REMOVE_HIDDEN_DRIVER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x837, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_CLEAR_HIDDEN_DRIVERS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x838, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_LIST_HIDDEN_DRIVERS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x839, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Hypervisor injection IOCTLs
#define IOCTL_DIOPROCESS_HV_INJECT_SHELLCODE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_INJECT_DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x841, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Hypervisor memory read/write IOCTLs
#define IOCTL_DIOPROCESS_HV_READ_VM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x842, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_WRITE_VM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x843, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_ALLOC_WRITE_NEAR \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x844, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Early injection IOCTLs
#define IOCTL_DIOPROCESS_EARLY_INJECT_ARM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x850, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_EARLY_INJECT_DISARM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x851, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_EARLY_INJECT_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x852, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Kernel memory copy IOCTL
#define IOCTL_DIOPROCESS_COPY_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x860, METHOD_BUFFERED, FILE_ANY_ACCESS)

// File hiding IOCTLs
#define IOCTL_DIOPROCESS_FILEHIDE_HIDE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x870, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_FILEHIDE_UNHIDE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x871, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_FILEHIDE_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x872, METHOD_BUFFERED, FILE_ANY_ACCESS)

// DKOM process hiding IOCTLs
#define IOCTL_DIOPROCESS_PROCESS_HIDE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x880, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_PROCESS_UNHIDE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x881, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_PROCESS_HIDE_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x882, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Physical memory translation IOCTLs
#define IOCTL_DIOPROCESS_TRANSLATE_VA \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x890, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_READ_PHYSICAL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x891, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_WRITE_PHYSICAL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x892, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_PHYS_READ_VM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x893, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_ENUM_VM_REGIONS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x894, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Port hiding IOCTLs
#define IOCTL_DIOPROCESS_PORT_HIDE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_PORT_UNHIDE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_PORT_HIDE_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A2, METHOD_BUFFERED, FILE_ANY_ACCESS)

// EPT hook IOCTLs
#define IOCTL_DIOPROCESS_EPT_HOOK_INSTALL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_EPT_HOOK_REMOVE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_EPT_HOOK_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_EPT_HOOK_INSTALL_DETOUR \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B3, METHOD_BUFFERED, FILE_ANY_ACCESS)

// EPT register change IOCTLs
#define IOCTL_DIOPROCESS_REG_CHANGE_INSTALL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8C0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_REG_CHANGE_REMOVE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8C1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_REG_CHANGE_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8C2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_REG_CHANGE_REMOVE_ALL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8C3, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Memory protection hiding IOCTL
#define IOCTL_DIOPROCESS_HIDE_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8D0, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Process kill IOCTLs
#define IOCTL_DIOPROCESS_KILL_TERMINATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8E0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_KILL_UNMAP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8E1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_KILL_PEB_CORRUPT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8E2, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Registry callback offsets IOCTL
#define IOCTL_DIOPROCESS_SET_REGISTRY_CALLBACK_OFFSETS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8F0, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Process/thread control IOCTLs
#define IOCTL_DIOPROCESS_SUSPEND_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8F1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_RESUME_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8F2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_SUSPEND_THREAD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8F4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_RESUME_THREAD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8F5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_TERMINATE_THREAD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8F6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_ENUM_SYSTEM_THREADS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8F7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_SET_ETHREAD_OFFSETS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8F8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_ENUM_ALL_KERNEL_THREADS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8F9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_SET_THREAD_API_ADDRESSES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8FA, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Packet capture IOCTLs
#define IOCTL_DIOPROCESS_PACKET_START_CAPTURE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_PACKET_STOP_CAPTURE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_PACKET_GET_PACKETS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_PACKET_INJECT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_PACKET_ADD_FILTER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_PACKET_REMOVE_FILTER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_PACKET_CLEAR_FILTERS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_PACKET_CLEAR_BUFFER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x907, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_PACKET_GET_STATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x908, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// Constants
// ============================================================================

#define MAX_HIDDEN_DRIVERS 16
#define MAX_DLL_PATH_LENGTH 520
#define MAX_CID_ENTRIES 2048
#define MAX_PROCESS_NAME_LENGTH 16
#define MAX_CALLBACK_ENTRIES 64
#define MAX_MODULE_NAME_LENGTH 256
#define MAX_OBJECT_CALLBACK_ENTRIES 64
#define MAX_ALTITUDE_LENGTH 64
#define MAX_REGISTRY_CALLBACK_ENTRIES 64
#define MAX_MINIFILTER_ENTRIES 64
#define MAX_FILTER_NAME_LENGTH 64
#define MAX_DRIVER_ENTRIES 512
#define MAX_DRIVER_NAME_LENGTH 64
#define MAX_DRIVER_PATH_LENGTH 260
#define MAX_HV_PROTECTED_PIDS 64
#define MAX_TARGET_PROCESS_NAME 64
#define MAX_FILEHIDE_ENTRIES 128
#define MAX_DKOM_HIDDEN_PROCESSES 64
#define PHYS_READ_VM_MAX_SIZE (64 * 1024)
#define HV_READ_VM_MAX_SIZE (64 * 1024)
#define MAX_EPT_HOOK_DETOUR_SIZE 3800
#define MAX_EPT_HOOK_LIST_ENTRIES 32
#define MAX_REG_CHANGES 32
#define MAX_PORTHIDE_ENTRIES 64
#define MAX_VM_REGION_ENTRIES 4096
#define MAX_PACKET_PAYLOAD_SIZE 1500
#define MAX_SYSTEM_THREADS 512
#define MAX_KERNEL_THREADS 1024

// Manual map flags
#define MANUAL_MAP_FLAG_NONE            0x00000000
#define MANUAL_MAP_FLAG_ERASE_HEADERS   0x00000001
#define MANUAL_MAP_FLAG_NO_ENTRY_POINT  0x00000002
#define MANUAL_MAP_FLAG_NO_IMPORTS      0x00000004

// IRP major function indices for minifilter
#define IRP_MJ_CREATE_INDEX          0
#define IRP_MJ_READ_INDEX            3
#define IRP_MJ_WRITE_INDEX           4
#define IRP_MJ_SET_INFORMATION_INDEX 6
#define IRP_MJ_CLEANUP_INDEX         18

// ============================================================================
// Enumerations
// ============================================================================

enum class EventType
{
    ProcessCreate,
    ProcessExit,
    ThreadCreate,
    ThreadExit,
    ImageLoad,
    ProcessHandleCreate,
    ProcessHandleDuplicate,
    ThreadHandleCreate,
    ThreadHandleDuplicate,
    RegistryCreate,
    RegistryOpen,
    RegistrySetValue,
    RegistryDeleteKey,
    RegistryDeleteValue,
    RegistryRenameKey,
    RegistryQueryValue,
};

enum class RegistryOperation : ULONG
{
    CreateKey,
    OpenKey,
    SetValue,
    DeleteKey,
    DeleteValue,
    RenameKey,
    QueryValue,
};

enum class ProcessProtectionLevel : UCHAR
{
    ProtectionNone = 0x00,
    PS_PROTECTED_AUTHENTICODE_LIGHT = 0x11,
    PS_PROTECTED_ANTIMALWARE_LIGHT = 0x31,
    PS_PROTECTED_LSA_LIGHT = 0x41,
    PS_PROTECTED_WINDOWS_LIGHT = 0x51,
    PS_PROTECTED_WINTCB_LIGHT = 0x61,
    PS_PROTECTED_AUTHENTICODE = 0x12,
    PS_PROTECTED_WINDOWS = 0x52,
    PS_PROTECTED_WINTCB = 0x62,
    PS_PROTECTED_SYSTEM = 0x72,
};

enum class CidObjectType : UCHAR
{
    CidProcess = 1,
    CidThread = 2
};

enum class ObjectCallbackType : UCHAR
{
    ObjectCallbackProcess = 1,
    ObjectCallbackThread = 2
};

enum class ObjectCallbackOperations : ULONG
{
    OpHandleCreate = 1,
    OpHandleDuplicate = 2
};

enum class EarlyInjectionMethod : ULONG
{
    EarlyInjectTrampoline = 0,
    EarlyInjectApcCallback = 1
};

enum class PacketDirection : UCHAR
{
    Outbound = 0,
    Inbound = 1
};

enum class PacketProtocol : UCHAR
{
    TCP = 6,
    UDP = 17
};

enum class PacketFilterAction : UCHAR
{
    Allow = 0,
    Block = 1
};

// ============================================================================
// Basic Structures
// ============================================================================

struct EventHeader
{
    EventType Type;
    ULONG Size;
    ULONG64 Timestamp;
};

struct ProcessCreateInfo
{
    ULONG ProcessId;
    ULONG ParentProcessId;
    ULONG CreatingProcessId;
    ULONG CommandLineLength;
    WCHAR CommandLine[1];
};

struct ProcessExitInfo
{
    ULONG ProcessId;
    ULONG ExitCode;
};

struct ThreadCreateInfo
{
    ULONG ProcessId;
    ULONG ThreadId;
};

struct ThreadExitInfo : ThreadCreateInfo
{
    ULONG ExitCode;
};

struct ImageLoadInfo
{
    ULONG ProcessId;
    ULONG64 ImageBase;
    ULONG64 ImageSize;
    BOOLEAN IsSystemImage;
    BOOLEAN IsKernelImage;
    ULONG ImageNameLength;
    WCHAR ImageName[1];
};

struct HandleOperationInfo
{
    ULONG SourceProcessId;
    ULONG SourceThreadId;
    ULONG TargetProcessId;
    ULONG TargetThreadId;
    ULONG DesiredAccess;
    ULONG GrantedAccess;
    BOOLEAN IsKernelHandle;
    ULONG SourceImageNameLength;
    WCHAR SourceImageName[1];
};

struct RegistryOperationInfo
{
    ULONG ProcessId;
    ULONG ThreadId;
    RegistryOperation Operation;
    NTSTATUS Status;
    ULONG KeyNameLength;
    ULONG ValueNameLength;
    WCHAR Names[1];
};

struct EventData
{
    EventHeader Header;
    union
    {
        ProcessCreateInfo ProcessCreate;
        ProcessExitInfo ProcessExit;
        ThreadCreateInfo ThreadCreate;
        ThreadExitInfo ThreadExit;
        ImageLoadInfo ImageLoad;
        HandleOperationInfo HandleOperation;
        RegistryOperationInfo RegistryOperation;
    };
};

struct CollectionStateResponse
{
    BOOLEAN IsCollecting;
    ULONG ItemCount;
};

struct TargetProcessRequest
{
    ULONG ProcessId;
};

struct ProtectProcessWithLevelRequest
{
    ULONG ProcessId;
    ProcessProtectionLevel Level;
    UCHAR _padding[3];
};

// ============================================================================
// Driver Hiding Structures
// ============================================================================

struct HideDriverRequest
{
    CHAR DriverName[64];
};

struct DriverHiddenResponse
{
    BOOLEAN IsHidden;
    ULONG HiddenCount;
};

struct HiddenDriverListResponse
{
    ULONG Count;
    CHAR DriverNames[MAX_HIDDEN_DRIVERS][64];
};

// ============================================================================
// Kernel Injection Structures
// ============================================================================

struct KernelInjectShellcodeRequest
{
    ULONG TargetProcessId;
    ULONG ShellcodeSize;
    UCHAR Shellcode[1];
};

struct KernelInjectShellcodeResponse
{
    ULONG64 AllocatedAddress;
    BOOLEAN Success;
};

struct KernelInjectDllRequest
{
    ULONG TargetProcessId;
    WCHAR DllPath[MAX_DLL_PATH_LENGTH];
};

struct KernelInjectDllResponse
{
    ULONG64 AllocatedAddress;
    ULONG64 LoadLibraryAddress;
    BOOLEAN Success;
};

struct KernelManualMapRequest
{
    ULONG TargetProcessId;
    ULONG Flags;
    ULONG DllSize;
    UCHAR DllBytes[1];
};

struct KernelManualMapResponse
{
    ULONG64 MappedBase;
    ULONG64 MappedSize;
    ULONG64 EntryPoint;
    BOOLEAN Success;
};

// ============================================================================
// PspCidTable Enumeration Structures
// ============================================================================

struct CidEntry
{
    ULONG Id;
    ULONG64 ObjectAddress;
    CidObjectType Type;
    ULONG ParentPid;
    CHAR ProcessName[MAX_PROCESS_NAME_LENGTH];
};

struct EnumCidTableResponse
{
    ULONG Count;
    CidEntry Entries[1];
};

// ============================================================================
// Callback Enumeration Structures
// ============================================================================

struct CallbackInformation
{
    CHAR ModuleName[MAX_MODULE_NAME_LENGTH];
    ULONG64 CallbackAddress;
    ULONG64 ModuleBase;
    ULONG64 ModuleOffset;
    ULONG Index;
};

struct RemoveCallbackRequest
{
    ULONG Index;
};

struct RestoreCallbackRequest
{
    ULONG Index;
};

// ============================================================================
// Object Callback Structures
// ============================================================================

struct ObjectCallbackInfo
{
    CHAR ModuleName[MAX_MODULE_NAME_LENGTH];
    CHAR Altitude[MAX_ALTITUDE_LENGTH];
    ULONG64 PreOperationCallback;
    ULONG64 PostOperationCallback;
    ULONG64 ModuleBase;
    ULONG64 PreOperationOffset;
    ULONG64 PostOperationOffset;
    ObjectCallbackType ObjectType;
    ObjectCallbackOperations Operations;
    ULONG Index;
};

struct RemoveObjectCallbackRequest
{
    ULONG Index;
    ObjectCallbackType ObjectType;
    UCHAR _padding[3];
    ULONG RemovePreOperation;
    ULONG RemovePostOperation;
};

struct RestoreObjectCallbackRequest
{
    ULONG Index;
    ObjectCallbackType ObjectType;
    UCHAR _padding[3];
    ULONG RestorePreOperation;
    ULONG RestorePostOperation;
};

struct EnumObjectCallbacksResponse
{
    ULONG Count;
    ObjectCallbackInfo Entries[1];
};

// ============================================================================
// Registry Callback Structures
// ============================================================================

struct RegistryCallbackInfo
{
    CHAR ModuleName[MAX_MODULE_NAME_LENGTH];
    CHAR Altitude[MAX_ALTITUDE_LENGTH];
    ULONG64 CallbackAddress;
    ULONG64 Context;
    ULONG64 ModuleBase;
    ULONG64 ModuleOffset;
    ULONG Index;
};

struct RemoveRegistryCallbackRequest
{
    ULONG Index;
};

struct SetRegistryCallbackOffsetsRequest
{
    ULONG CookieOffset;
    ULONG FunctionOffset;
    ULONG ContextOffset;
    ULONG AltitudeOffset;
};

struct RestoreRegistryCallbackRequest
{
    ULONG Index;
};

struct EnumRegistryCallbacksResponse
{
    ULONG Count;
    RegistryCallbackInfo Entries[1];
};

// ============================================================================
// Minifilter Structures
// ============================================================================

struct MinifilterCallbacks
{
    ULONG64 PreCreate;
    ULONG64 PostCreate;
    ULONG64 PreRead;
    ULONG64 PostRead;
    ULONG64 PreWrite;
    ULONG64 PostWrite;
    ULONG64 PreSetInfo;
    ULONG64 PostSetInfo;
    ULONG64 PreCleanup;
    ULONG64 PostCleanup;
};

struct MinifilterInfo
{
    CHAR FilterName[MAX_FILTER_NAME_LENGTH];
    CHAR Altitude[MAX_ALTITUDE_LENGTH];
    ULONG64 FilterAddress;
    ULONG64 FrameId;
    ULONG NumberOfInstances;
    ULONG Flags;
    MinifilterCallbacks Callbacks;
    CHAR OwnerModuleName[MAX_MODULE_NAME_LENGTH];
    ULONG Index;
};

struct EnumMinifiltersResponse
{
    ULONG Count;
    MinifilterInfo Entries[1];
};

struct UnlinkMinifilterRequest
{
    WCHAR FilterName[MAX_FILTER_NAME_LENGTH];
};

// ============================================================================
// Kernel Driver Enumeration Structures
// ============================================================================

struct KernelDriverInfo
{
    ULONG64 BaseAddress;
    ULONG64 Size;
    ULONG64 EntryPoint;
    ULONG64 DriverObject;
    ULONG Flags;
    ULONG LoadCount;
    CHAR DriverName[MAX_DRIVER_NAME_LENGTH];
    WCHAR DriverPath[MAX_DRIVER_PATH_LENGTH];
    ULONG Index;
};

struct EnumDriversResponse
{
    ULONG Count;
    KernelDriverInfo Entries[1];
};

// ============================================================================
// Hypervisor Control Structures
// ============================================================================

struct HvPingResponse
{
    BOOLEAN IsRunning;
    BOOLEAN HooksInstalled;
    ULONG ProtectedProcessCount;
};

struct HvProtectProcessRequest
{
    ULONG ProcessId;
};

struct HvIsProtectedResponse
{
    BOOLEAN IsProtected;
};

struct HvListProtectedResponse
{
    ULONG Count;
    ULONG Pids[MAX_HV_PROTECTED_PIDS];
};

struct HvInjectShellcodeRequest
{
    ULONG TargetProcessId;
    ULONG ShellcodeSize;
    UCHAR Shellcode[1];
};

struct HvInjectShellcodeResponse
{
    ULONG64 AllocatedAddress;
    ULONG64 BytesWritten;
    BOOLEAN Success;
};

struct HvInjectDllRequest
{
    ULONG TargetProcessId;
    ULONG PathLength;
    WCHAR DllPath[1];
};

struct HvInjectDllResponse
{
    ULONG64 ModuleBase;
    ULONG64 PathAddress;
    BOOLEAN Success;
};

struct HvReadVmRequest
{
    ULONG ProcessId;
    ULONG64 VirtualAddress;
    ULONG Size;
};

struct HvReadVmResponse
{
    ULONG BytesRead;
    BOOLEAN Success;
};

struct HvWriteVmRequest
{
    ULONG ProcessId;
    ULONG64 VirtualAddress;
    ULONG Size;
    UCHAR Data[1];
};

struct HvWriteVmResponse
{
    ULONG BytesWritten;
    BOOLEAN Success;
};

struct HvAllocWriteNearRequest
{
    ULONG ProcessId;
    ULONG64 NearAddress;
    ULONG Size;
    UCHAR Data[1];
};

struct HvAllocWriteNearResponse
{
    ULONG64 AllocatedAddress;
    ULONG BytesWritten;
    BOOLEAN Success;
};

// ============================================================================
// Early Injection Structures
// ============================================================================

struct EarlyInjectionArmRequest
{
    WCHAR TargetProcessName[MAX_TARGET_PROCESS_NAME];
    WCHAR DllPath[MAX_DLL_PATH_LENGTH];
    EarlyInjectionMethod Method;
    BOOLEAN OneShot;
};

struct EarlyInjectionStatusResponse
{
    BOOLEAN Armed;
    WCHAR TargetProcessName[MAX_TARGET_PROCESS_NAME];
    WCHAR DllPath[MAX_DLL_PATH_LENGTH];
    EarlyInjectionMethod Method;
    ULONG InjectionCount;
    ULONG LastInjectedPid;
    NTSTATUS LastStatus;
    BOOLEAN OneShot;
};

// ============================================================================
// Kernel Memory Copy Structures
// ============================================================================

struct KernelCopyMemoryRequest
{
    ULONG TargetProcessId;
    ULONG64 SourceAddress;
    ULONG64 DestinationAddress;
    ULONG Size;
};

struct KernelCopyMemoryResponse
{
    ULONG BytesCopied;
    BOOLEAN Success;
};

// ============================================================================
// File Hiding Structures
// ============================================================================

struct FileHideRequest
{
    WCHAR FilePath[260];
};

struct HiddenFileEntry
{
    WCHAR FilePath[260];
};

struct FileHideListResponse
{
    ULONG Count;
    HiddenFileEntry Entries[MAX_FILEHIDE_ENTRIES];
};

// ============================================================================
// DKOM Process Hiding Structures
// ============================================================================

struct HiddenProcessEntry
{
    ULONG Pid;
    CHAR ProcessName[16];
};

struct ProcessHideListResponse
{
    ULONG Count;
    HiddenProcessEntry Entries[MAX_DKOM_HIDDEN_PROCESSES];
};

// ============================================================================
// Physical Memory Translation Structures
// ============================================================================

struct TranslateVaRequest
{
    ULONG ProcessId;
    ULONG64 VirtualAddress;
};

struct PageTableEntryResult
{
    ULONG64 VirtualAddress;
    ULONG64 PhysicalAddress;
    ULONG64 RawValue;
    UCHAR Present;
    UCHAR ReadWrite;
    UCHAR UserSupervisor;
    UCHAR WriteThrough;
    UCHAR CacheDisable;
    UCHAR Accessed;
    UCHAR Dirty;
    UCHAR LargePage;
    UCHAR Global;
    UCHAR NoExecute;
};

struct TranslateVaResponse
{
    ULONG64 Cr3;
    PageTableEntryResult Pml4e;
    PageTableEntryResult Pdpte;
    PageTableEntryResult Pde;
    PageTableEntryResult Pte;
    ULONG64 PhysicalAddress;
    ULONG PageSize;
    UCHAR WalkDepth;
    UCHAR Success;
};

struct PhysicalMemoryRequest
{
    ULONG64 PhysicalAddress;
    ULONG64 BufferAddress;
    ULONG Size;
};

struct PhysicalMemoryResponse
{
    ULONG BytesTransferred;
    UCHAR Success;
};

struct PhysReadVmRequest
{
    ULONG ProcessId;
    ULONG64 VirtualAddress;
    ULONG Size;
};

struct PhysReadVmResponse
{
    ULONG BytesRead;
    UCHAR Success;
};

// ============================================================================
// VM Region Enumeration Structures
// ============================================================================

struct EnumVmRegionsRequest
{
    ULONG ProcessId;
};

struct VmRegionEntry
{
    ULONG64 BaseAddress;
    ULONG64 RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
    ULONG _pad;
};

struct EnumVmRegionsResponse
{
    ULONG Count;
    ULONG _pad;
    VmRegionEntry Entries[1];
};

// ============================================================================
// EPT Hook Structures
// ============================================================================

struct EptHookInstallRequest
{
    ULONG ProcessId;
    ULONG64 TargetVirtualAddress;
    ULONG PatchSize;
    UCHAR PatchBytes[256];
};

struct EptHookInstallResponse
{
    ULONG HookIndex;
    BOOLEAN Success;
};

struct EptHookDetourRequest
{
    ULONG ProcessId;
    ULONG64 TargetVirtualAddress;
    ULONG StolenBytes;
    ULONG DetourPageOffset;
    ULONG DetourCodeSize;
    UCHAR DetourCode[MAX_EPT_HOOK_DETOUR_SIZE];
};

struct EptHookRemoveRequest
{
    ULONG HookIndex;
};

struct EptHookListEntry
{
    ULONG ProcessId;
    ULONG64 TargetVirtualAddress;
    ULONG PatchSize;
    ULONG HookIndex;
    BOOLEAN Active;
};

struct EptHookListResponse
{
    ULONG Count;
    EptHookListEntry Entries[MAX_EPT_HOOK_LIST_ENTRIES];
};

// ============================================================================
// Memory Protection Hiding Structures
// ============================================================================

struct HideMemoryRequest
{
    ULONG ProcessId;
    ULONG64 VirtualAddress;
    ULONG Protection;
};

// ============================================================================
// EPT Register Change Structures
// ============================================================================

struct RegChangeInstallRequest
{
    ULONG ProcessId;
    ULONG64 TargetAddress;
    ULONG RegIndex;
    ULONG64 NewValue;
};

struct RegChangeInstallResponse
{
    ULONG EntryIndex;
    BOOLEAN Success;
};

struct RegChangeRemoveRequest
{
    ULONG EntryIndex;
};

struct RegChangeListEntry
{
    ULONG ProcessId;
    ULONG64 TargetAddress;
    ULONG RegIndex;
    ULONG64 NewValue;
    ULONG EntryIndex;
    BOOLEAN Active;
};

struct RegChangeListResponse
{
    ULONG Count;
    RegChangeListEntry Entries[MAX_REG_CHANGES];
};

// ============================================================================
// Port Hiding Structures
// ============================================================================

struct PortHideRequest
{
    USHORT Port;
};

struct PortUnhideRequest
{
    ULONG Index;
};

struct HiddenPortEntry
{
    USHORT Port;
    ULONG Index;
};

struct PortHideListResponse
{
    ULONG Count;
    HiddenPortEntry Entries[MAX_PORTHIDE_ENTRIES];
};

// ============================================================================
// Packet Capture Structures
// ============================================================================

#pragma pack(push, 1)
struct CapturedPacketData
{
    ULONG64 Id;
    ULONG64 Timestamp;
    ULONG ProcessId;
    PacketDirection Direction;
    PacketProtocol Protocol;
    ULONG LocalAddr;
    USHORT LocalPort;
    ULONG RemoteAddr;
    USHORT RemotePort;
    USHORT PayloadSize;
    UCHAR Payload[MAX_PACKET_PAYLOAD_SIZE];
};
#pragma pack(pop)

struct PacketCaptureStartRequest
{
    ULONG TargetPid;
};

struct PacketCaptureStateResponse
{
    BOOLEAN IsCapturing;
    ULONG TargetPid;
    ULONG PacketCount;
    ULONG DroppedCount;
};

#pragma pack(push, 1)
struct PacketFilterRuleData
{
    UCHAR Enabled;
    UCHAR Action;
    USHORT Port;
    ULONG IpAddress;
    UCHAR Protocol;
};
#pragma pack(pop)

struct PacketFilterRemoveRequest
{
    ULONG Index;
};

// ============================================================================
// Process/Thread Control Structures
// ============================================================================

struct SetThreadApiAddressesRequest
{
    ULONG64 PsSuspendThreadAddress;
    ULONG64 PsResumeThreadAddress;
    ULONG64 ZwTerminateThreadAddress;
};

struct ProcessControlRequest
{
    ULONG ProcessId;
};

struct ThreadControlRequest
{
    ULONG ThreadId;
};

struct SetEthreadOffsetsRequest
{
    ULONG Win32StartAddressOffset;
    ULONG StateOffset;
    ULONG WaitReasonOffset;
};

struct SystemThreadInfo
{
    ULONG ThreadId;
    ULONG64 StartAddress;
    ULONG64 Win32StartAddress;
    CHAR DriverName[MAX_MODULE_NAME_LENGTH];
    ULONG64 DriverBase;
    ULONG64 DriverOffset;
    UCHAR State;
    UCHAR WaitReason;
};

struct EnumSystemThreadsResponse
{
    ULONG Count;
    SystemThreadInfo Threads[1];
};

struct KernelThreadInfo
{
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG64 StartAddress;
    ULONG64 Win32StartAddress;
    CHAR ModuleName[MAX_MODULE_NAME_LENGTH];
    ULONG64 ModuleBase;
    ULONG64 ModuleOffset;
    UCHAR State;
    UCHAR WaitReason;
};

struct EnumAllKernelThreadsResponse
{
    ULONG Count;
    KernelThreadInfo Threads[1];
};

// ============================================================================
// DioProcessSDK Class - Inline Wrapper Functions
// ============================================================================

class DioProcessSDK
{
private:
    HANDLE m_hDevice;

    inline BOOL DeviceIoControlWrapper(DWORD ioctl, LPVOID inBuf, DWORD inSize,
                                       LPVOID outBuf, DWORD outSize, LPDWORD bytesReturned = nullptr)
    {
        DWORD bytes = 0;
        BOOL result = DeviceIoControl(m_hDevice, ioctl, inBuf, inSize, outBuf, outSize, &bytes, nullptr);
        if (bytesReturned) *bytesReturned = bytes;
        return result;
    }

public:
    DioProcessSDK() : m_hDevice(INVALID_HANDLE_VALUE) {}
    ~DioProcessSDK() { Close(); }

    // Prevent copying
    DioProcessSDK(const DioProcessSDK&) = delete;
    DioProcessSDK& operator=(const DioProcessSDK&) = delete;

    // ========== Connection Management ==========

    inline BOOL Open()
    {
        if (m_hDevice != INVALID_HANDLE_VALUE) return TRUE;
        m_hDevice = CreateFileW(DIOPROCESS_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        return m_hDevice != INVALID_HANDLE_VALUE;
    }

    inline void Close()
    {
        if (m_hDevice != INVALID_HANDLE_VALUE)
        {
            CloseHandle(m_hDevice);
            m_hDevice = INVALID_HANDLE_VALUE;
        }
    }

    inline BOOL IsOpen() const { return m_hDevice != INVALID_HANDLE_VALUE; }
    inline HANDLE GetHandle() const { return m_hDevice; }

    // ========== Collection Control ==========

    inline BOOL StartCollection()
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_START_COLLECTION, nullptr, 0, nullptr, 0);
    }

    inline BOOL StopCollection()
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_STOP_COLLECTION, nullptr, 0, nullptr, 0);
    }

    inline BOOL GetCollectionState(CollectionStateResponse* response)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_GET_COLLECTION_STATE, nullptr, 0,
                                      response, sizeof(CollectionStateResponse));
    }

    inline BOOL RegisterCallbacks()
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_REGISTER_CALLBACKS, nullptr, 0, nullptr, 0);
    }

    inline BOOL UnregisterCallbacks()
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_UNREGISTER_CALLBACKS, nullptr, 0, nullptr, 0);
    }

    // ========== Process Protection ==========

    inline BOOL ProtectProcess(ULONG pid)
    {
        TargetProcessRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PROTECT_PROCESS, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL UnprotectProcess(ULONG pid)
    {
        TargetProcessRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_UNPROTECT_PROCESS, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL ProtectProcessWithLevel(ULONG pid, ProcessProtectionLevel level)
    {
        ProtectProcessWithLevelRequest req = { pid, level, {0} };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PROTECT_PROCESS, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL EnablePrivileges(ULONG pid)
    {
        TargetProcessRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_ENABLE_PRIVILEGES, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL ClearDebugFlags(ULONG pid)
    {
        TargetProcessRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_CLEAR_DEBUG_FLAGS, &req, sizeof(req), nullptr, 0);
    }

    // ========== Callback Enumeration ==========

    inline BOOL EnumProcessCallbacks(LPVOID buffer, DWORD bufferSize, LPDWORD bytesReturned)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_ENUM_PROCESS_CALLBACKS, nullptr, 0,
                                      buffer, bufferSize, bytesReturned);
    }

    inline BOOL EnumThreadCallbacks(LPVOID buffer, DWORD bufferSize, LPDWORD bytesReturned)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_ENUM_THREAD_CALLBACKS, nullptr, 0,
                                      buffer, bufferSize, bytesReturned);
    }

    inline BOOL EnumImageCallbacks(LPVOID buffer, DWORD bufferSize, LPDWORD bytesReturned)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_ENUM_IMAGE_CALLBACKS, nullptr, 0,
                                      buffer, bufferSize, bytesReturned);
    }

    inline BOOL EnumObjectCallbacks(LPVOID buffer, DWORD bufferSize, LPDWORD bytesReturned)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_ENUM_OBJECT_CALLBACKS, nullptr, 0,
                                      buffer, bufferSize, bytesReturned);
    }

    inline BOOL EnumRegistryCallbacks(LPVOID buffer, DWORD bufferSize, LPDWORD bytesReturned)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_ENUM_REGISTRY_CALLBACKS, nullptr, 0,
                                      buffer, bufferSize, bytesReturned);
    }

    inline BOOL EnumMinifilters(LPVOID buffer, DWORD bufferSize, LPDWORD bytesReturned)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_ENUM_MINIFILTERS, nullptr, 0,
                                      buffer, bufferSize, bytesReturned);
    }

    inline BOOL EnumDrivers(LPVOID buffer, DWORD bufferSize, LPDWORD bytesReturned)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_ENUM_DRIVERS, nullptr, 0,
                                      buffer, bufferSize, bytesReturned);
    }

    inline BOOL EnumPspCidTable(LPVOID buffer, DWORD bufferSize, LPDWORD bytesReturned)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_ENUM_PSPCIDTABLE, nullptr, 0,
                                      buffer, bufferSize, bytesReturned);
    }

    // ========== Callback Removal ==========

    inline BOOL RemoveProcessCallback(ULONG index)
    {
        RemoveCallbackRequest req = { index };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_REMOVE_PROCESS_CALLBACK, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL RemoveThreadCallback(ULONG index)
    {
        RemoveCallbackRequest req = { index };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_REMOVE_THREAD_CALLBACK, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL RemoveImageCallback(ULONG index)
    {
        RemoveCallbackRequest req = { index };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_REMOVE_IMAGE_CALLBACK, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL RemoveObjectCallback(ULONG index, ObjectCallbackType type, BOOL removePre, BOOL removePost)
    {
        RemoveObjectCallbackRequest req = { index, type, {0}, removePre ? 1U : 0U, removePost ? 1U : 0U };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_REMOVE_OBJECT_CALLBACK, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL RemoveRegistryCallback(ULONG index)
    {
        RemoveRegistryCallbackRequest req = { index };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_REMOVE_REGISTRY_CALLBACK, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL UnlinkMinifilter(LPCWSTR filterName)
    {
        UnlinkMinifilterRequest req = {};
        wcsncpy_s(req.FilterName, filterName, MAX_FILTER_NAME_LENGTH - 1);
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_UNLINK_MINIFILTER, &req, sizeof(req), nullptr, 0);
    }

    // ========== Callback Restore ==========

    inline BOOL RestoreProcessCallback(ULONG index)
    {
        RestoreCallbackRequest req = { index };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_RESTORE_PROCESS_CALLBACK, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL RestoreThreadCallback(ULONG index)
    {
        RestoreCallbackRequest req = { index };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_RESTORE_THREAD_CALLBACK, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL RestoreImageCallback(ULONG index)
    {
        RestoreCallbackRequest req = { index };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_RESTORE_IMAGE_CALLBACK, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL RestoreObjectCallback(ULONG index, ObjectCallbackType type, BOOL restorePre, BOOL restorePost)
    {
        RestoreObjectCallbackRequest req = { index, type, {0}, restorePre ? 1U : 0U, restorePost ? 1U : 0U };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_RESTORE_OBJECT_CALLBACK, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL RestoreRegistryCallback(ULONG index)
    {
        RestoreRegistryCallbackRequest req = { index };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_RESTORE_REGISTRY_CALLBACK, &req, sizeof(req), nullptr, 0);
    }

    // ========== Kernel Injection ==========

    inline BOOL KernelInjectShellcode(ULONG pid, const UCHAR* shellcode, ULONG size, KernelInjectShellcodeResponse* response)
    {
        DWORD reqSize = sizeof(KernelInjectShellcodeRequest) + size - 1;
        auto req = (KernelInjectShellcodeRequest*)HeapAlloc(GetProcessHeap(), 0, reqSize);
        if (!req) return FALSE;
        req->TargetProcessId = pid;
        req->ShellcodeSize = size;
        memcpy(req->Shellcode, shellcode, size);
        BOOL result = DeviceIoControlWrapper(IOCTL_DIOPROCESS_KERNEL_INJECT_SHELLCODE, req, reqSize,
                                             response, sizeof(KernelInjectShellcodeResponse));
        HeapFree(GetProcessHeap(), 0, req);
        return result;
    }

    inline BOOL KernelInjectDll(ULONG pid, LPCWSTR dllPath, KernelInjectDllResponse* response)
    {
        KernelInjectDllRequest req = {};
        req.TargetProcessId = pid;
        wcsncpy_s(req.DllPath, dllPath, MAX_DLL_PATH_LENGTH - 1);
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_KERNEL_INJECT_DLL, &req, sizeof(req),
                                      response, sizeof(KernelInjectDllResponse));
    }

    inline BOOL KernelManualMap(ULONG pid, const UCHAR* dllBytes, ULONG dllSize, ULONG flags, KernelManualMapResponse* response)
    {
        DWORD reqSize = sizeof(KernelManualMapRequest) + dllSize - 1;
        auto req = (KernelManualMapRequest*)HeapAlloc(GetProcessHeap(), 0, reqSize);
        if (!req) return FALSE;
        req->TargetProcessId = pid;
        req->Flags = flags;
        req->DllSize = dllSize;
        memcpy(req->DllBytes, dllBytes, dllSize);
        BOOL result = DeviceIoControlWrapper(IOCTL_DIOPROCESS_KERNEL_MANUAL_MAP, req, reqSize,
                                             response, sizeof(KernelManualMapResponse));
        HeapFree(GetProcessHeap(), 0, req);
        return result;
    }

    // ========== Hypervisor Control ==========

    inline BOOL HvStart()
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_START, nullptr, 0, nullptr, 0);
    }

    inline BOOL HvStop()
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_STOP, nullptr, 0, nullptr, 0);
    }

    inline BOOL HvPing(HvPingResponse* response)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_PING, nullptr, 0, response, sizeof(HvPingResponse));
    }

    inline BOOL HvInstallHooks()
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_INSTALL_HOOKS, nullptr, 0, nullptr, 0);
    }

    inline BOOL HvRemoveHooks()
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_REMOVE_HOOKS, nullptr, 0, nullptr, 0);
    }

    inline BOOL HvProtectProcess(ULONG pid)
    {
        HvProtectProcessRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_PROTECT_PROCESS, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL HvUnprotectProcess(ULONG pid)
    {
        HvProtectProcessRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_UNPROTECT_PROCESS, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL HvIsProcessProtected(ULONG pid, HvIsProtectedResponse* response)
    {
        HvProtectProcessRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_IS_PROCESS_PROTECTED, &req, sizeof(req),
                                      response, sizeof(HvIsProtectedResponse));
    }

    inline BOOL HvListProtected(HvListProtectedResponse* response)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_LIST_PROTECTED, nullptr, 0,
                                      response, sizeof(HvListProtectedResponse));
    }

    // ========== Hypervisor Driver Hiding ==========

    inline BOOL HvHideDriver(LPCSTR driverName)
    {
        HideDriverRequest req = {};
        strncpy_s(req.DriverName, driverName, 63);
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_HIDE_DRIVER, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL HvUnhideDriver(LPCSTR driverName)
    {
        HideDriverRequest req = {};
        strncpy_s(req.DriverName, driverName, 63);
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_UNHIDE_DRIVER, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL HvIsDriverHidden(LPCSTR driverName, DriverHiddenResponse* response)
    {
        HideDriverRequest req = {};
        strncpy_s(req.DriverName, driverName, 63);
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_IS_DRIVER_HIDDEN, &req, sizeof(req),
                                      response, sizeof(DriverHiddenResponse));
    }

    inline BOOL HvListHiddenDrivers(HiddenDriverListResponse* response)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_LIST_HIDDEN_DRIVERS, nullptr, 0,
                                      response, sizeof(HiddenDriverListResponse));
    }

    inline BOOL HvClearHiddenDrivers()
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_CLEAR_HIDDEN_DRIVERS, nullptr, 0, nullptr, 0);
    }

    // ========== Hypervisor Memory Operations ==========

    inline BOOL HvReadVm(ULONG pid, ULONG64 address, ULONG size, LPVOID buffer, LPDWORD bytesRead)
    {
        HvReadVmRequest req = { pid, address, size };
        DWORD outSize = sizeof(HvReadVmResponse) + size;
        auto outBuf = (UCHAR*)HeapAlloc(GetProcessHeap(), 0, outSize);
        if (!outBuf) return FALSE;
        DWORD returned = 0;
        BOOL result = DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_READ_VM, &req, sizeof(req), outBuf, outSize, &returned);
        if (result && returned >= sizeof(HvReadVmResponse))
        {
            auto resp = (HvReadVmResponse*)outBuf;
            if (resp->Success && resp->BytesRead > 0)
            {
                memcpy(buffer, outBuf + sizeof(HvReadVmResponse), resp->BytesRead);
                if (bytesRead) *bytesRead = resp->BytesRead;
            }
        }
        HeapFree(GetProcessHeap(), 0, outBuf);
        return result;
    }

    inline BOOL HvWriteVm(ULONG pid, ULONG64 address, const UCHAR* data, ULONG size, LPDWORD bytesWritten)
    {
        DWORD reqSize = sizeof(HvWriteVmRequest) + size - 1;
        auto req = (HvWriteVmRequest*)HeapAlloc(GetProcessHeap(), 0, reqSize);
        if (!req) return FALSE;
        req->ProcessId = pid;
        req->VirtualAddress = address;
        req->Size = size;
        memcpy(req->Data, data, size);
        HvWriteVmResponse response = {};
        BOOL result = DeviceIoControlWrapper(IOCTL_DIOPROCESS_HV_WRITE_VM, req, reqSize,
                                             &response, sizeof(response));
        if (bytesWritten) *bytesWritten = response.BytesWritten;
        HeapFree(GetProcessHeap(), 0, req);
        return result && response.Success;
    }

    // ========== Early Injection ==========

    inline BOOL EarlyInjectArm(LPCWSTR processName, LPCWSTR dllPath, EarlyInjectionMethod method, BOOL oneShot)
    {
        EarlyInjectionArmRequest req = {};
        wcsncpy_s(req.TargetProcessName, processName, MAX_TARGET_PROCESS_NAME - 1);
        wcsncpy_s(req.DllPath, dllPath, MAX_DLL_PATH_LENGTH - 1);
        req.Method = method;
        req.OneShot = oneShot;
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_EARLY_INJECT_ARM, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL EarlyInjectDisarm()
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_EARLY_INJECT_DISARM, nullptr, 0, nullptr, 0);
    }

    inline BOOL EarlyInjectStatus(EarlyInjectionStatusResponse* response)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_EARLY_INJECT_STATUS, nullptr, 0,
                                      response, sizeof(EarlyInjectionStatusResponse));
    }

    // ========== Kernel Memory Copy ==========

    inline BOOL CopyMemory(ULONG pid, ULONG64 sourceAddr, LPVOID destBuffer, ULONG size, LPDWORD bytesCopied)
    {
        KernelCopyMemoryRequest req = { pid, sourceAddr, (ULONG64)destBuffer, size };
        KernelCopyMemoryResponse response = {};
        BOOL result = DeviceIoControlWrapper(IOCTL_DIOPROCESS_COPY_MEMORY, &req, sizeof(req),
                                             &response, sizeof(response));
        if (bytesCopied) *bytesCopied = response.BytesCopied;
        return result && response.Success;
    }

    // ========== File Hiding ==========

    inline BOOL HideFile(LPCWSTR filePath)
    {
        FileHideRequest req = {};
        wcsncpy_s(req.FilePath, filePath, 259);
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_FILEHIDE_HIDE, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL UnhideFile(LPCWSTR filePath)
    {
        FileHideRequest req = {};
        wcsncpy_s(req.FilePath, filePath, 259);
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_FILEHIDE_UNHIDE, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL ListHiddenFiles(FileHideListResponse* response)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_FILEHIDE_LIST, nullptr, 0,
                                      response, sizeof(FileHideListResponse));
    }

    // ========== DKOM Process Hiding ==========

    inline BOOL HideProcess(ULONG pid)
    {
        TargetProcessRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PROCESS_HIDE, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL UnhideProcess(ULONG pid)
    {
        TargetProcessRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PROCESS_UNHIDE, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL ListHiddenProcesses(ProcessHideListResponse* response)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PROCESS_HIDE_LIST, nullptr, 0,
                                      response, sizeof(ProcessHideListResponse));
    }

    // ========== Physical Memory Operations ==========

    inline BOOL TranslateVa(ULONG pid, ULONG64 virtualAddr, TranslateVaResponse* response)
    {
        TranslateVaRequest req = { pid, virtualAddr };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_TRANSLATE_VA, &req, sizeof(req),
                                      response, sizeof(TranslateVaResponse));
    }

    inline BOOL ReadPhysical(ULONG64 physAddr, LPVOID buffer, ULONG size, LPDWORD bytesRead)
    {
        PhysicalMemoryRequest req = { physAddr, (ULONG64)buffer, size };
        PhysicalMemoryResponse response = {};
        BOOL result = DeviceIoControlWrapper(IOCTL_DIOPROCESS_READ_PHYSICAL, &req, sizeof(req),
                                             &response, sizeof(response));
        if (bytesRead) *bytesRead = response.BytesTransferred;
        return result && response.Success;
    }

    inline BOOL WritePhysical(ULONG64 physAddr, const LPVOID data, ULONG size, LPDWORD bytesWritten)
    {
        PhysicalMemoryRequest req = { physAddr, (ULONG64)data, size };
        PhysicalMemoryResponse response = {};
        BOOL result = DeviceIoControlWrapper(IOCTL_DIOPROCESS_WRITE_PHYSICAL, &req, sizeof(req),
                                             &response, sizeof(response));
        if (bytesWritten) *bytesWritten = response.BytesTransferred;
        return result && response.Success;
    }

    inline BOOL PhysReadVm(ULONG pid, ULONG64 virtualAddr, LPVOID buffer, ULONG size, LPDWORD bytesRead)
    {
        PhysReadVmRequest req = { pid, virtualAddr, size };
        DWORD outSize = sizeof(PhysReadVmResponse) + size;
        auto outBuf = (UCHAR*)HeapAlloc(GetProcessHeap(), 0, outSize);
        if (!outBuf) return FALSE;
        DWORD returned = 0;
        BOOL result = DeviceIoControlWrapper(IOCTL_DIOPROCESS_PHYS_READ_VM, &req, sizeof(req), outBuf, outSize, &returned);
        if (result && returned >= sizeof(PhysReadVmResponse))
        {
            auto resp = (PhysReadVmResponse*)outBuf;
            if (resp->Success && resp->BytesRead > 0)
            {
                memcpy(buffer, outBuf + sizeof(PhysReadVmResponse), resp->BytesRead);
                if (bytesRead) *bytesRead = resp->BytesRead;
            }
        }
        HeapFree(GetProcessHeap(), 0, outBuf);
        return result;
    }

    // ========== VM Region Enumeration ==========

    inline BOOL EnumVmRegions(ULONG pid, LPVOID buffer, DWORD bufferSize, LPDWORD bytesReturned)
    {
        EnumVmRegionsRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_ENUM_VM_REGIONS, &req, sizeof(req),
                                      buffer, bufferSize, bytesReturned);
    }

    // ========== EPT Hooks ==========

    inline BOOL EptHookInstall(ULONG pid, ULONG64 targetAddr, const UCHAR* patchBytes, ULONG patchSize, EptHookInstallResponse* response)
    {
        EptHookInstallRequest req = {};
        req.ProcessId = pid;
        req.TargetVirtualAddress = targetAddr;
        req.PatchSize = patchSize > 256 ? 256 : patchSize;
        memcpy(req.PatchBytes, patchBytes, req.PatchSize);
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_EPT_HOOK_INSTALL, &req, sizeof(req),
                                      response, sizeof(EptHookInstallResponse));
    }

    inline BOOL EptHookRemove(ULONG hookIndex)
    {
        EptHookRemoveRequest req = { hookIndex };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_EPT_HOOK_REMOVE, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL EptHookList(EptHookListResponse* response)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_EPT_HOOK_LIST, nullptr, 0,
                                      response, sizeof(EptHookListResponse));
    }

    // ========== EPT Register Changes ==========

    inline BOOL RegChangeInstall(ULONG pid, ULONG64 targetAddr, ULONG regIndex, ULONG64 newValue, RegChangeInstallResponse* response)
    {
        RegChangeInstallRequest req = { pid, targetAddr, regIndex, newValue };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_REG_CHANGE_INSTALL, &req, sizeof(req),
                                      response, sizeof(RegChangeInstallResponse));
    }

    inline BOOL RegChangeRemove(ULONG entryIndex)
    {
        RegChangeRemoveRequest req = { entryIndex };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_REG_CHANGE_REMOVE, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL RegChangeRemoveAll()
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_REG_CHANGE_REMOVE_ALL, nullptr, 0, nullptr, 0);
    }

    inline BOOL RegChangeList(RegChangeListResponse* response)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_REG_CHANGE_LIST, nullptr, 0,
                                      response, sizeof(RegChangeListResponse));
    }

    // ========== Port Hiding ==========

    inline BOOL HidePort(USHORT port)
    {
        PortHideRequest req = { port };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PORT_HIDE, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL UnhidePort(ULONG index)
    {
        PortUnhideRequest req = { index };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PORT_UNHIDE, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL ListHiddenPorts(PortHideListResponse* response)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PORT_HIDE_LIST, nullptr, 0,
                                      response, sizeof(PortHideListResponse));
    }

    // ========== Memory Protection Hiding ==========

    inline BOOL HideMemory(ULONG pid, ULONG64 virtualAddr, ULONG protection)
    {
        HideMemoryRequest req = { pid, virtualAddr, protection };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_HIDE_MEMORY, &req, sizeof(req), nullptr, 0);
    }

    // ========== Process Kill ==========

    inline BOOL KillProcessTerminate(ULONG pid)
    {
        TargetProcessRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_KILL_TERMINATE, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL KillProcessUnmap(ULONG pid)
    {
        TargetProcessRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_KILL_UNMAP, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL KillProcessPebCorrupt(ULONG pid)
    {
        TargetProcessRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_KILL_PEB_CORRUPT, &req, sizeof(req), nullptr, 0);
    }

    // ========== Process/Thread Control ==========

    inline BOOL SuspendProcess(ULONG pid)
    {
        ProcessControlRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_SUSPEND_PROCESS, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL ResumeProcess(ULONG pid)
    {
        ProcessControlRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_RESUME_PROCESS, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL SuspendThread(ULONG tid)
    {
        ThreadControlRequest req = { tid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_SUSPEND_THREAD, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL ResumeThread(ULONG tid)
    {
        ThreadControlRequest req = { tid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_RESUME_THREAD, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL TerminateThread(ULONG tid)
    {
        ThreadControlRequest req = { tid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_TERMINATE_THREAD, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL EnumSystemThreads(LPVOID buffer, DWORD bufferSize, LPDWORD bytesReturned)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_ENUM_SYSTEM_THREADS, nullptr, 0,
                                      buffer, bufferSize, bytesReturned);
    }

    inline BOOL EnumAllKernelThreads(LPVOID buffer, DWORD bufferSize, LPDWORD bytesReturned)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_ENUM_ALL_KERNEL_THREADS, nullptr, 0,
                                      buffer, bufferSize, bytesReturned);
    }

    // ========== Packet Capture ==========

    inline BOOL PacketStartCapture(ULONG pid)
    {
        PacketCaptureStartRequest req = { pid };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PACKET_START_CAPTURE, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL PacketStopCapture()
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PACKET_STOP_CAPTURE, nullptr, 0, nullptr, 0);
    }

    inline BOOL PacketGetState(PacketCaptureStateResponse* response)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PACKET_GET_STATE, nullptr, 0,
                                      response, sizeof(PacketCaptureStateResponse));
    }

    inline BOOL PacketGetPackets(LPVOID buffer, DWORD bufferSize, LPDWORD bytesReturned)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PACKET_GET_PACKETS, nullptr, 0,
                                      buffer, bufferSize, bytesReturned);
    }

    inline BOOL PacketAddFilter(const PacketFilterRuleData* rule)
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PACKET_ADD_FILTER,
                                      (LPVOID)rule, sizeof(PacketFilterRuleData), nullptr, 0);
    }

    inline BOOL PacketRemoveFilter(ULONG index)
    {
        PacketFilterRemoveRequest req = { index };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PACKET_REMOVE_FILTER, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL PacketClearFilters()
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PACKET_CLEAR_FILTERS, nullptr, 0, nullptr, 0);
    }

    inline BOOL PacketClearBuffer()
    {
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_PACKET_CLEAR_BUFFER, nullptr, 0, nullptr, 0);
    }

    // ========== Configuration ==========

    inline BOOL SetRegistryCallbackOffsets(ULONG cookieOff, ULONG funcOff, ULONG ctxOff, ULONG altOff)
    {
        SetRegistryCallbackOffsetsRequest req = { cookieOff, funcOff, ctxOff, altOff };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_SET_REGISTRY_CALLBACK_OFFSETS, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL SetEthreadOffsets(ULONG win32StartOff, ULONG stateOff, ULONG waitReasonOff)
    {
        SetEthreadOffsetsRequest req = { win32StartOff, stateOff, waitReasonOff };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_SET_ETHREAD_OFFSETS, &req, sizeof(req), nullptr, 0);
    }

    inline BOOL SetThreadApiAddresses(ULONG64 suspendAddr, ULONG64 resumeAddr, ULONG64 terminateAddr)
    {
        SetThreadApiAddressesRequest req = { suspendAddr, resumeAddr, terminateAddr };
        return DeviceIoControlWrapper(IOCTL_DIOPROCESS_SET_THREAD_API_ADDRESSES, &req, sizeof(req), nullptr, 0);
    }
};

#endif // DIOPROCESS_SDK_H
