#pragma once

enum class EventType
{
	// Process/Thread callbacks
	ProcessCreate,
	ProcessExit,
	ThreadCreate,
	ThreadExit,

	// Image load callback
	ImageLoad,

	// Object Manager callbacks (handle operations)
	ProcessHandleCreate,
	ProcessHandleDuplicate,
	ThreadHandleCreate,
	ThreadHandleDuplicate,

	// Registry callbacks
	RegistryCreate,
	RegistryOpen,
	RegistrySetValue,
	RegistryDeleteKey,
	RegistryDeleteValue,
	RegistryRenameKey,
	RegistryQueryValue,
};

struct EventHeader
{
	EventType Type;
	ULONG Size;
	ULONG64 Timestamp;
};

// ============== Process/Thread Callbacks ==============

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

// ============== Image Load Callback ==============

struct ImageLoadInfo
{
	ULONG ProcessId;
	ULONG64 ImageBase;
	ULONG64 ImageSize;
	BOOLEAN IsSystemImage;      // Loaded from System32/SysWOW64
	BOOLEAN IsKernelImage;      // Kernel mode image
	ULONG ImageNameLength;      // Length in WCHARs (not bytes)
	WCHAR ImageName[1];         // Variable length
};

// ============== Object Manager Callbacks ==============

struct HandleOperationInfo
{
	ULONG SourceProcessId;      // Process performing the operation
	ULONG SourceThreadId;       // Thread performing the operation
	ULONG TargetProcessId;      // Target process (for process handles) or owning process (for thread handles)
	ULONG TargetThreadId;       // Target thread ID (only for thread handles, 0 for process handles)
	ULONG DesiredAccess;        // Requested access rights
	ULONG GrantedAccess;        // Actually granted access rights
	BOOLEAN IsKernelHandle;     // Handle is kernel handle
	ULONG SourceImageNameLength;
	WCHAR SourceImageName[1];   // Variable length - name of the process opening the handle
};

// ============== Registry Callbacks ==============

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

struct RegistryOperationInfo
{
	ULONG ProcessId;
	ULONG ThreadId;
	RegistryOperation Operation;
	NTSTATUS Status;            // Result status (for post-operation)
	ULONG KeyNameLength;        // Length in WCHARs
	ULONG ValueNameLength;      // Length in WCHARs (0 if not applicable)
	WCHAR Names[1];             // KeyName followed by ValueName (variable length)
};

// ============== Union of all event data ==============

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

// ============== IOCTL Definitions ==============

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

// Security research IOCTLs (from RedOctober)
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
#define IOCTL_DIOPROCESS_REMOVE_THREAD_CALLBACK \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_REMOVE_IMAGE_CALLBACK \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_REMOVE_OBJECT_CALLBACK \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Registry callback enumeration and removal IOCTLs (RCK style)
#define IOCTL_DIOPROCESS_ENUM_REGISTRY_CALLBACKS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_REMOVE_REGISTRY_CALLBACK \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============== Hypervisor Control IOCTLs ==============

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

// ============== Hypervisor Process Protection IOCTLs ==============

#define IOCTL_DIOPROCESS_HV_PROTECT_PROCESS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_UNPROTECT_PROCESS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_IS_PROCESS_PROTECTED \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_HV_LIST_PROTECTED \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x833, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============== Hypervisor Driver Hiding IOCTLs ==============

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

// ============== Hypervisor Injection IOCTLs (Ring -1) ==============

#define IOCTL_DIOPROCESS_HV_INJECT_SHELLCODE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DIOPROCESS_HV_INJECT_DLL \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x841, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct CollectionStateResponse
{
	BOOLEAN IsCollecting;
	ULONG ItemCount;
};

// ============== Driver Hiding Structures ==============

#define MAX_HIDDEN_DRIVERS 16

struct HideDriverRequest
{
	CHAR DriverName[64];  // Driver filename to hide (e.g., "dpdrv.sys")
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

// ============== Process Security Structures ==============

struct TargetProcessRequest
{
	ULONG ProcessId;
};

// ============== Kernel Injection Structures ==============

struct KernelInjectShellcodeRequest
{
	ULONG TargetProcessId;
	ULONG ShellcodeSize;
	UCHAR Shellcode[1];  // Variable length
};

struct KernelInjectShellcodeResponse
{
	ULONG64 AllocatedAddress;  // Where shellcode was written
	BOOLEAN Success;
};

#define MAX_DLL_PATH_LENGTH 520

struct KernelInjectDllRequest
{
	ULONG TargetProcessId;
	WCHAR DllPath[MAX_DLL_PATH_LENGTH];
};

struct KernelInjectDllResponse
{
	ULONG64 AllocatedAddress;  // Where DLL path was written
	ULONG64 LoadLibraryAddress;  // Address of LoadLibraryW
	BOOLEAN Success;
};

// ============== PspCidTable Enumeration Structures ==============

#define MAX_CID_ENTRIES 2048  // Maximum entries to return
#define MAX_PROCESS_NAME_LENGTH 16  // ImageFileName is 15 chars + null terminator

enum CidObjectType : UCHAR
{
	CidProcess = 1,
	CidThread = 2
};

struct CidEntry
{
	ULONG Id;              // PID or TID
	ULONG64 ObjectAddress; // EPROCESS or ETHREAD address
	CidObjectType Type;    // Process or Thread
	ULONG ParentPid;       // Parent PID (for processes) or owning process PID (for threads)
	CHAR ProcessName[MAX_PROCESS_NAME_LENGTH];  // Process name (from EPROCESS.ImageFileName)
};

struct EnumCidTableResponse
{
	ULONG Count;           // Number of entries returned
	CidEntry Entries[1];   // Variable length array
};

// ============== Callback Enumeration Structures ==============

#define MAX_CALLBACK_ENTRIES 64
#define MAX_MODULE_NAME_LENGTH 256

struct CallbackInformation
{
	CHAR ModuleName[MAX_MODULE_NAME_LENGTH];
	ULONG64 CallbackAddress;
	ULONG64 ModuleBase;     // Base address of the module (for RVA calculation)
	ULONG64 ModuleOffset;   // RVA offset within the module (CallbackAddress - ModuleBase)
	ULONG Index;            // Position in the callback array (0-63)
};

// Request structure for removing callbacks
struct RemoveCallbackRequest
{
	ULONG Index;  // Callback slot index (0-63)
};

// ============== Object Callback Enumeration Structures ==============

#define MAX_OBJECT_CALLBACK_ENTRIES 64
#define MAX_ALTITUDE_LENGTH 64

// Object type being monitored by the callback
enum ObjectCallbackType : UCHAR
{
	ObjectCallbackProcess = 1,
	ObjectCallbackThread = 2
};

// Operations the callback monitors
enum ObjectCallbackOperations : ULONG
{
	OpHandleCreate = 1,      // OB_OPERATION_HANDLE_CREATE
	OpHandleDuplicate = 2    // OB_OPERATION_HANDLE_DUPLICATE
};

struct ObjectCallbackInfo
{
	CHAR ModuleName[MAX_MODULE_NAME_LENGTH];      // Driver that registered the callback
	CHAR Altitude[MAX_ALTITUDE_LENGTH];           // Callback altitude (priority)
	ULONG64 PreOperationCallback;                 // Pre-operation callback address
	ULONG64 PostOperationCallback;                // Post-operation callback address
	ULONG64 ModuleBase;                           // Base address of owning module (OCKC style)
	ULONG64 PreOperationOffset;                   // RVA offset for PreOperation (OCKC style)
	ULONG64 PostOperationOffset;                  // RVA offset for PostOperation (OCKC style)
	ObjectCallbackType ObjectType;                // Process or Thread
	ObjectCallbackOperations Operations;          // Which operations are monitored
	ULONG Index;                                  // Entry index
};

// Request structure for removing object callbacks (OCKC style)
struct RemoveObjectCallbackRequest
{
	ULONG Index;                                  // Callback entry index
	ObjectCallbackType ObjectType;                // Process or Thread
	UCHAR _padding[3];                            // Alignment padding
	ULONG RemovePreOperation;                     // Remove PreOperation callback (non-zero = true)
	ULONG RemovePostOperation;                    // Remove PostOperation callback (non-zero = true)
};

struct EnumObjectCallbacksResponse
{
	ULONG Count;                                  // Number of entries returned
	ObjectCallbackInfo Entries[1];                // Variable length array
};

// ============== Registry Callback Enumeration Structures (RCK style) ==============

#define MAX_REGISTRY_CALLBACK_ENTRIES 64

struct RegistryCallbackInfo
{
	CHAR ModuleName[MAX_MODULE_NAME_LENGTH];      // Driver that registered the callback
	CHAR Altitude[MAX_ALTITUDE_LENGTH];           // Callback altitude (priority)
	ULONG64 CallbackAddress;                      // Callback function address
	ULONG64 Context;                              // Callback context value
	ULONG64 ModuleBase;                           // Base address of owning module
	ULONG64 ModuleOffset;                         // RVA offset for callback function
	ULONG Index;                                  // Entry index in linked list
};

// Request structure for removing registry callbacks (RCK style)
struct RemoveRegistryCallbackRequest
{
	ULONG Index;                                  // Callback entry index in linked list
};

struct EnumRegistryCallbacksResponse
{
	ULONG Count;                                  // Number of entries returned
	RegistryCallbackInfo Entries[1];              // Variable length array
};

// ============== Minifilter Enumeration Structures ==============

#define MAX_MINIFILTER_ENTRIES 64
#define MAX_FILTER_NAME_LENGTH 64

// IRP major function codes we care about for minifilter callbacks
#define IRP_MJ_CREATE_INDEX          0   // IRP_MJ_CREATE
#define IRP_MJ_READ_INDEX            3   // IRP_MJ_READ
#define IRP_MJ_WRITE_INDEX           4   // IRP_MJ_WRITE
#define IRP_MJ_SET_INFORMATION_INDEX 6   // IRP_MJ_SET_INFORMATION (delete, rename)
#define IRP_MJ_CLEANUP_INDEX         18  // IRP_MJ_CLEANUP

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
	CHAR FilterName[MAX_FILTER_NAME_LENGTH];      // Filter driver name
	CHAR Altitude[MAX_ALTITUDE_LENGTH];           // Filter altitude (load order priority)
	ULONG64 FilterAddress;                        // Address of FLT_FILTER structure
	ULONG64 FrameId;                              // Filter frame ID
	ULONG NumberOfInstances;                      // Number of active instances
	ULONG Flags;                                  // Filter flags
	MinifilterCallbacks Callbacks;                // Pre/Post callbacks for key operations
	CHAR OwnerModuleName[MAX_MODULE_NAME_LENGTH]; // Module that owns this filter
	ULONG Index;                                  // Entry index
};

struct EnumMinifiltersResponse
{
	ULONG Count;                                  // Number of entries returned
	MinifilterInfo Entries[1];                    // Variable length array
};

// ============== Kernel Driver Enumeration ==============

// Driver enumeration IOCTL
#define IOCTL_DIOPROCESS_ENUM_DRIVERS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_DRIVER_ENTRIES 512
#define MAX_DRIVER_NAME_LENGTH 64
#define MAX_DRIVER_PATH_LENGTH 260

struct KernelDriverInfo
{
	ULONG64 BaseAddress;                          // Driver base address in kernel
	ULONG64 Size;                                 // Driver size in bytes
	ULONG64 EntryPoint;                           // Driver entry point
	ULONG64 DriverObject;                         // Pointer to DRIVER_OBJECT (if available)
	ULONG Flags;                                  // Driver flags
	ULONG LoadCount;                              // Reference/load count
	CHAR DriverName[MAX_DRIVER_NAME_LENGTH];      // Driver name (e.g., "ntoskrnl.exe")
	WCHAR DriverPath[MAX_DRIVER_PATH_LENGTH];     // Full driver path
	ULONG Index;                                  // Entry index
};

struct EnumDriversResponse
{
	ULONG Count;                                  // Number of entries returned
	KernelDriverInfo Entries[1];                  // Variable length array
};

// ============== Hypervisor Control Structures ==============

// Response for HV_PING - check if hypervisor is running
struct HvPingResponse
{
	BOOLEAN IsRunning;                            // TRUE if hypervisor is running
	BOOLEAN HooksInstalled;                       // TRUE if protection hooks are installed
	ULONG ProtectedProcessCount;                  // Number of protected processes
};

// Request for HV_PROTECT_PROCESS / HV_UNPROTECT_PROCESS / HV_IS_PROCESS_PROTECTED
struct HvProtectProcessRequest
{
	ULONG ProcessId;                              // Process ID to protect/unprotect
};

// Response for HV_IS_PROCESS_PROTECTED
struct HvIsProtectedResponse
{
	BOOLEAN IsProtected;
};

// Response for HV_LIST_PROTECTED
#define MAX_HV_PROTECTED_PIDS 64
struct HvListProtectedResponse
{
	ULONG Count;                                  // Number of protected PIDs returned
	ULONG Pids[MAX_HV_PROTECTED_PIDS];            // Array of protected PIDs
};

// ============== Hypervisor Injection Structures (Ring -1) ==============

// Request for HV_INJECT_SHELLCODE
// Ring -1 injection: writes shellcode via hypervisor, bypassing all ring 0 protections
struct HvInjectShellcodeRequest
{
	ULONG TargetProcessId;                        // Target process PID
	ULONG ShellcodeSize;                          // Size of shellcode in bytes
	UCHAR Shellcode[1];                           // Variable length shellcode
};

// Response for HV_INJECT_SHELLCODE
struct HvInjectShellcodeResponse
{
	ULONG64 AllocatedAddress;                     // Where shellcode was written
	ULONG64 BytesWritten;                         // Bytes actually written via ring -1
	BOOLEAN Success;
};

// Request for HV_INJECT_DLL
// Ring -1 injection: writes DLL path via hypervisor, calls LoadLibraryW
struct HvInjectDllRequest
{
	ULONG TargetProcessId;                        // Target process PID
	ULONG PathLength;                             // Length of DLL path in bytes (including null)
	WCHAR DllPath[1];                             // Variable length wide string path
};

// Response for HV_INJECT_DLL
struct HvInjectDllResponse
{
	ULONG64 ModuleBase;                           // Base address of loaded DLL (0 if failed)
	ULONG64 PathAddress;                          // Where path was written
	BOOLEAN Success;
};

// ============== Early Injection IOCTLs ==============
// Early injection injects DLLs before any user code executes (at process creation)

#define IOCTL_DIOPROCESS_EARLY_INJECT_ARM \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x850, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_EARLY_INJECT_DISARM \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x851, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIOPROCESS_EARLY_INJECT_STATUS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x852, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============== Early Injection Structures ==============

// Injection method for early injection
enum EarlyInjectionMethod : ULONG
{
	EarlyInjectTrampoline = 0,    // Hook LdrLoadDll at process creation via PsSetCreateProcessNotifyRoutineEx
	EarlyInjectApcCallback = 1    // Queue APC when kernel32.dll loads via PsSetLoadImageNotifyRoutine
};

#define MAX_TARGET_PROCESS_NAME 64

// Request to arm early injection
struct EarlyInjectionArmRequest
{
	WCHAR TargetProcessName[MAX_TARGET_PROCESS_NAME];  // Process name pattern to match (e.g., "notepad.exe")
	WCHAR DllPath[MAX_DLL_PATH_LENGTH];                // Full path to DLL to inject
	EarlyInjectionMethod Method;                       // Injection method
	BOOLEAN OneShot;                                   // Disarm after first injection
};

// Response for early injection status
struct EarlyInjectionStatusResponse
{
	BOOLEAN Armed;                                     // Is early injection armed
	WCHAR TargetProcessName[MAX_TARGET_PROCESS_NAME];  // Target process pattern
	WCHAR DllPath[MAX_DLL_PATH_LENGTH];                // DLL path to inject
	EarlyInjectionMethod Method;                       // Current method
	ULONG InjectionCount;                              // Number of successful injections
	ULONG LastInjectedPid;                             // PID of last injected process
	NTSTATUS LastStatus;                               // Status of last injection attempt
	BOOLEAN OneShot;                                   // One-shot mode enabled
};
