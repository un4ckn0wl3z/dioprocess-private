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

struct CollectionStateResponse
{
	BOOLEAN IsCollecting;
	ULONG ItemCount;
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
	ULONG Index;  // Position in the callback array
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
	ObjectCallbackType ObjectType;                // Process or Thread
	ObjectCallbackOperations Operations;          // Which operations are monitored
	ULONG Index;                                  // Entry index
};

struct EnumObjectCallbacksResponse
{
	ULONG Count;                                  // Number of entries returned
	ObjectCallbackInfo Entries[1];                // Variable length array
};
