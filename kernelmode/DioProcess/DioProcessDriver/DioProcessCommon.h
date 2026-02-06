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

// Kernel shellcode injection IOCTL
#define IOCTL_DIOPROCESS_KERNEL_INJECT_SHELLCODE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)

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

// ============== Kernel Shellcode Injection Structures ==============

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

// ============== Callback Enumeration Structures ==============

#define MAX_CALLBACK_ENTRIES 64
#define MAX_MODULE_NAME_LENGTH 256

struct CallbackInformation
{
	CHAR ModuleName[MAX_MODULE_NAME_LENGTH];
	ULONG64 CallbackAddress;
	ULONG Index;  // Position in the callback array
};
