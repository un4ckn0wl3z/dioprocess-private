# Kernel Feature TODO - DioProcess

Future kernel-mode features and improvements for security research. All features are **PatchGuard-safe** (data-only modifications, read operations, or documented APIs).

## Current Kernel Features

| Feature | Type | PG-Safe | Status |
|---------|------|---------|--------|
| Process Protection (PPL) | Data modification | ✅ | Done |
| Token Privilege Escalation | Data modification | ✅ | Done |
| Clear Debug Flags | Data modification | ✅ | Done |
| Callback Enumeration (Process/Thread/Image) | Read-only | ✅ | Done |
| PspCidTable Enumeration | Read-only | ✅ | Done |
| Kernel Injection (Shellcode/DLL) | Thread creation | ✅ | Done |

---

## Suggested New Features

### 1. Extended Callback Enumeration

Currently we enumerate Process/Thread/Image callbacks. Add:

| Callback Type | API | Use Case |
|--------------|-----|----------|
| **Object Callbacks** | `ObRegisterCallbacks` | EDR hooks on handle operations (process/thread open) |
| **Registry Callbacks** | `CmRegisterCallbackEx` | Already have events, but enumerate registrations |
| **Minifilter Callbacks** | `FltRegisterFilter` | Filesystem monitoring (AV, EDR) |
| **Shutdown Callbacks** | `IoRegisterShutdownNotification` | Persistence detection |
| **Bug Check Callbacks** | `KeRegisterBugCheckCallback` | Crash dump manipulation |

**Implementation idea:**
```cpp
// Object callbacks are in the _OBJECT_TYPE structure
// ObTypeIndexTable[index]->CallbackList contains ObRegisterCallbacks entries
IOCTL_ENUM_OBJECT_CALLBACKS  // Enumerate OB_CALLBACK_REGISTRATION entries
```

**Priority:** 🔴 High - Find EDR handle hooks

---

### 2. Driver/Module Enumeration from Kernel

Enumerate loaded drivers directly from `PsLoadedModuleList`:

```cpp
struct DriverInfo {
    ULONG64 BaseAddress;
    ULONG64 Size;
    ULONG64 EntryPoint;
    WCHAR DriverName[256];
    WCHAR DriverPath[256];
    ULONG Flags;  // Signed, Microsoft, etc.
};

IOCTL_ENUM_KERNEL_MODULES  // List all loaded drivers
```

**Use cases:**
- Detect hidden/unlinked drivers (rootkits)
- Compare with usermode `EnumDeviceDrivers()` results
- View driver entry points for analysis

**Priority:** 🟡 Medium

---

### 3. Handle Table Direct Enumeration

Enumerate process handles directly from `_EPROCESS.ObjectTable`:

```cpp
struct KernelHandleInfo {
    ULONG64 HandleValue;
    ULONG64 ObjectAddress;     // Direct kernel object pointer
    ULONG ObjectTypeIndex;     // Type (Process, Thread, File, etc.)
    ULONG GrantedAccess;
    WCHAR ObjectName[256];
};

IOCTL_ENUM_PROCESS_HANDLES  // Enumerate handles from kernel
```

**Advantages over usermode:**
- Bypasses handle hiding techniques
- Shows actual kernel object addresses
- More reliable than NtQuerySystemInformation

**Priority:** 🟡 Medium

---

### 4. VAD (Virtual Address Descriptor) Tree Enumeration

Read process memory layout directly from kernel VAD tree:

```cpp
struct VadInfo {
    ULONG64 StartVpn;
    ULONG64 EndVpn;
    ULONG Protection;
    ULONG VadType;  // Private, Mapped, Image
    ULONG64 FileObject;  // For mapped files
    WCHAR FileName[256]; // If backed by file
    BOOLEAN IsExecute;
    BOOLEAN IsNoChange;  // CFG protected
};

IOCTL_ENUM_PROCESS_VAD  // Enumerate VAD tree
```

**Use cases:**
- Detect hidden executable regions
- Find injected code that VirtualQueryEx might miss
- Analyze memory-mapped files

**Priority:** 🔴 High - Detect hidden memory

---

### 5. Extended Token Manipulation

Add these token operations:

| Operation | Description |
|-----------|-------------|
| **Get/Set Integrity Level** | View/modify token integrity (Low/Medium/High/System) |
| **Enumerate Groups** | List all SIDs in token (useful for privilege analysis) |
| **Modify Token Flags** | TokenVirtualizationEnabled, TokenIsRestricted, etc. |
| **Session ID Manipulation** | Change token session ID |

```cpp
IOCTL_GET_TOKEN_INTEGRITY      // Read integrity level
IOCTL_SET_TOKEN_INTEGRITY      // Modify to System/High/Medium/Low
IOCTL_ENUM_TOKEN_GROUPS        // List all SIDs
```

**Priority:** 🟡 Medium - Sandbox escape research

---

### 6. Extended Process Manipulation

| Operation | Field | Description |
|-----------|-------|-------------|
| **Process Flags** | `_EPROCESS.Flags/Flags2/Flags3` | Audit, DEP, ASLR, CFG flags |
| **Mitigation Policies** | `_EPROCESS.MitigationFlags` | View/modify security mitigations |
| **Job Object** | `_EPROCESS.Job` | Detach from job (sandbox escape) |
| **Process Trust** | `_EPROCESS.TrustInfo` | Trust label manipulation |

```cpp
IOCTL_GET_PROCESS_MITIGATIONS  // Read all mitigation flags
IOCTL_SET_PROCESS_MITIGATIONS  // Modify specific flags
IOCTL_DETACH_FROM_JOB          // Remove job association
```

**Priority:** 🟡 Medium

---

### 7. ETW (Event Tracing for Windows) Enumeration

Many security tools rely on ETW. Enumerate and control:

```cpp
struct EtwProviderInfo {
    GUID ProviderGuid;
    WCHAR ProviderName[256];
    BOOLEAN IsEnabled;
    ULONG EnableLevel;
    ULONG64 EnableFlags;
    ULONG SessionCount;  // How many sessions consuming
};

IOCTL_ENUM_ETW_PROVIDERS       // List all registered providers
IOCTL_DISABLE_ETW_PROVIDER     // Disable specific provider (blind EDR)
```

**Note:** Disabling ETW providers is data modification (PG-safe), but commonly flagged by security tools.

**Priority:** 🟡 Medium - Blind EDR telemetry

---

### 8. Minifilter Enumeration

Enumerate registered filesystem minifilter drivers:

```cpp
struct MinifilterInfo {
    WCHAR FilterName[64];
    ULONG64 FilterAddress;
    ULONG FrameId;
    ULONG NumberOfInstances;
    ULONG64 Altitude;  // Filter load order
    // Pre/Post callbacks for each IRP_MJ_*
    ULONG64 PreCreateCallback;
    ULONG64 PostCreateCallback;
    ULONG64 PreReadCallback;
    ULONG64 PostReadCallback;
    ULONG64 PreWriteCallback;
    ULONG64 PostWriteCallback;
    // ... other operations
};

IOCTL_ENUM_MINIFILTERS  // List all minifilter registrations
```

**Use cases:**
- Identify AV/EDR filesystem monitoring
- Understand file access interception points
- Detect rootkit filesystem filters

**Priority:** 🔴 High - Find FS monitoring

---

### 9. Kernel Debugging Detection & Bypass

```cpp
struct KernelDebugInfo {
    BOOLEAN KdDebuggerEnabled;
    BOOLEAN KdDebuggerNotPresent;
    BOOLEAN KdPitchDebugger;
    ULONG64 KdpDebugRoutineSelect;
};

IOCTL_GET_KERNEL_DEBUG_STATUS  // Read debug status
IOCTL_CLEAR_KERNEL_DEBUG_FLAGS // Clear KdDebuggerEnabled (anti-anti-debug)
```

**Priority:** 🟢 Low

---

### 10. DSE (Driver Signature Enforcement) Status

Read-only check of CI.dll `g_CiOptions`:

```cpp
struct DseInfo {
    BOOLEAN IsEnabled;
    BOOLEAN IsTestSigningEnabled;
    ULONG CiOptions;  // Raw value
};

IOCTL_GET_DSE_STATUS  // Read CI options (useful before driver load)
```

**Priority:** 🟢 Low

---

### 11. Thread Manipulation

| Operation | Description |
|-----------|-------------|
| **Hide Thread** | Unlink from `_EPROCESS.ThreadListHead` (DKOM) |
| **Clear Thread Stack** | Zero call stack traces |
| **Modify Start Address** | Change `_ETHREAD.StartAddress` |
| **Set Thread Context from Kernel** | Direct context modification |

```cpp
IOCTL_HIDE_THREAD              // DKOM thread hiding
IOCTL_SET_THREAD_START_ADDRESS // Modify displayed start address
```

**Priority:** 🟢 Low - Offensive use

---

### 12. SSDT Enumeration (Read-Only)

Enumerate System Service Descriptor Table entries:

```cpp
struct SsdtEntry {
    ULONG ServiceNumber;     // Syscall number
    ULONG64 ServiceAddress;  // Handler address
    WCHAR ModuleName[64];    // Which module owns it
    BOOLEAN IsHooked;        // Compare with expected
};

IOCTL_ENUM_SSDT               // List all SSDT entries
IOCTL_ENUM_SHADOW_SSDT        // List Win32k.sys entries
```

**Use case:** Detect syscall hooking (though rare on modern Windows due to PatchGuard)

**Priority:** 🟢 Low - Educational/legacy

---

### 13. APC Injection from Kernel

Queue APCs directly from kernel mode:

```cpp
struct ApcRequest {
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG64 ApcRoutine;      // User-mode function to call
    ULONG64 ApcArgument;
    BOOLEAN ForceDelivery;   // Use KeAlertThread
};

IOCTL_QUEUE_USER_APC          // Queue user-mode APC
```

**Advantages over usermode APC injection:**
- Works on non-alertable threads with force delivery
- Bypasses some APC queue monitoring

**Priority:** 🟢 Low - Alternative injection

---

## Improvements to Existing Features

### Callback Enumeration Improvements

- [ ] Add callback removal capability (dangerous but useful for research)
- [ ] Show callback registration time if available in structure
- [ ] Decode callback addresses to symbol names if PDB available
- [ ] Add filtering by module name in UI

### PspCidTable Improvements

- [ ] Show process flags inline (Protection level, token integrity)
- [ ] Highlight hidden processes (compare with usermode, flag differences)
- [ ] Show more EPROCESS details (InheritedFromUniqueProcessId, CreateTime)
- [ ] Add "Compare with ToolHelp32" button to detect discrepancies

### Clear Debug Flags Improvements

- [ ] Clear additional flags: `ProcessBreakOnTermination`, `ProcessDebugObjectHandle`
- [ ] Clear heap debug structures: `_HEAP.Flags` debug bits
- [ ] Add "Verify cleared" status check after operation

### Process Protection Improvements

- [ ] Show current protection level before modification
- [ ] Support different protection levels (not just WinTcb-Light)
- [ ] Add batch protect/unprotect for multiple processes

### Token Privilege Improvements

- [ ] Show which privileges were already enabled vs newly enabled
- [ ] Support selective privilege enable/disable (not just "all")
- [ ] Display privilege names in UI after operation

---

## Priority Summary

| Priority | Feature | Effort | Value |
|----------|---------|--------|-------|
| 🔴 High | Object Callback Enumeration | Medium | Find EDR handle hooks |
| 🔴 High | Minifilter Enumeration | Medium | Find FS monitoring |
| 🔴 High | VAD Tree Enumeration | Medium | Detect hidden memory |
| 🟡 Medium | Driver Enumeration | Low | Detect hidden drivers |
| 🟡 Medium | Handle Table Direct Enum | Medium | Bypass handle hiding |
| 🟡 Medium | ETW Enumeration/Control | Medium | Blind EDR telemetry |
| 🟡 Medium | Token Integrity Manipulation | Low | Sandbox escape research |
| 🟡 Medium | Extended Process Manipulation | Medium | Mitigation bypass |
| 🟢 Low | SSDT Enumeration | Low | Educational/legacy |
| 🟢 Low | Thread Hiding (DKOM) | Medium | Offensive use |
| 🟢 Low | Kernel APC Injection | Medium | Alternative injection |
| 🟢 Low | DSE Status | Low | Driver load prep |
| 🟢 Low | Kernel Debug Detection | Low | Anti-anti-debug |

---

## Implementation Notes

### PatchGuard Safety Rules

All features must follow these rules to avoid PatchGuard/KPP:

1. ✅ **Data-only modifications** to per-process/per-token/per-thread structures
2. ✅ **Read-only access** to kernel tables (SSDT, PspCidTable, etc.)
3. ✅ **Using documented APIs** (RtlCreateUserThread, ZwAllocateVirtualMemory)
4. ❌ **NO code patching** (inline hooks, detours)
5. ❌ **NO SSDT/IDT/GDT modifications**
6. ❌ **NO critical structure modifications** (KiServiceTable, etc.)

### Structure Offset Management

For new features requiring structure offsets:

1. Add offsets to `WINDOWS_VERSION` enum handling in `GetWindowsVersion()`
2. Create offset arrays indexed by version (like `PROCESS_PROTECTION_OFFSET[]`)
3. Document offsets in `tools/verify_offsets.md`
4. Test on multiple Windows versions before release

### UI Integration Pattern

For new kernel features:

1. Add IOCTL constant to `DioProcessCommon.h`
2. Implement handler in `DioProcessDriver.cpp`
3. Add Rust binding in `crates/callback/src/driver.rs` or new module
4. Create UI component in `crates/ui/src/components/`
5. Add to Kernel Utilities tab or context menu as appropriate
