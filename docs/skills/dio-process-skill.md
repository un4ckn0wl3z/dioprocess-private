# DioProcess Skill Document (Internal Contributor Edition)

Last verified: 2026-05-28
Audience: Internal team contributors and trusted research collaborators
Scope: Full project coverage (all implemented features, architecture, and core file map)

## 1. Purpose
This document is a complete technical map of DioProcess for contributor onboarding and knowledge transfer.
It covers:
- What the project is and how it runs
- Every major implemented capability
- Where each feature is implemented (UI, Rust crates, kernel, EFI)
- How subsystems connect
- Which files to edit when extending features

This is not a beginner tutorial. It is a maintainer-oriented reference.

## 2. Responsible Use
DioProcess contains powerful security-research capabilities (ring 0, ring -1, and UEFI-stage patching).
Use only in authorized environments.
Recommended baseline:
- Isolated test machine or VM
- Explicit permission for all targets
- Non-production systems
- Full backups and recovery plan for kernel/UEFI experiments

## 3. Project Summary
DioProcess is a Windows desktop tool built with Rust + Dioxus that combines:
- System/process/network/service visibility
- Usermode process manipulation features
- Kernel driver communication and event capture
- Hypervisor-assisted ring -1 features
- UEFI boot-time patch configuration

Primary goals:
- Windows internals research
- Red/blue team tooling experiments
- Kernel and hypervisor behavior analysis
- Runtime memory and hook investigation

## 4. Build and Runtime Requirements

### 4.1 Build
- Rust 2021 workspace
- Cargo workspace build
- Windows target

Commands:
- cargo build
- cargo build --release
- cargo run

### 4.2 Runtime
- Administrator privileges required for many features
- App embeds requireAdministrator manifest
- Driver-dependent features require DioProcess.sys loaded
- Hypervisor features require driver + VT-x compatible environment
- UEFI features require UEFI firmware and proper boot conditions

### 4.3 Driver startup (manual)
Typical flow:
- sc create DioProcess type= kernel binPath= "C:\path\to\DioProcess.sys"
- sc start DioProcess

## 5. High-Level Architecture

```text
Dioxus UI (crates/ui)
  -> process crate (process/thread/handle/module/memory/string scan)
  -> network crate (TCP/UDP table enumeration)
  -> service crate (SCM operations)
  -> misc crate (usermode techniques + process creation/injection helpers)
  -> callback crate (driver IOCTL + event stream + hypervisor bindings + scanner)
  -> uefi crate (NVRAM + ESP install/remove)

Kernel: kernelmode/DioProcess/DioProcessDriver
  -> IOCTL handlers, callback registration, event queue
  -> minifilter, DKOM, NSI, WFP modules
  -> integrated hypervisor implementation

UEFI: efi/DioProcessEfi
  -> boot stage logic + config + patch modules + graphics animation
```

## 6. Workspace Structure

### 6.1 Root-level key areas
- crates: Rust application and libraries
- kernelmode: kernel driver source and related components
- efi: UEFI DXE/boot module source
- docs: Next.js documentation site and public SDK headers
- sdk: exported SDK header and examples
- assets: experiments and test harness resources

### 6.2 Crate map
- crates/dioprocess: desktop binary entry point
- crates/ui: Dioxus routes, components, state, styles, config storage
- crates/process: process enumeration and memory inspection primitives
- crates/network: TCP/UDP enumeration
- crates/service: Windows service operations
- crates/misc: usermode + kernel-assisted operational techniques
- crates/callback: kernel driver API surface, event storage, hypervisor/scanner APIs
- crates/uefi: UEFI config and ESP operations

## 7. Capability Matrix (Feature -> Entry -> Backend -> Files)

### 7.1 Core monitoring
1. Process monitoring
- UI entry: Process tab
- Backend: process crate
- Core files:
  - crates/ui/src/components/process_tab.rs
  - crates/process/src/lib.rs

2. Network monitoring
- UI entry: Network tab
- Backend: network crate
- Core files:
  - crates/ui/src/components/network_tab.rs
  - crates/network/src/lib.rs

3. Service monitoring and control
- UI entry: Service tab
- Backend: service crate
- Core files:
  - crates/ui/src/components/service_tab.rs
  - crates/service/src/lib.rs

### 7.2 Process inspection windows
4. Thread viewer
- UI entry: Process context menu -> Inspect -> Threads
- Files:
  - crates/ui/src/components/thread_window.rs
  - crates/process/src/lib.rs

5. Handle viewer
- UI entry: Process context menu -> Inspect -> Handles
- Files:
  - crates/ui/src/components/handle_window.rs
  - crates/process/src/lib.rs

6. Module viewer
- UI entry: Process context menu -> Inspect -> Modules
- Files:
  - crates/ui/src/components/module_window.rs
  - crates/process/src/lib.rs

7. Memory viewer and hex dump
- UI entry: Process context menu -> Inspect -> Memory
- Files:
  - crates/ui/src/components/memory_window.rs
  - crates/process/src/lib.rs
  - crates/misc/src/memory.rs

8. Process performance graph
- UI entry: Process context menu -> Inspect -> Performance
- Files:
  - crates/ui/src/components/graph_window.rs
  - crates/process/src/lib.rs

9. Process string scanning (ASCII + UTF-16)
- UI entry: Process context menu -> Inspect -> String Scan
- Files:
  - crates/ui/src/components/string_scan_window.rs
  - crates/process/src/lib.rs

10. Hook scanning and integrated unhook
- UI entry: Process context menu -> Inspect -> Hook Scan
- Files:
  - crates/ui/src/components/hook_scan_window.rs
  - crates/misc/src/hook_scanner.rs
  - crates/misc/src/unhook.rs

### 7.3 DLL injection methods (usermode)
11. LoadLibrary injection
- Files:
  - crates/misc/src/injection/loadlibrary.rs

12. Thread hijack injection
- Files:
  - crates/misc/src/injection/thread_hijack.rs

13. APC queue injection
- Files:
  - crates/misc/src/injection/apc_queue.rs

14. EarlyBird injection
- Files:
  - crates/misc/src/injection/earlybird.rs

15. Remote mapping injection
- Files:
  - crates/misc/src/injection/remote_mapping.rs

16. Function stomping injection
- Files:
  - crates/misc/src/injection/function_stomping.rs
  - crates/ui/src/components/function_stomping_window.rs

17. Manual map injection
- Files:
  - crates/misc/src/injection/manual_map.rs

### 7.4 Shellcode injection methods (usermode)
18. Classic shellcode injection
- Files:
  - crates/misc/src/shellcode_inject/classic.rs

19. Web staging shellcode injection
- UI modal:
  - crates/ui/src/components/shellcode_inject_window.rs
- Backend:
  - crates/misc/src/shellcode_inject/web_staging.rs

20. Threadless shellcode injection
- UI modal:
  - crates/ui/src/components/threadless_inject_window.rs
- Backend:
  - crates/misc/src/shellcode_inject/threadless.rs

### 7.5 Process creation and execution techniques
21. Standard process creation
- Files:
  - crates/misc/src/process/create.rs
  - crates/ui/src/components/create_process_window.rs

22. PPID spoofing
- Files:
  - crates/misc/src/process/ppid_spoof.rs
  - crates/ui/src/components/create_process_window.rs

23. Process hollowing
- Files:
  - crates/misc/src/process/hollow.rs
  - crates/ui/src/components/create_process_window.rs

24. Process ghosting
- Files:
  - crates/misc/src/process/ghost.rs
  - crates/ui/src/components/ghost_process_window.rs

25. Ghostly hollowing
- Files:
  - crates/misc/src/process/ghostly_hollow.rs
  - crates/ui/src/components/utilities_tab.rs

26. Process herpaderping
- Files:
  - crates/misc/src/process/herpaderp.rs
  - crates/ui/src/components/utilities_tab.rs

27. Herpaderping hollowing
- Files:
  - crates/misc/src/process/herpaderp_hollow.rs
  - crates/ui/src/components/utilities_tab.rs

### 7.6 Misc process operations
28. Token theft
- UI modal:
  - crates/ui/src/components/token_thief_window.rs
- Backend:
  - crates/misc/src/token.rs

29. AMSI hook
- Files:
  - crates/misc/src/amsi.rs
  - crates/ui/src/components/process_tab.rs

30. DLL unhooking
- Files:
  - crates/misc/src/unhook.rs
  - crates/ui/src/components/process_tab.rs

31. ETW patch helper
- Files:
  - crates/misc/src/etw.rs
  - crates/ui/src/components/process_tab.rs

### 7.7 Kernel callback and event system
32. Real-time event collection (process/thread/image/handle/registry)
- UI:
  - crates/ui/src/components/callback_tab.rs
- API and storage:
  - crates/callback/src/driver.rs
  - crates/callback/src/types.rs
  - crates/callback/src/storage.rs

33. Callback registration lifecycle
- Files:
  - crates/callback/src/driver.rs
  - kernelmode/DioProcess/DioProcessDriver/IRP/DeviceControl.cpp

34. Event queue and delivery
- Files:
  - kernelmode/DioProcess/DioProcessDriver/DioProcessDriver.cpp
  - kernelmode/DioProcess/DioProcessDriver/IRP/Read.cpp

### 7.8 Kernel security and control features
35. Process protection manipulation
- Files:
  - crates/callback/src/driver.rs
  - kernelmode/DioProcess/DioProcessDriver/DioProcessDriver.h
  - kernelmode/DioProcess/DioProcessDriver/DioProcessDriver.cpp

36. Enable all privileges
- Files:
  - crates/callback/src/driver.rs
  - kernelmode/DioProcess/DioProcessDriver/DioProcessDriver.cpp

37. Clear debug flags
- Files:
  - crates/callback/src/driver.rs
  - kernelmode/DioProcess/DioProcessDriver/DioProcessDriver.cpp

38. Kernel injection (shellcode and DLL)
- Rust binding:
  - crates/misc/src/kernel_inject.rs
- Kernel side:
  - kernelmode/DioProcess/DioProcessDriver/Injection/KernelInject.cpp

39. Early injection (APC callback method)
- Rust binding:
  - crates/callback/src/early_injection.rs
- UI:
  - crates/ui/src/components/early_injection_window.rs
- Kernel side:
  - kernelmode/DioProcess/DioProcessDriver/Injection/EarlyInjection.cpp

40. Kernel memory copy / dump support
- Files:
  - crates/callback/src/driver.rs
  - kernelmode/DioProcess/DioProcessDriver/IRP/DeviceControl.cpp

41. Callback enumeration/removal/restore
- Files:
  - crates/callback/src/driver.rs
  - crates/ui/src/components/kernel_enumeration/callback_enum.rs
  - kernelmode/DioProcess/DioProcessDriver/IRP/DeviceControl.cpp

42. PspCidTable enumeration
- Files:
  - crates/callback/src/pspcidtable.rs
  - crates/ui/src/components/kernel_enumeration/pspcidtable.rs

43. Minifilter enumeration and unlink
- Files:
  - crates/callback/src/driver.rs
  - crates/ui/src/components/kernel_enumeration/minifilters.rs

44. Kernel threads and driver enumeration
- Files:
  - crates/ui/src/components/kernel_enumeration/kernel_threads.rs
  - crates/ui/src/components/kernel_enumeration/all_kernel_threads.rs
  - crates/ui/src/components/kernel_enumeration/drivers.rs
  - crates/callback/src/driver.rs

45. File hiding / process hiding / port hiding API bindings
- Files:
  - crates/callback/src/filehide.rs
  - crates/callback/src/process_hide.rs
  - crates/callback/src/porthide.rs
  - crates/ui/src/components/kernel_enumeration/filehide.rs
  - crates/ui/src/components/process_tab.rs

46. ETWTI controls
- Files:
  - crates/callback/src/kernel_etw.rs
  - crates/ui/src/components/kernel_enumeration/etwti.rs

47. Respawn monitor
- Files:
  - crates/ui/src/components/kernel_enumeration/respawn_monitor.rs
  - crates/ui/src/state.rs

### 7.9 Hypervisor and memory research
48. Hypervisor lifecycle (start/stop/ping/status)
- Files:
  - crates/callback/src/hypervisor.rs
  - kernelmode/DioProcess/DioProcessDriver/Hypervisor/hv.cpp
  - crates/ui/src/components/kernel_enumeration/hypervisor.rs

49. Ring -1 injection
- Files:
  - crates/callback/src/hypervisor.rs
  - kernelmode/DioProcess/DioProcessDriver/IRP/DeviceControl.cpp
  - crates/ui/src/components/process_tab.rs

50. Hypervisor process/driver hide control
- Files:
  - crates/callback/src/hypervisor.rs
  - kernelmode/DioProcess/DioProcessDriver/Hypervisor/HvProtection.cpp

51. Memory scanner (first/next scan)
- UI:
  - crates/ui/src/components/memory_scanner_tab.rs
- APIs:
  - crates/callback/src/scanner.rs
  - crates/callback/src/hv_scanner.rs

52. Physical memory translation and access tools
- UI:
  - crates/ui/src/components/memory_translate_tab.rs
- APIs:
  - crates/callback/src/physical_memory.rs

53. EPT hook tooling
- Files:
  - crates/callback/src/ept_hook.rs
  - crates/ui/src/components/ept_hook_modal.rs
  - crates/ui/src/components/memory_scanner_tab.rs
  - kernelmode/DioProcess/DioProcessDriver/EptHook/

54. Register-change tooling
- Files:
  - crates/callback/src/reg_change.rs
  - crates/ui/src/components/reg_change_modal.rs
  - crates/ui/src/components/memory_scanner_tab.rs

55. Script systems (.dph and .dpr)
- UI:
  - crates/ui/src/components/scripts_tab.rs
  - crates/ui/src/components/memory_scanner_tab.rs
  - crates/ui/src/components/process_tab.rs
- State/config:
  - crates/ui/src/state.rs
  - crates/ui/src/config.rs

### 7.10 Packet capture
56. Packet capture tab and storage
- UI:
  - crates/ui/src/components/packet_capture_tab.rs
- APIs:
  - crates/callback/src/packet_capture.rs
  - crates/callback/src/packet_storage.rs
- Kernel:
  - kernelmode/DioProcess/DioProcessDriver/WFP/WfpCapture.cpp

### 7.11 UEFI subsystem
57. UEFI config and status tab
- Files:
  - crates/ui/src/components/uefi_tab.rs
  - crates/uefi/src/lib.rs
  - crates/uefi/src/nvram.rs
  - crates/uefi/src/esp.rs

58. EFI install/remove from title bar flow
- Files:
  - crates/ui/src/components/app.rs
  - crates/uefi/src/esp.rs

59. EFI boot module and patch logic
- Files:
  - efi/DioProcessEfi/DioProcessEfi.c
  - efi/DioProcessEfi/Config.c
  - efi/DioProcessEfi/PatchDse.c
  - efi/DioProcessEfi/PatchKpp.c
  - efi/DioProcessEfi/Graphics.c

### 7.12 Utilities
60. File bloating utility
- Files:
  - crates/ui/src/components/utilities_tab.rs

61. Utility launch points for ghostly/herpaderp flows
- Files:
  - crates/ui/src/components/utilities_tab.rs
  - crates/misc/src/process/ghostly_hollow.rs
  - crates/misc/src/process/herpaderp.rs
  - crates/misc/src/process/herpaderp_hollow.rs

## 8. UI Map (Top-Level Route to Feature Area)
Primary routing and layout:
- crates/ui/src/components/app.rs
- crates/ui/src/routes.rs

Top-level tabs/components:
- Process: crates/ui/src/components/process_tab.rs
- Network: crates/ui/src/components/network_tab.rs
- Service: crates/ui/src/components/service_tab.rs
- Utilities: crates/ui/src/components/utilities_tab.rs
- Kernel Utilities: crates/ui/src/components/kernel_enumeration/mod.rs
- Hypervisor: crates/ui/src/components/kernel_enumeration/hypervisor.rs
- Memory Translate: crates/ui/src/components/memory_translate_tab.rs
- Memory Scanner: crates/ui/src/components/memory_scanner_tab.rs
- HV Scanner: crates/ui/src/components/hv_scanner_tab.rs
- Scripts: crates/ui/src/components/scripts_tab.rs
- Packet Capture: crates/ui/src/components/packet_capture_tab.rs
- UEFI: crates/ui/src/components/uefi_tab.rs
- System Events: crates/ui/src/components/callback_tab.rs

## 9. State and Persistence Model

### 9.1 Global state
Central signal and mode state:
- crates/ui/src/state.rs

Includes:
- Modal window states
- Search query states per tab
- Scanner + hook + script state
- Debug/alldrv CLI flags
- Respawn monitor state

### 9.2 Local storage
Configuration and script persistence:
- crates/ui/src/config.rs

Stores:
- Theme settings
- Secret/token data
- Hidden entities persistence tables
- DPH/DPR script persistence
- Respawn target persistence

### 9.3 Event storage
System event SQLite persistence:
- crates/callback/src/storage.rs
- integrated in crates/ui/src/components/callback_tab.rs

## 10. Driver Contract and API Surface

### 10.1 Shared contract header
- kernelmode/DioProcess/DioProcessDriver/DioProcessCommon.h

Defines:
- Event types/structures
- IOCTL constants
- Request/response shapes

### 10.2 Rust public callback API surface
- crates/callback/src/lib.rs

Main categories exposed:
- Driver collection control and event reads
- Callback enum/remove/restore
- Process protection and privilege controls
- Hypervisor control and ring -1 injection
- EPT/reg hook helpers
- Scanner and physical memory helpers
- Process/file/port hide helpers
- ETWTI helpers
- Packet capture APIs

### 10.3 SDK header for external C/C++ clients
- docs/public/DioProcessSDK.h
- sdk/DioProcessSDK.h

## 11. Kernel Driver Subsystem File Map

### 11.1 Driver root
- kernelmode/DioProcess/DioProcessDriver/DioProcessDriver.cpp
- kernelmode/DioProcess/DioProcessDriver/DioProcessDriver.h
- kernelmode/DioProcess/DioProcessDriver/DioProcessCommon.h
- kernelmode/DioProcess/DioProcessDriver/DioProcessGlobals.h
- kernelmode/DioProcess/DioProcessDriver/FastMutex.cpp
- kernelmode/DioProcess/DioProcessDriver/FastMutex.h
- kernelmode/DioProcess/DioProcessDriver/Locker.h

### 11.2 IRP handlers
- kernelmode/DioProcess/DioProcessDriver/IRP/CreateClose.cpp
- kernelmode/DioProcess/DioProcessDriver/IRP/Read.cpp
- kernelmode/DioProcess/DioProcessDriver/IRP/DeviceControl.cpp

### 11.3 Injection module
- kernelmode/DioProcess/DioProcessDriver/Injection/EarlyInjection.cpp
- kernelmode/DioProcess/DioProcessDriver/Injection/EarlyInjection.h
- kernelmode/DioProcess/DioProcessDriver/Injection/KernelInject.cpp
- kernelmode/DioProcess/DioProcessDriver/Injection/ManualMap.cpp
- kernelmode/DioProcess/DioProcessDriver/Injection/ManualMap.h

### 11.4 Hypervisor module
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/arch.asm
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/arch.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/ept.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/ept.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/exception-routines.asm
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/exception-routines.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/exit-handlers.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/exit-handlers.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/gdt.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/gdt.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/guest-context.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/hv.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/hv.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/HvProtection.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/HvProtection.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/hypercalls.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/hypercalls.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/idt.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/idt.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/interrupt-handlers.asm
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/interrupt-handlers.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/introspection.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/introspection.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/logger.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/logger.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/mm.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/mm.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/mtrr.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/mtrr.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/page-tables.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/page-tables.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/segment.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/segment.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/spin-lock.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/timing.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/timing.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/trap-frame.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/vcpu.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/vcpu.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/vm-exit.asm
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/vm-launch.asm
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/vmcs.cpp
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/vmcs.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/vmx.asm
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/vmx.h
- kernelmode/DioProcess/DioProcessDriver/Hypervisor/vmx.inl

### 11.5 Additional kernel modules
- DKOM:
  - kernelmode/DioProcess/DioProcessDriver/DKOM/ProcessHide.cpp
  - kernelmode/DioProcess/DioProcessDriver/DKOM/ProcessHide.h
- WFP:
  - kernelmode/DioProcess/DioProcessDriver/WFP/WfpCapture.cpp
  - kernelmode/DioProcess/DioProcessDriver/WFP/WfpCapture.h
- NSI and file-hide modules exist under:
  - kernelmode/DioProcess/DioProcessDriver/NSI
  - kernelmode/DioProcess/DioProcessDriver/FileHide
- EPT usermode hook support:
  - kernelmode/DioProcess/DioProcessDriver/EptHook

## 12. EFI Subsystem File Map
- efi/DioProcessEfi/Animation.h
- efi/DioProcessEfi/Config.c
- efi/DioProcessEfi/Config.h
- efi/DioProcessEfi/DioProcessEfi.c
- efi/DioProcessEfi/DioProcessEfi.dsc
- efi/DioProcessEfi/DioProcessEfi.inf
- efi/DioProcessEfi/Graphics.c
- efi/DioProcessEfi/Graphics.h
- efi/DioProcessEfi/PatchDse.c
- efi/DioProcessEfi/PatchDse.h
- efi/DioProcessEfi/PatchKpp.c
- efi/DioProcessEfi/PatchKpp.h
- efi/DioProcessEfi/PatternScan.c
- efi/DioProcessEfi/PatternScan.h
- efi/DioProcessEfi/PeUtils.c
- efi/DioProcessEfi/PeUtils.h

## 13. Rust Source File Index (Core)

### 13.1 Binary and UI root
- crates/dioprocess/src/main.rs
- crates/ui/src/lib.rs
- crates/ui/src/routes.rs
- crates/ui/src/state.rs
- crates/ui/src/config.rs
- crates/ui/src/helpers.rs
- crates/ui/src/styles.rs

### 13.2 UI components
- crates/ui/src/components/app.rs
- crates/ui/src/components/callback_tab.rs
- crates/ui/src/components/create_process_window.rs
- crates/ui/src/components/early_injection_window.rs
- crates/ui/src/components/ept_hook_modal.rs
- crates/ui/src/components/function_stomping_window.rs
- crates/ui/src/components/ghost_process_window.rs
- crates/ui/src/components/graph_window.rs
- crates/ui/src/components/handle_window.rs
- crates/ui/src/components/hook_scan_window.rs
- crates/ui/src/components/hv_scanner_tab.rs
- crates/ui/src/components/memory_scanner_tab.rs
- crates/ui/src/components/memory_translate_tab.rs
- crates/ui/src/components/memory_window.rs
- crates/ui/src/components/module_window.rs
- crates/ui/src/components/network_tab.rs
- crates/ui/src/components/packet_capture_tab.rs
- crates/ui/src/components/process_row.rs
- crates/ui/src/components/process_tab.rs
- crates/ui/src/components/reg_change_modal.rs
- crates/ui/src/components/scripts_tab.rs
- crates/ui/src/components/service_tab.rs
- crates/ui/src/components/shellcode_inject_window.rs
- crates/ui/src/components/string_scan_window.rs
- crates/ui/src/components/threadless_inject_window.rs
- crates/ui/src/components/thread_window.rs
- crates/ui/src/components/token_thief_window.rs
- crates/ui/src/components/uefi_tab.rs
- crates/ui/src/components/utilities_tab.rs

### 13.3 Kernel utilities sub-tabs
- crates/ui/src/components/kernel_enumeration/mod.rs
- crates/ui/src/components/kernel_enumeration/all_kernel_threads.rs
- crates/ui/src/components/kernel_enumeration/callback_enum.rs
- crates/ui/src/components/kernel_enumeration/drivers.rs
- crates/ui/src/components/kernel_enumeration/etwti.rs
- crates/ui/src/components/kernel_enumeration/filehide.rs
- crates/ui/src/components/kernel_enumeration/hypervisor.rs
- crates/ui/src/components/kernel_enumeration/kernel_threads.rs
- crates/ui/src/components/kernel_enumeration/minifilters.rs
- crates/ui/src/components/kernel_enumeration/pspcidtable.rs
- crates/ui/src/components/kernel_enumeration/respawn_monitor.rs

### 13.4 Callback crate
- crates/callback/src/lib.rs
- crates/callback/src/assembler.rs
- crates/callback/src/driver.rs
- crates/callback/src/early_injection.rs
- crates/callback/src/ept_hook.rs
- crates/callback/src/error.rs
- crates/callback/src/filehide.rs
- crates/callback/src/hv_scanner.rs
- crates/callback/src/hypervisor.rs
- crates/callback/src/kernel_etw.rs
- crates/callback/src/packet_capture.rs
- crates/callback/src/packet_storage.rs
- crates/callback/src/pdb_resolver.rs
- crates/callback/src/physical_memory.rs
- crates/callback/src/porthide.rs
- crates/callback/src/process_hide.rs
- crates/callback/src/pspcidtable.rs
- crates/callback/src/reg_change.rs
- crates/callback/src/scanner.rs
- crates/callback/src/storage.rs
- crates/callback/src/types.rs

### 13.5 Misc crate
- crates/misc/src/lib.rs
- crates/misc/src/amsi.rs
- crates/misc/src/error.rs
- crates/misc/src/etw.rs
- crates/misc/src/hook_scanner.rs
- crates/misc/src/kernel_inject.rs
- crates/misc/src/memory.rs
- crates/misc/src/module.rs
- crates/misc/src/token.rs
- crates/misc/src/unhook.rs

Injection folder:
- crates/misc/src/injection/mod.rs
- crates/misc/src/injection/apc_queue.rs
- crates/misc/src/injection/earlybird.rs
- crates/misc/src/injection/function_stomping.rs
- crates/misc/src/injection/loadlibrary.rs
- crates/misc/src/injection/manual_map.rs
- crates/misc/src/injection/remote_mapping.rs
- crates/misc/src/injection/thread_hijack.rs

Shellcode folder:
- crates/misc/src/shellcode_inject/mod.rs
- crates/misc/src/shellcode_inject/classic.rs
- crates/misc/src/shellcode_inject/threadless.rs
- crates/misc/src/shellcode_inject/web_staging.rs

Process folder:
- crates/misc/src/process/mod.rs
- crates/misc/src/process/create.rs
- crates/misc/src/process/ghost.rs
- crates/misc/src/process/ghostly_hollow.rs
- crates/misc/src/process/herpaderp.rs
- crates/misc/src/process/herpaderp_hollow.rs
- crates/misc/src/process/hollow.rs
- crates/misc/src/process/ppid_spoof.rs

### 13.6 Other crates
- crates/process/src/lib.rs
- crates/network/src/lib.rs
- crates/service/src/lib.rs
- crates/uefi/src/lib.rs
- crates/uefi/src/error.rs
- crates/uefi/src/esp.rs
- crates/uefi/src/nvram.rs

## 14. Documentation and SDK Artifacts

### 14.1 Docs site tree (major)
- docs/src/app/docs/getting-started
- docs/src/app/docs/usermode
- docs/src/app/docs/kernel
- docs/src/app/docs/kernel-enumeration
- docs/src/app/docs/kernel-hiding
- docs/src/app/docs/hypervisor
- docs/src/app/docs/uefi
- docs/src/app/docs/utilities
- docs/src/app/docs/api-reference
- docs/src/app/docs/sdk

### 14.2 Public SDK headers
- docs/public/DioProcessSDK.h
- sdk/DioProcessSDK.h

## 15. Runtime Feature Gating and Constraints
- Admin rights required for most write/control operations
- Driver-dependent features must check callback::is_driver_loaded
- Hypervisor-specific features must check callback::hv_is_running where required
- Early injection currently APC callback method only
- Several process-manipulation techniques are x64 payload sensitive
- UEFI features require firmware/environment prerequisites

## 16. Extension Playbooks

### 16.1 Add a new injection/process technique
1. Add implementation file in crates/misc/src/injection or crates/misc/src/process
2. Export from local mod.rs and crates/misc/src/lib.rs
3. Add UI action and modal wiring in crates/ui/src/components/process_tab.rs (or relevant tab)
4. Add state signal in crates/ui/src/state.rs if modal/stateful workflow needed
5. Add documentation update in docs/src/app/docs/usermode (or relevant area)

### 16.2 Add a new driver-backed feature
1. Add IOCTL contract in kernelmode/DioProcess/DioProcessDriver/DioProcessCommon.h
2. Implement handler in kernelmode/DioProcess/DioProcessDriver/IRP/DeviceControl.cpp
3. Expose binding in crates/callback/src/*.rs and re-export from crates/callback/src/lib.rs
4. Wire UI controls under suitable tab/component
5. Update docs and this skill map

### 16.3 Add a new top-level UI tab
1. Create component under crates/ui/src/components
2. Register route in crates/ui/src/routes.rs
3. Add tab navigation in crates/ui/src/components/app.rs
4. Add search/state signals in crates/ui/src/state.rs as needed
5. Document feature and file map

## 17. Maintenance Rules for This Skill Document
When project changes, update this file in lockstep with code changes.
Minimum update triggers:
- New feature entry point in any tab/context menu
- New crate/module export in callback or misc
- New IOCTL or contract change
- New persistence table/schema in config/storage
- New UEFI or hypervisor component

Update checklist:
1. Update Capability Matrix section
2. Update relevant file index section
3. Update constraints/prerequisites if changed
4. Bump Last verified date

## 18. Quick Navigation
If you are new and need fastest orientation:
1. Start at crates/ui/src/components/app.rs and crates/ui/src/routes.rs
2. Follow process workflows in crates/ui/src/components/process_tab.rs
3. Inspect callback exports in crates/callback/src/lib.rs
4. Inspect misc exports in crates/misc/src/lib.rs
5. Inspect IOCTL contract in kernelmode/DioProcess/DioProcessDriver/DioProcessCommon.h
6. Inspect kernel handling in kernelmode/DioProcess/DioProcessDriver/IRP/DeviceControl.cpp

## 19. Notes and Assumptions
- This document tracks the implementation currently present in the repository at verification date.
- Experimental or environment-sensitive features may behave differently across Windows versions and machine protections.
- For exact runtime behavior, verify corresponding source files listed above.

## 20. Non-Core and Support Areas
These areas are part of the repository and useful for testing, reference, or distribution, but are not the primary runtime implementation path.

### 20.1 Assets and experiments
- assets/dll
- assets/example_stress_test
- assets/mimikatz_trunk
- assets/service_skeleton_test
- assets/unhook_test

### 20.2 SDK and examples
- sdk/DioProcessSDK.h
- sdk/examples

### 20.3 Documentation app and public files
- docs/src
- docs/public

### 20.4 Kernel and EFI build environments
- kernelmode/DioProcess
- efi/DioProcessEfi

### 20.5 Additional test and utility workspaces
- test_network
- tools

### 20.6 Reference archives
- ref

### 20.7 Build outputs
- target

When sharing this document externally, clarify whether reference archives and generated outputs are in scope for the recipient.
