#include <ntddk.h>
#include <ia32.hpp>
#include "hv.h"
#include "HvProtection.h"

// ============== Dynamic Protected Process List ==============

#define MAX_PROTECTED_PIDS 64

static ULONG g_ProtectedPids[MAX_PROTECTED_PIDS] = { 0 };
static ULONG g_ProtectedPidCount = 0;
static ERESOURCE g_ProtectedPidLock;  // Reader-writer lock for better perf
static bool g_HvInitialized = false;
static bool g_HooksInstalled = false;
static bool g_ProcessCallbackRegistered = false;
static bool g_ResourceInitialized = false;

// Function pointers for hooked functions
using fnObReferenceObjectByHandleWithTag = NTSTATUS(__stdcall*)(HANDLE Handle,
	ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, ULONG Tag,
	PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation, __int64 a0);
static fnObReferenceObjectByHandleWithTag g_OriginalObpReferenceObjectByHandleWithTag = nullptr;

using fnNtQuerySystemInformation = NTSTATUS(__stdcall*)(
	ULONG SystemInformationClass, PVOID SystemInformation,
	ULONG SystemInformationLength, PULONG ReturnLength);
static fnNtQuerySystemInformation g_OriginalNtQuerySystemInformation = nullptr;

extern "C" char* PsGetProcessImageFileName(PEPROCESS Process);

// ============== SYSTEM_PROCESS_INFORMATION for hiding ==============

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

#define SystemProcessInformation 5
#define SystemExtendedProcessInformation 57

// ============== Protected PID Management ==============

bool HvIsProcessProtectedByPid(ULONG Pid)
{
	if (!g_ResourceInitialized)
		return false;

	bool found = false;

	// Use shared (read) lock - allows multiple readers simultaneously
	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&g_ProtectedPidLock, TRUE);

	for (ULONG i = 0; i < g_ProtectedPidCount; i++) {
		if (g_ProtectedPids[i] == Pid) {
			found = true;
			break;
		}
	}

	ExReleaseResourceLite(&g_ProtectedPidLock);
	KeLeaveCriticalRegion();
	return found;
}

bool HvAddProtectedPid(ULONG Pid)
{
	if (!g_ResourceInitialized)
		return false;

	// Use exclusive (write) lock
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ProtectedPidLock, TRUE);

	// Check if already protected
	for (ULONG i = 0; i < g_ProtectedPidCount; i++) {
		if (g_ProtectedPids[i] == Pid) {
			ExReleaseResourceLite(&g_ProtectedPidLock);
			KeLeaveCriticalRegion();
			return true; // Already protected
		}
	}

	// Check if list is full
	if (g_ProtectedPidCount >= MAX_PROTECTED_PIDS) {
		ExReleaseResourceLite(&g_ProtectedPidLock);
		KeLeaveCriticalRegion();
		return false;
	}

	g_ProtectedPids[g_ProtectedPidCount++] = Pid;

	ExReleaseResourceLite(&g_ProtectedPidLock);
	KeLeaveCriticalRegion();

	DbgPrint("[DioProcess] Added PID %lu to HV protection list (count=%lu)\n", Pid, g_ProtectedPidCount);
	return true;
}

bool HvRemoveProtectedPid(ULONG Pid)
{
	if (!g_ResourceInitialized)
		return false;

	// Use exclusive (write) lock
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ProtectedPidLock, TRUE);

	for (ULONG i = 0; i < g_ProtectedPidCount; i++) {
		if (g_ProtectedPids[i] == Pid) {
			// Shift remaining elements
			for (ULONG j = i; j < g_ProtectedPidCount - 1; j++) {
				g_ProtectedPids[j] = g_ProtectedPids[j + 1];
			}
			g_ProtectedPidCount--;
			ExReleaseResourceLite(&g_ProtectedPidLock);
			KeLeaveCriticalRegion();
			DbgPrint("[DioProcess] Removed PID %lu from HV protection list (count=%lu)\n", Pid, g_ProtectedPidCount);
			return true;
		}
	}

	ExReleaseResourceLite(&g_ProtectedPidLock);
	KeLeaveCriticalRegion();
	return false;
}

ULONG HvGetProtectedPidCount()
{
	if (!g_ResourceInitialized)
		return 0;

	// Use shared (read) lock
	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&g_ProtectedPidLock, TRUE);
	ULONG count = g_ProtectedPidCount;
	ExReleaseResourceLite(&g_ProtectedPidLock);
	KeLeaveCriticalRegion();
	return count;
}

NTSTATUS HvGetProtectedPidList(ULONG* PidBuffer, ULONG BufferSize, ULONG* ReturnedCount)
{
	if (!PidBuffer || !ReturnedCount)
		return STATUS_INVALID_PARAMETER;

	if (!g_ResourceInitialized)
		return STATUS_UNSUCCESSFUL;

	// Use shared (read) lock
	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&g_ProtectedPidLock, TRUE);

	ULONG copyCount = min(g_ProtectedPidCount, BufferSize / sizeof(ULONG));
	RtlCopyMemory(PidBuffer, g_ProtectedPids, copyCount * sizeof(ULONG));
	*ReturnedCount = copyCount;

	ExReleaseResourceLite(&g_ProtectedPidLock);
	KeLeaveCriticalRegion();
	return STATUS_SUCCESS;
}

// ============== Process Exit Callback (Auto-cleanup) ==============

// Internal version without logging (to avoid recursion/lock issues)
static void HvRemoveProtectedPidInternal(ULONG Pid)
{
	if (!g_ResourceInitialized)
		return;

	// Use exclusive (write) lock
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ProtectedPidLock, TRUE);

	for (ULONG i = 0; i < g_ProtectedPidCount; i++) {
		if (g_ProtectedPids[i] == Pid) {
			for (ULONG j = i; j < g_ProtectedPidCount - 1; j++) {
				g_ProtectedPids[j] = g_ProtectedPids[j + 1];
			}
			g_ProtectedPidCount--;
			break;
		}
	}

	ExReleaseResourceLite(&g_ProtectedPidLock);
	KeLeaveCriticalRegion();
}

// Called when any process exits - removes dead PIDs from protection list
static void HvProcessNotifyCallback(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);

	// Only care about process exit (CreateInfo == NULL)
	if (CreateInfo != NULL)
		return;

	ULONG pid = (ULONG)(ULONG_PTR)ProcessId;

	// Check if this PID was protected and remove it
	if (HvIsProcessProtectedByPid(pid)) {
		HvRemoveProtectedPidInternal(pid);
		DbgPrint("[DioProcess] Auto-removed exited process PID %lu from HV protection\n", pid);
	}
}

// ============== Hook Implementations ==============

static uint8_t* FindObpReferenceObjectByHandleWithTag()
{
	auto const pObReferenceObjectByHandleWithTag =
		reinterpret_cast<uint8_t*>(ObReferenceObjectByHandleWithTag);

	for (size_t offset = 0; offset < 0x100; ++offset) {
		auto const curr = pObReferenceObjectByHandleWithTag + offset;
		if (*curr == 0xE8)
			return curr + 5 + *(int*)(curr + 1);
	}
	return nullptr;
}

// Hook: Bypass access checks for protected processes
static NTSTATUS ObpReferenceObjectByHandleWithTagHook(HANDLE Handle, ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, ULONG Tag, PVOID* Object,
	POBJECT_HANDLE_INFORMATION HandleInformation, __int64 a0)
{
	// Get current process PID
	HANDLE currentPid = PsGetCurrentProcessId();

	// If current process is protected, bypass access checks
	if (HvIsProcessProtectedByPid((ULONG)(ULONG_PTR)currentPid)) {
		return g_OriginalObpReferenceObjectByHandleWithTag(
			Handle, 0, ObjectType, KernelMode, Tag, Object, HandleInformation, a0);
	}

	return g_OriginalObpReferenceObjectByHandleWithTag(
		Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation, a0);
}

// Hook: Hide protected processes from NtQuerySystemInformation
// Handles both SystemProcessInformation (5) and SystemExtendedProcessInformation (57)
// Class 57 is used by Process Hacker and some other advanced tools
// Note: Threads are embedded in process entries, so hiding a process also hides its threads
static NTSTATUS NtQuerySystemInformationHook(ULONG SystemInformationClass,
	PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS stat = g_OriginalNtQuerySystemInformation(
		SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	// Handle both class 5 (basic) and class 57 (extended) - same structure layout for our needs
	if (NT_SUCCESS(stat) && SystemInformation &&
		(SystemInformationClass == SystemProcessInformation ||
		 SystemInformationClass == SystemExtendedProcessInformation)) {

		PSYSTEM_PROCESS_INFORMATION curr = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		PSYSTEM_PROCESS_INFORMATION prev = NULL;

		while (curr) {
			ULONG pid = (ULONG)(ULONG_PTR)curr->UniqueProcessId;
			bool shouldHide = HvIsProcessProtectedByPid(pid);

			if (shouldHide && prev == NULL) {
				// First entry is protected - shift the entire buffer
				// This is rare (first entry is usually System Idle Process)
				if (curr->NextEntryOffset != 0) {
					PSYSTEM_PROCESS_INFORMATION next = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)curr + curr->NextEntryOffset);
					// Calculate remaining size and shift data
					SIZE_T remainingSize = SystemInformationLength - curr->NextEntryOffset;
					RtlMoveMemory(curr, next, remainingSize);
					// Don't advance - recheck the new first entry
					continue;
				} else {
					// Only one entry and it's protected - zero it out
					RtlZeroMemory(curr, sizeof(SYSTEM_PROCESS_INFORMATION));
					break;
				}
			} else if (shouldHide && prev != NULL) {
				// Not first entry - skip over it by adjusting prev's NextEntryOffset
				if (curr->NextEntryOffset == 0) {
					prev->NextEntryOffset = 0;
				} else {
					prev->NextEntryOffset += curr->NextEntryOffset;
				}
				// Don't update prev, recheck from same position
				if (prev->NextEntryOffset == 0) break;
				curr = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)prev + prev->NextEntryOffset);
				continue;
			}

			// Move to next entry
			prev = curr;
			if (curr->NextEntryOffset == 0) break;
			curr = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)curr + curr->NextEntryOffset);
		}
	}
	return stat;
}

// ============== Hypervisor Control Functions ==============

bool HvIsHypervisorRunning()
{
	if (!g_HvInitialized)
		return false;

	__try {
		hv::hypercall_input input;
		input.code = hv::hypercall_ping;
		input.key = hv::hypercall_key;
		uint64_t result = hv::vmx_vmcall(input);
		return result == hv::hypervisor_signature;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}

NTSTATUS HvInstallProtectionHooks()
{
	if (g_HooksInstalled)
		return STATUS_SUCCESS;

	if (!g_HvInitialized || !HvIsHypervisorRunning())
		return STATUS_HV_NOT_PRESENT;

	// Install ObpReferenceObjectByHandleWithTag hook
	uint8_t* pObpFunc = FindObpReferenceObjectByHandleWithTag();
	if (!pObpFunc) {
		DbgPrint("[DioProcess] Failed to find ObpReferenceObjectByHandleWithTag\n");
		return STATUS_NOT_FOUND;
	}

	bool result = InstallEptHook(pObpFunc, ObpReferenceObjectByHandleWithTagHook,
		(void**)&g_OriginalObpReferenceObjectByHandleWithTag);
	if (!result) {
		DbgPrint("[DioProcess] Failed to install ObpReferenceObjectByHandleWithTag hook\n");
		return STATUS_UNSUCCESSFUL;
	}
	DbgPrint("[DioProcess] ObpReferenceObjectByHandleWithTag hook installed\n");

	// Install NtQuerySystemInformation hook
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
	uint8_t* pNtQsi = (uint8_t*)MmGetSystemRoutineAddress(&routineName);
	if (!pNtQsi) {
		DbgPrint("[DioProcess] Failed to find NtQuerySystemInformation\n");
		UnInstallEptHook(pObpFunc, g_OriginalObpReferenceObjectByHandleWithTag);
		g_OriginalObpReferenceObjectByHandleWithTag = nullptr;
		return STATUS_NOT_FOUND;
	}

	result = InstallEptHook(pNtQsi, NtQuerySystemInformationHook,
		(void**)&g_OriginalNtQuerySystemInformation);
	if (!result) {
		DbgPrint("[DioProcess] Failed to install NtQuerySystemInformation hook\n");
		UnInstallEptHook(pObpFunc, g_OriginalObpReferenceObjectByHandleWithTag);
		g_OriginalObpReferenceObjectByHandleWithTag = nullptr;
		return STATUS_UNSUCCESSFUL;
	}
	DbgPrint("[DioProcess] NtQuerySystemInformation hook installed\n");

	g_HooksInstalled = true;
	return STATUS_SUCCESS;
}

void HvRemoveProtectionHooks()
{
	if (!g_HooksInstalled)
		return;

	// Remove ObpReferenceObjectByHandleWithTag hook
	if (g_OriginalObpReferenceObjectByHandleWithTag) {
		uint8_t* pObpFunc = FindObpReferenceObjectByHandleWithTag();
		if (pObpFunc)
			UnInstallEptHook(pObpFunc, g_OriginalObpReferenceObjectByHandleWithTag);
		g_OriginalObpReferenceObjectByHandleWithTag = nullptr;
	}

	// Remove NtQuerySystemInformation hook
	if (g_OriginalNtQuerySystemInformation) {
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
		uint8_t* pNtQsi = (uint8_t*)MmGetSystemRoutineAddress(&routineName);
		if (pNtQsi)
			UnInstallEptHook(pNtQsi, g_OriginalNtQuerySystemInformation);
		g_OriginalNtQuerySystemInformation = nullptr;
	}

	g_HooksInstalled = false;
	DbgPrint("[DioProcess] Protection hooks removed\n");
}

NTSTATUS HvStartHypervisor()
{
	if (g_HvInitialized)
		return STATUS_ALREADY_INITIALIZED;

	// Initialize ERESOURCE (reader-writer lock)
	NTSTATUS resStatus = ExInitializeResourceLite(&g_ProtectedPidLock);
	if (!NT_SUCCESS(resStatus)) {
		DbgPrint("[DioProcess] Failed to initialize ERESOURCE (0x%X)\n", resStatus);
		return resStatus;
	}
	g_ResourceInitialized = true;

	// Register process exit callback for auto-cleanup of dead PIDs
	if (!g_ProcessCallbackRegistered) {
		NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(HvProcessNotifyCallback, FALSE);
		if (NT_SUCCESS(status)) {
			g_ProcessCallbackRegistered = true;
			DbgPrint("[DioProcess] Process exit callback registered\n");
		} else {
			DbgPrint("[DioProcess] Warning: Failed to register process callback (0x%X)\n", status);
			// Continue anyway - this is not critical
		}
	}

	DbgPrint("[DioProcess] Starting hypervisor...\n");

	if (!hv::start()) {
		DbgPrint("[DioProcess] Failed to virtualize system\n");
		// Unregister callback on failure
		if (g_ProcessCallbackRegistered) {
			PsSetCreateProcessNotifyRoutineEx(HvProcessNotifyCallback, TRUE);
			g_ProcessCallbackRegistered = false;
		}
		// Delete ERESOURCE on failure
		if (g_ResourceInitialized) {
			ExDeleteResourceLite(&g_ProtectedPidLock);
			g_ResourceInitialized = false;
		}
		return STATUS_HV_OPERATION_FAILED;
	}

	g_HvInitialized = true;

	if (HvIsHypervisorRunning()) {
		DbgPrint("[DioProcess] Hypervisor started successfully, signature verified\n");
		return STATUS_SUCCESS;
	} else {
		DbgPrint("[DioProcess] Hypervisor started but signature mismatch\n");
		return STATUS_HV_OPERATION_FAILED;
	}
}

void HvStopHypervisor()
{
	if (!g_HvInitialized)
		return;

	// Remove hooks first
	HvRemoveProtectionHooks();

	// Unregister process exit callback
	if (g_ProcessCallbackRegistered) {
		PsSetCreateProcessNotifyRoutineEx(HvProcessNotifyCallback, TRUE);
		g_ProcessCallbackRegistered = false;
		DbgPrint("[DioProcess] Process exit callback unregistered\n");
	}

	// Clear protected PID list using ERESOURCE
	if (g_ResourceInitialized) {
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(&g_ProtectedPidLock, TRUE);
		g_ProtectedPidCount = 0;
		RtlZeroMemory(g_ProtectedPids, sizeof(g_ProtectedPids));
		ExReleaseResourceLite(&g_ProtectedPidLock);
		KeLeaveCriticalRegion();
	}

	// Stop hypervisor
	hv::stop();
	g_HvInitialized = false;

	// Delete ERESOURCE after hypervisor is stopped
	if (g_ResourceInitialized) {
		ExDeleteResourceLite(&g_ProtectedPidLock);
		g_ResourceInitialized = false;
		DbgPrint("[DioProcess] ERESOURCE deleted\n");
	}

	DbgPrint("[DioProcess] Hypervisor stopped\n");
}

bool HvAreHooksInstalled()
{
	return g_HooksInstalled;
}
