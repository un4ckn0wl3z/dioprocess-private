#include <ntddk.h>
#include <ia32.hpp>
#include "hv.h"
#include "HvProtection.h"

// ============== Dynamic Protected Process List ==============

#define MAX_PROTECTED_PIDS 64

static ULONG g_ProtectedPids[MAX_PROTECTED_PIDS] = { 0 };
static ULONG g_ProtectedPidCount = 0;
static KSPIN_LOCK g_ProtectedPidLock;
static bool g_HvInitialized = false;
static bool g_HooksInstalled = false;

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

// ============== Protected PID Management ==============

bool HvIsProcessProtectedByPid(ULONG Pid)
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_ProtectedPidLock, &oldIrql);

	bool found = false;
	for (ULONG i = 0; i < g_ProtectedPidCount; i++) {
		if (g_ProtectedPids[i] == Pid) {
			found = true;
			break;
		}
	}

	KeReleaseSpinLock(&g_ProtectedPidLock, oldIrql);
	return found;
}

bool HvAddProtectedPid(ULONG Pid)
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_ProtectedPidLock, &oldIrql);

	// Check if already protected
	for (ULONG i = 0; i < g_ProtectedPidCount; i++) {
		if (g_ProtectedPids[i] == Pid) {
			KeReleaseSpinLock(&g_ProtectedPidLock, oldIrql);
			return true; // Already protected
		}
	}

	// Check if list is full
	if (g_ProtectedPidCount >= MAX_PROTECTED_PIDS) {
		KeReleaseSpinLock(&g_ProtectedPidLock, oldIrql);
		return false;
	}

	g_ProtectedPids[g_ProtectedPidCount++] = Pid;

	KeReleaseSpinLock(&g_ProtectedPidLock, oldIrql);

	DbgPrint("[DioProcess] Added PID %lu to HV protection list (count=%lu)\n", Pid, g_ProtectedPidCount);
	return true;
}

bool HvRemoveProtectedPid(ULONG Pid)
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_ProtectedPidLock, &oldIrql);

	for (ULONG i = 0; i < g_ProtectedPidCount; i++) {
		if (g_ProtectedPids[i] == Pid) {
			// Shift remaining elements
			for (ULONG j = i; j < g_ProtectedPidCount - 1; j++) {
				g_ProtectedPids[j] = g_ProtectedPids[j + 1];
			}
			g_ProtectedPidCount--;
			KeReleaseSpinLock(&g_ProtectedPidLock, oldIrql);
			DbgPrint("[DioProcess] Removed PID %lu from HV protection list (count=%lu)\n", Pid, g_ProtectedPidCount);
			return true;
		}
	}

	KeReleaseSpinLock(&g_ProtectedPidLock, oldIrql);
	return false;
}

ULONG HvGetProtectedPidCount()
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_ProtectedPidLock, &oldIrql);
	ULONG count = g_ProtectedPidCount;
	KeReleaseSpinLock(&g_ProtectedPidLock, oldIrql);
	return count;
}

NTSTATUS HvGetProtectedPidList(ULONG* PidBuffer, ULONG BufferSize, ULONG* ReturnedCount)
{
	if (!PidBuffer || !ReturnedCount)
		return STATUS_INVALID_PARAMETER;

	KIRQL oldIrql;
	KeAcquireSpinLock(&g_ProtectedPidLock, &oldIrql);

	ULONG copyCount = min(g_ProtectedPidCount, BufferSize / sizeof(ULONG));
	RtlCopyMemory(PidBuffer, g_ProtectedPids, copyCount * sizeof(ULONG));
	*ReturnedCount = copyCount;

	KeReleaseSpinLock(&g_ProtectedPidLock, oldIrql);
	return STATUS_SUCCESS;
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
static NTSTATUS NtQuerySystemInformationHook(ULONG SystemInformationClass,
	PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS stat = g_OriginalNtQuerySystemInformation(
		SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (NT_SUCCESS(stat) && SystemInformationClass == SystemProcessInformation && SystemInformation) {
		PSYSTEM_PROCESS_INFORMATION prev = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		PSYSTEM_PROCESS_INFORMATION curr = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)prev + prev->NextEntryOffset);

		while (prev->NextEntryOffset != 0) {
			ULONG pid = (ULONG)(ULONG_PTR)curr->UniqueProcessId;

			if (HvIsProcessProtectedByPid(pid)) {
				// Hide this process entry by skipping over it
				if (curr->NextEntryOffset == 0)
					prev->NextEntryOffset = 0;
				else
					prev->NextEntryOffset += curr->NextEntryOffset;
				curr = prev;
			}

			prev = curr;
			if (prev->NextEntryOffset == 0) break;
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

	KeInitializeSpinLock(&g_ProtectedPidLock);

	DbgPrint("[DioProcess] Starting hypervisor...\n");

	if (!hv::start()) {
		DbgPrint("[DioProcess] Failed to virtualize system\n");
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

	// Clear protected PID list
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_ProtectedPidLock, &oldIrql);
	g_ProtectedPidCount = 0;
	RtlZeroMemory(g_ProtectedPids, sizeof(g_ProtectedPids));
	KeReleaseSpinLock(&g_ProtectedPidLock, oldIrql);

	// Stop hypervisor
	hv::stop();
	g_HvInitialized = false;

	DbgPrint("[DioProcess] Hypervisor stopped\n");
}

bool HvAreHooksInstalled()
{
	return g_HooksInstalled;
}
