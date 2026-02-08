#include <ntddk.h>

#include <ia32.hpp>

#include "hv.h"

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount;				 // since WIN7
	ULONG NumberOfThreadsHighWatermark;	 // since WIN7
	ULONGLONG CycleTime;				 // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires
								// SystemExtendedProcessInformation)
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

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,		  // q: SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation,	  // q: SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
	SystemTimeOfDayInformation,	  // q: SYSTEM_TIMEOFDAY_INFORMATION
	SystemPathInformation,		  // not implemented
	SystemProcessInformation,	  // q: SYSTEM_PROCESS_INFORMATION
} SYSTEM_INFORMATION_CLASS;

using fnObReferenceObjectByHandleWithTag = NTSTATUS(__stdcall*)(HANDLE Handle,
	ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, ULONG Tag,
	PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation, __int64 a0);
fnObReferenceObjectByHandleWithTag old_ObpReferenceObjectByHandleWithTag = nullptr;

using fnNtQuerySystemInformation = NTSTATUS(__stdcall*)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
	ULONG SystemInformationLength, PULONG ReturnLength);
fnNtQuerySystemInformation old_NtQuerySystemInformation = nullptr;

extern "C" char* PsGetProcessImageFileName(PEPROCESS Process);

PCWCH protected_process_list[] = {
	L"cheatengine", L"HyperCE", L"x64dbg", L"x32dbg", L"ida", L"windbg"};

bool StringArrayContainsW(PCWCH str, PCWCH* arr, SIZE_T len)
{
	if (str == nullptr || arr == nullptr || len == 0)
		return false;

	for (SIZE_T i = 0; i < len; i++) {
		if (wcsstr(str, arr[i]) != nullptr)
			return true;
	}
	return false;
}

bool IsProtectedProcessW(PCWCH process)
{
	if (process == nullptr)
		return false;

	return StringArrayContainsW(
		process, protected_process_list, sizeof(protected_process_list) / sizeof(PCWCH));
}

bool IsProtectedProcessA(PCSZ process)
{
	if (process == nullptr)
		return false;

	ANSI_STRING process_ansi{0};
	UNICODE_STRING process_unicode{0};
	RtlInitAnsiString(&process_ansi, process);
	NTSTATUS status = RtlAnsiStringToUnicodeString(&process_unicode, &process_ansi, TRUE);
	if (!NT_SUCCESS(status))
		return false;

	bool result = IsProtectedProcessW(process_unicode.Buffer);
	RtlFreeUnicodeString(&process_unicode);
	return result;
}

uint8_t* FindObpReferenceObjectByHandleWithTag()
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

NTSTATUS ObpReferenceObjectByHandleWithTagHook(HANDLE Handle, ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, ULONG Tag, PVOID* Object,
	POBJECT_HANDLE_INFORMATION HandleInformation, __int64 a0)
{
	char* curr_process_name = PsGetProcessImageFileName(PsGetCurrentProcess());
	if (IsProtectedProcessA(curr_process_name))
		return old_ObpReferenceObjectByHandleWithTag(
			Handle, 0, ObjectType, KernelMode, Tag, Object, HandleInformation, a0);

	return old_ObpReferenceObjectByHandleWithTag(
		Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation, a0);
}

NTSTATUS NtQuerySystemInformationHook(SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	DbgPrint("[hv] NtQuerySystemInformation hook called.\n");
	NTSTATUS stat = old_NtQuerySystemInformation(
		SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (NT_SUCCESS(stat) && SystemInformationClass == SystemProcessInformation) {
		PSYSTEM_PROCESS_INFORMATION prev = PSYSTEM_PROCESS_INFORMATION(SystemInformation);
		PSYSTEM_PROCESS_INFORMATION curr =
			PSYSTEM_PROCESS_INFORMATION((PUCHAR)prev + prev->NextEntryOffset);

		while (prev->NextEntryOffset != NULL) {
			auto buffer = curr->ImageName.Buffer;
			if (buffer && IsProtectedProcessW(buffer)) {
				if (curr->NextEntryOffset == 0)
					prev->NextEntryOffset = 0;
				else
					prev->NextEntryOffset += curr->NextEntryOffset;
				curr = prev;
			}
			prev = curr;
			curr = PSYSTEM_PROCESS_INFORMATION((PUCHAR)curr + curr->NextEntryOffset);
		}
	}
	return stat;
}

// simple hypercall wrappers
static uint64_t ping()
{
	hv::hypercall_input input;
	input.code = hv::hypercall_ping;
	input.key = hv::hypercall_key;
	return hv::vmx_vmcall(input);
}

void driver_unload(PDRIVER_OBJECT)
{
	UnInstallEptHook(FindObpReferenceObjectByHandleWithTag(), old_ObpReferenceObjectByHandleWithTag);

	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
	const auto g_NtQuerySystemInformation = (uint8_t*)MmGetSystemRoutineAddress(&routineName);
	UnInstallEptHook(g_NtQuerySystemInformation, old_NtQuerySystemInformation);

	hv::stop();

	DbgPrint("[hv] Devirtualized the system.\n");
	DbgPrint("[hv] Driver unloaded.\n");
}

NTSTATUS driver_entry(PDRIVER_OBJECT const driver, PUNICODE_STRING)
{
	DbgPrint("[hv] Driver loaded.\n");

	if (driver)
		driver->DriverUnload = driver_unload;

	if (!hv::start()) {
		DbgPrint("[hv] Failed to virtualize system.\n");
		return STATUS_HV_OPERATION_FAILED;
	}

	if (ping() == hv::hypervisor_signature)
		DbgPrint("[client] Hypervisor signature matches.\n");
	else
		DbgPrint("[client] Failed to ping hypervisor!\n");

	auto result = InstallEptHook(FindObpReferenceObjectByHandleWithTag(),
		ObpReferenceObjectByHandleWithTagHook, (void**)&old_ObpReferenceObjectByHandleWithTag);
	DbgPrint("[hv] ObReferenceObjectByHandleWithTag hook installed: %s.\n",
		result ? "success\n" : "failure\n");

	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
	const auto g_NtQuerySystemInformation = (uint8_t*)MmGetSystemRoutineAddress(&routineName);
	result = InstallEptHook(g_NtQuerySystemInformation, NtQuerySystemInformationHook,
		(void**)&old_NtQuerySystemInformation);
	DbgPrint("[hv] NtQuerySystemInformation hook installed: %s.\n", result ? "success\n" : "failure\n");

	return STATUS_SUCCESS;
}
