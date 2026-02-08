#include "ShadowHook.h"

#include <capstone.h>
#include <pshpack1.h>
#if defined(_AMD64_)
struct TrampolineCode {
	UCHAR nop;
	UCHAR jmp[6];
	void* address;
};
static_assert(sizeof(TrampolineCode) == 15, "Size check");
#else
struct TrampolineCode {
	UCHAR nop;
	UCHAR push;
	void* address;
	UCHAR ret;
};
static_assert(sizeof(TrampolineCode) == 7, "Size check");
#endif

#define EPT_EXECUTE_PAGE_TAG 'pepe'
#define EPT_ORIGINAL_CALL_PAGE_TAG 'ofp1'

/// Checks if a system is x64
/// @return true if a system is x64
constexpr bool IsX64()
{
#if defined(_AMD64_)
	return true;
#else
	return false;
#endif
}

SIZE_T GetInstructionSize(void* address)
{
	// Save floating point state
	KFLOATING_SAVE float_save = {};
	auto status = KeSaveFloatingPointState(&float_save);
	if (!NT_SUCCESS(status))
		return 0;

	// max 15 bytes
	csh handle = {};
	const auto mode = IsX64() ? CS_MODE_64 : CS_MODE_32;
	if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
		KeRestoreFloatingPointState(&float_save);
		return 0;
	}

	static const auto kLongestInstSize = 15;
	cs_insn* instructions = nullptr;
	const auto count = cs_disasm(handle, reinterpret_cast<uint8_t*>(address), kLongestInstSize,
		reinterpret_cast<uint64_t>(address), 1, &instructions);
	if (count == 0) {
		cs_close(&handle);
		KeRestoreFloatingPointState(&float_save);
		return 0;
	}

	// get first instruction size
	const auto size = instructions[0].size;
	cs_free(instructions, count);
	cs_close(&handle);

	// Restore floating point state
	KeRestoreFloatingPointState(&float_save);
	return size;
}

static TrampolineCode MakeTrampolineCode(void* jmp_back_address)
{
#if defined(_AMD64_)
	// 90               nop
	// ff2500000000     jmp     qword ptr cs:jmp_addr(hook jump back address)
	// jmp_addr:
	// 0000000000000000 dq 0
	return {
		0x90,
		{ 0xff, 0x25, 0x00, 0x00, 0x00, 0x00, },
		jmp_back_address,
	};
#else
	// 90               nop
	// 6832e30582       push    offset nt!ExFreePoolWithTag + 0x2 (8205e332)
	// c3               ret
	return {
		0x90,
		0x68,
		jmp_back_address,
		0xc3,
	};
#endif
}

bool InstallEptHook(void* hook_add, void* self_func_add, void** old_func_add)
{
	if (hook_add == nullptr || self_func_add == nullptr || old_func_add == nullptr)
		return false;

	// mov rax, 0x7856341278563412
	// jmp rax
	uint8_t new_bytes[12] = {
		0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12,
		0xFF, 0xE0,
	};
	*reinterpret_cast<void**>(new_bytes + 2) = (void*)self_func_add;

	auto const exec_page =
		(uint8_t*)ExAllocatePoolWithTag(NonPagedPool, 0x1000, EPT_EXECUTE_PAGE_TAG);
	if (!exec_page) {
		DbgPrint("[hv] allocate exec page error\n");
		return false;
	}

	memcpy(exec_page, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(hook_add) & ~0xFFFull),
		0x1000);

	SIZE_T patch_bytes_size = 0;
	int get_patch_bytes_size_count = 0;
	while (true) {
		// Sometimes the exec_page data is not refreshed, so the original page is used for parsing
		patch_bytes_size += GetInstructionSize((uint8_t*)hook_add + patch_bytes_size);
		get_patch_bytes_size_count++;

		if (patch_bytes_size > sizeof(new_bytes))
			break;
		if (get_patch_bytes_size_count > sizeof(new_bytes)) {
			DbgPrint("[hv] patch bytes size too large, count = %d, path_bytes_size = %zd\n",
				get_patch_bytes_size_count, patch_bytes_size);
			return false;
		}
	}
	// DbgPrint("[hv] get patch bytes size count = %d, path_bytes_size = %d\n",
	// get_patch_bytes_size_count, patch_bytes_size);

	const auto jmp_to_original = MakeTrampolineCode((void*)((uint64_t)hook_add + patch_bytes_size));

	auto const original_function_page = (uint8_t*)ExAllocatePoolWithTag(NonPagedPoolExecute,
		patch_bytes_size + sizeof(jmp_to_original), EPT_ORIGINAL_CALL_PAGE_TAG);
	if (!original_function_page) {
		DbgPrint("[hv] allocate original function page error\n");
		return false;
	}
	RtlZeroMemory((void*)original_function_page, patch_bytes_size + sizeof(jmp_to_original));

	memcpy(original_function_page, hook_add, patch_bytes_size);
	memcpy(original_function_page + patch_bytes_size, &jmp_to_original, sizeof(jmp_to_original));

	*old_func_add = original_function_page;

	memcpy(exec_page + ((uint64_t)hook_add & 0xFFF), new_bytes, sizeof(new_bytes));

	for (size_t i = 0; i < KeQueryActiveProcessorCount(nullptr); ++i) {
		auto const orig_affinity = KeSetSystemAffinityThreadEx(1ull << i);

		hv::hypercall_input input;
		input.code = hv::hypercall_install_ept_hook;
		input.key = hv::hypercall_key;
		auto patch_phy = MmGetPhysicalAddress(hook_add).QuadPart >> 12;
		input.args[0] = patch_phy;
		auto exec_page_phy = MmGetPhysicalAddress(exec_page).QuadPart >> 12;
		input.args[1] = exec_page_phy;
		hv::vmx_vmcall(input);

		KeRevertToUserAffinityThreadEx(orig_affinity);
	}

	return true;
}

void UnInstallEptHook(void* hook_add, void* old_func_add)
{
	for (size_t i = 0; i < KeQueryActiveProcessorCount(nullptr); ++i) {
		auto const orig_affinity = KeSetSystemAffinityThreadEx(1ull << i);

		hv::hypercall_input input;
		input.code = hv::hypercall_remove_ept_hook;
		input.key = hv::hypercall_key;
		auto patch_phy = MmGetPhysicalAddress(hook_add).QuadPart >> 12;
		input.args[0] = patch_phy;
		hv::vmx_vmcall(input);

		KeRevertToUserAffinityThreadEx(orig_affinity);
	}

	ExFreePoolWithTag(old_func_add, EPT_ORIGINAL_CALL_PAGE_TAG);
}
