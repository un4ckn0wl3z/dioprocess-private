#pragma once

#include <ntddk.h>

//
// Simple x64 Length Disassembler Engine (LDE)
// Calculates instruction length without needing Capstone library
// Based on x86/x64 instruction encoding specification
//

#ifdef __cplusplus
extern "C" {
#endif

/// Get the length of an x64 instruction
/// @param address Pointer to instruction bytes
/// @return Instruction length in bytes (0 if invalid)
SIZE_T LDE64_GetInstructionLength(const void* address);

#ifdef __cplusplus
}
#endif
