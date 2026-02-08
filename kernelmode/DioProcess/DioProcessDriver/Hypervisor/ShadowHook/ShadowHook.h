#pragma once
#include <ia32.hpp>

#include "../vcpu.h"

bool InstallEptHook(void* hook_add, void* self_func_add, void** old_func_add);
void UnInstallEptHook(void* hook_add, void* old_func_add);
