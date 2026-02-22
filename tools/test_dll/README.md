# DLL Build Guidelines for Kernel Manual Map Injection

When building DLLs for use with the kernel manual map injection, follow these guidelines to ensure compatibility.

## Requirements

### 1. No CRT Dependencies (Recommended)
The target process may not have the Visual C++ runtime loaded. Build without CRT:

```cmake
target_link_options(YourDll PRIVATE
    /NODEFAULTLIB
    /ENTRY:_DllMainCRTStartup
)

target_link_libraries(YourDll PRIVATE
    kernel32.lib
)
```

### 2. Use Dynamic Function Resolution
Don't rely on import table resolution for non-kernel32 functions. Use `GetProcAddress`:

```cpp
typedef int (WINAPI* MessageBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT);

// Get function dynamically
HMODULE user32 = GetModuleHandleW(L"user32.dll");
MessageBoxW_t pMessageBoxW = (MessageBoxW_t)GetProcAddress(user32, "MessageBoxW");
pMessageBoxW(NULL, L"Hello", L"Title", MB_OK);
```

### 3. Enable Relocations
The DLL will be loaded at a random address. Ensure relocations are generated:

```cmake
target_link_options(YourDll PRIVATE
    /DYNAMICBASE:NO
    /FIXED:NO
)
```

### 4. Minimal Entry Point
Use a custom entry point without CRT initialization:

```cpp
extern "C" BOOL WINAPI _DllMainCRTStartup(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        // Your code here
    }
    return TRUE;
}
```

### 5. Disable Security Features
These can cause issues without CRT:

```cmake
target_compile_options(YourDll PRIVATE
    /GS-        # Disable buffer security check
)
```

## Supported Imports

The manual mapper resolves imports from modules **already loaded** in the target process. Common modules:
- `kernel32.dll` - Always loaded
- `ntdll.dll` - Always loaded
- `user32.dll` - Loaded in GUI applications

For other modules, use `LoadLibraryW` dynamically or ensure the target process has them loaded.

## Example CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.10)
project(MyInjectedDll)

add_library(MyDll SHARED dllmain.cpp)

target_compile_options(MyDll PRIVATE /GS-)

target_link_options(MyDll PRIVATE
    /NODEFAULTLIB
    /ENTRY:_DllMainCRTStartup
    /DYNAMICBASE:NO
    /FIXED:NO
)

target_link_libraries(MyDll PRIVATE kernel32.lib)
```

## Flags

The manual map injection supports these flags:
- `MANUAL_MAP_FLAG_NONE` (0x0) - Default, call DllMain
- `MANUAL_MAP_FLAG_ERASE_HEADERS` (0x1) - Erase PE headers after mapping (stealth)
- `MANUAL_MAP_FLAG_NO_ENTRY_POINT` (0x2) - Don't call DllMain
- `MANUAL_MAP_FLAG_NO_IMPORTS` (0x4) - Don't resolve imports (for shellcode-like DLLs)
