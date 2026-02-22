#include <Windows.h>

// Function pointer types
typedef HMODULE(WINAPI* GetModuleHandleW_t)(LPCWSTR);
typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE, LPCSTR);
typedef int (WINAPI* MessageBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT);

// Custom entry point - no CRT
extern "C" BOOL WINAPI _DllMainCRTStartup(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;

    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        // Get kernel32 functions dynamically
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32)
        {
            GetModuleHandleW_t pGetModuleHandleW = (GetModuleHandleW_t)GetProcAddress(kernel32, "GetModuleHandleW");
            GetProcAddress_t pGetProcAddress = (GetProcAddress_t)GetProcAddress(kernel32, "GetProcAddress");
            
            if (pGetModuleHandleW && pGetProcAddress)
            {
                HMODULE user32 = pGetModuleHandleW(L"user32.dll");
                if (user32)
                {
                    MessageBoxW_t pMessageBoxW = (MessageBoxW_t)pGetProcAddress(user32, "MessageBoxW");
                    if (pMessageBoxW)
                    {
                        pMessageBoxW(NULL, L"Hello from Kernel Manual Map!", L"Success", MB_OK | MB_ICONINFORMATION);
                    }
                }
            }
        }
    }
    return TRUE;
}
