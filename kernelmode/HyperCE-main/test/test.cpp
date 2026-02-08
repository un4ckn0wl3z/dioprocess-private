#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

// Function to get the base address of explorer.exe
DWORD64 GetExplorerBaseAddress(DWORD dwPID) {
    // Create a snapshot of the modules of the specified process
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed" << std::endl;
        return 0;
    }

    // Enumerate through the modules in the snapshot
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnapshot, &me32)) {
        do {
            // Check if the module is explorer.exe
            if (_wcsicmp(me32.szModule, L"explorer.exe") == 0) {
                CloseHandle(hSnapshot);
                return (DWORD64)me32.modBaseAddr; // Return the base address
            }
        } while (Module32Next(hSnapshot, &me32)); // Continue to next module
    }

    // If explorer.exe is not found
    CloseHandle(hSnapshot);
    return 0;
}

// Function to read memory content from the base address of explorer.exe
void ReadBaseAddressContent(HANDLE hProcess, DWORD64 baseAddress) {
    BYTE buffer[64]; // Buffer to store the memory content (64 bytes for example)
    SIZE_T bytesRead;

    // Read memory from the base address of explorer.exe
    if (ReadProcessMemory(hProcess, (LPCVOID)baseAddress, buffer, sizeof(buffer), &bytesRead)) {
        std::cout << "Memory content at base address: ";
        // Print the memory content in hexadecimal format
        for (SIZE_T i = 0; i < bytesRead; i++) {
            std::cout << std::hex << (int)buffer[i] << " ";
        }
        std::cout << std::dec << std::endl; // Reset the output to decimal format
    }
    else {
        std::cerr << "ReadProcessMemory failed" << std::endl; // If reading memory fails
    }
}

// Function to find the PID of explorer.exe
DWORD GetExplorerPID() {
    // Create a snapshot of all processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed" << std::endl;
        return 0;
    }

    // Enumerate through all processes in the snapshot
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Check if the process is explorer.exe
            if (wcscmp(pe32.szExeFile, L"explorer.exe") == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID; // Return the PID of explorer.exe
            }
        } while (Process32Next(hSnapshot, &pe32)); // Continue to next process
    }

    // If explorer.exe is not found
    CloseHandle(hSnapshot);
    return 0;
}

int main() {
    // Get the PID of explorer.exe
    DWORD dwPID = GetExplorerPID();
    if (dwPID == 0) {
        std::cerr << "Explorer.exe not found!" << std::endl;
        return 1;
    }

    // Open the explorer.exe process with read permission
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID);
    if (hProcess == NULL) {
        std::cerr << "OpenProcess failed" << std::endl;
        return 1;
    }

    // Get the base address of explorer.exe
    DWORD64 baseAddress = GetExplorerBaseAddress(dwPID);
    if (baseAddress != 0) {
        std::cout << "Explorer.exe base address: " << std::hex << baseAddress << std::endl;
        ReadBaseAddressContent(hProcess, baseAddress); // Read the memory content at the base address
    }
    else {
        std::cerr << "Explorer.exe base address not found!" << std::endl;
    }

    // Close the process handle
    CloseHandle(hProcess);

    return 0;
}
