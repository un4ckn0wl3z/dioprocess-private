/**
 * @file hello_world.cpp
 * @brief DioProcess SDK Hello World Example
 * 
 * This example demonstrates basic usage of the DioProcessSDK class.
 * It connects to the driver, performs some basic operations, and displays results.
 * 
 * Build: cl /EHsc hello_world.cpp /Fe:hello_world.exe
 * Run: hello_world.exe (requires administrator privileges and driver loaded)
 */

#include <iostream>
#include <iomanip>
#include "../DioProcessSDK.h"

void PrintHex(ULONG64 value) {
    std::cout << "0x" << std::hex << std::setfill('0') << std::setw(16) << value << std::dec;
}

int main() {
    std::cout << "=== DioProcess SDK Hello World ===" << std::endl << std::endl;

    // Create SDK instance
    DioProcessSDK sdk;

    // Try to open connection to driver
    std::cout << "[*] Opening connection to DioProcess driver..." << std::endl;
    if (!sdk.Open()) {
        std::cerr << "[!] Failed to open driver. Error: " << GetLastError() << std::endl;
        std::cerr << "    Make sure:" << std::endl;
        std::cerr << "    - You are running as Administrator" << std::endl;
        std::cerr << "    - The DioProcess driver is loaded" << std::endl;
        return 1;
    }
    std::cout << "[+] Connected to driver successfully!" << std::endl << std::endl;

    // Get current process ID
    ULONG currentPid = GetCurrentProcessId();
    std::cout << "[*] Current Process ID: " << currentPid << std::endl << std::endl;

    // Example 1: Check collection state
    std::cout << "--- Example 1: Collection State ---" << std::endl;
    CollectionStateResponse collectionState = {};
    if (sdk.GetCollectionState(&collectionState)) {
        std::cout << "[+] Collection active: " << (collectionState.IsCollecting ? "Yes" : "No") << std::endl;
        std::cout << "[+] Item count: " << collectionState.ItemCount << std::endl;
    } else {
        std::cout << "[-] Failed to get collection state" << std::endl;
    }
    std::cout << std::endl;

    // Example 2: Check hypervisor status
    std::cout << "--- Example 2: Hypervisor Status ---" << std::endl;
    HvPingResponse hvStatus = {};
    if (sdk.HvPing(&hvStatus)) {
        std::cout << "[+] Hypervisor running: " << (hvStatus.IsRunning ? "Yes" : "No") << std::endl;
        std::cout << "[+] Hooks installed: " << (hvStatus.HooksInstalled ? "Yes" : "No") << std::endl;
        std::cout << "[+] Protected processes: " << hvStatus.ProtectedProcessCount << std::endl;
    } else {
        std::cout << "[-] Failed to ping hypervisor (may not be started)" << std::endl;
    }
    std::cout << std::endl;

    // Example 3: Enumerate process callbacks
    std::cout << "--- Example 3: Process Callbacks ---" << std::endl;
    BYTE callbackBuffer[8192];
    DWORD bytesReturned = 0;
    if (sdk.EnumProcessCallbacks(callbackBuffer, sizeof(callbackBuffer), &bytesReturned)) {
        ULONG count = *(ULONG*)callbackBuffer;
        std::cout << "[+] Found " << count << " process callback(s)" << std::endl;
        
        CallbackInformation* callbacks = (CallbackInformation*)(callbackBuffer + sizeof(ULONG));
        for (ULONG i = 0; i < count && i < 5; i++) {
            std::cout << "    [" << i << "] " << callbacks[i].ModuleName << " @ ";
            PrintHex(callbacks[i].CallbackAddress);
            std::cout << std::endl;
        }
        if (count > 5) {
            std::cout << "    ... and " << (count - 5) << " more" << std::endl;
        }
    } else {
        std::cout << "[-] Failed to enumerate process callbacks" << std::endl;
    }
    std::cout << std::endl;

    // Example 4: Enumerate drivers
    std::cout << "--- Example 4: Kernel Drivers ---" << std::endl;
    BYTE driverBuffer[65536];
    if (sdk.EnumDrivers(driverBuffer, sizeof(driverBuffer), &bytesReturned)) {
        ULONG count = *(ULONG*)driverBuffer;
        std::cout << "[+] Found " << count << " driver(s)" << std::endl;
        
        KernelDriverInfo* drivers = (KernelDriverInfo*)(driverBuffer + sizeof(ULONG));
        for (ULONG i = 0; i < count && i < 5; i++) {
            std::cout << "    [" << i << "] " << drivers[i].DriverName;
            std::cout << " @ ";
            PrintHex(drivers[i].BaseAddress);
            std::cout << " (Size: 0x" << std::hex << drivers[i].Size << std::dec << ")" << std::endl;
        }
        if (count > 5) {
            std::cout << "    ... and " << (count - 5) << " more" << std::endl;
        }
    } else {
        std::cout << "[-] Failed to enumerate drivers" << std::endl;
    }
    std::cout << std::endl;

    // Example 5: Protect current process (optional - uncomment to test)
    /*
    std::cout << "--- Example 5: Process Protection ---" << std::endl;
    if (sdk.ProtectProcess(currentPid)) {
        std::cout << "[+] Process protected with PPL!" << std::endl;
        
        // Unprotect after demonstration
        if (sdk.UnprotectProcess(currentPid)) {
            std::cout << "[+] Process unprotected" << std::endl;
        }
    } else {
        std::cout << "[-] Failed to protect process" << std::endl;
    }
    std::cout << std::endl;
    */

    // Example 6: Virtual address translation
    std::cout << "--- Example 6: VA Translation ---" << std::endl;
    TranslateVaResponse vaResponse = {};
    ULONG64 testAddress = (ULONG64)&main;  // Use main function address
    if (sdk.TranslateVa(currentPid, testAddress, &vaResponse)) {
        if (vaResponse.Success) {
            std::cout << "[+] Virtual Address: ";
            PrintHex(testAddress);
            std::cout << std::endl;
            std::cout << "[+] Physical Address: ";
            PrintHex(vaResponse.PhysicalAddress);
            std::cout << std::endl;
            std::cout << "[+] CR3: ";
            PrintHex(vaResponse.Cr3);
            std::cout << std::endl;
            std::cout << "[+] Page Size: " << vaResponse.PageSize << " bytes" << std::endl;
        } else {
            std::cout << "[-] Translation failed" << std::endl;
        }
    } else {
        std::cout << "[-] Failed to translate VA" << std::endl;
    }
    std::cout << std::endl;

    // Close connection
    sdk.Close();
    std::cout << "[*] Connection closed." << std::endl;
    std::cout << std::endl << "=== Done ===" << std::endl;

    return 0;
}
