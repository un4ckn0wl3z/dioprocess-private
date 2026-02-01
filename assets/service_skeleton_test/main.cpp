#include <windows.h>

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;

void WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    if (ctrlCode == SERVICE_CONTROL_STOP) {
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);
    }
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    serviceStatusHandle = RegisterServiceCtrlHandler(
        TEXT("MyService"),
        ServiceCtrlHandler
    );

    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus.dwCurrentState = SERVICE_RUNNING;
    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    SetServiceStatus(serviceStatusHandle, &serviceStatus);

    // Main service loop
    while (serviceStatus.dwCurrentState == SERVICE_RUNNING) {
        Sleep(1000);
    }
}

int main() {
    SERVICE_TABLE_ENTRY serviceTable[] = {
        { (LPWSTR)L"MyService", ServiceMain },
        { NULL, NULL }
    };

    StartServiceCtrlDispatcher(serviceTable);
    return 0;
}
