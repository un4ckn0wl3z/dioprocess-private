@echo off
REM Build script for TCP test tools
REM Requires Visual Studio with C++ support

echo === Building TCP Test Tools ===
echo.

REM Check if cl.exe is available
where cl >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] cl.exe not found. Please run from Developer Command Prompt
    echo     or run: "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    exit /b 1
)

echo [*] Compiling tcp_server.cpp...
cl /nologo /EHsc /O2 tcp_server.cpp /Fe:tcp_server.exe /link ws2_32.lib
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to compile tcp_server.cpp
    exit /b 1
)
echo [+] tcp_server.exe built successfully

echo.
echo [*] Compiling tcp_client.cpp...
cl /nologo /EHsc /O2 tcp_client.cpp /Fe:tcp_client.exe /link ws2_32.lib
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to compile tcp_client.cpp
    exit /b 1
)
echo [+] tcp_client.exe built successfully

echo.
echo === Build Complete ===
echo.
echo Usage:
echo   1. Start server:  tcp_server.exe [port]
echo   2. Start client:  tcp_client.exe [host] [port]
echo   3. Use DioProcess Packet Capture tab with the server/client PID
echo.
