@echo off
REM Build script for Network Test Tools
REM Requires Visual Studio with C++ support

echo === Building Network Test Tools ===
echo.

REM Check if cl.exe is available
where cl >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] cl.exe not found. Please run from Developer Command Prompt
    echo     or run: "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    exit /b 1
)

REM Create output directory
if not exist "bin" mkdir bin

echo [*] Compiling tcp_server.cpp...
cl /nologo /EHsc /O2 /Fe:bin\tcp_server.exe tcp_server.cpp /link ws2_32.lib
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to compile tcp_server.cpp
    exit /b 1
)
echo [+] tcp_server.exe built successfully

echo [*] Compiling tcp_client.cpp...
cl /nologo /EHsc /O2 /Fe:bin\tcp_client.exe tcp_client.cpp /link ws2_32.lib
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to compile tcp_client.cpp
    exit /b 1
)
echo [+] tcp_client.exe built successfully

echo [*] Compiling udp_server.cpp...
cl /nologo /EHsc /O2 /Fe:bin\udp_server.exe udp_server.cpp /link ws2_32.lib
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to compile udp_server.cpp
    exit /b 1
)
echo [+] udp_server.exe built successfully

echo [*] Compiling udp_client.cpp...
cl /nologo /EHsc /O2 /Fe:bin\udp_client.exe udp_client.cpp /link ws2_32.lib
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to compile udp_client.cpp
    exit /b 1
)
echo [+] udp_client.exe built successfully

echo [*] Compiling tcp_server_multi.cpp...
cl /nologo /EHsc /O2 /Fe:bin\tcp_server_multi.exe tcp_server_multi.cpp /link ws2_32.lib
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to compile tcp_server_multi.cpp
    exit /b 1
)
echo [+] tcp_server_multi.exe built successfully

echo.
echo === Build Complete ===
echo.
echo Usage:
echo   TCP (single client):   bin\tcp_server.exe [port]
echo   TCP (multi client):    bin\tcp_server_multi.exe [port]  ^<-- Use this for resend testing
echo   TCP client:            bin\tcp_client.exe [host] [port]
echo   UDP server:            bin\udp_server.exe [port]
echo   UDP client:            bin\udp_client.exe [host] [port]
echo.
