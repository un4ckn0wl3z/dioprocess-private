@echo off
setlocal EnableExtensions

REM ===== Configuration =====
set "SOLUTION=DioProcess.sln"
set "CONFIG=Debug"
set "PLATFORM=x64"

REM ===== Check environment =====
where msbuild >nul 2>&1
if errorlevel 1 (
    echo [!] msbuild not found
    echo [!] Run from: x64 Native Tools Command Prompt for VS
    exit /b 1
)

if not exist "%SOLUTION%" (
    echo [!] Solution not found: %SOLUTION%
    exit /b 1
)

REM ===== Clean =====
echo [*] Cleaning %SOLUTION% - %CONFIG% %PLATFORM%
msbuild "%SOLUTION%" /t:Clean /p:Configuration=%CONFIG% /p:Platform=%PLATFORM%
if errorlevel 1 (
    echo [!] Clean FAILED
    exit /b 1
)

REM ===== Build =====
echo [*] Building %SOLUTION% - %CONFIG% %PLATFORM%
msbuild "%SOLUTION%" /t:Build /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /m /verbosity:minimal
if errorlevel 1 (
    echo [!] Build FAILED
    exit /b 1
)

echo [+] Clean build SUCCESS
endlocal
