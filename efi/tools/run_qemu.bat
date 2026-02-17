@echo off
REM run_qemu.bat — Test DioProcess EFI in QEMU with OVMF
REM
REM Prerequisites:
REM   1. QEMU: https://www.qemu.org/download/#windows (or: winget install QEMU.QEMU)
REM   2. OVMF: Download from https://retrage.github.io/edk2-nightly/ or use the one bundled with QEMU
REM
REM Usage:
REM   run_qemu.bat                     # Use default paths
REM   run_qemu.bat path\to\OVMF.fd     # Custom OVMF path
REM
REM The script creates a virtual ESP with DioProcessEfi.efi and boots it.

setlocal enabledelayedexpansion

REM === Configuration ===
set SCRIPT_DIR=%~dp0
set EFI_BUILD_DIR=%SCRIPT_DIR%..\Build\DioProcessEfi\RELEASE_VS2022\X64
set EFI_FILE=%EFI_BUILD_DIR%\DioProcessEfi.efi

REM QEMU paths (adjust if needed)
set QEMU_PATH=qemu-system-x86_64.exe
set OVMF_PATH=C:\Program Files\qemu\share\edk2-x86_64-code.fd

REM Check for custom OVMF path
if not "%~1"=="" set OVMF_PATH=%~1

REM === Verify prerequisites ===
echo [*] DioProcess EFI QEMU Test Runner
echo.

REM Check QEMU
where %QEMU_PATH% >nul 2>&1
if errorlevel 1 (
    echo [-] QEMU not found in PATH
    echo     Install: winget install QEMU.QEMU
    echo     Or download from: https://www.qemu.org/download/#windows
    exit /b 1
)
echo [+] QEMU: Found

REM Check OVMF
if not exist "%OVMF_PATH%" (
    echo [-] OVMF firmware not found: %OVMF_PATH%
    echo     Download from: https://retrage.github.io/edk2-nightly/
    echo     Or specify path: run_qemu.bat path\to\OVMF.fd
    exit /b 1
)
echo [+] OVMF: %OVMF_PATH%

REM Check EFI binary
if not exist "%EFI_FILE%" (
    echo [-] DioProcessEfi.efi not found: %EFI_FILE%
    echo     Build first with:
    echo       cd efi
    echo       build -a X64 -t VS2022 -p DioProcessEfi/DioProcessEfi.dsc -b RELEASE
    exit /b 1
)
echo [+] EFI binary: %EFI_FILE%

REM === Create virtual ESP ===
set ESP_DIR=%TEMP%\dioprocess_esp
set ESP_IMG=%TEMP%\dioprocess_esp.img

echo.
echo [*] Creating virtual ESP...

REM Clean previous
if exist "%ESP_DIR%" rmdir /s /q "%ESP_DIR%"
mkdir "%ESP_DIR%\EFI\BOOT"

REM Copy EFI as bootx64.efi (UEFI default boot path)
copy "%EFI_FILE%" "%ESP_DIR%\EFI\BOOT\bootx64.efi" >nul
echo [+] Copied to EFI\BOOT\bootx64.efi

REM Create FAT32 image (32MB)
echo [*] Creating FAT32 disk image...

REM Use PowerShell to create the image
powershell -Command ^
    "$size = 32MB; " ^
    "$path = '%ESP_IMG%'; " ^
    "$fs = [System.IO.File]::Create($path); " ^
    "$fs.SetLength($size); " ^
    "$fs.Close(); " ^
    "Write-Host '[+] Created 32MB image'"

REM Format as FAT32 using diskpart would require admin, so we use QEMU's vvfat instead
echo [+] Using QEMU vvfat for ESP directory

REM === Run QEMU ===
echo.
echo [*] Starting QEMU...
echo     Resolution: 1024x768
echo     Memory: 512MB
echo.
echo     Controls:
echo       Ctrl+Alt+G    = Release mouse grab
echo       Ctrl+Alt+F    = Toggle fullscreen  
echo       Ctrl+Alt+Q    = Quit QEMU
echo.
echo ============================================================

%QEMU_PATH% ^
    -machine q35 ^
    -m 512M ^
    -cpu qemu64 ^
    -bios "%OVMF_PATH%" ^
    -drive if=virtio,format=raw,file=fat:rw:%ESP_DIR% ^
    -device VGA,vgamem_mb=64 ^
    -serial stdio ^
    -boot menu=on

echo.
echo [*] QEMU exited

REM Cleanup
rmdir /s /q "%ESP_DIR%" 2>nul
del "%ESP_IMG%" 2>nul

endlocal
