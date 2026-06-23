@echo off
REM QEMU launch script with WHPX acceleration (FAST - no SMM)
REM Use this for Windows installation or general testing
REM SMM features will NOT work with WHPX

set SCRIPT_DIR=%~dp0
set QEMU="C:\Program Files\qemu\qemu-system-x86_64.exe"
set MACHINE_CONFIG=-m 8096 -smp 4,cores=4

set OVMF_CODE=-drive if=pflash,format=raw,unit=0,file=%SCRIPT_DIR%OVMF_CODE.fd,readonly=on
set OVMF_VARS=-drive if=pflash,format=raw,unit=1,file=%SCRIPT_DIR%OVMF_VARS.fd

set WIN_ISO=D:\AICoding\en-us_windows_10_consumer_editions_version_22h2_updated_oct_2025_x64_dvd_38efd00d.iso
set WIN_DISK=%SCRIPT_DIR%windows10.qcow2
set SERIAL_LOG=%SCRIPT_DIR%serial_fast.log

echo =====================================================
echo   QEMU with WHPX Acceleration (FAST MODE)
echo =====================================================
echo.
echo WARNING: SMM features will NOT work in this mode!
echo Use run_qemu.bat for SMM testing (slower).
echo.
echo OVMF_CODE: %SCRIPT_DIR%OVMF_CODE.fd
echo Windows ISO: %WIN_ISO%
echo Windows Disk: %WIN_DISK%
echo.

%QEMU% %MACHINE_CONFIG% -machine q35,accel=whpx ^
  %OVMF_CODE% %OVMF_VARS% ^
  -device ahci,id=ahci ^
  -drive file="%WIN_DISK%",format=qcow2,if=none,id=disk0 ^
  -device ide-hd,drive=disk0,bus=ahci.0 ^
  -cdrom "%WIN_ISO%" ^
  -boot d ^
  -device VGA ^
  -device usb-ehci,id=usbctrl -device usb-kbd -device usb-tablet ^
  -chardev file,id=serf,path=%SERIAL_LOG% ^
  -serial chardev:serf
