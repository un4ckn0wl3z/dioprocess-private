@echo off
REM QEMU launch script for DioProcess OVMF with SMM support

set SCRIPT_DIR=%~dp0
set QEMU="C:\Program Files\qemu\qemu-system-x86_64.exe"
set MACHINE_CONFIG=-m 8096 -smp 4,sockets=1,cores=2,threads=2

set OVMF_CODE=-drive if=pflash,format=raw,unit=0,file=%SCRIPT_DIR%OVMF_CODE.fd,readonly=on
set OVMF_VARS=-drive if=pflash,format=raw,unit=1,file=%SCRIPT_DIR%OVMF_VARS.fd

set WIN_ISO=D:\AICoding\en-us_windows_10_consumer_editions_version_22h2_updated_oct_2025_x64_dvd_38efd00d.iso
set WIN_DISK=%SCRIPT_DIR%windows10.qcow2
set SERIAL_LOG=%SCRIPT_DIR%serial.log

echo Starting QEMU with DioProcess SMM firmware...
echo OVMF_CODE: %SCRIPT_DIR%OVMF_CODE.fd
echo Windows ISO: %WIN_ISO%
echo Windows Disk: %WIN_DISK%
echo.
echo Serial output saved to: %SERIAL_LOG%
echo.

%QEMU% %MACHINE_CONFIG% -machine q35,smm=on,accel=tcg ^
  -global driver=cfi.pflash01,property=secure,value=on ^
  %OVMF_CODE% %OVMF_VARS% ^
  -device ahci,id=ahci ^
  -drive file="%WIN_DISK%",format=qcow2,if=none,id=disk0 ^
  -device ide-hd,drive=disk0,bus=ahci.0 ^
  -cdrom "%WIN_ISO%" ^
  -boot d ^
  -device VGA ^
  -device usb-ehci,id=usbctrl -device usb-kbd -device usb-tablet ^
  -global ICH9-LPC.disable_s3=1 ^
  -chardev file,id=serf,path=%SERIAL_LOG% ^
  -serial chardev:serf
