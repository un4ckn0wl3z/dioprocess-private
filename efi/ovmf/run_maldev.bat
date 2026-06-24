@echo off
REM QEMU launch script for Maldev-Academy VM with SMM support
REM Uses TCG emulation (slower but supports SMM)

set SCRIPT_DIR=%~dp0
set QEMU="C:\Program Files\qemu\qemu-system-x86_64.exe"
set MACHINE_CONFIG=-m 8096 -smp 8,cores=8

set OVMF_CODE=%SCRIPT_DIR%OVMF_CODE.fd
set OVMF_VARS=%SCRIPT_DIR%OVMF_VARS.fd
set WIN_DISK=%SCRIPT_DIR%maldev.qcow2
set SERIAL_LOG=%SCRIPT_DIR%serial_maldev.log
set SHARE_FOLDER=D:\AICoding\dioprocess

echo =====================================================
echo   QEMU with TCG + OVMF + SMM (Maldev-Academy VM)
echo =====================================================
echo.
echo OVMF Code: %OVMF_CODE%
echo OVMF Vars: %OVMF_VARS%
echo VM Disk: %WIN_DISK%
echo Serial Log: %SERIAL_LOG%
echo Shared Folder: %SHARE_FOLDER%
echo.
echo In VM, access shared folder via: \\10.0.2.4\qemu
echo.

%QEMU% %MACHINE_CONFIG% -accel tcg,thread=multi -machine q35,smm=on ^
  -global driver=cfi.pflash01,property=secure,value=on ^
  -drive if=pflash,format=raw,unit=0,file="%OVMF_CODE%",readonly=on ^
  -drive if=pflash,format=raw,unit=1,file="%OVMF_VARS%" ^
  -global ICH9-LPC.disable_s3=1 ^
  -drive file="%WIN_DISK%",format=qcow2,id=disk0,if=none ^
  -device ahci,id=ahci ^
  -device ide-hd,drive=disk0,bus=ahci.0 ^
  -device VGA ^
  -device usb-ehci,id=usbctrl -device usb-kbd -device usb-tablet ^
  -netdev user,id=net0,smb=%SHARE_FOLDER% ^
  -device e1000,netdev=net0 ^
  -chardev file,id=serf,path=%SERIAL_LOG% ^
  -serial chardev:serf
