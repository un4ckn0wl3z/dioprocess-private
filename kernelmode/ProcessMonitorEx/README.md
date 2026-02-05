# DioProcess Kernel Driver

Windows Process/Thread Callback Monitor - Kernel Mode Driver for DioProcess.

## Features
- Real-time process creation/exit notifications via `PsSetCreateProcessNotifyRoutineEx`
- Real-time thread creation/exit notifications via `PsSetCreateThreadNotifyRoutine`
- Event delivery via `IRP_MJ_READ` with timestamps and process details

## Device
- Device Name: `\\Device\\DioProcess`
- Symbolic Link: `\\.\DioProcess`

## Build
Requires Visual Studio with Windows Driver Kit (WDK).

## Usage
```batch
:: Enable test signing (for unsigned drivers)
bcdedit /set testsigning on

:: Install and start
sc create DioProcess type= kernel binPath= "C:\path\to\DioProcess.sys"
sc start DioProcess

:: Stop and remove
sc stop DioProcess
sc delete DioProcess
```
