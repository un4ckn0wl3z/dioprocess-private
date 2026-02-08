#pragma once

#include <ntddk.h>

// ============== Hypervisor Control ==============

// Start the hypervisor (virtualize the system)
NTSTATUS HvStartHypervisor();

// Stop the hypervisor (devirtualize the system)
void HvStopHypervisor();

// Check if hypervisor is running
bool HvIsHypervisorRunning();

// ============== Protection Hooks ==============

// Install EPT hooks for process protection
NTSTATUS HvInstallProtectionHooks();

// Remove EPT hooks
void HvRemoveProtectionHooks();

// Check if hooks are installed
bool HvAreHooksInstalled();

// ============== Protected PID Management ==============

// Add a PID to the protection list
bool HvAddProtectedPid(ULONG Pid);

// Remove a PID from the protection list
bool HvRemoveProtectedPid(ULONG Pid);

// Check if a PID is protected
bool HvIsProcessProtectedByPid(ULONG Pid);

// Get the count of protected PIDs
ULONG HvGetProtectedPidCount();

// Get the list of protected PIDs
// PidBuffer: output buffer for PIDs
// BufferSize: size of buffer in bytes
// ReturnedCount: number of PIDs returned
NTSTATUS HvGetProtectedPidList(ULONG* PidBuffer, ULONG BufferSize, ULONG* ReturnedCount);

// ============== Driver Hiding ==============

// Add a driver to the hidden list
bool HvAddHiddenDriver(const char* driverName);

// Remove a driver from the hidden list
bool HvRemoveHiddenDriver(const char* driverName);

// Clear all hidden drivers
void HvClearHiddenDrivers();

// Get count of hidden drivers
ULONG HvGetHiddenDriverCount();

// Get list of hidden drivers
// buffer: output buffer (array of char[64])
// bufferSize: size of buffer in bytes
// returnedCount: number of drivers returned
NTSTATUS HvGetHiddenDriverList(char* buffer, ULONG bufferSize, ULONG* returnedCount);

// Legacy compatibility
bool HvEnableDriverHiding(const char* driverName);
void HvDisableDriverHiding();
bool HvIsDriverHidingEnabled();
