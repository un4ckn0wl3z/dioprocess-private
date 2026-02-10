#include "pch.h"
#include "DioProcessGlobals.h"
#include "../Injection/EarlyInjection.h"

// ============== Process Callback ==============

VOID OnProcessCallback(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	if (CreateInfo)
	{
		KdPrint((DRIVER_PREFIX "Process (%u) Created\n", HandleToUlong(ProcessId)));

		// Check for early injection trigger (Trampoline method)
		if (CreateInfo->FileOpenNameAvailable && CreateInfo->ImageFileName)
		{
			if (EarlyInjectionMatchesTarget((PUNICODE_STRING)CreateInfo->ImageFileName))
			{
				KdPrint((DRIVER_PREFIX "Early injection target matched: %wZ (PID: %u)\n",
					CreateInfo->ImageFileName, HandleToULong(ProcessId)));

				// Only trigger if using Trampoline method
				ExAcquireFastMutex(&g_EarlyInjectionState.Lock);
				BOOLEAN armed = g_EarlyInjectionState.Armed;
				EarlyInjectionMethod method = g_EarlyInjectionState.Method;
				BOOLEAN oneShot = g_EarlyInjectionState.OneShot;
				ExReleaseFastMutex(&g_EarlyInjectionState.Lock);

				if (armed && method == EarlyInjectTrampoline)
				{
					BOOLEAN success = EarlyInjectTrampoline_Execute(Process, ProcessId);

					ExAcquireFastMutex(&g_EarlyInjectionState.Lock);
					if (success)
					{
						g_EarlyInjectionState.InjectionCount++;
						g_EarlyInjectionState.LastInjectedPid = HandleToULong(ProcessId);
						g_EarlyInjectionState.LastStatus = STATUS_SUCCESS;
						KdPrint((DRIVER_PREFIX "Early injection (Trampoline) successful for PID %u\n",
							HandleToULong(ProcessId)));

						if (oneShot)
						{
							g_EarlyInjectionState.Armed = FALSE;
							KdPrint((DRIVER_PREFIX "One-shot mode: early injection disarmed\n"));
						}
					}
					else
					{
						g_EarlyInjectionState.LastStatus = STATUS_UNSUCCESSFUL;
						KdPrint((DRIVER_PREFIX "Early injection (Trampoline) failed for PID %u\n",
							HandleToULong(ProcessId)));
					}
					ExReleaseFastMutex(&g_EarlyInjectionState.Lock);
				}
			}
		}
		auto commandLineLength = 0;

		if (CreateInfo->CommandLine)
		{
			commandLineLength = CreateInfo->CommandLine->Length;
		}
		auto size = sizeof(FullEventData) + commandLineLength;
		auto item = (FullEventData*)ExAllocatePool2(
			POOL_FLAG_PAGED,
			size,
			DRIVER_TAG
		);

		if (item == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Out of memory\n"));
			return;
		}

		auto& header = item->Data.Header;
		KeQuerySystemTimePrecise((PLARGE_INTEGER)&header.Timestamp);
		header.Size = sizeof(EventHeader) + sizeof(ProcessCreateInfo) + commandLineLength;
		header.Type = EventType::ProcessCreate;

		auto& data = item->Data.ProcessCreate;
		data.ProcessId = HandleToULong(ProcessId);
		data.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
		data.CreatingProcessId = HandleToULong(CreateInfo->CreatingThreadId.UniqueProcess);
		data.CommandLineLength = commandLineLength / sizeof(WCHAR);
		if (commandLineLength)
		{
			memcpy(data.CommandLine, CreateInfo->CommandLine->Buffer, commandLineLength);
		}

		AddItem(item);
	}
	else
	{
		KdPrint((DRIVER_PREFIX "Process (%u) Exited\n", HandleToUlong(ProcessId)));
		auto size = sizeof(FullEventData);
		auto item = (FullEventData*)ExAllocatePool2(
			POOL_FLAG_PAGED | POOL_FLAG_UNINITIALIZED,
			size,
			DRIVER_TAG
		);

		if (item == nullptr)
		{
			KdPrint((DRIVER_PREFIX "Out of memory\n"));
			return;
		}
		auto& header = item->Data.Header;
		KeQuerySystemTimePrecise((PLARGE_INTEGER)&header.Timestamp);
		header.Size = sizeof(EventHeader) + sizeof(ProcessExitInfo);
		header.Type = EventType::ProcessExit;

		auto& data = item->Data.ProcessExit;
		data.ProcessId = HandleToULong(ProcessId);
		data.ExitCode = PsGetProcessExitStatus(Process);

		AddItem(item);
	}
}
