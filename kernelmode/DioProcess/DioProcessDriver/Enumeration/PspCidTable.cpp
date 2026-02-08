#include "pch.h"
#include "DioProcessGlobals.h"

// ============== PspCidTable Enumeration ==============

// Find PspCidTable address dynamically via signature scanning
PVOID64 GetPspCidTableAddress()
{
	// Get PsLookupProcessByProcessId address
	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, L"PsLookupProcessByProcessId");
	PUCHAR funcAddr = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
	if (!funcAddr)
	{
		KdPrint((DRIVER_PREFIX "Failed to get PsLookupProcessByProcessId address\n"));
		return NULL;
	}

	// Search for CALL instruction (0xE8) in first 100 bytes
	// This calls PspReferenceCidTableEntry
	PUCHAR callSite = NULL;
	for (INT i = 0; i < 100; i++)
	{
		if (funcAddr[i] == 0xE8)
		{
			callSite = funcAddr + i;
			break;
		}
	}

	if (!callSite)
	{
		KdPrint((DRIVER_PREFIX "Failed to find CALL to PspReferenceCidTableEntry\n"));
		return NULL;
	}

	// Parse CALL offset and calculate target address
	INT callOffset = *(INT*)(callSite + 1);
	PUCHAR pspRefCidEntry = callSite + callOffset + 5;

	// Inside PspReferenceCidTableEntry, search for "MOV rcx, [PspCidTable]"
	// Pattern: 48 8B 0D ?? ?? ?? ??
	for (INT i = 0; i < 0x120; i++)
	{
		if (pspRefCidEntry[i] == 0x48 &&
			pspRefCidEntry[i + 1] == 0x8B &&
			pspRefCidEntry[i + 2] == 0x0D)
		{
			// Parse MOV offset
			INT movOffset = *(INT*)(pspRefCidEntry + i + 3);
			PVOID64 pspCidTableAddr = (PVOID64)(pspRefCidEntry + i + movOffset + 7);

			KdPrint((DRIVER_PREFIX "Found PspCidTable at: %p\n", pspCidTableAddr));
			return pspCidTableAddr;
		}
	}

	KdPrint((DRIVER_PREFIX "Failed to find PspCidTable reference\n"));
	return NULL;
}

// Decrypt handle table entry (Windows 10/11)
ULONG64 DecryptCidEntry(ULONG64 encryptedValue)
{
	// Decryption: (value >> 0x10) & 0xFFFFFFFFFFFFFFF0
	ULONG64 decrypted = (LONG64)encryptedValue >> 0x10;
	decrypted &= 0xFFFFFFFFFFFFFFF0;
	return decrypted;
}

// Parse level-1 table (stores actual EPROCESS/ETHREAD entries)
VOID ParseCidTable1(ULONG64 baseAddr, INT index1, INT index2, CidEntry* entries, ULONG* count, ULONG maxEntries)
{
	PEPROCESS eProcess = NULL;
	PETHREAD eThread = NULL;
	WINDOWS_VERSION winVersion = GetWindowsVersion();

	// Each entry is 16 bytes, 256 entries per table
	for (INT i = 0; i < 256 && *count < maxEntries; i++)
	{
		ULONG64 entryAddr = baseAddr + (i * 16);

		__try
		{
			if (!MmIsAddressValid((PVOID)entryAddr))
				continue;

			ULONG64 encryptedValue = *(PULONG64)entryAddr;
			if (encryptedValue == 0)
				continue;

			// Decrypt entry
			ULONG64 objectAddr = DecryptCidEntry(encryptedValue);
			if (!MmIsAddressValid((PVOID)objectAddr))
				continue;

			// Calculate ID: i * 4 + 1024 * index1 + 512 * 1024 * index2
			ULONG id = i * 4 + 1024 * index1 + 512 * 1024 * index2;

			// Determine if it's a process or thread
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)id, &eProcess)))
			{
				entries[*count].Id = id;
				entries[*count].ObjectAddress = objectAddr;
				entries[*count].Type = CidObjectType::CidProcess;

				// Extract parent PID (InheritedFromUniqueProcessId)
				if (winVersion != WINDOWS_UNSUPPORTED)
				{
					ULONG64 parentPidAddr = objectAddr + EPROCESS_PARENTPID_OFFSET[winVersion];
					if (MmIsAddressValid((PVOID)parentPidAddr))
					{
						entries[*count].ParentPid = *(PULONG)parentPidAddr;
					}
					else
					{
						entries[*count].ParentPid = 0;
					}

					// Extract process name (ImageFileName)
					ULONG64 nameAddr = objectAddr + EPROCESS_IMAGEFILENAME_OFFSET[winVersion];
					if (MmIsAddressValid((PVOID)nameAddr))
					{
						RtlCopyMemory(entries[*count].ProcessName, (PVOID)nameAddr, MAX_PROCESS_NAME_LENGTH - 1);
						entries[*count].ProcessName[MAX_PROCESS_NAME_LENGTH - 1] = '\0';  // Ensure null termination
					}
					else
					{
						entries[*count].ProcessName[0] = '\0';
					}
				}
				else
				{
					entries[*count].ParentPid = 0;
					entries[*count].ProcessName[0] = '\0';
				}

				(*count)++;
				ObDereferenceObject(eProcess);
			}
			else if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)id, &eThread)))
			{
				entries[*count].Id = id;
				entries[*count].ObjectAddress = objectAddr;
				entries[*count].Type = CidObjectType::CidThread;

				// Extract owning process PID (Cid.UniqueProcess in ETHREAD)
				if (winVersion != WINDOWS_UNSUPPORTED)
				{
					ULONG64 cidAddr = objectAddr + ETHREAD_CID_OFFSET[winVersion];
					if (MmIsAddressValid((PVOID)cidAddr))
					{
						// Cid.UniqueProcess is the first field of CLIENT_ID
						entries[*count].ParentPid = *(PULONG)cidAddr;

						// Try to get process name from the owning EPROCESS
						PEPROCESS ownerProcess = NULL;
						if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)entries[*count].ParentPid, &ownerProcess)))
						{
							ULONG64 ownerNameAddr = (ULONG64)ownerProcess + EPROCESS_IMAGEFILENAME_OFFSET[winVersion];
							if (MmIsAddressValid((PVOID)ownerNameAddr))
							{
								RtlCopyMemory(entries[*count].ProcessName, (PVOID)ownerNameAddr, MAX_PROCESS_NAME_LENGTH - 1);
								entries[*count].ProcessName[MAX_PROCESS_NAME_LENGTH - 1] = '\0';
							}
							else
							{
								entries[*count].ProcessName[0] = '\0';
							}
							ObDereferenceObject(ownerProcess);
						}
						else
						{
							entries[*count].ProcessName[0] = '\0';
						}
					}
					else
					{
						entries[*count].ParentPid = 0;
						entries[*count].ProcessName[0] = '\0';
					}
				}
				else
				{
					entries[*count].ParentPid = 0;
					entries[*count].ProcessName[0] = '\0';
				}

				(*count)++;
				ObDereferenceObject(eThread);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			continue;
		}
	}
}

// Parse level-2 table (stores pointers to level-1 tables)
VOID ParseCidTable2(ULONG64 baseAddr, INT index2, CidEntry* entries, ULONG* count, ULONG maxEntries)
{
	// Each entry is 8 bytes (pointer), 512 entries per table
	for (INT i = 0; i < 512 && *count < maxEntries; i++)
	{
		__try
		{
			ULONG64 ptrAddr = baseAddr + (i * 8);
			if (!MmIsAddressValid((PVOID)ptrAddr))
				continue;

			ULONG64 table1Addr = *(PULONG64)ptrAddr;
			if (!MmIsAddressValid((PVOID)table1Addr))
				continue;

			ParseCidTable1(table1Addr, i, index2, entries, count, maxEntries);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			continue;
		}
	}
}

// Parse level-3 table (stores pointers to level-2 tables)
VOID ParseCidTable3(ULONG64 baseAddr, CidEntry* entries, ULONG* count, ULONG maxEntries)
{
	// Each entry is 8 bytes (pointer), 512 entries per table
	for (INT i = 0; i < 512 && *count < maxEntries; i++)
	{
		__try
		{
			ULONG64 ptrAddr = baseAddr + (i * 8);
			if (!MmIsAddressValid((PVOID)ptrAddr))
				continue;

			ULONG64 table2Addr = *(PULONG64)ptrAddr;
			if (!MmIsAddressValid((PVOID)table2Addr))
				continue;

			ParseCidTable2(table2Addr, i, entries, count, maxEntries);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			continue;
		}
	}
}
