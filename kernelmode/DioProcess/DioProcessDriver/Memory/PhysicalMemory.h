#pragma once

#include "../pch.h"
#include "../DioProcessCommon.h"

/* Page Table Constants */
#define PTE_PRESENT      0x1ULL
#define PTE_READWRITE    0x2ULL
#define PTE_USER         0x4ULL
#define PTE_WRITETHROUGH 0x8ULL
#define PTE_CACHEDISABLE 0x10ULL
#define PTE_ACCESSED     0x20ULL
#define PTE_DIRTY        0x40ULL
#define PTE_LARGE_PAGE   0x80ULL
#define PTE_GLOBAL       0x100ULL
#define PTE_NX           0x8000000000000000ULL
#define PTE_PHYS_MASK    0x0000FFFFFFFFF000ULL
#define PAGE_OFFSET_MASK 0xFFFULL

/* Get CR3 for a process by attaching and reading the hardware register */
ULONG64 PhysMemGetProcessCR3(ULONG ProcessId);

/* Read physical memory using MmCopyMemory */
NTSTATUS PhysMemReadPhysical(ULONG64 PhysAddr, PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead);

/* Write physical memory using MmMapIoSpace */
NTSTATUS PhysMemWritePhysical(ULONG64 PhysAddr, PVOID Buffer, SIZE_T Size, PSIZE_T BytesWritten);

/* Walk 4-level page table and fill TranslateVaResponse */
NTSTATUS PhysMemTranslateVA(ULONG64 Cr3, ULONG64 VirtualAddress, TranslateVaResponse* Response);

/* Decode PTE bits into PageTableEntryResult */
void PhysMemDecodePte(ULONG64 RawPte, ULONG64 EntryVirtualAddr, PageTableEntryResult* Result);

/* Bulk read virtual memory via CR3 page table walk.
   Translates each page VA->PA and reads physical memory.
   Handles page boundaries and unmapped pages (fills zeros). */
NTSTATUS PhysMemReadVirtualMemory(ULONG ProcessId, ULONG64 VirtualAddress, PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead);

/* Enumerate virtual memory regions in a target process via ZwQueryVirtualMemory.
   Attaches to the process context, enumerates all VA regions, then detaches.
   No OpenProcess / PROCESS_QUERY_INFORMATION handle required. */
NTSTATUS PhysMemEnumVmRegions(ULONG ProcessId, VmRegionEntry* Entries, ULONG MaxEntries, PULONG Count);
