/** @file
  PE parsing utilities implementation.
**/

#include "PeUtils.h"
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

#define MZ_SIGNATURE 0x5A4D

BOOLEAN
PeValidateImage(
    IN VOID *ImageBase
    )
{
    PE_DOS_HEADER   *DosHeader;
    PE_NT_HEADERS64 *NtHeaders;

    if (ImageBase == NULL) {
        return FALSE;
    }

    DosHeader = (PE_DOS_HEADER *)ImageBase;
    if (DosHeader->e_magic != MZ_SIGNATURE) {
        return FALSE;
    }

    NtHeaders = (PE_NT_HEADERS64 *)((UINT8 *)ImageBase + DosHeader->e_lfanew);
    if (NtHeaders->Signature != PE_SIGNATURE) {
        return FALSE;
    }

    if (NtHeaders->FileHeader.Machine != PE_MACHINE_AMD64) {
        return FALSE;
    }

    if (NtHeaders->OptionalHeader.Magic != PE_OPT_MAGIC_PE32P) {
        return FALSE;
    }

    return TRUE;
}

PE_NT_HEADERS64 *
PeGetNtHeaders(
    IN VOID *ImageBase
    )
{
    PE_DOS_HEADER *DosHeader;

    if (!PeValidateImage(ImageBase)) {
        return NULL;
    }

    DosHeader = (PE_DOS_HEADER *)ImageBase;
    return (PE_NT_HEADERS64 *)((UINT8 *)ImageBase + DosHeader->e_lfanew);
}

PE_SECTION_HEADER *
PeFindSection(
    IN VOID       *ImageBase,
    IN CONST CHAR8 *SectionName
    )
{
    PE_NT_HEADERS64   *NtHeaders;
    PE_SECTION_HEADER *Section;
    UINT16             NumSections;
    UINT16             i;

    NtHeaders = PeGetNtHeaders(ImageBase);
    if (NtHeaders == NULL) {
        return NULL;
    }

    NumSections = NtHeaders->FileHeader.NumberOfSections;
    Section = (PE_SECTION_HEADER *)(
        (UINT8 *)&NtHeaders->OptionalHeader +
        NtHeaders->FileHeader.SizeOfOptionalHeader
    );

    for (i = 0; i < NumSections; i++) {
        if (CompareMem(Section[i].Name, SectionName, AsciiStrLen(SectionName)) == 0) {
            return &Section[i];
        }
    }

    return NULL;
}

EFI_STATUS
PeGetTextSection(
    IN  VOID  *ImageBase,
    OUT VOID  **TextBase,
    OUT UINTN *TextSize
    )
{
    PE_SECTION_HEADER *Section;

    Section = PeFindSection(ImageBase, ".text");
    if (Section == NULL) {
        return EFI_NOT_FOUND;
    }

    *TextBase = (UINT8 *)ImageBase + Section->VirtualAddress;
    *TextSize = Section->VirtualSize;

    return EFI_SUCCESS;
}

UINTN
PeGetImageSize(
    IN VOID *ImageBase
    )
{
    PE_NT_HEADERS64 *NtHeaders;

    NtHeaders = PeGetNtHeaders(ImageBase);
    if (NtHeaders == NULL) {
        return 0;
    }

    return (UINTN)NtHeaders->OptionalHeader.SizeOfImage;
}

VOID *
PeFindExport(
    IN VOID        *ImageBase,
    IN CONST CHAR8 *FuncName
    )
{
    PE_NT_HEADERS64    *NtHeaders;
    PE_DATA_DIRECTORY  *DataDirs;
    PE_EXPORT_DIRECTORY *ExportDir;
    UINT32             *NameRvas;
    UINT16             *Ordinals;
    UINT32             *FuncRvas;
    UINT32              NumNames;
    UINT32              i;
    UINTN               FuncNameLen;

    NtHeaders = PeGetNtHeaders(ImageBase);
    if (NtHeaders == NULL) {
        return NULL;
    }

    if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes <= PE_DIRECTORY_ENTRY_EXPORT) {
        return NULL;
    }

    DataDirs = (PE_DATA_DIRECTORY *)(
        (UINT8 *)&NtHeaders->OptionalHeader.NumberOfRvaAndSizes + sizeof(UINT32)
    );

    if (DataDirs[PE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
        DataDirs[PE_DIRECTORY_ENTRY_EXPORT].Size == 0) {
        return NULL;
    }

    ExportDir = (PE_EXPORT_DIRECTORY *)(
        (UINT8 *)ImageBase + DataDirs[PE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    NumNames  = ExportDir->NumberOfNames;
    NameRvas  = (UINT32 *)((UINT8 *)ImageBase + ExportDir->AddressOfNames);
    Ordinals  = (UINT16 *)((UINT8 *)ImageBase + ExportDir->AddressOfNameOrdinals);
    FuncRvas  = (UINT32 *)((UINT8 *)ImageBase + ExportDir->AddressOfFunctions);

    FuncNameLen = AsciiStrLen(FuncName);

    for (i = 0; i < NumNames; i++) {
        CONST CHAR8 *Name = (CONST CHAR8 *)((UINT8 *)ImageBase + NameRvas[i]);
        if (AsciiStrLen(Name) == FuncNameLen &&
            CompareMem(Name, FuncName, FuncNameLen) == 0) {
            UINT16 Ordinal = Ordinals[i];
            UINT32 FuncRva = FuncRvas[Ordinal];
            return (VOID *)((UINT8 *)ImageBase + FuncRva);
        }
    }

    return NULL;
}

//
// Case-insensitive ASCII helpers
//
STATIC
CHAR8
AsciiToLower(
    IN CHAR8 C
    )
{
    if (C >= 'A' && C <= 'Z') return (CHAR8)(C + ('a' - 'A'));
    return C;
}

STATIC
BOOLEAN
DioAsciiStriEq(
    IN CONST CHAR8 *A,
    IN CONST CHAR8 *B
    )
{
    while (*A && *B) {
        if (AsciiToLower(*A) != AsciiToLower(*B)) return FALSE;
        A++;
        B++;
    }
    return (*A == '\0' && *B == '\0');
}

VOID *
PeFindIATEntry(
    IN VOID        *ImageBase,
    IN CONST CHAR8 *DllName,
    IN CONST CHAR8 *FuncName
    )
{
    PE_NT_HEADERS64      *NtHeaders;
    PE_DATA_DIRECTORY    *DataDirs;
    PE_IMPORT_DESCRIPTOR *ImportDesc;
    UINTN                 FuncNameLen;

    NtHeaders = PeGetNtHeaders(ImageBase);
    if (NtHeaders == NULL) return NULL;

    if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes <= PE_DIRECTORY_ENTRY_IMPORT)
        return NULL;

    DataDirs = (PE_DATA_DIRECTORY *)(
        (UINT8 *)&NtHeaders->OptionalHeader.NumberOfRvaAndSizes + sizeof(UINT32)
    );

    if (DataDirs[PE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
        DataDirs[PE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
        return NULL;
    }

    ImportDesc = (PE_IMPORT_DESCRIPTOR *)(
        (UINT8 *)ImageBase + DataDirs[PE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
    );

    FuncNameLen = AsciiStrLen(FuncName);

    // Walk import descriptors (terminated by all-zero entry)
    while (ImportDesc->Name != 0) {
        CONST CHAR8 *ImportDllName = (CONST CHAR8 *)((UINT8 *)ImageBase + ImportDesc->Name);

        if (DioAsciiStriEq(ImportDllName, DllName)) {
            // Found the DLL. Walk the Import Name Table (INT) to find the function.
            UINT32 IntRva = ImportDesc->OriginalFirstThunk;
            UINT32 IatRva = ImportDesc->FirstThunk;
            UINT64 *IntEntry;
            UINT64 *IatEntry;
            UINTN   Idx;

            // If OriginalFirstThunk is 0, use FirstThunk (unbound imports)
            if (IntRva == 0) IntRva = IatRva;

            IntEntry = (UINT64 *)((UINT8 *)ImageBase + IntRva);
            IatEntry = (UINT64 *)((UINT8 *)ImageBase + IatRva);

            for (Idx = 0; IntEntry[Idx] != 0; Idx++) {
                PE_IMPORT_BY_NAME *ImportByName;
                UINT32 NameRva;

                // Skip ordinal imports (bit 63 set)
                if (IntEntry[Idx] & PE_IMAGE_ORDINAL_FLAG64) continue;

                // RVA to PE_IMPORT_BY_NAME
                NameRva = (UINT32)(IntEntry[Idx] & 0x7FFFFFFF);
                ImportByName = (PE_IMPORT_BY_NAME *)(
                    (UINT8 *)ImageBase + NameRva
                );

                if (AsciiStrLen(ImportByName->Name) == FuncNameLen &&
                    CompareMem(ImportByName->Name, FuncName, FuncNameLen) == 0) {
                    // Return the ADDRESS of the IAT slot (not its value)
                    return (VOID *)&IatEntry[Idx];
                }
            }
        }

        ImportDesc++;
    }

    return NULL;
}

VOID *
PeFindFunctionStart(
    IN VOID *ImageBase,
    IN VOID *Address
    )
{
    PE_NT_HEADERS64     *NtHeaders;
    PE_DATA_DIRECTORY   *DataDirs;
    PE_RUNTIME_FUNCTION *FuncTable;
    UINTN                NumEntries;
    UINT32               TargetRva;
    UINTN                Low, High;

    NtHeaders = PeGetNtHeaders(ImageBase);
    if (NtHeaders == NULL) return NULL;

    if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes <= PE_DIRECTORY_ENTRY_EXCEPTION)
        return NULL;

    DataDirs = (PE_DATA_DIRECTORY *)(
        (UINT8 *)&NtHeaders->OptionalHeader.NumberOfRvaAndSizes + sizeof(UINT32)
    );

    if (DataDirs[PE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress == 0 ||
        DataDirs[PE_DIRECTORY_ENTRY_EXCEPTION].Size == 0) {
        return NULL;
    }

    FuncTable = (PE_RUNTIME_FUNCTION *)(
        (UINT8 *)ImageBase + DataDirs[PE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress
    );
    NumEntries = DataDirs[PE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(PE_RUNTIME_FUNCTION);

    TargetRva = (UINT32)((UINT8 *)Address - (UINT8 *)ImageBase);

    // Binary search (RUNTIME_FUNCTION table is sorted by BeginAddress)
    Low = 0;
    High = NumEntries;
    while (Low < High) {
        UINTN Mid = (Low + High) / 2;
        if (FuncTable[Mid].EndAddress <= TargetRva) {
            Low = Mid + 1;
        } else if (FuncTable[Mid].BeginAddress > TargetRva) {
            High = Mid;
        } else {
            // Found: BeginAddress <= TargetRva < EndAddress
            return (UINT8 *)ImageBase + FuncTable[Mid].BeginAddress;
        }
    }

    return NULL;
}
