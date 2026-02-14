/** @file
  PE parsing utilities for scanning loaded Windows boot images.

  Provides helpers to find PE image bases in memory, locate sections,
  and resolve addresses within loaded PE files.
**/

#ifndef DIOPROCESS_PE_UTILS_H_
#define DIOPROCESS_PE_UTILS_H_

#include <Uefi.h>

//
// PE32+ structures (subset needed for boot-time parsing)
//
#pragma pack(push, 1)

#define PE_SIGNATURE        0x00004550  // "PE\0\0"
#define PE_MACHINE_AMD64    0x8664
#define PE_OPT_MAGIC_PE32P  0x020B      // PE32+ (64-bit)

typedef struct _PE_DOS_HEADER {
    UINT16 e_magic;     // MZ signature (0x5A4D)
    UINT8  _pad[58];    // DOS header fields we don't need
    UINT32 e_lfanew;    // Offset to PE signature
} PE_DOS_HEADER;

typedef struct _PE_FILE_HEADER {
    UINT16 Machine;
    UINT16 NumberOfSections;
    UINT32 TimeDateStamp;
    UINT32 PointerToSymbolTable;
    UINT32 NumberOfSymbols;
    UINT16 SizeOfOptionalHeader;
    UINT16 Characteristics;
} PE_FILE_HEADER;

typedef struct _PE_OPTIONAL_HEADER64 {
    UINT16 Magic;
    UINT8  MajorLinkerVersion;
    UINT8  MinorLinkerVersion;
    UINT32 SizeOfCode;
    UINT32 SizeOfInitializedData;
    UINT32 SizeOfUninitializedData;
    UINT32 AddressOfEntryPoint;
    UINT32 BaseOfCode;
    UINT64 ImageBase;
    UINT32 SectionAlignment;
    UINT32 FileAlignment;
    UINT16 MajorOperatingSystemVersion;
    UINT16 MinorOperatingSystemVersion;
    UINT16 MajorImageVersion;
    UINT16 MinorImageVersion;
    UINT16 MajorSubsystemVersion;
    UINT16 MinorSubsystemVersion;
    UINT32 Win32VersionValue;
    UINT32 SizeOfImage;
    UINT32 SizeOfHeaders;
    UINT32 CheckSum;
    UINT16 Subsystem;
    UINT16 DllCharacteristics;
    UINT64 SizeOfStackReserve;
    UINT64 SizeOfStackCommit;
    UINT64 SizeOfHeapReserve;
    UINT64 SizeOfHeapCommit;
    UINT32 LoaderFlags;
    UINT32 NumberOfRvaAndSizes;
    // Data directories follow (accessed via PeGetDataDirectory)
} PE_OPTIONAL_HEADER64;

#define PE_DIRECTORY_ENTRY_EXPORT    0
#define PE_DIRECTORY_ENTRY_IMPORT    1
#define PE_DIRECTORY_ENTRY_EXCEPTION 3

typedef struct _PE_DATA_DIRECTORY {
    UINT32 VirtualAddress;
    UINT32 Size;
} PE_DATA_DIRECTORY;

typedef struct _PE_EXPORT_DIRECTORY {
    UINT32 Characteristics;
    UINT32 TimeDateStamp;
    UINT16 MajorVersion;
    UINT16 MinorVersion;
    UINT32 Name;
    UINT32 Base;
    UINT32 NumberOfFunctions;
    UINT32 NumberOfNames;
    UINT32 AddressOfFunctions;
    UINT32 AddressOfNames;
    UINT32 AddressOfNameOrdinals;
} PE_EXPORT_DIRECTORY;

typedef struct _PE_IMPORT_DESCRIPTOR {
    UINT32 OriginalFirstThunk;  // RVA to Import Lookup Table (INT)
    UINT32 TimeDateStamp;
    UINT32 ForwarderChain;
    UINT32 Name;                // RVA to DLL name string
    UINT32 FirstThunk;          // RVA to Import Address Table (IAT)
} PE_IMPORT_DESCRIPTOR;

typedef struct _PE_IMPORT_BY_NAME {
    UINT16 Hint;
    CHAR8  Name[1];             // Variable-length
} PE_IMPORT_BY_NAME;

#define PE_IMAGE_ORDINAL_FLAG64  0x8000000000000000ULL

typedef struct _PE_RUNTIME_FUNCTION {
    UINT32 BeginAddress;
    UINT32 EndAddress;
    UINT32 UnwindInfoAddress;
} PE_RUNTIME_FUNCTION;

typedef struct _PE_NT_HEADERS64 {
    UINT32              Signature;
    PE_FILE_HEADER      FileHeader;
    PE_OPTIONAL_HEADER64 OptionalHeader;
} PE_NT_HEADERS64;

#define PE_SECTION_NAME_SIZE 8

typedef struct _PE_SECTION_HEADER {
    UINT8  Name[PE_SECTION_NAME_SIZE];
    UINT32 VirtualSize;
    UINT32 VirtualAddress;
    UINT32 SizeOfRawData;
    UINT32 PointerToRawData;
    UINT32 PointerToRelocations;
    UINT32 PointerToLinenumbers;
    UINT16 NumberOfRelocations;
    UINT16 NumberOfLinenumbers;
    UINT32 Characteristics;
} PE_SECTION_HEADER;

#pragma pack(pop)

/**
  Validate a PE32+ image at the given base address.

  @param[in] ImageBase  Pointer to start of PE image.

  @retval TRUE if valid PE32+ (64-bit) image, FALSE otherwise.
**/
BOOLEAN
PeValidateImage(
    IN VOID *ImageBase
    );

/**
  Get the NT headers from a PE image.

  @param[in] ImageBase  Pointer to start of PE image.

  @retval Pointer to PE_NT_HEADERS64, or NULL if invalid.
**/
PE_NT_HEADERS64 *
PeGetNtHeaders(
    IN VOID *ImageBase
    );

/**
  Find a PE section by name.

  @param[in] ImageBase    Pointer to start of PE image.
  @param[in] SectionName  8-byte section name (e.g., ".text\0\0\0").

  @retval Pointer to section header, or NULL if not found.
**/
PE_SECTION_HEADER *
PeFindSection(
    IN VOID       *ImageBase,
    IN CONST CHAR8 *SectionName
    );

/**
  Get the .text section of a PE image.
  Convenience wrapper for PeFindSection(ImageBase, ".text").

  @param[in]  ImageBase  Pointer to start of PE image.
  @param[out] TextBase   Receives pointer to .text section data.
  @param[out] TextSize   Receives size of .text section.

  @retval EFI_SUCCESS    Section found.
  @retval EFI_NOT_FOUND  No .text section.
**/
EFI_STATUS
PeGetTextSection(
    IN  VOID  *ImageBase,
    OUT VOID  **TextBase,
    OUT UINTN *TextSize
    );

/**
  Get the size of a loaded PE image.

  @param[in] ImageBase  Pointer to start of PE image.

  @retval Image size from optional header, or 0 on error.
**/
UINTN
PeGetImageSize(
    IN VOID *ImageBase
    );

/**
  Find an exported function by name in a PE image.

  Walks the PE export directory to find a function by name.
  Returns the function's virtual address within the loaded image.

  @param[in] ImageBase  Pointer to start of PE image.
  @param[in] FuncName   Name of the exported function (ASCII).

  @retval Pointer to the function, or NULL if not found.
**/
VOID *
PeFindExport(
    IN VOID        *ImageBase,
    IN CONST CHAR8 *FuncName
    );

/**
  Find the IAT (Import Address Table) entry for a specific imported function.

  Walks the PE import directory to find the DLL, then the function by name.
  Returns the ADDRESS of the IAT slot (not the value stored in it).
  This address is what CALL [rip+disp32] instructions reference.

  @param[in] ImageBase  Pointer to start of PE image.
  @param[in] DllName    Name of the importing DLL (case-insensitive, ASCII).
  @param[in] FuncName   Name of the imported function (case-sensitive, ASCII).

  @retval Pointer to the IAT entry, or NULL if not found.
**/
VOID *
PeFindIATEntry(
    IN VOID        *ImageBase,
    IN CONST CHAR8 *DllName,
    IN CONST CHAR8 *FuncName
    );

/**
  Find the start address of the function containing the given address.

  Uses the PE exception directory (.pdata / RUNTIME_FUNCTION table) to
  find proper function boundaries. Much more reliable than CC padding scan.

  @param[in] ImageBase  Pointer to start of PE image.
  @param[in] Address    An address within a function in the image.

  @retval Pointer to the function start, or NULL if not found.
**/
VOID *
PeFindFunctionStart(
    IN VOID *ImageBase,
    IN VOID *Address
    );

#endif // DIOPROCESS_PE_UTILS_H_
