/** @file
  DioProcess UEFI Application — Boot-time kernel patch engine.

  Runs as a UEFI application from the boot menu. Hooks ExitBootServices,
  then chainloads bootmgfw.efi. When Windows calls ExitBootServices, the
  hook fires and patches kernel images that winload has loaded into memory.

  Flow:
  1. Boot manager launches DioProcessEfi.efi
  2. We hook gBS->ExitBootServices
  3. We chainload \EFI\Microsoft\Boot\bootmgfw.efi
  4. winload.efi loads ntoskrnl.exe, CI.dll into memory
  5. winload.efi calls ExitBootServices — our hook fires
  6. Hook scans memory map, finds ntoskrnl, applies DSE/KPP patches
  7. Hook calls original ExitBootServices, kernel takes control

  Key insight: winload loads kernel images via its OWN loader (BlImgLoadImage),
  NOT via UEFI's LoadImage. So they don't appear in LoadedImage protocol handles.
  We must scan the UEFI memory map to find them.
**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>

#include "Config.h"
#include "Graphics.h"
#include "PatchDse.h"
#include "PatchKpp.h"
#include "PeUtils.h"
#include "PatternScan.h"

#define WINDOWS_BOOTMGR_PATH  L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"

//
// Global state
//
STATIC EFI_EXIT_BOOT_SERVICES gOriginalExitBootServices = NULL;

//
// Debug log stored in NVRAM (readable after boot)
//
STATIC EFI_GUID gDioProcessVarGuid = { 0xD100C0C5, 0x1337, 0x4242, { 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01 } };
STATIC CHAR16 gDebugLog[900];
STATIC UINTN  gDebugLogPos = 0;

// These are NOT static — PatchDse.c and PatchKpp.c use them via extern
VOID
DebugAppend(
    IN CONST CHAR16 *Str
    )
{
    while (*Str && gDebugLogPos < 880) {
        gDebugLog[gDebugLogPos++] = *Str++;
    }
    gDebugLog[gDebugLogPos] = L'\0';
}

VOID
DebugAppendHex(
    IN UINT64 Value
    )
{
    CHAR16 Buf[20];
    CHAR16 *HexChars = L"0123456789ABCDEF";
    INT32 i;

    Buf[0] = L'0';
    Buf[1] = L'x';
    for (i = 0; i < 16; i++) {
        Buf[17 - i] = HexChars[Value & 0xF];
        Value >>= 4;
    }
    Buf[18] = L'\0';
    DebugAppend(Buf);
}

VOID
DebugAppendDec(
    IN UINTN Value
    )
{
    CHAR16 Buf[12];
    INT32 i = 10;
    Buf[11] = L'\0';
    if (Value == 0) {
        DebugAppend(L"0");
        return;
    }
    while (Value > 0 && i >= 0) {
        Buf[i--] = L'0' + (CHAR16)(Value % 10);
        Value /= 10;
    }
    DebugAppend(&Buf[i + 1]);
}

STATIC
VOID
DebugSave(VOID)
{
    gRT->SetVariable(
        L"DioProcessDebugLog",
        &gDioProcessVarGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
        (gDebugLogPos + 1) * sizeof(CHAR16),
        gDebugLog
    );
}

/**
  Scan the UEFI memory map to find ntoskrnl.exe specifically.

  We can't just grab the first large PE — it might be winload, hal, etc.
  ntoskrnl is identified by:
  1. Size in the 4MB-64MB range
  2. Exports "NtCreateFile" (unique to ntoskrnl)
  3. Imports from "CI.dll" (unique to ntoskrnl)
**/
STATIC
EFI_STATUS
FindNtoskrnl(
    OUT VOID  **ImageBase,
    OUT UINTN  *ImageSize
    )
{
    EFI_STATUS             Status;
    UINTN                  MapSize = 0;
    UINTN                  MapKey;
    UINTN                  DescriptorSize;
    UINT32                 DescriptorVersion;
    EFI_MEMORY_DESCRIPTOR *MemMap = NULL;
    UINTN                  Offset;
    UINTN                  CandidateCount = 0;

    Status = gBS->GetMemoryMap(&MapSize, NULL, &MapKey, &DescriptorSize, &DescriptorVersion);
    if (Status != EFI_BUFFER_TOO_SMALL) {
        return EFI_NOT_FOUND;
    }

    MapSize += 4 * DescriptorSize;
    MemMap = AllocatePool(MapSize);
    if (MemMap == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    Status = gBS->GetMemoryMap(&MapSize, MemMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    if (EFI_ERROR(Status)) {
        FreePool(MemMap);
        return Status;
    }

    for (Offset = 0; Offset < MapSize; Offset += DescriptorSize) {
        EFI_MEMORY_DESCRIPTOR *Desc = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)MemMap + Offset);
        UINT8  *RegionBase;
        UINTN   RegionSize;
        UINTN   PageOffset;

        if (Desc->Type != EfiLoaderData &&
            Desc->Type != EfiLoaderCode &&
            Desc->Type != EfiBootServicesCode &&
            Desc->Type != EfiBootServicesData &&
            Desc->Type != EfiRuntimeServicesCode &&
            Desc->Type != EfiRuntimeServicesData) {
            continue;
        }

        RegionBase = (UINT8 *)(UINTN)Desc->PhysicalStart;
        RegionSize = Desc->NumberOfPages * EFI_PAGE_SIZE;

        if (RegionSize < 0x1000) continue;

        for (PageOffset = 0; PageOffset + 0x1000 <= RegionSize; PageOffset += EFI_PAGE_SIZE) {
            UINT8 *PageBase = RegionBase + PageOffset;
            UINTN ImgSize;

            if (PageBase[0] != 'M' || PageBase[1] != 'Z') continue;
            if (!PeValidateImage(PageBase)) continue;

            ImgSize = PeGetImageSize(PageBase);
            // ntoskrnl is typically 4MB-64MB
            if (ImgSize < 0x400000 || ImgSize > 0x4000000) continue;

            CandidateCount++;

            // Verify this is ntoskrnl by checking for a known export
            if (PeFindExport(PageBase, "NtCreateFile") != NULL) {
                *ImageBase = PageBase;
                *ImageSize = ImgSize;
                DebugAppend(L"(#");
                DebugAppendDec(CandidateCount);
                DebugAppend(L") ");
                FreePool(MemMap);
                return EFI_SUCCESS;
            }
        }
    }

    DebugAppend(L"(");
    DebugAppendDec(CandidateCount);
    DebugAppend(L"cand) ");
    FreePool(MemMap);
    return EFI_NOT_FOUND;
}

/**
  Hooked ExitBootServices — fires when winload.efi transfers to kernel.

  At this point, Boot Services are still available (we haven't called
  the original yet), and winload has loaded ntoskrnl + CI.dll into memory.

  Both DSE and KPP bypass patch NTOSKRNL, so we find it once and share.
**/
STATIC
EFI_STATUS
EFIAPI
HookedExitBootServices(
    IN EFI_HANDLE ImageHandle,
    IN UINTN      MapKey
    )
{
    DIOPROCESS_CONFIG Config;
    VOID             *NtoskrnlBase = NULL;
    UINTN             NtoskrnlSize = 0;

    gDebugLogPos = 0;
    DebugAppend(L"Hook fired.");

    ReadDioProcessConfig(&Config);

    //
    // Find ntoskrnl.exe (needed for both DSE and KPP)
    // ntoskrnl.exe: ~4MB (older) to ~16MB+ (newer Windows 11)
    //
    if (Config.DseBypass || Config.KppBypass) {
        if (!EFI_ERROR(FindNtoskrnl(&NtoskrnlBase, &NtoskrnlSize))) {
            DebugAppend(L" NT:");
            DebugAppendHex((UINT64)(UINTN)NtoskrnlBase);
            DebugAppend(L"(");
            DebugAppendDec(NtoskrnlSize / (1024 * 1024));
            DebugAppend(L"M) ");
        } else {
            DebugAppend(L" NT:NF ");
        }
    }

    //
    // DSE bypass: patch ntoskrnl's SepInitializeCodeIntegrity
    // to pass 0 as CiOptions to CiInitialize
    //
    if (Config.DseBypass) {
        DebugAppend(L"DSE:");
        if (NtoskrnlBase != NULL) {
            if (PatchDse(NtoskrnlBase, NtoskrnlSize)) {
                DebugAppend(L"OK ");
            } else {
                DebugAppend(L"FAIL ");
            }
        } else {
            DebugAppend(L"SKIP ");
        }
    }

    //
    // PatchGuard bypass: patch ntoskrnl's KPP init functions
    //
    if (Config.KppBypass) {
        DebugAppend(L"KPP:");
        if (NtoskrnlBase != NULL) {
            if (PatchKpp(NtoskrnlBase, NtoskrnlSize)) {
                DebugAppend(L"OK ");
            } else {
                DebugAppend(L"FAIL ");
            }
        } else {
            DebugAppend(L"SKIP ");
        }
    }

    // Save debug log to NVRAM
    DebugSave();

    // Restore original and call
    gBS->ExitBootServices = gOriginalExitBootServices;
    return gOriginalExitBootServices(ImageHandle, MapKey);
}

// ============================================================
// Chainloader
// ============================================================

STATIC
EFI_STATUS
FindEspFileSystem(
    OUT EFI_SIMPLE_FILE_SYSTEM_PROTOCOL **FileSystem
    )
{
    EFI_STATUS  Status;
    UINTN       HandleCount;
    EFI_HANDLE *HandleBuffer;
    UINTN       Index;

    Status = gBS->LocateHandleBuffer(
        ByProtocol,
        &gEfiSimpleFileSystemProtocolGuid,
        NULL,
        &HandleCount,
        &HandleBuffer
    );
    if (EFI_ERROR(Status)) return EFI_NOT_FOUND;

    for (Index = 0; Index < HandleCount; Index++) {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
        EFI_FILE_PROTOCOL               *Root;
        EFI_FILE_PROTOCOL               *TestFile;

        Status = gBS->HandleProtocol(
            HandleBuffer[Index],
            &gEfiSimpleFileSystemProtocolGuid,
            (VOID **)&Fs
        );
        if (EFI_ERROR(Status)) continue;

        Status = Fs->OpenVolume(Fs, &Root);
        if (EFI_ERROR(Status)) continue;

        Status = Root->Open(Root, &TestFile, WINDOWS_BOOTMGR_PATH, EFI_FILE_MODE_READ, 0);
        Root->Close(Root);

        if (!EFI_ERROR(Status)) {
            TestFile->Close(TestFile);
            *FileSystem = Fs;
            FreePool(HandleBuffer);
            return EFI_SUCCESS;
        }
    }

    FreePool(HandleBuffer);
    return EFI_NOT_FOUND;
}

STATIC
EFI_STATUS
ChainloadWindowsBootManager(
    IN EFI_HANDLE ImageHandle
    )
{
    EFI_STATUS                       Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
    EFI_FILE_PROTOCOL               *Root;
    EFI_FILE_PROTOCOL               *BootmgrFile;
    EFI_FILE_INFO                   *FileInfo;
    UINTN                            FileInfoSize;
    UINTN                            FileSize;
    VOID                            *FileBuffer;
    EFI_HANDLE                       NewImageHandle;
    EFI_LOADED_IMAGE_PROTOCOL       *OurLoadedImage;
    EFI_DEVICE_PATH_PROTOCOL        *BootmgrDevicePath;

    Status = FindEspFileSystem(&FileSystem);
    if (EFI_ERROR(Status)) {
        Print(L"DioProcess: bootmgfw.efi not found on any volume\r\n");
        return Status;
    }

    Status = FileSystem->OpenVolume(FileSystem, &Root);
    if (EFI_ERROR(Status)) {
        Print(L"DioProcess: Failed to open ESP volume\r\n");
        return Status;
    }

    Status = Root->Open(Root, &BootmgrFile, WINDOWS_BOOTMGR_PATH, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
        Root->Close(Root);
        Print(L"DioProcess: Failed to open bootmgfw.efi\r\n");
        return Status;
    }

    FileInfoSize = 0;
    Status = BootmgrFile->GetInfo(BootmgrFile, &gEfiFileInfoGuid, &FileInfoSize, NULL);
    if (Status != EFI_BUFFER_TOO_SMALL) {
        BootmgrFile->Close(BootmgrFile);
        Root->Close(Root);
        return EFI_NOT_FOUND;
    }

    FileInfo = AllocatePool(FileInfoSize);
    if (FileInfo == NULL) {
        BootmgrFile->Close(BootmgrFile);
        Root->Close(Root);
        return EFI_OUT_OF_RESOURCES;
    }

    Status = BootmgrFile->GetInfo(BootmgrFile, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
    if (EFI_ERROR(Status)) {
        FreePool(FileInfo);
        BootmgrFile->Close(BootmgrFile);
        Root->Close(Root);
        return Status;
    }

    FileSize = (UINTN)FileInfo->FileSize;
    FreePool(FileInfo);

    FileBuffer = AllocatePool(FileSize);
    if (FileBuffer == NULL) {
        BootmgrFile->Close(BootmgrFile);
        Root->Close(Root);
        return EFI_OUT_OF_RESOURCES;
    }

    Status = BootmgrFile->Read(BootmgrFile, &FileSize, FileBuffer);
    BootmgrFile->Close(BootmgrFile);
    Root->Close(Root);

    if (EFI_ERROR(Status)) {
        FreePool(FileBuffer);
        return Status;
    }

    Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&OurLoadedImage);
    if (EFI_ERROR(Status)) {
        FreePool(FileBuffer);
        return Status;
    }

    BootmgrDevicePath = FileDevicePath(OurLoadedImage->DeviceHandle, WINDOWS_BOOTMGR_PATH);
    if (BootmgrDevicePath == NULL) {
        FreePool(FileBuffer);
        return EFI_NOT_FOUND;
    }

    Status = gBS->LoadImage(FALSE, ImageHandle, BootmgrDevicePath, FileBuffer, FileSize, &NewImageHandle);
    FreePool(FileBuffer);
    FreePool(BootmgrDevicePath);

    if (EFI_ERROR(Status)) {
        Print(L"DioProcess: Failed to load bootmgfw.efi: %r\r\n", Status);
        return Status;
    }

    Print(L"DioProcess: Chainloading Windows Boot Manager...\r\n");
    Status = gBS->StartImage(NewImageHandle, NULL, NULL);

    Print(L"DioProcess: bootmgfw.efi returned: %r\r\n", Status);
    return Status;
}

/**
  UEFI Application entry point.
**/
EFI_STATUS
EFIAPI
DioProcessEfiEntry(
    IN EFI_HANDLE       ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
    EFI_STATUS Status;

    Print(L"\r\n");
    Print(L"   ____  _       ____                                   \r\n");
    Print(L"  |  _ \\(_) ___ |  _ \\ _ __ ___   ___ ___  ___ ___     \r\n");
    Print(L"  | | | | |/ _ \\| |_) | '__/ _ \\ / __/ _ \\/ __/ __|    \r\n");
    Print(L"  | |_| | | (_) |  __/| | | (_) | (_|  __/\\__ \\__ \\    \r\n");
    Print(L"  |____/|_|\\___/|_|   |_|  \\___/ \\___\\___||___/___/    \r\n");
    Print(L"\r\n");
    Print(L"        D I O P R O C E S S   I S   G O D   P R O C E S S\r\n");
    Print(L"\r\n");
    Print(L"        Before Kernel. Before PatchGuard. Before You.\r\n");
    Print(L"\r\n");
    Print(L"        https://un4ckn0wl3z.dev/\r\n");
    Print(L"\r\n");


    // Install ExitBootServices hook
    gOriginalExitBootServices = gBS->ExitBootServices;
    gBS->ExitBootServices = HookedExitBootServices;
    Print(L"[+] ExitBootServices hook installed\r\n");

    // Display current config
    {
        DIOPROCESS_CONFIG Config;
        ReadDioProcessConfig(&Config);
        Print(L"[*] DSE Bypass:        %s\r\n", Config.DseBypass ? L"ENABLED" : L"disabled");
        Print(L"[*] PatchGuard Bypass: %s\r\n", Config.KppBypass ? L"ENABLED" : L"disabled");
    }

    Print(L"[*] Booting in 5 seconds...\r\n");
    Print(L"\r\n");
    GraphicsPlayAnimation(5000); // 5 seconds animated boot screen

    // Chainload Windows Boot Manager
    Status = ChainloadWindowsBootManager(ImageHandle);
    if (EFI_ERROR(Status)) {
        Print(L"\r\n[-] Chainload failed: %r\r\n", Status);
        Print(L"[-] Restoring original ExitBootServices\r\n");
        Print(L"[-] Returning to boot menu in 5 seconds...\r\n");
        gBS->ExitBootServices = gOriginalExitBootServices;
        gBS->Stall(5000000);
    }

    return Status;
}
