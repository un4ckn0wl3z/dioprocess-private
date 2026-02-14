#include "FileHide.h"

// ============== Global Variables ==============

PFLT_FILTER g_FileHideFilter = NULL;
ERESOURCE g_FileHideLock;
LIST_ENTRY g_FileHideListHead;
ULONG g_FileHideCount = 0;
BOOLEAN g_FileHideInitialized = FALSE;

// ============== Forward Declarations ==============

FLT_PREOP_CALLBACK_STATUS
FileHide_OnPreDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
FileHide_OnPostDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

NTSTATUS
FileHide_Unload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
FileHide_InstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS
FileHide_InstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

VOID
FileHide_InstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
FileHide_InstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

static NTSTATUS
FileHide_CreateRegistryKeys(
    _In_ PUNICODE_STRING RegistryPath
);

// ============== Callback Registration ==============

CONST FLT_OPERATION_REGISTRATION FileHide_Callbacks[] = {
    {
        IRP_MJ_DIRECTORY_CONTROL,
        0,
        FileHide_OnPreDirectoryControl,
        FileHide_OnPostDirectoryControl
    },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FileHide_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    FileHide_Callbacks,
    FileHide_Unload,
    FileHide_InstanceSetup,
    FileHide_InstanceQueryTeardown,
    FileHide_InstanceTeardownStart,
    FileHide_InstanceTeardownComplete,
};

// ============== Helpers ==============

static VOID
FileHide_NormalizePath(
    _In_ PUNICODE_STRING Input,
    _Out_ PUNICODE_STRING Output
)
{
    *Output = *Input;
    if (Output->Length >= sizeof(WCHAR) &&
        Output->Buffer[(Output->Length / sizeof(WCHAR)) - 1] == L'\\')
    {
        Output->Length -= sizeof(WCHAR);
    }
}

// ============== Pre-operation Callback ==============

FLT_PREOP_CALLBACK_STATUS
FileHide_OnPreDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Only process user-mode directory queries
    if (Data->RequestorMode == KernelMode ||
        Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// ============== Post-operation Callback ==============

FLT_POSTOP_CALLBACK_STATUS
FileHide_OnPostDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode ||
        Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY ||
        (Flags & FLTFL_POST_OPERATION_DRAINING))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Get directory listing parameters
    PFLT_PARAMETERS params = &Data->Iopb->Parameters;

    // Get DOS path of the current directory
    POBJECT_NAME_INFORMATION dosPath = NULL;
    if (!NT_SUCCESS(IoQueryFileDosDeviceName(FltObjects->FileObject, &dosPath)) || !dosPath)
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Get the mapped buffer base
    PUCHAR base = NULL;
    if (params->DirectoryControl.QueryDirectory.MdlAddress)
    {
        base = (PUCHAR)MmGetSystemAddressForMdlSafe(
            params->DirectoryControl.QueryDirectory.MdlAddress,
            NormalPagePriority);
    }
    if (!base)
    {
        base = (PUCHAR)params->DirectoryControl.QueryDirectory.DirectoryBuffer;
    }
    if (!base)
    {
        ExFreePool(dosPath);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Determine directory information structure format
    static const FILE_INFORMATION_DEFINITION defs[] = {
        FileFullDirectoryInformationDefinition,
        FileBothDirectoryInformationDefinition,
        FileDirectoryInformationDefinition,
        FileNamesInformationDefinition,
        FileIdFullDirectoryInformationDefinition,
        FileIdBothDirectoryInformationDefinition,
        FileIdExtdDirectoryInformationDefinition,
        FileIdGlobalTxDirectoryInformationDefinition
    };

    const FILE_INFORMATION_DEFINITION* actual = NULL;
    for (ULONG i = 0; i < ARRAYSIZE(defs); ++i)
    {
        if (defs[i].Class == params->DirectoryControl.QueryDirectory.FileInformationClass)
        {
            actual = &defs[i];
            break;
        }
    }

    if (!actual)
    {
        ExFreePool(dosPath);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Lock the hidden files list
    ExAcquireResourceSharedLite(&g_FileHideLock, TRUE);

    // Iterate over hidden file entries
    for (PLIST_ENTRY listEntry = g_FileHideListHead.Flink;
         listEntry != &g_FileHideListHead;
         listEntry = listEntry->Flink)
    {
        PHIDDEN_FILE_ENTRY entry = CONTAINING_RECORD(listEntry, HIDDEN_FILE_ENTRY, ListEntry);

        // Build UNICODE_STRING from the hidden file path
        UNICODE_STRING hiddenFilePath;
        RtlInitUnicodeString(&hiddenFilePath, entry->FilePath);

        // Extract parent directory portion
        PWSTR lastBackslash = wcsrchr(hiddenFilePath.Buffer, L'\\');
        if (!lastBackslash)
            continue;

        UNICODE_STRING parentDir;
        parentDir.Buffer = hiddenFilePath.Buffer;
        parentDir.Length = (USHORT)((lastBackslash - hiddenFilePath.Buffer) * sizeof(WCHAR));
        parentDir.MaximumLength = parentDir.Length;

        // Normalize paths for comparison (remove trailing backslash)
        UNICODE_STRING normalizedParentDir, normalizedDosPath;
        FileHide_NormalizePath(&parentDir, &normalizedParentDir);
        FileHide_NormalizePath(&dosPath->Name, &normalizedDosPath);

        // Only process if we're in the same parent directory
        if (!RtlEqualUnicodeString(&normalizedParentDir, &normalizedDosPath, TRUE))
            continue;

        // Extract the leaf file name
        PWSTR fileName = lastBackslash + 1;
        if (*fileName == L'\0')
            continue;

        // Scan and modify the directory buffer to remove the hidden entry
        PUCHAR current = base;
        PUCHAR previous = NULL;
        ULONG nextOffset = 0;

        do {
            PULONG nextEntryOffset = (PULONG)(current + actual->NextEntryOffset);
            PULONG fileNameLengthPtr = (PULONG)(current + actual->FileNameLengthOffset);
            PWCHAR fileNamePtr = (PWCHAR)(current + actual->FileNameOffset);

            nextOffset = *nextEntryOffset;
            ULONG fileNameLen = *fileNameLengthPtr;

            if (fileNameLen > 0)
            {
                WCHAR tempName[256] = { 0 };
                ULONG copyLen = min(fileNameLen / sizeof(WCHAR), 255);
                RtlCopyMemory(tempName, fileNamePtr, copyLen * sizeof(WCHAR));
                tempName[copyLen] = L'\0';

                if (_wcsicmp(tempName, fileName) == 0)
                {
                    KdPrint(("DioProcess: FileHide - Hiding: %S\n", fileName));

                    if (!previous)
                    {
                        // First entry - advance buffer pointer
                        if (nextOffset == 0)
                        {
                            // Only entry in the buffer - return empty result
                            Data->IoStatus.Status = STATUS_NO_MORE_FILES;
                            FltSetCallbackDataDirty(Data);
                        }
                        else
                        {
                            params->DirectoryControl.QueryDirectory.DirectoryBuffer = current + nextOffset;
                            FltSetCallbackDataDirty(Data);
                        }
                    }
                    else
                    {
                        // Adjust previous entry's offset to skip current
                        PULONG prevNextOffset = (PULONG)(previous + actual->NextEntryOffset);
                        if (nextOffset == 0)
                        {
                            // Current is last entry - make previous the last
                            *prevNextOffset = 0;
                        }
                        else
                        {
                            *prevNextOffset += nextOffset;
                        }
                    }

                    // Stop scanning buffer for this hidden entry
                    break;
                }
            }

            previous = current;
            current += nextOffset;

        } while (nextOffset != 0);
    }

    ExReleaseResourceLite(&g_FileHideLock);
    ExFreePool(dosPath);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============== Filter Lifecycle ==============

NTSTATUS
FileHide_Unload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);
    KdPrint(("DioProcess: FileHide - Unload\n"));

    // Note: Full cleanup is done in FileHide_Cleanup() called from driver unload
    // This callback is for Filter Manager initiated unloads
    return STATUS_SUCCESS;
}

NTSTATUS
FileHide_InstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    // Only attach to NTFS volumes
    return (VolumeFilesystemType == FLT_FSTYPE_NTFS) ? STATUS_SUCCESS : STATUS_FLT_DO_NOT_ATTACH;
}

NTSTATUS
FileHide_InstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

VOID
FileHide_InstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

VOID
FileHide_InstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

// ============== Registry Key Setup ==============

static NTSTATUS
FileHide_CreateRegistryKeys(
    _In_ PUNICODE_STRING RegistryPath
)
{
    HANDLE hKey = NULL, hSubKey = NULL, hInstKey = NULL;
    OBJECT_ATTRIBUTES keyAttr = RTL_CONSTANT_OBJECT_ATTRIBUTES(RegistryPath, OBJ_KERNEL_HANDLE);
    NTSTATUS status;

    // Open base registry key
    status = ZwOpenKey(&hKey, KEY_WRITE, &keyAttr);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("DioProcess: FileHide - Failed to open base registry key (0x%08X)\n", status));
        return status;
    }

    // Create Instances subkey
    UNICODE_STRING subKey = RTL_CONSTANT_STRING(L"Instances");
    OBJECT_ATTRIBUTES subKeyAttr;
    InitializeObjectAttributes(&subKeyAttr, &subKey, OBJ_KERNEL_HANDLE, hKey, NULL);

    status = ZwCreateKey(&hSubKey, KEY_WRITE, &subKeyAttr, 0, NULL, 0, NULL);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("DioProcess: FileHide - Failed to create Instances key (0x%08X)\n", status));
        ZwClose(hKey);
        return status;
    }

    // Set DefaultInstance
    UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"DefaultInstance");
    WCHAR instanceName[] = L"DioProcessFileHide";
    status = ZwSetValueKey(hSubKey, &valueName, 0, REG_SZ, instanceName, sizeof(instanceName));
    if (!NT_SUCCESS(status))
    {
        KdPrint(("DioProcess: FileHide - Failed to set DefaultInstance (0x%08X)\n", status));
        ZwClose(hSubKey);
        ZwClose(hKey);
        return status;
    }

    // Create instance key
    UNICODE_STRING instKeyName;
    RtlInitUnicodeString(&instKeyName, instanceName);
    InitializeObjectAttributes(&subKeyAttr, &instKeyName, OBJ_KERNEL_HANDLE, hSubKey, NULL);

    status = ZwCreateKey(&hInstKey, KEY_WRITE, &subKeyAttr, 0, NULL, 0, NULL);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("DioProcess: FileHide - Failed to create instance key (0x%08X)\n", status));
        ZwClose(hSubKey);
        ZwClose(hKey);
        return status;
    }

    // Set Altitude (415161 - FSFilter Undelete range)
    WCHAR altitude[] = L"415161";
    UNICODE_STRING altitudeName = RTL_CONSTANT_STRING(L"Altitude");
    status = ZwSetValueKey(hInstKey, &altitudeName, 0, REG_SZ, altitude, sizeof(altitude));
    if (!NT_SUCCESS(status))
    {
        KdPrint(("DioProcess: FileHide - Failed to set Altitude (0x%08X)\n", status));
        ZwClose(hInstKey);
        ZwClose(hSubKey);
        ZwClose(hKey);
        return status;
    }

    // Set Flags to 0
    UNICODE_STRING flagsName = RTL_CONSTANT_STRING(L"Flags");
    ULONG flags = 0;
    status = ZwSetValueKey(hInstKey, &flagsName, 0, REG_DWORD, &flags, sizeof(flags));
    if (!NT_SUCCESS(status))
    {
        KdPrint(("DioProcess: FileHide - Failed to set Flags (0x%08X)\n", status));
    }

    ZwClose(hInstKey);
    ZwClose(hSubKey);
    ZwClose(hKey);

    return status;
}

// ============== Public API ==============

NTSTATUS FileHide_Init(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    KdPrint(("DioProcess: FileHide - Initializing\n"));

    // Initialize the ERESOURCE lock
    ExInitializeResourceLite(&g_FileHideLock);

    // Initialize the linked list
    InitializeListHead(&g_FileHideListHead);
    g_FileHideCount = 0;

    // Create registry keys for minifilter instance
    NTSTATUS status = FileHide_CreateRegistryKeys(RegistryPath);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("DioProcess: FileHide - Registry key creation failed (0x%08X), continuing anyway\n", status));
        // Non-fatal: keys may already exist
    }

    // Register the filter
    status = FltRegisterFilter(DriverObject, &FileHide_FilterRegistration, &g_FileHideFilter);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("DioProcess: FileHide - FltRegisterFilter failed (0x%08X)\n", status));
        ExDeleteResourceLite(&g_FileHideLock);
        return status;
    }

    // Start filtering
    status = FltStartFiltering(g_FileHideFilter);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("DioProcess: FileHide - FltStartFiltering failed (0x%08X)\n", status));
        FltUnregisterFilter(g_FileHideFilter);
        g_FileHideFilter = NULL;
        ExDeleteResourceLite(&g_FileHideLock);
        return status;
    }

    g_FileHideInitialized = TRUE;
    KdPrint(("DioProcess: FileHide - Initialized successfully\n"));
    return STATUS_SUCCESS;
}

VOID FileHide_Cleanup()
{
    if (!g_FileHideInitialized)
        return;

    KdPrint(("DioProcess: FileHide - Cleaning up\n"));

    // Unregister the minifilter
    if (g_FileHideFilter)
    {
        FltUnregisterFilter(g_FileHideFilter);
        g_FileHideFilter = NULL;
    }

    // Free all hidden file entries
    ExAcquireResourceExclusiveLite(&g_FileHideLock, TRUE);
    while (!IsListEmpty(&g_FileHideListHead))
    {
        PLIST_ENTRY listEntry = RemoveHeadList(&g_FileHideListHead);
        PHIDDEN_FILE_ENTRY entry = CONTAINING_RECORD(listEntry, HIDDEN_FILE_ENTRY, ListEntry);
        ExFreePoolWithTag(entry, FILEHIDE_POOL_TAG);
    }
    g_FileHideCount = 0;
    ExReleaseResourceLite(&g_FileHideLock);

    // Delete the resource lock
    ExDeleteResourceLite(&g_FileHideLock);

    g_FileHideInitialized = FALSE;
    KdPrint(("DioProcess: FileHide - Cleanup complete\n"));
}

NTSTATUS FileHide_AddPath(
    _In_ const WCHAR* FilePath
)
{
    if (!g_FileHideInitialized)
        return STATUS_DEVICE_NOT_READY;

    if (!FilePath || wcslen(FilePath) == 0)
        return STATUS_INVALID_PARAMETER;

    ExAcquireResourceExclusiveLite(&g_FileHideLock, TRUE);

    // Check if already present (idempotent)
    for (PLIST_ENTRY listEntry = g_FileHideListHead.Flink;
         listEntry != &g_FileHideListHead;
         listEntry = listEntry->Flink)
    {
        PHIDDEN_FILE_ENTRY entry = CONTAINING_RECORD(listEntry, HIDDEN_FILE_ENTRY, ListEntry);
        if (_wcsicmp(entry->FilePath, FilePath) == 0)
        {
            ExReleaseResourceLite(&g_FileHideLock);
            KdPrint(("DioProcess: FileHide - Path already hidden: %S\n", FilePath));
            return STATUS_SUCCESS;
        }
    }

    // Check max capacity
    if (g_FileHideCount >= MAX_HIDDEN_FILES)
    {
        ExReleaseResourceLite(&g_FileHideLock);
        KdPrint(("DioProcess: FileHide - Max hidden files reached (%u)\n", MAX_HIDDEN_FILES));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Allocate and initialize new entry
    PHIDDEN_FILE_ENTRY newEntry = (PHIDDEN_FILE_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(HIDDEN_FILE_ENTRY),
        FILEHIDE_POOL_TAG);

    if (!newEntry)
    {
        ExReleaseResourceLite(&g_FileHideLock);
        KdPrint(("DioProcess: FileHide - Failed to allocate entry\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newEntry, sizeof(HIDDEN_FILE_ENTRY));
    RtlStringCbCopyW(newEntry->FilePath, sizeof(newEntry->FilePath), FilePath);

    InsertTailList(&g_FileHideListHead, &newEntry->ListEntry);
    g_FileHideCount++;

    ExReleaseResourceLite(&g_FileHideLock);

    KdPrint(("DioProcess: FileHide - Hidden: %S (count=%u)\n", FilePath, g_FileHideCount));
    return STATUS_SUCCESS;
}

NTSTATUS FileHide_RemovePath(
    _In_ const WCHAR* FilePath
)
{
    if (!g_FileHideInitialized)
        return STATUS_DEVICE_NOT_READY;

    if (!FilePath || wcslen(FilePath) == 0)
        return STATUS_INVALID_PARAMETER;

    ExAcquireResourceExclusiveLite(&g_FileHideLock, TRUE);

    for (PLIST_ENTRY listEntry = g_FileHideListHead.Flink;
         listEntry != &g_FileHideListHead;
         listEntry = listEntry->Flink)
    {
        PHIDDEN_FILE_ENTRY entry = CONTAINING_RECORD(listEntry, HIDDEN_FILE_ENTRY, ListEntry);
        if (_wcsicmp(entry->FilePath, FilePath) == 0)
        {
            RemoveEntryList(listEntry);
            g_FileHideCount--;
            ExReleaseResourceLite(&g_FileHideLock);

            KdPrint(("DioProcess: FileHide - Unhidden: %S (count=%u)\n", FilePath, g_FileHideCount));
            ExFreePoolWithTag(entry, FILEHIDE_POOL_TAG);
            return STATUS_SUCCESS;
        }
    }

    ExReleaseResourceLite(&g_FileHideLock);
    KdPrint(("DioProcess: FileHide - Path not found: %S\n", FilePath));
    return STATUS_NOT_FOUND;
}

NTSTATUS FileHide_ListPaths(
    _Out_ WCHAR(*Entries)[FILEHIDE_MAX_PATH],
    _Out_ ULONG* Count,
    _In_ ULONG MaxEntries
)
{
    if (!g_FileHideInitialized)
    {
        *Count = 0;
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireResourceSharedLite(&g_FileHideLock, TRUE);

    ULONG index = 0;
    for (PLIST_ENTRY listEntry = g_FileHideListHead.Flink;
         listEntry != &g_FileHideListHead && index < MaxEntries;
         listEntry = listEntry->Flink)
    {
        PHIDDEN_FILE_ENTRY entry = CONTAINING_RECORD(listEntry, HIDDEN_FILE_ENTRY, ListEntry);
        RtlStringCbCopyW(Entries[index], FILEHIDE_MAX_PATH * sizeof(WCHAR), entry->FilePath);
        index++;
    }

    *Count = index;
    ExReleaseResourceLite(&g_FileHideLock);

    return STATUS_SUCCESS;
}
