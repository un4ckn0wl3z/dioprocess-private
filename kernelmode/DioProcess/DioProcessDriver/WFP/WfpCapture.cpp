#include "pch.h"
#include "WfpCapture.h"
#include "../DioProcessGlobals.h"

#pragma comment(lib, "fwpkclnt.lib")
#pragma comment(lib, "uuid.lib")

// ============== Global Variables ==============

HANDLE g_WfpEngineHandle = nullptr;
UINT32 g_WfpCalloutIdOutbound = 0;
UINT32 g_WfpCalloutIdInbound = 0;
UINT64 g_WfpFilterIdOutbound = 0;
UINT64 g_WfpFilterIdInbound = 0;
HANDLE g_InjectionHandle = nullptr;
NDIS_HANDLE g_NblPoolHandle = nullptr;
WfpCaptureState g_CaptureState = { 0 };

// ============== Internal Helpers ==============
// All WFP callout functions and helpers must be in non-paged memory (DISPATCH_LEVEL)
#pragma code_seg()

static void AddPacketToBuffer(const CapturedPacket* packet)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_CaptureState.BufferLock, &oldIrql);

    if (g_CaptureState.PacketBuffer == nullptr)
    {
        KeReleaseSpinLock(&g_CaptureState.BufferLock, oldIrql);
        return;
    }

    // Copy packet to buffer at tail position
    UINT32 index = g_CaptureState.BufferTail;
    RtlCopyMemory(&g_CaptureState.PacketBuffer[index], packet, sizeof(CapturedPacket));

    // Advance tail
    g_CaptureState.BufferTail = (g_CaptureState.BufferTail + 1) % MAX_CAPTURED_PACKETS;

    // If buffer is full, advance head (overwrite oldest)
    if (g_CaptureState.PacketCount >= MAX_CAPTURED_PACKETS)
    {
        g_CaptureState.BufferHead = (g_CaptureState.BufferHead + 1) % MAX_CAPTURED_PACKETS;
        g_CaptureState.DroppedCount++;
    }
    else
    {
        g_CaptureState.PacketCount++;
    }

    KeReleaseSpinLock(&g_CaptureState.BufferLock, oldIrql);
}

static BOOLEAN ShouldBlockPacket(
    PacketDirection direction,
    PacketProtocol protocol,
    UINT32 localAddr,
    UINT16 localPort,
    UINT32 remoteAddr,
    UINT16 remotePort)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_CaptureState.FilterLock, &oldIrql);

    BOOLEAN shouldBlock = FALSE;

    for (UINT32 i = 0; i < g_CaptureState.FilterRuleCount; i++)
    {
        const PacketFilterRule* rule = &g_CaptureState.FilterRules[i];
        if (!rule->Enabled)
            continue;

        // Check protocol match
        if (rule->Protocol != protocol)
            continue;

        // Check port match (0 = any)
        BOOLEAN portMatch = (rule->Port == 0) ||
            (rule->Port == localPort) ||
            (rule->Port == remotePort);
        if (!portMatch)
            continue;

        // Check IP match (0 = any)
        BOOLEAN ipMatch = (rule->IpAddress == 0) ||
            (rule->IpAddress == localAddr) ||
            (rule->IpAddress == remoteAddr);
        if (!ipMatch)
            continue;

        // Rule matches
        if (rule->Action == PacketFilterAction::Block)
        {
            shouldBlock = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_CaptureState.FilterLock, oldIrql);
    return shouldBlock;
}

static void ProcessPacket(
    PacketDirection direction,
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    // Check if we're capturing
    if (!g_CaptureState.IsCapturing)
    {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Get process ID
    UINT64 pid = 0;
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
    {
        pid = inMetaValues->processId;
    }

    // Check if this is our target process
    if (g_CaptureState.TargetPid != 0 && pid != g_CaptureState.TargetPid)
    {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Extract packet info based on layer
    UINT32 localAddr = 0;
    UINT16 localPort = 0;
    UINT32 remoteAddr = 0;
    UINT16 remotePort = 0;
    PacketProtocol protocol = PacketProtocol::TCP;

    if (direction == PacketDirection::Outbound)
    {
        // FWPM_LAYER_OUTBOUND_TRANSPORT_V4 indices
        localAddr = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
        localPort = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
        remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
        UINT8 proto = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
        protocol = (proto == 6) ? PacketProtocol::TCP : PacketProtocol::UDP;
    }
    else
    {
        // FWPM_LAYER_INBOUND_TRANSPORT_V4 indices
        localAddr = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
        localPort = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
        remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
        UINT8 proto = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
        protocol = (proto == 6) ? PacketProtocol::TCP : PacketProtocol::UDP;
    }

    // Check filter rules
    if (ShouldBlockPacket(direction, protocol, localAddr, localPort, remoteAddr, remotePort))
    {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    // Allocate packet from non-paged pool (CapturedPacket is too large for stack at DISPATCH_LEVEL)
    CapturedPacket* packet = (CapturedPacket*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(CapturedPacket),
        'pkpW'
    );
    if (packet == nullptr)
    {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    RtlZeroMemory(packet, sizeof(CapturedPacket));
    packet->Id = InterlockedIncrement64((LONG64*)&g_CaptureState.NextPacketId);
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&packet->Timestamp);
    packet->ProcessId = (UINT32)pid;
    packet->Direction = direction;
    packet->Protocol = protocol;
    packet->LocalAddr = localAddr;
    packet->LocalPort = localPort;
    packet->RemoteAddr = remoteAddr;
    packet->RemotePort = remotePort;

    // Extract payload from NET_BUFFER_LIST
    if (layerData != nullptr)
    {
        NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerData;
        NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
        if (nb != nullptr)
        {
            ULONG dataLength = NET_BUFFER_DATA_LENGTH(nb);
            if (dataLength > MAX_PACKET_PAYLOAD)
                dataLength = MAX_PACKET_PAYLOAD;

            PVOID dataPtr = NdisGetDataBuffer(nb, dataLength, packet->Payload, 1, 0);
            if (dataPtr != nullptr && dataPtr != packet->Payload)
            {
                RtlCopyMemory(packet->Payload, dataPtr, dataLength);
            }
            packet->PayloadSize = (UINT16)dataLength;
        }
    }

    // Add to buffer
    AddPacketToBuffer(packet);

    // Free temporary packet
    ExFreePoolWithTag(packet, 'pkpW');

    // Permit the packet
    classifyOut->actionType = FWP_ACTION_PERMIT;
}

// ============== WFP Callout Functions ==============

void NTAPI WfpClassifyOutbound(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // TEMPORARY: Just permit everything to test if callout registration works
    classifyOut->actionType = FWP_ACTION_PERMIT;
    // ProcessPacket(PacketDirection::Outbound, inFixedValues, inMetaValues, layerData, classifyOut);
}

void NTAPI WfpClassifyInbound(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // TEMPORARY: Just permit everything to test if callout registration works
    classifyOut->actionType = FWP_ACTION_PERMIT;
    // ProcessPacket(PacketDirection::Inbound, inFixedValues, inMetaValues, layerData, classifyOut);
}

NTSTATUS NTAPI WfpNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER0* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

void NTAPI WfpFlowDeleteFn(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}

// ============== Initialization ==============
// Restore paged code for init/cleanup (runs at PASSIVE_LEVEL)
#pragma code_seg("PAGE")

NTSTATUS WfpCaptureInit(PDEVICE_OBJECT DeviceObject)
{
    NTSTATUS status;

    // Initialize state
    RtlZeroMemory(&g_CaptureState, sizeof(g_CaptureState));
    KeInitializeSpinLock(&g_CaptureState.BufferLock);
    KeInitializeSpinLock(&g_CaptureState.FilterLock);

    // Allocate packet buffer
    g_CaptureState.PacketBuffer = (CapturedPacket*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(CapturedPacket) * MAX_CAPTURED_PACKETS,
        'pfpW'
    );
    if (g_CaptureState.PacketBuffer == nullptr)
    {
        KdPrint((DRIVER_PREFIX "Failed to allocate packet buffer\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Open WFP engine
    FWPM_SESSION0 session = { 0 };
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session, &g_WfpEngineHandle);
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_PREFIX "FwpmEngineOpen0 failed: 0x%X\n", status));
        goto cleanup;
    }

    // Start transaction
    status = FwpmTransactionBegin0(g_WfpEngineHandle, 0);
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_PREFIX "FwpmTransactionBegin0 failed: 0x%X\n", status));
        goto cleanup;
    }

    // Add sublayer
    FWPM_SUBLAYER0 sublayer = { 0 };
    sublayer.subLayerKey = GUID_WFP_SUBLAYER;
    sublayer.displayData.name = const_cast<wchar_t*>(L"DioProcess Packet Capture Sublayer");
    sublayer.weight = 0xFFFF;

    status = FwpmSubLayerAdd0(g_WfpEngineHandle, &sublayer, nullptr);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS)
    {
        KdPrint((DRIVER_PREFIX "FwpmSubLayerAdd0 failed: 0x%X\n", status));
        FwpmTransactionAbort0(g_WfpEngineHandle);
        goto cleanup;
    }

    // Register outbound callout
    FWPS_CALLOUT0 sCalloutOutbound = { 0 };
    sCalloutOutbound.calloutKey = GUID_WFP_CALLOUT_OUTBOUND;
    sCalloutOutbound.classifyFn = reinterpret_cast<FWPS_CALLOUT_CLASSIFY_FN0>(WfpClassifyOutbound);
    sCalloutOutbound.notifyFn = reinterpret_cast<FWPS_CALLOUT_NOTIFY_FN0>(WfpNotifyFn);
    sCalloutOutbound.flowDeleteFn = reinterpret_cast<FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0>(WfpFlowDeleteFn);

    status = FwpsCalloutRegister0(DeviceObject, &sCalloutOutbound, &g_WfpCalloutIdOutbound);
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_PREFIX "FwpsCalloutRegister0 (outbound) failed: 0x%X\n", status));
        FwpmTransactionAbort0(g_WfpEngineHandle);
        goto cleanup;
    }

    // Add outbound callout to WFP
    FWPM_CALLOUT0 mCalloutOutbound = { 0 };
    mCalloutOutbound.calloutKey = GUID_WFP_CALLOUT_OUTBOUND;
    mCalloutOutbound.displayData.name = const_cast<wchar_t*>(L"DioProcess Outbound Capture");
    mCalloutOutbound.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;

    status = FwpmCalloutAdd0(g_WfpEngineHandle, &mCalloutOutbound, nullptr, nullptr);
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_PREFIX "FwpmCalloutAdd0 (outbound) failed: 0x%X\n", status));
        FwpmTransactionAbort0(g_WfpEngineHandle);
        goto cleanup;
    }

    // Register inbound callout
    FWPS_CALLOUT0 sCalloutInbound = { 0 };
    sCalloutInbound.calloutKey = GUID_WFP_CALLOUT_INBOUND;
    sCalloutInbound.classifyFn = reinterpret_cast<FWPS_CALLOUT_CLASSIFY_FN0>(WfpClassifyInbound);
    sCalloutInbound.notifyFn = reinterpret_cast<FWPS_CALLOUT_NOTIFY_FN0>(WfpNotifyFn);
    sCalloutInbound.flowDeleteFn = reinterpret_cast<FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0>(WfpFlowDeleteFn);

    status = FwpsCalloutRegister0(DeviceObject, &sCalloutInbound, &g_WfpCalloutIdInbound);
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_PREFIX "FwpsCalloutRegister0 (inbound) failed: 0x%X\n", status));
        FwpmTransactionAbort0(g_WfpEngineHandle);
        goto cleanup;
    }

    // Add inbound callout to WFP
    FWPM_CALLOUT0 mCalloutInbound = { 0 };
    mCalloutInbound.calloutKey = GUID_WFP_CALLOUT_INBOUND;
    mCalloutInbound.displayData.name = const_cast<wchar_t*>(L"DioProcess Inbound Capture");
    mCalloutInbound.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4;

    status = FwpmCalloutAdd0(g_WfpEngineHandle, &mCalloutInbound, nullptr, nullptr);
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_PREFIX "FwpmCalloutAdd0 (inbound) failed: 0x%X\n", status));
        FwpmTransactionAbort0(g_WfpEngineHandle);
        goto cleanup;
    }

    // Add outbound filter
    FWPM_FILTER0 filterOutbound = { 0 };
    filterOutbound.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    filterOutbound.displayData.name = const_cast<wchar_t*>(L"DioProcess Outbound Filter");
    filterOutbound.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filterOutbound.action.calloutKey = GUID_WFP_CALLOUT_OUTBOUND;
    filterOutbound.subLayerKey = GUID_WFP_SUBLAYER;
    filterOutbound.weight.type = FWP_UINT8;
    filterOutbound.weight.uint8 = 0xF;

    status = FwpmFilterAdd0(g_WfpEngineHandle, &filterOutbound, nullptr, &g_WfpFilterIdOutbound);
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_PREFIX "FwpmFilterAdd0 (outbound) failed: 0x%X\n", status));
        FwpmTransactionAbort0(g_WfpEngineHandle);
        goto cleanup;
    }

    // Add inbound filter
    FWPM_FILTER0 filterInbound = { 0 };
    filterInbound.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
    filterInbound.displayData.name = const_cast<wchar_t*>(L"DioProcess Inbound Filter");
    filterInbound.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filterInbound.action.calloutKey = GUID_WFP_CALLOUT_INBOUND;
    filterInbound.subLayerKey = GUID_WFP_SUBLAYER;
    filterInbound.weight.type = FWP_UINT8;
    filterInbound.weight.uint8 = 0xF;

    status = FwpmFilterAdd0(g_WfpEngineHandle, &filterInbound, nullptr, &g_WfpFilterIdInbound);
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_PREFIX "FwpmFilterAdd0 (inbound) failed: 0x%X\n", status));
        FwpmTransactionAbort0(g_WfpEngineHandle);
        goto cleanup;
    }

    // Commit transaction
    status = FwpmTransactionCommit0(g_WfpEngineHandle);
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_PREFIX "FwpmTransactionCommit0 failed: 0x%X\n", status));
        goto cleanup;
    }

    // Create injection handle for packet resend (outside transaction)
    status = FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_TRANSPORT, &g_InjectionHandle);
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_PREFIX "FwpsInjectionHandleCreate0 failed: 0x%X\n", status));
        goto cleanup;
    }

    // Create NDIS pool for NET_BUFFER_LIST allocation (required for packet injection)
    {
        NET_BUFFER_LIST_POOL_PARAMETERS nblPoolParams = { 0 };
        nblPoolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        nblPoolParams.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        nblPoolParams.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        nblPoolParams.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
        nblPoolParams.fAllocateNetBuffer = TRUE;
        nblPoolParams.ContextSize = 0;
        nblPoolParams.PoolTag = 'lbNW';
        nblPoolParams.DataSize = 0;

        g_NblPoolHandle = NdisAllocateNetBufferListPool(nullptr, &nblPoolParams);
        if (g_NblPoolHandle == nullptr)
        {
            KdPrint((DRIVER_PREFIX "NdisAllocateNetBufferListPool failed\n"));
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }
    }

    KdPrint((DRIVER_PREFIX "WFP Packet Capture initialized successfully\n"));
    return STATUS_SUCCESS;

cleanup:
    WfpCaptureCleanup();
    return status;
}

void WfpCaptureCleanup()
{
    // Stop capturing
    g_CaptureState.IsCapturing = FALSE;

    // Free NDIS pool
    if (g_NblPoolHandle != nullptr)
    {
        NdisFreeNetBufferListPool(g_NblPoolHandle);
        g_NblPoolHandle = nullptr;
    }

    // Destroy injection handle
    if (g_InjectionHandle != nullptr)
    {
        FwpsInjectionHandleDestroy0(g_InjectionHandle);
        g_InjectionHandle = nullptr;
    }

    // Unregister callouts
    if (g_WfpCalloutIdOutbound != 0)
    {
        FwpsCalloutUnregisterById0(g_WfpCalloutIdOutbound);
        g_WfpCalloutIdOutbound = 0;
    }
    if (g_WfpCalloutIdInbound != 0)
    {
        FwpsCalloutUnregisterById0(g_WfpCalloutIdInbound);
        g_WfpCalloutIdInbound = 0;
    }

    // Close WFP engine (this removes filters and callouts added with DYNAMIC session)
    if (g_WfpEngineHandle != nullptr)
    {
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = nullptr;
    }

    // Free packet buffer
    if (g_CaptureState.PacketBuffer != nullptr)
    {
        ExFreePoolWithTag(g_CaptureState.PacketBuffer, 'pfpW');
        g_CaptureState.PacketBuffer = nullptr;
    }

    KdPrint((DRIVER_PREFIX "WFP Packet Capture cleaned up\n"));
}

// ============== Capture Control ==============

NTSTATUS WfpStartCapture(UINT32 TargetPid)
{
    if (g_WfpEngineHandle == nullptr)
        return STATUS_DEVICE_NOT_READY;

    g_CaptureState.TargetPid = TargetPid;
    g_CaptureState.IsCapturing = TRUE;

    KdPrint((DRIVER_PREFIX "Packet capture started for PID %u\n", TargetPid));
    return STATUS_SUCCESS;
}

NTSTATUS WfpStopCapture()
{
    g_CaptureState.IsCapturing = FALSE;
    KdPrint((DRIVER_PREFIX "Packet capture stopped\n"));
    return STATUS_SUCCESS;
}

BOOLEAN WfpIsCapturing()
{
    return g_CaptureState.IsCapturing;
}

// ============== Packet Buffer Operations ==============

NTSTATUS WfpGetCapturedPackets(
    _Out_writes_bytes_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG BytesWritten)
{
    *BytesWritten = 0;

    if (g_CaptureState.PacketBuffer == nullptr)
        return STATUS_DEVICE_NOT_READY;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_CaptureState.BufferLock, &oldIrql);

    // Calculate how many packets we can return
    ULONG maxPackets = OutputBufferSize / sizeof(CapturedPacket);
    ULONG packetsToReturn = min(maxPackets, g_CaptureState.PacketCount);

    // Copy packets from head
    CapturedPacket* outPackets = (CapturedPacket*)OutputBuffer;
    UINT32 readIndex = g_CaptureState.BufferHead;

    for (ULONG i = 0; i < packetsToReturn; i++)
    {
        RtlCopyMemory(&outPackets[i], &g_CaptureState.PacketBuffer[readIndex], sizeof(CapturedPacket));
        readIndex = (readIndex + 1) % MAX_CAPTURED_PACKETS;
    }

    // Clear returned packets from buffer
    g_CaptureState.BufferHead = readIndex;
    g_CaptureState.PacketCount -= packetsToReturn;

    *BytesWritten = packetsToReturn * sizeof(CapturedPacket);

    KeReleaseSpinLock(&g_CaptureState.BufferLock, oldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS WfpClearPacketBuffer()
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_CaptureState.BufferLock, &oldIrql);

    g_CaptureState.BufferHead = 0;
    g_CaptureState.BufferTail = 0;
    g_CaptureState.PacketCount = 0;
    g_CaptureState.DroppedCount = 0;

    KeReleaseSpinLock(&g_CaptureState.BufferLock, oldIrql);

    KdPrint((DRIVER_PREFIX "Packet buffer cleared\n"));
    return STATUS_SUCCESS;
}

// ============== Packet Injection ==============
// InjectComplete callback runs at DISPATCH_LEVEL
#pragma code_seg()

static void NTAPI InjectComplete(
    _In_ void* context,
    _Inout_ NET_BUFFER_LIST* netBufferList,
    _In_ BOOLEAN dispatchLevel)
{
    UNREFERENCED_PARAMETER(dispatchLevel);

    if (netBufferList != nullptr)
    {
        // Get the MDL from the NET_BUFFER
        NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(netBufferList);
        if (nb != nullptr)
        {
            PMDL mdl = NET_BUFFER_CURRENT_MDL(nb);
            if (mdl != nullptr)
            {
                IoFreeMdl(mdl);
            }
        }

        FwpsFreeNetBufferList0(netBufferList);
    }

    // Free the buffer passed as context
    if (context != nullptr)
    {
        ExFreePoolWithTag(context, 'jnIW');
    }
}

// Restore paged code for IOCTL handlers (PASSIVE_LEVEL)
#pragma code_seg("PAGE")

NTSTATUS WfpInjectPacket(_In_ const CapturedPacket* Packet)
{
    if (g_InjectionHandle == nullptr || g_NblPoolHandle == nullptr)
        return STATUS_DEVICE_NOT_READY;

    if (Packet->PayloadSize == 0)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS status;
    NET_BUFFER_LIST* nbl = nullptr;
    PMDL mdl = nullptr;
    PVOID buffer = nullptr;

    // Allocate non-paged buffer for packet data (must be done at PASSIVE_LEVEL)
    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Packet->PayloadSize, 'jnIW');
    if (buffer == nullptr)
    {
        KdPrint((DRIVER_PREFIX "Failed to allocate injection buffer\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Copy payload to non-paged buffer
    RtlCopyMemory(buffer, Packet->Payload, Packet->PayloadSize);

    // Create MDL for the buffer
    mdl = IoAllocateMdl(buffer, Packet->PayloadSize, FALSE, FALSE, nullptr);
    if (mdl == nullptr)
    {
        KdPrint((DRIVER_PREFIX "IoAllocateMdl failed\n"));
        ExFreePoolWithTag(buffer, 'jnIW');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Build MDL for non-paged pool
    MmBuildMdlForNonPagedPool(mdl);

    // Allocate NET_BUFFER_LIST using our NDIS pool
    status = FwpsAllocateNetBufferAndNetBufferList0(
        g_NblPoolHandle,
        0,
        0,
        mdl,
        0,
        Packet->PayloadSize,
        &nbl
    );
    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_PREFIX "FwpsAllocateNetBufferAndNetBufferList0 failed: 0x%X\n", status));
        IoFreeMdl(mdl);
        ExFreePoolWithTag(buffer, 'jnIW');
        return status;
    }

    // Store buffer pointer in NBL context for cleanup
    NET_BUFFER_LIST_INFO(nbl, NetBufferListCancelId) = buffer;

    // Inject based on direction
    if (Packet->Direction == PacketDirection::Outbound)
    {
        // Build send params with remote address
        FWPS_TRANSPORT_SEND_PARAMS0 sendParams = { 0 };
        SOCKADDR_IN remoteAddr = { 0 };
        remoteAddr.sin_family = AF_INET;
        remoteAddr.sin_addr.s_addr = RtlUlongByteSwap(Packet->RemoteAddr);
        remoteAddr.sin_port = RtlUshortByteSwap(Packet->RemotePort);
        sendParams.remoteAddress = (UCHAR*)&remoteAddr;
        sendParams.remoteScopeId.Value = 0;
        sendParams.controlData = nullptr;
        sendParams.controlDataLength = 0;

        status = FwpsInjectTransportSendAsync0(
            g_InjectionHandle,
            nullptr,                    // injectionContext
            0,                          // endpointHandle
            0,                          // flags
            &sendParams,                // sendArgs
            AF_INET,                    // addressFamily
            UNSPECIFIED_COMPARTMENT_ID, // compartmentId
            nbl,                        // netBufferList
            InjectComplete,             // completionFn
            buffer                      // completionContext (for cleanup)
        );
    }
    else
    {
        status = FwpsInjectTransportReceiveAsync0(
            g_InjectionHandle,
            nullptr,                    // injectionContext
            nullptr,                    // reserved
            0,                          // flags
            AF_INET,                    // addressFamily
            UNSPECIFIED_COMPARTMENT_ID, // compartmentId
            0,                          // interfaceIndex
            0,                          // subInterfaceIndex
            nbl,                        // netBufferList
            InjectComplete,             // completionFn
            buffer                      // completionContext (for cleanup)
        );
    }

    if (!NT_SUCCESS(status))
    {
        KdPrint((DRIVER_PREFIX "Packet injection failed: 0x%X\n", status));
        FwpsFreeNetBufferList0(nbl);
        IoFreeMdl(mdl);
        ExFreePoolWithTag(buffer, 'jnIW');
        return status;
    }

    KdPrint((DRIVER_PREFIX "Packet injected successfully\n"));
    return STATUS_SUCCESS;
}

// ============== Filter Rules ==============

NTSTATUS WfpAddFilterRule(const PacketFilterRule* Rule)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_CaptureState.FilterLock, &oldIrql);

    if (g_CaptureState.FilterRuleCount >= MAX_FILTER_RULES)
    {
        KeReleaseSpinLock(&g_CaptureState.FilterLock, oldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(
        &g_CaptureState.FilterRules[g_CaptureState.FilterRuleCount],
        Rule,
        sizeof(PacketFilterRule)
    );
    g_CaptureState.FilterRuleCount++;

    KeReleaseSpinLock(&g_CaptureState.FilterLock, oldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS WfpRemoveFilterRule(UINT32 Index)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_CaptureState.FilterLock, &oldIrql);

    if (Index >= g_CaptureState.FilterRuleCount)
    {
        KeReleaseSpinLock(&g_CaptureState.FilterLock, oldIrql);
        return STATUS_INVALID_PARAMETER;
    }

    // Shift remaining rules
    for (UINT32 i = Index; i < g_CaptureState.FilterRuleCount - 1; i++)
    {
        g_CaptureState.FilterRules[i] = g_CaptureState.FilterRules[i + 1];
    }
    g_CaptureState.FilterRuleCount--;

    KeReleaseSpinLock(&g_CaptureState.FilterLock, oldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS WfpClearFilterRules()
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_CaptureState.FilterLock, &oldIrql);

    g_CaptureState.FilterRuleCount = 0;
    RtlZeroMemory(g_CaptureState.FilterRules, sizeof(g_CaptureState.FilterRules));

    KeReleaseSpinLock(&g_CaptureState.FilterLock, oldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS WfpGetFilterRules(
    _Out_writes_bytes_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG BytesWritten)
{
    *BytesWritten = 0;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_CaptureState.FilterLock, &oldIrql);

    ULONG requiredSize = g_CaptureState.FilterRuleCount * sizeof(PacketFilterRule);
    if (OutputBufferSize < requiredSize)
    {
        KeReleaseSpinLock(&g_CaptureState.FilterLock, oldIrql);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(OutputBuffer, g_CaptureState.FilterRules, requiredSize);
    *BytesWritten = requiredSize;

    KeReleaseSpinLock(&g_CaptureState.FilterLock, oldIrql);
    return STATUS_SUCCESS;
}

// ============== Capture State ==============

NTSTATUS WfpGetCaptureState(
    _Out_ BOOLEAN* IsCapturing,
    _Out_ ULONG* TargetPid,
    _Out_ ULONG* PacketCount,
    _Out_ ULONG* DroppedCount)
{
    *IsCapturing = g_CaptureState.IsCapturing;
    *TargetPid = g_CaptureState.TargetPid;
    *PacketCount = g_CaptureState.PacketCount;
    *DroppedCount = g_CaptureState.DroppedCount;
    return STATUS_SUCCESS;
}
