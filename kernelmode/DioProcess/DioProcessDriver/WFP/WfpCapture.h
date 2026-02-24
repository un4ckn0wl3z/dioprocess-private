#pragma once

// Note: ndis.h must be included before fwpsk.h (done in pch.h)
#include <fwpsk.h>
#include <fwpmk.h>

#include "../DioProcessCommon.h"

// ============== WFP Capture Configuration ==============

#define MAX_CAPTURED_PACKETS 10000
#define MAX_PACKET_PAYLOAD MAX_PACKET_PAYLOAD_SIZE

// ============== Internal Packet Structure (uses types from DioProcessCommon.h) ==============

#pragma pack(push, 1)
struct CapturedPacket
{
    UINT64 Id;
    UINT64 Timestamp;
    UINT32 ProcessId;
    PacketDirection Direction;
    PacketProtocol Protocol;
    UINT32 LocalAddr;
    UINT16 LocalPort;
    UINT32 RemoteAddr;
    UINT16 RemotePort;
    UINT16 PayloadSize;
    UINT8 Payload[MAX_PACKET_PAYLOAD];
};
#pragma pack(pop)

// ============== Packet Filter Rule ==============

struct PacketFilterRule
{
    BOOLEAN Enabled;
    PacketFilterAction Action;
    UINT16 Port;           // 0 = any port
    UINT32 IpAddress;      // 0 = any IP
    PacketProtocol Protocol;
};

#define MAX_FILTER_RULES 32

// ============== Capture State ==============

struct WfpCaptureState
{
    BOOLEAN IsCapturing;
    UINT32 TargetPid;
    UINT64 NextPacketId;
    UINT32 PacketCount;
    UINT32 DroppedCount;
    
    // Ring buffer
    CapturedPacket* PacketBuffer;
    UINT32 BufferHead;
    UINT32 BufferTail;
    KSPIN_LOCK BufferLock;
    
    // Filter rules
    PacketFilterRule FilterRules[MAX_FILTER_RULES];
    UINT32 FilterRuleCount;
    KSPIN_LOCK FilterLock;
};

// ============== WFP Handles ==============

extern HANDLE g_WfpEngineHandle;
extern UINT32 g_WfpCalloutIdOutbound;
extern UINT32 g_WfpCalloutIdInbound;
extern UINT64 g_WfpFilterIdOutbound;
extern UINT64 g_WfpFilterIdInbound;
extern HANDLE g_InjectionHandle;
extern NDIS_HANDLE g_NblPoolHandle;
extern WfpCaptureState g_CaptureState;

// ============== GUIDs ==============

// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
DEFINE_GUID(GUID_WFP_CALLOUT_OUTBOUND,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90);

// {A1B2C3D4-E5F6-7890-ABCD-EF1234567891}
DEFINE_GUID(GUID_WFP_CALLOUT_INBOUND,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x91);

// {A1B2C3D4-E5F6-7890-ABCD-EF1234567892}
DEFINE_GUID(GUID_WFP_SUBLAYER,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x92);

// ============== Function Declarations ==============

// Initialization and cleanup
NTSTATUS WfpCaptureInit(PDEVICE_OBJECT DeviceObject);
void WfpCaptureCleanup();

// Capture control
NTSTATUS WfpStartCapture(UINT32 TargetPid);
NTSTATUS WfpStopCapture();
BOOLEAN WfpIsCapturing();

// Packet buffer operations
NTSTATUS WfpGetCapturedPackets(
    _Out_writes_bytes_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG BytesWritten
);
NTSTATUS WfpClearPacketBuffer();

// Packet injection
NTSTATUS WfpInjectPacket(
    _In_ const CapturedPacket* Packet
);

// Filter rules
NTSTATUS WfpAddFilterRule(const PacketFilterRule* Rule);
NTSTATUS WfpRemoveFilterRule(UINT32 Index);
NTSTATUS WfpClearFilterRules();
NTSTATUS WfpGetFilterRules(
    _Out_writes_bytes_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG BytesWritten
);

// Capture state
NTSTATUS WfpGetCaptureState(
    _Out_ BOOLEAN* IsCapturing,
    _Out_ ULONG* TargetPid,
    _Out_ ULONG* PacketCount,
    _Out_ ULONG* DroppedCount
);

// WFP Callout functions (internal)
void NTAPI WfpClassifyOutbound(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

void NTAPI WfpClassifyInbound(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

NTSTATUS NTAPI WfpNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER0* filter
);

void NTAPI WfpFlowDeleteFn(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
);
