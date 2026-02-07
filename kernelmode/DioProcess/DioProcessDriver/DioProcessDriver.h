#pragma once

#include "DioProcessCommon.h"
#include "FastMutex.h"

#define DRIVER_PREFIX "DioProcess: "
#define DRIVER_TAG 'oidp'  // 'diop' reversed for little-endian

struct FullEventData
{
	LIST_ENTRY Link;
	EventData Data;
};

struct DioProcessState
{
	LIST_ENTRY ItemsHead;
	ULONG ItemCount;
	FastMutex Lock;
	BOOLEAN CollectionEnabled;
};

// ============== Process Protection Structures ==============

typedef struct _PS_PROTECTION
{
	UCHAR Type : 3;
	UCHAR Audit : 1;
	UCHAR Signer : 4;
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _PROCESS_PROTECTION_INFO
{
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
	PS_PROTECTION Protection;
} PROCESS_PROTECTION_INFO, * PPROCESS_PROTECTION_INFO;

typedef struct _PROCESS_PRIVILEGES
{
	UCHAR Present[8];
	UCHAR Enabled[8];
	UCHAR EnabledByDefault[8];
} PROCESS_PRIVILEGES, * PPROCESS_PRIVILEGES;

// Windows version detection
typedef enum _WINDOWS_VERSION
{
	WINDOWS_UNSUPPORTED,
	WINDOWS_10_1507,		// 10240
	WINDOWS_10_1511,		// 10586
	WINDOWS_10_1607,		// 14393
	WINDOWS_10_1703,		// 15063
	WINDOWS_10_1709,		// 16299
	WINDOWS_10_1803,		// 17134
	WINDOWS_10_1809,		// 17763
	WINDOWS_10_1903,		// 18362
	WINDOWS_10_1909,		// 18363
	WINDOWS_10_2004,		// 19041
	WINDOWS_10_20H2,		// 19042
	WINDOWS_10_21H1,		// 19043
	WINDOWS_10_21H2,		// 19044
	WINDOWS_10_22H2,		// 19045
	WINDOWS_11_21H2,		// 22000
	WINDOWS_11_22H2,		// 22621
	WINDOWS_11_23H2,		// 22631
	WINDOWS_11_24H2			// 26100
} WINDOWS_VERSION;

// Structure offset arrays (indexed by WINDOWS_VERSION)
// Protection offset in EPROCESS
const ULONG PROCESS_PROTECTION_OFFSET[] =
{
	0x00,   // WINDOWS_UNSUPPORTED
	0x67a,  // WINDOWS_10_1507  (10240)
	0x67a,  // WINDOWS_10_1511  (10586)
	0x6c2,  // WINDOWS_10_1607  (14393)
	0x6ca,  // WINDOWS_10_1703  (15063)
	0x6ca,  // WINDOWS_10_1709  (16299)
	0x6ca,  // WINDOWS_10_1803  (17134)
	0x6ca,  // WINDOWS_10_1809  (17763)
	0x6fa,  // WINDOWS_10_1903  (18362)
	0x6fa,  // WINDOWS_10_1909  (18363)
	0x87a,  // WINDOWS_10_2004  (19041)
	0x87a,  // WINDOWS_10_20H2  (19042)
	0x87a,  // WINDOWS_10_21H1  (19043)
	0x87a,  // WINDOWS_10_21H2  (19044)
	0x87a,  // WINDOWS_10_22H2  (19045)
	0x87a,  // WINDOWS_11_21H2  (22000)
	0x87a,  // WINDOWS_11_22H2  (22621)
	0x87a,  // WINDOWS_11_23H2  (22631)
	0x87a   // WINDOWS_11_24H2  (26100)
};

// Token privilege offset in TOKEN
const ULONG PROCESS_PRIVILEGE_OFFSET[] =
{
	0x00,   // WINDOWS_UNSUPPORTED
	0x40,   // WINDOWS_10_1507  (10240)
	0x40,   // WINDOWS_10_1511  (10586)
	0x40,   // WINDOWS_10_1607  (14393)
	0x40,   // WINDOWS_10_1703  (15063)
	0x40,   // WINDOWS_10_1709  (16299)
	0x40,   // WINDOWS_10_1803  (17134)
	0x40,   // WINDOWS_10_1809  (17763)
	0x40,   // WINDOWS_10_1903  (18362)
	0x40,   // WINDOWS_10_1909  (18363)
	0x40,   // WINDOWS_10_2004  (19041)
	0x40,   // WINDOWS_10_20H2  (19042)
	0x40,   // WINDOWS_10_21H1  (19043)
	0x40,   // WINDOWS_10_21H2  (19044)
	0x40,   // WINDOWS_10_22H2  (19045)
	0x40,   // WINDOWS_11_21H2  (22000)
	0x40,   // WINDOWS_11_22H2  (22621)
	0x40,   // WINDOWS_11_23H2  (22631)
	0x40    // WINDOWS_11_24H2  (26100)
};

// DebugPort offset in EPROCESS
const ULONG PROCESS_DEBUGPORT_OFFSET[] =
{
	0x00,   // WINDOWS_UNSUPPORTED
	0x420,  // WINDOWS_10_1507  (10240)
	0x420,  // WINDOWS_10_1511  (10586)
	0x420,  // WINDOWS_10_1607  (14393)
	0x420,  // WINDOWS_10_1703  (15063)
	0x420,  // WINDOWS_10_1709  (16299)
	0x420,  // WINDOWS_10_1803  (17134)
	0x420,  // WINDOWS_10_1809  (17763)
	0x420,  // WINDOWS_10_1903  (18362)
	0x420,  // WINDOWS_10_1909  (18363)
	0x520,  // WINDOWS_10_2004  (19041)
	0x520,  // WINDOWS_10_20H2  (19042)
	0x520,  // WINDOWS_10_21H1  (19043)
	0x520,  // WINDOWS_10_21H2  (19044)
	0x520,  // WINDOWS_10_22H2  (19045)
	0x520,  // WINDOWS_11_21H2  (22000)
	0x520,  // WINDOWS_11_22H2  (22621)
	0x520,  // WINDOWS_11_23H2  (22631)
	0x520   // WINDOWS_11_24H2  (26100)
};

// Peb offset in EPROCESS
const ULONG PROCESS_PEB_OFFSET[] =
{
	0x00,   // WINDOWS_UNSUPPORTED
	0x3f8,  // WINDOWS_10_1507  (10240)
	0x3f8,  // WINDOWS_10_1511  (10586)
	0x3f8,  // WINDOWS_10_1607  (14393)
	0x3f8,  // WINDOWS_10_1703  (15063)
	0x3f8,  // WINDOWS_10_1709  (16299)
	0x3f8,  // WINDOWS_10_1803  (17134)
	0x3f8,  // WINDOWS_10_1809  (17763)
	0x3f8,  // WINDOWS_10_1903  (18362)
	0x3f8,  // WINDOWS_10_1909  (18363)
	0x550,  // WINDOWS_10_2004  (19041)
	0x550,  // WINDOWS_10_20H2  (19042)
	0x550,  // WINDOWS_10_21H1  (19043)
	0x550,  // WINDOWS_10_21H2  (19044)
	0x550,  // WINDOWS_10_22H2  (19045)
	0x550,  // WINDOWS_11_21H2  (22000)
	0x550,  // WINDOWS_11_22H2  (22621)
	0x550,  // WINDOWS_11_23H2  (22631)
	0x550   // WINDOWS_11_24H2  (26100)
};

// ImageFileName offset in EPROCESS (15-char ANSI process name)
const ULONG EPROCESS_IMAGEFILENAME_OFFSET[] =
{
	0x00,   // WINDOWS_UNSUPPORTED
	0x450,  // WINDOWS_10_1507  (10240)
	0x450,  // WINDOWS_10_1511  (10586)
	0x450,  // WINDOWS_10_1607  (14393)
	0x450,  // WINDOWS_10_1703  (15063)
	0x450,  // WINDOWS_10_1709  (16299)
	0x450,  // WINDOWS_10_1803  (17134)
	0x450,  // WINDOWS_10_1809  (17763)
	0x450,  // WINDOWS_10_1903  (18362)
	0x450,  // WINDOWS_10_1909  (18363)
	0x5a8,  // WINDOWS_10_2004  (19041)
	0x5a8,  // WINDOWS_10_20H2  (19042)
	0x5a8,  // WINDOWS_10_21H1  (19043)
	0x5a8,  // WINDOWS_10_21H2  (19044)
	0x5a8,  // WINDOWS_10_22H2  (19045)
	0x5a8,  // WINDOWS_11_21H2  (22000)
	0x5a8,  // WINDOWS_11_22H2  (22621)
	0x5a8,  // WINDOWS_11_23H2  (22631)
	0x5a8   // WINDOWS_11_24H2  (26100)
};

// InheritedFromUniqueProcessId offset in EPROCESS (parent PID)
const ULONG EPROCESS_PARENTPID_OFFSET[] =
{
	0x00,   // WINDOWS_UNSUPPORTED
	0x3e0,  // WINDOWS_10_1507  (10240)
	0x3e0,  // WINDOWS_10_1511  (10586)
	0x3e0,  // WINDOWS_10_1607  (14393)
	0x3e0,  // WINDOWS_10_1703  (15063)
	0x3e0,  // WINDOWS_10_1709  (16299)
	0x3e0,  // WINDOWS_10_1803  (17134)
	0x3e0,  // WINDOWS_10_1809  (17763)
	0x3e0,  // WINDOWS_10_1903  (18362)
	0x3e0,  // WINDOWS_10_1909  (18363)
	0x540,  // WINDOWS_10_2004  (19041)
	0x540,  // WINDOWS_10_20H2  (19042)
	0x540,  // WINDOWS_10_21H1  (19043)
	0x540,  // WINDOWS_10_21H2  (19044)
	0x540,  // WINDOWS_10_22H2  (19045)
	0x540,  // WINDOWS_11_21H2  (22000)
	0x540,  // WINDOWS_11_22H2  (22621)
	0x540,  // WINDOWS_11_23H2  (22631)
	0x540   // WINDOWS_11_24H2  (26100)
};

// Cid.UniqueProcess offset in ETHREAD (thread's owning process)
const ULONG ETHREAD_CID_OFFSET[] =
{
	0x00,   // WINDOWS_UNSUPPORTED
	0x3e8,  // WINDOWS_10_1507  (10240)
	0x3e8,  // WINDOWS_10_1511  (10586)
	0x3e8,  // WINDOWS_10_1607  (14393)
	0x3e8,  // WINDOWS_10_1703  (15063)
	0x3e8,  // WINDOWS_10_1709  (16299)
	0x3e8,  // WINDOWS_10_1803  (17134)
	0x3e8,  // WINDOWS_10_1809  (17763)
	0x3e8,  // WINDOWS_10_1903  (18362)
	0x3e8,  // WINDOWS_10_1909  (18363)
	0x4e0,  // WINDOWS_10_2004  (19041)
	0x4e0,  // WINDOWS_10_20H2  (19042)
	0x4e0,  // WINDOWS_10_21H1  (19043)
	0x4e0,  // WINDOWS_10_21H2  (19044)
	0x4e0,  // WINDOWS_10_22H2  (19045)
	0x4e0,  // WINDOWS_11_21H2  (22000)
	0x4e0,  // WINDOWS_11_22H2  (22621)
	0x4e0,  // WINDOWS_11_23H2  (22631)
	0x4e0   // WINDOWS_11_24H2  (26100)
};

// CallbackList offset in _OBJECT_TYPE (for ObRegisterCallbacks enumeration)
const ULONG OBJECT_TYPE_CALLBACKLIST_OFFSET[] =
{
	0x00,   // WINDOWS_UNSUPPORTED
	0xC8,   // WINDOWS_10_1507  (10240)
	0xC8,   // WINDOWS_10_1511  (10586)
	0xC8,   // WINDOWS_10_1607  (14393)
	0xC8,   // WINDOWS_10_1703  (15063)
	0xC8,   // WINDOWS_10_1709  (16299)
	0xC8,   // WINDOWS_10_1803  (17134)
	0xC8,   // WINDOWS_10_1809  (17763)
	0xC8,   // WINDOWS_10_1903  (18362)
	0xC8,   // WINDOWS_10_1909  (18363)
	0xC8,   // WINDOWS_10_2004  (19041)
	0xC8,   // WINDOWS_10_20H2  (19042)
	0xC8,   // WINDOWS_10_21H1  (19043)
	0xC8,   // WINDOWS_10_21H2  (19044)
	0xC8,   // WINDOWS_10_22H2  (19045)
	0xC8,   // WINDOWS_11_21H2  (22000)
	0xC8,   // WINDOWS_11_22H2  (22621)
	0xC8,   // WINDOWS_11_23H2  (22631)
	0xC8    // WINDOWS_11_24H2  (26100)
};

// ============== Object Callback Internal Structures ==============
// These are undocumented structures used by ObRegisterCallbacks

typedef struct _CALLBACK_ENTRY_ITEM {
	LIST_ENTRY EntryItemList;
	OB_OPERATION Operations;
	struct _CALLBACK_ENTRY* CallbackEntry;
	POBJECT_TYPE ObjectType;
	POB_PRE_OPERATION_CALLBACK PreOperation;
	POB_POST_OPERATION_CALLBACK PostOperation;
	__int64 unk;
} CALLBACK_ENTRY_ITEM, *PCALLBACK_ENTRY_ITEM;

typedef struct _CALLBACK_ENTRY {
	__int16 Version;
	char buffer1[6];
	POB_OPERATION_REGISTRATION RegistrationContext;
	__int16 AltitudeLength1;
	__int16 AltitudeLength2;
	char buffer2[4];
	WCHAR* AltitudeString;
	CALLBACK_ENTRY_ITEM Items;
} CALLBACK_ENTRY, *PCALLBACK_ENTRY;

// ============== Minifilter Internal Structures ==============
// These are undocumented structures from fltmgr.sys

// Forward declarations
typedef struct _FLT_FILTER* PFLT_FILTER;
typedef struct _FLT_INSTANCE* PFLT_INSTANCE;
typedef struct _FLT_VOLUME* PFLT_VOLUME;
typedef struct _FLTP_FRAME* PFLTP_FRAME;

// FLT_OPERATION_REGISTRATION - describes callbacks for a single IRP type
typedef struct _FLT_OPERATION_REGISTRATION_INTERNAL {
	UCHAR MajorFunction;
	UCHAR Padding[3];
	ULONG Flags;
	PVOID PreOperation;   // PFLT_PRE_OPERATION_CALLBACK
	PVOID PostOperation;  // PFLT_POST_OPERATION_CALLBACK
	PVOID Reserved;
} FLT_OPERATION_REGISTRATION_INTERNAL, *PFLT_OPERATION_REGISTRATION_INTERNAL;

// FLT_OBJECT base structure (0x30 bytes)
typedef struct _FLT_OBJECT {
	ULONG Flags;                               // +0x000
	ULONG PointerCount;                        // +0x004
	EX_RUNDOWN_REF RundownRef;                 // +0x008
	LIST_ENTRY PrimaryLink;                    // +0x010 (used in frame's filter list)
	GUID UniqueIdentifier;                     // +0x020
} FLT_OBJECT, *PFLT_OBJECT;

// Simplified FLT_FILTER structure (partial, key fields only)
// FLT_FILTER inherits from FLT_OBJECT (first 0x30 bytes)
typedef struct _FLT_FILTER_PARTIAL {
	FLT_OBJECT Base;                           // +0x000 (0x30 bytes)
	PVOID Frame;                               // +0x030 (PFLTP_FRAME)
	UNICODE_STRING Name;                       // +0x038 (0x10 bytes)
	UNICODE_STRING DefaultAltitude;            // +0x048 (0x10 bytes)
	// ... many more fields follow
} FLT_FILTER_PARTIAL, *PFLT_FILTER_PARTIAL;

// FLT_FILTER offsets (Windows 10/11 x64)
// FLT_FILTER starts with FLT_OBJECT base (0x30 bytes):
//   FLT_OBJECT: Flags(4) | PointerCount(4) | RundownRef(8) | PrimaryLink(16) | UniqueIdentifier(16)
// Then FLT_FILTER specific fields follow at +0x30
#define FLT_FILTER_FLAGS_OFFSET           0x000   // FLT_OBJECT.Flags
#define FLT_FILTER_PRIMARYLINK_OFFSET     0x010   // FLT_OBJECT.PrimaryLink (LIST_ENTRY, used in frame's list)
#define FLT_FILTER_FRAME_OFFSET           0x030   // Ptr64 _FLTP_FRAME
#define FLT_FILTER_NAME_OFFSET            0x038   // UNICODE_STRING FilterName
#define FLT_FILTER_ALTITUDE_OFFSET        0x048   // UNICODE_STRING DefaultAltitude
#define FLT_FILTER_INSTANCE_LIST_OFFSET   0x098   // LIST_ENTRY InstanceList
#define FLT_FILTER_OPERATIONS_OFFSET      0x0D8   // Pointer to FLT_OPERATION_REGISTRATION array
#define FLT_FILTER_NUMINSTANCES_OFFSET    0x090   // ULONG NumberOfInstances

// FLTP_FRAME offsets
#define FLTP_FRAME_FRAMEID_OFFSET          0x000
#define FLTP_FRAME_FILTERLIST_OFFSET       0x048   // LIST_ENTRY RegisteredFilters
#define FLTP_FRAME_LINKS_OFFSET            0x038   // LIST_ENTRY Links (link in global frame list)

// FltGlobals offsets in fltmgr.sys
// We'll pattern scan to find FltGlobals, then access FrameList at offset
#define FLTGLOBALS_FRAMELIST_OFFSET        0x058   // LIST_ENTRY FrameList
