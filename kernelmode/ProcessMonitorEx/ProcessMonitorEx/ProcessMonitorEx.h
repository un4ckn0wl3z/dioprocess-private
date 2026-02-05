#pragma once

#include "ProcessMonitorExCommon.h"
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
};