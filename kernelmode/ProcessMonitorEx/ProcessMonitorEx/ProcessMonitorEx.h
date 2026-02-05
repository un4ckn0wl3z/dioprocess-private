#pragma once

#include "ProcessMonitorExCommon.h"
#include "FastMutex.h"

#define DRIVER_PREFIX "ProcessMonitorEx: "
#define DRIVER_TAG 'xepw'

struct FullEventData
{
	LIST_ENTRY Link;
	EventData Data;
};

struct ProcessMonitorExState
{
	LIST_ENTRY ItemsHead;
	ULONG ItemCount;
	FastMutex Lock;
};