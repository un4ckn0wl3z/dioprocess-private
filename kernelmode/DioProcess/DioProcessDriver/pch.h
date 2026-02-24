#pragma once

#include <ntifs.h>

// Required for WFP (fwpsk.h needs NDIS types like NET_BUFFER_LIST)
#define NDIS_WDM 1
#define NDIS630 1
#include <ndis.h>

#include <aux_klib.h>
