#include "pch.h"
#include "DioProcessGlobals.h"
#include "Locker.h"

// ============== IRP Create/Close Handlers ==============

NTSTATUS DioProcessCreateClose(PDEVICE_OBJECT, PIRP Irp)
{
	return CompleteRequest(Irp);
}
