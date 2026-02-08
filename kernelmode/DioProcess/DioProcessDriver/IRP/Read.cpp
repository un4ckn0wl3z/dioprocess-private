#include "pch.h"
#include "DioProcessGlobals.h"
#include "Locker.h"

// ============== IRP Read Handler ==============

NTSTATUS DioProcessRead(PDEVICE_OBJECT, PIRP Irp)
{
	auto irpSp = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;
	auto info = 0;
	do
	{
		auto len = irpSp->Parameters.Read.Length;
		if (len < sizeof(FullEventData))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		NT_ASSERT(Irp->MdlAddress);
		auto buffer = (PUCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		if (!buffer)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		Locker locker(g_State.Lock);
		while (!IsListEmpty(&g_State.ItemsHead))
		{
			auto link = g_State.ItemsHead.Flink;
			if (!link)
				break;

			auto item = CONTAINING_RECORD(link, FullEventData, Link);
#pragma warning(suppress: 6001)
			auto size = item->Data.Header.Size;
			if (size > len)
			{
				break;
			}
			memcpy(buffer, &item->Data, size);
			buffer += size;
			len -= size;
			info += size;
			link = RemoveHeadList(&g_State.ItemsHead);
			g_State.ItemCount--;
			ExFreePool(CONTAINING_RECORD(link, FullEventData, Link));
		}

	} while (false);

	return CompleteRequest(Irp, status, info);
}
