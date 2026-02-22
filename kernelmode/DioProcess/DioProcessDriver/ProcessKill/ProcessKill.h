#pragma once

#include "../pch.h"

// Forward declarations for process kill handlers
NTSTATUS HandleKillTerminate(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleKillUnmap(PIRP Irp, PIO_STACK_LOCATION irpSp);
NTSTATUS HandleKillPebCorrupt(PIRP Irp, PIO_STACK_LOCATION irpSp);
