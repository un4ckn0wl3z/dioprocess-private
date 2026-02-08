#include "pch.h"
#include "DioProcessGlobals.h"

// ============== Windows Version Detection ==============

WINDOWS_VERSION GetWindowsVersion()
{
	RTL_OSVERSIONINFOW info;
	info.dwOSVersionInfoSize = sizeof(info);

	NTSTATUS status = RtlGetVersion(&info);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "RtlGetVersion failed (0x%X)\n", status));
		return WINDOWS_UNSUPPORTED;
	}

	KdPrint((DRIVER_PREFIX "Windows Build: %d.%d (Build %d)\n",
		info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber));

	// Only support Windows 10/11 (major version 10)
	if (info.dwMajorVersion != 10)
	{
		KdPrint((DRIVER_PREFIX "Unsupported Windows major version: %d\n", info.dwMajorVersion));
		return WINDOWS_UNSUPPORTED;
	}

	// Map build number to version
	switch (info.dwBuildNumber)
	{
	case 10240: return WINDOWS_10_1507;
	case 10586: return WINDOWS_10_1511;
	case 14393: return WINDOWS_10_1607;
	case 15063: return WINDOWS_10_1703;
	case 16299: return WINDOWS_10_1709;
	case 17134: return WINDOWS_10_1803;
	case 17763: return WINDOWS_10_1809;
	case 18362: return WINDOWS_10_1903;
	case 18363: return WINDOWS_10_1909;
	case 19041: return WINDOWS_10_2004;
	case 19042: return WINDOWS_10_20H2;
	case 19043: return WINDOWS_10_21H1;
	case 19044: return WINDOWS_10_21H2;
	case 19045: return WINDOWS_10_22H2;
	case 22000: return WINDOWS_11_21H2;
	case 22621: return WINDOWS_11_22H2;
	case 22631: return WINDOWS_11_23H2;
	case 26100: return WINDOWS_11_24H2;
	default:
		// For newer builds, try to use the closest known version
		if (info.dwBuildNumber > 26100)
		{
			return WINDOWS_11_24H2; // Use latest known offsets
		}
		else if (info.dwBuildNumber >= 22000)
		{
			return WINDOWS_11_21H2; // Windows 11 range
		}
		else if (info.dwBuildNumber >= 19041)
		{
			return WINDOWS_10_2004; // Windows 10 20H1+ range
		}
		return WINDOWS_UNSUPPORTED;
	}
}
