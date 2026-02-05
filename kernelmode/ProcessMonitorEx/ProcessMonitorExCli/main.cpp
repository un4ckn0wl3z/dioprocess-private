#include <Windows.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include "..\ProcessMonitorEx\ProcessMonitorExCommon.h"

void DisplayData(const BYTE* buffer, DWORD size);
void DisplayTime(ULONG64 time);


int main()
{
	std::cout << R"(

  _____                             __  __             _ _             ______      
 |  __ \                           |  \/  |           (_) |           |  ____|     
 | |__) | __ ___   ___ ___  ___ ___| \  / | ___  _ __  _| |_ ___  _ __| |__  __  __
 |  ___/ '__/ _ \ / __/ _ \/ __/ __| |\/| |/ _ \| '_ \| | __/ _ \| '__|  __| \ \/ /
 | |   | | | (_) | (_|  __/\__ \__ \ |  | | (_) | | | | | || (_) | |  | |____ >  < 
 |_|   |_|  \___/ \___\___||___/___/_|  |_|\___/|_| |_|_|\__\___/|_|  |______/_/\_\

 The kernelmode process monitor developed by un4ckn0wl3z
)" << std::endl;

	HANDLE hDevice = CreateFile(
		L"\\\\.\\ProcessMonitorEx",
		GENERIC_READ,
		0,
		nullptr,
		OPEN_EXISTING,
		0,
		nullptr
	);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("Error in CreateFile (%u)\n", GetLastError());
		return -1;
	}

	BYTE buffer[1 << 16];

	for (;;)
	{
		DWORD read;
		if(!(ReadFile(
			hDevice,
			buffer,
			sizeof(buffer),
			&read,
			nullptr)))
		{
			break;
		}

		if (read)
		{
			DisplayData(buffer, read);
		}


		Sleep(1000);
	}


	CloseHandle(hDevice);
}

void DisplayData(const BYTE* buffer, DWORD size)
{
	while (size > 0)
	{
		auto data = (EventData*)buffer;
		DisplayTime(data->Header.Timestamp);

		switch (data->Header.Type)
		{
		case EventType::ProcessExit:
		{
			auto& info = data->ProcessExit;
			printf("Process Exit: PID: %u Exit Code: %u\n", info.ProcessId, info.ExitCode);
			break;
		}
		case EventType::ProcessCreate:
		{
			auto& info = data->ProcessCreate;
			printf("Process Create: PID: %u PPID: %u CPID: %u CMD: %ws\n",
				info.ProcessId,
				info.ParentProcessId,
				info.CreatingProcessId,
				std::wstring(info.CommandLine, info.CommandLineLength).c_str()
			);


			break;
		}
		case EventType::ThreadCreate:
		{
			auto& info = data->ThreadCreate;
			printf("Thread Create: PID: %u TID: %u\n",
				info.ProcessId,
				info.ThreadId
			);
			break;
		}
		case EventType::ThreadExit:
		{
			auto& info = data->ThreadExit;
			printf("Thread Exit: PID: %u TID: %u ExitCode: %u\n",
				info.ProcessId,
				info.ThreadId,
				info.ExitCode
			);
			break;
		}
		default:
			break;
		}

		buffer += data->Header.Size;
		size -= data->Header.Size;
	}
}

void DisplayTime(ULONG64 time)
{
	auto ft = *(FILETIME*)&time;
	FileTimeToLocalFileTime(&ft, &ft);
	SYSTEMTIME st;
	FileTimeToSystemTime(&ft, &st);
	printf("%02d:%02d:%02d.%03d ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}
