#pragma once

enum class EventType
{
	ProcessCreate,
	ProcessExit,
	ThreadCreate,
	ThreadExit
};

struct EventHeader
{
	EventType Type;
	ULONG Size;
	ULONG64 Timestamp;
};

struct ProcessCreateInfo
{
	ULONG ProcessId;
	ULONG ParentProcessId;
	ULONG CreatingProcessId;
	ULONG CommandLineLength;
	WCHAR CommandLine[1];
};

struct ProcessExitInfo
{
	ULONG ProcessId;
	ULONG ExitCode;
};

struct ThreadCreateInfo
{
	ULONG ProcessId;
	ULONG ThreadId;
};

struct ThreadExitInfo : ThreadCreateInfo
{
	ULONG ExitCode;
};

struct EventData
{
	EventHeader Header;
	union 
	{
		ProcessCreateInfo ProcessCreate;
		ProcessExitInfo ProcessExit;
		ThreadCreateInfo ThreadCreate;
		ThreadExitInfo ThreadExit;
	};
};