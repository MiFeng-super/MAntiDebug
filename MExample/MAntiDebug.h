#pragma once

#include "utils.h"

//
// flags
//
enum flags
{
	CheckSum		= (1 << 0),
	DebugFlags		= (1 << 1),
	ObjectHandles	= (1 << 2),
	Exception		= (1 << 3),
	Timing			= (1 << 4),
	Memory			= (1 << 5),
	Instruct		= (1 << 7),
	Interaction		= (1 << 8),
	Misc			= (1 << 9),
	AntiPlugin		= (1 << 10),
	Syscall			= (1 << 11),
	ALL				= CheckSum | DebugFlags | ObjectHandles | Exception | Timing | Memory | Instruct | Interaction | Misc | AntiPlugin | Syscall,
};

typedef struct _section_info
{
	uintptr_t vAddress;
	uint32_t  vSize;
	uint32_t  crc;
}section_info;

typedef void(* Notification)(const char* describe, bool isDebug);

class MAntiDebug
{


private:
	HMODULE		m_hModule;
	uint32_t	m_flags;

	bool		m_initialize			= false;

	std::vector<section_info> m_secInfo;


public:
	static MAntiDebug& getInstance(HMODULE hModule, uint32_t flag);


	MAntiDebug(HMODULE hModule, uint32_t flag);
	~MAntiDebug();

	bool initialize();
	bool execute(Notification notification);
};

