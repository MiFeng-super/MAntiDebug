#include "pch.h"
#include "utils.h"

void utils::GetSystemInfo(_Out_ LPSYSTEM_INFO lpSystemInfo)
{
	static auto fnGetNativeSystemInfo
		= (decltype(&GetNativeSystemInfo))GetProcAddress("kernel32.dll", "GetNativeSystemInfo");

	if (fnGetNativeSystemInfo)
	{
		fnGetNativeSystemInfo(lpSystemInfo);
	}
	else
	{
		::GetSystemInfo(lpSystemInfo);
	}
}


bool utils::Wow64DisableWow64FsRedirection(PVOID& value)
{
	static auto func =
		(decltype(&::Wow64DisableWow64FsRedirection))
		GetProcAddress("kernel32.dll", "Wow64DisableWow64FsRedirection");

	if (func)
	{
		func(&value);
		return true;
	}

	return false;
}


bool utils::Wow64RevertWow64FsRedirection(PVOID& value)
{
	static auto func =
		(decltype(&::Wow64RevertWow64FsRedirection))
		GetProcAddress("kernel32.dll", "Wow64RevertWow64FsRedirection");

	if (func)
	{
		func(&value);
		return true;
	}

	return false;
}

PVOID utils::GetProcAddress(const char* dllName, const char* funcName)
{
	HMODULE hModule = LoadLibraryA(dllName);
	if (hModule)
	{
		return utils::GetProcAddress(hModule, funcName);
	}
	return nullptr;
}

PVOID utils::GetProcAddress(HMODULE hModule, const char* funcName)
{
	return ::GetProcAddress(hModule, funcName);
}

std::string utils::GetCurrentFullName()
{
	std::string result(MAX_PATH + 1, '\0');

	GetModuleFileName(nullptr, result.data(), MAX_PATH);

	return result;
}


uint32_t x64::v2f(uint8_t* file, uint32_t va)
{
	auto ntHeader = RtlImageNtHeader(file);
	auto secHeader = IMAGE_FIRST_SECTION(ntHeader);

	for (uint16_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, secHeader++)
	{
		if (secHeader->VirtualAddress <= va
			&& va < (secHeader->VirtualAddress + secHeader->Misc.VirtualSize))
		{
			return (va - secHeader->VirtualAddress) + secHeader->PointerToRawData;
		}
	}

	return uint32_t();
}

uint32_t x64::f2v(uint8_t* file, uint32_t f)
{
	auto ntHeader = RtlImageNtHeader(file);
	auto secHeader = IMAGE_FIRST_SECTION(ntHeader);

	for (uint16_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, secHeader++)
	{
		if (secHeader->PointerToRawData >= f
			&& f < (secHeader->PointerToRawData + secHeader->Misc.VirtualSize))
		{
			return (f - secHeader->VirtualAddress) + secHeader->VirtualAddress;
		}
	}

	return uint32_t();
}


void x64::initialize()
{
	static std::once_flag flags;

	std::call_once(flags, []()
	{
		SYSTEM_INFO si;
		utils::GetSystemInfo(&si);

		isArch64 = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
			|| si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64;

		IsWow64Process(GetCurrentProcess(), &isWow64);

		if (isArch64 && isWow64)
		{
			isWow64FsReDriectory = true;
		}

		heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
		if (!heap)
		{
			return;
		}

		PVOID   value = nullptr;
		HANDLE	hFile = nullptr;
		char	sysDir[MAX_PATH] = { 0 };
		GetSystemDirectoryA(sysDir, MAX_PATH);
		strcat_s(sysDir, "\\ntdll.dll");

		if (isWow64FsReDriectory)
		{
			utils::Wow64DisableWow64FsRedirection(value);
		}

		hFile = CreateFileA(sysDir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			return;
		}

		DWORD dwRead = 0;

		ntSize = GetFileSize(hFile, nullptr);
		ntFile = new uint8_t[ntSize];

		ReadFile(hFile, ntFile, ntSize, &dwRead, nullptr);
		CloseHandle(hFile);

		if (isWow64FsReDriectory)
		{
			utils::Wow64RevertWow64FsRedirection(value);
		}

		isInitialize = true;
	});
}


uint32_t x64::getIndex(const uint32_t h)
{
	if (isInitialize)
	{
		uint8_t* func = nullptr;

		if (isArch64)
		{
			auto ntHeader = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(ntFile);
			auto exportDir = (PIMAGE_EXPORT_DIRECTORY)(ntFile + v2f(ntFile, ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress));
			auto nameDir = (uint32_t*)(ntFile + v2f(ntFile, exportDir->AddressOfNames));
			auto nameOrdinal = (uint16_t*)(ntFile + v2f(ntFile, exportDir->AddressOfNameOrdinals));
			auto funcDir = (uint32_t*)(ntFile + v2f(ntFile, exportDir->AddressOfFunctions));

			for (size_t i = 0; i < exportDir->NumberOfNames; i++)
			{
				auto name = (const char*)(ntFile + v2f(ntFile, nameDir[i]));

				if (h == hash_dynamic(name))
				{
					func = (ntFile + v2f(ntFile, funcDir[nameOrdinal[i]]));
					break;
				}
			}
		}
		else
		{
			auto ntHeader = (PIMAGE_NT_HEADERS)RtlImageNtHeader(ntFile);
			auto exportDir = (PIMAGE_EXPORT_DIRECTORY)(ntFile + v2f(ntFile, ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress));
			auto nameDir = (uint32_t*)(ntFile + v2f(ntFile, exportDir->AddressOfNames));
			auto nameOrdinal = (uint16_t*)(ntFile + v2f(ntFile, exportDir->AddressOfNameOrdinals));
			auto funcDir = (uint32_t*)(ntFile + v2f(ntFile, exportDir->AddressOfFunctions));

			for (size_t i = 0; i < exportDir->NumberOfNames; i++)
			{
				auto name = (const char*)(ntFile + v2f(ntFile, nameDir[i]));

				if (h == hash_dynamic(name))
				{
					func = (ntFile + v2f(ntFile, funcDir[nameOrdinal[i]]));
					break;
				}
			}
		}

		if (func)
		{
			ldasm_data ld = { 0 };
			size_t len = 0;
			while (true)
			{
				len = ldasm(func, &ld, isArch64);
				if (len == 5 && *func == 0xB8)	// mov eax, xxxxx
				{
					return *(uint32_t*)(func + 1);
				}

				func += len;
			}
		}
	}

	return -1;
}

uintptr_t x64::getFunction(const uint32_t h)
{
	uint32_t index = getIndex(h);
	if (index != -1)
	{
		if (isArch64)
		{
			unsigned char sysCall64[] = {
				0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,xxx
				0x4C, 0x8B, 0xD1,           // mov r10,rcx
				0x0F, 0x05,                 // syscall
				0xC3                        // retn
			};

			*(uint32_t*)&sysCall64[1] = index;
			PVOID func = HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(sysCall64));
			memcpy(func, sysCall64, sizeof(sysCall64));
			return (uintptr_t)func;
		}
		else
		{
			unsigned char sysCall32[] = {
				0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,xxx
				0xE8, 0x1, 0x0, 0x0, 0x0,   // call sysentry
				0xC3,						// retn
				// sysenter:
				0x8B, 0xD4,                 // mov edx,esp
				0x0F, 0x34,                 // sysenter
				0xC3                        // retn
			};

			*(uint32_t*)&sysCall32[1] = index;
			PVOID func = HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(sysCall32));
			memcpy(func, sysCall32, sizeof(sysCall32));
			return (uintptr_t)func;
		}
	}

	return uintptr_t();
}
