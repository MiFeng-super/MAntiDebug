#include "pch.h"
#include "MAntiDebug.h"

MAntiDebug* pThis = nullptr;


MAntiDebug& MAntiDebug::getInstance(HMODULE hModule, uint32_t flag)
{
	static MAntiDebug* instance = new MAntiDebug(hModule, flag);
	return *instance;
}


MAntiDebug::MAntiDebug(HMODULE hModule, uint32_t flag)
{
	pThis = this;

	m_hModule = hModule;
	m_flags = flag;

	PROCESS_BASIC_INFORMATION info = { 0 };

	x64::initialize();
}



MAntiDebug::~MAntiDebug() 
{

}

bool MAntiDebug::initialize()
{
	if (m_initialize)
	{
		return true;
	}

	if (m_flags & flags::CheckSum)
	{
		if (IsBadReadPtr(m_hModule, sizeof(void*)) == 0)
		{
			auto ntHeader  = RtlImageNtHeader(m_hModule);
			auto secHeader = IMAGE_FIRST_SECTION(ntHeader);

			m_secInfo.clear();

			for (uint16_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, secHeader++)
			{
				if ((secHeader->Characteristics & IMAGE_SCN_MEM_READ)
					&& !(secHeader->Characteristics & IMAGE_SCN_MEM_WRITE))
				{
					section_info info
					{
						(uintptr_t)m_hModule + secHeader->VirtualAddress,
						secHeader->Misc.VirtualSize,
						crc32((PVOID)((uintptr_t)m_hModule + secHeader->VirtualAddress), secHeader->Misc.VirtualSize)
					};

					m_secInfo.push_back(info);
				}
			}
		}
	}


	m_initialize = true;

	return true;
}

bool MAntiDebug::execute(Notification notification)
{
	if (!m_initialize)
	{
		return false;
	}


	if (m_flags & flags::CheckSum) 
	{
		bool result = false;

		for (const auto& item : m_secInfo)
		{
			if (crc32((PVOID)item.vAddress, item.vSize) != item.crc)
			{
				result = true;
				break;
			}
		}

		notification("check section sum", result);
	}

	if (m_flags & flags::DebugFlags)
	{
		{
			notification("check IsDebuggerPresent API ()", IsDebuggerPresent());
		}

		{
			BOOL is = FALSE;
			CheckRemoteDebuggerPresent(NtCurrentProcess(), &is);
			notification("check CheckRemoteDebuggerPresent API ()", is);
		}

		{
			DWORD debugPort = 0;
			DWORD length	= 0;

			NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), &length);
			notification("check NtQuerySystemInformation with ProcessDebugPort", debugPort != 0);
		}

		{
			DWORD debugFlags = 0;
			DWORD length = 0;

			NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugFlags, &debugFlags, sizeof(debugFlags), &length);
			notification("check NtQuerySystemInformation with ProcessDebugFlags", debugFlags == 0);
		}

		{
			HANDLE hDebugObject = 0;
			DWORD length = 0;

			NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugObjectHandle, &hDebugObject, sizeof(hDebugObject), &length);
			notification("check NtQuerySystemInformation with ProcessDebugObjectHandle", hDebugObject != nullptr);
		}

		{
			SYSTEM_KERNEL_DEBUGGER_INFORMATION info{ 0 };
			DWORD length = 0;

			NtQuerySystemInformation(SystemKernelDebuggerInformation, &info, sizeof(info), &length);

			notification("check NtQuerySystemInformation with SystemKernelDebuggerInformation", info.KernelDebuggerNotPresent == 0);
		}

		{
			notification("check PEB.BeingDebugged", NtCurrentPeb()->BeingDebugged == 1);
		}

		{
			notification("check PEB.NtGlobalFlag", NtCurrentPeb()->NtGlobalFlag & 0x70);
		}

		{
			auto heap = (uintptr_t*)NtCurrentPeb()->ProcessHeap;
#ifdef _WIN64
			notification("check ProcessHeap.flags", *(uint32_t*)(heap + (IsWindowsVistaOrGreater() ? 0x70 : 0x40)) > 2);
#else
			notification("check ProcessHeap.flags", *(uint32_t*)(heap + (IsWindowsVistaOrGreater() ? 0x40 : 0x0C)) > 2);
#endif // _WIN64
		}

		{
			auto heap = (uintptr_t*)NtCurrentPeb()->ProcessHeap;
#ifdef _WIN64
			notification("check ProcessHeap.forceFlags", *(uint32_t*)(heap + (IsWindowsVistaOrGreater() ? 0x74 : 0x18)) > 0);
#else
			notification("check ProcessHeap.forceFlags", *(uint32_t*)(heap + (IsWindowsVistaOrGreater() ? 0x44 : 0x10)) > 0);
#endif // _WIN64
		}
	}

	if (m_flags & flags::ObjectHandles)
	{
		{
			typedef DWORD(WINAPI* fnCsrGetProcessId)();

			auto result = false;
			auto CsrGetProcessId = (fnCsrGetProcessId)utils::GetProcAddress("ntdll.dll", "CsrGetProcessId");
			if (CsrGetProcessId)
			{
				HANDLE hCsr = OpenProcess(PROCESS_ALL_ACCESS, false, CsrGetProcessId());
				if (hCsr)
				{
					CloseHandle(hCsr);
				}
			}

			notification("check OpenProcess with CsrGetProcessId", result);
		}

		{
			auto result = false;
			auto fullName = utils::GetCurrentFullName();
			HANDLE hFile = CreateFile(fullName.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, 0);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				CloseHandle(hFile);
			}
			else 
			{
				result = true;
			}

			notification("check CreateFile API()", result);
		}

		{
			[=]()
			{
				auto result = false;
				__try
				{
#ifdef _WIN64
					x64::NtClose((HANDLE)0x99999999ULL);
#else
					NtClose((HANDLE)0x99999999ULL);
#endif // !_WIN64
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					result = true;
				}

				notification("check CloseHandle with an invalide handle", result);
			}();
		}

		{
			[=]() 
			{
				auto result = false;
				HANDLE hMutex = CreateMutex(nullptr, false, "random name");
				if (hMutex)
				{
					SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
					__try 
					{
						CloseHandle(hMutex);
					}
					__except (EXCEPTION_EXECUTE_HANDLER) 
					{
						result = true;
					}
				}

				notification("check CloseHandle with protected handle trick", result);
			}();
		}
	}

	if (m_flags & flags::Exception)
	{
		{
			static bool is = true;
			is = true;
			auto old = SetUnhandledExceptionFilter([](_EXCEPTION_POINTERS* ExceptionInfo) -> LONG
			{
				if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
				{
					is = false;
#ifdef _WIN64
					ExceptionInfo->ContextRecord->Rip++;
#else
					ExceptionInfo->ContextRecord->Eip++;
#endif // !_WIN64
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				return EXCEPTION_CONTINUE_SEARCH;
			});
			__debugbreak();
			SetUnhandledExceptionFilter(old);
			notification("check UnhandledExceptionFilter", is);
		}

		{
			[=]()
			{
				auto result = false;
				__try
				{
					RaiseException(DBG_CONTROL_C, 0, 0, NULL);
					result = true;
				}
				__except (DBG_CONTROL_C == GetExceptionCode()
					? EXCEPTION_EXECUTE_HANDLER
					: EXCEPTION_CONTINUE_SEARCH)
				{
					result = false;
				}
				notification("check RaiseException with DBG_CONTROL_C", result);
			}();
		}
	}

	if (m_flags & flags::Timing)
	{
		{
			auto tick = GetTickCount();
			auto func = [](PVOID) -> DWORD { return 0; };

			HANDLE handles[] =
			{
				CreateThread(nullptr, 0, func, nullptr, 0, nullptr),
				CreateThread(nullptr, 0, func, nullptr, 0, nullptr),
				CreateThread(nullptr, 0, func, nullptr, 0, nullptr),
			};
			WaitForMultipleObjects(std::size(handles), handles, true, INFINITE);
			auto diff = GetTickCount() - tick;

			for (const auto& item : handles)
			{
				CloseHandle(item);
			}

			CString str;
			str.Format("check GetTickCount with create thread£º%d tick", diff);

			notification(str, diff > 30);
		}
	}

	if (m_flags & flags::Memory)
	{
		{
			constexpr const size_t size = 50;

			const auto address = (uint8_t*)utils::GetCurrentIP() - (size / 2);

			std::span<uint8_t> s (address, size);

			volatile uint8_t i = 0xCB;
			volatile bool result = std::find(s.begin(), s.end(), i + 1) != s.end();

			notification("check Software breakpoints ", result);
		}

		{
			bool result = false;
			CONTEXT context{ 0 };

			context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
			if (GetThreadContext(NtCurrentThread(), &context))
			{
				if (context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3)
				{
					result = true;
				}
			}

			notification("check Hardware breakpoints ", result);
		}

		{
			[=]() 
			{
				bool result = false;
				PVOID buffer = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (buffer)
				{
					memset(buffer, 0xC3, 1);

					DWORD oldProtect;

					if (VirtualProtect(buffer, 1, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &oldProtect))
					{
						__try
						{
							((void(*)())buffer)();
							result = true;
						}
						__except (EXCEPTION_EXECUTE_HANDLER)
						{
							;
						}
					}

					VirtualFree(buffer, 0, MEM_RELEASE);
				}
				notification("check Memory breakpoints ", result);
			}();
		}

		{
			bool result = true;
			PVOID func = utils::GetProcAddress("ntdll.dll", "DbgBreakPoint");
			if (func)
			{
				DWORD oldProtect;
				
				if (VirtualProtect(func, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
				{

					*(uint8_t*)func = 0xC3;
					result = false;
					VirtualProtect(func, 1, oldProtect, &oldProtect);
				}
			}

			notification("patch DbgBreakPoint API", result);
		}

		{
			//
			// xor eax, eax
			// jmp eax
			//
			const uint8_t patchs[] = { 49,192,255,224 };

			bool result = true;
			PVOID func = utils::GetProcAddress("ntdll.dll", "DbgUiRemoteBreakin");
			if (func)
			{
				DWORD oldProtect;

				if (VirtualProtect(func, sizeof(patchs), PAGE_EXECUTE_READWRITE, &oldProtect))
				{
					memcpy(func, patchs, sizeof(patchs));

					result = false;
					VirtualProtect(func, sizeof(patchs), oldProtect, &oldProtect);
				}
			}

			notification("patch DbgUiRemoteBreakin API", result);
		}
	}

	if (m_flags & flags::Instruct)
	{
		{
			static bool result = true;

			auto handle = AddVectoredExceptionHandler(1, [](_EXCEPTION_POINTERS* ExceptionInfo) -> LONG
			{
					if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
					{
#ifdef _WIN64
						ExceptionInfo->ContextRecord->Rip++;
#else
						ExceptionInfo->ContextRecord->Eip++;
#endif
						result = false;
						return EXCEPTION_CONTINUE_EXECUTION;
					}
					return EXCEPTION_CONTINUE_SEARCH;
			});

			__debugbreak();

			RemoveVectoredExceptionHandler(handle);

			notification("check Int 3", result);
		}

		{
			static bool result = IsWindowsVistaOrGreater();

			auto handle = AddVectoredExceptionHandler(1, [](_EXCEPTION_POINTERS* ExceptionInfo) -> LONG
				{
					if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
					{
						result = false;
						return EXCEPTION_CONTINUE_EXECUTION;
					}
					return EXCEPTION_CONTINUE_SEARCH;
				});

			utils::Int2D();

			RemoveVectoredExceptionHandler(handle);

			notification("check Int 0x2D", result);
		}
	}

	if (m_flags && flags::Interaction)
	{
		{
			bool result = true;
			NTSTATUS status = 0;

			do 
			{
				status = NtSetInformationThread(NtCurrentThread(), ThreadHideFromDebugger, nullptr, 123456);
				if (NT_SUCCESS(status))
				{
					break;
				}

				status = NtSetInformationThread(NtCurrentProcess(), ThreadHideFromDebugger, nullptr, 0);
				if (NT_SUCCESS(status))
				{
					break;
				}

				status = NtSetInformationThread(NtCurrentThread(), ThreadHideFromDebugger, nullptr, 0);
				if (NT_SUCCESS(status))
				{
					if (IsWindowsVistaOrGreater())
					{
						alignas(4) bool value;

						status = NtQueryInformationThread(NtCurrentThread(), ThreadHideFromDebugger, &value, sizeof(value), nullptr);
						if (NT_SUCCESS(status))
						{
							result = !value;
						}
					}
					else
					{
						result = false;
					}
				}
			} while (false);

			notification("check NtSetInformationThread with ThreadHideFromDebugger", result);
		}

		{
			auto error = GetLastError();
			OutputDebugString("mifeng");
			notification("check OutputDebugString API ()", IsWindowsXPOr2k() ? GetLastError() == error : false);
		}
	}

	if (m_flags & flags::Misc)
	{
		{
			bool result = false;
			std::initializer_list<const char*> windowClass =
			{
				"OLLYDBG",
				"1212121",
				"WinDbgFrameClass", // WinDbg
				"ID",               // Immunity Debugger
				"Zeta Debugger",
				"Rock Debugger",
				"ObsidianGUI",
			};

			for (const auto& item : windowClass)
			{
				if (FindWindow(item, nullptr))
				{
					result = true;
				}
			}

			notification("check FindWindow API ()", result);
		}

		{
			bool result = false;
			HWND hShell = ::GetShellWindow();

			if (hShell)
			{
				DWORD dwProcessId = 0;
				GetWindowThreadProcessId(hShell, &dwProcessId);

				PROCESS_BASIC_INFORMATION info { 0 };

				auto status = NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &info, sizeof(info), nullptr);
				if (NT_SUCCESS(status))
				{
					if (dwProcessId != (uintptr_t)info.InheritedFromUniqueProcessId)
					{
						result = true;
					}
				}
			}

			notification("check If Parent Process is explorer.exe", result);
		}
	}

	if (m_flags & flags::AntiPlugin)
	{
		{
			auto status = x64::NtSetInformationThread(NtCurrentProcess(), ThreadHideFromDebugger, (PVOID)sizeof(PVOID), sizeof(PVOID));
			notification("check StrongOD Plugin", status == 0);
		}

		{
			bool result = false;
			if (x64::isWow64)
			{
				TEB64 teb64;
				PEB64 peb64;

				getMem64(&teb64, getTEB64(), sizeof(teb64));
				getMem64(&peb64, teb64.ProcessEnvironmentBlock, sizeof(peb64));

				result = peb64.BeingDebugged;
			}

			notification("check PhantOm Plugin", result);
		}

		{
			bool result = false;
			NTSTATUS status = 0;
			HANDLE   hDebug = nullptr;
			OBJECT_ATTRIBUTES attr{ 0 };

			attr.Length = sizeof(attr);

			status = NtCreateDebugObject(&hDebug, DEBUG_READ_EVENT, &attr, DEBUG_KILL_ON_CLOSE);
			if (NT_SUCCESS(status))
			{
				auto buffer = std::make_unique<uint8_t[]>(0x1000);
				auto info   = (POBJECT_TYPE_INFORMATION)buffer.get();
				ULONG retLength = 0;

				status = NtQueryObject(hDebug, ObjectTypeInformation, buffer.get(), 0x1000, &retLength);
				if (NT_SUCCESS(status))
				{
					result = info->TotalNumberOfHandles == 0 || info->TotalNumberOfObjects == 0;
				}

				NtClose(hDebug);
			}
			notification("check titanHide Plugin", result);
		}
	}

	if (m_flags & flags::Syscall)
	{
		{
			if (x64::isWow64)
			{
				uint64_t debugPort = 0;
				x64::NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), nullptr);
				notification("check Syscall NtQuerySystemInformation with ProcessDebugPort", debugPort != 0);
			}
			else
			{
				uintptr_t debugPort = 0;
				x64::NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), nullptr);
				notification("check Syscall NtQuerySystemInformation with ProcessDebugPort", debugPort != 0);
			}
		}

		{
			DWORD debugFlags = 0;
			x64::NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugFlags, &debugFlags, sizeof(debugFlags), nullptr);
			notification("check Syscall NtQuerySystemInformation with ProcessDebugFlags", debugFlags == 0);
		}

		{
			if (x64::isWow64)
			{
				uint64_t debugHandle = 0;
				x64::NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugObjectHandle, &debugHandle, sizeof(debugHandle), nullptr);
				notification("check Syscall NtQuerySystemInformation with ProcessDebugObjectHandle", debugHandle != 0);
			}
			else
			{
				uintptr_t debugHandle = 0;
				x64::NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugObjectHandle, &debugHandle, sizeof(debugHandle), nullptr);
				notification("check Syscall NtQuerySystemInformation with ProcessDebugObjectHandle", debugHandle != 0);
			}
		}
	}

	return true;
}
