#pragma once
#include <mutex>
#include <vector>
#include <tuple>
#include <string>
#include <span>
#include <intrin.h>
#include "include/Veil-main/Veil.h"
#include "include/crc32.h"
#include "include/ldasm.h"
#include "wow64ext.h"
#include "include/VersionHelpers.h"

namespace AnyCall
{
	template <typename T, typename... Args>
	T cd_call(uintptr_t address, Args... args)
	{
		typedef T(__cdecl* Func)(Args...);
		auto func = (Func)address;
		return func(std::forward<Args>(args)...);
	}

	template <typename T, typename... Args>
	T std_call(uintptr_t address, Args... args)
	{
		typedef T(__stdcall* Func)(Args...);
		auto func = (Func)address;
		return func(std::forward<Args>(args)...);
	}

	template <typename T, typename C, typename... Args>
	T this_call(C* This, uintptr_t address, Args... args)
	{
		typedef T(__thiscall* Func)(PVOID, Args...);
		auto func = (Func)address;
		return func(This, std::forward<Args>(args)...);
	}
};

struct hash_const
{
	uint32_t result;
	template <uint32_t len>
	constexpr __forceinline hash_const(const char(&e)[len]) : hash_const(e, std::make_index_sequence<len - 1>()) {}
	template <uint32_t len>
	constexpr __forceinline hash_const(const wchar_t(&e)[len]) : hash_const(e, std::make_index_sequence<len - 1>()) {}
	template <typename T, uint32_t len>
	constexpr __forceinline hash_const(const T(&e)[len]) : hash_const(e, std::make_index_sequence<len>()) {}
	template <typename T, uint32_t... ids>
	constexpr __forceinline hash_const(const T e, std::index_sequence<ids...>) : hash_const(0, e[ids]...) {}
	template <typename T, typename... T_>
	constexpr __forceinline hash_const(uint32_t result_, const T elem, const T_... elems) : hash_const(((result_ >> 13) | (result_ << 19)) + elem, elems...) {}
	constexpr __forceinline hash_const(uint32_t result_) : result(result_) {}
	operator uint32_t () { return result; }
};

struct hash_dynamic
{
	uint32_t result;

	template <typename T, typename = std::enable_if_t<std::is_same_v<T, char> | std::is_same_v<T, wchar_t>>>
	hash_dynamic(const T* str)
		: result(0)
	{
		while (*str)
		{
			result = ((result >> 13) | (result << 19)) + *str;
			str++;
		}
	}
	template <typename T>
	hash_dynamic(const T* elems, size_t size)
		: result(0)
	{
		for (size_t i = 0; i < size; i++)
		{
			result = ((result >> 13) | (result << 19)) + elems[i];
		}
	}
	operator uint32_t () { return result; }
};


namespace utils
{
	//
	// 获取系统信息
	//
	void GetSystemInfo(_Out_ LPSYSTEM_INFO lpSystemInfo);

	//
	// 禁止目录重定向
	//
	bool Wow64DisableWow64FsRedirection(PVOID& value);

	//
	// 恢复目录重定向
	//
	bool Wow64RevertWow64FsRedirection(PVOID& value);

	//
	// GetProcAddress
	//
	PVOID GetProcAddress(HMODULE hModule, const char* funcName);

	//
	// GetProcAddress
	//
	PVOID GetProcAddress(const char* dllName, const char* funcName);

	//
	// GetCurrentFullPath
	//
	std::string GetCurrentFullName();


	extern "C" uintptr_t GetCurrentIP();
	extern "C" void Int2D();
};


namespace x64 
{
	inline BOOL		isInitialize		 = false;
	inline BOOL		isArch64			 = false;
	inline BOOL		isWow64				 = false;	
	inline BOOL		isWow64FsReDriectory = false;
	inline HANDLE	heap;
	inline uint8_t* ntFile;
	inline uint32_t ntSize;

	void		initialize();
	uint32_t	v2f(uint8_t* file, uint32_t va);
	uint32_t	f2v(uint8_t* file, uint32_t f);

	uint32_t  getIndex(const uint32_t h);
	uintptr_t getFunction(const uint32_t h);

	template <typename... Args>
	NTSTATUS NativeCall(uintptr_t func, Args... args)
	{
		if (isArch64)
		{
#ifdef _WIN64
			return AnyCall::std_call<NTSTATUS>(func, args...);
#else
			return X64Call(func, sizeof...(Args), (DWORD64)args...);
#endif // _WIN64
		}
		else
		{
			return AnyCall::cd_call<NTSTATUS>(func, args...);
		}
	}


#define DEF_FUNC(name) \
template <typename... Args>\
NTSTATUS name (Args... args)\
{\
	static uintptr_t func = getFunction(hash_const("" #name "")); \
	if (func)\
	{\
		return NativeCall(func, args...);\
	}\
	return STATUS_UNSUCCESSFUL;\
}


#pragma warning(push)
#pragma warning(disable: 4244)

	DEF_FUNC(NtOpenProcess);
	DEF_FUNC(NtQueryInformationProcess);
	DEF_FUNC(NtClose);
	DEF_FUNC(NtSetInformationThread);
	
#pragma warning(pop)

}
