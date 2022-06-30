#pragma once

#include <Windows.h>

#define EMIT(a) __asm __emit (a)

#define X64_Start_with_CS(_cs) \
    { \
    EMIT(0x6A) EMIT(_cs)                         /*  push   _cs             */ \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)   /*  call   $+5             */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(5)        /*  add    dword [esp], 5  */ \
    EMIT(0xCB)                                   /*  retf                   */ \
    }

#define X64_End_with_CS(_cs) \
    { \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                 /*  call   $+5                   */ \
    EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(4) EMIT(_cs) EMIT(0) EMIT(0) EMIT(0) /*  mov    dword [rsp + 4], _cs  */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(0xD)                                    /*  add    dword [rsp], 0xD      */ \
    EMIT(0xCB)                                                                 /*  retf                         */ \
    }

#define X64_Start() X64_Start_with_CS(0x33)
#define X64_End() X64_End_with_CS(0x23)

#define _RAX  0
#define _RCX  1
#define _RDX  2
#define _RBX  3
#define _RSP  4
#define _RBP  5
#define _RSI  6
#define _RDI  7
#define _R8   8
#define _R9   9
#define _R10 10
#define _R11 11
#define _R12 12
#define _R13 13
#define _R14 14
#define _R15 15

#define X64_Push(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x50 | ((r) & 7))
#define X64_Pop(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))

#define REX_W EMIT(0x48) __asm

//to fool M$ inline asm compiler I'm using 2 DWORDs instead of DWORD64
//use of DWORD64 will generate wrong 'pop word ptr[]' and it will break stack
union reg64
{
    DWORD64 v;
	DWORD dw[2];
};

DWORD64 __cdecl X64Call(unsigned __int64 func, int argC, ...);
void getMem64(void* dstMem, DWORD64 srcMem, size_t sz);
DWORD64 getTEB64();

#pragma pack(push)
#pragma pack(1)
template <class T>
struct _LIST_ENTRY_T
{
	T Flink;
	T Blink;
};

template <class T>
struct _UNICODE_STRING_T
{
	union
	{
		struct
		{
			WORD Length;
			WORD MaximumLength;
		};
		T dummy;
	};
	T Buffer;
};

template <class T>
struct _NT_TIB_T
{
	T ExceptionList;
	T StackBase;
	T StackLimit;
	T SubSystemTib;
	T FiberData;
	T ArbitraryUserPointer;
	T Self;
};

template <class T>
struct _CLIENT_ID_T
{
	T UniqueProcess;
	T UniqueThread;
};

template <class T>
struct _TEB_T_
{
	_NT_TIB_T<T> NtTib;
	T EnvironmentPointer;
	_CLIENT_ID_T<T> ClientId;
	T ActiveRpcHandle;
	T ThreadLocalStoragePointer;
	T ProcessEnvironmentBlock;
	DWORD LastErrorValue;
	DWORD CountOfOwnedCriticalSections;
	T CsrClientThread;
	T Win32ThreadInfo;
	DWORD User32Reserved[26];
	//rest of the structure is not defined for now, as it is not needed
};

template <class T>
struct _LDR_DATA_TABLE_ENTRY_T
{
	_LIST_ENTRY_T<T> InLoadOrderLinks;
	_LIST_ENTRY_T<T> InMemoryOrderLinks;
	_LIST_ENTRY_T<T> InInitializationOrderLinks;
	T DllBase;
	T EntryPoint;
	union
	{
		DWORD SizeOfImage;
		T dummy01;
	};
	_UNICODE_STRING_T<T> FullDllName;
	_UNICODE_STRING_T<T> BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		_LIST_ENTRY_T<T> HashLinks;
		struct
		{
			T SectionPointer;
			T CheckSum;
		};
	};
	union
	{
		T LoadedImports;
		DWORD TimeDateStamp;
	};
	T EntryPointActivationContext;
	T PatchInformation;
	_LIST_ENTRY_T<T> ForwarderLinks;
	_LIST_ENTRY_T<T> ServiceTagLinks;
	_LIST_ENTRY_T<T> StaticLinks;
	T ContextInformation;
	T OriginalBase;
	_LARGE_INTEGER LoadTime;
};

template <class T>
struct _PEB_LDR_DATA_T
{
	DWORD Length;
	DWORD Initialized;
	T SsHandle;
	_LIST_ENTRY_T<T> InLoadOrderModuleList;
	_LIST_ENTRY_T<T> InMemoryOrderModuleList;
	_LIST_ENTRY_T<T> InInitializationOrderModuleList;
	T EntryInProgress;
	DWORD ShutdownInProgress;
	T ShutdownThreadId;

};

template <class T, class NGF, int A>
struct _PEB_T
{
	union
	{
		struct
		{
			BYTE InheritedAddressSpace;
			BYTE ReadImageFileExecOptions;
			BYTE BeingDebugged;
			BYTE BitField;
		};
		T dummy01;
	};
	T Mutant;
	T ImageBaseAddress;
	T Ldr;
	T ProcessParameters;
	T SubSystemData;
	T ProcessHeap;
	T FastPebLock;
	T AtlThunkSListPtr;
	T IFEOKey;
	T CrossProcessFlags;
	T UserSharedInfoPtr;
	DWORD SystemReserved;
	DWORD AtlThunkSListPtr32;
	T ApiSetMap;
	T TlsExpansionCounter;
	T TlsBitmap;
	DWORD TlsBitmapBits[2];
	T ReadOnlySharedMemoryBase;
	T HotpatchInformation;
	T ReadOnlyStaticServerData;
	T AnsiCodePageData;
	T OemCodePageData;
	T UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	union
	{
		DWORD NtGlobalFlag;
		NGF dummy02;
	};
	LARGE_INTEGER CriticalSectionTimeout;
	T HeapSegmentReserve;
	T HeapSegmentCommit;
	T HeapDeCommitTotalFreeThreshold;
	T HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	T ProcessHeaps;
	T GdiSharedHandleTable;
	T ProcessStarterHelper;
	T GdiDCAttributeList;
	T LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	T ImageSubsystemMinorVersion;
	T ActiveProcessAffinityMask;
	T GdiHandleBuffer[A];
	T PostProcessInitRoutine;
	T TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	T SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	T pShimData;
	T AppCompatInfo;
	_UNICODE_STRING_T<T> CSDVersion;
	T ActivationContextData;
	T ProcessAssemblyStorageMap;
	T SystemDefaultActivationContextData;
	T SystemAssemblyStorageMap;
	T MinimumStackCommit;
	T FlsCallback;
	_LIST_ENTRY_T<T> FlsListHead;
	T FlsBitmap;
	DWORD FlsBitmapBits[4];
	T FlsHighIndex;
	T WerRegistrationData;
	T WerShipAssertPtr;
	T pContextData;
	T pImageHeaderHash;
	T TracingFlags;
};

typedef _LDR_DATA_TABLE_ENTRY_T<DWORD> LDR_DATA_TABLE_ENTRY32;
typedef _LDR_DATA_TABLE_ENTRY_T<DWORD64> LDR_DATA_TABLE_ENTRY64;

typedef _TEB_T_<DWORD> TEB32;
typedef _TEB_T_<DWORD64> TEB64;

typedef _PEB_LDR_DATA_T<DWORD> PEB_LDR_DATA32;
typedef _PEB_LDR_DATA_T<DWORD64> PEB_LDR_DATA64;

typedef _PEB_T<DWORD, DWORD64, 34> PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> PEB64;

struct _XSAVE_FORMAT64
{
	WORD ControlWord;
	WORD StatusWord;
	BYTE TagWord;
	BYTE Reserved1;
	WORD ErrorOpcode;
	DWORD ErrorOffset;
	WORD ErrorSelector;
	WORD Reserved2;
	DWORD DataOffset;
	WORD DataSelector;
	WORD Reserved3;
	DWORD MxCsr;
	DWORD MxCsr_Mask;
	_M128A FloatRegisters[8];
	_M128A XmmRegisters[16];
	BYTE Reserved4[96];
};

struct _CONTEXT64
{
	DWORD64 P1Home;
	DWORD64 P2Home;
	DWORD64 P3Home;
	DWORD64 P4Home;
	DWORD64 P5Home;
	DWORD64 P6Home;
	DWORD ContextFlags;
	DWORD MxCsr;
	WORD SegCs;
	WORD SegDs;
	WORD SegEs;
	WORD SegFs;
	WORD SegGs;
	WORD SegSs;
	DWORD EFlags;
	DWORD64 Dr0;
	DWORD64 Dr1;
	DWORD64 Dr2;
	DWORD64 Dr3;
	DWORD64 Dr6;
	DWORD64 Dr7;
	DWORD64 Rax;
	DWORD64 Rcx;
	DWORD64 Rdx;
	DWORD64 Rbx;
	DWORD64 Rsp;
	DWORD64 Rbp;
	DWORD64 Rsi;
	DWORD64 Rdi;
	DWORD64 R8;
	DWORD64 R9;
	DWORD64 R10;
	DWORD64 R11;
	DWORD64 R12;
	DWORD64 R13;
	DWORD64 R14;
	DWORD64 R15;
	DWORD64 Rip;
	_XSAVE_FORMAT64 FltSave;
	_M128A Header[2];
	_M128A Legacy[8];
	_M128A Xmm0;
	_M128A Xmm1;
	_M128A Xmm2;
	_M128A Xmm3;
	_M128A Xmm4;
	_M128A Xmm5;
	_M128A Xmm6;
	_M128A Xmm7;
	_M128A Xmm8;
	_M128A Xmm9;
	_M128A Xmm10;
	_M128A Xmm11;
	_M128A Xmm12;
	_M128A Xmm13;
	_M128A Xmm14;
	_M128A Xmm15;
	_M128A VectorRegister[26];
	DWORD64 VectorControl;
	DWORD64 DebugControl;
	DWORD64 LastBranchToRip;
	DWORD64 LastBranchFromRip;
	DWORD64 LastExceptionToRip;
	DWORD64 LastExceptionFromRip;
};

// Below defines for .ContextFlags field are taken from WinNT.h
#ifndef CONTEXT_AMD64
#define CONTEXT_AMD64 0x100000
#endif

#define CONTEXT64_CONTROL (CONTEXT_AMD64 | 0x1L)
#define CONTEXT64_INTEGER (CONTEXT_AMD64 | 0x2L)
#define CONTEXT64_SEGMENTS (CONTEXT_AMD64 | 0x4L)
#define CONTEXT64_FLOATING_POINT  (CONTEXT_AMD64 | 0x8L)
#define CONTEXT64_DEBUG_REGISTERS (CONTEXT_AMD64 | 0x10L)
#define CONTEXT64_FULL (CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT)
#define CONTEXT64_ALL (CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS)
#define CONTEXT64_XSTATE (CONTEXT_AMD64 | 0x20L)

#pragma pack(pop)