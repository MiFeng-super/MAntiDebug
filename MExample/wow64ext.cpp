#include "pch.h"
#include "wow64ext.h"




#pragma warning(push)
#pragma warning(disable : 4409)
DWORD64 __cdecl X64Call(unsigned __int64 func, int argC, ...)
{
#ifndef _WIN64
	va_list args;
	va_start(args, argC);
	reg64 _rcx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _rdx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _r8 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _r9 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _rax = { 0 };

	reg64 restArgs = { (DWORD64)&va_arg(args, DWORD64) };

	// conversion to QWORD for easier use in inline assembly
	reg64 _argC = { (DWORD64)argC };
	DWORD back_esp = 0;
	WORD back_fs = 0;

	__asm
	{
		;// reset FS segment, to properly handle RFG
		mov    back_fs, fs
			mov    eax, 0x2B
			mov    fs, ax

			;// keep original esp in back_esp variable
		mov    back_esp, esp

			;// align esp to 0x10, without aligned stack some syscalls may return errors !
		;// (actually, for syscalls it is sufficient to align to 8, but SSE opcodes 
		;// requires 0x10 alignment), it will be further adjusted according to the
		;// number of arguments above 4
		and esp, 0xFFFFFFF0

			X64_Start();

		;// below code is compiled as x86 inline asm, but it is executed as x64 code
		;// that's why it need sometimes REX_W() macro, right column contains detailed
		;// transcription how it will be interpreted by CPU

		;// fill first four arguments
		REX_W mov    ecx, _rcx.dw[0];// mov     rcx, qword ptr [_rcx]
		REX_W mov    edx, _rdx.dw[0];// mov     rdx, qword ptr [_rdx]
		push   _r8.v;// push    qword ptr [_r8]
		X64_Pop(_R8); ;// pop     r8
		push   _r9.v;// push    qword ptr [_r9]
		X64_Pop(_R9); ;// pop     r9
		;//
		REX_W mov    eax, _argC.dw[0];// mov     rax, qword ptr [_argC]
		;// 
		;// final stack adjustment, according to the    ;//
		;// number of arguments above 4                 ;// 
		test   al, 1;// test    al, 1
		jnz    _no_adjust;// jnz     _no_adjust
		sub    esp, 8;// sub     rsp, 8
	_no_adjust:;//
		;// 
		push   edi;// push    rdi
		REX_W mov    edi, restArgs.dw[0];// mov     rdi, qword ptr [restArgs]
		;// 
		;// put rest of arguments on the stack          ;// 
		REX_W test   eax, eax;// test    rax, rax
		jz     _ls_e;// je      _ls_e
		REX_W lea    edi, dword ptr[edi + 8 * eax - 8];// lea     rdi, [rdi + rax*8 - 8]
		;// 
	_ls:;// 
		REX_W test   eax, eax;// test    rax, rax
		jz     _ls_e;// je      _ls_e
		push   dword ptr[edi];// push    qword ptr [rdi]
		REX_W sub    edi, 8;// sub     rdi, 8
		REX_W sub    eax, 1;// sub     rax, 1
		jmp    _ls;// jmp     _ls
	_ls_e:;// 
		;// 
		;// create stack space for spilling registers   ;// 
		REX_W sub    esp, 0x20;// sub     rsp, 20h
		;// 
		call   func;// call    qword ptr [func]
		;// 
		;// cleanup stack                               ;// 
		REX_W mov    ecx, _argC.dw[0];// mov     rcx, qword ptr [_argC]
		REX_W lea    esp, dword ptr[esp + 8 * ecx + 0x20];// lea     rsp, [rsp + rcx*8 + 20h]
		;// 
		pop    edi;// pop     rdi
		;// 
// set return value                             ;// 
		REX_W mov    _rax.dw[0], eax;// mov     qword ptr [_rax], rax

		X64_End();

		mov    ax, ds
			mov    ss, ax
			mov    esp, back_esp

			;// restore FS segment
		mov    ax, back_fs
			mov    fs, ax
	}
	return _rax.v;
#endif // _WIN32
	return 0;
}
#pragma warning(pop)

void getMem64(void* dstMem, DWORD64 srcMem, size_t sz)
{
	if ((nullptr == dstMem) || (0 == srcMem) || (0 == sz))
		return;

#ifndef _WIN64
	reg64 _src = { srcMem };

	__asm
	{
		X64_Start();

		;// below code is compiled as x86 inline asm, but it is executed as x64 code
		;// that's why it need sometimes REX_W() macro, right column contains detailed
		;// transcription how it will be interpreted by CPU

		push   edi;// push     rdi
		push   esi;// push     rsi
		;//
		mov    edi, dstMem;// mov      edi, dword ptr [dstMem]        ; high part of RDI is zeroed
		REX_W mov    esi, _src.dw[0];// mov      rsi, qword ptr [_src]
		mov    ecx, sz;// mov      ecx, dword ptr [sz]            ; high part of RCX is zeroed
		;//
		mov    eax, ecx;// mov      eax, ecx
		and eax, 3;// and      eax, 3
		shr    ecx, 2;// shr      ecx, 2
		;//
		rep    movsd;// rep movs dword ptr [rdi], dword ptr [rsi]
		;//
		test   eax, eax;// test     eax, eax
		je     _move_0;// je       _move_0
		cmp    eax, 1;// cmp      eax, 1
		je     _move_1;// je       _move_1
		;//
		movsw;// movs     word ptr [rdi], word ptr [rsi]
		cmp    eax, 2;// cmp      eax, 2
		je     _move_0;// je       _move_0
		;//
	_move_1:;//
		movsb;// movs     byte ptr [rdi], byte ptr [rsi]
		;//
	_move_0:;//
		pop    esi;// pop      rsi
		pop    edi;// pop      rdi

		X64_End();
	}

#else
	memcpy(dstMem, (PVOID)srcMem, sz);
#endif // _WIN64

}

DWORD64 getTEB64()
{
#ifndef _WIN64
	reg64 reg;
	reg.v = 0;

	X64_Start();
	// R12 register should always contain pointer to TEB64 in WoW64 processes
	X64_Push(_R12);
	// below pop will pop QWORD from stack, as we're in x64 mode now
	__asm pop reg.dw[0]
		X64_End();

	return reg.v;

#else
	return __readgsqword(0x30);

#endif // !_WIN64

}