.code

GetCurrentIP proc
	mov rax, [rsp]
	ret
GetCurrentIP endp

Int2D proc
	mov rax, 1
	int 2dh
	nop
	ret
Int2D endp

end