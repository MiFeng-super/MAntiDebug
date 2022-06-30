.model flat
.code

_GetCurrentIP proc
	mov eax, [esp]
	ret
_GetCurrentIP endp

_Int2D proc
	mov eax, 1
	int 2dh
	nop
	ret
_Int2D endp

end