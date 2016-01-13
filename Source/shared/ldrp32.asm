.586
.xlist
.list

public _SfpldrPostCallHandler@4
public _pSfldrPostCallHandler

_DATA$00 SEGMENT PARA 'DATA'
_pSfldrPostCallHandler label dword
	dd 0
_DATA$00 ENDS


_TEXT$00 SEGMENT DWORD PUBLIC 'CODE'
			ASSUME DS:FLAT, ES:FLAT, SS:FLAT, FS:NOTHING, GS:NOTHING

ALIGN 4

_SfpldrPostCallHandler@4 PROC NEAR
	mov ecx, eax
	call _pSfldrPostCallHandler
	int 3
_SfpldrPostCallHandler@4 ENDP


_TEXT$00 ENDS

END