public SfpldrPostCallHandler

public pSfldrPostCallHandler

	_DATA$00 SEGMENT PARA 'DATA'

pSfldrPostCallHandler label qword
	dq	0

	_DATA$00 ENDS

_TEXT$00 segment para 'CODE'

	ALIGN 16
	PUBLIC SfpldrPostCallHandler

SfpldrPostCallHandler PROC
	mov ecx, eax
	call pSfldrPostCallHandler
	int 3
SfpldrPostCallHandler ENDP

	_TEXT$00 ENDS
	
END