/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       CUI.C
*
*  VERSION:     1.00
*
*  DATE:        10 Jan 2016
*
*  Console output.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

VOID SfcuiPrintText(
	HANDLE hOutConsole,
	LPWSTR lpText,
	BOOL ConsoleOutputEnabled,
	BOOL UseReturn
	)
{
	DWORD consoleIO;
	PTCHAR Buffer;

	consoleIO = (DWORD)_strlen(lpText) * sizeof(WCHAR) + 4 + sizeof(UNICODE_NULL);
	Buffer = (PTCHAR)RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, consoleIO);
	if (Buffer) {

		_strcpy(Buffer, lpText);
		if (UseReturn) _strcat(Buffer, TEXT("\r\n"));

		consoleIO = (DWORD)_strlen(Buffer);

		if (ConsoleOutputEnabled == TRUE) {
			WriteConsole(hOutConsole, Buffer, consoleIO, &consoleIO, NULL);
		}
		else {
			WriteFile(hOutConsole, Buffer, consoleIO * sizeof(TCHAR), &consoleIO, NULL);
		}
		RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, Buffer);
	}
}
