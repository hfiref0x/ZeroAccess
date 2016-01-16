/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.00
*
*  DATE:        15 Jan 2016
*
*  Harusame program entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "..\shared\global.h"
#include "..\shared\cui.h"
#include "..\shared\za_rkey.h"

HANDLE g_ConOut = NULL;
WCHAR BE = 0xFEFF;
BOOL g_ConsoleOutput = FALSE;

#define T_SFCHECKTTITLE  L"Sirefef/ZeroAccess 3 file checker v1.0 (14/01/16)"
#define T_SFCHECKUSAGE   L"Usage: sfcheck inputfile [mode 32 or 64, default 32]\n\r\te.g. sfcheck in.dll 32\r\n"
#define T_SFCHECKMODE    L"Wrong mode, possible values 32 or 64\r\n"
#define T_SFCHECKED      L"File verification SUCCESSFUL "
#define T_SFCHECKFAIL    L"File verification FAILED "
#define T_SFEAFAILURE    L"File extended attributes missing or incorrect, cannot verify file"
#define T_SFPRESSANYKEY  L"\r\nPress Enter to exit"

UINT SfProcessCmdLine(
	LPWSTR lpCommandLine
	)
{
	ULONG        rlen, uMode = 32;
	WCHAR        InputFile[MAX_PATH + 1];
	WCHAR        szMode[MAX_PATH + 1];
	NTSTATUS     status;
	PBYTE        pKey;
	ULONG        KeySize;

	//path
	rlen = 0;
	RtlSecureZeroMemory(InputFile, sizeof(InputFile));
	GetCommandLineParam(GetCommandLine(), 1, InputFile, MAX_PATH, &rlen);
	if (rlen == 0) {
		SfcuiPrintText(g_ConOut,
			T_SFCHECKUSAGE,
			g_ConsoleOutput, FALSE);
		return (UINT)-1;
	}

	//type
	RtlSecureZeroMemory(&szMode, sizeof(szMode));
	GetCommandLineParam(lpCommandLine, 2, (LPWSTR)&szMode, sizeof(szMode), &rlen);
	if (rlen == 0) {
		uMode = 32;
	}
	else {
		uMode = strtoul(szMode);
		if (uMode != 32 && uMode != 64) {

			SfcuiPrintText(g_ConOut,
				T_SFCHECKMODE,
				g_ConsoleOutput, FALSE);

			return (UINT)-2;
		}
	}

	pKey = (PBYTE)&ZA_key32;
	KeySize = sizeof(ZA_key32);

	if (uMode == 64) {
		pKey = (PBYTE)&ZA_key64;
		KeySize = sizeof(ZA_key64);
	}

	status = SfcIsFileLegit(InputFile, pKey, KeySize);

	//print result
	SfcuiPrintText(g_ConOut,
		InputFile,
		g_ConsoleOutput, TRUE);

	_strcpy(szMode, TEXT("Verification mode: "));
	ultostr(uMode, _strend(szMode));
	_strcat(szMode, TEXT("\r\n"));
	SfcuiPrintText(g_ConOut,
		szMode,
		g_ConsoleOutput, TRUE);

	switch (status) {

	case STATUS_EA_LIST_INCONSISTENT:
		SfcuiPrintText(g_ConOut,
			T_SFEAFAILURE,
			g_ConsoleOutput, TRUE);
		break;

	case STATUS_SUCCESS:
		SfcuiPrintText(g_ConOut,
			T_SFCHECKED,
			g_ConsoleOutput, TRUE);
		break;

	default:
		SfcuiPrintText(g_ConOut,
			T_SFCHECKFAIL,
			g_ConsoleOutput, TRUE);
		break;
	}

	return (NT_SUCCESS(status));
}

void SfMain(
	VOID
	)
{
	BOOL         cond = FALSE;
	UINT         uResult = 0;
	DWORD        dwTemp;
	HANDLE       StdIn;
	INPUT_RECORD inp1;

	__security_init_cookie();

	do {

		if (!SfInitMD5()) {
			uResult = (UINT)-1;
			break;
		}

		g_ConOut = GetStdHandle(STD_OUTPUT_HANDLE);
		if (g_ConOut == INVALID_HANDLE_VALUE) {
			uResult = (UINT)-2;
			break;
		}

		g_ConsoleOutput = TRUE;
		if (!GetConsoleMode(g_ConOut, &dwTemp)) {
			g_ConsoleOutput = FALSE;
		}

		SetConsoleTitle(T_SFCHECKTTITLE);
		SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);
		if (g_ConsoleOutput == FALSE) {
			WriteFile(g_ConOut, &BE, sizeof(WCHAR), &dwTemp, NULL);
		}

		uResult = SfProcessCmdLine(GetCommandLine());

		if (g_ConsoleOutput) {

			SfcuiPrintText(g_ConOut,
				T_SFPRESSANYKEY,
				TRUE, FALSE);

			StdIn = GetStdHandle(STD_INPUT_HANDLE);
			RtlSecureZeroMemory(&inp1, sizeof(inp1));
			ReadConsoleInput(StdIn, &inp1, 1, &dwTemp);
			ReadConsole(StdIn, &BE, sizeof(BE), &dwTemp, NULL);
		}

	} while (cond);

	ExitProcess(uResult);
}
