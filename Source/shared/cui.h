/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       CUI.H
*
*  VERSION:     1.0
*
*  DATE:        15 Jan 2016
*
*  Common header file for console ui.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

VOID SfcuiPrintText(
	HANDLE hOutConsole,
	LPWSTR lpText,
	BOOL ConsoleOutputEnabled,
	BOOL UseReturn
	);
