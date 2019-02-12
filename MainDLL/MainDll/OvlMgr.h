#pragma once

#include <windows.h>
#include <stdio.h>

typedef struct
{
	WORD offset : 12;
	WORD type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;

typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

HMODULE MapOverlay(const char *filePath, char *ovlLocation);