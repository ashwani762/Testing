// MainDll.cpp : Defines the exported functions for the DLL application.
//

#include "OvlMgr.h"

#pragma data_seg(".ovl")
char ovl[0xC000] = { 0 };

#pragma comment(linker, "/SECTION:.ovl,REW")

#pragma data_seg()

typedef int(__cdecl *AWE)();

void __declspec(dllexport) initialize() {
	HMODULE a = MapOverlay("F:/Overlay/Take1/Take1/Overlays/Add.dll", ovl);

	a = (AWE)GetProcAddress(ovl, "add");

}

