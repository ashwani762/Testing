#include "Controller.h"

typedef int(__cdecl *MYPROC)();

int main() {
	
	HINSTANCE mainDLL;
	MYPROC initialize;

	mainDLL = LoadLibrary(TEXT("F:/Overlay/Take1/Take1/Overlays/MainDll.dll"));

	if (mainDLL != NULL) {
		initialize = (MYPROC)GetProcAddress(mainDLL, "initialize");

		if (initialize != NULL) {
			(initialize)();
		}
	}


	return 0;
}