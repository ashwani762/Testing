#include "OvlMgr.h"

char *Buffer;

void loadInMemory(const char *filePath) {
	FILE *file = NULL;
	file = fopen(filePath, "rb");

	fseek(file, 0, SEEK_END);
	long fsize = ftell(file);
	fseek(file, 0, SEEK_SET);

	Buffer = malloc(fsize + 1);
	fread(Buffer, fsize, 1, file);
	fclose(file);

	Buffer[fsize] = 0;
}

HMODULE MapOverlay(const char *filePath, char *ovlLocation) {
	//load dll as a file here

	ULONG_PTR uiLibraryAddress;
	ULONG_PTR uiHeaderValue;

	loadInMemory(filePath);

	if (Buffer != NULL) {
		uiLibraryAddress = Buffer;
	}

	uiHeaderValue = (ULONG_PTR)((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

	uiHeaderValue += uiLibraryAddress;

	//get the virtual address
	auto ImageVirtualAddress = (PIMAGE_NT_HEADERS)((PBYTE)uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

	memcpy(ovlLocation, uiLibraryAddress, ((PIMAGE_NT_HEADERS)ImageVirtualAddress)->OptionalHeader.SizeOfHeaders);
	ImageVirtualAddress = (PIMAGE_NT_HEADERS)(ovlLocation + ((PIMAGE_DOS_HEADER)ovlLocation)->e_lfanew);

	//Load all sections in the .ovl sectiton of DLL
	//We assume that it will debug otherwise it is waste

	auto pSection = ((PIMAGE_SECTION_HEADER)((PBYTE)&((PIMAGE_NT_HEADERS)ImageVirtualAddress)->OptionalHeader + ((PIMAGE_NT_HEADERS)ImageVirtualAddress)->FileHeader.SizeOfOptionalHeader));
	for (WORD i = 0; i < ((PIMAGE_NT_HEADERS)ImageVirtualAddress)->FileHeader.NumberOfSections; i++, ((PIMAGE_SECTION_HEADER)pSection)++) {
		memcpy(ovlLocation + ((PIMAGE_SECTION_HEADER)pSection)->VirtualAddress, (PBYTE)uiLibraryAddress + ((PIMAGE_SECTION_HEADER)pSection)->PointerToRawData, ((PIMAGE_SECTION_HEADER)pSection)->SizeOfRawData);
	}

	//Process IAT
	if (((PIMAGE_NT_HEADERS)ImageVirtualAddress)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(ovlLocation + ((PIMAGE_NT_HEADERS)ImageVirtualAddress)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		// iterate through all imports
		while (pImport->Name)
		{
			LPCSTR cpLibraryName = (LPCSTR)(ovlLocation + pImport->Name);
			PBYTE bpDepBase = 0;

			bpDepBase = (PBYTE)LoadLibraryA(cpLibraryName);

			if (bpDepBase)
			{
				PIMAGE_THUNK_DATA pThunkOrig = (PIMAGE_THUNK_DATA)(ovlLocation + pImport->OriginalFirstThunk);
				PIMAGE_THUNK_DATA pThunkFirst = (PIMAGE_THUNK_DATA)(ovlLocation + pImport->FirstThunk);
				PIMAGE_NT_HEADERS pNtHdrDep = (PIMAGE_NT_HEADERS)(ovlLocation + ((PIMAGE_DOS_HEADER)bpDepBase)->e_lfanew);

				// iterate through all imported functions, importing by ordinal if no name present
				while (pThunkFirst->u1.Function)
				{
					if (pThunkOrig && (pThunkOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG))
					{
						PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(bpDepBase +
							pNtHdrDep->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
						PDWORD addressArray = (PDWORD)(bpDepBase + exportDir->AddressOfFunctions);
						pThunkFirst->u1.Function =
							(UINT_PTR)(bpDepBase + addressArray[IMAGE_ORDINAL(pThunkOrig->u1.Ordinal) - exportDir->Base]);
					}
					else
					{
						LPCSTR cpName = (LPCSTR)((PIMAGE_IMPORT_BY_NAME)(ovlLocation + pThunkFirst->u1.Function))->Name;
						pThunkFirst->u1.Function = (ULONG_PTR)GetProcAddress((HMODULE)bpDepBase, cpName);

						if (pThunkFirst->u1.Function == 0)
						{
							//printf("%s: missing import %s.%s", GetOriginalImageName(ovlLocation), cpLibraryName, cpName);
							
							return 0;
						}
					}
					// get the next imported function
					pThunkFirst++;
					if (pThunkOrig)
						pThunkOrig++;
				}
			}
			else
			{
				printf("%s not found!", cpLibraryName);
				
				return 0;
			}

			// get the next import
			pImport++;
		}
	}

	//Reloactions

	 // check if their are any relocations present
	if (((PIMAGE_NT_HEADERS)ImageVirtualAddress)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		// calculate the base address delta and perform relocations (even if we load at desired image base)
		ULONG_PTR delta = (ULONG_PTR)(ovlLocation - ((PIMAGE_NT_HEADERS)ImageVirtualAddress)->OptionalHeader.ImageBase);

		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(ovlLocation +
			((PIMAGE_NT_HEADERS)ImageVirtualAddress)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		// and we iterate through all entries...
		while (pReloc->SizeOfBlock)
		{
			ULONG_PTR relocVA = (ULONG_PTR)(ovlLocation + pReloc->VirtualAddress);
			DWORD entryCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
			PIMAGE_RELOC pRelocBlock = (PIMAGE_RELOC)(pReloc + 1);

			// we iterate through all the entries in the current block...
			while (entryCount--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we don't use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if (pRelocBlock->type == IMAGE_REL_BASED_DIR64)
					*(ULONG_PTR*)(relocVA + pRelocBlock->offset) += delta;
				else if (pRelocBlock->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD*)(relocVA + pRelocBlock->offset) += (DWORD)delta;
				else if (pRelocBlock->type == IMAGE_REL_BASED_HIGH)
					*(WORD*)(relocVA + pRelocBlock->offset) += HIWORD(delta);
				else if (pRelocBlock->type == IMAGE_REL_BASED_LOW)
					*(WORD*)(relocVA + pRelocBlock->offset) += LOWORD(delta);

				pRelocBlock++;
			}

			// get the next entry in the relocation directory
			pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
		}
	}

	FlushInstructionCache((HANDLE)-1, NULL, 0);

	void * src = ovlLocation + ((PIMAGE_NT_HEADERS)ImageVirtualAddress)->OptionalHeader.AddressOfEntryPoint;
	if (src) {
		DLLMAIN pEntryPoint = (DLLMAIN)(ovlLocation + ((PIMAGE_NT_HEADERS)ImageVirtualAddress)->OptionalHeader.AddressOfEntryPoint);
		pEntryPoint((HINSTANCE)ovlLocation, DLL_PROCESS_ATTACH, NULL);
	}

	return (HMODULE)ovlLocation;

}