#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>

void Error()
{
	printf("Error number %d!", GetLastError());
	_getch();
}

int main()
{ 
	LPTSTR lpFileName = malloc(MAX_PATH);
	DWORD hookingFunc, hookedFuncIatEntry;
	
	// a regular call to MessageBoxA
	MessageBoxA(NULL, "Regular call", "MessageBoxA", MB_OK);

	// get handle and filename of the current module
	HANDLE hProc = GetModuleHandleA(NULL);
	GetModuleFileNameW(NULL, lpFileName, MAX_PATH);

	PIMAGE_DOS_HEADER pDosHeader = hProc;

	// check DOS signature (MZ)
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		Error();
	else
		printf("\n%x (MZ) found, valid PE\nPE Header offset: 0x%x\n", pDosHeader->e_magic, pDosHeader->e_lfanew);

	PIMAGE_NT_HEADERS pImageHeader = (char*)pDosHeader + pDosHeader->e_lfanew;

	// check NT signature (PE)
	if (pImageHeader->Signature != IMAGE_NT_SIGNATURE)
		Error();
	else 
		printf("\n%x (PE00) signature found\nImageBase: 0x%x\n\n", pImageHeader->Signature, pImageHeader->OptionalHeader.ImageBase);

	// find relevant data directories
	PIMAGE_IMPORT_DESCRIPTOR pImportTableEntry = (char*)pDosHeader + 
		pImageHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	
	PIMAGE_IMPORT_DESCRIPTOR pIATEntry = (char*)pDosHeader + 
		pImageHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;

	printf("\nThe imported modules are:");

	// iterate the imported modules
	while (*(DWORD*)pImportTableEntry != 0)
	{
		char* moduleName = (char*)pDosHeader + pImportTableEntry->Name;
		printf("\n\n%.*s", strlen(moduleName), "==============================");
		printf("\n%s\n", moduleName);
		printf("%.*s", strlen(moduleName), "==============================");

		PIMAGE_THUNK_DATA pINTEntry = (char*)pDosHeader + pImportTableEntry->OriginalFirstThunk; // Import Name Table
		PIMAGE_THUNK_DATA pIATEntry = (char*)pDosHeader + pImportTableEntry->FirstThunk; // Import Address Table - after loading, contains the functions addresses

		printf("\n\nImported functions for this module:\n");
		printf("----------------------------------\n\n");

		// Iterate the imported functions
		while (*(DWORD*)pINTEntry != 0)
		{
			PIMAGE_IMPORT_BY_NAME pFuncName = (char*)pDosHeader + pINTEntry->u1.AddressOfData;
			printf("%s at 0x%x\n", pFuncName->Name, pIATEntry->u1.Function);

			// find the hooking function
			if (strcmp((char*)pFuncName->Name, "MessageBoxA") == 0)
				hookingFunc = pIATEntry->u1.Function;

			// find the (gonna be) hooked function
			else if (strcmp((char*)pFuncName->Name, "Sleep") == 0)
				hookedFuncIatEntry = pIATEntry;

			pINTEntry++;
			pIATEntry++;
		}
		pImportTableEntry++;
	}
	
	PDWORD lpflOldProtect = malloc(4);
	
	// remove memory protection
	VirtualProtect(hookedFuncIatEntry, 4, PAGE_READWRITE, lpflOldProtect);

	((PIMAGE_THUNK_DATA)hookedFuncIatEntry)->u1.Function = hookingFunc;

	Sleep(NULL, "Hooked!", "Sleep", MB_OK);

	free(lpFileName);
	free(lpflOldProtect);

	_getch();
	return 0;
}