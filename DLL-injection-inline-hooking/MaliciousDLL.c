#include <stdio.h>
#include <Windows.h>
#include <string.h>

int WINAPI newLstrcmpA(LPCSTR, LPCSTR);

// trampoline type definition
typedef int (WINAPI *TdefTrampolineStrcmp)(LPCSTR pStr1, LPCSTR pStr2);
TdefTrampolineStrcmp trampolineLstrcmpA;

BOOL APIENTRY DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		inlineHooker();
		printf("DLL injected.");
		break;

	/*
	case DLL_PROCESS_DETACH:
		printf("DLL_PROCESS_DETACH\n");
		break;

	case DLL_THREAD_ATTACH:
		printf("DLL_THREAD_ATTACH\n");
		break;

	case DLL_THREAD_DETACH:
		printf("DLL_THREAD_DETACH\n");
		break;
	*/
	}
	return TRUE;
}

BOOL inlineHooker()
{
	// find lstrcmpA function address
	HANDLE hKernel32 = GetModuleHandle(L"kernel32.dll");
	FARPROC pStrcmp = GetProcAddress(hKernel32, "lstrcmpA");

	// Copy the (goingToBe) overwritten memory
	byte overwritten[5];
	CopyMemory(overwritten, pStrcmp, 5);

	// build the trampoline
	// --------------------------------------------------
	// the trampoline needs 10 bytes: 5 for the overwritten bytes, and 5 for the jump instruction
	trampolineLstrcmpA = (TdefTrampolineStrcmp)VirtualAlloc(NULL, 10, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	CopyMemory(trampolineLstrcmpA, overwritten, 5);

	// calculate the source and destination of the jump in the trampoline
	// the source is the end of the jump in the trampoline
	// the dst is the orignial function after overwritten
	DWORD src = (DWORD)trampolineLstrcmpA + 10;
	DWORD dst = (DWORD)pStrcmp + 5;

	// build the jump opcodes for the trampoline
	byte jmp[5];
	jmp[0] = 0xE9; // jmp instruction (relative jump)
	*(DWORD *)(jmp + 1) = dst - src;

	// copy the jump to the end of the trampoline
	CopyMemory((LPVOID)((DWORD)trampolineLstrcmpA + 5), jmp, 5);
	// --------------------------------------------------

	// Hook!

	// remove memory protection
	DWORD oldProtect;
	VirtualProtect(pStrcmp, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

	// build the hooking jump
	src = dst;
	dst = (DWORD)newLstrcmpA;

	*(DWORD *)(jmp + 1) = dst - src;

	CopyMemory(pStrcmp, jmp, 5);

	// retrieve memory protection
	VirtualProtect(pStrcmp, 5, oldProtect, NULL);

	return TRUE;
}

int WINAPI newLstrcmpA(LPCSTR pStr1, LPCSTR pStr2)
{
	printf("hooked successfully.");
	strcpy(pStr1, pStr2);

	return trampolineLstrcmpA(pStr1, pStr2);
}