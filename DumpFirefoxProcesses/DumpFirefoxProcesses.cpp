// DumpFirefoxProcesses.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

const wchar_t* kTargetProcessName = _T("firefox.exe");


LONG(WINAPI *NtQueryInformationProcess)(HANDLE ProcessHandle, ULONG ProcessInformationClass,
	PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) = nullptr;

ULONG_PTR GetParentProcessId(HANDLE hProcess) // By Napalm @ NetCore2K
{
	ULONG_PTR pbi[6];
	ULONG ulSize = 0;
	if (NtQueryInformationProcess){
		if (NtQueryInformationProcess(hProcess, 0,
			&pbi, sizeof(pbi), &ulSize) >= 0 && ulSize == sizeof(pbi))
			return pbi[5];
	}
	return (ULONG_PTR)-1;
}



bool PrintProcessNameAndID(DWORD processID, std::map<DWORD,DWORD>& parent_ids)
{
	wchar_t szProcessName[MAX_PATH] = L"<unknown>";

	// Get a handle to the process.

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);

	// Get the process name.
	if (NULL != hProcess)
	{
		parent_ids[processID] = GetParentProcessId(hProcess);
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
			&cbNeeded))
		{
			GetModuleBaseNameW(hProcess, hMod, szProcessName,
				sizeof(szProcessName) / sizeof(wchar_t));
		}
	}

	// Print the process name and identifier.

	printf("%S  PID: %u\n", szProcessName, processID);

	// Release the handle to the process.

	CloseHandle(hProcess);

	return lstrcmp(szProcessName, kTargetProcessName) == 0;
}

void WriteDump(DWORD pid, const wchar_t* directory, const wchar_t* base_filename)
{
	wchar_t filename[MAX_PATH];
	wcscpy_s(filename, directory);
	wcscat_s(filename, base_filename);
	wcscat_s(filename, L".");
	wchar_t pid_s[9];
	swprintf_s(pid_s, L"%u", pid);
	wcscat_s(filename, pid_s);
	wcscat_s(filename, L".dmp");


	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, pid);
	if (hProcess != nullptr) {
		HANDLE file = CreateFile(filename, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if (file != INVALID_HANDLE_VALUE) {
			if (MiniDumpWriteDump(hProcess, pid, file, MiniDumpNormal, nullptr, nullptr, nullptr)) {
				return;
			}
		}
	}
}

int wmain(int argc, wchar_t** argv)
{
	*(FARPROC *)&NtQueryInformationProcess = GetProcAddress(LoadLibraryA("NTDLL.DLL"), "NtQueryInformationProcess");
	// Get the list of process identifiers.

	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 1;
	}


	// Calculate how many process identifiers were returned.

	cProcesses = cbNeeded / sizeof(DWORD);

	std::map<DWORD, DWORD> parent_ids;
	DWORD process_to_dump = 0;

	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			if (PrintProcessNameAndID(aProcesses[i], parent_ids)) {
				process_to_dump = aProcesses[i];
			}
		}
	}

	wchar_t dump_directory[MAX_PATH] = {};
	if (argc > 1) {
		wcscpy_s(dump_directory, argv[1]);
		int len = wcslen(dump_directory);
		if (dump_directory[len - 1] != '\\') {
			lstrcat(dump_directory, L"\\");
		}
	}

	if (process_to_dump != 0) {
		time_t t = time(nullptr);
		wchar_t time_str[17];
		_i64tow_s(t, time_str, 17, 10);
		wcscat_s(dump_directory, time_str);
		wcscat_s(dump_directory, L"\\");
		_wmkdir(dump_directory);

		wchar_t dir[MAX_PATH];
		if (GetCurrentDirectoryW(MAX_PATH, dir)) {
			printf("dir: %S\n", dir);
		}

		WriteDump(process_to_dump, dump_directory, kTargetProcessName);
		for (std::map<DWORD, DWORD>::iterator iter = parent_ids.begin(); iter != parent_ids.end(); iter++) {
			if (iter->second == process_to_dump) {
				WriteDump(iter->first, dump_directory, L"child");
			}
		}
	}

	return 0;
}
