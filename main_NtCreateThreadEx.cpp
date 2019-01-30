#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <tlhelp32.h>

typedef NTSTATUS (WINAPI *LPFUN_NtCreateThreadEx) 
(
  OUT PHANDLE hThread,
  IN ACCESS_MASK DesiredAccess,
  IN LPVOID ObjectAttributes,
  IN HANDLE ProcessHandle,
  IN LPTHREAD_START_ROUTINE lpStartAddress,
  IN LPVOID lpParameter,
  IN BOOL CreateSuspended, 
  IN ULONG StackZeroBits,
  IN ULONG SizeOfStackCommit,
  IN ULONG SizeOfStackReserve,
  OUT LPVOID lpBytesBuffer
);


struct NtCreateThreadExBuffer
{
  ULONG Size;
  ULONG Unknown1;
  ULONG Unknown2;
  PULONG Unknown3;
  ULONG Unknown4;
  ULONG Unknown5;
  ULONG Unknown6;
  PULONG Unknown7;
  ULONG Unknown8;
};

void fatal(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    printf("FATAL: ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
    exit(1);
}

DWORD NtCreateThreadEx(PCWSTR pszLibFile, DWORD dwProcessId)
{
	HANDLE spy_thread = NULL;
	NtCreateThreadExBuffer ntbuffer;
	LARGE_INTEGER dwTmp1 = { 0 };
	LARGE_INTEGER dwTmp2 = { 0 };

	memset(&ntbuffer, 0, sizeof(NtCreateThreadExBuffer));

	DWORD dwSize = (lstrlenW(pszLibFile) + 1) * sizeof(wchar_t);

	HANDLE process = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE, dwProcessId);

	if (process == NULL)
		fatal("main: process == NULL");

	LPVOID p_dllname = (PWSTR)VirtualAllocEx(process, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (p_dllname == NULL)
		fatal("main: p_dllname == NULL");

	if (!WriteProcessMemory(process, p_dllname, (LPVOID)pszLibFile, dwSize, NULL))
		fatal("main: Read count = 0");

	PTHREAD_START_ROUTINE NtCreateThreadEx_addr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateThreadEx");

	if (NtCreateThreadEx_addr)
	{
		ntbuffer.Size = sizeof(struct NtCreateThreadExBuffer);
		ntbuffer.Unknown1 = 0x10003;
		ntbuffer.Unknown2 = 0x8;
		ntbuffer.Unknown3 = (DWORD*)&dwTmp2;
		ntbuffer.Unknown4 = 0;
		ntbuffer.Unknown5 = 0x10004;
		ntbuffer.Unknown6 = 4;
		ntbuffer.Unknown7 = (DWORD*)&dwTmp1;
		ntbuffer.Unknown8 = 0;

		LPFUN_NtCreateThreadEx funNtCreateThreadEx = (LPFUN_NtCreateThreadEx)NtCreateThreadEx_addr;

		NTSTATUS status = funNtCreateThreadEx(
			&spy_thread,
			0x1FFFFF,
			NULL,
			process,
			(PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW"),
			(LPVOID)p_dllname,
			FALSE,
			NULL,
			NULL,
			NULL,
			NULL
			);

		if (GetLastError() != NULL)
			fatal("main: GetLastError() != NULL");
		else
		{
			printf("Good");
			WaitForSingleObject(spy_thread, INFINITE);
		}
	}

	if (p_dllname != NULL)
		VirtualFreeEx(process, p_dllname, 0, MEM_RELEASE);

	if (spy_thread != NULL)
		CloseHandle(spy_thread);

	if (process != NULL)
		CloseHandle(process);

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2)
		fatal("main: argc < 2");

	LPCSTR dllpath = "test.dll";
	PROCESSENTRY32 entry;

	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snap, &entry))
    {
        while (Process32Next(snap, &entry))
        {
        	if (stricmp(entry.szExeFile, argv[1]) == 0)
        	{
        		NtCreateThreadEx(L"test.dll", entry.th32ProcessID);
        	}
        }
    }

	CloseHandle(snap);

	return 0;
}