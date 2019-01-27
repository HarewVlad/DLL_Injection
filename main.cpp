#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <tlhelp32.h>

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

int main(int argc, char **argv)
{
	if (argc < 2)
		fatal("main: argc < 2");

	LPCSTR dllpath = "test.dll";
	HANDLE process = nullptr;
	PROCESSENTRY32 entry;

	entry.dwSize = sizeof(PROCESSENTRY32);

	// To get PID //
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snap, &entry))
    {
        while (Process32Next(snap, &entry))
        {
        	if (stricmp(entry.szExeFile, argv[1]) == 0)
        	{
        		process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
        	}
        }
    }
    //

	if (process == nullptr)
		fatal("main: OpenProcess error");

	LPVOID p_dllpath = VirtualAllocEx(process, 0, strlen(dllpath) + 1,
	MEM_COMMIT, PAGE_READWRITE);

	if (p_dllpath == nullptr)
		fatal("main: VirtualAllocEx error");

	if (!WriteProcessMemory(process, p_dllpath, (LPVOID)dllpath, strlen(dllpath) + 1, 0))
		fatal("main: WriteProcessMemory error");

	HANDLE spy_thread = CreateRemoteThread(process, 0, 0,
	(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"),
	"LoadLibraryA"), p_dllpath, 0, 0);

	SetThreadPriority(spy_thread, THREAD_PRIORITY_TIME_CRITICAL);

	WaitForSingleObject(spy_thread, INFINITE);

	VirtualFreeEx(process, p_dllpath, strlen(dllpath) + 1, MEM_RELEASE);

	CloseHandle(snap);

	return 0;
}