#include <Windows.h>

#pragma comment(lib, "User32.lib");

BOOL WINAPI DllMain(
  _In_ HINSTANCE hinstDLL,
  _In_ DWORD     fdwReason,
  _In_ LPVOID    lpvReserved
)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
		MessageBox(0, "CONGRATULATIONS!\nYOU WON!", "CONGRATULATIONS", MB_ICONINFORMATION);

	return TRUE;
}

// to compile: cl /LD test.cpp