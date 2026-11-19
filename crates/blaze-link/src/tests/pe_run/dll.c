// A DLL: an exported function and exported data, `DllMain` through the CRT's
// `_DllMainCRTStartup`, and a base relocation (the pointer in `table`) the loader applies when
// the DLL does not load at its preferred base (`build.ps1`).
#include <windows.h>

static int attaches = 0;
static int twice(int x) { return 2 * x; }
static int (*const table[])(int) = {twice};

__declspec(dllexport) int runlib_value = 40;

__declspec(dllexport) int runlib_add(int a, int b) { return table[0](a) / 2 + b + attaches; }

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) attaches++;
    return TRUE;
}
