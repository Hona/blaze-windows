// An executable importing a function and data from `runlib.dll` (`dll.c`) through its import
// library, and loading it a second time by name (`build.ps1`).
#include <stdio.h>
#include <windows.h>

__declspec(dllimport) int runlib_value;
__declspec(dllimport) int runlib_add(int a, int b);

int main(void) {
    int sum = runlib_add(1, runlib_value);
    HMODULE module = GetModuleHandleA("runlib.dll");
    FARPROC add = module ? GetProcAddress(module, "runlib_add") : NULL;
    printf("dll %d %s\n", sum, add ? "found" : "missing");
    return sum == 42 && add != NULL ? 0 : 1;
}
