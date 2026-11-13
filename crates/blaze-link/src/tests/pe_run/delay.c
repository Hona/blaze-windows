// Delay-loaded imports (`/DELAYLOAD:comctl32.dll /DELAYLOAD:version.dll /DELAYLOAD:nosuch.dll`
// with `delayimp.lib`, `build.ps1`): neither DLL is loaded before its first call, each is after
// it, a second call goes straight to the function, and a DLL that is not there raises the
// helper's exception (`VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND)`), which unwinds
// through the tail merge to this `__except`.
#include <stdio.h>
#include <windows.h>
#include <commctrl.h>

#pragma comment(lib, "comctl32")
#pragma comment(lib, "version")

__declspec(dllimport) int nosuch_fn(void);

static DWORD caught(void) {
    __try {
        return (DWORD)nosuch_fn();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

int main(void) {
    int failed = 0;
    if (GetModuleHandleW(L"comctl32.dll") != NULL) failed |= 1;
    if (GetModuleHandleW(L"version.dll") != NULL) failed |= 2;
    INITCOMMONCONTROLSEX init = {sizeof init, ICC_WIN95_CLASSES};
    if (!InitCommonControlsEx(&init)) failed |= 4;
    if (GetModuleHandleW(L"comctl32.dll") == NULL) failed |= 8;
    if (!InitCommonControlsEx(&init)) failed |= 16;
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    GetFileVersionInfoSizeW(path, NULL);
    if (GetModuleHandleW(L"version.dll") == NULL) failed |= 32;
    // The exception: facility 0x6d (delay load), ERROR_MOD_NOT_FOUND.
    if (caught() != 0xC06D007E) failed |= 64;
    printf("delay %d\n", failed);
    return failed;
}
