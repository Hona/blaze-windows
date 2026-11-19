// Reads its own resources back as the loader and the shell do (`build.ps1`): the manifest the
// loader activated (common controls 6 answers `TaskDialogIndirect`, which only version 6 has;
// per-monitor DPI awareness), the icon, the version info, data by name and by number, and a
// string in a second resource file's language.
#define UNICODE
#include <stdio.h>
#include <string.h>
#include <windows.h>

#pragma comment(lib, "version")
#pragma comment(lib, "user32")

static int has(HMODULE module, LPCWSTR type, LPCWSTR name, WORD language, const char *want) {
    HRSRC found = FindResourceExW(module, type, name, language);
    if (found == NULL) return 0;
    HGLOBAL loaded = LoadResource(module, found);
    const char *bytes = (const char *)LockResource(loaded);
    if (want == NULL) return SizeofResource(module, found) > 0;
    return bytes != NULL && memcmp(bytes, want, strlen(want) + 1) == 0;
}

int main(void) {
    HMODULE self = GetModuleHandleW(NULL);
    int failed = 0;
    // The manifest's common controls 6: comctl32 v6 exports TaskDialogIndirect, v5 does not.
    HMODULE comctl = LoadLibraryW(L"comctl32.dll");
    if (comctl == NULL || GetProcAddress(comctl, "TaskDialogIndirect") == NULL) failed |= 1;
    // The manifest's DPI awareness, which the loader applies before `main`.
    if (!AreDpiAwarenessContextsEqual(GetThreadDpiAwarenessContext(), DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) failed |= 2;
    if (!has(self, RT_GROUP_ICON, MAKEINTRESOURCEW(1), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), NULL)) failed |= 4;
    if (!has(self, RT_RCDATA, L"BLOB", MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), "blob data")) failed |= 8;
    if (!has(self, RT_RCDATA, MAKEINTRESOURCEW(7), MAKELANGID(LANG_GERMAN, SUBLANG_GERMAN), "seven")) failed |= 16;
    WCHAR text[32] = {0};
    // String 100 is in block 100 / 16 + 1, in German only.
    HRSRC block = FindResourceExW(self, RT_STRING, MAKEINTRESOURCEW(100 / 16 + 1), MAKELANGID(LANG_GERMAN, SUBLANG_GERMAN));
    if (block == NULL || LoadStringW(self, 100, text, 32) == 0 || wcscmp(text, L"zweite Datei") != 0) failed |= 32;
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    DWORD size = GetFileVersionInfoSizeW(path, NULL);
    static char info[4096];
    VS_FIXEDFILEINFO *fixed = NULL;
    UINT len = 0;
    if (size == 0 || size > sizeof info || !GetFileVersionInfoW(path, 0, sizeof info, info) ||
        !VerQueryValueW(info, L"\\", (void **)&fixed, &len) || fixed->dwFileVersionMS != 0x00010002 ||
        fixed->dwFileVersionLS != 0x00030004)
        failed |= 64;
    printf("res %d\n", failed);
    return failed;
}
