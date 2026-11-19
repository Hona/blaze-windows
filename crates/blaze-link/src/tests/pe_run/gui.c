// A GUI-subsystem program entered at `mainCRTStartup` (what rustc links for
// `#![windows_subsystem = "windows"]`, and rune-desktop's `/SUBSYSTEM:WINDOWS`
// `/ENTRY:mainCRTStartup`): the loader gives it no console, and `main` still runs (`build.ps1`).
#include <stdio.h>
#include <windows.h>

int main(void) {
    HWND console = GetConsoleWindow();
    printf("gui %s\n", console == NULL ? "without a console" : "with a console");
    return console == NULL ? 0 : 1;
}
