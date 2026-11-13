// A console program: the CRT's startup, stdio, a /GS-checked buffer, an import, and its
// exit code. Built twice, with the dynamic and the static C runtime (`build.ps1`).
#include <stdio.h>
#include <string.h>
#include <windows.h>

static int copied(const char *from) {
    char buffer[64];
    strcpy_s(buffer, sizeof buffer, from);
    return (int)strlen(buffer);
}

int main(int argc, char **argv) {
    printf("hello from %s, %d args\n", argc > 1 ? argv[1] : "nobody", argc);
    DWORD pid = GetCurrentProcessId();
    printf("pid %s\n", pid != 0 ? "set" : "zero");
    return copied("seven!!") * 6;
}
