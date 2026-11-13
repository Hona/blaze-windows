// A program that asks dbghelp, as std's backtrace does, for the name and line of a function
// blaze linked from Rust code (`blaze_answer`), and the name of its own `main`: what the
// image's PDB says of them.
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>

#pragma comment(lib, "dbghelp.lib")

int blaze_answer(void);

int main(void) {
    HANDLE process = GetCurrentProcess();
    DWORD64 at = (DWORD64)(ULONG_PTR)&blaze_answer;
    char buffer[sizeof(SYMBOL_INFO) + 256];
    SYMBOL_INFO *symbol = (SYMBOL_INFO *)buffer;
    IMAGEHLP_LINE64 line;
    DWORD64 displacement = 0;
    DWORD column = 0;
    int answer = blaze_answer();
    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_DEFERRED_LOADS);
    if (!SymInitialize(process, NULL, TRUE)) {
        printf("SymInitialize: %lu\n", GetLastError());
        return 1;
    }
    ZeroMemory(buffer, sizeof buffer);
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = 255;
    if (!SymFromAddr(process, at + 2, &displacement, symbol)) {
        printf("SymFromAddr: %lu\n", GetLastError());
        return 2;
    }
    printf("%d %s+%llu\n", answer, symbol->Name, displacement);
    ZeroMemory(&line, sizeof line);
    line.SizeOfStruct = sizeof line;
    if (!SymGetLineFromAddr64(process, at + 5, &column, &line)) {
        printf("SymGetLineFromAddr64: %lu\n", GetLastError());
        return 3;
    }
    printf("%s:%lu\n", line.FileName, line.LineNumber);
    // C code is named too, by the PDB's publics.
    if (!SymFromAddr(process, (DWORD64)(ULONG_PTR)&main + 1, &displacement, symbol)) {
        printf("SymFromAddr main: %lu\n", GetLastError());
        return 4;
    }
    printf("%s+%llu\n", symbol->Name, displacement);
    return 0;
}
