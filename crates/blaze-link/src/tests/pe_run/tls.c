// Thread-locals (`__declspec(thread)`: `.tls`, `_tls_index`, the TLS directory the CRT's
// `_tls_used` is), a TLS callback (`.CRT$XLB`, run by the loader for the process and each
// thread), and threads that each see their own copy (`build.ps1`).
#include <stdio.h>
#include <windows.h>

static __declspec(thread) int counter = 100;
static __declspec(thread) char big[4096] = {1};
static volatile LONG attached = 0;
static volatile LONG process_attached = 0;

static void NTAPI callback(PVOID module, DWORD reason, PVOID reserved) {
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) InterlockedIncrement(&process_attached);
    if (reason == DLL_THREAD_ATTACH) InterlockedIncrement(&attached);
}

#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK tls_callback = callback;
// Kept although nothing names it: link.exe keeps `.CRT$XL*` because the CRT's `_tls_used`
// refers to `__xl_a`, and the symbol is the object's.
#pragma comment(linker, "/INCLUDE:tls_callback")

static DWORD WINAPI worker(LPVOID arg) {
    int n = (int)(INT_PTR)arg;
    if (counter != 100 || big[0] != 1) return 1000;
    counter += n;
    big[0] = (char)n;
    Sleep(10);
    return (DWORD)(counter - 100 + big[0]);
}

int main(void) {
    HANDLE threads[4];
    for (int i = 0; i < 4; i++) threads[i] = CreateThread(NULL, 0, worker, (LPVOID)(INT_PTR)(i + 1), 0, NULL);
    WaitForMultipleObjects(4, threads, TRUE, INFINITE);
    int bad = 0;
    for (int i = 0; i < 4; i++) {
        DWORD code = 0;
        GetExitCodeThread(threads[i], &code);
        if (code != (DWORD)(2 * (i + 1))) bad++;
        CloseHandle(threads[i]);
    }
    printf("tls %d %d %ld %ld\n", counter, bad, process_attached, attached);
    return counter == 100 && bad == 0 && process_attached == 1 && attached >= 4 ? 0 : 1;
}
