// An entry into each native library rune-desktop links (`pe_run.rs`'s
// `rune_desktops_native_libraries_link_and_run`), built `/MT` as `cc` builds them under
// `+crt-static` (`build.ps1`). Each check sets a bit of the exit code when it fails; a library
// the link took wrong crashes instead. The prototypes are the libraries' own C interfaces.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <commctrl.h>
#include <psapi.h>
#include <objbase.h>

#pragma comment(lib, "comctl32")
#pragma comment(lib, "psapi")
#pragma comment(lib, "ole32")
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "winmm")

// SQLite (libsqlite3-sys's bundled amalgamation).
typedef struct sqlite3 sqlite3;
const char *sqlite3_libversion(void);
int sqlite3_open(const char *, sqlite3 **);
int sqlite3_exec(sqlite3 *, const char *, int (*)(void *, int, char **, char **), void *, char **);
int sqlite3_close(sqlite3 *);
// Luau (mlua-sys; C++, its errors are C++ exceptions).
typedef struct lua_State lua_State;
lua_State *luaL_newstate(void);
void luaL_openlibs(lua_State *);
char *luau_compile(const char *, size_t, void *, size_t *);
int luau_load(lua_State *, const char *, const char *, size_t, int);
int lua_pcall(lua_State *, int, int, int);
double lua_tonumberx(lua_State *, int, int *);
void lua_close(lua_State *);
// mimalloc (its thread-exit hook is a TLS callback).
void *mi_malloc(size_t);
void mi_free(void *);
// zstd.
size_t ZSTD_compress(void *, size_t, const void *, size_t, int);
size_t ZSTD_decompress(void *, size_t, const void *, size_t);
unsigned ZSTD_isError(size_t);
// ring's pre-assembled SHA-256 (perlasm COFF objects with SEH handlers).
void ring_core_0_17_14__sha256_block_data_order_nohw(unsigned *, const void *, size_t);
// BLAKE3's MASM compression.
void blake3_compress_in_place_sse2(unsigned *, const unsigned char *, unsigned char, unsigned long long, unsigned char);
// Ghostty's VT (Zig-built).
typedef void *GhosttyTerminal;
int ghostty_terminal_new(const void *, GhosttyTerminal *, unsigned short, unsigned short);
void ghostty_terminal_vt_write(GhosttyTerminal, const unsigned char *, size_t);
void ghostty_terminal_free(GhosttyTerminal);

static int rows(void *count, int n, char **values, char **names) {
    (void)n, (void)values, (void)names;
    ++*(int *)count;
    return 0;
}

static DWORD WINAPI allocating(LPVOID arg) {
    (void)arg;
    void *p = mi_malloc(4096);
    memset(p, 1, 4096);
    mi_free(p);
    return 0;
}

int main(void) {
    int failed = 0;
    sqlite3 *db = NULL;
    int count = 0;
    if (sqlite3_open(":memory:", &db) != 0 ||
        sqlite3_exec(db, "create table t(x); insert into t values (1), (2), (3); select * from t;", rows, &count, NULL) != 0 ||
        count != 3 || strncmp(sqlite3_libversion(), "3.", 2) != 0)
        failed |= 1;
    sqlite3_close(db);

    lua_State *L = luaL_newstate();
    luaL_openlibs(L);
    const char *source = "local ok, why = pcall(error, 'boom') if ok then return 0 end return #tostring(why) + 3";
    size_t size = 0;
    char *bytecode = luau_compile(source, strlen(source), NULL, &size);
    if (luau_load(L, "=natives", bytecode, size, 0) != 0 || lua_pcall(L, 0, 1, 0) != 0 || lua_tonumberx(L, -1, NULL) != 7)
        failed |= 2;
    free(bytecode);
    // An error past every Lua pcall: lua_pcall catches the C++ exception itself.
    const char *throws = "error('out')";
    bytecode = luau_compile(throws, strlen(throws), NULL, &size);
    if (luau_load(L, "=throws", bytecode, size, 0) != 0 || lua_pcall(L, 0, 0, 0) == 0) failed |= 4;
    free(bytecode);
    lua_close(L);

    HANDLE thread = CreateThread(NULL, 0, allocating, NULL, 0, NULL);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    void *block = mi_malloc(100);
    if (block == NULL) failed |= 8;
    mi_free(block);

    char text[256], packed[512], back[256];
    memset(text, 'z', sizeof text);
    size_t n = ZSTD_compress(packed, sizeof packed, text, sizeof text, 3);
    if (ZSTD_isError(n) || ZSTD_decompress(back, sizeof back, packed, n) != sizeof text || memcmp(text, back, sizeof text))
        failed |= 16;

    // SHA-256("abc"): one padded block.
    unsigned state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    unsigned char abc[64] = {'a', 'b', 'c', 0x80};
    abc[63] = 24;
    ring_core_0_17_14__sha256_block_data_order_nohw(state, abc, 1);
    if (state[0] != 0xba7816bf || state[7] != 0xf20015ad) failed |= 32;

    // BLAKE3 of the empty input: one compression of the IV, CHUNK_START | CHUNK_END | ROOT.
    unsigned cv[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};
    unsigned char empty[64] = {0};
    blake3_compress_in_place_sse2(cv, empty, 0, 0, 1 | 2 | 8);
    if (cv[0] != 0xb94913af) failed |= 64;

    GhosttyTerminal term = NULL;
    if (ghostty_terminal_new(NULL, &term, 80, 24) != 0 || term == NULL) {
        failed |= 128;
    } else {
        ghostty_terminal_vt_write(term, (const unsigned char *)"\x1b[1mhi\r\n", 8);
        ghostty_terminal_free(term);
    }

    // Delay-loaded DLLs: none loaded before its first call.
    if (GetModuleHandleW(L"comctl32.dll") != NULL || GetModuleHandleW(L"ws2_32.dll") != NULL) failed |= 256;
    INITCOMMONCONTROLSEX init = {sizeof init, ICC_WIN95_CLASSES};
    WSADATA wsa;
    PROCESS_MEMORY_COUNTERS memory = {sizeof memory};
    if (!InitCommonControlsEx(&init) || WSAStartup(MAKEWORD(2, 2), &wsa) != 0 ||
        !GetProcessMemoryInfo(GetCurrentProcess(), &memory, sizeof memory) || FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)) ||
        timeGetTime() == 0)
        failed |= 512;
    if (GetModuleHandleW(L"comctl32.dll") == NULL || GetModuleHandleW(L"ws2_32.dll") == NULL) failed |= 1024;
    WSACleanup();
    CoUninitialize();

    printf("natives %d\n", failed);
    return failed;
}
