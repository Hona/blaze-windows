// Code built with `/guard:cf` and `/GS`: indirect calls through `__guard_dispatch_icall_fptr`
// (`.gfids`, the load config's guard fields), a stack buffer the security cookie guards, and
// `setjmp`/`longjmp` (`.gljmp`) (`build.ps1`).
#include <setjmp.h>
#include <stdio.h>
#include <string.h>

static jmp_buf back;

static int square(int x) { return x * x; }
static int negate(int x) { return -x; }
static int (*volatile pick[2])(int) = {square, negate};

static void jumps(int x) {
    char buffer[32];
    memset(buffer, x, sizeof buffer);
    if (buffer[31] == x) longjmp(back, x);
}

int main(void) {
    int total = pick[0](5) + pick[1](3);
    int jumped = setjmp(back);
    if (jumped == 0) jumps(7);
    printf("cfg %d %d\n", total, jumped);
    return total == 22 && jumped == 7 ? 0 : 1;
}
