// C++ with exceptions (`/EHsc`: `__CxxFrameHandler4`, `.xdata` handler data, `_CxxThrowException`),
// static initialisers (`.CRT$XCU`), a function-local static (thread-safe init through
// `_Init_thread_header`), `std::string` and `std::vector` (the STL's COMDATs), and a destructor
// run during unwinding. Built with the dynamic and the static C runtime (`build.ps1`).
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

static int constructed = 0;
static int destroyed = 0;

struct Counted {
    std::string name;
    explicit Counted(const char *it) : name(it) { constructed++; }
    ~Counted() { destroyed++; }
};

// Two dynamic initialisers: they run before `main`, in this order.
static Counted first("first");
static std::vector<int> squares = [] {
    std::vector<int> out;
    for (int i = 0; i < 10; i++) out.push_back(i * i);
    return out;
}();

static int once() {
    static Counted local("local");
    return (int)local.name.size();
}

static void thrower(int depth) {
    Counted guard("guard");
    if (depth == 0) throw std::runtime_error("deep");
    thrower(depth - 1);
}

int main() {
    if (constructed != 1 || squares.size() != 10 || squares[9] != 81) {
        std::printf("static initialisers did not run: %d %zu\n", constructed, squares.size());
        return 1;
    }
    int caught = 0;
    try {
        thrower(4);
    } catch (const std::exception &e) {
        caught = std::string(e.what()) == "deep" ? 1 : 2;
    }
    if (caught != 1 || destroyed != 5) {
        std::printf("unwinding: caught %d, destroyed %d\n", caught, destroyed);
        return 2;
    }
    try {
        throw 42;
    } catch (int value) {
        caught = value;
    }
    std::printf("cpp ok %d %d\n", caught, once() + once());
    return caught == 42 ? 0 : 3;
}
