#include <stdint.h>

int32_t native_add_mul(int32_t a, int32_t b, int32_t scale) {
    return (a + b) * scale;
}
