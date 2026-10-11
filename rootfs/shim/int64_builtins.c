/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>

static void udivmod64(uint64_t n, uint64_t d, uint64_t *q, uint64_t *r) {
    if (d == 0) {
        if (q) *q = 0;
        if (r) *r = 0;
        return;
    }
    uint64_t quot = 0;
    uint64_t rem = 0;
    for (int i = 63; i >= 0; i--) {
        rem = (rem << 1) | ((n >> i) & 1);
        if (rem >= d) {
            rem -= d;
            quot |= ((uint64_t)1 << i);
        }
    }
    if (q) *q = quot;
    if (r) *r = rem;
}

uint64_t __udivdi3(uint64_t a, uint64_t b) {
    uint64_t q;
    udivmod64(a, b, &q, 0);
    return q;
}

uint64_t __umoddi3(uint64_t a, uint64_t b) {
    uint64_t r;
    udivmod64(a, b, 0, &r);
    return r;
}

int64_t __divdi3(int64_t a, int64_t b) {
    int neg = 0;
    if (a < 0) { a = -a; neg = !neg; }
    if (b < 0) { b = -b; neg = !neg; }
    uint64_t q;
    udivmod64((uint64_t)a, (uint64_t)b, &q, 0);
    return neg ? -(int64_t)q : (int64_t)q;
}

int64_t __moddi3(int64_t a, int64_t b) {
    int neg = (a < 0);
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    uint64_t r;
    udivmod64((uint64_t)a, (uint64_t)b, 0, &r);
    return neg ? -(int64_t)r : (int64_t)r;
}
