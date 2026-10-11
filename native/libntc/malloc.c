/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * native/libntc/malloc.c
 * Heap Allocation, Numeric Conversions, Sorting, and Dynamic Linker Wrappers
 */

#include "../include/ntnative.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <dlfcn.h>

#define HEAP_ZERO_MEMORY 0x00000008

void * __cdecl malloc(size_t size) {
    void *p = RtlAllocateHeap(RtlGetProcessHeap(), 0, size ? size : 1);
    if (!p) errno = ENOMEM;
    return p;
}

void * __cdecl calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    void *p = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, total ? total : 1);
    if (!p) errno = ENOMEM;
    return p;
}

void * __cdecl realloc(void *ptr, size_t size) {
    void *p = RtlReAllocateHeap(RtlGetProcessHeap(), 0, ptr, size);
    if (!p && size != 0) errno = ENOMEM;
    return p;
}

void __cdecl free(void *ptr) {
    if (ptr) {
        RtlFreeHeap(RtlGetProcessHeap(), 0, ptr);
    }
}

int __cdecl abs(int j) {
    return (j < 0) ? -j : j;
}

long __cdecl labs(long j) {
    return (j < 0) ? -j : j;
}

unsigned __int64 __cdecl strtoull(const char *nptr, char **endptr, int base) {
    const char *s = nptr;
    unsigned __int64 acc = 0;
    int neg = 0;
    int any = 0;

    if (!s) {
        if (endptr) *endptr = NULL;
        return 0;
    }
    while (isspace((unsigned char)*s)) s++;
    if (*s == '-') {
        neg = 1;
        s++;
    } else if (*s == '+') {
        s++;
    }
    if ((base == 0 || base == 16) && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
        base = 16;
    }
    if (base == 0) {
        base = (s[0] == '0') ? 8 : 10;
    }
    for (; *s; s++) {
        int c = (unsigned char)*s;
        int digit;
        if (isdigit(c)) digit = c - '0';
        else if (isalpha(c)) digit = toupper(c) - 'A' + 10;
        else break;
        if (digit >= base) break;
        acc = acc * (unsigned __int64)base + (unsigned __int64)digit;
        any = 1;
    }
    if (endptr) {
        *endptr = (char *)(any ? s : nptr);
    }
    return neg ? (unsigned __int64)(-(__int64)acc) : acc;
}

__int64 __cdecl strtoll(const char *nptr, char **endptr, int base) {
    return (__int64)strtoull(nptr, endptr, base);
}

unsigned long __cdecl strtoul(const char *nptr, char **endptr, int base) {
    return (unsigned long)strtoull(nptr, endptr, base);
}

long __cdecl strtol(const char *nptr, char **endptr, int base) {
    return (long)strtoll(nptr, endptr, base);
}

int __cdecl atoi(const char *nptr) {
    return (int)strtol(nptr, NULL, 10);
}

long __cdecl atol(const char *nptr) {
    return strtol(nptr, NULL, 10);
}

__int64 __cdecl _atoi64(const char *nptr) {
    return strtoll(nptr, NULL, 10);
}

static unsigned int g_rand_seed = 1;

void __cdecl srand(unsigned int seed) {
    g_rand_seed = seed;
}

int __cdecl rand(void) {
    g_rand_seed = g_rand_seed * 1103515245 + 12345;
    return (int)((g_rand_seed >> 16) & RAND_MAX);
}

void __cdecl qsort(
    void *base,
    size_t nmemb,
    size_t size,
    int (__cdecl *compar)(const void *, const void *)
) {
    unsigned char *arr = (unsigned char *)base;
    size_t i, j;
    if (nmemb < 2 || size == 0 || !base || !compar) return;

    /* Shell sort (in-place, bounded stack, fast for embedded arrays) */
    {
        size_t gap = nmemb / 2;
        while (gap > 0) {
            for (i = gap; i < nmemb; i++) {
                j = i;
                while (j >= gap && compar(arr + (j - gap) * size, arr + j * size) > 0) {
                    unsigned char *a = arr + (j - gap) * size;
                    unsigned char *b = arr + j * size;
                    size_t k;
                    for (k = 0; k < size; k++) {
                        unsigned char tmp = a[k];
                        a[k] = b[k];
                        b[k] = tmp;
                    }
                    j -= gap;
                }
            }
            gap /= 2;
        }
    }
}

void * __cdecl bsearch(
    const void *key,
    const void *base,
    size_t nmemb,
    size_t size,
    int (__cdecl *compar)(const void *, const void *)
) {
    const unsigned char *arr = (const unsigned char *)base;
    size_t low = 0, high = nmemb;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        const void *elem = arr + mid * size;
        int cmp = compar(key, elem);
        if (cmp == 0) return (void *)elem;
        if (cmp < 0) high = mid;
        else low = mid + 1;
    }
    return NULL;
}

/* POSIX dlopen / dlsym / dlclose / dlerror backed by LdrLoadDll */
static char g_dlerror_buf[128] = "";

void * __cdecl dlopen(const char *filename, int flags) {
    ANSI_STRING a_str;
    UNICODE_STRING u_str;
    WCHAR wbuf[260];
    PVOID handle = NULL;
    NTSTATUS st;

    if (!filename) {
        return NtCurrentPeb()->ImageBaseAddress;
    }

    RtlInitAnsiString(&a_str, filename);
    u_str.Buffer = wbuf;
    u_str.Length = 0;
    u_str.MaximumLength = sizeof(wbuf);
    RtlAnsiStringToUnicodeString(&u_str, &a_str, FALSE);

    st = LdrLoadDll(NULL, NULL, &u_str, &handle);
    if (!NT_SUCCESS(st)) {
        strcpy(g_dlerror_buf, "LdrLoadDll failed");
        return NULL;
    }
    g_dlerror_buf[0] = '\0';
    return handle;
}

void * __cdecl dlsym(void *handle, const char *symbol) {
    ANSI_STRING a_sym;
    PVOID addr = NULL;
    NTSTATUS st;

    if (!handle || !symbol) {
        strcpy(g_dlerror_buf, "Invalid handle or symbol");
        return NULL;
    }
    RtlInitAnsiString(&a_sym, symbol);
    st = LdrGetProcedureAddress(handle, &a_sym, 0, &addr);
    if (!NT_SUCCESS(st)) {
        strcpy(g_dlerror_buf, "LdrGetProcedureAddress failed");
        return NULL;
    }
    g_dlerror_buf[0] = '\0';
    return addr;
}

int __cdecl dlclose(void *handle) {
    NTSTATUS st = LdrUnloadDll(handle);
    return NT_SUCCESS(st) ? 0 : -1;
}

char * __cdecl dlerror(void) {
    return g_dlerror_buf[0] ? g_dlerror_buf : NULL;
}
