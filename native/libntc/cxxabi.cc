/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * native/libntc/cxxabi.cc
 * Freestanding C++ Runtime Support (new, delete, _purecall, static initializers)
 */

#include "../include/ntnative.h"
#include <stdlib.h>
#include <new>

typedef void (__cdecl *_PVFV)(void);

#pragma data_seg(".CRT$XCA")
_PVFV __xc_a[] = { 0 };
#pragma data_seg(".CRT$XCZ")
_PVFV __xc_z[] = { 0 };
#pragma data_seg()

#pragma comment(linker, "/merge:.CRT=.data")

extern "C" void __cdecl _libntc_run_cxx_ctors(void) {
    _PVFV *pf = __xc_a;
    for (; pf < __xc_z; pf++) {
        if (*pf) {
            (**pf)();
        }
    }
}

extern "C" void __cdecl _libntc_run_cxx_dtors(void) {
}

extern "C" int __cdecl _purecall(void) {
    abort();
    return 0;
}

void * __cdecl operator new(size_t size) {
    return malloc(size ? size : 1);
}

void * __cdecl operator new[](size_t size) {
    return malloc(size ? size : 1);
}

void __cdecl operator delete(void *ptr) {
    if (ptr) free(ptr);
}

void __cdecl operator delete[](void *ptr) {
    if (ptr) free(ptr);
}
