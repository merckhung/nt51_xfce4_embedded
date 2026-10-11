/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _DLFCN_H_
#define _DLFCN_H_

#ifdef __cplusplus
extern "C" {
#endif

#define RTLD_LAZY   1
#define RTLD_NOW    2
#define RTLD_GLOBAL 4
#define RTLD_LOCAL  8

void * __cdecl dlopen(const char *filename, int flags);
void * __cdecl dlsym(void *handle, const char *symbol);
int    __cdecl dlclose(void *handle);
char * __cdecl dlerror(void);

#ifdef __cplusplus
}
#endif

#endif /* _DLFCN_H_ */
