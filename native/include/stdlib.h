/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _STDLIB_H_
#define _STDLIB_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define RAND_MAX     0x7FFF

void * __cdecl malloc(size_t size);
void * __cdecl calloc(size_t nmemb, size_t size);
void * __cdecl realloc(void *ptr, size_t size);
void   __cdecl free(void *ptr);

void   __cdecl exit(int status);
void   __cdecl _exit(int status);
void   __cdecl abort(void);
int    __cdecl atexit(void (__cdecl *func)(void));

int    __cdecl atoi(const char *nptr);
long   __cdecl atol(const char *nptr);
__int64 __cdecl _atoi64(const char *nptr);
long   __cdecl strtol(const char *nptr, char **endptr, int base);
unsigned long __cdecl strtoul(const char *nptr, char **endptr, int base);
__int64 __cdecl strtoll(const char *nptr, char **endptr, int base);
unsigned __int64 __cdecl strtoull(const char *nptr, char **endptr, int base);

int    __cdecl abs(int j);
long   __cdecl labs(long j);

int    __cdecl rand(void);
void   __cdecl srand(unsigned int seed);

void   __cdecl qsort(void *base, size_t nmemb, size_t size,
                     int (__cdecl *compar)(const void *, const void *));
void * __cdecl bsearch(const void *key, const void *base, size_t nmemb, size_t size,
                       int (__cdecl *compar)(const void *, const void *));

char * __cdecl getenv(const char *name);
int    __cdecl setenv(const char *name, const char *value, int overwrite);
int    __cdecl unsetenv(const char *name);
char **__cdecl _get_environ(void);
#define environ (_get_environ())

int    __cdecl system(const char *command);

#ifdef __cplusplus
}
#endif

#endif /* _STDLIB_H_ */
