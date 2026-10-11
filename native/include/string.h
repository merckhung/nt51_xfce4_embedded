/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _STRING_H_
#define _STRING_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void * __cdecl memcpy(void *dst, const void *src, size_t n);
void * __cdecl memmove(void *dst, const void *src, size_t n);
void * __cdecl memset(void *dst, int c, size_t n);
int    __cdecl memcmp(const void *s1, const void *s2, size_t n);
void * __cdecl memchr(const void *s, int c, size_t n);

size_t __cdecl strlen(const char *s);
size_t __cdecl strnlen(const char *s, size_t maxlen);
char * __cdecl strcpy(char *dst, const char *src);
char * __cdecl strncpy(char *dst, const char *src, size_t n);
char * __cdecl strcat(char *dst, const char *src);
char * __cdecl strncat(char *dst, const char *src, size_t n);

int    __cdecl strcmp(const char *s1, const char *s2);
int    __cdecl strncmp(const char *s1, const char *s2, size_t n);
int    __cdecl strcasecmp(const char *s1, const char *s2);
int    __cdecl strncasecmp(const char *s1, const char *s2, size_t n);
#define _stricmp  strcasecmp
#define _strnicmp strncasecmp

char * __cdecl strchr(const char *s, int c);
char * __cdecl strrchr(const char *s, int c);
char * __cdecl strstr(const char *haystack, const char *needle);
char * __cdecl strpbrk(const char *s, const char *accept);
size_t __cdecl strspn(const char *s, const char *accept);
size_t __cdecl strcspn(const char *s, const char *reject);
char * __cdecl strtok(char *str, const char *delim);
char * __cdecl strtok_r(char *str, const char *delim, char **saveptr);
char * __cdecl strdup(const char *s);
char * __cdecl strndup(const char *s, size_t n);
char * __cdecl strerror(int errnum);

/* Wide-character string helpers */
size_t   __cdecl wcslen(const wchar_t *s);
wchar_t *__cdecl wcscpy(wchar_t *dst, const wchar_t *src);
wchar_t *__cdecl wcsncpy(wchar_t *dst, const wchar_t *src, size_t n);
wchar_t *__cdecl wcscat(wchar_t *dst, const wchar_t *src);
int      __cdecl wcscmp(const wchar_t *s1, const wchar_t *s2);
int      __cdecl _wcsicmp(const wchar_t *s1, const wchar_t *s2);
int      __cdecl _wcsnicmp(const wchar_t *s1, const wchar_t *s2, size_t n);
wchar_t *__cdecl wcsrchr(const wchar_t *s, wchar_t c);

#ifdef __cplusplus
}
#endif

#endif /* _STRING_H_ */
