/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * native/libntc/string.c
 * Standard C99/POSIX String, Memory, Wide-String, and Errno Routines
 */

#include "../include/ntnative.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#pragma function(memset, memcpy, memcmp, strlen)

static int g_errno_val = 0;

int * __cdecl __errno_location(void) {
    return &g_errno_val;
}

int __cdecl _ntstatus_to_errno(long status) {
    NTSTATUS st = (NTSTATUS)status;
    if (NT_SUCCESS(st)) return 0;
    switch (st) {
        case STATUS_OBJECT_NAME_NOT_FOUND:
        case STATUS_NO_SUCH_FILE:
        case STATUS_OBJECT_PATH_NOT_FOUND:
        case STATUS_NO_SUCH_DEVICE:        return ENOENT;
        case STATUS_ACCESS_DENIED:
        case STATUS_PRIVILEGE_NOT_HELD:
        case STATUS_SHARING_VIOLATION:     return EACCES;
        case STATUS_INVALID_HANDLE:        return EBADF;
        case STATUS_NO_MEMORY:
        case STATUS_INSUFFICIENT_RESOURCES:return ENOMEM;
        case STATUS_INVALID_PARAMETER:
        case STATUS_OBJECT_NAME_INVALID:
        case STATUS_OBJECT_PATH_SYNTAX_BAD:return EINVAL;
        case STATUS_OBJECT_NAME_COLLISION: return EEXIST;
        case STATUS_DIRECTORY_NOT_EMPTY:   return ENOTEMPTY;
        case STATUS_NOT_A_DIRECTORY:       return ENOTDIR;
        case STATUS_FILE_IS_A_DIRECTORY:   return EISDIR;
        case STATUS_DISK_FULL:             return ENOSPC;
        case STATUS_PIPE_BROKEN:
        case STATUS_PIPE_CLOSING:
        case STATUS_PIPE_DISCONNECTED:     return EPIPE;
        case STATUS_INVALID_IMAGE_FORMAT:  return ENOEXEC;
        case STATUS_NOT_IMPLEMENTED:
        case STATUS_NOT_SUPPORTED:         return ENOSYS;
        default:                           return EIO;
    }
}

void * __cdecl memset(void *dst, int c, size_t n) {
    unsigned char *p = (unsigned char *)dst;
    while (n--) {
        *p++ = (unsigned char)c;
    }
    return dst;
}

void * __cdecl memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) {
        *d++ = *s++;
    }
    return dst;
}

void * __cdecl memmove(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d < s) {
        while (n--) {
            *d++ = *s++;
        }
    } else if (d > s) {
        d += n;
        s += n;
        while (n--) {
            *--d = *--s;
        }
    }
    return dst;
}

int __cdecl memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;
    while (n--) {
        if (*p1 != *p2) {
            return (int)*p1 - (int)*p2;
        }
        p1++;
        p2++;
    }
    return 0;
}

void * __cdecl memchr(const void *s, int c, size_t n) {
    const unsigned char *p = (const unsigned char *)s;
    unsigned char uc = (unsigned char)c;
    while (n--) {
        if (*p == uc) return (void *)p;
        p++;
    }
    return NULL;
}

size_t __cdecl strlen(const char *s) {
    const char *p = s;
    if (!s) return 0;
    while (*p) p++;
    return (size_t)(p - s);
}

size_t __cdecl strnlen(const char *s, size_t maxlen) {
    size_t len = 0;
    if (!s) return 0;
    while (len < maxlen && s[len]) len++;
    return len;
}

char * __cdecl strcpy(char *dst, const char *src) {
    char *d = dst;
    while ((*d++ = *src++) != '\0') {}
    return dst;
}

char * __cdecl strncpy(char *dst, const char *src, size_t n) {
    size_t i = 0;
    for (; i < n && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    for (; i < n; i++) {
        dst[i] = '\0';
    }
    return dst;
}

char * __cdecl strcat(char *dst, const char *src) {
    char *d = dst + strlen(dst);
    while ((*d++ = *src++) != '\0') {}
    return dst;
}

char * __cdecl strncat(char *dst, const char *src, size_t n) {
    char *d = dst + strlen(dst);
    size_t i = 0;
    for (; i < n && src[i] != '\0'; i++) {
        d[i] = src[i];
    }
    d[i] = '\0';
    return dst;
}

int __cdecl strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return (int)(unsigned char)*s1 - (int)(unsigned char)*s2;
}

int __cdecl strncmp(const char *s1, const char *s2, size_t n) {
    if (n == 0) return 0;
    while (--n && *s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return (int)(unsigned char)*s1 - (int)(unsigned char)*s2;
}

int __cdecl strcasecmp(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        int c1 = tolower((unsigned char)*s1);
        int c2 = tolower((unsigned char)*s2);
        if (c1 != c2) return c1 - c2;
        s1++;
        s2++;
    }
    return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
}

int __cdecl strncasecmp(const char *s1, const char *s2, size_t n) {
    if (n == 0) return 0;
    while (--n && *s1 && *s2) {
        int c1 = tolower((unsigned char)*s1);
        int c2 = tolower((unsigned char)*s2);
        if (c1 != c2) return c1 - c2;
        s1++;
        s2++;
    }
    return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
}

char * __cdecl strchr(const char *s, int c) {
    char ch = (char)c;
    for (; *s != '\0'; s++) {
        if (*s == ch) return (char *)s;
    }
    return (ch == '\0') ? (char *)s : NULL;
}

char * __cdecl strrchr(const char *s, int c) {
    const char *last = NULL;
    char ch = (char)c;
    for (; *s != '\0'; s++) {
        if (*s == ch) last = s;
    }
    return (ch == '\0') ? (char *)s : (char *)last;
}

char * __cdecl strstr(const char *haystack, const char *needle) {
    size_t nlen;
    if (!*needle) return (char *)haystack;
    nlen = strlen(needle);
    for (; *haystack; haystack++) {
        if (*haystack == *needle && strncmp(haystack, needle, nlen) == 0) {
            return (char *)haystack;
        }
    }
    return NULL;
}

char * __cdecl strpbrk(const char *s, const char *accept) {
    for (; *s; s++) {
        if (strchr(accept, *s)) return (char *)s;
    }
    return NULL;
}

size_t __cdecl strspn(const char *s, const char *accept) {
    size_t count = 0;
    for (; *s && strchr(accept, *s); s++) {
        count++;
    }
    return count;
}

size_t __cdecl strcspn(const char *s, const char *reject) {
    size_t count = 0;
    for (; *s && !strchr(reject, *s); s++) {
        count++;
    }
    return count;
}

char * __cdecl strtok_r(char *str, const char *delim, char **saveptr) {
    char *token;
    if (!str) str = *saveptr;
    if (!str) return NULL;
    str += strspn(str, delim);
    if (*str == '\0') {
        *saveptr = NULL;
        return NULL;
    }
    token = str;
    str = strpbrk(token, delim);
    if (str) {
        *str = '\0';
        *saveptr = str + 1;
    } else {
        *saveptr = NULL;
    }
    return token;
}

static char *g_strtok_save = NULL;

char * __cdecl strtok(char *str, const char *delim) {
    return strtok_r(str, delim, &g_strtok_save);
}

char * __cdecl strdup(const char *s) {
    size_t len;
    char *copy;
    if (!s) return NULL;
    len = strlen(s);
    copy = (char *)malloc(len + 1);
    if (!copy) return NULL;
    memcpy(copy, s, len + 1);
    return copy;
}

char * __cdecl strndup(const char *s, size_t n) {
    size_t len;
    char *copy;
    if (!s) return NULL;
    len = strnlen(s, n);
    copy = (char *)malloc(len + 1);
    if (!copy) return NULL;
    memcpy(copy, s, len);
    copy[len] = '\0';
    return copy;
}

char * __cdecl strerror(int errnum) {
    switch (errnum) {
        case 0:          return "Success";
        case EPERM:      return "Operation not permitted";
        case ENOENT:     return "No such file or directory";
        case ESRCH:      return "No such process";
        case EINTR:      return "Interrupted system call";
        case EIO:        return "I/O error";
        case EBADF:      return "Bad file descriptor";
        case ECHILD:     return "No child processes";
        case EAGAIN:     return "Resource temporarily unavailable";
        case ENOMEM:     return "Out of memory";
        case EACCES:     return "Permission denied";
        case EEXIST:     return "File exists";
        case ENOTDIR:    return "Not a directory";
        case EISDIR:     return "Is a directory";
        case EINVAL:     return "Invalid argument";
        case EMFILE:     return "Too many open files";
        case ENOSPC:     return "No space left on device";
        case EPIPE:      return "Broken pipe";
        case ENOEXEC:    return "Exec format error";
        case ENOTEMPTY:  return "Directory not empty";
        case ENOSYS:     return "Function not implemented";
        default:         return "Unknown error";
    }
}

size_t __cdecl wcslen(const wchar_t *s) {
    const wchar_t *p = s;
    if (!s) return 0;
    while (*p) p++;
    return (size_t)(p - s);
}

wchar_t * __cdecl wcscpy(wchar_t *dst, const wchar_t *src) {
    wchar_t *d = dst;
    while ((*d++ = *src++) != L'\0') {}
    return dst;
}

wchar_t * __cdecl wcsncpy(wchar_t *dst, const wchar_t *src, size_t n) {
    size_t i = 0;
    for (; i < n && src[i] != L'\0'; i++) dst[i] = src[i];
    for (; i < n; i++) dst[i] = L'\0';
    return dst;
}

wchar_t * __cdecl wcscat(wchar_t *dst, const wchar_t *src) {
    wchar_t *d = dst + wcslen(dst);
    while ((*d++ = *src++) != L'\0') {}
    return dst;
}

int __cdecl wcscmp(const wchar_t *s1, const wchar_t *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return (int)*s1 - (int)*s2;
}

int __cdecl _wcsicmp(const wchar_t *s1, const wchar_t *s2) {
    while (*s1 && *s2) {
        wchar_t c1 = RtlUpcaseUnicodeChar(*s1);
        wchar_t c2 = RtlUpcaseUnicodeChar(*s2);
        if (c1 != c2) return (int)c1 - (int)c2;
        s1++;
        s2++;
    }
    return (int)RtlUpcaseUnicodeChar(*s1) - (int)RtlUpcaseUnicodeChar(*s2);
}

int __cdecl _wcsnicmp(const wchar_t *s1, const wchar_t *s2, size_t n) {
    if (n == 0) return 0;
    while (--n && *s1 && *s2) {
        wchar_t c1 = RtlUpcaseUnicodeChar(*s1);
        wchar_t c2 = RtlUpcaseUnicodeChar(*s2);
        if (c1 != c2) return (int)c1 - (int)c2;
        s1++;
        s2++;
    }
    return (int)RtlUpcaseUnicodeChar(*s1) - (int)RtlUpcaseUnicodeChar(*s2);
}

wchar_t * __cdecl wcsrchr(const wchar_t *s, wchar_t c) {
    const wchar_t *last = NULL;
    for (; *s != L'\0'; s++) {
        if (*s == c) last = s;
    }
    return (c == L'\0') ? (wchar_t *)s : (wchar_t *)last;
}
