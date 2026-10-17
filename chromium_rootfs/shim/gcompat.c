/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * chromium_rootfs/shim/gcompat.c
 * Minimal 32-bit glibc ABI compatibility layer (libc.so.6) on top of musl
 * (ld-musl-i386.so.1) for running 32-bit Chromium, ANGLE, and SwiftShader
 * natively on the NT 5.1 kernel + Linux syscall shim.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <langinfo.h>
#include <locale.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define strerror_r __musl_posix_strerror_r
#include <string.h>
#undef strerror_r
#include <time.h>
#include <wchar.h>
#include <wctype.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/stat.h>

/* Stack end pointer expected by glibc-linked binaries/libraries */
void *__libc_stack_end = 0;

/* Fork and atexit handler registration */
int __register_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void), void *dso_handle) {
    (void)prepare;
    (void)parent;
    (void)child;
    (void)dso_handle;
    return 0;
}

int __cxa_atexit(void (*func)(void *), void *arg, void *dso_handle) {
    (void)func;
    (void)arg;
    (void)dso_handle;
    return 0;
}

/*
 * Thread stack attribute query (pthread_getattr_np):
 * On the NT 5.1 kernel + Linux shim, %fs selector is 0x38 (TEB) where
 * %fs:0x04 is StackBase (top) and %fs:0x08 is StackLimit (bottom) for
 * both the main thread and all NtCreateThread worker threads.
 */
int pthread_getattr_np(void *thread, void *attr) {
    if (!attr) return 22; /* EINVAL */
    unsigned long *a = (unsigned long *)attr;
    memset(a, 0, 9 * sizeof(unsigned long));
    unsigned short fs_sel = 0;
    __asm__ volatile("movw %%fs, %0" : "=r"(fs_sel));
    if (fs_sel == 0x38) {
        unsigned long stack_top = 0, stack_limit = 0;
        __asm__ volatile("movl %%fs:0x04, %0; movl %%fs:0x08, %1" : "=r"(stack_top), "=r"(stack_limit));
        if (stack_top > stack_limit && stack_limit >= 0x10000UL) {
            a[0] = stack_top - stack_limit; /* _a_stacksize */
            a[1] = 4096;                    /* _a_guardsize */
            a[2] = stack_top;               /* _a_stackaddr (top of stack in musl) */
            return 0;
        }
    }
    if (thread) {
        unsigned long *t = (unsigned long *)thread;
        /* In musl 1.2.x i386 struct __pthread: offset 0x34 (t[13]) = stack, 0x38 (t[14]) = stack_size, 0x3c (t[15]) = guard_size */
        if (t[13] && t[14]) {
            a[0] = t[14];
            a[1] = t[15];
            a[2] = t[13];
            return 0;
        }
    }
    unsigned long sp = 0;
    __asm__ volatile("movl %%esp, %0" : "=r"(sp));
    unsigned long top = (sp + 0xFFFFUL) & ~0xFFFFUL;
    a[0] = 2 * 1024 * 1024;
    a[1] = 4096;
    a[2] = top;
    return 0;
}

int pthread_attr_init(void *attr) {
    if (!attr) return 22;
    unsigned long *a = (unsigned long *)attr;
    memset(a, 0, 9 * sizeof(unsigned long));
    a[0] = 2 * 1024 * 1024; /* 2 MB default stack size (matching glibc instead of musl's 128 KB) */
    a[1] = 4096;
    return 0;
}

/* Multibyte character length helper */
size_t __mbrlen(const char *s, size_t n, mbstate_t *ps) {
    return mbrlen(s, n, ps);
}

/* Fortify (_chk) string & memory wrappers */
void *__memcpy_chk(void *dst, const void *src, size_t len, size_t dstlen) {
    (void)dstlen;
    return memcpy(dst, src, len);
}

void *__memmove_chk(void *dst, const void *src, size_t len, size_t dstlen) {
    (void)dstlen;
    return memmove(dst, src, len);
}

void *__memset_chk(void *dst, int c, size_t len, size_t dstlen) {
    (void)dstlen;
    return memset(dst, c, len);
}

void *__mempcpy_chk(void *dst, const void *src, size_t len, size_t dstlen) {
    (void)dstlen;
    return (char *)memcpy(dst, src, len) + len;
}

void *__explicit_bzero_chk(void *dst, size_t len, size_t dstlen) {
    (void)dstlen;
    memset(dst, 0, len);
    __asm__ volatile("" : : "r"(dst) : "memory");
    return dst;
}

char *__strcpy_chk(char *dst, const char *src, size_t dstlen) {
    (void)dstlen;
    return strcpy(dst, src);
}

char *__stpcpy_chk(char *dst, const char *src, size_t dstlen) {
    (void)dstlen;
    return stpcpy(dst, src);
}

char *__strncpy_chk(char *dst, const char *src, size_t len, size_t dstlen) {
    (void)dstlen;
    return strncpy(dst, src, len);
}

char *__strcat_chk(char *dst, const char *src, size_t dstlen) {
    (void)dstlen;
    return strcat(dst, src);
}

char *__strncat_chk(char *dst, const char *src, size_t len, size_t dstlen) {
    (void)dstlen;
    return strncat(dst, src, len);
}

int __sprintf_chk(char *s, int flag, size_t slen, const char *format, ...) {
    (void)flag;
    (void)slen;
    va_list ap;
    va_start(ap, format);
    int ret = vsprintf(s, format, ap);
    va_end(ap);
    return ret;
}

int __snprintf_chk(char *s, size_t maxlen, int flag, size_t slen, const char *format, ...) {
    (void)flag;
    (void)slen;
    va_list ap;
    va_start(ap, format);
    int ret = vsnprintf(s, maxlen, format, ap);
    va_end(ap);
    return ret;
}

int __vsprintf_chk(char *s, int flag, size_t slen, const char *format, va_list ap) {
    (void)flag;
    (void)slen;
    return vsprintf(s, format, ap);
}

int __vsnprintf_chk(char *s, size_t maxlen, int flag, size_t slen, const char *format, va_list ap) {
    (void)flag;
    (void)slen;
    return vsnprintf(s, maxlen, format, ap);
}

int __fprintf_chk(FILE *stream, int flag, const char *format, ...) {
    (void)flag;
    va_list ap;
    va_start(ap, format);
    int ret = vfprintf(stream, format, ap);
    va_end(ap);
    return ret;
}

int __vfprintf_chk(FILE *stream, int flag, const char *format, va_list ap) {
    (void)flag;
    return vfprintf(stream, format, ap);
}

int __printf_chk(int flag, const char *format, ...) {
    (void)flag;
    va_list ap;
    va_start(ap, format);
    int ret = vprintf(format, ap);
    va_end(ap);
    return ret;
}

int __vprintf_chk(int flag, const char *format, va_list ap) {
    (void)flag;
    return vprintf(format, ap);
}

int __vasprintf_chk(char **result_ptr, int flag, const char *format, va_list ap) {
    (void)flag;
    return vasprintf(result_ptr, format, ap);
}

int __asprintf_chk(char **result_ptr, int flag, const char *format, ...) {
    (void)flag;
    va_list ap;
    va_start(ap, format);
    int ret = vasprintf(result_ptr, format, ap);
    va_end(ap);
    return ret;
}

char *__fgets_chk(char *buf, size_t size, int n, FILE *fp) {
    (void)size;
    return fgets(buf, n, fp);
}

ssize_t __read_chk(int fd, void *buf, size_t nbytes, size_t buflen) {
    (void)buflen;
    return read(fd, buf, nbytes);
}

ssize_t __pread_chk(int fd, void *buf, size_t nbytes, off_t offset, size_t buflen) {
    (void)buflen;
    return pread(fd, buf, nbytes, offset);
}

ssize_t __pread64_chk(int fd, void *buf, size_t nbytes, off_t offset, size_t buflen) {
    (void)buflen;
    return pread(fd, buf, nbytes, offset);
}

ssize_t __readlink_chk(const char *path, char *buf, size_t len, size_t buflen) {
    (void)buflen;
    return readlink(path, buf, len);
}

char *__realpath_chk(const char *path, char *resolved, size_t resolvedlen) {
    (void)resolvedlen;
    return realpath(path, resolved);
}

char *__getcwd_chk(char *buf, size_t len, size_t buflen) {
    (void)buflen;
    return getcwd(buf, len);
}

long __fdelt_chk(long d) {
    return d / (8 * sizeof(long));
}

void __longjmp_chk(jmp_buf env, int val) {
    longjmp(env, val);
}

/* CPU affinity allocation helpers */
void *__sched_cpualloc(size_t count) {
    size_t bytes = ((count + 31) / 32) * sizeof(unsigned long);
    if (bytes < 128) bytes = 128;
    return calloc(1, bytes);
}

void __sched_cpufree(void *set) {
    free(set);
}

int __sched_cpucount(size_t setsize, const void *setp) {
    const unsigned char *p = (const unsigned char *)setp;
    int count = 0;
    for (size_t i = 0; i < setsize; i++) {
        unsigned char v = p[i];
        while (v) {
            count += v & 1;
            v >>= 1;
        }
    }
    return count;
}

/* Backtrace stubs */
int backtrace(void **buffer, int size) {
    (void)buffer;
    (void)size;
    return 0;
}

char **backtrace_symbols(void *const *buffer, int size) {
    (void)buffer;
    (void)size;
    return NULL;
}

void backtrace_symbols_fd(void *const *buffer, int size, int fd) {
    (void)buffer;
    (void)size;
    (void)fd;
}

/* Malloc info stubs */
struct glibc_mallinfo {
    int arena;
    int ordblks;
    int smblks;
    int hblks;
    int hblkhd;
    int usmblks;
    int fsmblks;
    int uordblks;
    int fordblks;
    int keepcost;
};

struct glibc_mallinfo mallinfo(void) {
    struct glibc_mallinfo mi;
    memset(&mi, 0, sizeof(mi));
    return mi;
}

struct glibc_mallinfo2 {
    size_t arena;
    size_t ordblks;
    size_t smblks;
    size_t hblks;
    size_t hblkhd;
    size_t usmblks;
    size_t fsmblks;
    size_t uordblks;
    size_t fordblks;
    size_t keepcost;
};

struct glibc_mallinfo2 mallinfo2(void) {
    struct glibc_mallinfo2 mi;
    memset(&mi, 0, sizeof(mi));
    return mi;
}

int malloc_trim(size_t pad) {
    (void)pad;
    return 0;
}

/* Misc glibc string/system helpers */
const char *gnu_get_libc_version(void) {
    return "2.31";
}

const char *gnu_get_libc_release(void) {
    return "stable";
}

char *canonicalize_file_name(const char *name) {
    return realpath(name, NULL);
}

void *__rawmemchr(const void *s, int c) {
    const unsigned char *p = (const unsigned char *)s;
    while (*p != (unsigned char)c) p++;
    return (void *)p;
}

void *rawmemchr(const void *s, int c) {
    return __rawmemchr(s, c);
}

char *__strdup(const char *s) {
    return strdup(s);
}

char *__strndup(const char *s, size_t n) {
    return strndup(s, n);
}

char *__strtok_r(char *s, const char *delim, char **save_ptr) {
    return strtok_r(s, delim, save_ptr);
}

/*
 * GNU vs POSIX strerror_r ABI compatibility:
 * Glibc-compiled C++ code (such as Chromium's base::safe_strerror) calls
 * strerror_r expecting the GNU signature:
 *   char *strerror_r(int errnum, char *buf, size_t buflen);
 * whereas musl's strerror_r implements the POSIX signature returning int (0 on
 * success), which glibc-compiled callers interpret as a NULL char* pointer!
 */
char *strerror_r(int errnum, char *buf, size_t buflen) {
    const char *msg = strerror(errnum);
    if (!msg) msg = "Unknown error";
    if (buf && buflen > 0) {
        size_t len = strlen(msg);
        if (len >= buflen) len = buflen - 1;
        memcpy(buf, msg, len);
        buf[len] = '\0';
        return buf;
    }
    return (char *)msg;
}

int __xpg_strerror_r(int errnum, char *buf, size_t buflen) {
    if (!buf || buflen == 0) return 34; /* ERANGE */
    const char *msg = strerror(errnum);
    if (!msg) msg = "Unknown error";
    size_t len = strlen(msg);
    if (len >= buflen) {
        memcpy(buf, msg, buflen - 1);
        buf[buflen - 1] = '\0';
        return 34; /* ERANGE */
    }
    memcpy(buf, msg, len + 1);
    return 0;
}

int __res_init(void) {
    return 0;
}

int __res_ninit(void *statp) {
    (void)statp;
    return 0;
}

void __res_nclose(void *statp) {
    (void)statp;
}

int __isnan(double x) { return __builtin_isnan(x); }
int __isnanf(float x) { return __builtin_isnan(x); }
int __isinf(double x) { return __builtin_isinf(x); }
int __isinff(float x) { return __builtin_isinf(x); }
int __finite(double x) { return __builtin_isfinite(x); }
int __finitef(float x) { return __builtin_isfinite(x); }

/* Reentrant PRNG helpers (random_r / initstate_r / srandom_r / setstate_r) */
struct gcompat_random_data {
    int32_t *fptr;
    int32_t *rptr;
    int32_t *state;
    int rand_type;
    int rand_deg;
    int rand_sep;
    int32_t *end_ptr;
};

int srandom_r(unsigned int seed, void *buf_ptr) {
    struct gcompat_random_data *buf = (struct gcompat_random_data *)buf_ptr;
    if (!buf) return -1;
    buf->rand_sep = (int)(seed ? seed : 1);
    return 0;
}

int initstate_r(unsigned int seed, char *__restrict statbuf, size_t statlen, void *__restrict buf_ptr) {
    struct gcompat_random_data *buf = (struct gcompat_random_data *)buf_ptr;
    (void)statbuf;
    (void)statlen;
    if (!buf) return -1;
    buf->rand_sep = (int)(seed ? seed : 1);
    return 0;
}

int setstate_r(char *__restrict statbuf, void *__restrict buf_ptr) {
    (void)statbuf;
    if (!buf_ptr) return -1;
    return 0;
}

int random_r(void *__restrict buf_ptr, int32_t *__restrict result) {
    struct gcompat_random_data *buf = (struct gcompat_random_data *)buf_ptr;
    if (!buf || !result) return -1;
    uint32_t x = (uint32_t)buf->rand_sep;
    if (x == 0) x = 0x6D2B79F5U;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    buf->rand_sep = (int)x;
    *result = (int32_t)(x & 0x7FFFFFFFU);
    return 0;
}

/*
 * Glibc struct __locale_struct and ctype table ABI compatibility:
 * On 32-bit x86 glibc, locale_t points to struct __locale_struct where:
 *   offset 0x00..0x33: void *__locales[13] (first 6 pointers overlap musl's cat[6]; NULL = C locale in musl)
 *   offset 0x34: const unsigned short int *__ctype_b
 *   offset 0x38: const int *__ctype_tolower
 *   offset 0x3c: const int *__ctype_toupper
 *   offset 0x40..0x73: const char *__names[13]
 * Chromium's libc++ (compiled against glibc headers) reads __loc->__ctype_b
 * directly in std::ctype<char>::classic_table().
 */
struct glibc_locale_struct {
    void *__locales[13];
    const unsigned short int *__ctype_b;
    const int32_t *__ctype_tolower;
    const int32_t *__ctype_toupper;
    const char *__names[13];
};

static unsigned short int g_ctype_b_storage[384];
static int32_t g_ctype_tolower_storage[384];
static int32_t g_ctype_toupper_storage[384];
static const unsigned short int *g_ctype_b_ptr = &g_ctype_b_storage[128];
static const int32_t *g_ctype_tolower_ptr = &g_ctype_tolower_storage[128];
static const int32_t *g_ctype_toupper_ptr = &g_ctype_toupper_storage[128];
static int g_ctype_initialized = 0;

static struct glibc_locale_struct g_glibc_c_locale = {
    .__locales = {0},
    .__ctype_b = &g_ctype_b_storage[128],
    .__ctype_tolower = &g_ctype_tolower_storage[128],
    .__ctype_toupper = &g_ctype_toupper_storage[128],
    .__names = {
        "C", "C", "C", "C", "C", "C", "C",
        "C", "C", "C", "C", "C", "C"
    }
};

/* Little-endian glibc _ISbit(0..11) masks in <ctype.h> */
#define GLIBC_ISupper  0x0100U
#define GLIBC_ISlower  0x0200U
#define GLIBC_ISalpha  0x0400U
#define GLIBC_ISdigit  0x0800U
#define GLIBC_ISxdigit 0x1000U
#define GLIBC_ISspace  0x2000U
#define GLIBC_ISprint  0x4000U
#define GLIBC_ISgraph  0x8000U
#define GLIBC_ISblank  0x0001U
#define GLIBC_IScntrl  0x0002U
#define GLIBC_ISpunct  0x0004U
#define GLIBC_ISalnum  0x0008U

__attribute__((constructor(101)))
static void ensure_glibc_c_locale(void) {
    if (g_ctype_initialized) return;
    for (int i = -128; i < 256; i++) {
        int idx = i + 128;
        int c = (i >= 0 && i <= 127) ? i : -1;
        unsigned short mask = 0;
        int32_t lo = i;
        int32_t up = i;
        if (c >= 0) {
            if (c >= 'A' && c <= 'Z') {
                mask |= GLIBC_ISupper | GLIBC_ISalpha | GLIBC_ISalnum | GLIBC_ISprint | GLIBC_ISgraph;
                lo = c + ('a' - 'A');
            }
            if (c >= 'a' && c <= 'z') {
                mask |= GLIBC_ISlower | GLIBC_ISalpha | GLIBC_ISalnum | GLIBC_ISprint | GLIBC_ISgraph;
                up = c - ('a' - 'A');
            }
            if (c >= '0' && c <= '9') {
                mask |= GLIBC_ISdigit | GLIBC_ISalnum | GLIBC_ISxdigit | GLIBC_ISprint | GLIBC_ISgraph;
            }
            if ((c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
                mask |= GLIBC_ISxdigit;
            }
            if (c == ' ' || c == '\t') {
                mask |= GLIBC_ISblank;
            }
            if (c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v') {
                mask |= GLIBC_ISspace;
            }
            if (c == ' ') {
                mask |= GLIBC_ISprint;
            }
            if (c >= 0x21 && c <= 0x7e) {
                mask |= GLIBC_ISprint | GLIBC_ISgraph;
                if (!(mask & GLIBC_ISalnum)) {
                    mask |= GLIBC_ISpunct;
                }
            }
            if (c < 0x20 || c == 0x7f) {
                mask |= GLIBC_IScntrl;
            }
        }
        g_ctype_b_storage[idx] = mask;
        g_ctype_tolower_storage[idx] = lo;
        g_ctype_toupper_storage[idx] = up;
    }
    g_ctype_b_ptr = &g_ctype_b_storage[128];
    g_ctype_tolower_ptr = &g_ctype_tolower_storage[128];
    g_ctype_toupper_ptr = &g_ctype_toupper_storage[128];
    g_glibc_c_locale.__ctype_b = g_ctype_b_ptr;
    g_glibc_c_locale.__ctype_tolower = g_ctype_tolower_ptr;
    g_glibc_c_locale.__ctype_toupper = g_ctype_toupper_ptr;
    g_ctype_initialized = 1;
}

const unsigned short int **__ctype_b_loc(void) {
    ensure_glibc_c_locale();
    return &g_ctype_b_ptr;
}

const int32_t **__ctype_tolower_loc(void) {
    ensure_glibc_c_locale();
    return &g_ctype_tolower_ptr;
}

const int32_t **__ctype_toupper_loc(void) {
    ensure_glibc_c_locale();
    return &g_ctype_toupper_ptr;
}

locale_t newlocale(int mask, const char *name, locale_t base) {
    (void)mask;
    (void)name;
    (void)base;
    ensure_glibc_c_locale();
    return (locale_t)&g_glibc_c_locale;
}

locale_t __newlocale(int mask, const char *name, locale_t base) {
    return newlocale(mask, name, base);
}

locale_t duplocale(locale_t loc) {
    (void)loc;
    ensure_glibc_c_locale();
    return (locale_t)&g_glibc_c_locale;
}

locale_t __duplocale(locale_t loc) {
    return duplocale(loc);
}

void freelocale(locale_t loc) {
    (void)loc;
}

void __freelocale(locale_t loc) {
    (void)loc;
}

locale_t uselocale(locale_t newloc) {
    (void)newloc;
    ensure_glibc_c_locale();
    return (locale_t)&g_glibc_c_locale;
}

locale_t __uselocale(locale_t newloc) {
    return uselocale(newloc);
}

char *nl_langinfo_l(nl_item item, locale_t loc) {
    (void)loc;
    return nl_langinfo(item);
}

char *__nl_langinfo_l(nl_item item, locale_t loc) {
    (void)loc;
    return nl_langinfo(item);
}

float strtof_l(const char *__restrict nptr, char **__restrict endptr, locale_t loc) {
    (void)loc;
    return strtof(nptr, endptr);
}

float __strtof_l(const char *__restrict nptr, char **__restrict endptr, locale_t loc) {
    (void)loc;
    return strtof(nptr, endptr);
}

double strtod_l(const char *__restrict nptr, char **__restrict endptr, locale_t loc) {
    (void)loc;
    return strtod(nptr, endptr);
}

double __strtod_l(const char *__restrict nptr, char **__restrict endptr, locale_t loc) {
    (void)loc;
    return strtod(nptr, endptr);
}

long double strtold_l(const char *__restrict nptr, char **__restrict endptr, locale_t loc) {
    (void)loc;
    return strtold(nptr, endptr);
}

long double __strtold_l(const char *__restrict nptr, char **__restrict endptr, locale_t loc) {
    (void)loc;
    return strtold(nptr, endptr);
}

extern long long musl_strtoll(const char *, char **, int) __asm__("strtoll");
extern unsigned long long musl_strtoull(const char *, char **, int) __asm__("strtoull");

long long strtoll_l(const char *__restrict nptr, char **__restrict endptr, int base, locale_t loc) {
    (void)loc;
    return musl_strtoll(nptr, endptr, base);
}

unsigned long long strtoull_l(const char *__restrict nptr, char **__restrict endptr, int base, locale_t loc) {
    (void)loc;
    return musl_strtoull(nptr, endptr, base);
}

int strcoll_l(const char *s1, const char *s2, locale_t loc) {
    (void)loc;
    return strcoll(s1, s2);
}

size_t strxfrm_l(char *__restrict dest, const char *__restrict src, size_t n, locale_t loc) {
    (void)loc;
    return strxfrm(dest, src, n);
}

int wcscoll_l(const wchar_t *ws1, const wchar_t *ws2, locale_t loc) {
    (void)loc;
    return wcscoll(ws1, ws2);
}

size_t wcsxfrm_l(wchar_t *__restrict dest, const wchar_t *__restrict src, size_t n, locale_t loc) {
    (void)loc;
    return wcsxfrm(dest, src, n);
}

size_t strftime_l(char *__restrict s, size_t maxsize, const char *__restrict format, const struct tm *__restrict timeptr, locale_t loc) {
    (void)loc;
    return strftime(s, maxsize, format, timeptr);
}

#undef tolower_l
#undef toupper_l
#undef tolower
#undef toupper
int tolower_l(int c, locale_t loc) {
    (void)loc;
    return tolower(c);
}

int toupper_l(int c, locale_t loc) {
    (void)loc;
    return toupper(c);
}

wint_t towlower_l(wint_t c, locale_t loc) {
    (void)loc;
    return towlower(c);
}

wint_t towupper_l(wint_t c, locale_t loc) {
    (void)loc;
    return towupper(c);
}

int iswctype_l(wint_t wc, wctype_t desc, locale_t loc) {
    (void)loc;
    return iswctype(wc, desc);
}

int __iswctype_l(wint_t wc, wctype_t desc, locale_t loc) {
    (void)loc;
    return iswctype(wc, desc);
}

int iswspace_l(wint_t wc, locale_t loc) { (void)loc; return iswspace(wc); }
int iswprint_l(wint_t wc, locale_t loc) { (void)loc; return iswprint(wc); }
int iswcntrl_l(wint_t wc, locale_t loc) { (void)loc; return iswcntrl(wc); }
int iswupper_l(wint_t wc, locale_t loc) { (void)loc; return iswupper(wc); }
int iswlower_l(wint_t wc, locale_t loc) { (void)loc; return iswlower(wc); }
int iswalpha_l(wint_t wc, locale_t loc) { (void)loc; return iswalpha(wc); }
int iswblank_l(wint_t wc, locale_t loc) { (void)loc; return iswblank(wc); }
int iswdigit_l(wint_t wc, locale_t loc) { (void)loc; return iswdigit(wc); }
int iswpunct_l(wint_t wc, locale_t loc) { (void)loc; return iswpunct(wc); }
int iswxdigit_l(wint_t wc, locale_t loc) { (void)loc; return iswxdigit(wc); }
int iswalnum_l(wint_t wc, locale_t loc) { (void)loc; return iswalnum(wc); }
int iswgraph_l(wint_t wc, locale_t loc) { (void)loc; return iswgraph(wc); }

/*
 * fcntl / fcntl64 wrapper:
 * - Handles 32-bit struct flock vs struct flock64 ABI mismatch on F_GETLK/F_SETLK/F_SETLKW
 * - Clamps F_DUPFD / F_DUPFD_CLOEXEC minimum fd >= 128 down to 64 so it fits within MAX_FD
 */
extern long __syscall_fcntl64(long n, long a1, long a2, long a3);
__asm__(
    ".text\n"
    ".global __syscall_fcntl64\n"
    ".type __syscall_fcntl64, @function\n"
    "__syscall_fcntl64:\n"
    "    pushl %ebx\n"
    "    movl 8(%esp), %eax\n"
    "    movl 12(%esp), %ebx\n"
    "    movl 16(%esp), %ecx\n"
    "    movl 20(%esp), %edx\n"
    "    call *%gs:0x10\n"
    "    popl %ebx\n"
    "    ret\n"
);

int fcntl(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    unsigned long arg = va_arg(ap, unsigned long);
    va_end(ap);

    /* F_SETLK (6), F_SETLKW (7), F_SETLK64 (13), F_SETLKW64 (14) */
    if (cmd == 6 || cmd == 7 || cmd == 13 || cmd == 14) {
        return 0;
    }
    /* F_GETLK (5), F_GETLK64 (12) */
    if (cmd == 5 || cmd == 12) {
        if (arg) *(short *)arg = 2; /* F_UNLCK */
        return 0;
    }
    /* F_DUPFD (0), F_DUPFD_CLOEXEC (1030) */
    if ((cmd == 0 || cmd == 1030) && arg >= 128) {
        arg = 64;
    }
    if (cmd == 4 /* F_SETFL */) {
        arg |= 0x8000UL; /* O_LARGEFILE */
    }
    long ret = __syscall_fcntl64(221 /* SYS_fcntl64 */, fd, cmd, (long)arg);
    if (ret < 0) {
        return -1;
    }
    if (cmd == 1030 /* F_DUPFD_CLOEXEC */) {
        __syscall_fcntl64(221, ret, 2 /* F_SETFD */, 1 /* FD_CLOEXEC */);
    }
    return (int)ret;
}

int fcntl64(int fd, int cmd, ...) __attribute__((alias("fcntl")));

/*
 * Clean process termination for --single-process Chromium:
 * In --single-process mode, background threads (Blink, ThreadPool, GpuChannel,
 * LevelDB) remain active when the browser main thread finishes and calls exit().
 * Flushing stdio streams and invoking exit_group(status) avoids use-after-free
 * races against global C++ static destructors (__cxa_finalize).
 */
void exit(int status) {
    fflush(NULL);
    __syscall_fcntl64(252 /* SYS_exit_group */, status, 0, 0);
    __syscall_fcntl64(1 /* SYS_exit */, status, 0, 0);
    __builtin_unreachable();
}



