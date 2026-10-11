/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * native/libntc/stdio.c
 * Standard C99 Formatted Output/Input (printf/snprintf/sscanf) and FILE Streams
 */

#include "../include/ntnative.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static FILE g_StdinFile  = { 0, O_RDONLY, 0, 0, -1 };
static FILE g_StdoutFile = { 1, O_WRONLY, 0, 0, -1 };
static FILE g_StderrFile = { 2, O_WRONLY, 0, 0, -1 };

FILE *stdin  = &g_StdinFile;
FILE *stdout = &g_StdoutFile;
FILE *stderr = &g_StderrFile;

static void EmitChar(char *buf, size_t size, size_t *pos, char c) {
    if (buf && *pos + 1 < size) {
        buf[*pos] = c;
    }
    (*pos)++;
}

static void EmitString(char *buf, size_t size, size_t *pos, const char *s, int width, int precision, int left_align, char pad_char) {
    int len = 0;
    int pad = 0;
    int i;

    if (!s) s = "(null)";
    while (s[len] && (precision < 0 || len < precision)) {
        len++;
    }
    if (width > len) {
        pad = width - len;
    }
    if (!left_align) {
        for (i = 0; i < pad; i++) EmitChar(buf, size, pos, pad_char);
    }
    for (i = 0; i < len; i++) {
        EmitChar(buf, size, pos, s[i]);
    }
    if (left_align) {
        for (i = 0; i < pad; i++) EmitChar(buf, size, pos, ' ');
    }
}

static void EmitNumber(
    char *buf,
    size_t size,
    size_t *pos,
    unsigned __int64 val,
    int is_signed,
    int is_neg,
    int base,
    int uppercase,
    int width,
    int precision,
    int left_align,
    char pad_char,
    int alt_form
) {
    char digits[68];
    int dlen = 0;
    const char *alphabet = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    char prefix[4];
    int plen = 0;
    int zero_pad = 0;
    int space_pad = 0;
    int total_len;
    int i;

    if (val == 0) {
        if (precision != 0) {
            digits[dlen++] = '0';
        }
    } else {
        while (val > 0) {
            digits[dlen++] = alphabet[(unsigned int)(val % (unsigned __int64)base)];
            val /= (unsigned __int64)base;
        }
    }

    if (is_signed && is_neg) {
        prefix[plen++] = '-';
    } else if (alt_form && base == 16 && dlen > 0) {
        prefix[plen++] = '0';
        prefix[plen++] = uppercase ? 'X' : 'x';
    } else if (alt_form && base == 8 && dlen > 0) {
        prefix[plen++] = '0';
    }

    if (precision > dlen) {
        zero_pad = precision - dlen;
    } else if (precision < 0 && !left_align && pad_char == '0' && width > plen + dlen) {
        zero_pad = width - (plen + dlen);
    }

    total_len = plen + zero_pad + dlen;
    if (width > total_len) {
        space_pad = width - total_len;
    }

    if (!left_align) {
        for (i = 0; i < space_pad; i++) EmitChar(buf, size, pos, ' ');
    }
    for (i = 0; i < plen; i++) {
        EmitChar(buf, size, pos, prefix[i]);
    }
    for (i = 0; i < zero_pad; i++) {
        EmitChar(buf, size, pos, '0');
    }
    for (i = dlen - 1; i >= 0; i--) {
        EmitChar(buf, size, pos, digits[i]);
    }
    if (left_align) {
        for (i = 0; i < space_pad; i++) EmitChar(buf, size, pos, ' ');
    }
}

int __cdecl vsnprintf(char *str, size_t size, const char *format, va_list ap) {
    size_t pos = 0;
    const char *p = format;

    if (!format) {
        if (str && size > 0) str[0] = '\0';
        return 0;
    }

    while (*p) {
        int left_align = 0;
        int alt_form = 0;
        char pad_char = ' ';
        int width = 0;
        int precision = -1;
        int length_mod = 0; /* 0=int, 1=long, 2=long long, 3=size_t */

        if (*p != '%') {
            EmitChar(str, size, &pos, *p++);
            continue;
        }
        p++; /* skip '%' */
        if (*p == '%') {
            EmitChar(str, size, &pos, *p++);
            continue;
        }

        /* Flags */
        for (;;) {
            if (*p == '-') { left_align = 1; p++; }
            else if (*p == '0') { pad_char = '0'; p++; }
            else if (*p == '#') { alt_form = 1; p++; }
            else if (*p == '+' || *p == ' ') { p++; }
            else break;
        }
        if (left_align) pad_char = ' ';

        /* Width */
        if (*p == '*') {
            width = va_arg(ap, int);
            if (width < 0) {
                left_align = 1;
                pad_char = ' ';
                width = -width;
            }
            p++;
        } else {
            while (isdigit((unsigned char)*p)) {
                width = width * 10 + (*p - '0');
                p++;
            }
        }

        /* Precision */
        if (*p == '.') {
            p++;
            precision = 0;
            if (*p == '*') {
                precision = va_arg(ap, int);
                p++;
            } else {
                while (isdigit((unsigned char)*p)) {
                    precision = precision * 10 + (*p - '0');
                    p++;
                }
            }
        }

        /* Length modifier */
        if (p[0] == 'I' && p[1] == '6' && p[2] == '4') {
            length_mod = 2;
            p += 3;
        } else if (p[0] == 'l' && p[1] == 'l') {
            length_mod = 2;
            p += 2;
        } else if (*p == 'l') {
            length_mod = 1;
            p++;
        } else if (*p == 'z' || *p == 't') {
            length_mod = 3;
            p++;
        } else if (*p == 'h') {
            p++;
            if (*p == 'h') p++;
        }

        switch (*p) {
            case 'c': {
                char ch = (char)va_arg(ap, int);
                char tmp[2] = { ch, '\0' };
                EmitString(str, size, &pos, tmp, width, 1, left_align, ' ');
                break;
            }
            case 's': {
                const char *s = va_arg(ap, const char *);
                EmitString(str, size, &pos, s, width, precision, left_align, pad_char);
                break;
            }
            case 'S': {
                /* Wide string support (%S or %ls) */
                const wchar_t *ws = va_arg(ap, const wchar_t *);
                char abuf[260];
                int k = 0;
                if (!ws) {
                    EmitString(str, size, &pos, "(null)", width, precision, left_align, pad_char);
                } else {
                    while (ws[k] && k < 258 && (precision < 0 || k < precision)) {
                        abuf[k] = (ws[k] < 0x100) ? (char)ws[k] : '?';
                        k++;
                    }
                    abuf[k] = '\0';
                    EmitString(str, size, &pos, abuf, width, precision, left_align, pad_char);
                }
                break;
            }
            case 'd':
            case 'i': {
                __int64 sval;
                unsigned __int64 uval;
                int is_neg = 0;
                if (length_mod == 2) sval = va_arg(ap, __int64);
                else if (length_mod == 1) sval = va_arg(ap, long);
                else sval = va_arg(ap, int);
                if (sval < 0) {
                    is_neg = 1;
                    uval = (unsigned __int64)(-sval);
                } else {
                    uval = (unsigned __int64)sval;
                }
                EmitNumber(str, size, &pos, uval, 1, is_neg, 10, 0, width, precision, left_align, pad_char, 0);
                break;
            }
            case 'u':
            case 'o':
            case 'x':
            case 'X': {
                unsigned __int64 uval;
                int base = (*p == 'o') ? 8 : ((*p == 'u') ? 10 : 16);
                int upper = (*p == 'X');
                if (length_mod == 2) uval = va_arg(ap, unsigned __int64);
                else if (length_mod == 1) uval = va_arg(ap, unsigned long);
                else uval = va_arg(ap, unsigned int);
                EmitNumber(str, size, &pos, uval, 0, 0, base, upper, width, precision, left_align, pad_char, alt_form);
                break;
            }
            case 'p': {
                unsigned __int64 uval = (unsigned int)(ULONG_PTR)va_arg(ap, void *);
                EmitString(str, size, &pos, "0x", 0, -1, 0, ' ');
                EmitNumber(str, size, &pos, uval, 0, 0, 16, 1, 8, 8, 0, '0', 0);
                break;
            }
            default:
                EmitChar(str, size, &pos, *p);
                break;
        }
        if (*p) p++;
    }

    if (str && size > 0) {
        if (pos < size) str[pos] = '\0';
        else str[size - 1] = '\0';
    }
    return (int)pos;
}

int __cdecl vsprintf(char *str, const char *format, va_list ap) {
    return vsnprintf(str, 0x7FFFFFFF, format, ap);
}

int __cdecl snprintf(char *str, size_t size, const char *format, ...) {
    va_list ap;
    int rc;
    va_start(ap, format);
    rc = vsnprintf(str, size, format, ap);
    va_end(ap);
    return rc;
}

int __cdecl sprintf(char *str, const char *format, ...) {
    va_list ap;
    int rc;
    va_start(ap, format);
    rc = vsnprintf(str, 0x7FFFFFFF, format, ap);
    va_end(ap);
    return rc;
}

int __cdecl vfprintf(FILE *stream, const char *format, va_list ap) {
    char stack_buf[1024];
    int len;
    if (!stream) stream = stdout;
    len = vsnprintf(stack_buf, sizeof(stack_buf), format, ap);
    if (len <= 0) return 0;
    if ((size_t)len < sizeof(stack_buf)) {
        write(stream->fd, stack_buf, (size_t)len);
    } else {
        char *heap_buf = (char *)malloc((size_t)len + 1);
        if (heap_buf) {
            vsnprintf(heap_buf, (size_t)len + 1, format, ap);
            write(stream->fd, heap_buf, (size_t)len);
            free(heap_buf);
        } else {
            write(stream->fd, stack_buf, sizeof(stack_buf) - 1);
        }
    }
    return len;
}

int __cdecl vprintf(const char *format, va_list ap) {
    return vfprintf(stdout, format, ap);
}

int __cdecl printf(const char *format, ...) {
    va_list ap;
    int rc;
    va_start(ap, format);
    rc = vfprintf(stdout, format, ap);
    va_end(ap);
    return rc;
}

int __cdecl fprintf(FILE *stream, const char *format, ...) {
    va_list ap;
    int rc;
    va_start(ap, format);
    rc = vfprintf(stream, format, ap);
    va_end(ap);
    return rc;
}

int __cdecl dprintf(int fd, const char *format, ...) {
    char buf[1024];
    va_list ap;
    int len;
    va_start(ap, format);
    len = vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    if (len > 0) {
        size_t wlen = ((size_t)len < sizeof(buf)) ? (size_t)len : (sizeof(buf) - 1);
        write(fd, buf, wlen);
    }
    return len;
}

int __cdecl sscanf(const char *str, const char *format, ...) {
    va_list ap;
    int matched = 0;
    const char *s = str;
    const char *f = format;

    if (!str || !format) return 0;
    va_start(ap, format);

    while (*f && *s) {
        if (isspace((unsigned char)*f)) {
            while (isspace((unsigned char)*f)) f++;
            while (isspace((unsigned char)*s)) s++;
            continue;
        }
        if (*f != '%') {
            if (*f != *s) break;
            f++;
            s++;
            continue;
        }
        f++; /* skip '%' */
        while (isspace((unsigned char)*s)) s++;
        if (!*s) break;

        if (*f == 'd' || *f == 'i') {
            char *endp = NULL;
            long val = strtol(s, &endp, (*f == 'd') ? 10 : 0);
            if (endp == s) break;
            *va_arg(ap, int *) = (int)val;
            s = endp;
            f++;
            matched++;
        } else if (*f == 'u' || *f == 'x' || *f == 'X') {
            char *endp = NULL;
            unsigned long val = strtoul(s, &endp, (*f == 'u') ? 10 : 16);
            if (endp == s) break;
            *va_arg(ap, unsigned int *) = (unsigned int)val;
            s = endp;
            f++;
            matched++;
        } else if (*f == 's') {
            char *out = va_arg(ap, char *);
            while (*s && !isspace((unsigned char)*s)) {
                *out++ = *s++;
            }
            *out = '\0';
            f++;
            matched++;
        } else if (*f == 'c') {
            *va_arg(ap, char *) = *s++;
            f++;
            matched++;
        } else {
            break;
        }
    }

    va_end(ap);
    return matched;
}

/*----------------------------------------------------------------------------
 * FILE Stream Operations
 *----------------------------------------------------------------------------*/
FILE * __cdecl fopen(const char *path, const char *mode) {
    int flags = O_RDONLY;
    int fd;
    FILE *fp;

    if (!path || !mode) {
        errno = EINVAL;
        return NULL;
    }
    if (strchr(mode, 'r')) {
        flags = strchr(mode, '+') ? O_RDWR : O_RDONLY;
    } else if (strchr(mode, 'w')) {
        flags = (strchr(mode, '+') ? O_RDWR : O_WRONLY) | O_CREAT | O_TRUNC;
    } else if (strchr(mode, 'a')) {
        flags = (strchr(mode, '+') ? O_RDWR : O_WRONLY) | O_CREAT | O_APPEND;
    }

    fd = open(path, flags, 0666);
    if (fd < 0) return NULL;

    fp = (FILE *)malloc(sizeof(FILE));
    if (!fp) {
        close(fd);
        return NULL;
    }
    fp->fd = fd;
    fp->flags = flags;
    fp->eof = 0;
    fp->error = 0;
    fp->ungot_char = -1;
    return fp;
}

FILE * __cdecl fdopen(int fd, const char *mode) {
    FILE *fp;
    if (fd < 0) return NULL;
    fp = (FILE *)malloc(sizeof(FILE));
    if (!fp) return NULL;
    fp->fd = fd;
    fp->flags = 0;
    fp->eof = 0;
    fp->error = 0;
    fp->ungot_char = -1;
    return fp;
}

int __cdecl fclose(FILE *stream) {
    int rc;
    if (!stream) return EOF;
    if (stream == stdin || stream == stdout || stream == stderr) {
        return 0;
    }
    rc = close(stream->fd);
    free(stream);
    return (rc == 0) ? 0 : EOF;
}

size_t __cdecl fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t total = size * nmemb;
    unsigned char *dst = (unsigned char *)ptr;
    size_t done = 0;

    if (!stream || !ptr || total == 0) return 0;

    if (stream->ungot_char >= 0) {
        *dst++ = (unsigned char)stream->ungot_char;
        stream->ungot_char = -1;
        done++;
    }

    while (done < total) {
        ssize_t n = read(stream->fd, dst + done, total - done);
        if (n < 0) {
            stream->error = 1;
            break;
        }
        if (n == 0) {
            stream->eof = 1;
            break;
        }
        done += (size_t)n;
        if (isatty(stream->fd)) break;
    }

    return done / size;
}

size_t __cdecl fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t total = size * nmemb;
    ssize_t n;
    if (!stream || !ptr || total == 0) return 0;
    n = write(stream->fd, ptr, total);
    if (n < 0) {
        stream->error = 1;
        return 0;
    }
    return (size_t)n / size;
}

int __cdecl fgetc(FILE *stream) {
    unsigned char ch;
    ssize_t n;
    if (!stream) return EOF;
    if (stream->ungot_char >= 0) {
        int c = stream->ungot_char;
        stream->ungot_char = -1;
        return c;
    }
    n = read(stream->fd, &ch, 1);
    if (n <= 0) {
        if (n == 0) stream->eof = 1;
        else stream->error = 1;
        return EOF;
    }
    return (int)ch;
}

int __cdecl getc(FILE *stream) {
    return fgetc(stream);
}

int __cdecl getchar(void) {
    return fgetc(stdin);
}

int __cdecl ungetc(int c, FILE *stream) {
    if (!stream || c == EOF) return EOF;
    stream->ungot_char = c & 0xFF;
    stream->eof = 0;
    return stream->ungot_char;
}

char * __cdecl fgets(char *s, int size, FILE *stream) {
    int i = 0;
    if (!s || size <= 0 || !stream) return NULL;
    while (i + 1 < size) {
        int c = fgetc(stream);
        if (c == EOF) {
            if (i == 0) return NULL;
            break;
        }
        s[i++] = (char)c;
        if (c == '\n') break;
    }
    s[i] = '\0';
    return s;
}

int __cdecl fputc(int c, FILE *stream) {
    unsigned char ch = (unsigned char)c;
    if (!stream) return EOF;
    if (write(stream->fd, &ch, 1) != 1) {
        stream->error = 1;
        return EOF;
    }
    return (int)ch;
}

int __cdecl putc(int c, FILE *stream) {
    return fputc(c, stream);
}

int __cdecl putchar(int c) {
    return fputc(c, stdout);
}

int __cdecl fputs(const char *s, FILE *stream) {
    size_t len;
    if (!s || !stream) return EOF;
    len = strlen(s);
    if (len > 0 && write(stream->fd, s, len) < 0) {
        stream->error = 1;
        return EOF;
    }
    return 0;
}

int __cdecl puts(const char *s) {
    if (fputs(s, stdout) == EOF) return EOF;
    if (fputc('\n', stdout) == EOF) return EOF;
    return 0;
}

int __cdecl fflush(FILE *stream) {
    return 0;
}

int __cdecl fseek(FILE *stream, long offset, int whence) {
    if (!stream) return -1;
    stream->ungot_char = -1;
    stream->eof = 0;
    return (lseek(stream->fd, offset, whence) < 0) ? -1 : 0;
}

long __cdecl ftell(FILE *stream) {
    if (!stream) return -1L;
    return (long)lseek(stream->fd, 0, SEEK_CUR);
}

void __cdecl rewind(FILE *stream) {
    if (stream) fseek(stream, 0L, SEEK_SET);
}

int __cdecl feof(FILE *stream) {
    return stream ? stream->eof : 0;
}

int __cdecl ferror(FILE *stream) {
    return stream ? stream->error : 0;
}

void __cdecl clearerr(FILE *stream) {
    if (stream) {
        stream->eof = 0;
        stream->error = 0;
    }
}

int __cdecl fileno(FILE *stream) {
    return stream ? stream->fd : -1;
}

void __cdecl perror(const char *s) {
    if (s && s[0]) {
        fprintf(stderr, "%s: %s\n", s, strerror(errno));
    } else {
        fprintf(stderr, "%s\n", strerror(errno));
    }
}
