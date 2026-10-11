/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _STDIO_H_
#define _STDIO_H_

#include <stddef.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EOF (-1)
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#define BUFSIZ   4096

typedef struct _NTC_FILE {
    int   fd;
    int   flags;
    int   eof;
    int   error;
    int   ungot_char;
} FILE;

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

int    __cdecl vsnprintf(char *str, size_t size, const char *format, va_list ap);
int    __cdecl vsprintf(char *str, const char *format, va_list ap);
int    __cdecl snprintf(char *str, size_t size, const char *format, ...);
int    __cdecl sprintf(char *str, const char *format, ...);
int    __cdecl vprintf(const char *format, va_list ap);
int    __cdecl vfprintf(FILE *stream, const char *format, va_list ap);
int    __cdecl printf(const char *format, ...);
int    __cdecl fprintf(FILE *stream, const char *format, ...);
int    __cdecl dprintf(int fd, const char *format, ...);

int    __cdecl sscanf(const char *str, const char *format, ...);

int    __cdecl fgetc(FILE *stream);
int    __cdecl getc(FILE *stream);
int    __cdecl getchar(void);
int    __cdecl ungetc(int c, FILE *stream);
char * __cdecl fgets(char *s, int size, FILE *stream);

int    __cdecl fputc(int c, FILE *stream);
int    __cdecl putc(int c, FILE *stream);
int    __cdecl putchar(int c);
int    __cdecl fputs(const char *s, FILE *stream);
int    __cdecl puts(const char *s);

FILE * __cdecl fopen(const char *path, const char *mode);
FILE * __cdecl fdopen(int fd, const char *mode);
int    __cdecl fclose(FILE *stream);
size_t __cdecl fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t __cdecl fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int    __cdecl fflush(FILE *stream);
int    __cdecl fseek(FILE *stream, long offset, int whence);
long   __cdecl ftell(FILE *stream);
void   __cdecl rewind(FILE *stream);
int    __cdecl feof(FILE *stream);
int    __cdecl ferror(FILE *stream);
void   __cdecl clearerr(FILE *stream);
int    __cdecl fileno(FILE *stream);

int    __cdecl remove(const char *pathname);
int    __cdecl rename(const char *oldpath, const char *newpath);
void   __cdecl perror(const char *s);

/* Dual-head console raw helpers (bootvid/VGA + PS/2 keyboard + COM1 serial) */
void   __cdecl nt_console_init(void);
void   __cdecl nt_console_write(const char *buf, size_t len);
void   __cdecl nt_console_puts(const char *s);
int    __cdecl nt_console_getc(int nonblocking);
int    __cdecl nt_console_readline(const char *prompt, char *buf, size_t maxlen);
void   __cdecl nt_console_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* _STDIO_H_ */
