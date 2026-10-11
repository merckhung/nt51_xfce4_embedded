/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * native/libntc/time_env.c
 * Time, Clock, Sleep, and Environment Variable Management over NT Syscalls
 */

#include "../include/ntnative.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#define NT_EPOCH_DIFF_100NS 116444736000000000i64

unsigned __int64 __cdecl nt_uptime_ms(void) {
    ULONGLONG intr_time;
    ULONG high1, high2, low;
    do {
        high1 = (ULONG)SharedUserData->InterruptTime.High1Time;
        low   = SharedUserData->InterruptTime.LowPart;
        high2 = (ULONG)SharedUserData->InterruptTime.High2Time;
    } while (high1 != high2);
    intr_time = ((ULONGLONG)high1 << 32) | low;
    return intr_time / 10000ui64;
}

clock_t __cdecl clock(void) {
    return (clock_t)nt_uptime_ms();
}

time_t __cdecl time(time_t *tloc) {
    LARGE_INTEGER sys_time;
    time_t secs = 0;

    if (NT_SUCCESS(NtQuerySystemTime(&sys_time)) && sys_time.QuadPart > NT_EPOCH_DIFF_100NS) {
        secs = (time_t)((sys_time.QuadPart - NT_EPOCH_DIFF_100NS) / 10000000i64);
    }
    if (tloc) *tloc = secs;
    return secs;
}

int __cdecl gettimeofday(struct timeval *tv, void *tz) {
    LARGE_INTEGER sys_time;
    if (!tv) {
        errno = EINVAL;
        return -1;
    }
    if (NT_SUCCESS(NtQuerySystemTime(&sys_time)) && sys_time.QuadPart > NT_EPOCH_DIFF_100NS) {
        LONGLONG us = (sys_time.QuadPart - NT_EPOCH_DIFF_100NS) / 10i64;
        tv->tv_sec  = (time_t)(us / 1000000i64);
        tv->tv_usec = (suseconds_t)(us % 1000000i64);
    } else {
        tv->tv_sec = 0;
        tv->tv_usec = 0;
    }
    return 0;
}

static int IsLeapYear(int year) {
    return ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
}

static const int g_MonthDays[2][12] = {
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
    { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

struct tm * __cdecl gmtime_r(const time_t *timep, struct tm *result) {
    long t, days, rem;
    int year = 1970;
    int leap, mon;

    if (!timep || !result) return NULL;
    t = (long)*timep;
    if (t < 0) t = 0;

    days = t / 86400L;
    rem  = t % 86400L;

    result->tm_hour = (int)(rem / 3600L);
    rem %= 3600L;
    result->tm_min  = (int)(rem / 60L);
    result->tm_sec  = (int)(rem % 60L);
    result->tm_wday = (int)((4 + days) % 7);

    for (;;) {
        int ydays = IsLeapYear(year) ? 366 : 365;
        if (days < ydays) break;
        days -= ydays;
        year++;
    }
    result->tm_year = year - 1900;
    result->tm_yday = (int)days;

    leap = IsLeapYear(year);
    for (mon = 0; mon < 11; mon++) {
        if (days < g_MonthDays[leap][mon]) break;
        days -= g_MonthDays[leap][mon];
    }
    result->tm_mon   = mon;
    result->tm_mday  = (int)days + 1;
    result->tm_isdst = 0;
    return result;
}

static struct tm g_StaticTm;

struct tm * __cdecl gmtime(const time_t *timep) {
    return gmtime_r(timep, &g_StaticTm);
}

struct tm * __cdecl localtime_r(const time_t *timep, struct tm *result) {
    return gmtime_r(timep, result);
}

struct tm * __cdecl localtime(const time_t *timep) {
    return gmtime_r(timep, &g_StaticTm);
}

time_t __cdecl mktime(struct tm *tm) {
    int year, y, m;
    long days = 0;
    if (!tm) return (time_t)-1;
    year = tm->tm_year + 1900;
    for (y = 1970; y < year; y++) {
        days += IsLeapYear(y) ? 366 : 365;
    }
    for (m = 0; m < tm->tm_mon && m < 12; m++) {
        days += g_MonthDays[IsLeapYear(year)][m];
    }
    days += (tm->tm_mday - 1);
    return (time_t)(days * 86400L + tm->tm_hour * 3600L + tm->tm_min * 60L + tm->tm_sec);
}

size_t __cdecl strftime(char *s, size_t max, const char *format, const struct tm *tm) {
    static const char *wday_names[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    static const char *mon_names[]  = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    size_t pos = 0;
    const char *p = format;

    if (!s || max == 0 || !format || !tm) return 0;

    while (*p && pos + 1 < max) {
        char tmp[32];
        if (*p != '%') {
            s[pos++] = *p++;
            continue;
        }
        p++;
        tmp[0] = '\0';
        switch (*p) {
            case 'Y': snprintf(tmp, sizeof(tmp), "%04d", tm->tm_year + 1900); break;
            case 'y': snprintf(tmp, sizeof(tmp), "%02d", (tm->tm_year + 1900) % 100); break;
            case 'm': snprintf(tmp, sizeof(tmp), "%02d", tm->tm_mon + 1); break;
            case 'd': snprintf(tmp, sizeof(tmp), "%02d", tm->tm_mday); break;
            case 'H': snprintf(tmp, sizeof(tmp), "%02d", tm->tm_hour); break;
            case 'M': snprintf(tmp, sizeof(tmp), "%02d", tm->tm_min); break;
            case 'S': snprintf(tmp, sizeof(tmp), "%02d", tm->tm_sec); break;
            case 'a': snprintf(tmp, sizeof(tmp), "%s", wday_names[tm->tm_wday % 7]); break;
            case 'b': snprintf(tmp, sizeof(tmp), "%s", mon_names[tm->tm_mon % 12]); break;
            case 'F': snprintf(tmp, sizeof(tmp), "%04d-%02d-%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday); break;
            case 'T': snprintf(tmp, sizeof(tmp), "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec); break;
            case '%': strcpy(tmp, "%"); break;
            default:  snprintf(tmp, sizeof(tmp), "%%%c", *p); break;
        }
        {
            size_t tlen = strlen(tmp);
            if (pos + tlen < max) {
                memcpy(s + pos, tmp, tlen);
                pos += tlen;
            } else {
                break;
            }
        }
        if (*p) p++;
    }
    s[pos] = '\0';
    return pos;
}

unsigned int __cdecl sleep(unsigned int seconds) {
    LARGE_INTEGER delay;
    delay.QuadPart = -((LONGLONG)seconds * 10000000i64);
    NtDelayExecution(FALSE, &delay);
    return 0;
}

int __cdecl usleep(useconds_t usec) {
    LARGE_INTEGER delay;
    delay.QuadPart = -((LONGLONG)usec * 10i64);
    NtDelayExecution(FALSE, &delay);
    return 0;
}

/*----------------------------------------------------------------------------
 * Environment Variables Table (environ, getenv, setenv, unsetenv)
 *----------------------------------------------------------------------------*/
#define MAX_ENV_VARS 128

static char *g_EnvArray[MAX_ENV_VARS];
static int   g_EnvCount = 0;
static int   g_EnvInitialized = 0;

void __cdecl _libntc_init_env(PPEB peb) {
    if (g_EnvInitialized) return;
    g_EnvInitialized = 1;
    memset(g_EnvArray, 0, sizeof(g_EnvArray));
    g_EnvCount = 0;

    /* Default embedded NT environment */
    setenv("PATH", "C:\\bin;C:\\WINDOWS\\system32;C:\\WINDOWS", 1);
    setenv("SystemRoot", "C:\\WINDOWS", 1);
    setenv("SystemDrive", "C:", 1);
    setenv("HOME", "C:\\root", 1);
    setenv("USER", "SYSTEM", 1);
    setenv("HOSTNAME", "nt-embedded", 1);
    setenv("SHELL", "/bin/sh", 1);
    setenv("TERM", "vt100", 1);
    setenv("PS1", "\\u@\\h:\\w# ", 1);

    /* Import UTF-16LE environment block from PEB if present */
    if (peb && peb->ProcessParameters && peb->ProcessParameters->Environment) {
        const WCHAR *wenv = (const WCHAR *)peb->ProcessParameters->Environment;
        while (*wenv) {
            char line[512];
            int i = 0;
            while (*wenv && i < 510) {
                line[i++] = (*wenv < 0x100) ? (char)*wenv : '?';
                wenv++;
            }
            line[i] = '\0';
            while (*wenv) wenv++;
            wenv++; /* advance past NUL */

            if (line[0] && line[0] != '=') {
                char *eq = strchr(line, '=');
                if (eq) {
                    *eq = '\0';
                    setenv(line, eq + 1, 1);
                }
            }
        }
    }
}

char ** __cdecl _get_environ(void) {
    if (!g_EnvInitialized) _libntc_init_env(NtCurrentPeb());
    return g_EnvArray;
}

char * __cdecl getenv(const char *name) {
    size_t nlen;
    int i;
    if (!name || !name[0]) return NULL;
    if (!g_EnvInitialized) _libntc_init_env(NtCurrentPeb());
    nlen = strlen(name);
    for (i = 0; i < g_EnvCount; i++) {
        if (strncasecmp(g_EnvArray[i], name, nlen) == 0 && g_EnvArray[i][nlen] == '=') {
            return g_EnvArray[i] + nlen + 1;
        }
    }
    return NULL;
}

int __cdecl setenv(const char *name, const char *value, int overwrite) {
    size_t nlen, vlen;
    char *entry;
    int i;

    if (!name || !name[0] || strchr(name, '=')) {
        errno = EINVAL;
        return -1;
    }
    if (!g_EnvInitialized) _libntc_init_env(NtCurrentPeb());
    if (!value) value = "";

    nlen = strlen(name);
    vlen = strlen(value);

    for (i = 0; i < g_EnvCount; i++) {
        if (strncasecmp(g_EnvArray[i], name, nlen) == 0 && g_EnvArray[i][nlen] == '=') {
            if (!overwrite) return 0;
            entry = (char *)malloc(nlen + 1 + vlen + 1);
            if (!entry) return -1;
            memcpy(entry, name, nlen);
            entry[nlen] = '=';
            memcpy(entry + nlen + 1, value, vlen + 1);
            free(g_EnvArray[i]);
            g_EnvArray[i] = entry;
            return 0;
        }
    }

    if (g_EnvCount + 1 >= MAX_ENV_VARS) {
        errno = ENOMEM;
        return -1;
    }
    entry = (char *)malloc(nlen + 1 + vlen + 1);
    if (!entry) return -1;
    memcpy(entry, name, nlen);
    entry[nlen] = '=';
    memcpy(entry + nlen + 1, value, vlen + 1);
    g_EnvArray[g_EnvCount++] = entry;
    g_EnvArray[g_EnvCount] = NULL;
    return 0;
}

int __cdecl unsetenv(const char *name) {
    size_t nlen;
    int i, j;
    if (!name || !name[0]) return -1;
    if (!g_EnvInitialized) _libntc_init_env(NtCurrentPeb());
    nlen = strlen(name);
    for (i = 0; i < g_EnvCount; i++) {
        if (strncasecmp(g_EnvArray[i], name, nlen) == 0 && g_EnvArray[i][nlen] == '=') {
            free(g_EnvArray[i]);
            for (j = i; j < g_EnvCount - 1; j++) {
                g_EnvArray[j] = g_EnvArray[j + 1];
            }
            g_EnvCount--;
            g_EnvArray[g_EnvCount] = NULL;
            return 0;
        }
    }
    return 0;
}
