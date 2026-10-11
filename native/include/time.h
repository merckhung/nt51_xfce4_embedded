/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _TIME_H_
#define _TIME_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CLOCKS_PER_SEC 1000

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

struct timespec {
    time_t tv_sec;
    long   tv_nsec;
};

struct timeval {
    time_t      tv_sec;
    suseconds_t tv_usec;
};

time_t     __cdecl time(time_t *tloc);
clock_t    __cdecl clock(void);
struct tm *__cdecl gmtime(const time_t *timep);
struct tm *__cdecl gmtime_r(const time_t *timep, struct tm *result);
struct tm *__cdecl localtime(const time_t *timep);
struct tm *__cdecl localtime_r(const time_t *timep, struct tm *result);
time_t     __cdecl mktime(struct tm *tm);
size_t     __cdecl strftime(char *s, size_t max, const char *format, const struct tm *tm);
int        __cdecl gettimeofday(struct timeval *tv, void *tz);
unsigned __int64 __cdecl nt_uptime_ms(void);

#ifdef __cplusplus
}
#endif

#endif /* _TIME_H_ */
