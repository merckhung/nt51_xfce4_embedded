/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SIGNAL_H_
#define _SIGNAL_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int sig_atomic_t;
typedef void (__cdecl *sighandler_t)(int);

#define SIG_DFL ((sighandler_t)0)
#define SIG_IGN ((sighandler_t)1)
#define SIG_ERR ((sighandler_t)-1)

#define SIGHUP    1
#define SIGINT    2
#define SIGQUIT   3
#define SIGILL    4
#define SIGTRAP   5
#define SIGABRT   6
#define SIGFPE    8
#define SIGKILL   9
#define SIGSEGV   11
#define SIGPIPE   13
#define SIGALRM   14
#define SIGTERM   15
#define SIGCHLD   17
#define SIGCONT   18
#define SIGSTOP   19
#define SIGTSTP   20

sighandler_t __cdecl signal(int signum, sighandler_t handler);
int          __cdecl raise(int sig);
int          __cdecl kill(pid_t pid, int sig);

#ifdef __cplusplus
}
#endif

#endif /* _SIGNAL_H_ */
