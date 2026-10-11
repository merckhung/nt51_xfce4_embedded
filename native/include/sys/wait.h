/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SYS_WAIT_H_
#define _SYS_WAIT_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WNOHANG   1
#define WUNTRACED 2

#define WIFEXITED(s)    (((s) & 0x7F) == 0)
#define WEXITSTATUS(s)  (((s) >> 8) & 0xFF)
#define WIFSIGNALED(s)  (((s) & 0x7F) != 0 && ((s) & 0x7F) != 0x7F)
#define WTERMSIG(s)     ((s) & 0x7F)
#define WIFSTOPPED(s)   (((s) & 0xFF) == 0x7F)
#define WSTOPSIG(s)     (((s) >> 8) & 0xFF)

pid_t __cdecl waitpid(pid_t pid, int *status, int options);
pid_t __cdecl wait(int *status);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_WAIT_H_ */
