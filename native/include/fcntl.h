/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _FCNTL_H_
#define _FCNTL_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_ACCMODE   0x0003

#define O_CREAT     0x0100
#define O_TRUNC     0x0200
#define O_EXCL      0x0400
#define O_APPEND    0x0800
#define O_NONBLOCK  0x1000
#define O_BINARY    0x8000
#define O_DIRECTORY 0x10000
#define O_CLOEXEC   0x80000

#define F_DUPFD     0
#define F_GETFD     1
#define F_SETFD     2
#define F_GETFL     3
#define F_SETFL     4
#define FD_CLOEXEC  1

int __cdecl open(const char *pathname, int flags, ...);
int __cdecl creat(const char *pathname, mode_t mode);
int __cdecl fcntl(int fd, int cmd, ...);

#ifdef __cplusplus
}
#endif

#endif /* _FCNTL_H_ */
