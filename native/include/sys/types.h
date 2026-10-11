/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SYS_TYPES_H_
#define _SYS_TYPES_H_

#include <stddef.h>
#include <stdint.h>

typedef int          pid_t;
typedef int          uid_t;
typedef int          gid_t;
typedef unsigned int mode_t;
typedef unsigned int dev_t;
typedef unsigned int ino_t;
typedef unsigned int nlink_t;
typedef __int64      off_t;
typedef int          ssize_t;
typedef long         time_t;
typedef long         clock_t;
typedef unsigned int useconds_t;
typedef long         suseconds_t;

#endif /* _SYS_TYPES_H_ */
