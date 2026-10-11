/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rootfs/shim/nt_linux_shim.h
 * Linux i386 to Windows NT Native System Call Translation Bridge
 */

#ifndef _NT_LINUX_SHIM_H_
#define _NT_LINUX_SHIM_H_

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed char        s8;
typedef signed short       s16;
typedef signed int         s32;
typedef signed long long   s64;

/* ========================================================================= */
/* Linux i386 System Call Numbers                                            */
/* ========================================================================= */
#define LINUX_SYS_restart_syscall   0
#define LINUX_SYS_exit             1
#define LINUX_SYS_fork             2
#define LINUX_SYS_read             3
#define LINUX_SYS_write            4
#define LINUX_SYS_open             5
#define LINUX_SYS_close            6
#define LINUX_SYS_waitpid          7
#define LINUX_SYS_creat            8
#define LINUX_SYS_link             9
#define LINUX_SYS_unlink           10
#define LINUX_SYS_execve           11
#define LINUX_SYS_chdir            12
#define LINUX_SYS_time             13
#define LINUX_SYS_mknod            14
#define LINUX_SYS_chmod            15
#define LINUX_SYS_lchown           16
#define LINUX_SYS_lseek            19
#define LINUX_SYS_getpid           20
#define LINUX_SYS_mount            21
#define LINUX_SYS_umount           22
#define LINUX_SYS_setuid           23
#define LINUX_SYS_getuid           24
#define LINUX_SYS_fstat            28
#define LINUX_SYS_pause            29
#define LINUX_SYS_utime            30
#define LINUX_SYS_access           33
#define LINUX_SYS_sync             36
#define LINUX_SYS_kill             37
#define LINUX_SYS_rename           38
#define LINUX_SYS_mkdir            39
#define LINUX_SYS_rmdir            40
#define LINUX_SYS_dup              41
#define LINUX_SYS_pipe             42
#define LINUX_SYS_times            43
#define LINUX_SYS_brk              45
#define LINUX_SYS_setgid           46
#define LINUX_SYS_getgid           47
#define LINUX_SYS_signal           48
#define LINUX_SYS_geteuid          49
#define LINUX_SYS_getegid          50
#define LINUX_SYS_ioctl            54
#define LINUX_SYS_fcntl            55
#define LINUX_SYS_setpgid          57
#define LINUX_SYS_umask            60
#define LINUX_SYS_chroot           61
#define LINUX_SYS_dup2             63
#define LINUX_SYS_getppid          64
#define LINUX_SYS_getpgrp          65
#define LINUX_SYS_setsid           66
#define LINUX_SYS_sigaction        67
#define LINUX_SYS_sgetmask         68
#define LINUX_SYS_ssetmask         69
#define LINUX_SYS_setreuid         70
#define LINUX_SYS_setregid         71
#define LINUX_SYS_sigsuspend       72
#define LINUX_SYS_sigpending       73
#define LINUX_SYS_sethostname      74
#define LINUX_SYS_setrlimit        75
#define LINUX_SYS_getrlimit        76
#define LINUX_SYS_getrusage        77
#define LINUX_SYS_gettimeofday     78
#define LINUX_SYS_settimeofday     79
#define LINUX_SYS_getgroups        80
#define LINUX_SYS_setgroups        81
#define LINUX_SYS_select           82
#define LINUX_SYS_symlink          83
#define LINUX_SYS_lstat            84
#define LINUX_SYS_readlink         85
#define LINUX_SYS_reboot           88
#define LINUX_SYS_mmap             90
#define LINUX_SYS_munmap           91
#define LINUX_SYS_truncate         92
#define LINUX_SYS_ftruncate        93
#define LINUX_SYS_fchmod           94
#define LINUX_SYS_fchown           95
#define LINUX_SYS_statfs           99
#define LINUX_SYS_fstatfs          100
#define LINUX_SYS_stat             106
#define LINUX_SYS_lstat_old        107
#define LINUX_SYS_fstat_old        108
#define LINUX_SYS_wait4            114
#define LINUX_SYS_sysinfo          116
#define LINUX_SYS_fsync            118
#define LINUX_SYS_sigreturn        119
#define LINUX_SYS_clone            120
#define LINUX_SYS_uname            122
#define LINUX_SYS_mprotect         125
#define LINUX_SYS_sigprocmask      126
#define LINUX_SYS_fchdir           133
#define LINUX_SYS_llseek           140
#define LINUX_SYS_getdents         141
#define LINUX_SYS__newselect       142
#define LINUX_SYS_flock            143
#define LINUX_SYS_msync            144
#define LINUX_SYS_readv            145
#define LINUX_SYS_writev           146
#define LINUX_SYS_getsid           147
#define LINUX_SYS_fdatasync        148
#define LINUX_SYS_nanosleep        162
#define LINUX_SYS_mremap           163
#define LINUX_SYS_poll             168
#define LINUX_SYS_prctl            172
#define LINUX_SYS_rt_sigreturn     173
#define LINUX_SYS_rt_sigaction     174
#define LINUX_SYS_rt_sigprocmask   175
#define LINUX_SYS_rt_sigpending    176
#define LINUX_SYS_rt_sigtimedwait  177
#define LINUX_SYS_rt_sigqueueinfo  178
#define LINUX_SYS_rt_sigsuspend    179
#define LINUX_SYS_chown            182
#define LINUX_SYS_getcwd           183
#define LINUX_SYS_capget           184
#define LINUX_SYS_capset           185
#define LINUX_SYS_sigaltstack      186
#define LINUX_SYS_vfork            190
#define LINUX_SYS_mmap2            192
#define LINUX_SYS_truncate64       193
#define LINUX_SYS_ftruncate64      194
#define LINUX_SYS_stat64           195
#define LINUX_SYS_lstat64          196
#define LINUX_SYS_fstat64          197
#define LINUX_SYS_getdents64       220
#define LINUX_SYS_fcntl64          221
#define LINUX_SYS_gettid           224
#define LINUX_SYS_tkill            238
#define LINUX_SYS_futex            240
#define LINUX_SYS_sched_setaffinity 241
#define LINUX_SYS_sched_getaffinity 242
#define LINUX_SYS_set_thread_area  243
#define LINUX_SYS_get_thread_area  244
#define LINUX_SYS_exit_group       252
#define LINUX_SYS_set_tid_address  258
#define LINUX_SYS_clock_gettime    265
#define LINUX_SYS_clock_getres     266
#define LINUX_SYS_clock_nanosleep  267
#define LINUX_SYS_statfs64         268
#define LINUX_SYS_fstatfs64        269
#define LINUX_SYS_tgkill           270
#define LINUX_SYS_utimes           271
#define LINUX_SYS_openat           295
#define LINUX_SYS_mkdirat          296
#define LINUX_SYS_mknodat          297
#define LINUX_SYS_fchownat         298
#define LINUX_SYS_futimesat        299
#define LINUX_SYS_fstatat64        300
#define LINUX_SYS_unlinkat         301
#define LINUX_SYS_renameat         302
#define LINUX_SYS_linkat           303
#define LINUX_SYS_symlinkat        304
#define LINUX_SYS_readlinkat       305
#define LINUX_SYS_fchmodat         306
#define LINUX_SYS_faccessat        307
#define LINUX_SYS_pselect6         308
#define LINUX_SYS_ppoll            309
#define LINUX_SYS_dup3             330
#define LINUX_SYS_pipe2            331
#define LINUX_SYS_prlimit64        340

/* ========================================================================= */
/* Linux Error Codes (negative errno return values)                          */
/* ========================================================================= */
#define LINUX_EPERM          1   /* Operation not permitted */
#define LINUX_ENOENT         2   /* No such file or directory */
#define LINUX_ESRCH          3   /* No such process */
#define LINUX_EINTR          4   /* Interrupted system call */
#define LINUX_EIO            5   /* I/O error */
#define LINUX_ENXIO          6   /* No such device or address */
#define LINUX_E2BIG          7   /* Argument list too long */
#define LINUX_ENOEXEC        8   /* Exec format error */
#define LINUX_EBADF          9   /* Bad file number */
#define LINUX_ECHILD        10   /* No child processes */
#define LINUX_EAGAIN        11   /* Try again */
#define LINUX_ENOMEM        12   /* Out of memory */
#define LINUX_EACCES        13   /* Permission denied */
#define LINUX_EFAULT        14   /* Bad address */
#define LINUX_ENOTBLK       15   /* Block device required */
#define LINUX_EBUSY         16   /* Device or resource busy */
#define LINUX_EEXIST        17   /* File exists */
#define LINUX_EXDEV         18   /* Cross-device link */
#define LINUX_ENODEV        19   /* No such device */
#define LINUX_ENOTDIR       20   /* Not a directory */
#define LINUX_EISDIR        21   /* Is a directory */
#define LINUX_EINVAL        22   /* Invalid argument */
#define LINUX_ENFILE        23   /* File table overflow */
#define LINUX_EMFILE        24   /* Too many open files */
#define LINUX_ENOTTY        25   /* Not a typewriter */
#define LINUX_ETXTBSY       26   /* Text file busy */
#define LINUX_EFBIG         27   /* File too large */
#define LINUX_ENOSPC        28   /* No space left on device */
#define LINUX_ESPIPE        29   /* Illegal seek */
#define LINUX_EROFS         30   /* Read-only file system */
#define LINUX_EMLINK        31   /* Too many links */
#define LINUX_EPIPE         32   /* Broken pipe */
#define LINUX_EDOM          33   /* Math argument out of domain */
#define LINUX_ERANGE        34   /* Math result not representable */
#define LINUX_ENAMETOOLONG  36   /* File name too long */
#define LINUX_ENOSYS        38   /* Function not implemented */
#define LINUX_ENOTEMPTY     39   /* Directory not empty */
#define LINUX_ELOOP         40   /* Too many symbolic links encountered */
#define LINUX_ENOTSOCK      88   /* Socket operation on non-socket */
#define LINUX_EAFNOSUPPORT  97   /* Address family not supported */
#define LINUX_EADDRINUSE    98   /* Address already in use */
#define LINUX_ENOTCONN     107   /* Transport endpoint is not connected */
#define LINUX_ECONNREFUSED 111   /* Connection refused */
#define LINUX_EINPROGRESS  115   /* Operation now in progress */

/* ========================================================================= */
/* Linux Structures for i386                                                 */
/* ========================================================================= */
struct linux_timespec {
    long tv_sec;
    long tv_nsec;
};

struct linux_timeval {
    long tv_sec;
    long tv_usec;
};

struct linux_stat64 {
    u64 st_dev;
    u32 __pad1;
    u32 __st_ino;
    u32 st_mode;
    u32 st_nlink;
    u32 st_uid;
    u32 st_gid;
    u64 st_rdev;
    u32 __pad2;
    s64 st_size;
    s32 st_blksize;
    s64 st_blocks;
    struct linux_timespec st_atim;
    struct linux_timespec st_mtim;
    struct linux_timespec st_ctim;
    u64 st_ino;
};

struct linux_dirent64 {
    u64            d_ino;
    s64            d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

struct linux_winsize {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
};

struct linux_termios {
    unsigned int c_iflag;
    unsigned int c_oflag;
    unsigned int c_cflag;
    unsigned int c_lflag;
    unsigned char c_line;
    unsigned char c_cc[32];
    unsigned int c_ispeed;
    unsigned int c_ospeed;
};

struct linux_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct linux_iovec {
    void *iov_base;
    unsigned int iov_len;
};

/* Core Entry Point Called from MUSL's syscall_arch.h */
long __nt_linux_syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6);

/* Initialization & Subsystem Interface */
void nt_linux_shim_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _NT_LINUX_SHIM_H_ */
