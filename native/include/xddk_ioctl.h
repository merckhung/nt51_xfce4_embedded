/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * native/include/xddk_ioctl.h
 * XDDK shared user/kernel definitions (IOCTL codes and structures).
 *
 * This header has no Windows header dependency so it can be included by
 * kernel modules (MSVC + ntddk.h) and by user tools (clang + MUSL).
 */
#ifndef XDDK_IOCTL_H
#define XDDK_IOCTL_H

#ifdef _MSC_VER
typedef unsigned __int64 xddk_u64;
#else
typedef unsigned long long xddk_u64;
#endif
typedef unsigned long xddk_u32;

/* Device type in the customer range, METHOD_BUFFERED, FILE_ANY_ACCESS */
#define XDDK_DEVICE_TYPE      0x8000u
#define XDDK_CTL(fn)          ((XDDK_DEVICE_TYPE << 16) | (0u << 14) | ((xddk_u32)(fn) << 2) | 0u)

/* ---- Built-in IOCTL answered by every XDDK device -------------------- */
#define IOCTL_XDDK_GET_INFO   XDDK_CTL(0x800)

typedef struct XDDK_INFO {
    char     module[32];       /* module name   (XDDK_MODULE_NAME)    */
    char     version[16];      /* module version (XDDK_MODULE_VERSION) */
    char     device[32];       /* device name, e.g. "xchar"           */
    xddk_u32 open_count;       /* handles currently open              */
    xddk_u32 total_opens;      /* opens since load                    */
    xddk_u32 ioctls;           /* IOCTLs handled since load           */
    xddk_u32 live_allocs;      /* outstanding xddk_alloc blocks       */
    xddk_u64 bytes_read;
    xddk_u64 bytes_written;
    xddk_u64 loaded_ms;        /* milliseconds since module load      */
} XDDK_INFO;

/* Driver-specific IOCTLs must use function numbers >= this value */
#define XDDK_CTL_USER_BASE    0x900

/* ---- Sample: xchar (ring buffer char device) ------------------------- */
#define IOCTL_XCHAR_CLEAR     XDDK_CTL(0x900)
#define IOCTL_XCHAR_STATS     XDDK_CTL(0x901)

typedef struct XCHAR_STATS {
    xddk_u32 used;             /* bytes currently buffered   */
    xddk_u32 capacity;         /* ring buffer size           */
    xddk_u64 total_in;         /* bytes written since load   */
    xddk_u64 total_out;        /* bytes read since load      */
} XCHAR_STATS;

/* ---- Sample: xticker (C++ periodic timer device) --------------------- */
#define IOCTL_XTICKER_GET         XDDK_CTL(0x910)
#define IOCTL_XTICKER_SET_PERIOD  XDDK_CTL(0x911)   /* in: xddk_u32 period_ms */

typedef struct XTICKER_STATE {
    xddk_u64 ticks;            /* timer DPC executions       */
    xddk_u32 period_ms;        /* current period             */
    xddk_u32 objects_alive;    /* live C++ objects (ctor/dtor accounting) */
} XTICKER_STATE;

#endif /* XDDK_IOCTL_H */
