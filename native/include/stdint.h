/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _STDINT_H_
#define _STDINT_H_

typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef __int64            int64_t;

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned __int64   uint64_t;

typedef int                intptr_t;
typedef unsigned int       uintptr_t;
typedef __int64            intmax_t;
typedef unsigned __int64   uintmax_t;

#define INT8_MIN           (-128)
#define INT16_MIN          (-32768)
#define INT32_MIN          (-2147483647 - 1)
#define INT64_MIN          (-9223372036854775807i64 - 1)

#define INT8_MAX           127
#define INT16_MAX          32767
#define INT32_MAX          2147483647
#define INT64_MAX          9223372036854775807i64

#define UINT8_MAX          0xFFU
#define UINT16_MAX         0xFFFFU
#define UINT32_MAX         0xFFFFFFFFU
#define UINT64_MAX         0xFFFFFFFFFFFFFFFFui64

#define INTPTR_MIN         INT32_MIN
#define INTPTR_MAX         INT32_MAX
#define UINTPTR_MAX        UINT32_MAX
#define SIZE_MAX           UINT32_MAX

#endif /* _STDINT_H_ */
