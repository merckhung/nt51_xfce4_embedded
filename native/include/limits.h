/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LIMITS_H_
#define _LIMITS_H_

#define CHAR_BIT   8
#define SCHAR_MIN  (-128)
#define SCHAR_MAX  127
#define UCHAR_MAX  255
#define CHAR_MIN   SCHAR_MIN
#define CHAR_MAX   SCHAR_MAX
#define SHRT_MIN   (-32768)
#define SHRT_MAX   32767
#define USHRT_MAX  0xFFFF
#define INT_MIN    (-2147483647 - 1)
#define INT_MAX    2147483647
#define UINT_MAX   0xFFFFFFFFU
#define LONG_MIN   (-2147483647L - 1)
#define LONG_MAX   2147483647L
#define ULONG_MAX  0xFFFFFFFFUL
#define LLONG_MIN  (-9223372036854775807i64 - 1)
#define LLONG_MAX  9223372036854775807i64
#define ULLONG_MAX 0xFFFFFFFFFFFFFFFFui64
#define PATH_MAX   260

#endif /* _LIMITS_H_ */
