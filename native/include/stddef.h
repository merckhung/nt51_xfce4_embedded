/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _STDDEF_H_
#define _STDDEF_H_

#ifndef NULL
#ifdef __cplusplus
#define NULL 0
#else
#define NULL ((void *)0)
#endif
#endif

typedef unsigned int size_t;
typedef int          ptrdiff_t;

#ifndef _WCHAR_T_DEFINED
#define _WCHAR_T_DEFINED
#ifndef __cplusplus
typedef unsigned short wchar_t;
#endif
#endif

#define offsetof(s, m) ((size_t)&(((s *)0)->m))

#endif /* _STDDEF_H_ */
