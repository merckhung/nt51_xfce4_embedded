/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _CTYPE_H_
#define _CTYPE_H_

#ifdef __cplusplus
extern "C" {
#endif

static __inline int isspace(int c) {
    return (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v');
}
static __inline int isdigit(int c) {
    return (c >= '0' && c <= '9');
}
static __inline int isupper(int c) {
    return (c >= 'A' && c <= 'Z');
}
static __inline int islower(int c) {
    return (c >= 'a' && c <= 'z');
}
static __inline int isalpha(int c) {
    return isupper(c) || islower(c);
}
static __inline int isalnum(int c) {
    return isalpha(c) || isdigit(c);
}
static __inline int isxdigit(int c) {
    return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static __inline int isprint(int c) {
    return (c >= 0x20 && c <= 0x7E);
}
static __inline int isgraph(int c) {
    return (c > 0x20 && c <= 0x7E);
}
static __inline int iscntrl(int c) {
    return ((c >= 0 && c < 0x20) || c == 0x7F);
}
static __inline int ispunct(int c) {
    return isgraph(c) && !isalnum(c);
}
static __inline int tolower(int c) {
    return isupper(c) ? (c + ('a' - 'A')) : c;
}
static __inline int toupper(int c) {
    return islower(c) ? (c - ('a' - 'A')) : c;
}

#ifdef __cplusplus
}
#endif

#endif /* _CTYPE_H_ */
