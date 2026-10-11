/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _DIRENT_H_
#define _DIRENT_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DT_UNKNOWN 0
#define DT_FIFO    1
#define DT_CHR     2
#define DT_DIR     4
#define DT_BLK     6
#define DT_REG     8
#define DT_LNK     10

struct dirent {
    ino_t          d_ino;
    unsigned char  d_type;
    unsigned int   d_attributes;
    unsigned __int64 d_size;
    __int64        d_mtime;
    char           d_name[260];
};

typedef struct _NTC_DIR DIR;

DIR *          __cdecl opendir(const char *name);
struct dirent *__cdecl readdir(DIR *dirp);
void           __cdecl rewinddir(DIR *dirp);
int            __cdecl closedir(DIR *dirp);

#ifdef __cplusplus
}
#endif

#endif /* _DIRENT_H_ */
