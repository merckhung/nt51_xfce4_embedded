/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _UNISTD_H_
#define _UNISTD_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4

ssize_t __cdecl read(int fd, void *buf, size_t count);
ssize_t __cdecl write(int fd, const void *buf, size_t count);
int     __cdecl close(int fd);
off_t   __cdecl lseek(int fd, off_t offset, int whence);
int     __cdecl dup(int oldfd);
int     __cdecl dup2(int oldfd, int newfd);
int     __cdecl pipe(int pipefd[2]);
int     __cdecl isatty(int fd);
int     __cdecl fsync(int fd);
int     __cdecl ftruncate(int fd, off_t length);

int     __cdecl unlink(const char *pathname);
int     __cdecl rmdir(const char *pathname);
int     __cdecl access(const char *pathname, int mode);
int     __cdecl chdir(const char *path);
char *  __cdecl getcwd(char *buf, size_t size);

pid_t   __cdecl getpid(void);
pid_t   __cdecl getppid(void);
uid_t   __cdecl getuid(void);
uid_t   __cdecl geteuid(void);
gid_t   __cdecl getgid(void);
gid_t   __cdecl getegid(void);
int     __cdecl gethostname(char *name, size_t len);

unsigned int __cdecl sleep(unsigned int seconds);
int     __cdecl usleep(useconds_t usec);

/* Native NT process spawning & path conversion helpers */
int     __cdecl nt_dos_to_nt_path(const char *dos_path, unsigned short *nt_wbuf, size_t max_wchars);
int     __cdecl nt_resolve_path(const char *in_path, char *out_dos_path, size_t max_chars);
void *  __cdecl nt_get_osfhnd(int fd);
int     __cdecl nt_open_osfhandle(void *nt_handle, int flags);
pid_t   __cdecl nt_spawnve(const char *path, char *const argv[], char *const envp[],
                           int stdin_fd, int stdout_fd, int stderr_fd, int background);

#ifdef __cplusplus
}
#endif

#endif /* _UNISTD_H_ */
