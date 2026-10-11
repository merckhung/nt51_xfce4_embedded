/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * native/libntc/fd.c
 * POSIX File Descriptor Table, Path Translation, Directory & File I/O over NT Syscalls
 */

#include "../include/ntnative.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAX_FDS 128

#define FD_TYPE_NONE    0
#define FD_TYPE_CONSOLE 1
#define FD_TYPE_FILE    2
#define FD_TYPE_PIPE    3
#define FD_TYPE_NULL    4

typedef struct _NTC_FD_ENTRY {
    int      type;
    HANDLE   handle;
    int      flags;
    LONGLONG offset;
} NTC_FD_ENTRY;

static NTC_FD_ENTRY g_FdTable[MAX_FDS];
static BOOLEAN      g_FdsInitialized = FALSE;
static char         g_CurrentDir[260] = "C:\\";
static ULONG        g_PipeSeq = 1;

/* Convert NT 100ns timestamp (since 1601-01-01) to Unix epoch seconds (1970-01-01) */
static time_t NtTimeToUnixTime(LONGLONG nt_time) {
    const LONGLONG epoch_diff = 116444736000000000i64;
    if (nt_time <= epoch_diff) return 0;
    return (time_t)((nt_time - epoch_diff) / 10000000i64);
}

int __cdecl nt_resolve_path(const char *in_path, char *out_dos_path, size_t max_chars) {
    char temp[520];
    char *parts[64];
    int part_count = 0;
    char drive = 'C';
    int i = 0;
    char *p;

    if (!in_path || !out_dos_path || max_chars < 8) {
        errno = EINVAL;
        return -1;
    }

    while (isspace((unsigned char)*in_path)) in_path++;

    /* Special device aliases */
    if (strcmp(in_path, "/dev/null") == 0 || strcasecmp(in_path, "NUL") == 0) {
        strncpy(out_dos_path, "\\Device\\Null", max_chars - 1);
        out_dos_path[max_chars - 1] = '\0';
        return 0;
    }
    if (strcmp(in_path, "/dev/tty") == 0 || strcmp(in_path, "/dev/console") == 0 ||
        strcasecmp(in_path, "CON") == 0) {
        strncpy(out_dos_path, "\\Device\\Console", max_chars - 1);
        out_dos_path[max_chars - 1] = '\0';
        return 0;
    }
    if (strcmp(in_path, "/dev/ttyS0") == 0 || strcasecmp(in_path, "COM1") == 0) {
        strncpy(out_dos_path, "\\Device\\Serial0", max_chars - 1);
        out_dos_path[max_chars - 1] = '\0';
        return 0;
    }

    /* Raw NT object paths (\Device\..., \??\..., \SystemRoot\..., \Registry\...) */
    if (in_path[0] == '\\' &&
        (strncasecmp(in_path, "\\??\\", 4) == 0 ||
         strncasecmp(in_path, "\\Device\\", 8) == 0 ||
         strncasecmp(in_path, "\\SystemRoot", 11) == 0 ||
         strncasecmp(in_path, "\\Registry", 9) == 0 ||
         strncasecmp(in_path, "\\ArcName", 8) == 0 ||
         strncasecmp(in_path, "\\Driver", 7) == 0 ||
         strncasecmp(in_path, "\\ObjectTypes", 12) == 0)) {
        strncpy(out_dos_path, in_path, max_chars - 1);
        out_dos_path[max_chars - 1] = '\0';
        for (i = 0; out_dos_path[i]; i++) {
            if (out_dos_path[i] == '/') out_dos_path[i] = '\\';
        }
        return 0;
    }

    /* Determine starting base path */
    if (isalpha((unsigned char)in_path[0]) && in_path[1] == ':') {
        drive = (char)toupper((unsigned char)in_path[0]);
        if (in_path[2] == '\\' || in_path[2] == '/') {
            strncpy(temp, in_path + 3, sizeof(temp) - 1);
            temp[sizeof(temp) - 1] = '\0';
        } else {
            snprintf(temp, sizeof(temp), "%s\\%s", g_CurrentDir + 3, in_path + 2);
        }
    } else if (in_path[0] == '/' || in_path[0] == '\\') {
        drive = g_CurrentDir[0] ? g_CurrentDir[0] : 'C';
        strncpy(temp, in_path + 1, sizeof(temp) - 1);
        temp[sizeof(temp) - 1] = '\0';
    } else {
        drive = g_CurrentDir[0] ? g_CurrentDir[0] : 'C';
        snprintf(temp, sizeof(temp), "%s\\%s", g_CurrentDir + 3, in_path);
    }

    /* Normalize slashes and split components */
    for (i = 0; temp[i]; i++) {
        if (temp[i] == '/') temp[i] = '\\';
    }

    p = temp;
    while (*p) {
        char *seg;
        while (*p == '\\') p++;
        if (!*p) break;
        seg = p;
        while (*p && *p != '\\') p++;
        if (*p == '\\') {
            *p++ = '\0';
        }
        if (strcmp(seg, ".") == 0) {
            continue;
        } else if (strcmp(seg, "..") == 0) {
            if (part_count > 0) part_count--;
        } else if (part_count < 64) {
            parts[part_count++] = seg;
        }
    }

    out_dos_path[0] = drive;
    out_dos_path[1] = ':';
    out_dos_path[2] = '\\';
    out_dos_path[3] = '\0';

    for (i = 0; i < part_count; i++) {
        if (i > 0) {
            strncat(out_dos_path, "\\", max_chars - strlen(out_dos_path) - 1);
        }
        strncat(out_dos_path, parts[i], max_chars - strlen(out_dos_path) - 1);
    }
    return 0;
}

int __cdecl nt_dos_to_nt_path(const char *dos_path, unsigned short *nt_wbuf, size_t max_wchars) {
    char resolved[260];
    size_t i = 0, w = 0;

    if (!dos_path || !nt_wbuf || max_wchars < 12) {
        errno = EINVAL;
        return -1;
    }
    if (nt_resolve_path(dos_path, resolved, sizeof(resolved)) < 0) {
        return -1;
    }

    if (resolved[0] == '\\') {
        for (i = 0; resolved[i] && w + 1 < max_wchars; i++) {
            nt_wbuf[w++] = (unsigned short)(unsigned char)resolved[i];
        }
        nt_wbuf[w] = L'\0';
        return 0;
    }

    nt_wbuf[w++] = L'\\';
    nt_wbuf[w++] = L'?';
    nt_wbuf[w++] = L'?';
    nt_wbuf[w++] = L'\\';
    for (i = 0; resolved[i] && w + 1 < max_wchars; i++) {
        nt_wbuf[w++] = (unsigned short)(unsigned char)resolved[i];
    }
    nt_wbuf[w] = L'\0';
    return 0;
}

static void EnsureDosDriveLinks(void) {
    UNICODE_STRING u_c, u_arc, u_sysroot, u_target;
    OBJECT_ATTRIBUTES oa;
    HANDLE hLink = NULL;
    WCHAR target_buf[260];
    ULONG ret_len = 0;

    RtlInitUnicodeString(&u_c, L"\\??\\C:");
    InitializeObjectAttributes(&oa, &u_c, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NT_SUCCESS(NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &oa))) {
        NtClose(hLink);
        return;
    }

    /* Try \ArcName\ramdisk(0) first */
    RtlInitUnicodeString(&u_arc, L"\\ArcName\\ramdisk(0)");
    InitializeObjectAttributes(&oa, &u_arc, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NT_SUCCESS(NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &oa))) {
        u_target.Buffer = target_buf;
        u_target.Length = 0;
        u_target.MaximumLength = sizeof(target_buf) - sizeof(WCHAR);
        if (NT_SUCCESS(NtQuerySymbolicLinkObject(hLink, &u_target, &ret_len))) {
            HANDLE hNewLink = NULL;
            target_buf[u_target.Length / sizeof(WCHAR)] = L'\0';
            InitializeObjectAttributes(&oa, &u_c, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL);
            if (NT_SUCCESS(NtCreateSymbolicLinkObject(&hNewLink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &u_target))) {
                NtMakePermanentObject(hNewLink);
                NtClose(hNewLink);
                NtClose(hLink);
                return;
            }
        }
        NtClose(hLink);
    }

    /* Fallback: extract device prefix from \SystemRoot */
    RtlInitUnicodeString(&u_sysroot, L"\\SystemRoot");
    InitializeObjectAttributes(&oa, &u_sysroot, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NT_SUCCESS(NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &oa))) {
        u_target.Buffer = target_buf;
        u_target.Length = 0;
        u_target.MaximumLength = sizeof(target_buf) - sizeof(WCHAR);
        if (NT_SUCCESS(NtQuerySymbolicLinkObject(hLink, &u_target, &ret_len))) {
            USHORT chars = u_target.Length / sizeof(WCHAR);
            USHORT i;
            target_buf[chars] = L'\0';
            /* Strip trailing \WINDOWS or \WINNT */
            for (i = chars; i > 8; i--) {
                if (target_buf[i - 1] == L'\\') {
                    target_buf[i - 1] = L'\0';
                    u_target.Length = (USHORT)((i - 1) * sizeof(WCHAR));
                    break;
                }
            }
            {
                HANDLE hNewLink = NULL;
                InitializeObjectAttributes(&oa, &u_c, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL);
                if (NT_SUCCESS(NtCreateSymbolicLinkObject(&hNewLink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &u_target))) {
                    NtMakePermanentObject(hNewLink);
                    NtClose(hNewLink);
                }
            }
        }
        NtClose(hLink);
    }
}

void __cdecl _libntc_init_fds(PPEB peb) {
    int i;
    if (g_FdsInitialized) return;
    EnsureDosDriveLinks();
    for (i = 0; i < MAX_FDS; i++) {
        g_FdTable[i].type = FD_TYPE_NONE;
        g_FdTable[i].handle = NULL;
        g_FdTable[i].flags = 0;
        g_FdTable[i].offset = 0;
    }

    /* Default 0, 1, 2 to dual-head console */
    g_FdTable[0].type = FD_TYPE_CONSOLE;
    g_FdTable[0].flags = O_RDONLY;
    g_FdTable[1].type = FD_TYPE_CONSOLE;
    g_FdTable[1].flags = O_WRONLY;
    g_FdTable[2].type = FD_TYPE_CONSOLE;
    g_FdTable[2].flags = O_WRONLY;

    if (peb && peb->ProcessParameters) {
        PRTL_USER_PROCESS_PARAMETERS pp = peb->ProcessParameters;
        if (pp->StandardInput && pp->StandardInput != (HANDLE)(LONG_PTR)-1) {
            g_FdTable[0].type = FD_TYPE_FILE;
            g_FdTable[0].handle = pp->StandardInput;
        }
        if (pp->StandardOutput && pp->StandardOutput != (HANDLE)(LONG_PTR)-1) {
            g_FdTable[1].type = FD_TYPE_FILE;
            g_FdTable[1].handle = pp->StandardOutput;
        }
        if (pp->StandardError && pp->StandardError != (HANDLE)(LONG_PTR)-1) {
            g_FdTable[2].type = FD_TYPE_FILE;
            g_FdTable[2].handle = pp->StandardError;
        }
        if (pp->CurrentDirectory.DosPath.Buffer && pp->CurrentDirectory.DosPath.Length > 0) {
            USHORT chars = pp->CurrentDirectory.DosPath.Length / sizeof(WCHAR);
            USHORT k;
            if (chars < sizeof(g_CurrentDir) - 1) {
                for (k = 0; k < chars; k++) {
                    g_CurrentDir[k] = (char)pp->CurrentDirectory.DosPath.Buffer[k];
                }
                g_CurrentDir[chars] = '\0';
                if (chars > 3 && g_CurrentDir[chars - 1] == '\\') {
                    g_CurrentDir[chars - 1] = '\0';
                }
            }
        }
    }

    g_FdsInitialized = TRUE;
}

static int AllocFd(int min_fd) {
    int i;
    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    for (i = min_fd; i < MAX_FDS; i++) {
        if (g_FdTable[i].type == FD_TYPE_NONE) {
            return i;
        }
    }
    errno = EMFILE;
    return -1;
}

void * __cdecl nt_get_osfhnd(int fd) {
    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    if (fd < 0 || fd >= MAX_FDS || g_FdTable[fd].type == FD_TYPE_NONE) {
        return NULL;
    }
    return g_FdTable[fd].handle;
}

int __cdecl nt_open_osfhandle(void *nt_handle, int flags) {
    int fd = AllocFd(3);
    if (fd < 0) return -1;
    g_FdTable[fd].type = FD_TYPE_FILE;
    g_FdTable[fd].handle = (HANDLE)nt_handle;
    g_FdTable[fd].flags = flags;
    g_FdTable[fd].offset = 0;
    return fd;
}

int __cdecl open(const char *pathname, int flags, ...) {
    char resolved[260];
    WCHAR nt_path[280];
    UNICODE_STRING u_path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    ACCESS_MASK access = SYNCHRONIZE;
    ULONG disposition = FILE_OPEN;
    ULONG create_opts = FILE_SYNCHRONOUS_IO_NONALERT;
    HANDLE hFile = NULL;
    NTSTATUS st;
    int fd;

    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    if (!pathname) {
        errno = EINVAL;
        return -1;
    }
    if (nt_resolve_path(pathname, resolved, sizeof(resolved)) < 0) {
        return -1;
    }

    if (strcmp(resolved, "\\Device\\Null") == 0) {
        fd = AllocFd(0);
        if (fd < 0) return -1;
        g_FdTable[fd].type = FD_TYPE_NULL;
        g_FdTable[fd].handle = NULL;
        g_FdTable[fd].flags = flags;
        g_FdTable[fd].offset = 0;
        return fd;
    }
    if (strcmp(resolved, "\\Device\\Console") == 0) {
        fd = AllocFd(0);
        if (fd < 0) return -1;
        g_FdTable[fd].type = FD_TYPE_CONSOLE;
        g_FdTable[fd].handle = NULL;
        g_FdTable[fd].flags = flags;
        g_FdTable[fd].offset = 0;
        return fd;
    }

    if ((flags & O_ACCMODE) == O_WRONLY) {
        access |= GENERIC_WRITE | FILE_READ_ATTRIBUTES;
    } else if ((flags & O_ACCMODE) == O_RDWR) {
        access |= GENERIC_READ | GENERIC_WRITE;
    } else {
        access |= GENERIC_READ;
    }

    if (flags & O_CREAT) {
        if (flags & O_EXCL) disposition = FILE_CREATE;
        else if (flags & O_TRUNC) disposition = FILE_OVERWRITE_IF;
        else disposition = FILE_OPEN_IF;
    } else if (flags & O_TRUNC) {
        disposition = FILE_OVERWRITE;
    } else {
        disposition = FILE_OPEN;
    }

    if (flags & O_DIRECTORY) {
        create_opts |= FILE_DIRECTORY_FILE;
    } else {
        create_opts |= FILE_NON_DIRECTORY_FILE;
    }

    if (nt_dos_to_nt_path(resolved, nt_path, 275) < 0) {
        return -1;
    }
    RtlInitUnicodeString(&u_path, nt_path);
    InitializeObjectAttributes(&oa, &u_path, OBJ_CASE_INSENSITIVE | OBJ_INHERIT, NULL, NULL);

    st = NtCreateFile(
        &hFile,
        access,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        disposition,
        create_opts,
        NULL,
        0
    );
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }

    fd = AllocFd(0);
    if (fd < 0) {
        NtClose(hFile);
        return -1;
    }

    g_FdTable[fd].type = FD_TYPE_FILE;
    g_FdTable[fd].handle = hFile;
    g_FdTable[fd].flags = flags;
    g_FdTable[fd].offset = 0;

    if (flags & O_APPEND) {
        FILE_STANDARD_INFORMATION fsi;
        if (NT_SUCCESS(NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation))) {
            g_FdTable[fd].offset = fsi.EndOfFile.QuadPart;
        }
    }

    return fd;
}

int __cdecl creat(const char *pathname, mode_t mode) {
    return open(pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

int __cdecl close(int fd) {
    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    if (fd < 0 || fd >= MAX_FDS || g_FdTable[fd].type == FD_TYPE_NONE) {
        errno = EBADF;
        return -1;
    }
    if ((g_FdTable[fd].type == FD_TYPE_FILE || g_FdTable[fd].type == FD_TYPE_PIPE) &&
        g_FdTable[fd].handle) {
        NtClose(g_FdTable[fd].handle);
    }
    g_FdTable[fd].type = FD_TYPE_NONE;
    g_FdTable[fd].handle = NULL;
    g_FdTable[fd].flags = 0;
    g_FdTable[fd].offset = 0;
    return 0;
}

ssize_t __cdecl read(int fd, void *buf, size_t count) {
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER byte_offset;
    NTSTATUS st;

    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    if (fd < 0 || fd >= MAX_FDS || g_FdTable[fd].type == FD_TYPE_NONE) {
        errno = EBADF;
        return -1;
    }
    if (count == 0) return 0;

    if (g_FdTable[fd].type == FD_TYPE_NULL) {
        return 0;
    }
    if (g_FdTable[fd].type == FD_TYPE_CONSOLE) {
        char *cbuf = (char *)buf;
        size_t i = 0;
        while (i < count) {
            int ch = nt_console_getc(0);
            if (ch < 0 || ch == 4) break; /* EOF / Ctrl+D */
            cbuf[i++] = (char)ch;
            nt_console_write(&cbuf[i - 1], 1);
            if (ch == '\n') break;
        }
        return (ssize_t)i;
    }

    byte_offset.QuadPart = g_FdTable[fd].offset;
    st = NtReadFile(
        g_FdTable[fd].handle,
        NULL,
        NULL,
        NULL,
        &iosb,
        buf,
        (ULONG)count,
        (g_FdTable[fd].type == FD_TYPE_PIPE) ? NULL : &byte_offset,
        NULL
    );
    if (st == STATUS_PENDING) {
        NtWaitForSingleObject(g_FdTable[fd].handle, FALSE, NULL);
        st = iosb.Status;
    }
    if (st == STATUS_END_OF_FILE || st == STATUS_PIPE_BROKEN || st == STATUS_PIPE_CLOSING) {
        return 0;
    }
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }
    g_FdTable[fd].offset += (LONGLONG)iosb.Information;
    return (ssize_t)iosb.Information;
}

ssize_t __cdecl write(int fd, const void *buf, size_t count) {
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER byte_offset;
    NTSTATUS st;

    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    if (fd < 0 || fd >= MAX_FDS || g_FdTable[fd].type == FD_TYPE_NONE) {
        errno = EBADF;
        return -1;
    }
    if (count == 0) return 0;

    if (g_FdTable[fd].type == FD_TYPE_NULL) {
        return (ssize_t)count;
    }
    if (g_FdTable[fd].type == FD_TYPE_CONSOLE) {
        nt_console_write((const char *)buf, count);
        return (ssize_t)count;
    }

    if (g_FdTable[fd].flags & O_APPEND) {
        FILE_STANDARD_INFORMATION fsi;
        if (NT_SUCCESS(NtQueryInformationFile(g_FdTable[fd].handle, &iosb, &fsi, sizeof(fsi), FileStandardInformation))) {
            g_FdTable[fd].offset = fsi.EndOfFile.QuadPart;
        }
    }

    byte_offset.QuadPart = g_FdTable[fd].offset;
    st = NtWriteFile(
        g_FdTable[fd].handle,
        NULL,
        NULL,
        NULL,
        &iosb,
        (PVOID)buf,
        (ULONG)count,
        (g_FdTable[fd].type == FD_TYPE_PIPE) ? NULL : &byte_offset,
        NULL
    );
    if (st == STATUS_PENDING) {
        NtWaitForSingleObject(g_FdTable[fd].handle, FALSE, NULL);
        st = iosb.Status;
    }
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }
    g_FdTable[fd].offset += (LONGLONG)iosb.Information;
    return (ssize_t)iosb.Information;
}

off_t __cdecl lseek(int fd, off_t offset, int whence) {
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION fsi;
    FILE_POSITION_INFORMATION fpi;
    LONGLONG new_pos = 0;

    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    if (fd < 0 || fd >= MAX_FDS || g_FdTable[fd].type == FD_TYPE_NONE) {
        errno = EBADF;
        return -1;
    }
    if (g_FdTable[fd].type != FD_TYPE_FILE) {
        errno = ESPIPE;
        return -1;
    }

    if (whence == SEEK_SET) {
        new_pos = offset;
    } else if (whence == SEEK_CUR) {
        new_pos = g_FdTable[fd].offset + offset;
    } else if (whence == SEEK_END) {
        if (!NT_SUCCESS(NtQueryInformationFile(g_FdTable[fd].handle, &iosb, &fsi, sizeof(fsi), FileStandardInformation))) {
            errno = EIO;
            return -1;
        }
        new_pos = fsi.EndOfFile.QuadPart + offset;
    } else {
        errno = EINVAL;
        return -1;
    }

    if (new_pos < 0) {
        errno = EINVAL;
        return -1;
    }
    g_FdTable[fd].offset = new_pos;
    fpi.CurrentByteOffset.QuadPart = new_pos;
    NtSetInformationFile(g_FdTable[fd].handle, &iosb, &fpi, sizeof(fpi), FilePositionInformation);
    return new_pos;
}

int __cdecl dup(int oldfd) {
    int newfd;
    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    if (oldfd < 0 || oldfd >= MAX_FDS || g_FdTable[oldfd].type == FD_TYPE_NONE) {
        errno = EBADF;
        return -1;
    }
    newfd = AllocFd(0);
    if (newfd < 0) return -1;

    if (g_FdTable[oldfd].handle) {
        HANDLE dup_h = NULL;
        NTSTATUS st = NtDuplicateObject(
            NtCurrentProcess(),
            g_FdTable[oldfd].handle,
            NtCurrentProcess(),
            &dup_h,
            0,
            OBJ_INHERIT,
            DUPLICATE_SAME_ACCESS
        );
        if (!NT_SUCCESS(st)) {
            errno = _ntstatus_to_errno(st);
            return -1;
        }
        g_FdTable[newfd] = g_FdTable[oldfd];
        g_FdTable[newfd].handle = dup_h;
    } else {
        g_FdTable[newfd] = g_FdTable[oldfd];
    }
    return newfd;
}

int __cdecl dup2(int oldfd, int newfd) {
    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    if (oldfd < 0 || oldfd >= MAX_FDS || g_FdTable[oldfd].type == FD_TYPE_NONE ||
        newfd < 0 || newfd >= MAX_FDS) {
        errno = EBADF;
        return -1;
    }
    if (oldfd == newfd) return newfd;
    if (g_FdTable[newfd].type != FD_TYPE_NONE) {
        close(newfd);
    }
    if (g_FdTable[oldfd].handle) {
        HANDLE dup_h = NULL;
        NTSTATUS st = NtDuplicateObject(
            NtCurrentProcess(),
            g_FdTable[oldfd].handle,
            NtCurrentProcess(),
            &dup_h,
            0,
            OBJ_INHERIT,
            DUPLICATE_SAME_ACCESS
        );
        if (!NT_SUCCESS(st)) {
            errno = _ntstatus_to_errno(st);
            return -1;
        }
        g_FdTable[newfd] = g_FdTable[oldfd];
        g_FdTable[newfd].handle = dup_h;
    } else {
        g_FdTable[newfd] = g_FdTable[oldfd];
    }
    return newfd;
}

int __cdecl pipe(int pipefd[2]) {
    WCHAR pipe_name[128];
    char  pipe_name_a[128];
    UNICODE_STRING u_name;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER timeout;
    HANDLE hRead = NULL, hWrite = NULL;
    NTSTATUS st;
    int rfd, wfd, i;

    if (!pipefd) {
        errno = EINVAL;
        return -1;
    }
    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());

    snprintf(pipe_name_a, sizeof(pipe_name_a), "\\Device\\NamedPipe\\ntbox_pipe_%u_%u",
             (unsigned int)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess,
             (unsigned int)g_PipeSeq++);
    for (i = 0; pipe_name_a[i]; i++) {
        pipe_name[i] = (WCHAR)(unsigned char)pipe_name_a[i];
    }
    pipe_name[i] = L'\0';

    RtlInitUnicodeString(&u_name, pipe_name);
    InitializeObjectAttributes(&oa, &u_name, OBJ_CASE_INSENSITIVE | OBJ_INHERIT, NULL, NULL);
    timeout.QuadPart = -50000000i64; /* 5 seconds */

    st = NtCreateNamedPipeFile(
        &hRead,
        GENERIC_READ | SYNCHRONIZE | FILE_WRITE_ATTRIBUTES,
        &oa,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT,
        0, /* FILE_PIPE_BYTE_STREAM_TYPE */
        0, /* FILE_PIPE_BYTE_STREAM_MODE */
        0, /* FILE_PIPE_QUEUE_OPERATION */
        1,
        65536,
        65536,
        &timeout
    );
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }

    st = NtOpenFile(
        &hWrite,
        GENERIC_WRITE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
        &oa,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    );
    if (!NT_SUCCESS(st)) {
        NtClose(hRead);
        errno = _ntstatus_to_errno(st);
        return -1;
    }

    rfd = AllocFd(0);
    if (rfd < 0) {
        NtClose(hRead);
        NtClose(hWrite);
        return -1;
    }
    g_FdTable[rfd].type = FD_TYPE_PIPE;
    g_FdTable[rfd].handle = hRead;
    g_FdTable[rfd].flags = O_RDONLY;
    g_FdTable[rfd].offset = 0;

    wfd = AllocFd(0);
    if (wfd < 0) {
        close(rfd);
        NtClose(hWrite);
        return -1;
    }
    g_FdTable[wfd].type = FD_TYPE_PIPE;
    g_FdTable[wfd].handle = hWrite;
    g_FdTable[wfd].flags = O_WRONLY;
    g_FdTable[wfd].offset = 0;

    pipefd[0] = rfd;
    pipefd[1] = wfd;
    return 0;
}

int __cdecl isatty(int fd) {
    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    if (fd >= 0 && fd < MAX_FDS && g_FdTable[fd].type == FD_TYPE_CONSOLE) {
        return 1;
    }
    return 0;
}

int __cdecl fsync(int fd) {
    IO_STATUS_BLOCK iosb;
    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    if (fd < 0 || fd >= MAX_FDS || g_FdTable[fd].type == FD_TYPE_NONE) {
        errno = EBADF;
        return -1;
    }
    if (g_FdTable[fd].handle) {
        NtFlushBuffersFile(g_FdTable[fd].handle, &iosb);
    }
    return 0;
}

int __cdecl ftruncate(int fd, off_t length) {
    IO_STATUS_BLOCK iosb;
    FILE_END_OF_FILE_INFORMATION eof_info;
    NTSTATUS st;

    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    if (fd < 0 || fd >= MAX_FDS || g_FdTable[fd].type != FD_TYPE_FILE) {
        errno = EBADF;
        return -1;
    }
    eof_info.EndOfFile.QuadPart = length;
    st = NtSetInformationFile(g_FdTable[fd].handle, &iosb, &eof_info, sizeof(eof_info), FileEndOfFileInformation);
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }
    return 0;
}

int __cdecl fcntl(int fd, int cmd, ...) {
    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    if (fd < 0 || fd >= MAX_FDS || g_FdTable[fd].type == FD_TYPE_NONE) {
        errno = EBADF;
        return -1;
    }
    if (cmd == F_GETFL) return g_FdTable[fd].flags;
    if (cmd == F_DUPFD) return dup(fd);
    return 0;
}

int __cdecl fstat(int fd, struct stat *buf) {
    IO_STATUS_BLOCK iosb;
    FILE_BASIC_INFORMATION fbi;
    FILE_STANDARD_INFORMATION fsi;
    NTSTATUS st;

    if (!buf) {
        errno = EINVAL;
        return -1;
    }
    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    if (fd < 0 || fd >= MAX_FDS || g_FdTable[fd].type == FD_TYPE_NONE) {
        errno = EBADF;
        return -1;
    }
    memset(buf, 0, sizeof(*buf));

    if (g_FdTable[fd].type == FD_TYPE_CONSOLE || g_FdTable[fd].type == FD_TYPE_NULL) {
        buf->st_mode = S_IFCHR | 0666;
        buf->st_nlink = 1;
        return 0;
    }
    if (g_FdTable[fd].type == FD_TYPE_PIPE) {
        buf->st_mode = S_IFIFO | 0600;
        buf->st_nlink = 1;
        return 0;
    }

    st = NtQueryInformationFile(g_FdTable[fd].handle, &iosb, &fbi, sizeof(fbi), FileBasicInformation);
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }
    st = NtQueryInformationFile(g_FdTable[fd].handle, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }

    buf->st_nlink = fsi.NumberOfLinks ? fsi.NumberOfLinks : 1;
    buf->st_size = fsi.EndOfFile.QuadPart;
    buf->st_atime = NtTimeToUnixTime(fbi.LastAccessTime.QuadPart);
    buf->st_mtime = NtTimeToUnixTime(fbi.LastWriteTime.QuadPart);
    buf->st_ctime = NtTimeToUnixTime(fbi.CreationTime.QuadPart);
    if (fsi.Directory || (fbi.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        buf->st_mode = S_IFDIR | 0755;
    } else {
        buf->st_mode = S_IFREG | ((fbi.FileAttributes & FILE_ATTRIBUTE_READONLY) ? 0555 : 0755);
    }
    return 0;
}

int __cdecl stat(const char *path, struct stat *buf) {
    WCHAR nt_path[280];
    UNICODE_STRING u_path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS st;
    int fd, rc;

    nt_console_puts("[stat] path='");
    nt_console_puts(path ? path : "NULL");
    nt_console_puts("'\n");

    if (!path || !buf) {
        errno = EINVAL;
        return -1;
    }
    if (nt_dos_to_nt_path(path, nt_path, 275) < 0) {
        return -1;
    }
    RtlInitUnicodeString(&u_path, nt_path);
    InitializeObjectAttributes(&oa, &u_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = NtOpenFile(
        &hFile,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &oa,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT
    );
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }

    fd = nt_open_osfhandle(hFile, O_RDONLY);
    if (fd < 0) {
        NtClose(hFile);
        return -1;
    }
    rc = fstat(fd, buf);
    close(fd);
    return rc;
}

int __cdecl lstat(const char *path, struct stat *buf) {
    return stat(path, buf);
}

int __cdecl access(const char *pathname, int mode) {
    struct stat st;
    if (stat(pathname, &st) < 0) return -1;
    return 0;
}

int __cdecl mkdir(const char *pathname, mode_t mode) {
    WCHAR nt_path[280];
    UNICODE_STRING u_path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hDir = NULL;
    NTSTATUS st;

    if (!pathname) {
        errno = EINVAL;
        return -1;
    }
    if (nt_dos_to_nt_path(pathname, nt_path, 275) < 0) {
        return -1;
    }
    RtlInitUnicodeString(&u_path, nt_path);
    InitializeObjectAttributes(&oa, &u_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = NtCreateFile(
        &hDir,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_CREATE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }
    NtClose(hDir);
    return 0;
}

int __cdecl chmod(const char *pathname, mode_t mode) {
    WCHAR nt_path[280];
    UNICODE_STRING u_path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    FILE_BASIC_INFORMATION fbi;
    HANDLE hFile = NULL;
    NTSTATUS st;

    if (!pathname) {
        errno = EINVAL;
        return -1;
    }
    if (nt_dos_to_nt_path(pathname, nt_path, 275) < 0) return -1;
    RtlInitUnicodeString(&u_path, nt_path);
    InitializeObjectAttributes(&oa, &u_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = NtOpenFile(
        &hFile,
        FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
        &oa,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }
    if (NT_SUCCESS(NtQueryInformationFile(hFile, &iosb, &fbi, sizeof(fbi), FileBasicInformation))) {
        if (mode & S_IWUSR) {
            fbi.FileAttributes &= ~FILE_ATTRIBUTE_READONLY;
            if (fbi.FileAttributes == 0) fbi.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        } else {
            fbi.FileAttributes |= FILE_ATTRIBUTE_READONLY;
        }
        NtSetInformationFile(hFile, &iosb, &fbi, sizeof(fbi), FileBasicInformation);
    }
    NtClose(hFile);
    return 0;
}

static int DeleteNtPath(const char *pathname, ULONG open_opts) {
    WCHAR nt_path[280];
    UNICODE_STRING u_path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    FILE_BASIC_INFORMATION fbi;
    FILE_DISPOSITION_INFORMATION fdi;
    HANDLE hFile = NULL;
    NTSTATUS st;

    if (!pathname) {
        errno = EINVAL;
        return -1;
    }
    if (nt_dos_to_nt_path(pathname, nt_path, 275) < 0) return -1;
    RtlInitUnicodeString(&u_path, nt_path);
    InitializeObjectAttributes(&oa, &u_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = NtOpenFile(
        &hFile,
        DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
        &oa,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | open_opts
    );
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }

    /* Clear read-only attribute if set */
    if (NT_SUCCESS(NtQueryInformationFile(hFile, &iosb, &fbi, sizeof(fbi), FileBasicInformation))) {
        if (fbi.FileAttributes & FILE_ATTRIBUTE_READONLY) {
            fbi.FileAttributes &= ~FILE_ATTRIBUTE_READONLY;
            if (fbi.FileAttributes == 0) fbi.FileAttributes = FILE_ATTRIBUTE_NORMAL;
            NtSetInformationFile(hFile, &iosb, &fbi, sizeof(fbi), FileBasicInformation);
        }
    }

    fdi.DeleteFile = TRUE;
    st = NtSetInformationFile(hFile, &iosb, &fdi, sizeof(fdi), FileDispositionInformation);
    NtClose(hFile);
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }
    return 0;
}

int __cdecl unlink(const char *pathname) {
    return DeleteNtPath(pathname, FILE_NON_DIRECTORY_FILE);
}

int __cdecl rmdir(const char *pathname) {
    return DeleteNtPath(pathname, FILE_DIRECTORY_FILE);
}

int __cdecl remove(const char *pathname) {
    struct stat st;
    if (stat(pathname, &st) < 0) return -1;
    if (S_ISDIR(st.st_mode)) return rmdir(pathname);
    return unlink(pathname);
}

int __cdecl rename(const char *oldpath, const char *newpath) {
    WCHAR old_nt[280], new_nt[280];
    UNICODE_STRING u_old;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS st;
    unsigned char rename_buf[sizeof(FILE_RENAME_INFORMATION) + 560];
    PFILE_RENAME_INFORMATION fri = (PFILE_RENAME_INFORMATION)rename_buf;
    ULONG new_byte_len;

    if (!oldpath || !newpath) {
        errno = EINVAL;
        return -1;
    }
    if (nt_dos_to_nt_path(oldpath, old_nt, 275) < 0) return -1;
    if (nt_dos_to_nt_path(newpath, new_nt, 275) < 0) return -1;

    RtlInitUnicodeString(&u_old, old_nt);
    InitializeObjectAttributes(&oa, &u_old, OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = NtOpenFile(
        &hFile,
        DELETE | SYNCHRONIZE,
        &oa,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }

    memset(rename_buf, 0, sizeof(rename_buf));
    new_byte_len = (ULONG)(wcslen(new_nt) * sizeof(WCHAR));
    fri->ReplaceIfExists = TRUE;
    fri->RootDirectory = NULL;
    fri->FileNameLength = new_byte_len;
    memcpy(fri->FileName, new_nt, new_byte_len);

    st = NtSetInformationFile(
        hFile,
        &iosb,
        fri,
        sizeof(FILE_RENAME_INFORMATION) + new_byte_len,
        FileRenameInformation
    );
    NtClose(hFile);
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }
    return 0;
}

int __cdecl chdir(const char *path) {
    char resolved[260];
    struct stat st;
    if (!path) {
        errno = EINVAL;
        return -1;
    }
    if (nt_resolve_path(path, resolved, sizeof(resolved)) < 0) {
        return -1;
    }
    if (stat(resolved, &st) < 0) {
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    strncpy(g_CurrentDir, resolved, sizeof(g_CurrentDir) - 1);
    g_CurrentDir[sizeof(g_CurrentDir) - 1] = '\0';
    return 0;
}

char * __cdecl getcwd(char *buf, size_t size) {
    if (!g_FdsInitialized) _libntc_init_fds(NtCurrentPeb());
    if (!buf) {
        return strdup(g_CurrentDir);
    }
    if (size <= strlen(g_CurrentDir)) {
        errno = ERANGE;
        return NULL;
    }
    strcpy(buf, g_CurrentDir);
    return buf;
}

/*----------------------------------------------------------------------------
 * Directory Enumeration (opendir / readdir / rewinddir / closedir)
 *----------------------------------------------------------------------------*/
struct _NTC_DIR {
    HANDLE        hDir;
    BOOLEAN       first_query;
    BOOLEAN       eof;
    unsigned char padding[2];
    __declspec(align(4)) unsigned char buffer[4096];
    ULONG         cur_offset;
    struct dirent current_ent;
};

DIR * __cdecl opendir(const char *name) {
    WCHAR nt_path[280];
    UNICODE_STRING u_path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hDir = NULL;
    NTSTATUS st;
    DIR *dirp;

    nt_console_puts("[opendir] entered name='");
    nt_console_puts(name ? name : "NULL");
    nt_console_puts("'\n");

    if (!name) {
        errno = EINVAL;
        return NULL;
    }
    if (nt_dos_to_nt_path(name, nt_path, 275) < 0) {
        return NULL;
    }
    RtlInitUnicodeString(&u_path, nt_path);
    InitializeObjectAttributes(&oa, &u_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = NtOpenFile(
        &hDir,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &oa,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
    );
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return NULL;
    }

    dirp = (DIR *)calloc(1, sizeof(DIR));
    if (!dirp) {
        NtClose(hDir);
        return NULL;
    }
    dirp->hDir = hDir;
    dirp->first_query = TRUE;
    dirp->eof = FALSE;
    dirp->cur_offset = 0xFFFFFFFFUL;
    return dirp;
}

struct dirent * __cdecl readdir(DIR *dirp) {
    IO_STATUS_BLOCK iosb;
    PFILE_BOTH_DIR_INFORMATION fbdi;
    ULONG name_chars, i;

    nt_console_puts("[readdir] entered\n");

    if (!dirp || dirp->eof) {
        nt_console_puts("[readdir] returning NULL (eof)\n");
        return NULL;
    }

    if (dirp->cur_offset == 0xFFFFFFFFUL) {
        NTSTATUS st;
        nt_console_puts("[readdir] calling NtQueryDirectoryFile...\n");
        st = NtQueryDirectoryFile(
            dirp->hDir,
            NULL,
            NULL,
            NULL,
            &iosb,
            dirp->buffer,
            sizeof(dirp->buffer),
            FileBothDirectoryInformation,
            FALSE,
            NULL,
            dirp->first_query
        );
        dirp->first_query = FALSE;
        if (!NT_SUCCESS(st) || iosb.Information == 0) {
            dirp->eof = TRUE;
            return NULL;
        }
        dirp->cur_offset = 0;
    }

    fbdi = (PFILE_BOTH_DIR_INFORMATION)(dirp->buffer + dirp->cur_offset);
    if (fbdi->NextEntryOffset != 0) {
        dirp->cur_offset += fbdi->NextEntryOffset;
    } else {
        dirp->cur_offset = 0xFFFFFFFFUL;
    }

    memset(&dirp->current_ent, 0, sizeof(dirp->current_ent));
    dirp->current_ent.d_ino = fbdi->FileIndex;
    dirp->current_ent.d_attributes = fbdi->FileAttributes;
    dirp->current_ent.d_size = (unsigned __int64)fbdi->EndOfFile.QuadPart;
    dirp->current_ent.d_mtime = (__int64)NtTimeToUnixTime(fbdi->LastWriteTime.QuadPart);
    dirp->current_ent.d_type = (fbdi->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? DT_DIR : DT_REG;

    name_chars = fbdi->FileNameLength / sizeof(WCHAR);
    if (name_chars >= sizeof(dirp->current_ent.d_name)) {
        name_chars = sizeof(dirp->current_ent.d_name) - 1;
    }
    for (i = 0; i < name_chars; i++) {
        WCHAR wc = fbdi->FileName[i];
        dirp->current_ent.d_name[i] = (wc < 0x100) ? (char)wc : '?';
    }
    dirp->current_ent.d_name[name_chars] = '\0';

    return &dirp->current_ent;
}

void __cdecl rewinddir(DIR *dirp) {
    if (!dirp) return;
    dirp->first_query = TRUE;
    dirp->eof = FALSE;
    dirp->cur_offset = 0xFFFFFFFFUL;
}

int __cdecl closedir(DIR *dirp) {
    if (!dirp) {
        errno = EBADF;
        return -1;
    }
    if (dirp->hDir) {
        NtClose(dirp->hDir);
    }
    free(dirp);
    return 0;
}
