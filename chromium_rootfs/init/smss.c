/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rootfs/init/smss.c
 * Native NT Session Manager (smss.exe) / PID 1 Init Process & ELF Host
 * Windows XP Embedded (NT 5.1 x86) + MUSL + Linux BusyBox 1.36.1
 */

#include "ntnative.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern void  __cdecl nt_console_init(void);
extern void  __cdecl nt_console_write(const char *buf, size_t len);
extern void  __cdecl nt_console_puts(const char *s);
extern int   __cdecl nt_console_getc(int nonblocking);
extern pid_t __cdecl nt_spawnve(const char *path, char *const argv[], char *const envp[],
                                int stdin_fd, int stdout_fd, int stderr_fd, int background);

void __cdecl _exit(int status) {
    NtTerminateProcess(NtCurrentProcess(), (NTSTATUS)status);
    for (;;) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000000i64;
        NtDelayExecution(FALSE, &delay);
    }
}

void __cdecl exit(int status) {
    _exit(status);
}


static void MountExtraDrives(void) {
    UNICODE_STRING u_d, u_part, u_hd;
    OBJECT_ATTRIBUTES oa;
    HANDLE hLink = NULL, hFile = NULL;
    IO_STATUS_BLOCK iosb;

    RtlInitUnicodeString(&u_d, L"\\??\\D:");
    InitializeObjectAttributes(&oa, &u_d, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NT_SUCCESS(NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &oa))) {
        NtClose(hLink);
        return;
    }

    RtlInitUnicodeString(&u_part, L"\\Device\\Harddisk0\\Partition1");
    InitializeObjectAttributes(&oa, &u_part, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NT_SUCCESS(NtOpenFile(&hFile, SYNCHRONIZE, &oa, &iosb,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT))) {
        NtClose(hFile);
        InitializeObjectAttributes(&oa, &u_d, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL);
        if (NT_SUCCESS(NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &u_part))) {
            NtMakePermanentObject(hLink);
            NtClose(hLink);
        }
    } else {
        RtlInitUnicodeString(&u_hd, L"\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)");
        InitializeObjectAttributes(&oa, &u_hd, OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (NT_SUCCESS(NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &oa))) {
            NtClose(hLink);
            InitializeObjectAttributes(&oa, &u_d, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL);
            if (NT_SUCCESS(NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &u_hd))) {
                NtMakePermanentObject(hLink);
                NtClose(hLink);
            }
        }
    }
}

static void EnsureStandardDirectories(void) {
    mkdir("C:\\bin", 0755);
    mkdir("C:\\etc", 0755);
    mkdir("C:\\tmp", 0755);
    mkdir("C:\\root", 0755);
    mkdir("C:\\var", 0755);
    mkdir("C:\\dev", 0755);
    mkdir("C:\\usr", 0755);
    mkdir("C:\\usr\\bin", 0755);
    mkdir("C:\\usr\\include", 0755);
    mkdir("C:\\usr\\lib", 0755);
}

int RunElfBinary(const char *dos_path, int argc, char **argv, char **envp) {
    WCHAR wPath[260];
    ELF_IMAGE_HANDLE img;
    NTSTATUS status;
    int rc;
    size_t i;

    for (i = 0; dos_path[i] && i < 258; i++) {
        wPath[i] = (WCHAR)(unsigned char)dos_path[i];
    }
    wPath[i] = L'\0';

    memset(&img, 0, sizeof(img));
    status = LdrLoadElfImage(wPath, &img);
    if (!NT_SUCCESS(status)) {
        printf("[init] Failed to load ELF binary '%s' (0x%08X)\n", dos_path, (unsigned int)status);
        return 127;
    }

    printf("[loader] Loaded '%s' entry=%p base=%p, executing...\n", dos_path, img.EntryPoint, img.BaseAddress);
    rc = (int)LdrExecuteElfImage(&img, argc, argv, envp);
    printf("[loader] Returned from ELF image '%s', rc=%d (0x%X)\n", dos_path, rc, (unsigned int)rc);
    LdrUnloadElfImage(&img);
    return rc;
}

void __cdecl NtProcessStartup(PPEB Peb) {
    int argc = 0;
    char *argv[64];
    char cmdline_buf[1024];
    char *prog_name = "smss";
    char *p;
    unsigned int len;
    unsigned int i;
    const char *slash;
    SYSTEM_BASIC_INFORMATION sbi;
    ULONG total_mb = 0;
    LARGE_INTEGER delay;
    int rc;
    char *rc_argv[4];
    char *sh_argv[4];
    pid_t child_pid;
    int child_status = 0;

    if (Peb && Peb->ProcessParameters) {
        UNICODE_STRING *u_cmd = &Peb->ProcessParameters->CommandLine;
        if (u_cmd && u_cmd->Length > 0 && u_cmd->Buffer) {
            len = u_cmd->Length / sizeof(WCHAR);
            if (len >= sizeof(cmdline_buf)) len = sizeof(cmdline_buf) - 1;
            for (i = 0; i < len; i++) {
                cmdline_buf[i] = (char)u_cmd->Buffer[i];
            }
            cmdline_buf[len] = '\0';

            p = cmdline_buf;
            while (*p && argc < 62) {
                while (*p == ' ' || *p == '\t') p++;
                if (!*p) break;
                if (*p == '"') {
                    p++;
                    argv[argc++] = p;
                    while (*p && *p != '"') p++;
                    if (*p == '"') *p++ = '\0';
                } else {
                    argv[argc++] = p;
                    while (*p && *p != ' ' && *p != '\t') p++;
                    if (*p) *p++ = '\0';
                }
            }
            argv[argc] = NULL;
        }
    }

    if (argc > 0 && argv[0]) {
        prog_name = argv[0];
        slash = strrchr(prog_name, '\\');
        if (!slash) slash = strrchr(prog_name, '/');
        if (slash) prog_name = (char *)slash + 1;
    }

    /* Initialize console for both PID 1 and child processes */
    nt_console_init();

    /* 1. If invoked as elfloader: execute target ELF binary */
    if (argc >= 2 && (strcmp(prog_name, "elfloader") == 0 || strcmp(argv[0], "elfloader") == 0 || strcmp(argv[1], "elfloader") == 0)) {
        int target_idx = (strcmp(argv[0], "elfloader") == 0) ? 1 : 2;
        if (target_idx < argc) {
            int sub_argc = argc - target_idx;
            char **sub_argv = argv + target_idx;
            printf("[child] elfloader target='%s', sub_argc=%d\n", sub_argv[0], sub_argc);
            rc = RunElfBinary(sub_argv[0], sub_argc, sub_argv, environ);
            printf("[child] ELF image returned rc=%d\n", rc);
            NtTerminateProcess(NtCurrentProcess(), (NTSTATUS)rc);
            return;
        }
    }

    /* 2. Otherwise, we are PID 1 (smss.exe) at kernel boot! */
    NtInitializeRegistry(0);
    MountExtraDrives();
    EnsureStandardDirectories();
    chdir("C:\\");

    memset(&sbi, 0, sizeof(sbi));
    if (NT_SUCCESS(NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), NULL))) {
        total_mb = (ULONG)(((ULONGLONG)sbi.NumberOfPhysicalPages * (ULONGLONG)sbi.PageSize) / (1024 * 1024));
    }

    printf("\n");
    printf("========================================================================\n");
    printf("  Windows XP Embedded Native Linux Subsystem (NT %u.%u Build 2600 x86)\n",
           (unsigned int)SharedUserData->NtMajorVersion,
           (unsigned int)SharedUserData->NtMinorVersion);
    printf("  Kernel:     ntoskrnl.exe (UP/MP) + Native ELF32 Dynamic Loader\n");
    printf("  Libc:       MUSL Libc 1.2.5 (Direct NT Syscall Translation Layer)\n");
    printf("  Userspace:  Upstream Linux BusyBox 1.36.1 (276 Applets + Hush Shell)\n");
    printf("  Hardware:   CPUs: %u, RAM: %u MB, VGA: bootvid, Input: RawKbd + COM1\n",
           sbi.NumberOfProcessors ? (unsigned int)sbi.NumberOfProcessors : 1,
           (unsigned int)total_mb);
    printf("========================================================================\n\n");

    /* Run /etc/rc.sysinit in child process if present */
    if (access("C:\\etc\\rc.sysinit", 0) == 0) {
        rc_argv[0] = "busybox";
        rc_argv[1] = "sh";
        rc_argv[2] = "/etc/rc.sysinit";
        rc_argv[3] = NULL;
        printf("[init] Executing /etc/rc.sysinit...\n");
        child_pid = nt_spawnve("C:\\bin\\busybox", rc_argv, environ, 0, 1, 2, 0);
        if (child_pid > 0) {
            waitpid(child_pid, &child_status, 0);
        }
    }

    /* Run the actual NT syscall suite; publish its real exit status. */
    {
        char *test_argv[3];
        test_argv[0] = "nttest.elf";
        test_argv[1] = "all";
        test_argv[2] = NULL;
        printf("[init] Running nttest.elf all...\n");
        child_pid = nt_spawnve("C:\\bin\\nttest.elf", test_argv, environ, 0, 1, 2, 0);
        if (child_pid > 0) {
            waitpid(child_pid, &child_status, 0);
            printf("[init] NTTEST_EXIT=%d status=0x%08X\n", WEXITSTATUS(child_status), child_status);
        }
    }

    /* Main supervisory loop: launch interactive BusyBox shell in child process */
    for (;;) {
        sh_argv[0] = "busybox";
        sh_argv[1] = "sh";
        sh_argv[2] = "-l";
        sh_argv[3] = NULL;
        printf("\n[init] Starting interactive BusyBox shell (/bin/sh)...\n");
        child_status = 0;
        child_pid = nt_spawnve("C:\\bin\\busybox", sh_argv, environ, 0, 1, 2, 0);
        if (child_pid > 0) {
            waitpid(child_pid, &child_status, 0);
            printf("\n[init] BusyBox shell PID %d exited: status=0x%08X (WEXITSTATUS=%d). Respawning in 1 second...\n",
                   (int)child_pid, (unsigned int)child_status, WEXITSTATUS(child_status));
        } else {
            printf("[init] Failed to spawn BusyBox shell. Retrying in 1 second...\n");
        }
        delay.QuadPart = -10000000i64; /* 1 second */
        NtDelayExecution(FALSE, &delay);
    }
}
