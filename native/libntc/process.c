/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * native/libntc/process.c
 * Native NT Process Creation (NtCreateProcessEx + NtCreateThread), Wait, Signals & IDs
 */

#include "../include/ntnative.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#define MAX_CHILDREN 64

typedef struct _NTC_CHILD_PROC {
    int    in_use;
    pid_t  pid;
    HANDLE hProcess;
    HANDLE hThread;
    int    exited;
    int    exit_code;
} NTC_CHILD_PROC;

static NTC_CHILD_PROC g_Children[MAX_CHILDREN];
static sighandler_t   g_SigHandlers[32];

pid_t __cdecl getpid(void) {
    return (pid_t)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess;
}

pid_t __cdecl getppid(void) {
    PROCESS_BASIC_INFORMATION pbi;
    if (NT_SUCCESS(NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), NULL))) {
        return (pid_t)pbi.InheritedFromUniqueProcessId;
    }
    return 0;
}

uid_t __cdecl getuid(void)  { return 0; }
uid_t __cdecl geteuid(void) { return 0; }
gid_t __cdecl getgid(void)  { return 0; }
gid_t __cdecl getegid(void) { return 0; }

int __cdecl gethostname(char *name, size_t len) {
    const char *h = getenv("HOSTNAME");
    if (!h || !h[0]) h = "nt-embedded";
    if (!name || len == 0) {
        errno = EINVAL;
        return -1;
    }
    strncpy(name, h, len - 1);
    name[len - 1] = '\0';
    return 0;
}

static int IsElfFile(HANDLE hFile) {
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    unsigned char magic[4] = { 0, 0, 0, 0 };
    offset.QuadPart = 0;
    if (NT_SUCCESS(NtReadFile(hFile, NULL, NULL, NULL, &iosb, magic, 4, &offset, NULL)) &&
        iosb.Information == 4) {
        if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
            return 1;
        }
    }
    return 0;
}

static PVOID CopyEnvToRemoteProcess(HANDLE hProcess, char *const envp[]) {
    char *const *ep = envp ? envp : environ;
    size_t total_wchars = 2;
    int i;
    WCHAR *local_buf, *wp;
    PVOID remote_base = NULL;
    SIZE_T region_size;
    NTSTATUS st;

    if (!ep) return NULL;
    for (i = 0; ep[i]; i++) {
        total_wchars += strlen(ep[i]) + 1;
    }

    local_buf = (WCHAR *)malloc(total_wchars * sizeof(WCHAR));
    if (!local_buf) return NULL;

    wp = local_buf;
    for (i = 0; ep[i]; i++) {
        const char *s = ep[i];
        while (*s) {
            *wp++ = (WCHAR)(unsigned char)*s++;
        }
        *wp++ = L'\0';
    }
    *wp++ = L'\0';

    region_size = (total_wchars * sizeof(WCHAR) + 0xFFF) & ~((SIZE_T)0xFFF);
    st = NtAllocateVirtualMemory(
        hProcess,
        &remote_base,
        0,
        &region_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (NT_SUCCESS(st) && remote_base) {
        NtWriteVirtualMemory(
            hProcess,
            remote_base,
            local_buf,
            total_wchars * sizeof(WCHAR),
            NULL
        );
    }
    free(local_buf);
    return remote_base;
}

static HANDLE DuplicateFdToChild(HANDLE hChildProcess, int fd) {
    HANDLE src_h = (HANDLE)nt_get_osfhnd(fd);
    HANDLE dst_h = NULL;
    if (!src_h) return NULL;
    if (NT_SUCCESS(NtDuplicateObject(
            NtCurrentProcess(),
            src_h,
            hChildProcess,
            &dst_h,
            0,
            OBJ_INHERIT,
            DUPLICATE_SAME_ACCESS))) {
        return dst_h;
    }
    return NULL;
}

pid_t __cdecl nt_spawnve(
    const char *path,
    char *const argv[],
    char *const envp[],
    int stdin_fd,
    int stdout_fd,
    int stderr_fd,
    int background
) {
    char resolved_dos[260];
    WCHAR nt_image_path[280];
    UNICODE_STRING u_image;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    HANDLE hSection = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    SECTION_IMAGE_INFORMATION img_info;
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS st;
    int is_elf = 0;

    if (!path || !argv || !argv[0]) {
        errno = EINVAL;
        return -1;
    }

    if (nt_resolve_path(path, resolved_dos, sizeof(resolved_dos)) < 0) {
        return -1;
    }
    if (nt_dos_to_nt_path(resolved_dos, nt_image_path, 275) < 0) {
        return -1;
    }

    RtlInitUnicodeString(&u_image, nt_image_path);
    InitializeObjectAttributes(&oa, &u_image, OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = NtOpenFile(
        &hFile,
        SYNCHRONIZE | FILE_EXECUTE | FILE_READ_DATA,
        &oa,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    );
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }

    /* Check if target is an ELF32 binary: if so, host it inside smss.exe elfloader */
    if (IsElfFile(hFile)) {
        NtClose(hFile);
        hFile = NULL;
        is_elf = 1;
        wcscpy(nt_image_path, L"\\SystemRoot\\system32\\smss.exe");
        RtlInitUnicodeString(&u_image, nt_image_path);
        InitializeObjectAttributes(&oa, &u_image, OBJ_CASE_INSENSITIVE, NULL, NULL);
        st = NtOpenFile(
            &hFile,
            SYNCHRONIZE | FILE_EXECUTE | FILE_READ_DATA,
            &oa,
            &iosb,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
        );
        if (!NT_SUCCESS(st)) {
            errno = _ntstatus_to_errno(st);
            return -1;
        }
    }

    st = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_EXECUTE,
        SEC_IMAGE,
        hFile
    );
    NtClose(hFile);
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }

    memset(&img_info, 0, sizeof(img_info));
    st = NtQuerySection(
        hSection,
        SectionImageInformation,
        &img_info,
        sizeof(img_info),
        NULL
    );
    if (!NT_SUCCESS(st)) {
        NtClose(hSection);
        errno = _ntstatus_to_errno(st);
        return -1;
    }

    /* Create native NT process */
    st = NtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        NtCurrentProcess(),
        4, /* PS_INHERIT_HANDLES */
        hSection,
        NULL,
        NULL,
        0
    );
    if (!NT_SUCCESS(st)) {
        st = NtCreateProcess(
            &hProcess,
            PROCESS_ALL_ACCESS,
            NULL,
            NtCurrentProcess(),
            TRUE,
            hSection,
            NULL,
            NULL
        );
    }
    NtClose(hSection);
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }

    memset(&pbi, 0, sizeof(pbi));
    st = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        NULL
    );
    if (!NT_SUCCESS(st) || !pbi.PebBaseAddress) {
        NtTerminateProcess(hProcess, STATUS_UNSUCCESSFUL);
        NtClose(hProcess);
        errno = EIO;
        return -1;
    }

    /* Build command line and process parameters for child */
    {
        char cmdline_a[1024];
        WCHAR cmdline_w[1024];
        char cwd_a[260];
        WCHAR cwd_w[260];
        UNICODE_STRING u_cmdline, u_cwd;
        PRTL_USER_PROCESS_PARAMETERS local_params = NULL;
        PVOID remote_params = NULL;
        PVOID remote_env = CopyEnvToRemoteProcess(hProcess, envp);
        SIZE_T params_size;
        int i;

        cmdline_a[0] = '\0';
        if (is_elf) {
            snprintf(cmdline_a, sizeof(cmdline_a), "elfloader \"%s\"", resolved_dos);
            for (i = 1; argv[i]; i++) {
                strncat(cmdline_a, " \"", sizeof(cmdline_a) - strlen(cmdline_a) - 1);
                strncat(cmdline_a, argv[i], sizeof(cmdline_a) - strlen(cmdline_a) - 1);
                strncat(cmdline_a, "\"", sizeof(cmdline_a) - strlen(cmdline_a) - 1);
            }
        } else {
            for (i = 0; argv[i]; i++) {
                if (i > 0) strncat(cmdline_a, " ", sizeof(cmdline_a) - strlen(cmdline_a) - 1);
                if (strchr(argv[i], ' ') || strchr(argv[i], '\t')) {
                    strncat(cmdline_a, "\"", sizeof(cmdline_a) - strlen(cmdline_a) - 1);
                    strncat(cmdline_a, argv[i], sizeof(cmdline_a) - strlen(cmdline_a) - 1);
                    strncat(cmdline_a, "\"", sizeof(cmdline_a) - strlen(cmdline_a) - 1);
                } else {
                    strncat(cmdline_a, argv[i], sizeof(cmdline_a) - strlen(cmdline_a) - 1);
                }
            }
        }

        for (i = 0; cmdline_a[i] && i < 1022; i++) {
            cmdline_w[i] = (WCHAR)(unsigned char)cmdline_a[i];
        }
        cmdline_w[i] = L'\0';
        RtlInitUnicodeString(&u_cmdline, cmdline_w);

        if (!getcwd(cwd_a, sizeof(cwd_a))) {
            strcpy(cwd_a, "C:\\");
        }
        for (i = 0; cwd_a[i] && i < 258; i++) {
            cwd_w[i] = (WCHAR)(unsigned char)cwd_a[i];
        }
        cwd_w[i] = L'\0';
        RtlInitUnicodeString(&u_cwd, cwd_w);

        st = RtlCreateProcessParameters(
            &local_params,
            &u_image,
            NULL,
            &u_cwd,
            &u_cmdline,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        );
        if (!NT_SUCCESS(st) || !local_params) {
            NtTerminateProcess(hProcess, STATUS_UNSUCCESSFUL);
            NtClose(hProcess);
            errno = ENOMEM;
            return -1;
        }

        local_params->Environment = remote_env;
        local_params->StandardInput  = (stdin_fd >= 0)  ? DuplicateFdToChild(hProcess, stdin_fd)  : NULL;
        local_params->StandardOutput = (stdout_fd >= 0) ? DuplicateFdToChild(hProcess, stdout_fd) : NULL;
        local_params->StandardError  = (stderr_fd >= 0) ? DuplicateFdToChild(hProcess, stderr_fd) : NULL;

        params_size = local_params->MaximumLength;
        st = NtAllocateVirtualMemory(
            hProcess,
            &remote_params,
            0,
            &params_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        );
        if (NT_SUCCESS(st) && remote_params) {
            NtWriteVirtualMemory(
                hProcess,
                remote_params,
                local_params,
                local_params->Length,
                NULL
            );
            NtWriteVirtualMemory(
                hProcess,
                &pbi.PebBaseAddress->ProcessParameters,
                &remote_params,
                sizeof(remote_params),
                NULL
            );
        }
        RtlDestroyProcessParameters(local_params);
    }

    /* Allocate stack and create initial thread */
    {
        SIZE_T stack_reserve = img_info.MaximumStackSize ? img_info.MaximumStackSize : (256 * 1024);
        SIZE_T stack_commit  = img_info.CommittedStackSize ? img_info.CommittedStackSize : (64 * 1024);
        PVOID stack_alloc = NULL;
        PVOID commit_addr;
        SIZE_T guard_size = 4096;
        ULONG old_prot = 0;
        INITIAL_TEB init_teb;
        CONTEXT ctx;
        CLIENT_ID cid;
        ULONG param_peb = (ULONG)(ULONG_PTR)pbi.PebBaseAddress;
        ULONG dummy_ret = 0;

        if (stack_reserve < 64 * 1024) stack_reserve = 256 * 1024;
        if (stack_commit < 16 * 1024)  stack_commit = 64 * 1024;
        if (stack_commit >= stack_reserve) stack_reserve = stack_commit + 64 * 1024;

        st = NtAllocateVirtualMemory(
            hProcess,
            &stack_alloc,
            0,
            &stack_reserve,
            MEM_RESERVE,
            PAGE_READWRITE
        );
        if (!NT_SUCCESS(st)) {
            NtTerminateProcess(hProcess, st);
            NtClose(hProcess);
            errno = ENOMEM;
            return -1;
        }

        memset(&init_teb, 0, sizeof(init_teb));
        init_teb.StackAllocationBase = stack_alloc;
        init_teb.StackBase = (PUCHAR)stack_alloc + stack_reserve;
        commit_addr = (PUCHAR)init_teb.StackBase - stack_commit;
        init_teb.StackLimit = commit_addr;

        {
            PVOID commit_region_base = (PUCHAR)commit_addr - guard_size;
            SIZE_T commit_region_size = stack_commit + guard_size;
            st = NtAllocateVirtualMemory(
                hProcess,
                &commit_region_base,
                0,
                &commit_region_size,
                MEM_COMMIT,
                PAGE_READWRITE
            );
            if (!NT_SUCCESS(st)) {
                NtTerminateProcess(hProcess, st);
                NtClose(hProcess);
                errno = ENOMEM;
                return -1;
            }
            NtProtectVirtualMemory(
                hProcess,
                &commit_region_base,
                &guard_size,
                PAGE_READWRITE | PAGE_GUARD,
                &old_prot
            );
        }

        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_FULL;
        ctx.SegGs = 0;
        ctx.SegFs = 0x38; /* KGDT_R3_TEB */
        ctx.SegEs = 0x23; /* KGDT_R3_DATA */
        ctx.SegDs = 0x23;
        ctx.SegSs = 0x23;
        ctx.SegCs = 0x1B; /* KGDT_R3_CODE */
        ctx.EFlags = 0x200;
        ctx.Eip = (ULONG)(ULONG_PTR)img_info.TransferAddress;
        ctx.Esp = (ULONG)(ULONG_PTR)init_teb.StackBase - 8;

        NtWriteVirtualMemory(hProcess, (PVOID)(ULONG_PTR)(ctx.Esp + 4), &param_peb, sizeof(param_peb), NULL);
        NtWriteVirtualMemory(hProcess, (PVOID)(ULONG_PTR)ctx.Esp, &dummy_ret, sizeof(dummy_ret), NULL);

        st = NtCreateThread(
            &hThread,
            THREAD_ALL_ACCESS,
            NULL,
            hProcess,
            &cid,
            &ctx,
            &init_teb,
            FALSE
        );
        if (!NT_SUCCESS(st)) {
            NtTerminateProcess(hProcess, st);
            NtClose(hProcess);
            errno = _ntstatus_to_errno(st);
            return -1;
        }
    }

    /* Record in child process table */
    {
        pid_t child_pid = (pid_t)pbi.UniqueProcessId;
        int i;
        for (i = 0; i < MAX_CHILDREN; i++) {
            if (!g_Children[i].in_use) {
                g_Children[i].in_use = 1;
                g_Children[i].pid = child_pid;
                g_Children[i].hProcess = hProcess;
                g_Children[i].hThread = hThread;
                g_Children[i].exited = 0;
                g_Children[i].exit_code = 0;
                return child_pid;
            }
        }
        /* Table full: wait if foreground, otherwise close handles */
        NtClose(hThread);
        NtClose(hProcess);
        return child_pid;
    }
}

pid_t __cdecl waitpid(pid_t pid, int *status, int options) {
    int i;
    int any_children = 0;

    for (;;) {
        any_children = 0;
        for (i = 0; i < MAX_CHILDREN; i++) {
            if (!g_Children[i].in_use) continue;
            if (pid > 0 && g_Children[i].pid != pid) continue;
            any_children = 1;

            if (!g_Children[i].exited) {
                LARGE_INTEGER zero_wait;
                LARGE_INTEGER *timeout_ptr = NULL;
                NTSTATUS st;

                if (options & WNOHANG) {
                    zero_wait.QuadPart = 0;
                    timeout_ptr = &zero_wait;
                } else if (pid <= 0) {
                    /* Poll across multiple children every 20ms */
                    zero_wait.QuadPart = -200000i64;
                    timeout_ptr = &zero_wait;
                }

                st = NtWaitForSingleObject(g_Children[i].hProcess, FALSE, timeout_ptr);
                if (st == STATUS_WAIT_0) {
                    PROCESS_BASIC_INFORMATION pbi;
                    g_Children[i].exited = 1;
                    if (NT_SUCCESS(NtQueryInformationProcess(
                            g_Children[i].hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL))) {
                        g_Children[i].exit_code = (int)pbi.ExitStatus;
                    }
                }
            }

            if (g_Children[i].exited) {
                pid_t done_pid = g_Children[i].pid;
                int code = g_Children[i].exit_code;
                if (g_Children[i].hThread) NtClose(g_Children[i].hThread);
                if (g_Children[i].hProcess) NtClose(g_Children[i].hProcess);
                g_Children[i].in_use = 0;
                if (status) {
                    *status = (code & 0xFF) << 8;
                }
                return done_pid;
            }
        }

        if (!any_children) {
            errno = ECHILD;
            return -1;
        }
        if (options & WNOHANG) {
            return 0;
        }
    }
}

pid_t __cdecl wait(int *status) {
    return waitpid(-1, status, 0);
}

int __cdecl kill(pid_t pid, int sig) {
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    HANDLE hProc = NULL;
    NTSTATUS st;

    if (pid <= 0) {
        errno = EINVAL;
        return -1;
    }
    if (pid == getpid()) {
        return raise(sig);
    }

    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = NULL;

    st = NtOpenProcess(&hProc, PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME, &oa, &cid);
    if (!NT_SUCCESS(st) || !hProc) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }

    if (sig == 0) {
        NtClose(hProc);
        return 0;
    }
    st = NtTerminateProcess(hProc, (NTSTATUS)(128 + sig));
    NtClose(hProc);
    if (!NT_SUCCESS(st)) {
        errno = _ntstatus_to_errno(st);
        return -1;
    }
    return 0;
}

sighandler_t __cdecl signal(int signum, sighandler_t handler) {
    sighandler_t prev;
    if (signum <= 0 || signum >= 32) {
        errno = EINVAL;
        return SIG_ERR;
    }
    prev = g_SigHandlers[signum];
    g_SigHandlers[signum] = handler;
    return prev;
}

int __cdecl raise(int sig) {
    if (sig <= 0 || sig >= 32) {
        errno = EINVAL;
        return -1;
    }
    if (g_SigHandlers[sig] != SIG_DFL && g_SigHandlers[sig] != SIG_IGN) {
        g_SigHandlers[sig](sig);
        return 0;
    }
    if (sig == SIGABRT || sig == SIGKILL || sig == SIGTERM) {
        _exit(128 + sig);
    }
    return 0;
}

int __cdecl system(const char *command) {
    char *argv[4];
    pid_t pid;
    int status = 0;

    if (!command) return 1;
    argv[0] = "sh";
    argv[1] = "-c";
    argv[2] = (char *)command;
    argv[3] = NULL;

    pid = nt_spawnve("\\SystemRoot\\system32\\smss.exe", argv, environ, 0, 1, 2, 0);
    if (pid < 0) return -1;
    waitpid(pid, &status, 0);
    return WEXITSTATUS(status);
}
