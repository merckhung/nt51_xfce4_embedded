/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * native/libntc/crt0.c
 * Native NT Process Startup (NtProcessStartup), Command-Line Parser & Exit Handling
 */

#include "../include/ntnative.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

extern void __cdecl _libntc_init_fds(PPEB peb);
extern void __cdecl _libntc_init_env(PPEB peb);
extern void __cdecl _libntc_run_cxx_ctors(void);
extern void __cdecl _libntc_run_cxx_dtors(void);
extern int  __cdecl main(int argc, char **argv, char **envp);

#define MAX_ATEXIT_FUNCS 32
#define MAX_CMDLINE_ARGS 128

static void (__cdecl *g_AtexitFuncs[MAX_ATEXIT_FUNCS])(void);
static int g_AtexitCount = 0;

int __cdecl atexit(void (__cdecl *func)(void)) {
    if (!func || g_AtexitCount >= MAX_ATEXIT_FUNCS) {
        return -1;
    }
    g_AtexitFuncs[g_AtexitCount++] = func;
    return 0;
}

void __cdecl _exit(int status) {
    NtTerminateProcess(NtCurrentProcess(), (NTSTATUS)status);
    for (;;) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000000i64;
        NtDelayExecution(FALSE, &delay);
    }
}

void __cdecl exit(int status) {
    while (g_AtexitCount > 0) {
        void (__cdecl *fn)(void) = g_AtexitFuncs[--g_AtexitCount];
        if (fn) fn();
    }
    _libntc_run_cxx_dtors();
    fflush(stdout);
    fflush(stderr);
    _exit(status);
}

void __cdecl abort(void) {
    _exit(134);
}

static int ParseCommandLine(const char *cmdline, char *buf, char **argv, int max_args) {
    int argc = 0;
    const char *s = cmdline;
    char *d = buf;

    if (!s) return 0;
    while (*s && argc < max_args - 1) {
        while (isspace((unsigned char)*s)) s++;
        if (!*s) break;

        argv[argc++] = d;
        if (*s == '"' || *s == '\'') {
            char quote = *s++;
            while (*s && *s != quote) {
                if (*s == '\\' && s[1] == quote) {
                    s++;
                }
                *d++ = *s++;
            }
            if (*s == quote) s++;
        } else {
            while (*s && !isspace((unsigned char)*s)) {
                if (*s == '"') {
                    s++;
                    while (*s && *s != '"') {
                        *d++ = *s++;
                    }
                    if (*s == '"') s++;
                } else {
                    *d++ = *s++;
                }
            }
        }
        *d++ = '\0';
    }
    argv[argc] = NULL;
    return argc;
}

VOID NTAPI NtProcessStartup(PPEB Peb) {
    UNICODE_STRING u_dbg;
    char cmdline_raw[1024];
    char cmdline_parsed[1024];
    char *argv[MAX_CMDLINE_ARGS];
    int argc = 0;
    int ret;

    RtlInitUnicodeString(&u_dbg, L"\r\n[CRT0] In NtProcessStartup!\r\n");
    NtDisplayString(&u_dbg);

    if (!Peb) {
        Peb = NtCurrentPeb();
    }
    if (Peb && Peb->ProcessParameters) {
        RtlNormalizeProcessParams(Peb->ProcessParameters);
    }

    RtlGetProcessHeap();
    _libntc_init_fds(Peb);
    _libntc_init_env(Peb);

    cmdline_raw[0] = '\0';
    if (Peb && Peb->ProcessParameters &&
        Peb->ProcessParameters->CommandLine.Buffer &&
        Peb->ProcessParameters->CommandLine.Length > 0) {
        USHORT chars = Peb->ProcessParameters->CommandLine.Length / sizeof(WCHAR);
        USHORT i;
        if (chars >= sizeof(cmdline_raw)) {
            chars = sizeof(cmdline_raw) - 1;
        }
        for (i = 0; i < chars; i++) {
            WCHAR wc = Peb->ProcessParameters->CommandLine.Buffer[i];
            cmdline_raw[i] = (wc < 0x100) ? (char)wc : '?';
        }
        cmdline_raw[chars] = '\0';
    } else if (Peb && Peb->ProcessParameters &&
               Peb->ProcessParameters->ImagePathName.Buffer &&
               Peb->ProcessParameters->ImagePathName.Length > 0) {
        USHORT chars = Peb->ProcessParameters->ImagePathName.Length / sizeof(WCHAR);
        USHORT i;
        if (chars >= sizeof(cmdline_raw)) {
            chars = sizeof(cmdline_raw) - 1;
        }
        for (i = 0; i < chars; i++) {
            WCHAR wc = Peb->ProcessParameters->ImagePathName.Buffer[i];
            cmdline_raw[i] = (wc < 0x100) ? (char)wc : '?';
        }
        cmdline_raw[chars] = '\0';
    }

    argc = ParseCommandLine(cmdline_raw, cmdline_parsed, argv, MAX_CMDLINE_ARGS);
    if (argc == 0) {
        argv[0] = "smss.exe";
        argv[1] = NULL;
        argc = 1;
    }

    _libntc_run_cxx_ctors();
    ret = main(argc, argv, environ);
    exit(ret);
}
