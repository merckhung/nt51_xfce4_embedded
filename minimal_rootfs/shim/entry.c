/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * minimal_rootfs/shim/entry.c
 * Linux ELF32 Entry Point on Windows XP Kernel
 * Bridges LdrExecuteElfImage to MUSL libc 1.2.5 and BusyBox 1.36.1
 */

#include <stddef.h>

extern void shim_debug_print(const char *msg);
extern void __init_libc(char **envp, char *pn);
extern void __libc_start_init(void);
extern int main(int argc, char **argv, char **envp);
extern void exit(int status);

static char *g_default_env[] = {
    "PATH=/bin:/usr/bin:/sbin:/usr/sbin",
    "HOME=/root",
    "TERM=vt100",
    "USER=root",
    "SHELL=/bin/sh",
    "PWD=/",
    NULL
};

static size_t g_random_bytes[4] = { 0x12345678, 0x9abcdef0, 0x0fedcba9, 0x87654321 };

#define MAX_ENV_AND_AUXV 256
static void *g_env_aux_buf[MAX_ENV_AND_AUXV];

int _start(int argc, char **argv, char **envp) {
    int pos = 0;
    int i;
    char *progname = "busybox";

    shim_debug_print("[entry] _start entered!\n");

    if (argv && argc > 0 && argv[0]) {
        /* Strip path prefix if present e.g. "C:\bin\busybox" -> "busybox" */
        char *p1 = 0;
        char *p2 = 0;
        char *s;
        for (s = argv[0]; *s; s++) {
            if (*s == '/') p1 = s + 1;
            else if (*s == '\\') p2 = s + 1;
        }
        char *p = p1 > p2 ? p1 : p2;
        if (p && *p) {
            argv[0] = p;
        }
        progname = argv[0];
    }

    /* 1. Populate environment variables */
    if (envp && envp[0]) {
        for (i = 0; envp[i] && pos < 100; i++) {
            g_env_aux_buf[pos++] = envp[i];
        }
    } else {
        for (i = 0; g_default_env[i] && pos < 100; i++) {
            g_env_aux_buf[pos++] = g_default_env[i];
        }
    }
    g_env_aux_buf[pos++] = NULL; /* End of envp */

    /* 2. Populate auxv immediately following envp NULL */
    g_env_aux_buf[pos++] = (void *)6;  /* AT_PAGESZ */
    g_env_aux_buf[pos++] = (void *)4096;
    g_env_aux_buf[pos++] = (void *)17; /* AT_CLKTCK */
    g_env_aux_buf[pos++] = (void *)100;
    g_env_aux_buf[pos++] = (void *)25; /* AT_RANDOM */
    g_env_aux_buf[pos++] = (void *)g_random_bytes;
    g_env_aux_buf[pos++] = (void *)31; /* AT_EXECFN */
    g_env_aux_buf[pos++] = (void *)progname;
    g_env_aux_buf[pos++] = (void *)23; /* AT_SECURE */
    g_env_aux_buf[pos++] = (void *)0;
    g_env_aux_buf[pos++] = (void *)11; /* AT_UID */
    g_env_aux_buf[pos++] = (void *)0;
    g_env_aux_buf[pos++] = (void *)12; /* AT_EUID */
    g_env_aux_buf[pos++] = (void *)0;
    g_env_aux_buf[pos++] = (void *)13; /* AT_GID */
    g_env_aux_buf[pos++] = (void *)0;
    g_env_aux_buf[pos++] = (void *)14; /* AT_EGID */
    g_env_aux_buf[pos++] = (void *)0;
    g_env_aux_buf[pos++] = (void *)0;  /* AT_NULL */
    g_env_aux_buf[pos++] = (void *)0;

    shim_debug_print("[entry] calling __init_libc...\n");
    __init_libc((char **)g_env_aux_buf, progname);
    shim_debug_print("[entry] __init_libc finished!\n");

    shim_debug_print("[entry] calling __libc_start_init...\n");
    __libc_start_init();
    shim_debug_print("[entry] __libc_start_init finished!\n");

    shim_debug_print("[entry] calling main...\n");
    int rc = main(argc, argv, (char **)g_env_aux_buf);

    shim_debug_print("[entry] main finished, calling exit...\n");
    exit(rc);
    return 0;
}
