/* SPDX-License-Identifier: GPL-2.0-only */
#include "test_framework.h"
#include <stdio.h>
#include <string.h>

extern void run_ob_tests(void);
extern void run_mm_tests(void);
extern void run_ke_ex_tests(void);
extern void run_ps_tests(void);
extern void run_lpc_tests(void);
extern void run_io_tests(void);
extern void run_se_tests(void);
extern void run_cm_tests(void);
extern void run_sys_tests(void);

static void print_usage(const char *prog) {
    printf("Windows XP (NT 5.1 x86) Kernel Subsystem Test Suite (nttest)\n");
    printf("Usage: %s [all | <subsystem>]\n\n", prog);
    printf("Subsystems:\n");
    printf("  all   - Run all 9 NT kernel subsystem test suites\n");
    printf("  ob    - Object Manager (directories, symlinks, handles, namespace)\n");
    printf("  mm    - Memory Manager (virtual memory, page protection, sections, views)\n");
    printf("  ke    - Executive & Synchronization (events, mutants, semaphores, timers, waits)\n");
    printf("  ps    - Process & Thread Manager (process/thread info, memory ops, scheduling)\n");
    printf("  lpc   - Local Procedure Calls (connection ports, message queues)\n");
    printf("  io    - I/O Manager & Filesystem (files, volumes, completion ports, deletion)\n");
    printf("  se    - Security Reference Monitor (access tokens, SIDs, groups, privileges)\n");
    printf("  cm    - Configuration Manager (registry keys, DWORD/SZ values, enumeration)\n");
    printf("  sys   - System Information & Timers (system time, resolution, counters, stats)\n");
}

int nttest_main(int argc, char **argv) {
    test_framework_init();

    const char *target = "all";
    if (argc > 1) {
        target = argv[1];
    }

    if (strcmp(target, "--help") == 0 || strcmp(target, "-h") == 0 || strcmp(target, "help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    printf("============================================================\n");
    printf("  WINDOWS XP KERNEL USERSPACE TEST SUITE (NTTEST)\n");
    printf("  Testing NT OS Kernel (NT 5.1.2600 x86) System Calls\n");
    printf("============================================================\n");

    int run_all = (strcmp(target, "all") == 0);
    int matched = 0;

    if (run_all || strcmp(target, "ob") == 0) {
        run_ob_tests();
        matched = 1;
    }
    if (run_all || strcmp(target, "mm") == 0) {
        run_mm_tests();
        matched = 1;
    }
    if (run_all || strcmp(target, "ke") == 0 || strcmp(target, "ex") == 0) {
        run_ke_ex_tests();
        matched = 1;
    }
    if (run_all || strcmp(target, "ps") == 0) {
        run_ps_tests();
        matched = 1;
    }
    if (run_all || strcmp(target, "lpc") == 0) {
        run_lpc_tests();
        matched = 1;
    }
    if (run_all || strcmp(target, "io") == 0) {
        run_io_tests();
        matched = 1;
    }
    if (run_all || strcmp(target, "se") == 0) {
        run_se_tests();
        matched = 1;
    }
    if (run_all || strcmp(target, "cm") == 0) {
        run_cm_tests();
        matched = 1;
    }
    if (run_all || strcmp(target, "sys") == 0) {
        run_sys_tests();
        matched = 1;
    }

    if (!matched) {
        printf("Unknown subsystem: '%s'\n\n", target);
        print_usage(argv[0]);
        return 1;
    }

    test_print_summary();

    return (g_test_stats.tests_failed == 0 && g_test_stats.tests_run > 0) ? 0 : 1;
}

#ifndef LIBNTSHIM_BUILD
int main(int argc, char **argv) {
    return nttest_main(argc, argv);
}
#endif
