/* SPDX-License-Identifier: GPL-2.0-only */
#include "test_framework.h"
#include <stdio.h>

TEST_STATS g_test_stats;
static int s_case_has_failure = 0;

void test_framework_init(void) {
    memset(&g_test_stats, 0, sizeof(g_test_stats));
}

void test_suite_begin(const char *name) {
    g_test_stats.current_suite_name = name;
    g_test_stats.current_suite_tests = 0;
    g_test_stats.current_suite_passed = 0;
    g_test_stats.current_suite_failed = 0;
    printf("\n=== [SUITE] %s ===\n", name);
}

void test_suite_end(void) {
    g_test_stats.suites_run++;
    if (g_test_stats.current_suite_failed == 0) {
        g_test_stats.suites_passed++;
        printf("--- [SUITE PASS] %s (%d/%d tests passed) ---\n",
               g_test_stats.current_suite_name,
               g_test_stats.current_suite_passed,
               g_test_stats.current_suite_tests);
    } else {
        g_test_stats.suites_failed++;
        printf("--- [SUITE FAIL] %s (%d failed, %d passed) ---\n",
               g_test_stats.current_suite_name,
               g_test_stats.current_suite_failed,
               g_test_stats.current_suite_passed);
    }
}

void test_case_begin(const char *name) {
    g_test_stats.current_test_name = name;
    s_case_has_failure = 0;
    g_test_stats.tests_run++;
    g_test_stats.current_suite_tests++;
    printf("  [TEST] %s ... ", name);
    fflush(stdout);
}

void test_case_end(void) {
    if (s_case_has_failure == 0) {
        g_test_stats.tests_passed++;
        g_test_stats.current_suite_passed++;
        printf("PASS\n");
    } else {
        g_test_stats.tests_failed++;
        g_test_stats.current_suite_failed++;
        printf("FAIL\n");
    }
}

void test_record_assertion(int passed, const char *expr, const char *file, int line, const char *details) {
    if (!passed) {
        s_case_has_failure = 1;
        printf("\n    FAILED: %s at %s:%d (%s)\n  ", expr, file, line, details ? details : "");
    }
}

void test_print_summary(void) {
    printf("\n============================================================\n");
    printf("              NT OS KERNEL TEST SUITE SUMMARY\n");
    printf("============================================================\n");
    printf("  Subsystem Suites: %d total | %d passed | %d failed\n",
           g_test_stats.suites_run, g_test_stats.suites_passed, g_test_stats.suites_failed);
    printf("  Individual Tests: %d total | %d passed | %d failed\n",
           g_test_stats.tests_run, g_test_stats.tests_passed, g_test_stats.tests_failed);
    printf("------------------------------------------------------------\n");
    if (g_test_stats.tests_failed == 0 && g_test_stats.tests_run > 0) {
        printf("  VERDICT: ALL EXECUTED NT TESTS PASSED\n");
    } else {
        printf("  VERDICT: TEST SUITE FAILED (%d test failures detected)\n", g_test_stats.tests_failed);
    }
    printf("============================================================\n\n");
}
