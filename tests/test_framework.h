/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "nt_syscall_defs.h"

typedef struct _TEST_STATS {
    int suites_run;
    int suites_passed;
    int suites_failed;
    int tests_run;
    int tests_passed;
    int tests_failed;
    int current_suite_tests;
    int current_suite_passed;
    int current_suite_failed;
    const char *current_suite_name;
    const char *current_test_name;
} TEST_STATS;

extern TEST_STATS g_test_stats;

void test_framework_init(void);
void test_suite_begin(const char *name);
void test_suite_end(void);
void test_case_begin(const char *name);
void test_case_end(void);
void test_record_assertion(int passed, const char *expr, const char *file, int line, const char *details);
void test_print_summary(void);

#define TEST_SUITE_START(name) test_suite_begin(name)
#define TEST_SUITE_FINISH()    test_suite_end()
#define TEST_CASE_START(name)  test_case_begin(name)
#define TEST_CASE_FINISH()     test_case_end()

#define TEST_ASSERT(cond, msg) \
    do { \
        int _pass = (cond) ? 1 : 0; \
        test_record_assertion(_pass, #cond, __FILE__, __LINE__, msg); \
    } while (0)

#define TEST_ASSERT_STATUS(actual, expected) \
    do { \
        NTSTATUS _act = (actual); \
        NTSTATUS _exp = (expected); \
        char _msg[64]; \
        snprintf(_msg, sizeof(_msg), "exp=0x%08X act=0x%08X", (unsigned int)_exp, (unsigned int)_act); \
        test_record_assertion((_act == _exp), #actual " == " #expected, __FILE__, __LINE__, _msg); \
    } while (0)

#define TEST_ASSERT_SUCCESS(actual) \
    do { \
        NTSTATUS _act = (actual); \
        char _msg[64]; \
        snprintf(_msg, sizeof(_msg), "status=0x%08X", (unsigned int)_act); \
        test_record_assertion(NT_SUCCESS(_act), "NT_SUCCESS(" #actual ")", __FILE__, __LINE__, _msg); \
    } while (0)

#define TEST_ASSERT_EQUAL(actual, expected) \
    do { \
        uint32_t _act = (uint32_t)(actual); \
        uint32_t _exp = (uint32_t)(expected); \
        char _msg[64]; \
        snprintf(_msg, sizeof(_msg), "exp=%u act=%u", (unsigned int)_exp, (unsigned int)_act); \
        test_record_assertion((_act == _exp), #actual " == " #expected, __FILE__, __LINE__, _msg); \
    } while (0)

#define TEST_ASSERT_NOT_NULL(ptr) \
    do { \
        test_record_assertion(((ptr) != NULL), #ptr " != NULL", __FILE__, __LINE__, ""); \
    } while (0)

#define TEST_ASSERT_NULL(ptr) \
    do { \
        test_record_assertion(((ptr) == NULL), #ptr " == NULL", __FILE__, __LINE__, ""); \
    } while (0)

#endif /* TEST_FRAMEWORK_H */
