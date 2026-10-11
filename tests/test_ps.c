/* SPDX-License-Identifier: GPL-2.0-only */
#include "test_framework.h"

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG      Priority;
    LONG      BasePriority;
} THREAD_BASIC_INFORMATION;

void run_ps_tests(void) {
    TEST_SUITE_START("Process & Thread Manager (Ps)");

    /* Test 1: Query Current Process Basic Information */
    TEST_CASE_START("Current Process Information Query (ProcessBasicInformation)");
    {
        PROCESS_BASIC_INFORMATION pbi;
        memset(&pbi, 0, sizeof(pbi));
        ULONG retLen = 0;

        NTSTATUS st = Nt_QueryInformationProcess((HANDLE)-1, 0 /* ProcessBasicInformation */, &pbi, sizeof(pbi), &retLen);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_EQUAL(retLen, sizeof(pbi));
        TEST_ASSERT_NOT_NULL(pbi.PebBaseAddress);
        TEST_ASSERT(pbi.UniqueProcessId > 0, "UniqueProcessId must be non-zero");
    }
    TEST_CASE_FINISH();

    /* Test 2: Query Current Thread Basic Information */
    TEST_CASE_START("Current Thread Information Query (ThreadBasicInformation)");
    {
        THREAD_BASIC_INFORMATION tbi;
        memset(&tbi, 0, sizeof(tbi));
        ULONG retLen = 0;

        NTSTATUS st = Nt_QueryInformationThread((HANDLE)-2, 0 /* ThreadBasicInformation */, &tbi, sizeof(tbi), &retLen);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_EQUAL(retLen, sizeof(tbi));
        TEST_ASSERT_NOT_NULL(tbi.TebBaseAddress);
        TEST_ASSERT((uint32_t)tbi.ClientId.UniqueThread > 0, "UniqueThread must be non-zero");
    }
    TEST_CASE_FINISH();

    /* Test 3: Process Virtual Memory Read & Write Syscalls */
    TEST_CASE_START("Inter-Process Memory Read & Write Operations");
    {
        uint32_t source_val = 0x87654321;
        uint32_t dest_val = 0;
        ULONG bytes_written = 0, bytes_read = 0;

        /* Write memory into current process */
        unsigned long a_w[5] = { (unsigned long)(HANDLE)-1, (unsigned long)&dest_val, (unsigned long)&source_val, sizeof(source_val), (unsigned long)&bytes_written };
        NTSTATUS st = (NTSTATUS)DoNtSyscall(277 /* NtWriteVirtualMemory */, a_w, 5);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_EQUAL(bytes_written, sizeof(source_val));
        TEST_ASSERT_EQUAL(dest_val, 0x87654321);

        /* Read memory back from current process */
        uint32_t verify_val = 0;
        unsigned long a_r[5] = { (unsigned long)(HANDLE)-1, (unsigned long)&dest_val, (unsigned long)&verify_val, sizeof(verify_val), (unsigned long)&bytes_read };
        st = (NTSTATUS)DoNtSyscall(186 /* NtReadVirtualMemory */, a_r, 5);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_EQUAL(bytes_read, sizeof(verify_val));
        TEST_ASSERT_EQUAL(verify_val, 0x87654321);
    }
    TEST_CASE_FINISH();

    /* Test 4: Thread Alert & Yield Execution */
    TEST_CASE_START("Thread Alerting & Cooperative Execution Yielding");
    {
        NTSTATUS st = Nt_AlertThread((HANDLE)-2);
        TEST_ASSERT_SUCCESS(st);

        st = Nt_YieldExecution();
        TEST_ASSERT_SUCCESS(st);
    }
    TEST_CASE_FINISH();

    /* Test 5: Negative - Invalid Process Handle & Buffer Undersize */
    TEST_CASE_START("Negative - Invalid Process Handle & Info Length Mismatch");
    {
        PROCESS_BASIC_INFORMATION pbi;
        ULONG retLen = 0;
        NTSTATUS st = Nt_QueryInformationProcess((HANDLE)0xBADF00D, 0, &pbi, sizeof(pbi), &retLen);
        TEST_ASSERT_STATUS(st, STATUS_INVALID_HANDLE);

        /* Undersized buffer for ProcessBasicInformation */
        st = Nt_QueryInformationProcess((HANDLE)-1, 0, &pbi, 4, &retLen);
        TEST_ASSERT_STATUS(st, STATUS_INFO_LENGTH_MISMATCH);
    }
    TEST_CASE_FINISH();

    TEST_SUITE_FINISH();
}
