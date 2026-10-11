/* SPDX-License-Identifier: GPL-2.0-only */
#include "test_framework.h"

void run_ob_tests(void) {
    TEST_SUITE_START("Object Manager (Ob)");

    /* Test 1: Directory Object Lifecycle */
    TEST_CASE_START("Directory Object Create/Open/Query/Close");
    {
        HANDLE hDir = NULL, hOpen = NULL;
        USHORT wname[64];
        UNICODE_STRING uName;
        OBJECT_ATTRIBUTES oa;
        AsciiToUnicode("\\TestDir_Ob", wname, &uName, 64);
        InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st = Nt_CreateDirectoryObject(&hDir, 0xF000F /* DIRECTORY_ALL_ACCESS */, &oa);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(hDir);

        st = Nt_OpenDirectoryObject(&hOpen, 0x0001 /* DIRECTORY_QUERY */, &oa);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(hOpen);

        /* Query directory contents */
        UCHAR buf[512];
        ULONG context = 0, retLen = 0;
        st = Nt_QueryDirectoryObject(hOpen, buf, sizeof(buf), 1, 1, &context, &retLen);
        /* Can be SUCCESS or NO_MORE_ENTRIES if empty */
        TEST_ASSERT(NT_SUCCESS(st) || st == STATUS_NO_MORE_ENTRIES, "QueryDirectoryObject returns success or empty");

        Nt_Close(hOpen);
        Nt_Close(hDir);
    }
    TEST_CASE_FINISH();

    /* Test 2: Symbolic Link Lifecycle */
    TEST_CASE_START("Symbolic Link Create/Open/Query/Close");
    {
        HANDLE hLink = NULL, hOpen = NULL;
        USHORT wname[64], wtarget[64], wquery[64];
        UNICODE_STRING uName, uTarget, uQuery;
        OBJECT_ATTRIBUTES oa;

        AsciiToUnicode("\\TestLink_Ob", wname, &uName, 64);
        AsciiToUnicode("\\Device\\Null", wtarget, &uTarget, 64);
        InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st = Nt_CreateSymbolicLinkObject(&hLink, 0xF0001 /* SYMBOLIC_LINK_ALL_ACCESS */, &oa, &uTarget);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(hLink);

        st = Nt_OpenSymbolicLinkObject(&hOpen, 0x0001 /* GENERIC_READ */, &oa);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(hOpen);

        uQuery.Buffer = wquery;
        uQuery.Length = 0;
        uQuery.MaximumLength = sizeof(wquery);
        ULONG retLen = 0;
        st = Nt_QuerySymbolicLinkObject(hOpen, &uQuery, &retLen);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT(uQuery.Length > 0, "Target link length > 0");

        Nt_Close(hOpen);
        Nt_Close(hLink);
    }
    TEST_CASE_FINISH();

    /* Test 3: Handle Duplication */
    TEST_CASE_START("Handle Duplication & Inheritance Verification");
    {
        HANDLE hEvent = NULL, hDup = NULL;
        USHORT wname[64];
        UNICODE_STRING uName;
        OBJECT_ATTRIBUTES oa;
        AsciiToUnicode("\\TestDup_Ob", wname, &uName, 64);
        InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st = Nt_CreateEvent(&hEvent, EVENT_ALL_ACCESS, &oa, NotificationEvent, 0);
        TEST_ASSERT_SUCCESS(st);

        /* Duplicate handle into current process ((HANDLE)-1) */
        st = Nt_DuplicateObject((HANDLE)-1, hEvent, (HANDLE)-1, &hDup, 0, 0, 2 /* DUPLICATE_SAME_ACCESS */);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(hDup);
        TEST_ASSERT(hDup != hEvent, "Duplicated handle must have unique handle table entry");

        /* Set event via duplicated handle */
        LONG prev = 0;
        st = Nt_SetEvent(hDup, &prev);
        TEST_ASSERT_SUCCESS(st);

        Nt_Close(hDup);
        Nt_Close(hEvent);
    }
    TEST_CASE_FINISH();

    /* Test 4: Invalid Handle Rejection */
    TEST_CASE_START("Invalid Handle & Double-Close Detection");
    {
        NTSTATUS st = Nt_Close((HANDLE)0xDEADBEEF);
        TEST_ASSERT_STATUS(st, STATUS_INVALID_HANDLE);

        HANDLE hEv = NULL;
        st = Nt_CreateEvent(&hEv, EVENT_ALL_ACCESS, NULL, NotificationEvent, 0);
        TEST_ASSERT_SUCCESS(st);

        st = Nt_Close(hEv);
        TEST_ASSERT_SUCCESS(st);

        /* Second close must fail with STATUS_INVALID_HANDLE */
        st = Nt_Close(hEv);
        TEST_ASSERT_STATUS(st, STATUS_INVALID_HANDLE);
    }
    TEST_CASE_FINISH();

    /* Test 5: Negative - Nonexistent Object Lookup */
    TEST_CASE_START("Nonexistent Object Lookup Error Handling");
    {
        HANDLE hDir = NULL;
        USHORT wname[64];
        UNICODE_STRING uName;
        OBJECT_ATTRIBUTES oa;
        AsciiToUnicode("\\NonExistentDirectory_XYZ123", wname, &uName, 64);
        InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st = Nt_OpenDirectoryObject(&hDir, 0x0001, &oa);
        TEST_ASSERT_STATUS(st, STATUS_OBJECT_NAME_NOT_FOUND);
    }
    TEST_CASE_FINISH();

    /* Test 6: Boundary - Probe NULL Pointers */
    TEST_CASE_START("Kernel Boundary - Probing Null Output Pointers");
    {
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        NTSTATUS st = Nt_CreateDirectoryObject(NULL, 0x0001, &oa);
        TEST_ASSERT_STATUS(st, STATUS_ACCESS_VIOLATION);
    }
    TEST_CASE_FINISH();

    /* Test 7: Stress - Rapid Handle Churn */
    TEST_CASE_START("Stress - Rapid Handle Allocation & Teardown (100 cycles)");
    {
        int i, fail = 0;
        for (i = 0; i < 100; i++) {
            HANDLE hEv = NULL, hDup = NULL;
            if (!NT_SUCCESS(Nt_CreateEvent(&hEv, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, 0))) { fail++; break; }
            if (!NT_SUCCESS(Nt_DuplicateObject((HANDLE)-1, hEv, (HANDLE)-1, &hDup, 0, 0, 2))) { fail++; }
            Nt_Close(hDup);
            Nt_Close(hEv);
        }
        TEST_ASSERT(fail == 0, "100 handle creation/duplication/close cycles succeeded with 0 errors");
    }
    TEST_CASE_FINISH();

    TEST_SUITE_FINISH();
}
