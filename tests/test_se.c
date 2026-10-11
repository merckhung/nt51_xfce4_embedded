/* SPDX-License-Identifier: GPL-2.0-only */
#include "test_framework.h"

typedef struct _SID_AND_ATTRIBUTES {
    PVOID Sid;
    ULONG Attributes;
} SID_AND_ATTRIBUTES;

typedef struct _TOKEN_USER {
    SID_AND_ATTRIBUTES User;
} TOKEN_USER;

typedef struct _TOKEN_GROUPS {
    ULONG GroupCount;
    SID_AND_ATTRIBUTES Groups[1];
} TOKEN_GROUPS;

typedef struct _LUID {
    ULONG LowPart;
    LONG HighPart;
} LUID;

typedef struct _LUID_AND_ATTRIBUTES {
    LUID  Luid;
    ULONG Attributes;
} LUID_AND_ATTRIBUTES;

typedef struct _TOKEN_PRIVILEGES {
    ULONG PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
} TOKEN_PRIVILEGES;

void run_se_tests(void) {
    TEST_SUITE_START("Security Reference Monitor (Se)");

    /* Test 1: Open Process Access Token */
    TEST_CASE_START("Process Token Acquisition (TOKEN_QUERY)");
    {
        HANDLE hToken = NULL;
        NTSTATUS st = Nt_OpenProcessToken((HANDLE)-1, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(hToken);

        Nt_Close(hToken);
    }
    TEST_CASE_FINISH();

    /* Test 2: Query Token User (User SID) */
    TEST_CASE_START("Token User SID Query (TokenUser)");
    {
        HANDLE hToken = NULL;
        NTSTATUS st = Nt_OpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken);
        TEST_ASSERT_SUCCESS(st);

        UCHAR buf[256];
        ULONG retLen = 0;
        st = Nt_QueryInformationToken(hToken, 1 /* TokenUser */, buf, sizeof(buf), &retLen);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT(retLen >= sizeof(TOKEN_USER), "TokenUser data size verified");

        TOKEN_USER *tu = (TOKEN_USER *)buf;
        TEST_ASSERT_NOT_NULL(tu->User.Sid);

        Nt_Close(hToken);
    }
    TEST_CASE_FINISH();

    /* Test 3: Query Token Groups */
    TEST_CASE_START("Token Membership Groups Query (TokenGroups)");
    {
        HANDLE hToken = NULL;
        Nt_OpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken);

        UCHAR buf[512];
        ULONG retLen = 0;
        NTSTATUS st = Nt_QueryInformationToken(hToken, 2 /* TokenGroups */, buf, sizeof(buf), &retLen);
        TEST_ASSERT_SUCCESS(st);

        TOKEN_GROUPS *tg = (TOKEN_GROUPS *)buf;
        TEST_ASSERT(tg->GroupCount > 0, "Token has at least one group membership");

        Nt_Close(hToken);
    }
    TEST_CASE_FINISH();

    /* Test 4: Query Token Privileges */
    TEST_CASE_START("Token Privileges Query (TokenPrivileges)");
    {
        HANDLE hToken = NULL;
        Nt_OpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken);

        UCHAR buf[512];
        ULONG retLen = 0;
        NTSTATUS st = Nt_QueryInformationToken(hToken, 3 /* TokenPrivileges */, buf, sizeof(buf), &retLen);
        TEST_ASSERT_SUCCESS(st);

        TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)buf;
        TEST_ASSERT(tp->PrivilegeCount > 0, "Token has assigned privileges");

        Nt_Close(hToken);
    }
    TEST_CASE_FINISH();

    /* Test 5: Token Duplication */
    TEST_CASE_START("Access Token Duplication (TokenImpersonation)");
    {
        HANDLE hToken = NULL, hDupToken = NULL;
        Nt_OpenProcessToken((HANDLE)-1, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

        NTSTATUS st = Nt_DuplicateToken(hToken, TOKEN_QUERY, &oa, 0, 2 /* TokenImpersonation */, &hDupToken);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(hDupToken);

        Nt_Close(hDupToken);
        Nt_Close(hToken);
    }
    TEST_CASE_FINISH();

    /* Test 6: Negative - Invalid Token Handle & Class */
    TEST_CASE_START("Negative - Invalid Token Handle & Information Class");
    {
        UCHAR buf[64];
        ULONG retLen = 0;
        NTSTATUS st = Nt_QueryInformationToken((HANDLE)0xBAD70C, 1, buf, sizeof(buf), &retLen);
        TEST_ASSERT_STATUS(st, STATUS_INVALID_HANDLE);

        HANDLE hToken = NULL;
        Nt_OpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken);
        st = Nt_QueryInformationToken(hToken, 999 /* invalid */, buf, sizeof(buf), &retLen);
        TEST_ASSERT(!NT_SUCCESS(st), "Querying invalid token information class must fail");
        Nt_Close(hToken);
    }
    TEST_CASE_FINISH();

    TEST_SUITE_FINISH();
}
