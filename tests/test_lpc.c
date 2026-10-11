/* SPDX-License-Identifier: GPL-2.0-only */
#include "test_framework.h"

void run_lpc_tests(void) {
    TEST_SUITE_START("Local Procedure Call (Lpc)");

    /* Test 1: Connection Port Creation & Teardown */
    TEST_CASE_START("Connection Port Creation & Teardown");
    {
        HANDLE hPort = NULL;
        USHORT wname[64];
        UNICODE_STRING uName;
        OBJECT_ATTRIBUTES oa;
        AsciiToUnicode("\\TestPort_Lpc", wname, &uName, 64);
        InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st = Nt_CreatePort(&hPort, &oa, 64, 128, 0);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(hPort);

        st = Nt_Close(hPort);
        TEST_ASSERT_SUCCESS(st);
    }
    TEST_CASE_FINISH();

    /* Test 2: Waitable Port Creation */
    TEST_CASE_START("Waitable Port Creation & Teardown");
    {
        HANDLE hPort = NULL;
        USHORT wname[64];
        UNICODE_STRING uName;
        OBJECT_ATTRIBUTES oa;
        AsciiToUnicode("\\TestWaitPort_Lpc", wname, &uName, 64);
        InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st = Nt_CreateWaitablePort(&hPort, &oa, 64, 128, 0);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(hPort);

        st = Nt_Close(hPort);
        TEST_ASSERT_SUCCESS(st);
    }
    TEST_CASE_FINISH();

    /* Test 3: Port Name Collision */
    TEST_CASE_START("Port Object Name Collision Detection");
    {
        HANDLE hPort1 = NULL, hPort2 = NULL;
        USHORT wname[64];
        UNICODE_STRING uName;
        OBJECT_ATTRIBUTES oa;
        AsciiToUnicode("\\CollisionPort_Lpc", wname, &uName, 64);
        InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st1 = Nt_CreatePort(&hPort1, &oa, 64, 128, 0);
        TEST_ASSERT_SUCCESS(st1);

        /* Second creation with same name must fail with OBJECT_NAME_COLLISION */
        NTSTATUS st2 = Nt_CreatePort(&hPort2, &oa, 64, 128, 0);
        TEST_ASSERT_STATUS(st2, STATUS_OBJECT_NAME_COLLISION);

        Nt_Close(hPort1);
    }
    TEST_CASE_FINISH();

    /* Test 4: Negative - Connect to Nonexistent Port */
    TEST_CASE_START("Negative - Connect to Nonexistent Port");
    {
        HANDLE hClient = NULL;
        USHORT wname[64];
        UNICODE_STRING uName;
        AsciiToUnicode("\\BaseNamedObjects\\NoSuchPort_9999", wname, &uName, 64);

        /* NtConnectPort: syscall 31 */
        unsigned long a[8] = {
            (unsigned long)&hClient, (unsigned long)&uName, 0, 0, 0, 0, 0, 0
        };
        NTSTATUS st = (NTSTATUS)DoNtSyscall(31 /* NtConnectPort */, a, 8);
        TEST_ASSERT(!NT_SUCCESS(st), "Connecting to nonexistent port must fail");
    }
    TEST_CASE_FINISH();

    /* Test 5: Negative - Request on Invalid Port Handle */
    TEST_CASE_START("Negative - Message Request on Invalid Port Handle");
    {
        PORT_MESSAGE msg;
        memset(&msg, 0, sizeof(msg));
        msg.u1.s1.DataLength = 0;
        msg.u1.s1.TotalLength = sizeof(PORT_MESSAGE);

        NTSTATUS st = Nt_RequestPort((HANDLE)0xBAD999, &msg);
        TEST_ASSERT_STATUS(st, STATUS_INVALID_HANDLE);
    }
    TEST_CASE_FINISH();

    TEST_SUITE_FINISH();
}
