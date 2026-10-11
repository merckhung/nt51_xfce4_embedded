/* SPDX-License-Identifier: GPL-2.0-only */
#include "test_framework.h"

void run_ke_ex_tests(void) {
    TEST_SUITE_START("Executive & Synchronization (Ex / Ke)");

    /* Test 1: Notification (Manual-Reset) vs Synchronization (Auto-Reset) Events */
    TEST_CASE_START("Event Semantics (Notification vs Synchronization)");
    {
        HANDLE hNotif = NULL, hSync = NULL;
        NTSTATUS st = Nt_CreateEvent(&hNotif, EVENT_ALL_ACCESS, NULL, NotificationEvent, 0);
        TEST_ASSERT_SUCCESS(st);
        st = Nt_CreateEvent(&hSync, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, 0);
        TEST_ASSERT_SUCCESS(st);

        /* Notification Event: persists signaled until explicitly reset */
        LONG prev = 0;
        st = Nt_SetEvent(hNotif, &prev);
        TEST_ASSERT_SUCCESS(st);

        LARGE_INTEGER zeroTimeout;
        zeroTimeout.QuadPart = 0;
        st = Nt_WaitForSingleObject(hNotif, 0, &zeroTimeout);
        TEST_ASSERT_STATUS(st, STATUS_WAIT_0);
        /* Second wait must ALSO succeed without resetting */
        st = Nt_WaitForSingleObject(hNotif, 0, &zeroTimeout);
        TEST_ASSERT_STATUS(st, STATUS_WAIT_0);

        /* Reset event */
        st = Nt_ResetEvent(hNotif, &prev);
        TEST_ASSERT_SUCCESS(st);
        st = Nt_WaitForSingleObject(hNotif, 0, &zeroTimeout);
        TEST_ASSERT_STATUS(st, STATUS_TIMEOUT);

        /* Synchronization Event: auto-resets upon successful wait */
        st = Nt_SetEvent(hSync, &prev);
        TEST_ASSERT_SUCCESS(st);
        st = Nt_WaitForSingleObject(hSync, 0, &zeroTimeout);
        TEST_ASSERT_STATUS(st, STATUS_WAIT_0);
        /* Second wait must immediately timeout because first wait consumed signal */
        st = Nt_WaitForSingleObject(hSync, 0, &zeroTimeout);
        TEST_ASSERT_STATUS(st, STATUS_TIMEOUT);

        Nt_Close(hNotif);
        Nt_Close(hSync);
    }
    TEST_CASE_FINISH();

    /* Test 2: Mutant / Mutex Acquire & Release */
    TEST_CASE_START("Mutant (Mutex) Ownership & Release Semantics");
    {
        HANDLE hMutant = NULL;
        NTSTATUS st = Nt_CreateMutant(&hMutant, 0x1F0001 /* MUTANT_ALL_ACCESS */, NULL, 0 /* unowned */);
        TEST_ASSERT_SUCCESS(st);

        LARGE_INTEGER zeroTimeout;
        zeroTimeout.QuadPart = 0;
        st = Nt_WaitForSingleObject(hMutant, 0, &zeroTimeout);
        TEST_ASSERT_STATUS(st, STATUS_WAIT_0);

        /* Release mutant */
        LONG prevCount = 0;
        st = Nt_ReleaseMutant(hMutant, &prevCount);
        TEST_ASSERT_SUCCESS(st);

        Nt_Close(hMutant);
    }
    TEST_CASE_FINISH();

    /* Test 3: Semaphore Counting & Saturation */
    TEST_CASE_START("Semaphore Capacity, Consumption & Saturation");
    {
        HANDLE hSem = NULL;
        NTSTATUS st = Nt_CreateSemaphore(&hSem, 0x1F0003 /* SEMAPHORE_ALL_ACCESS */, NULL, 2 /* initial */, 5 /* max */);
        TEST_ASSERT_SUCCESS(st);

        LARGE_INTEGER zeroTimeout;
        zeroTimeout.QuadPart = 0;

        /* Consume token 1 */
        st = Nt_WaitForSingleObject(hSem, 0, &zeroTimeout);
        TEST_ASSERT_STATUS(st, STATUS_WAIT_0);

        /* Consume token 2 */
        st = Nt_WaitForSingleObject(hSem, 0, &zeroTimeout);
        TEST_ASSERT_STATUS(st, STATUS_WAIT_0);

        /* Semaphore now exhausted: wait must return TIMEOUT */
        st = Nt_WaitForSingleObject(hSem, 0, &zeroTimeout);
        TEST_ASSERT_STATUS(st, STATUS_TIMEOUT);

        /* Release 2 tokens */
        LONG prev = 0;
        st = Nt_ReleaseSemaphore(hSem, 2, &prev);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_EQUAL(prev, 0);

        /* Now token is available again */
        st = Nt_WaitForSingleObject(hSem, 0, &zeroTimeout);
        TEST_ASSERT_STATUS(st, STATUS_WAIT_0);

        Nt_Close(hSem);
    }
    TEST_CASE_FINISH();

    /* Test 4: Timer Object Relative Delay & Expiration */
    TEST_CASE_START("Notification Timer Relative Expiration");
    {
        HANDLE hTimer = NULL;
        NTSTATUS st = Nt_CreateTimer(&hTimer, 0x1F0003 /* TIMER_ALL_ACCESS */, NULL, 0 /* NotificationTimer */);
        TEST_ASSERT_SUCCESS(st);

        /* Set relative timer: 10ms (100,000 * 100ns units negative) */
        LARGE_INTEGER dueTime;
        dueTime.QuadPart = -100000LL;
        UCHAR prevState = 0;
        st = Nt_SetTimer(hTimer, &dueTime, NULL, NULL, 0, 0, &prevState);
        TEST_ASSERT_SUCCESS(st);

        /* Wait for timer expiration (up to 500ms timeout) */
        LARGE_INTEGER waitTimeout;
        waitTimeout.QuadPart = -5000000LL;
        st = Nt_WaitForSingleObject(hTimer, 0, &waitTimeout);
        TEST_ASSERT_STATUS(st, STATUS_WAIT_0);

        Nt_Close(hTimer);
    }
    TEST_CASE_FINISH();

    /* Test 5: Multi-Object Wait (WaitAny & WaitAll) */
    TEST_CASE_START("Multi-Object Synchronization (WaitAny & WaitAll)");
    {
        HANDLE events[3] = { NULL, NULL, NULL };
        int i;
        for (i = 0; i < 3; i++) {
            Nt_CreateEvent(&events[i], EVENT_ALL_ACCESS, NULL, NotificationEvent, 0);
        }

        /* Signal only event[1] */
        LONG prev = 0;
        Nt_SetEvent(events[1], &prev);

        LARGE_INTEGER zeroTimeout;
        zeroTimeout.QuadPart = 0;

        /* WaitAny: must return index 1 (STATUS_WAIT_0 + 1) */
        NTSTATUS st = Nt_WaitForMultipleObjects(3, events, 1 /* WaitAny */, 0, &zeroTimeout);
        TEST_ASSERT_STATUS(st, STATUS_WAIT_0 + 1);

        /* WaitAll: not all signaled yet, must timeout */
        st = Nt_WaitForMultipleObjects(3, events, 0 /* WaitAll */, 0, &zeroTimeout);
        TEST_ASSERT_STATUS(st, STATUS_TIMEOUT);

        /* Signal remaining events */
        Nt_SetEvent(events[0], &prev);
        Nt_SetEvent(events[2], &prev);

        /* WaitAll: now all signaled, must succeed with STATUS_WAIT_0 */
        st = Nt_WaitForMultipleObjects(3, events, 0 /* WaitAll */, 0, &zeroTimeout);
        TEST_ASSERT_STATUS(st, STATUS_WAIT_0);

        for (i = 0; i < 3; i++) {
            Nt_Close(events[i]);
        }
    }
    TEST_CASE_FINISH();

    /* Test 6: Thread Execution Delay */
    TEST_CASE_START("Execution Delay (NtDelayExecution)");
    {
        LARGE_INTEGER delay;
        delay.QuadPart = -50000LL; /* 5ms relative delay */
        NTSTATUS st = Nt_DelayExecution(0, &delay);
        TEST_ASSERT_SUCCESS(st);
    }
    TEST_CASE_FINISH();

    /* Test 7: Stress - Rapid Event Signaling Loop */
    TEST_CASE_START("Stress - High-Frequency Event Signal/Wait Loop (100 rounds)");
    {
        HANDLE hEv = NULL;
        Nt_CreateEvent(&hEv, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, 0);
        int i, fail = 0;
        LARGE_INTEGER zeroTimeout;
        zeroTimeout.QuadPart = 0;

        for (i = 0; i < 100; i++) {
            LONG p = 0;
            if (!NT_SUCCESS(Nt_SetEvent(hEv, &p))) { fail++; break; }
            if (Nt_WaitForSingleObject(hEv, 0, &zeroTimeout) != STATUS_WAIT_0) { fail++; break; }
        }
        TEST_ASSERT(fail == 0, "100 rapid signal-wait cycles completed with zero dropped signals");
        Nt_Close(hEv);
    }
    TEST_CASE_FINISH();

    TEST_SUITE_FINISH();
}
