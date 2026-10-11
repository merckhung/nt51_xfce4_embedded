/* SPDX-License-Identifier: GPL-2.0-only */
#include "test_framework.h"

typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserAddress;
    ULONG_PTR MaximumUserAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    UCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_PERFORMANCE_INFORMATION {
    LARGE_INTEGER IdleProcessTime;
    LARGE_INTEGER IoReadTransferCount;
    LARGE_INTEGER IoWriteTransferCount;
    LARGE_INTEGER IoOtherTransferCount;
    ULONG IoReadOperationCount;
    ULONG IoWriteOperationCount;
    ULONG IoOtherOperationCount;
    ULONG AvailablePages;
    ULONG CommittedPages;
    ULONG CommitLimit;
    ULONG PeakCommitment;
    ULONG PageFaultCount;
    ULONG CopyOnWriteCount;
    ULONG TransitionCount;
    ULONG CacheTransitionCount;
    ULONG DemandZeroCount;
    ULONG PageReadCount;
    ULONG PageReadIoCount;
    ULONG CacheReadCount;
    ULONG CacheIoCount;
    ULONG DirtyPagesWriteCount;
    ULONG DirtyWriteIoCount;
    ULONG MappedPagesWriteCount;
    ULONG MappedWriteIoCount;
    ULONG PagedPoolPages;
    ULONG NonPagedPoolPages;
    ULONG PagedPoolAllocs;
    ULONG PagedPoolFrees;
    ULONG NonPagedPoolAllocs;
    ULONG NonPagedPoolFrees;
    ULONG FreeSystemPtes;
    ULONG ResidentSystemCodePage;
    ULONG TotalSystemDriverPages;
    ULONG TotalSystemCodePages;
    ULONG NonPagedPoolLookasideHits;
    ULONG PagedPoolLookasideHits;
    ULONG AvailablePagedPoolPages;
    ULONG ResidentSystemCachePage;
    ULONG ResidentPagedPoolPage;
    ULONG ResidentSystemDriverPage;
    ULONG CcFastReadNoWait;
    ULONG CcFastReadWait;
    ULONG CcFastReadResourceMiss;
    ULONG CcFastReadNotPossible;
    ULONG CcFastMdlReadNoWait;
    ULONG CcFastMdlReadWait;
    ULONG CcFastMdlReadResourceMiss;
    ULONG CcFastMdlReadNotPossible;
    ULONG CcMapDataNoWait;
    ULONG CcMapDataWait;
    ULONG CcMapDataNoWaitMiss;
    ULONG CcMapDataWaitMiss;
    ULONG CcPinMappedDataCount;
    ULONG CcPinReadNoWait;
    ULONG CcPinReadWait;
    ULONG CcPinReadNoWaitMiss;
    ULONG CcPinReadWaitMiss;
    ULONG CcCopyReadNoWait;
    ULONG CcCopyReadWait;
    ULONG CcCopyReadNoWaitMiss;
    ULONG CcCopyReadWaitMiss;
    ULONG CcMdlReadNoWait;
    ULONG CcMdlReadWait;
    ULONG CcMdlReadNoWaitMiss;
    ULONG CcMdlReadWaitMiss;
    ULONG CcReadAheadIos;
    ULONG CcLazyWriteIos;
    ULONG CcLazyWritePages;
    ULONG CcDataFlushes;
    ULONG CcDataPages;
    ULONG ContextSwitches;
    ULONG FirstLevelTbFills;
    ULONG SecondLevelTbFills;
    ULONG SystemCalls;
} SYSTEM_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION {
    LARGE_INTEGER BootTime;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeZoneBias;
    ULONG TimeZoneId;
    ULONG Reserved;
    ULONGLONG BootTimeBias;
    ULONGLONG SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION;

void run_sys_tests(void) {
    TEST_SUITE_START("System Information & Timers (Sys)");

    /* Test 1: System Time Query & Monotonicity */
    TEST_CASE_START("System Time Query & Monotonic Progression");
    {
        LARGE_INTEGER t1, t2;
        NTSTATUS st = Nt_QuerySystemTime(&t1);
        TEST_ASSERT_SUCCESS(st);
        /* Year 2000 is ~125911584000000000 in 100ns units */
        TEST_ASSERT(t1.QuadPart > 116444736000000000ULL, "System time post-dates 1970 UNIX epoch");

        LARGE_INTEGER delay;
        delay.QuadPart = -20000LL; /* 2ms */
        Nt_DelayExecution(0, &delay);

        st = Nt_QuerySystemTime(&t2);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT(t2.QuadPart >= t1.QuadPart, "System time advances monotonically");
    }
    TEST_CASE_FINISH();

    /* Test 2: Timer Resolution Query */
    TEST_CASE_START("Timer Resolution Bounds Query");
    {
        ULONG maxTime = 0, minTime = 0, curTime = 0;
        NTSTATUS st = Nt_QueryTimerResolution(&maxTime, &minTime, &curTime);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT(maxTime >= curTime, "Maximum resolution interval >= current interval");
        TEST_ASSERT(curTime >= minTime, "Current resolution interval >= minimum interval");
        TEST_ASSERT(minTime > 0, "Minimum resolution interval > 0");
    }
    TEST_CASE_FINISH();

    /* Test 3: High-Resolution Performance Counter Query */
    TEST_CASE_START("Performance Counter Frequency & Progression");
    {
        LARGE_INTEGER count1, count2, freq;
        NTSTATUS st = Nt_QueryPerformanceCounter(&count1, &freq);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT(freq.QuadPart > 0, "Performance counter frequency is non-zero");

        int i;
        volatile int dummy = 0;
        for (i = 0; i < 50000; i++) dummy += i;

        st = Nt_QueryPerformanceCounter(&count2, NULL);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT(count2.QuadPart > count1.QuadPart, "Performance counter increments over CPU loop");
    }
    TEST_CASE_FINISH();

    /* Test 4: System Basic Information Query */
    TEST_CASE_START("System Basic Information (Processors, PageSize, Memory Limits)");
    {
        SYSTEM_BASIC_INFORMATION sbi;
        memset(&sbi, 0, sizeof(sbi));
        ULONG retLen = 0;
        NTSTATUS st = Nt_QuerySystemInformation(0 /* SystemBasicInformation */, &sbi, sizeof(sbi), &retLen);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_EQUAL(sbi.PageSize, 4096);
        TEST_ASSERT(sbi.NumberOfProcessors >= 1, "At least 1 processor reported");
        TEST_ASSERT(sbi.NumberOfPhysicalPages > 0, "Physical pages reported > 0");
    }
    TEST_CASE_FINISH();

    /* Test 5: System Performance Information Query */
    TEST_CASE_START("System Performance Information (Available & Committed Pages)");
    {
        SYSTEM_PERFORMANCE_INFORMATION spi;
        memset(&spi, 0, sizeof(spi));
        ULONG retLen = 0;
        NTSTATUS st = Nt_QuerySystemInformation(2 /* SystemPerformanceInformation */, &spi, sizeof(spi), &retLen);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT(spi.AvailablePages > 0, "Available physical pages > 0");
        TEST_ASSERT(spi.CommittedPages > 0, "Committed virtual pages > 0");
    }
    TEST_CASE_FINISH();

    /* Test 6: System TimeOfDay Information Query */
    TEST_CASE_START("System TimeOfDay Information (BootTime & CurrentTime)");
    {
        SYSTEM_TIMEOFDAY_INFORMATION sti;
        memset(&sti, 0, sizeof(sti));
        ULONG retLen = 0;
        NTSTATUS st = Nt_QuerySystemInformation(3 /* SystemTimeOfDayInformation */, &sti, sizeof(sti), &retLen);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT(sti.BootTime.QuadPart > 0, "BootTime is non-zero");
        TEST_ASSERT(sti.CurrentTime.QuadPart >= sti.BootTime.QuadPart, "CurrentTime >= BootTime");
    }
    TEST_CASE_FINISH();

    /* Test 7: Negative - Invalid System Info Class & Length Mismatch */
    TEST_CASE_START("Negative - Invalid System Info Class & Buffer Undersize");
    {
        char buf[16];
        ULONG retLen = 0;
        NTSTATUS st = Nt_QuerySystemInformation(9999 /* invalid class */, buf, sizeof(buf), &retLen);
        TEST_ASSERT(!NT_SUCCESS(st), "Invalid system info class returns failure");

        /* Undersized buffer for SystemBasicInformation */
        st = Nt_QuerySystemInformation(0, buf, 4, &retLen);
        TEST_ASSERT_STATUS(st, STATUS_INFO_LENGTH_MISMATCH);
    }
    TEST_CASE_FINISH();

    TEST_SUITE_FINISH();
}
