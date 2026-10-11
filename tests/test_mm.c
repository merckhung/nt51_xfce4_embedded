/* SPDX-License-Identifier: GPL-2.0-only */
#include "test_framework.h"

void run_mm_tests(void) {
    TEST_SUITE_START("Memory Manager (Mm)");

    /* Test 1: Virtual Memory Reservation & Commitment */
    TEST_CASE_START("Virtual Memory Reserve, Commit, Access & Verification");
    {
        PVOID base = NULL;
        ULONG size = 64 * 1024;
        NTSTATUS st = Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &size, MEM_RESERVE, PAGE_READWRITE);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(base);

        /* Commit first 4KB page */
        PVOID commit_base = base;
        ULONG commit_size = 4096;
        st = Nt_AllocateVirtualMemory((HANDLE)-1, &commit_base, 0, &commit_size, MEM_COMMIT, PAGE_READWRITE);
        TEST_ASSERT_SUCCESS(st);

        /* Write memory pattern */
        volatile uint32_t *p = (volatile uint32_t *)base;
        p[0] = 0x12345678;
        p[1] = 0x9ABCDEF0;
        p[1023] = 0xCAFEBABE;

        /* Verify pattern */
        TEST_ASSERT(p[0] == 0x12345678 && p[1] == 0x9ABCDEF0 && p[1023] == 0xCAFEBABE, "Memory pattern read/write match");

        /* Decommit and Release */
        ULONG free_size = 4096;
        st = Nt_FreeVirtualMemory((HANDLE)-1, &commit_base, &free_size, MEM_DECOMMIT);
        TEST_ASSERT_SUCCESS(st);

        free_size = 0;
        st = Nt_FreeVirtualMemory((HANDLE)-1, &base, &free_size, MEM_RELEASE);
        TEST_ASSERT_SUCCESS(st);
    }
    TEST_CASE_FINISH();

    /* Test 2: Page Protection Transitions */
    TEST_CASE_START("Page Protection Modification (PAGE_READONLY <-> PAGE_READWRITE)");
    {
        PVOID base = NULL;
        ULONG size = 4096;
        NTSTATUS st = Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        TEST_ASSERT_SUCCESS(st);

        *(volatile uint32_t *)base = 0xDEADBEEF;

        ULONG old_prot = 0;
        ULONG protect_size = 4096;
        st = Nt_ProtectVirtualMemory((HANDLE)-1, &base, &protect_size, PAGE_READONLY, &old_prot);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_EQUAL(old_prot, PAGE_READWRITE);

        /* Read must still succeed */
        uint32_t val = *(volatile uint32_t *)base;
        TEST_ASSERT_EQUAL(val, 0xDEADBEEF);

        /* Restore READWRITE */
        st = Nt_ProtectVirtualMemory((HANDLE)-1, &base, &protect_size, PAGE_READWRITE, &old_prot);
        TEST_ASSERT_SUCCESS(st);

        ULONG free_size = 0;
        Nt_FreeVirtualMemory((HANDLE)-1, &base, &free_size, MEM_RELEASE);
    }
    TEST_CASE_FINISH();

    /* Test 3: Query Virtual Memory Attributes */
    TEST_CASE_START("Virtual Memory Query (MemoryBasicInformation)");
    {
        PVOID base = NULL;
        ULONG size = 8192;
        NTSTATUS st = Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        TEST_ASSERT_SUCCESS(st);

        MEMORY_BASIC_INFORMATION mbi;
        ULONG retLen = 0;
        st = Nt_QueryVirtualMemory((HANDLE)-1, base, 0 /* MemoryBasicInformation */, &mbi, sizeof(mbi), &retLen);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_EQUAL(mbi.State, MEM_COMMIT);
        TEST_ASSERT_EQUAL(mbi.Protect, PAGE_READWRITE);
        TEST_ASSERT(mbi.RegionSize >= 8192, "Region size >= 8192");

        ULONG free_size = 0;
        Nt_FreeVirtualMemory((HANDLE)-1, &base, &free_size, MEM_RELEASE);
    }
    TEST_CASE_FINISH();

    /* Test 4: Section Object & Cross-View Shared Memory Coherence */
    TEST_CASE_START("Section Creation & Coherent Cross-View Mapping");
    {
        HANDLE hSection = NULL;
        USHORT wname[64];
        UNICODE_STRING uName;
        OBJECT_ATTRIBUTES oa;
        AsciiToUnicode("\\TestSec_Mm", wname, &uName, 64);
        InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        LARGE_INTEGER secSize;
        secSize.QuadPart = 64 * 1024;
        NTSTATUS st = Nt_CreateSection(&hSection, 0xF001F /* SECTION_ALL_ACCESS */, &oa, &secSize, PAGE_READWRITE, 0x08000000 /* SEC_COMMIT */, NULL);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(hSection);

        /* Map first view */
        PVOID view1 = NULL;
        ULONG view1_size = 0;
        st = NtMapViewOfSection(hSection, (HANDLE)-1, &view1, 0, 0, NULL, &view1_size, 1 /* ViewShare */, 0, PAGE_READWRITE);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(view1);

        /* Map second view of the same section */
        PVOID view2 = NULL;
        ULONG view2_size = 0;
        st = NtMapViewOfSection(hSection, (HANDLE)-1, &view2, 0, 0, NULL, &view2_size, 1 /* ViewShare */, 0, PAGE_READWRITE);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(view2);
        TEST_ASSERT(view1 != view2, "Dual views mapped to distinct virtual addresses");

        /* Write data to view 1 and verify instant visibility in view 2 */
        if (view1 && view2) {
            volatile uint32_t *v1 = (volatile uint32_t *)view1;
            volatile uint32_t *v2 = (volatile uint32_t *)view2;
            v1[0] = 0xA1B2C3D4;
            v1[128] = 0x55AA1122;

            TEST_ASSERT(v2[0] == 0xA1B2C3D4 && v2[128] == 0x55AA1122, "Shared memory coherence verified across views");
        }

        /* Unmap views and close */
        if (view1) {
            st = Nt_UnmapViewOfSection((HANDLE)-1, view1);
            TEST_ASSERT_SUCCESS(st);
        }
        if (view2) {
            st = Nt_UnmapViewOfSection((HANDLE)-1, view2);
            TEST_ASSERT_SUCCESS(st);
        }
        if (hSection) {
            Nt_Close(hSection);
        }
    }
    TEST_CASE_FINISH();

    /* Test 5: Negative & Boundary Handling */
    TEST_CASE_START("Negative - Invalid Memory Parameters & Protection Errors");
    {
        PVOID bad_addr = (PVOID)0x70000000;
        ULONG size = 4096;
        ULONG old_prot = 0;
        NTSTATUS st = Nt_ProtectVirtualMemory((HANDLE)-1, &bad_addr, &size, PAGE_READONLY, &old_prot);
        TEST_ASSERT(!NT_SUCCESS(st), "Protecting unallocated memory returns failure");

        /* Probing NULL BaseAddress pointer in NtAllocateVirtualMemory */
        size = 4096;
        st = Nt_AllocateVirtualMemory((HANDLE)-1, NULL, 0, &size, MEM_COMMIT, PAGE_READWRITE);
        TEST_ASSERT_STATUS(st, STATUS_ACCESS_VIOLATION);
    }
    TEST_CASE_FINISH();

    /* Test 6: Stress - Multi-Allocation Cycles */
    TEST_CASE_START("Stress - Sequential Allocation/Commit/Free (32 blocks)");
    {
        int i, fail = 0;
        for (i = 0; i < 32; i++) {
            PVOID base = NULL;
            ULONG size = 16 * 1024;
            if (!NT_SUCCESS(Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
                fail++; break;
            }
            *(volatile uint32_t *)base = i;
            ULONG free_size = 0;
            if (!NT_SUCCESS(Nt_FreeVirtualMemory((HANDLE)-1, &base, &free_size, MEM_RELEASE))) {
                fail++;
            }
        }
        TEST_ASSERT(fail == 0, "32 sequential 16KB allocation/touch/free cycles succeeded");
    }
    TEST_CASE_FINISH();

    TEST_SUITE_FINISH();
}
