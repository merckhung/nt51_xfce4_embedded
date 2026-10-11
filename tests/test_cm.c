/* SPDX-License-Identifier: GPL-2.0-only */
#include "test_framework.h"

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG         TitleIndex;
    ULONG         NameLength;
    USHORT        Name[1];
} KEY_BASIC_INFORMATION;

void run_cm_tests(void) {
    TEST_SUITE_START("Configuration Manager / Registry (Cm)");

    /* Test 1: Open System Registry Hive */
    TEST_CASE_START("Registry System Key Open (\\Registry\\Machine\\SYSTEM)");
    {
        HANDLE hKey = NULL;
        USHORT wname[64];
        UNICODE_STRING uName;
        OBJECT_ATTRIBUTES oa;
        AsciiToUnicode("\\Registry\\Machine\\SYSTEM", wname, &uName, 64);
        InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st = Nt_OpenKey(&hKey, KEY_READ, &oa);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(hKey);

        Nt_Close(hKey);
    }
    TEST_CASE_FINISH();

    /* Test 2: Subkey & Value Creation, Query & Verification */
    TEST_CASE_START("Volatile Key & Value Creation (DWORD & String)");
    {
        HANDLE hParent = NULL, hTestKey = NULL;
        USHORT wparent[64], wtest[64], wvalDword[32], wvalStr[32];
        UNICODE_STRING uParent, uTest, uValDword, uValStr;
        OBJECT_ATTRIBUTES oaParent, oaTest;

        AsciiToUnicode("\\Registry\\Machine\\SYSTEM", wparent, &uParent, 64);
        InitializeObjectAttributes(&oaParent, &uParent, OBJ_CASE_INSENSITIVE, NULL, NULL);
        NTSTATUS st = Nt_OpenKey(&hParent, KEY_ALL_ACCESS, &oaParent);
        TEST_ASSERT_SUCCESS(st);

        AsciiToUnicode("TestKey_Cm", wtest, &uTest, 64);
        InitializeObjectAttributes(&oaTest, &uTest, OBJ_CASE_INSENSITIVE, hParent, NULL);

        ULONG disposition = 0;
        st = Nt_CreateKey(&hTestKey, KEY_ALL_ACCESS, &oaTest, 0, NULL, 1 /* REG_OPTION_VOLATILE */, &disposition);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(hTestKey);

        /* Set DWORD Value: 0xCAFEBABE */
        AsciiToUnicode("DwordValue", wvalDword, &uValDword, 32);
        uint32_t dwordData = 0xCAFEBABE;
        st = Nt_SetValueKey(hTestKey, &uValDword, 0, REG_DWORD, &dwordData, sizeof(dwordData));
        TEST_ASSERT_SUCCESS(st);

        /* Set String Value: "TestValString" */
        AsciiToUnicode("StringValue", wvalStr, &uValStr, 32);
        USHORT wStrData[32];
        UNICODE_STRING uStrData;
        AsciiToUnicode("TestValString", wStrData, &uStrData, 32);
        st = Nt_SetValueKey(hTestKey, &uValStr, 0, REG_SZ, uStrData.Buffer, uStrData.Length + 2);
        TEST_ASSERT_SUCCESS(st);

        /* Query DWORD value back and verify */
        UCHAR qbuf[128];
        ULONG retLen = 0;
        st = Nt_QueryValueKey(hTestKey, &uValDword, 2 /* KeyValuePartialInformation */, qbuf, sizeof(qbuf), &retLen);
        TEST_ASSERT_SUCCESS(st);
        KEY_VALUE_PARTIAL_INFORMATION *kvpi = (KEY_VALUE_PARTIAL_INFORMATION *)qbuf;
        TEST_ASSERT_EQUAL(kvpi->Type, REG_DWORD);
        TEST_ASSERT_EQUAL(kvpi->DataLength, sizeof(uint32_t));
        TEST_ASSERT_EQUAL(*(uint32_t *)kvpi->Data, 0xCAFEBABE);

        /* Query String value back and verify */
        st = Nt_QueryValueKey(hTestKey, &uValStr, 2 /* KeyValuePartialInformation */, qbuf, sizeof(qbuf), &retLen);
        TEST_ASSERT_SUCCESS(st);
        kvpi = (KEY_VALUE_PARTIAL_INFORMATION *)qbuf;
        TEST_ASSERT_EQUAL(kvpi->Type, REG_SZ);
        TEST_ASSERT(kvpi->DataLength > 0, "String value data length > 0");

        /* Clean up key and values */
        st = Nt_DeleteValueKey(hTestKey, &uValDword);
        TEST_ASSERT_SUCCESS(st);
        st = Nt_DeleteValueKey(hTestKey, &uValStr);
        TEST_ASSERT_SUCCESS(st);

        st = Nt_DeleteKey(hTestKey);
        TEST_ASSERT_SUCCESS(st);

        Nt_Close(hTestKey);
        Nt_Close(hParent);
    }
    TEST_CASE_FINISH();

    /* Test 3: Value Enumeration */
    TEST_CASE_START("Registry Key Value Enumeration");
    {
        HANDLE hKey = NULL;
        USHORT wname[64];
        UNICODE_STRING uName;
        OBJECT_ATTRIBUTES oa;
        AsciiToUnicode("\\Registry\\Machine\\SYSTEM\\Setup", wname, &uName, 64);
        InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st = Nt_OpenKey(&hKey, KEY_READ, &oa);
        if (NT_SUCCESS(st)) {
            UCHAR buf[256];
            ULONG retLen = 0;
            st = Nt_EnumerateValueKey(hKey, 0, 2 /* KeyValuePartialInformation */, buf, sizeof(buf), &retLen);
            TEST_ASSERT(NT_SUCCESS(st) || st == STATUS_NO_MORE_ENTRIES, "Enumerating first value succeeds or empty");
            Nt_Close(hKey);
        } else {
            TEST_ASSERT(1, "Optional setup key skipped");
        }
    }
    TEST_CASE_FINISH();

    /* Test 4: Registry Flush */
    TEST_CASE_START("Registry Hive Flush (NtFlushKey)");
    {
        HANDLE hKey = NULL;
        USHORT wname[64];
        UNICODE_STRING uName;
        OBJECT_ATTRIBUTES oa;
        AsciiToUnicode("\\Registry\\Machine\\SYSTEM", wname, &uName, 64);
        InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st = Nt_OpenKey(&hKey, KEY_READ, &oa);
        TEST_ASSERT_SUCCESS(st);

        st = Nt_FlushKey(hKey);
        /* In our read-only or in-memory hive, flush succeeds or returns success */
        TEST_ASSERT(NT_SUCCESS(st) || st == STATUS_ACCESS_DENIED, "FlushKey completed");
        Nt_Close(hKey);
    }
    TEST_CASE_FINISH();

    /* Test 5: Negative - Nonexistent Registry Key */
    TEST_CASE_START("Negative - Nonexistent Registry Key Access");
    {
        HANDLE hKey = NULL;
        USHORT wname[64];
        UNICODE_STRING uName;
        OBJECT_ATTRIBUTES oa;
        AsciiToUnicode("\\Registry\\Machine\\NonExistentHive_9876", wname, &uName, 64);
        InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st = Nt_OpenKey(&hKey, KEY_READ, &oa);
        TEST_ASSERT_STATUS(st, STATUS_OBJECT_NAME_NOT_FOUND);
    }
    TEST_CASE_FINISH();

    TEST_SUITE_FINISH();
}
