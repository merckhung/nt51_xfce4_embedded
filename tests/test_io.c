/* SPDX-License-Identifier: GPL-2.0-only */
#include "test_framework.h"

typedef struct _FILE_STANDARD_INFO {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    UCHAR         DeletePending;
    UCHAR         Directory;
} FILE_STANDARD_INFO;

typedef struct _FILE_FS_SIZE_INFO {
    LARGE_INTEGER TotalAllocationUnits;
    LARGE_INTEGER AvailableAllocationUnits;
    ULONG         SectorsPerAllocationUnit;
    ULONG         BytesPerSector;
} FILE_FS_SIZE_INFO;

typedef struct _FILE_DISPOSITION_INFO {
    UCHAR DeleteFile;
} FILE_DISPOSITION_INFO;

void run_io_tests(void) {
    TEST_SUITE_START("I/O Manager & Filesystem (Io)");

    /* Test 1: File Create, Synchronous Write, Flush, Read & Verify */
    TEST_CASE_START("Synchronous File I/O (Create, Write, Flush, Read, Verify)");
    {
        HANDLE hFile = NULL;
        USHORT wpath[64];
        UNICODE_STRING uPath;
        OBJECT_ATTRIBUTES oa;
        IO_STATUS_BLOCK iosb;

        AsciiToUnicode("\\??\\C:\\test_io.tmp", wpath, &uPath, 64);
        InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        /* Create / Supersede file */
        NTSTATUS st = Nt_CreateFile(&hFile, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
                                    NULL, 0, FILE_SHARE_READ, FILE_SUPERSEDE,
                                    FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(hFile);

        /* Write 256 bytes */
        char write_buf[256];
        int i;
        for (i = 0; i < 256; i++) write_buf[i] = (char)(i ^ 0x5A);

        st = Nt_WriteFile(hFile, NULL, NULL, NULL, &iosb, write_buf, sizeof(write_buf), NULL, NULL);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_EQUAL(iosb.Information, sizeof(write_buf));

        /* Flush buffers */
        st = Nt_FlushBuffersFile(hFile, &iosb);
        TEST_ASSERT_SUCCESS(st);
        Nt_Close(hFile);

        /* Re-open for reading */
        st = Nt_OpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
        TEST_ASSERT_SUCCESS(st);

        char read_buf[256];
        memset(read_buf, 0, sizeof(read_buf));
        st = Nt_ReadFile(hFile, NULL, NULL, NULL, &iosb, read_buf, sizeof(read_buf), NULL, NULL);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_EQUAL(iosb.Information, sizeof(read_buf));

        /* Verify content */
        int match = (memcmp(write_buf, read_buf, 256) == 0);
        TEST_ASSERT(match, "Written data identical to read-back data");

        Nt_Close(hFile);
    }
    TEST_CASE_FINISH();

    /* Test 2: File Standard Information Query */
    TEST_CASE_START("File Standard Information Query (EndOfFile & Directory flag)");
    {
        HANDLE hFile = NULL;
        USHORT wpath[64];
        UNICODE_STRING uPath;
        OBJECT_ATTRIBUTES oa;
        IO_STATUS_BLOCK iosb;

        AsciiToUnicode("\\??\\C:\\test_io.tmp", wpath, &uPath, 64);
        InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st = Nt_OpenFile(&hFile, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
        TEST_ASSERT_SUCCESS(st);

        FILE_STANDARD_INFO fsi;
        st = Nt_QueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), 5 /* FileStandardInformation */);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_EQUAL((uint32_t)fsi.EndOfFile.QuadPart, 256);
        TEST_ASSERT_EQUAL(fsi.Directory, 0);

        Nt_Close(hFile);
    }
    TEST_CASE_FINISH();

    /* Test 3: Filesystem Volume Size Query */
    TEST_CASE_START("Filesystem Volume Size Query (FileFsSizeInformation)");
    {
        HANDLE hRoot = NULL;
        USHORT wpath[64];
        UNICODE_STRING uPath;
        OBJECT_ATTRIBUTES oa;
        IO_STATUS_BLOCK iosb;

        AsciiToUnicode("\\??\\C:\\", wpath, &uPath, 64);
        InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st = Nt_OpenFile(&hRoot, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        TEST_ASSERT_SUCCESS(st);

        FILE_FS_SIZE_INFO fssi;
        st = Nt_QueryVolumeInformationFile(hRoot, &iosb, &fssi, sizeof(fssi), 3 /* FileFsSizeInformation */);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT(fssi.TotalAllocationUnits.QuadPart > 0, "TotalAllocationUnits > 0");
        TEST_ASSERT(fssi.BytesPerSector >= 512, "BytesPerSector >= 512");

        Nt_Close(hRoot);
    }
    TEST_CASE_FINISH();

    /* Test 4: I/O Completion Port Lifecycle */
    TEST_CASE_START("I/O Completion Port (Create, Post, Dequeue)");
    {
        HANDLE hIoComp = NULL;
        NTSTATUS st = Nt_CreateIoCompletion(&hIoComp, 0x1F0003 /* IO_COMPLETION_ALL_ACCESS */, NULL, 1 /* concurrency */);
        TEST_ASSERT_SUCCESS(st);
        TEST_ASSERT_NOT_NULL(hIoComp);

        /* Post completion packet */
        st = Nt_SetIoCompletion(hIoComp, 0x12345678 /* Key */, (PVOID)0xAABBCCDD, STATUS_SUCCESS, 42 /* bytes */);
        TEST_ASSERT_SUCCESS(st);

        /* Dequeue completion packet */
        ULONG_PTR compKey = 0;
        PVOID compContext = NULL;
        IO_STATUS_BLOCK compIosb;
        LARGE_INTEGER timeout;
        timeout.QuadPart = 0;

        st = Nt_RemoveIoCompletion(hIoComp, (PVOID)&compKey, &compContext, &compIosb, &timeout);
        TEST_ASSERT_STATUS(st, STATUS_SUCCESS);
        TEST_ASSERT_EQUAL(compKey, 0x12345678);
        TEST_ASSERT_EQUAL((uint32_t)compContext, 0xAABBCCDD);
        TEST_ASSERT_EQUAL(compIosb.Information, 42);

        Nt_Close(hIoComp);
    }
    TEST_CASE_FINISH();

    /* Test 5: File Deletion via Disposition */
    TEST_CASE_START("File Deletion via FileDispositionInformation");
    {
        HANDLE hFile = NULL;
        USHORT wpath[64];
        UNICODE_STRING uPath;
        OBJECT_ATTRIBUTES oa;
        IO_STATUS_BLOCK iosb;

        AsciiToUnicode("\\??\\C:\\test_io.tmp", wpath, &uPath, 64);
        InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st = Nt_OpenFile(&hFile, 0x00010000L /* DELETE */ | SYNCHRONIZE, &oa, &iosb,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  FILE_SYNCHRONOUS_IO_NONALERT);
        TEST_ASSERT_SUCCESS(st);

        FILE_DISPOSITION_INFO disp;
        disp.DeleteFile = 1;
        st = Nt_SetInformationFile(hFile, &iosb, &disp, sizeof(disp), 13 /* FileDispositionInformation */);
        TEST_ASSERT_SUCCESS(st);
        Nt_Close(hFile);

        /* Re-opening deleted file must fail */
        st = Nt_OpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
        TEST_ASSERT_STATUS(st, STATUS_OBJECT_NAME_NOT_FOUND);
    }
    TEST_CASE_FINISH();

    /* Test 6: Negative - Invalid Handle & Missing File */
    TEST_CASE_START("Negative - Invalid File Handle & Nonexistent Target");
    {
        IO_STATUS_BLOCK iosb;
        char buf[16];
        NTSTATUS st = Nt_ReadFile((HANDLE)0xBAD1010, NULL, NULL, NULL, &iosb, buf, sizeof(buf), NULL, NULL);
        TEST_ASSERT_STATUS(st, STATUS_INVALID_HANDLE);

        USHORT wpath[64];
        UNICODE_STRING uPath;
        OBJECT_ATTRIBUTES oa;
        AsciiToUnicode("\\??\\C:\\NonExistent_File_9876.xyz", wpath, &uPath, 64);
        InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hFile = NULL;
        st = Nt_OpenFile(&hFile, FILE_READ_DATA, &oa, &iosb, FILE_SHARE_READ, 0);
        TEST_ASSERT_STATUS(st, STATUS_OBJECT_NAME_NOT_FOUND);
    }
    TEST_CASE_FINISH();

    TEST_SUITE_FINISH();
}
