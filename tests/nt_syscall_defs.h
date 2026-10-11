/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NT_SYSCALL_DEFS_H
#define NT_SYSCALL_DEFS_H

#include <stdint.h>
#include <stddef.h>

/* ========================================================================= */
/* System Call Invocation (via KiFastSystemCall 0x7FFE0300)                   */
/* ========================================================================= */
extern long DoNtSyscall(unsigned long id, const unsigned long *args, unsigned int num_args);

/* Standard NT Types */
typedef int32_t NTSTATUS;
typedef void *HANDLE;
typedef void *PVOID;
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;
typedef long LONG;
typedef unsigned long ULONG_PTR;
typedef long LONG_PTR;
typedef uint64_t ULONG64;
typedef int64_t LONG64;
typedef uint64_t ULONGLONG;
typedef int64_t LONGLONG;

typedef union _LARGE_INTEGER {
    struct {
        ULONG LowPart;
        LONG HighPart;
    };
    LONG64 QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef union _ULARGE_INTEGER {
    struct {
        ULONG LowPart;
        ULONG HighPart;
    };
    ULONG64 QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    USHORT *Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR    Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/* Initialize Object Attributes Macro */
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
}

/* Attributes */
#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L

/* Standard Status Codes */
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_WAIT_0                    ((NTSTATUS)0x00000000L)
#define STATUS_TIMEOUT                   ((NTSTATUS)0x00000102L)
#define STATUS_BUFFER_OVERFLOW           ((NTSTATUS)0x80000005L)
#define STATUS_NO_MORE_FILES             ((NTSTATUS)0x80000006L)
#define STATUS_NO_MORE_ENTRIES           ((NTSTATUS)0x8000001AL)
#define STATUS_NOT_IMPLEMENTED           ((NTSTATUS)0xC0000002L)
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define STATUS_ACCESS_VIOLATION          ((NTSTATUS)0xC0000005L)
#define STATUS_INVALID_HANDLE            ((NTSTATUS)0xC0000008L)
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#define STATUS_END_OF_FILE               ((NTSTATUS)0xC0000011L)
#define STATUS_NO_MEMORY                 ((NTSTATUS)0xC0000017L)
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#define STATUS_OBJECT_NAME_NOT_FOUND     ((NTSTATUS)0xC0000034L)
#define STATUS_OBJECT_NAME_COLLISION     ((NTSTATUS)0xC0000035L)
#define STATUS_PORT_DISCONNECTED         ((NTSTATUS)0xC0000037L)
#define STATUS_OBJECT_PATH_NOT_FOUND     ((NTSTATUS)0xC000003AL)
#define STATUS_OBJECT_PATH_SYNTAX_BAD    ((NTSTATUS)0xC000003BL)

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/* Helper: Initialize Unicode String */
static inline void InitUnicodeString(UNICODE_STRING *us, const unsigned short *wstr) {
    if (!wstr) {
        us->Length = 0;
        us->MaximumLength = 0;
        us->Buffer = NULL;
        return;
    }
    USHORT len = 0;
    while (wstr[len]) len++;
    us->Length = len * sizeof(USHORT);
    us->MaximumLength = us->Length + sizeof(USHORT);
    us->Buffer = (USHORT *)wstr;
}

/* Helper: Convert ASCII to Unicode String buffer */
static inline void AsciiToUnicode(const char *ascii, USHORT *wbuf, UNICODE_STRING *us, unsigned int max_chars) {
    unsigned int i = 0;
    while (ascii && ascii[i] && i < max_chars - 1) {
        wbuf[i] = (USHORT)(UCHAR)ascii[i];
        i++;
    }
    wbuf[i] = 0;
    us->Length = (USHORT)(i * sizeof(USHORT));
    us->MaximumLength = (USHORT)((i + 1) * sizeof(USHORT));
    us->Buffer = wbuf;
}

/* ========================================================================= */
/* Syscall Wrappers (XP SP1 x86 IDs matching services.tab)                    */
/* ========================================================================= */

/* Object Manager (Ob) */
static inline NTSTATUS Nt_CreateDirectoryObject(HANDLE *DirectoryHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes) {
    unsigned long a[3] = { (unsigned long)DirectoryHandle, DesiredAccess, (unsigned long)ObjectAttributes };
    return (NTSTATUS)DoNtSyscall(34, a, 3);
}

static inline NTSTATUS Nt_OpenDirectoryObject(HANDLE *DirectoryHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes) {
    unsigned long a[3] = { (unsigned long)DirectoryHandle, DesiredAccess, (unsigned long)ObjectAttributes };
    return (NTSTATUS)DoNtSyscall(113, a, 3);
}

static inline NTSTATUS Nt_QueryDirectoryObject(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length, UCHAR ReturnSingleEntry,
                                              UCHAR RestartScan, ULONG *Context, ULONG *ReturnLength) {
    unsigned long a[7] = { (unsigned long)DirectoryHandle, (unsigned long)Buffer, Length, ReturnSingleEntry, RestartScan, (unsigned long)Context, (unsigned long)ReturnLength };
    return (NTSTATUS)DoNtSyscall(146, a, 7);
}

static inline NTSTATUS Nt_CreateSymbolicLinkObject(HANDLE *LinkHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes, UNICODE_STRING *TargetName) {
    unsigned long a[4] = { (unsigned long)LinkHandle, DesiredAccess, (unsigned long)ObjectAttributes, (unsigned long)TargetName };
    return (NTSTATUS)DoNtSyscall(52, a, 4);
}

static inline NTSTATUS Nt_OpenSymbolicLinkObject(HANDLE *LinkHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes) {
    unsigned long a[3] = { (unsigned long)LinkHandle, DesiredAccess, (unsigned long)ObjectAttributes };
    return (NTSTATUS)DoNtSyscall(127, a, 3);
}

static inline NTSTATUS Nt_QuerySymbolicLinkObject(HANDLE LinkHandle, UNICODE_STRING *LinkTarget, ULONG *ReturnedLength) {
    unsigned long a[3] = { (unsigned long)LinkHandle, (unsigned long)LinkTarget, (unsigned long)ReturnedLength };
    return (NTSTATUS)DoNtSyscall(170, a, 3);
}

static inline NTSTATUS Nt_Close(HANDLE Handle) {
    unsigned long a[1] = { (unsigned long)Handle };
    return (NTSTATUS)DoNtSyscall(25, a, 1);
}

static inline NTSTATUS Nt_DuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle,
                                         HANDLE *TargetHandle, ULONG DesiredAccess, ULONG HandleAttributes, ULONG Options) {
    unsigned long a[7] = { (unsigned long)SourceProcessHandle, (unsigned long)SourceHandle, (unsigned long)TargetProcessHandle,
                           (unsigned long)TargetHandle, DesiredAccess, HandleAttributes, Options };
    return (NTSTATUS)DoNtSyscall(68, a, 7);
}

static inline NTSTATUS Nt_QueryObject(HANDLE Handle, ULONG ObjectInformationClass, PVOID ObjectInformation, ULONG Length, ULONG *ReturnLength) {
    unsigned long a[5] = { (unsigned long)Handle, ObjectInformationClass, (unsigned long)ObjectInformation, Length, (unsigned long)ReturnLength };
    return (NTSTATUS)DoNtSyscall(163, a, 5);
}

static inline NTSTATUS Nt_MakeTemporaryObject(HANDLE Handle) {
    unsigned long a[1] = { (unsigned long)Handle };
    return (NTSTATUS)DoNtSyscall(105, a, 1);
}

/* Memory Manager (Mm) */
#define MEM_COMMIT      0x1000
#define MEM_RESERVE     0x2000
#define MEM_DECOMMIT    0x4000
#define MEM_RELEASE     0x8000
#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_WRITECOPY         0x08
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_GUARD             0x100

typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    ULONG RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

static inline NTSTATUS Nt_AllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits,
                                               ULONG *RegionSize, ULONG AllocationType, ULONG Protect) {
    unsigned long a[6] = { (unsigned long)ProcessHandle, (unsigned long)BaseAddress, ZeroBits, (unsigned long)RegionSize, AllocationType, Protect };
    return (NTSTATUS)DoNtSyscall(17, a, 6);
}

static inline NTSTATUS Nt_FreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG *RegionSize, ULONG FreeType) {
    unsigned long a[4] = { (unsigned long)ProcessHandle, (unsigned long)BaseAddress, (unsigned long)RegionSize, FreeType };
    return (NTSTATUS)DoNtSyscall(83, a, 4);
}

static inline NTSTATUS Nt_ProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG *NumberOfBytesToProtect,
                                              ULONG NewAccessProtection, ULONG *OldAccessProtection) {
    unsigned long a[5] = { (unsigned long)ProcessHandle, (unsigned long)BaseAddress, (unsigned long)NumberOfBytesToProtect, NewAccessProtection, (unsigned long)OldAccessProtection };
    return (NTSTATUS)DoNtSyscall(137, a, 5);
}

static inline NTSTATUS Nt_QueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, ULONG MemoryInformationClass,
                                            PVOID MemoryInformation, ULONG MemoryInformationLength, ULONG *ReturnLength) {
    unsigned long a[6] = { (unsigned long)ProcessHandle, (unsigned long)BaseAddress, MemoryInformationClass, (unsigned long)MemoryInformation, MemoryInformationLength, (unsigned long)ReturnLength };
    return (NTSTATUS)DoNtSyscall(178, a, 6);
}

static inline NTSTATUS Nt_CreateSection(HANDLE *SectionHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes,
                                       LARGE_INTEGER *MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
    unsigned long a[7] = { (unsigned long)SectionHandle, DesiredAccess, (unsigned long)ObjectAttributes, (unsigned long)MaximumSize, SectionPageProtection, AllocationAttributes, (unsigned long)FileHandle };
    return (NTSTATUS)DoNtSyscall(50, a, 7);
}

static inline NTSTATUS Nt_OpenSection(HANDLE *SectionHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes) {
    unsigned long a[3] = { (unsigned long)SectionHandle, DesiredAccess, (unsigned long)ObjectAttributes };
    return (NTSTATUS)DoNtSyscall(125, a, 3);
}

static inline NTSTATUS NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits,
                                         ULONG CommitSize, LARGE_INTEGER *SectionOffset, ULONG *ViewSize, ULONG InheritDisposition,
                                         ULONG AllocationType, ULONG Win32Protect) {
    unsigned long a[10] = { (unsigned long)SectionHandle, (unsigned long)ProcessHandle, (unsigned long)BaseAddress, ZeroBits,
                            CommitSize, (unsigned long)SectionOffset, (unsigned long)ViewSize, InheritDisposition, AllocationType, Win32Protect };
    return (NTSTATUS)DoNtSyscall(108, a, 10);
}

static inline NTSTATUS Nt_UnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    unsigned long a[2] = { (unsigned long)ProcessHandle, (unsigned long)BaseAddress };
    return (NTSTATUS)DoNtSyscall(267, a, 2);
}

/* Executive & Synchronization (Ex / Ke) */
#define EVENT_QUERY_STATE     0x0001
#define EVENT_MODIFY_STATE    0x0002
#define EVENT_ALL_ACCESS      0x1F0003
typedef enum _EVENT_TYPE { NotificationEvent, SynchronizationEvent } EVENT_TYPE;

static inline NTSTATUS Nt_CreateEvent(HANDLE *EventHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes,
                                     EVENT_TYPE EventType, UCHAR InitialState) {
    unsigned long a[5] = { (unsigned long)EventHandle, DesiredAccess, (unsigned long)ObjectAttributes, (unsigned long)EventType, InitialState };
    return (NTSTATUS)DoNtSyscall(35, a, 5);
}

static inline NTSTATUS Nt_OpenEvent(HANDLE *EventHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes) {
    unsigned long a[3] = { (unsigned long)EventHandle, DesiredAccess, (unsigned long)ObjectAttributes };
    return (NTSTATUS)DoNtSyscall(114, a, 3);
}

static inline NTSTATUS Nt_SetEvent(HANDLE EventHandle, LONG *PreviousState) {
    unsigned long a[2] = { (unsigned long)EventHandle, (unsigned long)PreviousState };
    return (NTSTATUS)DoNtSyscall(219, a, 2);
}

static inline NTSTATUS Nt_ResetEvent(HANDLE EventHandle, LONG *PreviousState) {
    unsigned long a[2] = { (unsigned long)EventHandle, (unsigned long)PreviousState };
    return (NTSTATUS)DoNtSyscall(202, a, 2);
}

static inline NTSTATUS Nt_PulseEvent(HANDLE EventHandle, LONG *PreviousState) {
    unsigned long a[2] = { (unsigned long)EventHandle, (unsigned long)PreviousState };
    return (NTSTATUS)DoNtSyscall(138, a, 2);
}

static inline NTSTATUS Nt_CreateMutant(HANDLE *MutantHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes, UCHAR InitialOwner) {
    unsigned long a[4] = { (unsigned long)MutantHandle, DesiredAccess, (unsigned long)ObjectAttributes, InitialOwner };
    return (NTSTATUS)DoNtSyscall(43, a, 4);
}

static inline NTSTATUS Nt_OpenMutant(HANDLE *MutantHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes) {
    unsigned long a[3] = { (unsigned long)MutantHandle, DesiredAccess, (unsigned long)ObjectAttributes };
    return (NTSTATUS)DoNtSyscall(120, a, 3);
}

static inline NTSTATUS Nt_ReleaseMutant(HANDLE MutantHandle, LONG *PreviousCount) {
    unsigned long a[2] = { (unsigned long)MutantHandle, (unsigned long)PreviousCount };
    return (NTSTATUS)DoNtSyscall(188, a, 2);
}

static inline NTSTATUS Nt_CreateSemaphore(HANDLE *SemaphoreHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes, LONG InitialCount, LONG MaximumCount) {
    unsigned long a[5] = { (unsigned long)SemaphoreHandle, DesiredAccess, (unsigned long)ObjectAttributes, (unsigned long)InitialCount, (unsigned long)MaximumCount };
    return (NTSTATUS)DoNtSyscall(51, a, 5);
}

static inline NTSTATUS Nt_OpenSemaphore(HANDLE *SemaphoreHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes) {
    unsigned long a[3] = { (unsigned long)SemaphoreHandle, DesiredAccess, (unsigned long)ObjectAttributes };
    return (NTSTATUS)DoNtSyscall(126, a, 3);
}

static inline NTSTATUS Nt_ReleaseSemaphore(HANDLE SemaphoreHandle, LONG ReleaseCount, LONG *PreviousCount) {
    unsigned long a[3] = { (unsigned long)SemaphoreHandle, (unsigned long)ReleaseCount, (unsigned long)PreviousCount };
    return (NTSTATUS)DoNtSyscall(189, a, 3);
}

static inline NTSTATUS Nt_CreateTimer(HANDLE *TimerHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes, ULONG TimerType) {
    unsigned long a[4] = { (unsigned long)TimerHandle, DesiredAccess, (unsigned long)ObjectAttributes, TimerType };
    return (NTSTATUS)DoNtSyscall(54, a, 4);
}

static inline NTSTATUS Nt_SetTimer(HANDLE TimerHandle, LARGE_INTEGER *DueTime, PVOID TimerApcRoutine, PVOID TimerContext,
                                  UCHAR WakeTimer, LONG Period, UCHAR *PreviousState) {
    unsigned long a[7] = { (unsigned long)TimerHandle, (unsigned long)DueTime, (unsigned long)TimerApcRoutine, (unsigned long)TimerContext, WakeTimer, (unsigned long)Period, (unsigned long)PreviousState };
    return (NTSTATUS)DoNtSyscall(244, a, 7);
}

static inline NTSTATUS Nt_CancelTimer(HANDLE TimerHandle, UCHAR *CurrentState) {
    unsigned long a[2] = { (unsigned long)TimerHandle, (unsigned long)CurrentState };
    return (NTSTATUS)DoNtSyscall(23, a, 2);
}

static inline NTSTATUS Nt_WaitForSingleObject(HANDLE Handle, UCHAR Alertable, LARGE_INTEGER *Timeout) {
    unsigned long a[3] = { (unsigned long)Handle, Alertable, (unsigned long)Timeout };
    return (NTSTATUS)DoNtSyscall(271, a, 3);
}

static inline NTSTATUS Nt_WaitForMultipleObjects(ULONG Count, HANDLE *Handles, ULONG WaitType, UCHAR Alertable, LARGE_INTEGER *Timeout) {
    unsigned long a[5] = { Count, (unsigned long)Handles, WaitType, Alertable, (unsigned long)Timeout };
    return (NTSTATUS)DoNtSyscall(270, a, 5);
}

static inline NTSTATUS Nt_DelayExecution(UCHAR Alertable, LARGE_INTEGER *DelayInterval) {
    unsigned long a[2] = { Alertable, (unsigned long)DelayInterval };
    return (NTSTATUS)DoNtSyscall(59, a, 2);
}

/* Process and Thread Management (Ps) */
static inline NTSTATUS Nt_QueryInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, ULONG *ReturnLength) {
    unsigned long a[5] = { (unsigned long)ProcessHandle, ProcessInformationClass, (unsigned long)ProcessInformation, ProcessInformationLength, (unsigned long)ReturnLength };
    return (NTSTATUS)DoNtSyscall(154, a, 5);
}

static inline NTSTATUS Nt_QueryInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, ULONG *ReturnLength) {
    unsigned long a[5] = { (unsigned long)ThreadHandle, ThreadInformationClass, (unsigned long)ThreadInformation, ThreadInformationLength, (unsigned long)ReturnLength };
    return (NTSTATUS)DoNtSyscall(155, a, 5);
}

static inline NTSTATUS Nt_SuspendThread(HANDLE ThreadHandle, ULONG *PreviousSuspendCount) {
    unsigned long a[2] = { (unsigned long)ThreadHandle, (unsigned long)PreviousSuspendCount };
    return (NTSTATUS)DoNtSyscall(254, a, 2);
}

static inline NTSTATUS Nt_ResumeThread(HANDLE ThreadHandle, ULONG *PreviousSuspendCount) {
    unsigned long a[2] = { (unsigned long)ThreadHandle, (unsigned long)PreviousSuspendCount };
    return (NTSTATUS)DoNtSyscall(206, a, 2);
}

static inline NTSTATUS Nt_AlertThread(HANDLE ThreadHandle) {
    unsigned long a[1] = { (unsigned long)ThreadHandle };
    return (NTSTATUS)DoNtSyscall(13, a, 1);
}

static inline NTSTATUS Nt_YieldExecution(void) {
    return (NTSTATUS)DoNtSyscall(278, NULL, 0);
}

/* Local Procedure Calls (Lpc) */
typedef struct _PORT_MESSAGE {
    union {
        struct {
            USHORT DataLength;
            USHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            USHORT Type;
            USHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    CLIENT_ID ClientId;
    ULONG MessageId;
    union {
        ULONG ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE, *PPORT_MESSAGE;

static inline NTSTATUS Nt_CreatePort(HANDLE *PortHandle, OBJECT_ATTRIBUTES *ObjectAttributes, ULONG MaxConnectionInfoLength, ULONG MaxMessageLength, ULONG SetMaxPoolSize) {
    unsigned long a[5] = { (unsigned long)PortHandle, (unsigned long)ObjectAttributes, MaxConnectionInfoLength, MaxMessageLength, SetMaxPoolSize };
    return (NTSTATUS)DoNtSyscall(46, a, 5);
}

static inline NTSTATUS Nt_CreateWaitablePort(HANDLE *PortHandle, OBJECT_ATTRIBUTES *ObjectAttributes, ULONG MaxConnectionInfoLength, ULONG MaxMessageLength, ULONG SetMaxPoolSize) {
    unsigned long a[5] = { (unsigned long)PortHandle, (unsigned long)ObjectAttributes, MaxConnectionInfoLength, MaxMessageLength, SetMaxPoolSize };
    return (NTSTATUS)DoNtSyscall(56, a, 5);
}

static inline NTSTATUS Nt_RequestPort(HANDLE PortHandle, PORT_MESSAGE *RequestMessage) {
    unsigned long a[2] = { (unsigned long)PortHandle, (unsigned long)RequestMessage };
    return (NTSTATUS)DoNtSyscall(199, a, 2);
}

/* I/O Manager & Filesystem (Io) */
#define FILE_READ_DATA            0x0001
#define FILE_WRITE_DATA           0x0002
#define FILE_APPEND_DATA          0x0004
#define FILE_READ_ATTRIBUTES      0x0080
#define FILE_WRITE_ATTRIBUTES     0x0100
#define FILE_LIST_DIRECTORY       0x0001
#define FILE_SHARE_READ           0x00000001
#define FILE_SHARE_WRITE          0x00000002
#define FILE_SHARE_DELETE         0x00000004
#define FILE_SUPERSEDE            0x00000000
#define FILE_OPEN                 0x00000001
#define FILE_CREATE               0x00000002
#define FILE_OPEN_IF              0x00000003
#define FILE_OVERWRITE            0x00000004
#define FILE_OVERWRITE_IF         0x00000005
#define FILE_DIRECTORY_FILE       0x00000001
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE   0x00000040
#define SYNCHRONIZE               0x00100000L

static inline NTSTATUS Nt_CreateFile(HANDLE *FileHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes,
                                    IO_STATUS_BLOCK *IoStatusBlock, LARGE_INTEGER *AllocationSize, ULONG FileAttributes,
                                    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    unsigned long a[11] = { (unsigned long)FileHandle, DesiredAccess, (unsigned long)ObjectAttributes, (unsigned long)IoStatusBlock,
                            (unsigned long)AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, (unsigned long)EaBuffer, EaLength };
    return (NTSTATUS)DoNtSyscall(37, a, 11);
}

static inline NTSTATUS Nt_OpenFile(HANDLE *FileHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes,
                                  IO_STATUS_BLOCK *IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    unsigned long a[6] = { (unsigned long)FileHandle, DesiredAccess, (unsigned long)ObjectAttributes, (unsigned long)IoStatusBlock, ShareAccess, OpenOptions };
    return (NTSTATUS)DoNtSyscall(116, a, 6);
}

static inline NTSTATUS Nt_ReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
                                  IO_STATUS_BLOCK *IoStatusBlock, PVOID Buffer, ULONG Length, LARGE_INTEGER *ByteOffset, ULONG *Key) {
    unsigned long a[9] = { (unsigned long)FileHandle, (unsigned long)Event, (unsigned long)ApcRoutine, (unsigned long)ApcContext,
                           (unsigned long)IoStatusBlock, (unsigned long)Buffer, Length, (unsigned long)ByteOffset, (unsigned long)Key };
    return (NTSTATUS)DoNtSyscall(183, a, 9);
}

static inline NTSTATUS Nt_WriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
                                   IO_STATUS_BLOCK *IoStatusBlock, PVOID Buffer, ULONG Length, LARGE_INTEGER *ByteOffset, ULONG *Key) {
    unsigned long a[9] = { (unsigned long)FileHandle, (unsigned long)Event, (unsigned long)ApcRoutine, (unsigned long)ApcContext,
                           (unsigned long)IoStatusBlock, (unsigned long)Buffer, Length, (unsigned long)ByteOffset, (unsigned long)Key };
    return (NTSTATUS)DoNtSyscall(274, a, 9);
}

static inline NTSTATUS Nt_DeleteFile(OBJECT_ATTRIBUTES *ObjectAttributes) {
    unsigned long a[1] = { (unsigned long)ObjectAttributes };
    return (NTSTATUS)DoNtSyscall(62, a, 1);
}

static inline NTSTATUS Nt_FlushBuffersFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock) {
    unsigned long a[2] = { (unsigned long)FileHandle, (unsigned long)IoStatusBlock };
    return (NTSTATUS)DoNtSyscall(77, a, 2);
}

static inline NTSTATUS Nt_QueryInformationFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, PVOID FileInformation, ULONG Length, ULONG FileInformationClass) {
    unsigned long a[5] = { (unsigned long)FileHandle, (unsigned long)IoStatusBlock, (unsigned long)FileInformation, Length, FileInformationClass };
    return (NTSTATUS)DoNtSyscall(151, a, 5);
}

static inline NTSTATUS Nt_SetInformationFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, PVOID FileInformation, ULONG Length, ULONG FileInformationClass) {
    unsigned long a[5] = { (unsigned long)FileHandle, (unsigned long)IoStatusBlock, (unsigned long)FileInformation, Length, FileInformationClass };
    return (NTSTATUS)DoNtSyscall(224, a, 5);
}

static inline NTSTATUS Nt_QueryVolumeInformationFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, PVOID FsInformation, ULONG Length, ULONG FsInformationClass) {
    unsigned long a[5] = { (unsigned long)FileHandle, (unsigned long)IoStatusBlock, (unsigned long)FsInformation, Length, FsInformationClass };
    return (NTSTATUS)DoNtSyscall(179, a, 5);
}

static inline NTSTATUS Nt_DeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
                                            IO_STATUS_BLOCK *IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer,
                                            ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
    unsigned long a[10] = { (unsigned long)FileHandle, (unsigned long)Event, (unsigned long)ApcRoutine, (unsigned long)ApcContext,
                            (unsigned long)IoStatusBlock, IoControlCode, (unsigned long)InputBuffer, InputBufferLength,
                            (unsigned long)OutputBuffer, OutputBufferLength };
    return (NTSTATUS)DoNtSyscall(66, a, 10);
}

static inline NTSTATUS Nt_CreateIoCompletion(HANDLE *IoCompletionHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes, ULONG Count) {
    unsigned long a[4] = { (unsigned long)IoCompletionHandle, DesiredAccess, (unsigned long)ObjectAttributes, Count };
    return (NTSTATUS)DoNtSyscall(38, a, 4);
}

static inline NTSTATUS Nt_SetIoCompletion(HANDLE IoCompletionHandle, ULONG_PTR KeyContext, PVOID ApcContext, NTSTATUS IoStatus, ULONG_PTR IoStatusInformation) {
    unsigned long a[5] = { (unsigned long)IoCompletionHandle, (unsigned long)KeyContext, (unsigned long)ApcContext, (unsigned long)IoStatus, (unsigned long)IoStatusInformation };
    return (NTSTATUS)DoNtSyscall(232, a, 5);
}

static inline NTSTATUS Nt_RemoveIoCompletion(HANDLE IoCompletionHandle, PVOID KeyContext, PVOID *ApcContext, IO_STATUS_BLOCK *IoStatusBlock, LARGE_INTEGER *Timeout) {
    unsigned long a[5] = { (unsigned long)IoCompletionHandle, (unsigned long)KeyContext, (unsigned long)ApcContext, (unsigned long)IoStatusBlock, (unsigned long)Timeout };
    return (NTSTATUS)DoNtSyscall(190, a, 5);
}

/* Security Reference Monitor (Se) */
#define TOKEN_ASSIGN_PRIMARY    0x0001
#define TOKEN_DUPLICATE         0x0002
#define TOKEN_IMPERSONATE       0x0004
#define TOKEN_QUERY             0x0008
#define TOKEN_QUERY_SOURCE      0x0010
#define TOKEN_ADJUST_PRIVILEGES 0x0020
#define TOKEN_ADJUST_GROUPS     0x0040
#define TOKEN_ADJUST_DEFAULT    0x0080
#define TOKEN_ADJUST_SESSIONID  0x0100

static inline NTSTATUS Nt_OpenProcessToken(HANDLE ProcessHandle, ULONG DesiredAccess, HANDLE *TokenHandle) {
    unsigned long a[3] = { (unsigned long)ProcessHandle, DesiredAccess, (unsigned long)TokenHandle };
    return (NTSTATUS)DoNtSyscall(123, a, 3);
}

static inline NTSTATUS Nt_OpenThreadToken(HANDLE ThreadHandle, ULONG DesiredAccess, UCHAR OpenAsSelf, HANDLE *TokenHandle) {
    unsigned long a[4] = { (unsigned long)ThreadHandle, DesiredAccess, OpenAsSelf, (unsigned long)TokenHandle };
    return (NTSTATUS)DoNtSyscall(129, a, 4);
}

static inline NTSTATUS Nt_QueryInformationToken(HANDLE TokenHandle, ULONG TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, ULONG *ReturnLength) {
    unsigned long a[5] = { (unsigned long)TokenHandle, TokenInformationClass, (unsigned long)TokenInformation, TokenInformationLength, (unsigned long)ReturnLength };
    return (NTSTATUS)DoNtSyscall(156, a, 5);
}

static inline NTSTATUS Nt_DuplicateToken(HANDLE ExistingTokenHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes,
                                        UCHAR EffectiveOnly, ULONG TokenType, HANDLE *NewTokenHandle) {
    unsigned long a[6] = { (unsigned long)ExistingTokenHandle, DesiredAccess, (unsigned long)ObjectAttributes, EffectiveOnly, TokenType, (unsigned long)NewTokenHandle };
    return (NTSTATUS)DoNtSyscall(69, a, 6);
}

/* Configuration Manager (Cm - Registry) */
#define KEY_QUERY_VALUE         0x0001
#define KEY_SET_VALUE           0x0002
#define KEY_CREATE_SUB_KEY      0x0004
#define KEY_ENUMERATE_SUB_KEYS  0x0008
#define KEY_NOTIFY              0x0010
#define KEY_CREATE_LINK         0x0020
#define KEY_READ                0x20019
#define KEY_WRITE               0x20006
#define KEY_ALL_ACCESS          0xF003F

#define REG_NONE                0
#define REG_SZ                  1
#define REG_EXPAND_SZ           2
#define REG_BINARY              3
#define REG_DWORD               4
#define REG_MULTI_SZ            7

static inline NTSTATUS Nt_OpenKey(HANDLE *KeyHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes) {
    unsigned long a[3] = { (unsigned long)KeyHandle, DesiredAccess, (unsigned long)ObjectAttributes };
    return (NTSTATUS)DoNtSyscall(119, a, 3);
}

static inline NTSTATUS Nt_CreateKey(HANDLE *KeyHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes,
                                   ULONG TitleIndex, UNICODE_STRING *Class, ULONG CreateOptions, ULONG *Disposition) {
    unsigned long a[7] = { (unsigned long)KeyHandle, DesiredAccess, (unsigned long)ObjectAttributes, TitleIndex, (unsigned long)Class, CreateOptions, (unsigned long)Disposition };
    return (NTSTATUS)DoNtSyscall(41, a, 7);
}

static inline NTSTATUS Nt_QueryKey(HANDLE KeyHandle, ULONG KeyInformationClass, PVOID KeyInformation, ULONG Length, ULONG *ResultLength) {
    unsigned long a[5] = { (unsigned long)KeyHandle, KeyInformationClass, (unsigned long)KeyInformation, Length, (unsigned long)ResultLength };
    return (NTSTATUS)DoNtSyscall(160, a, 5);
}

static inline NTSTATUS Nt_EnumerateKey(HANDLE KeyHandle, ULONG Index, ULONG KeyInformationClass, PVOID KeyInformation, ULONG Length, ULONG *ResultLength) {
    unsigned long a[6] = { (unsigned long)KeyHandle, Index, KeyInformationClass, (unsigned long)KeyInformation, Length, (unsigned long)ResultLength };
    return (NTSTATUS)DoNtSyscall(71, a, 6);
}

static inline NTSTATUS Nt_SetValueKey(HANDLE KeyHandle, UNICODE_STRING *ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize) {
    unsigned long a[6] = { (unsigned long)KeyHandle, (unsigned long)ValueName, TitleIndex, Type, (unsigned long)Data, DataSize };
    return (NTSTATUS)DoNtSyscall(247, a, 6);
}

static inline NTSTATUS Nt_QueryValueKey(HANDLE KeyHandle, UNICODE_STRING *ValueName, ULONG KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, ULONG *ResultLength) {
    unsigned long a[6] = { (unsigned long)KeyHandle, (unsigned long)ValueName, KeyValueInformationClass, (unsigned long)KeyValueInformation, Length, (unsigned long)ResultLength };
    return (NTSTATUS)DoNtSyscall(177, a, 6);
}

static inline NTSTATUS Nt_EnumerateValueKey(HANDLE KeyHandle, ULONG Index, ULONG KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, ULONG *ResultLength) {
    unsigned long a[6] = { (unsigned long)KeyHandle, Index, KeyValueInformationClass, (unsigned long)KeyValueInformation, Length, (unsigned long)ResultLength };
    return (NTSTATUS)DoNtSyscall(73, a, 6);
}

static inline NTSTATUS Nt_DeleteValueKey(HANDLE KeyHandle, UNICODE_STRING *ValueName) {
    unsigned long a[2] = { (unsigned long)KeyHandle, (unsigned long)ValueName };
    return (NTSTATUS)DoNtSyscall(65, a, 2);
}

static inline NTSTATUS Nt_DeleteKey(HANDLE KeyHandle) {
    unsigned long a[1] = { (unsigned long)KeyHandle };
    return (NTSTATUS)DoNtSyscall(63, a, 1);
}

static inline NTSTATUS Nt_FlushKey(HANDLE KeyHandle) {
    unsigned long a[1] = { (unsigned long)KeyHandle };
    return (NTSTATUS)DoNtSyscall(79, a, 1);
}

/* System & Time Information (Sys) */
static inline NTSTATUS Nt_QuerySystemTime(LARGE_INTEGER *SystemTime) {
    unsigned long a[1] = { (unsigned long)SystemTime };
    return (NTSTATUS)DoNtSyscall(174, a, 1);
}

static inline NTSTATUS Nt_QueryTimerResolution(ULONG *MaximumTime, ULONG *MinimumTime, ULONG *CurrentTime) {
    unsigned long a[3] = { (unsigned long)MaximumTime, (unsigned long)MinimumTime, (unsigned long)CurrentTime };
    return (NTSTATUS)DoNtSyscall(176, a, 3);
}

static inline NTSTATUS Nt_QueryPerformanceCounter(LARGE_INTEGER *PerformanceCounter, LARGE_INTEGER *PerformanceFrequency) {
    unsigned long a[2] = { (unsigned long)PerformanceCounter, (unsigned long)PerformanceFrequency };
    return (NTSTATUS)DoNtSyscall(165, a, 2);
}

static inline NTSTATUS Nt_QuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, ULONG *ReturnLength) {
    unsigned long a[4] = { SystemInformationClass, (unsigned long)SystemInformation, SystemInformationLength, (unsigned long)ReturnLength };
    return (NTSTATUS)DoNtSyscall(173, a, 4);
}

#endif /* NT_SYSCALL_DEFS_H */
