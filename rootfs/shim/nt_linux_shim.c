/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rootfs/shim/nt_linux_shim.c
 * Linux i386 to Windows NT Native System Call Translation Bridge
 * Supports MUSL libc 1.2.5, BusyBox 1.36.1, dynamic Alpine i386 ELF binaries (Xvfb, XFCE 4.18),
 * Cross-Process Shared IPC (UNIX/INET Sockets, Pipes, EventFD, SysV SHM), and Multi-Process/Thread ELF Execution
 */

#include "nt_linux_shim.h"

#define NT_SUCCESS(Status) (((long)(Status)) >= 0)

typedef void *HANDLE;
typedef long NTSTATUS;

typedef struct _UNICODE_STRING {
    unsigned short Length;
    unsigned short MaximumLength;
    unsigned short *Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    unsigned long Length;
    HANDLE RootDirectory;
    UNICODE_STRING *ObjectName;
    unsigned long Attributes;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        void *Pointer;
    };
    unsigned long Information;
} IO_STATUS_BLOCK;

typedef struct _LARGE_INTEGER {
    union {
        struct {
            unsigned long LowPart;
            long HighPart;
        };
        s64 QuadPart;
    };
} LARGE_INTEGER;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    void *PebBaseAddress;
    unsigned long AffinityMask;
    long BasePriority;
    unsigned long UniqueProcessId;
    unsigned long InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct _INITIAL_TEB {
    struct {
        void *OldStackBase;
        void *OldStackLimit;
    } OldInitialTeb;
    void *StackBase;
    void *StackLimit;
    void *StackAllocationBase;
} INITIAL_TEB;

typedef struct _FLOATING_SAVE_AREA {
    unsigned long ControlWord;
    unsigned long StatusWord;
    unsigned long TagWord;
    unsigned long ErrorOffset;
    unsigned long ErrorSelector;
    unsigned long DataOffset;
    unsigned long DataSelector;
    unsigned char RegisterArea[80];
    unsigned long Cr0NpxState;
} FLOATING_SAVE_AREA;

typedef struct _CONTEXT {
    unsigned long ContextFlags;
    unsigned long Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    FLOATING_SAVE_AREA FloatSave;
    unsigned long SegGs, SegFs, SegEs, SegDs;
    unsigned long Edi, Esi, Ebx, Edx, Ecx, Eax;
    unsigned long Ebp, Eip, SegCs, EFlags, Esp, SegSs;
    unsigned char ExtendedRegisters[512];
} CONTEXT;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    unsigned long NumberOfLinks;
    unsigned char DeletePending;
    unsigned char Directory;
} FILE_STANDARD_INFORMATION;

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    unsigned long FileAttributes;
} FILE_BASIC_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION {
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION {
    unsigned char DeleteFile;
} FILE_DISPOSITION_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
    unsigned long NextEntryOffset;
    unsigned long FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    unsigned long FileAttributes;
    unsigned long FileNameLength;
    unsigned long EaSize;
    char ShortNameLength;
    unsigned short ShortName[12];
    unsigned short FileName[1];
} FILE_BOTH_DIR_INFORMATION;

typedef struct _KEYBOARD_INPUT_DATA {
    unsigned short UnitId;
    unsigned short MakeCode;
    unsigned short Flags;
    unsigned short Reserved;
    unsigned long  ExtraInformation;
} KEYBOARD_INPUT_DATA;

typedef struct _MOUSE_INPUT_DATA_PKT {
    long          DeltaX;
    long          DeltaY;
    unsigned long Buttons;
    unsigned long RawStatus;
} MOUSE_INPUT_DATA_PKT;

#define KEY_MAKE  0
#define KEY_BREAK 1
#define KEY_E0    2
#define KEY_E1    4

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define OBJ_OPENIF           0x00000080L

#define FILE_READ_DATA        0x0001
#define FILE_WRITE_DATA       0x0002
#define FILE_APPEND_DATA      0x0004
#define FILE_LIST_DIRECTORY   0x0001
#define FILE_EXECUTE          0x0020
#define FILE_READ_ATTRIBUTES  0x0080
#define FILE_WRITE_ATTRIBUTES 0x0100
#define SYNCHRONIZE           0x00100000L
#define DELETE                0x00010000L

#define FILE_SHARE_READ       0x00000001
#define FILE_SHARE_WRITE      0x00000002
#define FILE_SHARE_DELETE     0x00000004

#define FILE_SUPERSEDE           0x00000000
#define FILE_OPEN                0x00000001
#define FILE_CREATE              0x00000002
#define FILE_OPEN_IF             0x00000003
#define FILE_OVERWRITE           0x00000004
#define FILE_OVERWRITE_IF        0x00000005

#define FILE_DIRECTORY_FILE            0x00000001
#define FILE_NON_DIRECTORY_FILE        0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT   0x00000020

#define MEM_COMMIT   0x1000
#define MEM_RESERVE  0x2000
#define MEM_DECOMMIT 0x4000
#define MEM_RELEASE  0x8000

#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40

#define SEC_IMAGE              0x01000000
#define SEC_COMMIT             0x08000000
#define SECTION_ALL_ACCESS     0x000F001F
#define PROCESS_ALL_ACCESS     0x001F0FFF
#define THREAD_ALL_ACCESS      0x001F03FF

#define FileBasicInformation         4
#define FileStandardInformation      5
#define FilePositionInformation     14
#define FileDispositionInformation  13
#define FileBothDirectoryInformation 3

extern long DoNtSyscall(unsigned long id, void *args, unsigned int num_args);
extern void __kernel_vsyscall(void);

static NTSTATUS Nt_AllocateVirtualMemory(HANDLE hProcess, void **BaseAddress, unsigned long ZeroBits,
                                         unsigned long *RegionSize, unsigned long AllocationType, unsigned long Protect) {
    unsigned long a[6] = { (unsigned long)hProcess, (unsigned long)BaseAddress, ZeroBits, (unsigned long)RegionSize, AllocationType, Protect };
    return (NTSTATUS)DoNtSyscall(17, a, 6);
}

static NTSTATUS Nt_FreeVirtualMemory(HANDLE hProcess, void **BaseAddress, unsigned long *RegionSize, unsigned long FreeType) {
    unsigned long a[4] = { (unsigned long)hProcess, (unsigned long)BaseAddress, (unsigned long)RegionSize, FreeType };
    return (NTSTATUS)DoNtSyscall(83, a, 4);
}

static NTSTATUS Nt_ProtectVirtualMemory(HANDLE hProcess, void **BaseAddress, unsigned long *RegionSize,
                                        unsigned long NewProtect, unsigned long *OldProtect) {
    unsigned long a[5] = { (unsigned long)hProcess, (unsigned long)BaseAddress, (unsigned long)RegionSize, NewProtect, (unsigned long)OldProtect };
    return (NTSTATUS)DoNtSyscall(137, a, 5);
}

static NTSTATUS Nt_CreateFile(HANDLE *FileHandle, unsigned long DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes,
                              IO_STATUS_BLOCK *IoStatusBlock, LARGE_INTEGER *AllocationSize, unsigned long FileAttributes,
                              unsigned long ShareAccess, unsigned long CreateDisposition, unsigned long CreateOptions,
                              void *EaBuffer, unsigned long EaLength) {
    unsigned long a[11] = {
        (unsigned long)FileHandle, DesiredAccess, (unsigned long)ObjectAttributes, (unsigned long)IoStatusBlock,
        (unsigned long)AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions,
        (unsigned long)EaBuffer, EaLength
    };
    return (NTSTATUS)DoNtSyscall(37, a, 11);
}

static NTSTATUS Nt_OpenFile(HANDLE *FileHandle, unsigned long DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes,
                            IO_STATUS_BLOCK *IoStatusBlock, unsigned long ShareAccess, unsigned long OpenOptions) {
    unsigned long a[6] = { (unsigned long)FileHandle, DesiredAccess, (unsigned long)ObjectAttributes, (unsigned long)IoStatusBlock, ShareAccess, OpenOptions };
    return (NTSTATUS)DoNtSyscall(116, a, 6);
}

static NTSTATUS Nt_ReadFile(HANDLE FileHandle, HANDLE Event, void *ApcRoutine, void *ApcContext,
                            IO_STATUS_BLOCK *IoStatusBlock, void *Buffer, unsigned long Length,
                            LARGE_INTEGER *ByteOffset, unsigned long *Key) {
    unsigned long a[9] = {
        (unsigned long)FileHandle, (unsigned long)Event, (unsigned long)ApcRoutine, (unsigned long)ApcContext,
        (unsigned long)IoStatusBlock, (unsigned long)Buffer, Length, (unsigned long)ByteOffset, (unsigned long)Key
    };
    return (NTSTATUS)DoNtSyscall(183, a, 9);
}

static NTSTATUS Nt_WriteFile(HANDLE FileHandle, HANDLE Event, void *ApcRoutine, void *ApcContext,
                             IO_STATUS_BLOCK *IoStatusBlock, void *Buffer, unsigned long Length,
                             LARGE_INTEGER *ByteOffset, unsigned long *Key) {
    unsigned long a[9] = {
        (unsigned long)FileHandle, (unsigned long)Event, (unsigned long)ApcRoutine, (unsigned long)ApcContext,
        (unsigned long)IoStatusBlock, (unsigned long)Buffer, Length, (unsigned long)ByteOffset, (unsigned long)Key
    };
    return (NTSTATUS)DoNtSyscall(274, a, 9);
}

static NTSTATUS Nt_DeviceIoControlFile(HANDLE FileHandle, HANDLE Event, void *ApcRoutine, void *ApcContext,
                                       IO_STATUS_BLOCK *IoStatusBlock, unsigned long IoControlCode,
                                       void *InputBuffer, unsigned long InputBufferLength,
                                       void *OutputBuffer, unsigned long OutputBufferLength) {
    unsigned long a[10] = {
        (unsigned long)FileHandle, (unsigned long)Event, (unsigned long)ApcRoutine, (unsigned long)ApcContext,
        (unsigned long)IoStatusBlock, IoControlCode, (unsigned long)InputBuffer, InputBufferLength,
        (unsigned long)OutputBuffer, OutputBufferLength
    };
    return (NTSTATUS)DoNtSyscall(66, a, 10);
}

static NTSTATUS Nt_Close(HANDLE Handle) {
    unsigned long a[1] = { (unsigned long)Handle };
    return (NTSTATUS)DoNtSyscall(25, a, 1);
}

static NTSTATUS Nt_QueryInformationFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, void *FileInformation,
                                        unsigned long Length, unsigned long FileInformationClass) {
    unsigned long a[5] = { (unsigned long)FileHandle, (unsigned long)IoStatusBlock, (unsigned long)FileInformation, Length, FileInformationClass };
    return (NTSTATUS)DoNtSyscall(151, a, 5);
}

static NTSTATUS Nt_SetInformationFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, void *FileInformation,
                                      unsigned long Length, unsigned long FileInformationClass) {
    unsigned long a[5] = { (unsigned long)FileHandle, (unsigned long)IoStatusBlock, (unsigned long)FileInformation, Length, FileInformationClass };
    return (NTSTATUS)DoNtSyscall(224, a, 5);
}

static NTSTATUS Nt_QueryDirectoryFile(HANDLE FileHandle, HANDLE Event, void *ApcRoutine, void *ApcContext,
                                      IO_STATUS_BLOCK *IoStatusBlock, void *FileInformation, unsigned long Length,
                                      unsigned long FileInformationClass, unsigned char ReturnSingleEntry,
                                      UNICODE_STRING *FileName, unsigned char RestartScan) {
    unsigned long a[11] = {
        (unsigned long)FileHandle, (unsigned long)Event, (unsigned long)ApcRoutine, (unsigned long)ApcContext,
        (unsigned long)IoStatusBlock, (unsigned long)FileInformation, Length, FileInformationClass,
        (unsigned long)ReturnSingleEntry, (unsigned long)FileName, (unsigned long)RestartScan
    };
    return (NTSTATUS)DoNtSyscall(145, a, 11);
}

static NTSTATUS Nt_TerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    unsigned long a[2] = { (unsigned long)ProcessHandle, (unsigned long)ExitStatus };
    return (NTSTATUS)DoNtSyscall(257, a, 2);
}

static NTSTATUS Nt_TerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus) {
    unsigned long a[2] = { (unsigned long)ThreadHandle, (unsigned long)ExitStatus };
    return (NTSTATUS)DoNtSyscall(258, a, 2);
}

static NTSTATUS Nt_DelayExecution(unsigned char Alertable, LARGE_INTEGER *DelayInterval) {
    unsigned long a[2] = { (unsigned long)Alertable, (unsigned long)DelayInterval };
    return (NTSTATUS)DoNtSyscall(59, a, 2);
}

static NTSTATUS Nt_DisplayString(UNICODE_STRING *String) {
    unsigned long a[1] = { (unsigned long)String };
    return (NTSTATUS)DoNtSyscall(67, a, 1);
}

static NTSTATUS Nt_CreateSection(HANDLE *SectionHandle, unsigned long DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes,
                                 LARGE_INTEGER *MaximumSize, unsigned long SectionPageProtection,
                                 unsigned long AllocationAttributes, HANDLE FileHandle) {
    unsigned long a[7] = {
        (unsigned long)SectionHandle, DesiredAccess, (unsigned long)ObjectAttributes,
        (unsigned long)MaximumSize, SectionPageProtection, AllocationAttributes, (unsigned long)FileHandle
    };
    return (NTSTATUS)DoNtSyscall(50, a, 7);
}

static NTSTATUS Nt_OpenSection(HANDLE *SectionHandle, unsigned long DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes) {
    unsigned long a[3] = { (unsigned long)SectionHandle, DesiredAccess, (unsigned long)ObjectAttributes };
    return (NTSTATUS)DoNtSyscall(125, a, 3);
}

static NTSTATUS Nt_MapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, void **BaseAddress,
                                    unsigned long ZeroBits, unsigned long CommitSize, LARGE_INTEGER *SectionOffset,
                                    unsigned long *ViewSize, unsigned long InheritDisposition,
                                    unsigned long AllocationType, unsigned long Protect) {
    unsigned long a[10] = {
        (unsigned long)SectionHandle, (unsigned long)ProcessHandle, (unsigned long)BaseAddress,
        ZeroBits, CommitSize, (unsigned long)SectionOffset, (unsigned long)ViewSize,
        InheritDisposition, AllocationType, Protect
    };
    return (NTSTATUS)DoNtSyscall(108, a, 10);
}

static NTSTATUS Nt_UnmapViewOfSection(HANDLE ProcessHandle, void *BaseAddress) {
    unsigned long a[2] = { (unsigned long)ProcessHandle, (unsigned long)BaseAddress };
    return (NTSTATUS)DoNtSyscall(267, a, 2);
}

static NTSTATUS Nt_CreateProcessEx(HANDLE *ProcessHandle, unsigned long DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes,
                                   HANDLE ParentProcess, unsigned long Flags, HANDLE SectionHandle,
                                   HANDLE DebugPort, HANDLE ExceptionPort, unsigned long JobMemberLevel) {
    unsigned long a[9] = {
        (unsigned long)ProcessHandle, DesiredAccess, (unsigned long)ObjectAttributes,
        (unsigned long)ParentProcess, Flags, (unsigned long)SectionHandle,
        (unsigned long)DebugPort, (unsigned long)ExceptionPort, JobMemberLevel
    };
    return (NTSTATUS)DoNtSyscall(48, a, 9);
}

static NTSTATUS Nt_CreateProcess(HANDLE *ProcessHandle, unsigned long DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes,
                                 HANDLE ParentProcess, unsigned char InheritObjectTable, HANDLE SectionHandle,
                                 HANDLE DebugPort, HANDLE ExceptionPort) {
    unsigned long a[8] = {
        (unsigned long)ProcessHandle, DesiredAccess, (unsigned long)ObjectAttributes,
        (unsigned long)ParentProcess, (unsigned long)InheritObjectTable, (unsigned long)SectionHandle,
        (unsigned long)DebugPort, (unsigned long)ExceptionPort
    };
    return (NTSTATUS)DoNtSyscall(47, a, 8);
}

static NTSTATUS Nt_CreateThread(HANDLE *ThreadHandle, unsigned long DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes,
                                HANDLE ProcessHandle, CLIENT_ID *ClientId, CONTEXT *ThreadContext,
                                INITIAL_TEB *InitialTeb, unsigned char CreateSuspended) {
    unsigned long a[8] = {
        (unsigned long)ThreadHandle, DesiredAccess, (unsigned long)ObjectAttributes,
        (unsigned long)ProcessHandle, (unsigned long)ClientId, (unsigned long)ThreadContext,
        (unsigned long)InitialTeb, (unsigned long)CreateSuspended
    };
    return (NTSTATUS)DoNtSyscall(53, a, 8);
}

static NTSTATUS Nt_QueryInformationProcess(HANDLE ProcessHandle, unsigned long ProcessInformationClass,
                                           void *ProcessInformation, unsigned long ProcessInformationLength,
                                           unsigned long *ReturnLength) {
    unsigned long a[5] = {
        (unsigned long)ProcessHandle, ProcessInformationClass, (unsigned long)ProcessInformation,
        ProcessInformationLength, (unsigned long)ReturnLength
    };
    return (NTSTATUS)DoNtSyscall(154, a, 5);
}

static NTSTATUS Nt_WaitForSingleObject(HANDLE Handle, unsigned char Alertable, LARGE_INTEGER *Timeout) {
    unsigned long a[3] = { (unsigned long)Handle, (unsigned long)Alertable, (unsigned long)Timeout };
    return (NTSTATUS)DoNtSyscall(271, a, 3);
}

static NTSTATUS Nt_WriteVirtualMemory(HANDLE ProcessHandle, void *BaseAddress, const void *Buffer,
                                      unsigned long NumberOfBytesToWrite, unsigned long *NumberOfBytesWritten) {
    unsigned long a[5] = {
        (unsigned long)ProcessHandle, (unsigned long)BaseAddress, (unsigned long)Buffer,
        NumberOfBytesToWrite, (unsigned long)NumberOfBytesWritten
    };
    return (NTSTATUS)DoNtSyscall(277, a, 5);
}

static NTSTATUS Nt_DuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle,
                                   HANDLE TargetProcessHandle, HANDLE *TargetHandle,
                                   unsigned long DesiredAccess, unsigned long HandleAttributes,
                                   unsigned long Options) {
    unsigned long a[7] = {
        (unsigned long)SourceProcessHandle, (unsigned long)SourceHandle,
        (unsigned long)TargetProcessHandle, (unsigned long)TargetHandle,
        DesiredAccess, HandleAttributes, Options
    };
    return (NTSTATUS)DoNtSyscall(68, a, 7);
}

/* ========================================================================= */
/* Cross-Process Shared IPC Section (\BaseNamedObjects\LxssIpcSection)       */
/* ========================================================================= */
#define MAX_IPC_PIPES      64
#define IPC_PIPE_BUF_SIZE  32768
#define MAX_IPC_LISTENERS  32
#define MAX_IPC_CONNS      48
#define IPC_RING_SIZE      65536
#define MAX_IPC_EVENTFDS   32
#define MAX_IPC_SHMS       32

typedef struct _SHIM_IPC_PIPE {
    volatile long lock;
    unsigned char buf[IPC_PIPE_BUF_SIZE];
    volatile unsigned int head;
    volatile unsigned int tail;
    volatile unsigned int count;
    volatile int read_refs;
    volatile int write_refs;
} SHIM_IPC_PIPE;

typedef struct _SHIM_IPC_RING {
    volatile long lock;
    unsigned char buf[IPC_RING_SIZE];
    volatile unsigned int head;
    volatile unsigned int tail;
    volatile unsigned int count;
} SHIM_IPC_RING;

typedef struct _SHIM_IPC_LISTENER {
    volatile int active;
    volatile int refs;
    char addr[108];
} SHIM_IPC_LISTENER;

#define CONN_FREE        0
#define CONN_SYN         1
#define CONN_ESTABLISHED 2
#define CONN_ALLOCATING  3

typedef struct _SHIM_IPC_CONN {
    volatile int state;
    volatile int listener_idx;
    volatile int client_refs;
    volatile int server_refs;
    volatile int client_closed;
    volatile int server_closed;
    SHIM_IPC_RING c2s;
    SHIM_IPC_RING s2c;
} SHIM_IPC_CONN;

typedef struct _SHIM_IPC_EVENTFD {
    volatile int in_use;
    volatile int refs;
    volatile u64 counter;
} SHIM_IPC_EVENTFD;

typedef struct _SHIM_IPC_SHM {
    volatile int in_use;
    volatile int key;
    volatile unsigned int size;
} SHIM_IPC_SHM;

typedef struct _LXSS_IPC_SECTION {
    volatile unsigned int magic;
    volatile int banner_printed;
    volatile int graphics_active;
    volatile unsigned int xvfb_fb_size;
    volatile int next_pid;
    SHIM_IPC_PIPE     pipes[MAX_IPC_PIPES];
    SHIM_IPC_LISTENER listeners[MAX_IPC_LISTENERS];
    SHIM_IPC_CONN     conns[MAX_IPC_CONNS];
    SHIM_IPC_EVENTFD  eventfds[MAX_IPC_EVENTFDS];
    SHIM_IPC_SHM      shms[MAX_IPC_SHMS];
    unsigned char     xvfb_fb[2097152] __attribute__((aligned(4096)));
} LXSS_IPC_SECTION;

static LXSS_IPC_SECTION *g_ipc = NULL;

static void ipc_lock(volatile long *lk) {
    while (__sync_lock_test_and_set(lk, 1)) {
        __asm__ volatile("pause");
    }
}

static void ipc_unlock(volatile long *lk) {
    __sync_lock_release(lk);
}

static s64 shim_now_ms(void) {
    volatile LARGE_INTEGER *pTime = (volatile LARGE_INTEGER *)0x7FFE0008; /* InterruptTime (monotonic 100ns) */
    return (s64)(pTime->QuadPart / 10000ULL);
}

static void shim_ipc_wait(int iter) {
    LARGE_INTEGER delay;
    if (iter < 16) {
        delay.QuadPart = 0; /* Yield CPU quantum immediately without waiting for 15.6ms clock tick */
    } else {
        delay.QuadPart = -10000LL;
    }
    Nt_DelayExecution(0, &delay);
}

static void *MapNamedSection(const char *ascii_name, unsigned long size_bytes, int *out_created) {
    unsigned short wname[64];
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    LARGE_INTEGER max_sz;
    HANDLE hSec = NULL;
    void *base = NULL;
    unsigned long view_sz = 0;
    NTSTATUS st;
    int i = 0;

    if (out_created) *out_created = 0;
    while (ascii_name[i] && i < 62) {
        wname[i] = (unsigned short)(unsigned char)ascii_name[i];
        i++;
    }
    wname[i] = 0;
    us.Length = (unsigned short)(i * 2);
    us.MaximumLength = us.Length + 2;
    us.Buffer = wname;

    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = OBJ_CASE_INSENSITIVE | OBJ_OPENIF | 0x00000010L /* OBJ_PERMANENT */;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    max_sz.QuadPart = (s64)size_bytes;
    st = Nt_CreateSection(&hSec, SECTION_ALL_ACCESS, &oa, &max_sz, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(st)) {
        oa.Attributes = OBJ_CASE_INSENSITIVE | OBJ_OPENIF;
        st = Nt_CreateSection(&hSec, SECTION_ALL_ACCESS, &oa, &max_sz, PAGE_READWRITE, SEC_COMMIT, NULL);
    }
    if (!NT_SUCCESS(st)) {
        st = Nt_OpenSection(&hSec, SECTION_ALL_ACCESS, &oa);
    } else if (out_created && st != 0x40000000L /* STATUS_OBJECT_NAME_EXISTS */) {
        *out_created = 1;
    }
    if (!NT_SUCCESS(st) || !hSec) return NULL;

    view_sz = size_bytes;
    st = Nt_MapViewOfSection(hSec, (HANDLE)-1, &base, 0, size_bytes, NULL, &view_sz, 1 /* ViewShare */, 0, PAGE_READWRITE);
    /* Keep hSec open so ObjectHeader->HandleCount >= 1 and ObpDeleteNameCheck never unlinks the section name! */
    return NT_SUCCESS(st) ? base : NULL;
}

/* ========================================================================= */
/* Console & UART Output Helpers                                             */
/* ========================================================================= */
static HANDLE g_hSerial = NULL;
static unsigned char g_serial_attempted = 0;

static void OpenSerial(void) {
    UNICODE_STRING u_ser;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    unsigned short ser_name[32];
    const char *dev = "\\Device\\Serial0";
    unsigned int i;

    if (g_serial_attempted) return;
    g_serial_attempted = 1;

    for (i = 0; dev[i]; i++) ser_name[i] = (unsigned short)(unsigned char)dev[i];
    ser_name[i] = 0;
    u_ser.Length = (unsigned short)(i * 2);
    u_ser.MaximumLength = u_ser.Length + 2;
    u_ser.Buffer = ser_name;

    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &u_ser;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    Nt_CreateFile(&g_hSerial, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
                  &oa, &iosb, NULL, 0,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                  FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

static void SerialWriteBuffer(const char *buf, unsigned int count) {
    if (!g_serial_attempted) OpenSerial();
    if (g_hSerial && count > 0) {
        IO_STATUS_BLOCK iosb;
        LARGE_INTEGER offset;
        offset.QuadPart = 0;
        Nt_WriteFile(g_hSerial, NULL, NULL, NULL, &iosb, (void *)buf, count, &offset, NULL);
    }
}

int g_graphics_mode_active = 0;
void (*g_gui_terminal_write_hook)(const char *buf, unsigned int count) = 0;

static void ConsoleWriteBuffer(const char *buf, unsigned int count) {
    unsigned int i;
    unsigned short ubuf[256];
    unsigned int upos = 0;
    static int ansi_state = 0;

    if (g_gui_terminal_write_hook) {
        g_gui_terminal_write_hook(buf, count);
    }
    if (g_graphics_mode_active || (g_ipc && g_ipc->graphics_active)) {
        SerialWriteBuffer(buf, count);
        return;
    }

    for (i = 0; i < count; i++) {
        unsigned char ch = (unsigned char)buf[i];
        if (ansi_state == 0) {
            if (ch == 0x1B) { ansi_state = 1; continue; }
        } else if (ansi_state == 1) {
            if (ch == '[') { ansi_state = 2; continue; }
            else if (ch == ']') { ansi_state = 3; continue; }
            else { ansi_state = 0; continue; }
        } else if (ansi_state == 2) {
            if (ch >= 0x40 && ch <= 0x7E) ansi_state = 0;
            continue;
        } else if (ansi_state == 3) {
            if (ch == 0x07 || ch == 0x1B) ansi_state = 0;
            continue;
        }

        if (ch == '\n') {
            ubuf[upos++] = L'\r';
            ubuf[upos++] = L'\n';
        } else if (ch == '\r') {
            ubuf[upos++] = L'\r';
        } else {
            ubuf[upos++] = (unsigned short)ch;
        }

        if (upos >= 250) {
            UNICODE_STRING us;
            us.Length = (unsigned short)(upos * sizeof(unsigned short));
            us.MaximumLength = us.Length;
            us.Buffer = ubuf;
            Nt_DisplayString(&us);
            upos = 0;
        }
    }

    if (upos > 0) {
        UNICODE_STRING us;
        us.Length = (unsigned short)(upos * sizeof(unsigned short));
        us.MaximumLength = us.Length;
        us.Buffer = ubuf;
        Nt_DisplayString(&us);
    }

    SerialWriteBuffer(buf, count);
}

void shim_debug_print(const char *msg) {
    unsigned int len = 0;
    while (msg && msg[len]) len++;
    if (len > 0) SerialWriteBuffer(msg, len);
}

void shim_debug_hex(const char *prefix, unsigned long val) {
    char buf[64];
    int pos = 0;
    int i;
    while (prefix && prefix[pos] && pos < 40) {
        buf[pos] = prefix[pos];
        pos++;
    }
    buf[pos++] = '0';
    buf[pos++] = 'x';
    for (i = 7; i >= 0; i--) {
        unsigned int nib = (val >> (i * 4)) & 0xF;
        buf[pos++] = (nib < 10) ? ('0' + nib) : ('A' + nib - 10);
    }
    buf[pos++] = '\n';
    buf[pos] = 0;
    shim_debug_print(buf);
}

/* ========================================================================= */
/* Interactive Console Input (PS/2 Keyboard via \Device\RawKeyboard + COM1)   */
/* ========================================================================= */
static HANDLE g_hKeyboard = NULL;
static unsigned char g_InputQueue[256];
static unsigned int g_InputHead = 0;
static unsigned int g_InputTail = 0;
static unsigned char g_ShiftDown = 0;
static unsigned char g_CtrlDown = 0;
static unsigned char g_CapsLock = 0;

static const char g_ScanNormal[88] = {
    0,    27,  '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b', '\t',
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n', 0,   'a', 's',
    'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'','`',  0,  '\\','z', 'x', 'c', 'v',
    'b', 'n', 'm', ',', '.', '/',  0,  '*',  0,  ' ',  0,   0,   0,   0,   0,   0,
    0,    0,   0,   0,   0,   0,   0,  '7', '8', '9', '-', '4', '5', '6', '+', '1',
    '2', '3', '0', '.',  0,   0,   0,   0
};

static const char g_ScanShift[88] = {
    0,    27,  '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\b', '\t',
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n', 0,   'A', 'S',
    'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~',  0,  '|', 'Z', 'X', 'C', 'V',
    'B', 'N', 'M', '<', '>', '?',  0,  '*',  0,  ' ',  0,   0,   0,   0,   0,   0,
    0,    0,   0,   0,   0,   0,   0,  '7', '8', '9', '-', '4', '5', '6', '+', '1',
    '2', '3', '0', '.',  0,   0,   0,   0
};

static void EnqueueInputByte(unsigned char b) {
    unsigned int next = (g_InputTail + 1) & 255;
    if (next != g_InputHead) {
        g_InputQueue[g_InputTail] = b;
        g_InputTail = next;
    }
}

static unsigned char g_kbd_attempted = 0;

static void OpenKeyboard(void) {
    UNICODE_STRING u_kbd;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    unsigned short kbd_name[32];
    const char *dev = "\\Device\\RawKeyboard";
    unsigned int i;

    if (g_hKeyboard || g_kbd_attempted) return;
    g_kbd_attempted = 1;

    for (i = 0; dev[i]; i++) kbd_name[i] = (unsigned short)(unsigned char)dev[i];
    kbd_name[i] = 0;
    u_kbd.Length = (unsigned short)(i * 2);
    u_kbd.MaximumLength = u_kbd.Length + 2;
    u_kbd.Buffer = kbd_name;

    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &u_kbd;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    NTSTATUS st = Nt_CreateFile(&g_hKeyboard, 0x80000000 | SYNCHRONIZE, &oa, &iosb, NULL, 0,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) {
        const char *dev2 = "\\Device\\KeyboardClass0";
        for (i = 0; dev2[i]; i++) kbd_name[i] = (unsigned short)(unsigned char)dev2[i];
        kbd_name[i] = 0;
        u_kbd.Length = (unsigned short)(i * 2);
        u_kbd.MaximumLength = u_kbd.Length + 2;
        Nt_CreateFile(&g_hKeyboard, 0x80000000 | SYNCHRONIZE, &oa, &iosb, NULL, 0,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    }
}

static void PollKeyboard(void) {
    KEYBOARD_INPUT_DATA kbdData[16];
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    NTSTATUS st;
    unsigned int i, count;

    if (g_ipc && g_ipc->graphics_active) return;
    if (!g_hKeyboard) OpenKeyboard();
    if (!g_hKeyboard) return;

    offset.QuadPart = 0;
    st = Nt_ReadFile(g_hKeyboard, NULL, NULL, NULL, &iosb, kbdData, sizeof(kbdData), &offset, NULL);
    if (NT_SUCCESS(st) && iosb.Information >= sizeof(KEYBOARD_INPUT_DATA)) {
        count = iosb.Information / sizeof(KEYBOARD_INPUT_DATA);
        for (i = 0; i < count; i++) {
            unsigned short sc = kbdData[i].MakeCode;
            unsigned char is_break = (kbdData[i].Flags & KEY_BREAK) != 0;
            unsigned char is_e0 = (kbdData[i].Flags & KEY_E0) != 0;

            if (sc == 0x2A || sc == 0x36) { g_ShiftDown = !is_break; continue; }
            if (sc == 0x1D) { g_CtrlDown = !is_break; continue; }
            if (sc == 0x3A && !is_break) { g_CapsLock = !g_CapsLock; continue; }
            if (is_break) continue;

            if (is_e0) {
                switch (sc) {
                    case 0x1C: EnqueueInputByte('\n'); break;
                    case 0x48: EnqueueInputByte(27); EnqueueInputByte('['); EnqueueInputByte('A'); break;
                    case 0x50: EnqueueInputByte(27); EnqueueInputByte('['); EnqueueInputByte('B'); break;
                    case 0x4D: EnqueueInputByte(27); EnqueueInputByte('['); EnqueueInputByte('C'); break;
                    case 0x4B: EnqueueInputByte(27); EnqueueInputByte('['); EnqueueInputByte('D'); break;
                    case 0x53: EnqueueInputByte(127); break;
                }
                continue;
            }

            if (sc < 88) {
                char ch = g_ShiftDown ? g_ScanShift[sc] : g_ScanNormal[sc];
                if (!ch) continue;
                if (g_CapsLock) {
                    if (ch >= 'a' && ch <= 'z') ch -= ('a' - 'A');
                    else if (ch >= 'A' && ch <= 'Z') ch += ('a' - 'A');
                }
                if (g_CtrlDown) {
                    if (ch >= 'a' && ch <= 'z') ch = ch - 'a' + 1;
                    else if (ch >= 'A' && ch <= 'Z') ch = ch - 'A' + 1;
                }
                EnqueueInputByte((unsigned char)ch);
            }
        }
    }
}

extern void net_poll_once(void);

static int ConsoleGetByte(int nonblocking) {
    for (;;) {
        if (g_InputHead != g_InputTail) {
            unsigned char c = g_InputQueue[g_InputHead];
            g_InputHead = (g_InputHead + 1) & 255;
            return (int)c;
        }
        if (nonblocking) return -1;
        PollKeyboard();
        net_poll_once();
        if (g_InputHead != g_InputTail) {
            unsigned char c = g_InputQueue[g_InputHead];
            g_InputHead = (g_InputHead + 1) & 255;
            return (int)c;
        }
        LARGE_INTEGER delay;
        delay.QuadPart = -100000LL;
        Nt_DelayExecution(0, &delay);
    }
}

/* ========================================================================= */
/* File Descriptor Table, Epoll & Pristine Data Snapshot                     */
/* ========================================================================= */
#define MAX_FD 128

#define SOCK_UNUSED    0
#define SOCK_CREATED   1
#define SOCK_BOUND     2
#define SOCK_LISTENING 3
#define SOCK_CONNECTED 4

typedef struct _SHIM_FD {
    HANDLE        h;
    unsigned char is_open;
    unsigned char is_dir;
    unsigned char is_console;
    unsigned char is_pipe;
    unsigned char is_pipe_write;
    unsigned char is_sock;
    unsigned char is_server;
    unsigned char sock_state;
    unsigned char sock_domain;
    unsigned char sock_type;
    unsigned char is_eventfd;
    unsigned char is_epoll;
    unsigned char is_inotify;
    unsigned char is_xvfb_fb;
    unsigned char is_devnull;
    unsigned char is_pty;
    unsigned char pty_pkt;
    unsigned char nonblock;
    unsigned char cloexec;
    unsigned char dir_first;
    unsigned char dir_eof;
    int           ipc_idx;
    u64           offset;
    char          dir_path[260];
    __attribute__((aligned(4))) u8 dir_buffer[4096];
} SHIM_FD;

#define MAX_EPOLLS 8
#define MAX_EPOLL_ITEMS 64

typedef struct _SHIM_EPOLL_ITEM {
    int   active;
    int   fd;
    u32   events;
    u64   data;
} SHIM_EPOLL_ITEM;

typedef struct _SHIM_EPOLL {
    int in_use;
    SHIM_EPOLL_ITEM items[MAX_EPOLL_ITEMS];
} SHIM_EPOLL;

static SHIM_FD    g_fds[MAX_FD];
static SHIM_EPOLL g_epolls[MAX_EPOLLS];
static unsigned char g_shim_initialized = 0;
static char g_cwd[260] = "/";
static char g_current_exe_path[260] = "/bin/busybox";

/* Heap arena for brk */
static u32 g_brk_base = 0;
static u32 g_brk_curr = 0;
static u32 g_brk_limit = 0;

/* Pristine copy of busybox writable PT_LOAD file data for fast RAM fork/spawn */
static unsigned char g_pristine_data[32768];
static unsigned int  g_pristine_saved = 0;

typedef struct _SHIM_SPAWN_FD {
    HANDLE        h;
    unsigned char is_open;
    unsigned char is_dir;
    unsigned char is_console;
    unsigned char is_pipe;
    unsigned char is_pipe_write;
    unsigned char is_sock;
    unsigned char is_server;
    unsigned char sock_state;
    unsigned char sock_domain;
    unsigned char sock_type;
    unsigned char is_eventfd;
    unsigned char is_inotify;
    unsigned char is_xvfb_fb;
    unsigned char is_devnull;
    unsigned char is_pty;
    unsigned char pty_pkt;
    unsigned char nonblock;
    int           ipc_idx;
    u64           offset;
    char          dir_path[260];
} SHIM_SPAWN_FD;

#define SHIM_SPAWN_INFO_ADDR 0x014F0000UL
#define SHIM_SPAWN_MAGIC     0x5350574EUL

typedef struct _SHIM_SPAWN_INFO {
    unsigned int  magic;
    int           is_applet;
    int           argc;
    int           envc;
    char          elf_path[260];
    char          cwd[260];
    int           argv_off[64];
    int           envp_off[128];
    char          str_pool[8192];
    SHIM_SPAWN_FD fds[MAX_FD];
} SHIM_SPAWN_INFO;

typedef struct {
    unsigned char e_ident[16];
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u32 e_entry;
    u32 e_phoff;
    u32 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    u32 p_type;
    u32 p_offset;
    u32 p_vaddr;
    u32 p_paddr;
    u32 p_filesz;
    u32 p_memsz;
    u32 p_flags;
    u32 p_align;
} Elf32_Phdr;

static void SavePristineData(void) {
    if (g_pristine_saved) return;
    const Elf32_Ehdr *eh = (const Elf32_Ehdr *)0x01000000UL;
    if (eh->e_ident[0] == 0x7F && eh->e_ident[1] == 'E' && eh->e_ident[2] == 'L' && eh->e_ident[3] == 'F') {
        const Elf32_Phdr *ph = (const Elf32_Phdr *)(0x01000000UL + eh->e_phoff);
        unsigned int off = 0;
        for (int i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type == 1 && (ph[i].p_flags & 2) && ph[i].p_filesz > 0) {
                if (off + ph[i].p_filesz <= sizeof(g_pristine_data)) {
                    const unsigned char *src = (const unsigned char *)ph[i].p_vaddr;
                    for (unsigned int k = 0; k < ph[i].p_filesz; k++) {
                        g_pristine_data[off + k] = src[k];
                    }
                    off += ph[i].p_filesz;
                }
            }
        }
        g_pristine_saved = 1;
    }
}

static void LoadSymlinksTable(void);

static inline void shim_init_fpu(void) {
    unsigned short cw = 0x037F;
    __asm__ volatile("fninit; fldcw %0" : : "m"(cw));
}

static void InitShim(void) {
    int i;
    void *base = (void *)0x20000000;
    unsigned long size = 64 * 1024 * 1024;
    int ipc_created = 0;

    shim_init_fpu();
    if (g_shim_initialized) return;
    SavePristineData();

    for (i = 0; i < MAX_FD; i++) {
        g_fds[i].is_open = 0;
    }
    g_fds[0].is_open = 1; g_fds[0].is_console = 1;
    g_fds[1].is_open = 1; g_fds[1].is_console = 1;
    g_fds[2].is_open = 1; g_fds[2].is_console = 1;

    if (!NT_SUCCESS(Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &size, MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
        base = NULL;
        size = 64 * 1024 * 1024;
        Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &size, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (base) {
        g_brk_base = (u32)base;
        g_brk_curr = (u32)base;
        g_brk_limit = (u32)base + size;
    }

    g_ipc = (LXSS_IPC_SECTION *)MapNamedSection("\\LxssIpcSection", sizeof(LXSS_IPC_SECTION), &ipc_created);
    if (g_ipc && g_ipc->magic != 0x4C585353UL) {
        for (unsigned int k = 0; k < sizeof(LXSS_IPC_SECTION); k++) ((unsigned char *)g_ipc)[k] = 0;
        g_ipc->magic = 0x4C585353UL;
        g_ipc->next_pid = 200;
    }

    g_shim_initialized = 1;
    LoadSymlinksTable();

    if (g_ipc && !g_ipc->banner_printed) {
        g_ipc->banner_printed = 1;
    }
}

/* ========================================================================= */
/* Path Translation & Symlink Table (/etc/symlinks.tab + D:/C: auto-select)  */
/* ========================================================================= */
#define MAX_SYMLINKS 1024
typedef struct _SHIM_SYMLINK {
    char link[128];
    char target[128];
} SHIM_SYMLINK;

static SHIM_SYMLINK g_symlinks[MAX_SYMLINKS];
static int g_num_symlinks = 0;
static char g_root_drive = 0;

static int shim_strcmp(const char *s1, const char *s2) {
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    while (*s1 && (*s1 == *s2)) { s1++; s2++; }
    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

static int shim_strncmp(const char *s1, const char *s2, unsigned int n) {
    for (unsigned int i = 0; i < n; i++) {
        if (s1[i] != s2[i] || !s1[i] || !s2[i])
            return (unsigned char)s1[i] - (unsigned char)s2[i];
    }
    return 0;
}

static unsigned int shim_strlen(const char *s) {
    unsigned int n = 0;
    while (s && s[n]) n++;
    return n;
}

static void shim_strcpy(char *dst, const char *src, unsigned int max_len) {
    unsigned int i = 0;
    while (src && src[i] && i + 1 < max_len) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static void DetectRootDrive(void) {
    if (g_root_drive) return;
    unsigned short test_d[] = L"\\??\\D:\\usr\\bin\\Xvfb";
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;

    us.Buffer = test_d;
    us.Length = sizeof(test_d) - 2;
    us.MaximumLength = sizeof(test_d);
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    if (NT_SUCCESS(Nt_OpenFile(&h, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT))) {
        Nt_Close(h);
        g_root_drive = 'D';
    } else {
        g_root_drive = 'C';
    }
}

static void LoadSymlinksTable(void) {
    DetectRootDrive();
    unsigned short path_w[64];
    const char *p = (g_root_drive == 'D') ? "\\??\\D:\\etc\\symlinks.tab" : "\\??\\C:\\etc\\symlinks.tab";
    unsigned int i = 0;
    while (p[i]) { path_w[i] = (unsigned short)(unsigned char)p[i]; i++; }
    path_w[i] = 0;

    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    us.Buffer = path_w;
    us.Length = (unsigned short)(i * 2);
    us.MaximumLength = us.Length + 2;
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    if (!NT_SUCCESS(Nt_OpenFile(&h, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
                                FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT))) {
        return;
    }

    static char tab_buf[131072];
    LARGE_INTEGER off;
    off.QuadPart = 0;
    if (NT_SUCCESS(Nt_ReadFile(h, NULL, NULL, NULL, &iosb, tab_buf, sizeof(tab_buf) - 1, &off, NULL))) {
        unsigned int n = (unsigned int)iosb.Information;
        tab_buf[n] = '\0';
        unsigned int pos = 0;
        while (pos < n && g_num_symlinks < MAX_SYMLINKS) {
            unsigned int l_start = pos;
            while (pos < n && tab_buf[pos] != '\t' && tab_buf[pos] != '\n' && tab_buf[pos] != '\r') pos++;
            unsigned int l_len = pos - l_start;
            if (pos < n && tab_buf[pos] == '\t') {
                pos++;
                unsigned int t_start = pos;
                while (pos < n && tab_buf[pos] != '\n' && tab_buf[pos] != '\r') pos++;
                unsigned int t_len = pos - t_start;
                if (l_len > 0 && l_len < 127 && t_len > 0 && t_len < 127) {
                    for (unsigned int k = 0; k < l_len; k++) g_symlinks[g_num_symlinks].link[k] = tab_buf[l_start + k];
                    g_symlinks[g_num_symlinks].link[l_len] = '\0';
                    for (unsigned int k = 0; k < t_len; k++) g_symlinks[g_num_symlinks].target[k] = tab_buf[t_start + k];
                    g_symlinks[g_num_symlinks].target[t_len] = '\0';
                    g_num_symlinks++;
                }
            }
            while (pos < n && (tab_buf[pos] == '\n' || tab_buf[pos] == '\r')) pos++;
        }
    }
    Nt_Close(h);
}

static void CanonicalizePosixPathNoSymlink(const char *in_path, char *out_path, unsigned int max_out) {
    char raw[512];
    unsigned int rlen = 0;

    if (!in_path || !in_path[0]) in_path = ".";
    if (in_path[0] != '/') {
        const char *cwd = g_cwd;
        while (*cwd && rlen < sizeof(raw) - 2) {
            raw[rlen++] = (*cwd == '\\') ? '/' : *cwd;
            cwd++;
        }
        if (rlen > 0 && raw[rlen - 1] != '/') raw[rlen++] = '/';
    }

    while (*in_path && rlen < sizeof(raw) - 1) {
        raw[rlen++] = (*in_path == '\\') ? '/' : *in_path;
        in_path++;
    }
    raw[rlen] = '\0';

    out_path[0] = '/';
    out_path[1] = '\0';
    unsigned int out_len = 1;

    const char *s = raw;
    while (*s) {
        while (*s == '/') s++;
        if (!*s) break;
        const char *seg = s;
        while (*s && *s != '/') s++;
        unsigned int seg_len = (unsigned int)(s - seg);

        if (seg_len == 1 && seg[0] == '.') {
            continue;
        } else if (seg_len == 2 && seg[0] == '.' && seg[1] == '.') {
            if (out_len > 1) {
                out_len--;
                while (out_len > 1 && out_path[out_len - 1] != '/') out_len--;
                if (out_len > 1 && out_path[out_len - 1] == '/') out_len--;
                out_path[out_len] = '\0';
            }
        } else {
            if (out_len > 1 && out_len < max_out - 1) out_path[out_len++] = '/';
            for (unsigned int k = 0; k < seg_len && out_len < max_out - 1; k++) {
                out_path[out_len++] = seg[k];
            }
            out_path[out_len] = '\0';
        }
    }
}

static void CanonicalizePosixPath(const char *in_path, char *out_path, unsigned int max_out) {
    CanonicalizePosixPathNoSymlink(in_path, out_path, max_out);
    for (int hop = 0; hop < 4; hop++) {
        int matched = 0;
        for (int i = 0; i < g_num_symlinks; i++) {
            unsigned int llen = shim_strlen(g_symlinks[i].link);
            if (shim_strncmp(out_path, g_symlinks[i].link, llen) == 0 &&
                (out_path[llen] == '\0' || out_path[llen] == '/')) {
                char combined[512];
                const char *tgt = g_symlinks[i].target;
                if (tgt[0] == '/') {
                    shim_strcpy(combined, tgt, sizeof(combined));
                } else {
                    /* Relative to parent of link */
                    unsigned int p = llen;
                    while (p > 0 && g_symlinks[i].link[p - 1] != '/') p--;
                    for (unsigned int k = 0; k < p; k++) combined[k] = g_symlinks[i].link[k];
                    combined[p] = '\0';
                    unsigned int clen = p;
                    for (unsigned int k = 0; tgt[k] && clen + 1 < sizeof(combined); k++) combined[clen++] = tgt[k];
                    combined[clen] = '\0';
                }
                if (out_path[llen] == '/') {
                    unsigned int clen = shim_strlen(combined);
                    for (unsigned int k = llen; out_path[k] && clen + 1 < sizeof(combined); k++) {
                        combined[clen++] = out_path[k];
                    }
                    combined[clen] = '\0';
                }
                CanonicalizePosixPathNoSymlink(combined, out_path, max_out);
                matched = 1;
                break;
            }
        }
        if (!matched) break;
    }
}

static void TranslatePathToNTDrive(const char *posix_path, unsigned short *nt_buf, unsigned int max_chars, char drive) {
    char clean[260];
    unsigned int p = 0, i = 0;

    if (!posix_path || !posix_path[0]) posix_path = "/";

    if (posix_path[0] == '\\' && posix_path[1] == '?' && posix_path[2] == '?' && posix_path[3] == '\\') {
        while (*posix_path && p < 255) clean[p++] = *posix_path++;
        clean[p] = '\0';
    } else if ((posix_path[0] >= 'A' && posix_path[0] <= 'Z' && posix_path[1] == ':') ||
               (posix_path[0] >= 'a' && posix_path[0] <= 'z' && posix_path[1] == ':')) {
        clean[p++] = '\\'; clean[p++] = '?'; clean[p++] = '?'; clean[p++] = '\\';
        clean[p++] = posix_path[0]; clean[p++] = ':'; clean[p++] = '\\';
        const char *sub = posix_path + 2;
        if (*sub == '\\' || *sub == '/') sub++;
        while (*sub && p < 250) {
            clean[p++] = (*sub == '/') ? '\\' : *sub;
            sub++;
        }
        clean[p] = '\0';
    } else {
        char can[260];
        CanonicalizePosixPath(posix_path, can, sizeof(can));

        clean[p++] = '\\'; clean[p++] = '?'; clean[p++] = '?'; clean[p++] = '\\';
        clean[p++] = drive; clean[p++] = ':'; clean[p++] = '\\';

        if (can[0] == '/' && can[1] == '\0') {
            clean[7] = '\0';
            p = 7;
        } else {
            const char *sub = can;
            if (*sub == '/') sub++;
            while (*sub && p < 250) {
                clean[p++] = (*sub == '/') ? '\\' : *sub;
                sub++;
            }
            clean[p] = '\0';
            if (p > 7 && clean[p - 1] == '\\') {
                p--;
                clean[p] = '\0';
            }
        }
    }

    for (i = 0; clean[i] && i < max_chars - 1; i++) {
        nt_buf[i] = (unsigned short)(unsigned char)clean[i];
    }
    nt_buf[i] = 0;
}

static void TranslatePathToNT(const char *posix_path, unsigned short *nt_buf, unsigned int max_chars) {
    DetectRootDrive();
    TranslatePathToNTDrive(posix_path, nt_buf, max_chars, g_root_drive);
}

void shim_translate_path(const char *posix_path, unsigned short *nt_buf, unsigned int max_chars) {
    TranslatePathToNT(posix_path, nt_buf, max_chars);
}

/* ========================================================================= */
/* TLS GDT[12] (%gs = 0x63) & IDT[0x80] Kernel Hook Bridge                   */
/* ========================================================================= */
#define IOCTL_FB_SET_TLS_GDT 0x83202014UL
static HANDLE g_hFbTls = NULL;
static unsigned long g_current_tls_base = 0;

static int shim_set_tls_base(unsigned long base_addr) {
    IO_STATUS_BLOCK iosb;
    unsigned short fpu_cw = 0x037F;
    __asm__ volatile("fldcw %0" : : "m"(fpu_cw));
    if (!g_hFbTls) {
        unsigned short dev_name[] = L"\\Device\\fb0";
        UNICODE_STRING us;
        OBJECT_ATTRIBUTES oa;
        us.Buffer = dev_name;
        us.Length = sizeof(dev_name) - 2;
        us.MaximumLength = sizeof(dev_name);
        oa.Length = sizeof(OBJECT_ATTRIBUTES);
        oa.RootDirectory = NULL;
        oa.ObjectName = &us;
        oa.Attributes = OBJ_CASE_INSENSITIVE;
        oa.SecurityDescriptor = NULL;
        oa.SecurityQualityOfService = NULL;
        Nt_CreateFile(&g_hFbTls, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
                      NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                      FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    }
    g_current_tls_base = base_addr;
    if (g_hFbTls) {
        unsigned long in_buf[3] = { base_addr, (unsigned long)&__kernel_vsyscall, 12 };
        unsigned long out_buf[3] = { base_addr, (unsigned long)&__kernel_vsyscall, 12 };
        Nt_DeviceIoControlFile(g_hFbTls, NULL, NULL, NULL, &iosb,
                               IOCTL_FB_SET_TLS_GDT, in_buf, sizeof(in_buf),
                               out_buf, sizeof(out_buf));
        __asm__ volatile("movw %w0, %%gs" : : "r"(0x63));
        return 0;
    }
    return -1;
}
/* ========================================================================= */
/* Ring Buffer & Socket / Pipe / EventFD Helpers                             */
/* ========================================================================= */
static unsigned int ring_read(SHIM_IPC_RING *r, void *dst, unsigned int len) {
    unsigned int n = 0;
    unsigned char *p = (unsigned char *)dst;
    ipc_lock(&r->lock);
    while (n < len && r->count > 0) {
        p[n++] = r->buf[r->head];
        r->head = (r->head + 1) % IPC_RING_SIZE;
        r->count--;
    }
    ipc_unlock(&r->lock);
    return n;
}

static unsigned int ring_write(SHIM_IPC_RING *r, const void *src, unsigned int len) {
    unsigned int n = 0;
    const unsigned char *p = (const unsigned char *)src;
    ipc_lock(&r->lock);
    while (n < len && r->count < IPC_RING_SIZE) {
        r->buf[r->tail] = p[n++];
        r->tail = (r->tail + 1) % IPC_RING_SIZE;
        r->count++;
    }
    ipc_unlock(&r->lock);
    return n;
}

static void shim_fd_addref(const SHIM_FD *f) {
    if (!f || !f->is_open || !g_ipc) return;
    if (f->is_pipe && f->ipc_idx >= 0 && f->ipc_idx < MAX_IPC_PIPES) {
        if (f->is_pipe_write) __sync_fetch_and_add(&g_ipc->pipes[f->ipc_idx].write_refs, 1);
        else __sync_fetch_and_add(&g_ipc->pipes[f->ipc_idx].read_refs, 1);
    } else if (f->is_sock && (f->sock_state == SOCK_LISTENING || f->sock_state == SOCK_BOUND) && f->ipc_idx >= 0 && f->ipc_idx < MAX_IPC_LISTENERS) {
        __sync_fetch_and_add(&g_ipc->listeners[f->ipc_idx].refs, 1);
    } else if (f->is_sock && f->sock_state == SOCK_CONNECTED && f->ipc_idx >= 0 && f->ipc_idx < MAX_IPC_CONNS) {
        if (f->is_server) __sync_fetch_and_add(&g_ipc->conns[f->ipc_idx].server_refs, 1);
        else __sync_fetch_and_add(&g_ipc->conns[f->ipc_idx].client_refs, 1);
    } else if (f->is_eventfd && f->ipc_idx >= 0 && f->ipc_idx < MAX_IPC_EVENTFDS) {
        __sync_fetch_and_add(&g_ipc->eventfds[f->ipc_idx].refs, 1);
    }
}

static long sock_read_fd(int fd, void *buf, unsigned int count, int flags_dontwait) {
    if (!g_ipc) return -LINUX_EIO;
    if (g_fds[fd].sock_state != SOCK_CONNECTED || g_fds[fd].ipc_idx < 0 || g_fds[fd].ipc_idx >= MAX_IPC_CONNS)
        return -LINUX_ENOTCONN;
    if (count == 0) return 0;

    SHIM_IPC_CONN *conn = &g_ipc->conns[g_fds[fd].ipc_idx];
    SHIM_IPC_RING *rx = g_fds[fd].is_server ? &conn->c2s : &conn->s2c;
    int nonblock = g_fds[fd].nonblock || (flags_dontwait != 0);

    for (int iter = 0;; iter++) {
        if (g_fds[fd].is_pty && !g_fds[fd].is_server && g_fds[fd].pty_pkt) {
            if (count < 2) return 0;
            unsigned char *dst = (unsigned char *)buf;
            unsigned int got = ring_read(rx, dst + 1, count - 1);
            if (got > 0) {
                dst[0] = 0; /* TIOCPKT_DATA */
                shim_debug_print("[pty_read_pkt] ");
                shim_debug_print(g_current_exe_path);
                shim_debug_hex(" got=", (unsigned long)(got + 1));
                return (long)(got + 1);
            }
        } else {
            unsigned int got = ring_read(rx, buf, count);
            if (got > 0) {
                if (g_fds[fd].is_pty) {
                    shim_debug_print("[pty_read] ");
                    shim_debug_print(g_current_exe_path);
                    shim_debug_hex(" got=", (unsigned long)got);
                }
                return (long)got;
            }
        }
        int peer_closed = g_fds[fd].is_server ? (conn->client_closed || conn->client_refs <= 0)
                                              : (conn->server_closed || conn->server_refs <= 0);
        if (peer_closed) return 0;
        if (nonblock) return -LINUX_EAGAIN;
        shim_ipc_wait(iter);
    }
}

static long sock_write_fd(int fd, const void *buf, unsigned int count, int flags_dontwait) {
    if (!g_ipc) return -LINUX_EIO;
    if (g_fds[fd].sock_state != SOCK_CONNECTED || g_fds[fd].ipc_idx < 0 || g_fds[fd].ipc_idx >= MAX_IPC_CONNS)
        return -LINUX_EPIPE;
    if (count == 0) return 0;

    SHIM_IPC_CONN *conn = &g_ipc->conns[g_fds[fd].ipc_idx];
    SHIM_IPC_RING *tx = g_fds[fd].is_server ? &conn->s2c : &conn->c2s;
    int nonblock = g_fds[fd].nonblock || (flags_dontwait != 0);
    unsigned int total = 0;
    const unsigned char *src = (const unsigned char *)buf;

    /* PTY slave -> master ONLCR (\n -> \r\n) */
    if (g_fds[fd].is_pty && g_fds[fd].is_server) {
        shim_debug_print("[pty_slave_write] ");
        shim_debug_print(g_current_exe_path);
        shim_debug_hex(" len=", (unsigned long)count);
        for (unsigned int i = 0; i < count; i++) {
            if (src[i] == '\n' && (i == 0 || src[i - 1] != '\r')) {
                unsigned char cr = '\r';
                ring_write(tx, &cr, 1);
            }
            ring_write(tx, &src[i], 1);
        }
        return (long)count;
    }
    if (g_fds[fd].is_pty && !g_fds[fd].is_server) {
        shim_debug_print("[pty_master_write] ");
        shim_debug_print(g_current_exe_path);
        shim_debug_hex(" len=", (unsigned long)count);
    }

    for (int iter = 0; total < count; iter++) {
        int peer_closed = g_fds[fd].is_server ? (conn->client_closed || conn->client_refs <= 0)
                                              : (conn->server_closed || conn->server_refs <= 0);
        if (peer_closed) return total > 0 ? (long)total : -LINUX_EPIPE;
        unsigned int put = ring_write(tx, src + total, count - total);
        total += put;
        if (total >= count) break;
        if (nonblock) return total > 0 ? (long)total : -LINUX_EAGAIN;
        if (put > 0) iter = 0;
        shim_ipc_wait(iter);
    }
    return (long)total;
}

static long sys_read(int fd, void *buf, unsigned int count) {
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;
    if (g_fds[fd].is_devnull) return 0;

    if (g_fds[fd].is_inotify) {
        if (g_fds[fd].nonblock) return -LINUX_EAGAIN;
        for (int iter = 0;; iter++) {
            shim_ipc_wait(iter);
        }
    }

    if (g_fds[fd].is_eventfd && g_ipc) {
        if (count < 8) return -LINUX_EINVAL;
        SHIM_IPC_EVENTFD *ev = &g_ipc->eventfds[g_fds[fd].ipc_idx];
        for (int iter = 0;; iter++) {
            u64 val = ev->counter;
            if (val > 0) {
                if (__sync_bool_compare_and_swap(&ev->counter, val, 0ULL)) {
                    *(u64 *)buf = val;
                    return 8;
                }
            }
            if (g_fds[fd].nonblock) return -LINUX_EAGAIN;
            shim_ipc_wait(iter);
        }
    }

    if (g_fds[fd].is_sock) {
        return sock_read_fd(fd, buf, count, 0);
    }

    if (g_fds[fd].is_pipe && g_ipc) {
        SHIM_IPC_PIPE *p = &g_ipc->pipes[g_fds[fd].ipc_idx];
        if (count == 0) return 0;
        for (int iter = 0;; iter++) {
            unsigned int n = 0;
            unsigned char *dst = (unsigned char *)buf;
            ipc_lock(&p->lock);
            while (n < count && p->count > 0) {
                dst[n++] = p->buf[p->head];
                p->head = (p->head + 1) % IPC_PIPE_BUF_SIZE;
                p->count--;
            }
            ipc_unlock(&p->lock);
            if (n > 0) {
                if (shim_strcmp(g_current_exe_path, "/usr/bin/xfce4-terminal") == 0) {
                    shim_debug_hex("[term_pipe_read] n=", (unsigned long)n);
                }
                return (long)n;
            }
            if (p->write_refs <= 0) {
                if (shim_strcmp(g_current_exe_path, "/usr/bin/xfce4-terminal") == 0) {
                    shim_debug_hex("[term_pipe_eof] fd=", (unsigned long)fd);
                }
                return 0;
            }
            if (g_fds[fd].nonblock) return -LINUX_EAGAIN;
            shim_ipc_wait(iter);
        }
    }

    if (g_fds[fd].is_console) {
        if (count == 0) return 0;
        char *p = (char *)buf;
        int c = ConsoleGetByte(g_fds[fd].nonblock);
        if (c < 0) return g_fds[fd].nonblock ? -LINUX_EAGAIN : 0;
        p[0] = (char)c;
        if (c == '\n') return 1;
        unsigned int n = 1;
        while (n < count) {
            c = ConsoleGetByte(1);
            if (c < 0) break;
            p[n++] = (char)c;
            if (c == '\n') break;
        }
        return (long)n;
    }

    status = Nt_ReadFile(g_fds[fd].h, NULL, NULL, NULL, &iosb, buf, count, NULL, NULL);
    if (!NT_SUCCESS(status)) return 0;
    g_fds[fd].offset += iosb.Information;
    return (long)iosb.Information;
}

static long sys_write(int fd, const void *buf, unsigned int count) {
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;
    if (g_fds[fd].is_devnull) return (long)count;

    if (g_fds[fd].is_xvfb_fb) {
        g_fds[fd].offset += count;
        if (g_ipc && g_fds[fd].offset > g_ipc->xvfb_fb_size) {
            g_ipc->xvfb_fb_size = (unsigned int)g_fds[fd].offset;
        }
        return (long)count;
    }

    if (g_fds[fd].is_eventfd && g_ipc) {
        if (count < 8) return -LINUX_EINVAL;
        u64 add = *(const u64 *)buf;
        __sync_fetch_and_add(&g_ipc->eventfds[g_fds[fd].ipc_idx].counter, add);
        return 8;
    }

    if (g_fds[fd].is_sock) {
        return sock_write_fd(fd, buf, count, 0);
    }

    if (g_fds[fd].is_pipe && g_ipc) {
        SHIM_IPC_PIPE *p = &g_ipc->pipes[g_fds[fd].ipc_idx];
        const unsigned char *src = (const unsigned char *)buf;
        unsigned int n = 0;
        while (n < count) {
            if (p->read_refs <= 0) return n > 0 ? (long)n : -LINUX_EPIPE;
            ipc_lock(&p->lock);
            while (n < count && p->count < IPC_PIPE_BUF_SIZE) {
                p->buf[p->tail] = src[n++];
                p->tail = (p->tail + 1) % IPC_PIPE_BUF_SIZE;
                p->count++;
            }
            ipc_unlock(&p->lock);
            if (n >= count) break;
            if (g_fds[fd].nonblock) return n > 0 ? (long)n : -LINUX_EAGAIN;
            LARGE_INTEGER delay;
            delay.QuadPart = -10000LL;
            Nt_DelayExecution(0, &delay);
        }
        return (long)count;
    }

    if (g_fds[fd].is_console ||
        ((fd == 1 || fd == 2) && !g_fds[fd].is_pipe && !g_fds[fd].is_sock && !g_fds[fd].h)) {
        ConsoleWriteBuffer((const char *)buf, count);
        return (long)count;
    }

    status = Nt_WriteFile(g_fds[fd].h, NULL, NULL, NULL, &iosb, (void *)buf, count, NULL, NULL);
    if (!NT_SUCCESS(status)) return -LINUX_EIO;
    g_fds[fd].offset += iosb.Information;
    return (long)iosb.Information;
}

static long sys_writev(int fd, const struct linux_iovec *iov, int iovcnt) {
    if (!iov || iovcnt < 0) return -LINUX_EINVAL;
    long total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len > 0 && iov[i].iov_base) {
            long ret = sys_write(fd, iov[i].iov_base, (unsigned int)iov[i].iov_len);
            if (ret < 0) return total > 0 ? total : ret;
            total += ret;
            if (ret < (long)iov[i].iov_len) break;
        }
    }
    return total;
}

static long sys_readv(int fd, const struct linux_iovec *iov, int iovcnt) {
    if (!iov || iovcnt < 0) return -LINUX_EINVAL;
    long total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len > 0 && iov[i].iov_base) {
            if (total > 0 && fd >= 0 && fd < MAX_FD && g_fds[fd].is_console && g_InputHead == g_InputTail) break;
            if (total > 0 && fd >= 0 && fd < MAX_FD && (g_fds[fd].is_sock || g_fds[fd].is_pipe)) {
                /* Don't block on subsequent iovecs if we already got bytes */
                int saved_nb = g_fds[fd].nonblock;
                g_fds[fd].nonblock = 1;
                long ret = sys_read(fd, iov[i].iov_base, (unsigned int)iov[i].iov_len);
                g_fds[fd].nonblock = (unsigned char)saved_nb;
                if (ret <= 0) break;
                total += ret;
                if (ret < (long)iov[i].iov_len) break;
                continue;
            }
            long ret = sys_read(fd, iov[i].iov_base, (unsigned int)iov[i].iov_len);
            if (ret < 0) return total > 0 ? total : ret;
            total += ret;
            if (ret < (long)iov[i].iov_len) break;
            if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_console && ret > 0 &&
                ((const char *)iov[i].iov_base)[ret - 1] == '\n') break;
        }
    }
    return total;
}

static int path_ends_with(const char *s, const char *suffix) {
    unsigned int slen = shim_strlen(s);
    unsigned int suflen = shim_strlen(suffix);
    if (slen < suflen) return 0;
    return shim_strcmp(s + slen - suflen, suffix) == 0;
}

static void EnsureParentDirsExist(const char *posix_path);

static long sys_openat(int dirfd, const char *pathname, int flags, unsigned int mode) {
    int fd;
    char resolved[512];
    unsigned short nt_path[260];
    UNICODE_STRING u_name;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS status;
    unsigned long access_mask = FILE_READ_DATA | SYNCHRONIZE;
    unsigned long disposition = FILE_OPEN;
    unsigned long options = FILE_SYNCHRONOUS_IO_NONALERT;

    for (fd = 0; fd < MAX_FD; fd++) {
        if (!g_fds[fd].is_open) break;
    }
    if (fd >= MAX_FD) return -LINUX_EMFILE;

    if (!pathname) pathname = ".";

    if (pathname[0] != '/' && dirfd != -100 && dirfd >= 0 && dirfd < MAX_FD &&
        g_fds[dirfd].is_open && g_fds[dirfd].dir_path[0]) {
        unsigned int p = 0;
        const char *dp = g_fds[dirfd].dir_path;
        while (*dp && p < 250) resolved[p++] = *dp++;
        if (p > 0 && resolved[p - 1] != '/') resolved[p++] = '/';
        while (*pathname && p < 500) resolved[p++] = *pathname++;
        resolved[p] = '\0';
    } else {
        unsigned int p = 0;
        while (*pathname && p < 500) resolved[p++] = *pathname++;
        resolved[p] = '\0';
    }

    for (unsigned int k = 0; k < sizeof(SHIM_FD); k++) ((unsigned char *)&g_fds[fd])[k] = 0;
    g_fds[fd].nonblock = (flags & 00004000) ? 1 : 0;
    g_fds[fd].cloexec  = (flags & 02000000) ? 1 : 0;
    CanonicalizePosixPath(resolved, g_fds[fd].dir_path, sizeof(g_fds[fd].dir_path));

    if (shim_strcmp(resolved, "/dev/null") == 0 || shim_strcmp(resolved, "/dev/zero") == 0 ||
        shim_strcmp(resolved, "/dev/tty") == 0) {
        if (shim_strcmp(resolved, "/dev/tty") == 0 && g_fds[0].is_open && g_fds[0].is_pty) {
            g_fds[fd] = g_fds[0];
            g_fds[fd].nonblock = (flags & 00004000) ? 1 : 0;
            g_fds[fd].cloexec  = (flags & 02000000) ? 1 : 0;
            shim_fd_addref(&g_fds[fd]);
            return fd;
        }
        g_fds[fd].is_open = 1;
        if (shim_strcmp(resolved, "/dev/tty") == 0) g_fds[fd].is_console = 1;
        else g_fds[fd].is_devnull = 1;
        return fd;
    }

    if (shim_strcmp(resolved, "/dev/ptmx") == 0 && g_ipc) {
        int cidx = -1;
        for (int i = 0; i < MAX_IPC_CONNS; i++) {
            if (__sync_bool_compare_and_swap(&g_ipc->conns[i].state, CONN_FREE, CONN_ESTABLISHED)) {
                cidx = i;
                break;
            }
        }
        if (cidx < 0) return -LINUX_ENOMEM;
        SHIM_IPC_CONN *conn = &g_ipc->conns[cidx];
        conn->listener_idx = -2;
        conn->client_refs = 1;
        conn->server_refs = 1; /* Held until slave opens or master closes */
        conn->client_closed = 0;
        conn->server_closed = 0;
        conn->c2s.lock = 0; conn->c2s.head = 0; conn->c2s.tail = 0; conn->c2s.count = 0;
        conn->s2c.lock = 0; conn->s2c.head = 0; conn->s2c.tail = 0; conn->s2c.count = 0;
        g_fds[fd].is_open = 1;
        g_fds[fd].is_sock = 1;
        g_fds[fd].is_pty = 1;
        g_fds[fd].is_server = 0;
        g_fds[fd].sock_state = SOCK_CONNECTED;
        g_fds[fd].ipc_idx = cidx;
        shim_debug_print("[ptmx] ");
        shim_debug_print(g_current_exe_path);
        shim_debug_hex(" cidx=", (unsigned long)cidx);
        return fd;
    }

    if (shim_strncmp(resolved, "/dev/pts/", 9) == 0 && g_ipc) {
        int cidx = 0;
        const char *p = resolved + 9;
        while (*p >= '0' && *p <= '9') { cidx = cidx * 10 + (*p - '0'); p++; }
        if (cidx < 0 || cidx >= MAX_IPC_CONNS) return -LINUX_ENOENT;
        SHIM_IPC_CONN *conn = &g_ipc->conns[cidx];
        if (conn->listener_idx == -2) {
            conn->listener_idx = -3; /* First slave open claims initial server_ref */
        } else {
            __sync_fetch_and_add(&conn->server_refs, 1);
        }
        g_fds[fd].is_open = 1;
        g_fds[fd].is_sock = 1;
        g_fds[fd].is_pty = 1;
        g_fds[fd].is_server = 1;
        g_fds[fd].sock_state = SOCK_CONNECTED;
        g_fds[fd].ipc_idx = cidx;
        shim_debug_print("[pts_open] ");
        shim_debug_print(g_current_exe_path);
        shim_debug_hex(" cidx=", (unsigned long)cidx);
        return fd;
    }

    if (path_ends_with(resolved, "Xvfb_screen0")) {
        g_fds[fd].is_open = 1;
        g_fds[fd].is_xvfb_fb = 1;
        if (g_ipc) g_ipc->graphics_active = 1;
        return fd;
    }

    /* /dev/<name> device open */
    if (resolved[0] == '/' && resolved[1] == 'd' && resolved[2] == 'e' &&
        resolved[3] == 'v' && resolved[4] == '/' && resolved[5] && !(flags & 00200000)) {
        unsigned short dev_path[64];
        const char *dn = resolved + 5;
        unsigned int k = 0, ok = 1;
        dev_path[k++] = '\\'; dev_path[k++] = '?'; dev_path[k++] = '?'; dev_path[k++] = '\\';
        while (*dn && k < 62) { if (*dn == '/') ok = 0; dev_path[k++] = (unsigned char)*dn++; }
        dev_path[k] = 0;
        if (ok) {
            UNICODE_STRING u_dev;
            OBJECT_ATTRIBUTES oa_dev;
            u_dev.Length = (unsigned short)(k * 2);
            u_dev.MaximumLength = u_dev.Length + 2;
            u_dev.Buffer = dev_path;
            oa_dev.Length = sizeof(OBJECT_ATTRIBUTES);
            oa_dev.RootDirectory = NULL;
            oa_dev.ObjectName = &u_dev;
            oa_dev.Attributes = OBJ_CASE_INSENSITIVE;
            oa_dev.SecurityDescriptor = NULL;
            oa_dev.SecurityQualityOfService = NULL;
            status = Nt_CreateFile(&hFile, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, &oa_dev, &iosb,
                                   NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                                   FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
            if (NT_SUCCESS(status)) {
                g_fds[fd].h = hFile;
                g_fds[fd].is_open = 1;
                g_fds[fd].dir_first = 1;
                return fd;
            }
        }
    }

    if (flags & 00000100) {
        EnsureParentDirsExist(resolved);
    }

    TranslatePathToNT(resolved, nt_path, 260);
    u_name.Length = 0;
    while (nt_path[u_name.Length / 2]) u_name.Length += 2;
    u_name.MaximumLength = u_name.Length + 2;
    u_name.Buffer = nt_path;

    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &u_name;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    if (flags & 00000002) access_mask |= FILE_WRITE_DATA;
    if (flags & 00000001) { access_mask &= ~FILE_READ_DATA; access_mask |= FILE_WRITE_DATA; }
    if (flags & 00002000) access_mask |= FILE_APPEND_DATA;

    if (flags & 00000100) {
        if (flags & 00000200) disposition = FILE_CREATE;
        else if (flags & 00001000) disposition = FILE_OVERWRITE_IF;
        else disposition = FILE_OPEN_IF;
    } else if (flags & 00001000) {
        disposition = FILE_OVERWRITE;
    }

    if (flags & 00200000) {
        options |= FILE_DIRECTORY_FILE;
        access_mask = FILE_LIST_DIRECTORY | SYNCHRONIZE;
    }

    status = Nt_CreateFile(&hFile, access_mask, &oa, &iosb, NULL, 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           disposition, options, NULL, 0);


    if (!NT_SUCCESS(status) && g_root_drive == 'D') {
        TranslatePathToNTDrive(resolved, nt_path, 260, 'C');
        u_name.Length = 0;
        while (nt_path[u_name.Length / 2]) u_name.Length += 2;
        u_name.MaximumLength = u_name.Length + 2;
        status = Nt_CreateFile(&hFile, access_mask, &oa, &iosb, NULL, 0,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               disposition, options, NULL, 0);
    }

    if (!NT_SUCCESS(status) && (options & FILE_DIRECTORY_FILE)) {
        options &= ~FILE_DIRECTORY_FILE;
        options |= FILE_NON_DIRECTORY_FILE;
        access_mask = FILE_READ_DATA | SYNCHRONIZE;
        status = Nt_CreateFile(&hFile, access_mask, &oa, &iosb, NULL, 0,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               FILE_OPEN, options, NULL, 0);
    }

    if (!NT_SUCCESS(status)) return -LINUX_ENOENT;

    g_fds[fd].h = hFile;
    g_fds[fd].is_open = 1;
    g_fds[fd].is_dir = (flags & 00200000) ? 1 : 0;
    g_fds[fd].dir_first = 1;
    if (flags & 00200000) {
        CanonicalizePosixPath(resolved, g_fds[fd].dir_path, sizeof(g_fds[fd].dir_path));
    }
    return fd;
}

static long sys_close(int fd) {
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;

    if (g_fds[fd].is_pipe && g_ipc) {
        int idx = g_fds[fd].ipc_idx;
        if (idx >= 0 && idx < MAX_IPC_PIPES) {
            if (g_fds[fd].is_pipe_write) __sync_fetch_and_sub(&g_ipc->pipes[idx].write_refs, 1);
            else __sync_fetch_and_sub(&g_ipc->pipes[idx].read_refs, 1);
        }
        g_fds[fd].is_open = 0;
        return 0;
    }

    if (g_fds[fd].is_sock && g_ipc) {
        int idx = g_fds[fd].ipc_idx;
        if ((g_fds[fd].sock_state == SOCK_LISTENING || g_fds[fd].sock_state == SOCK_BOUND) && idx >= 0 && idx < MAX_IPC_LISTENERS) {
            if (__sync_sub_and_fetch(&g_ipc->listeners[idx].refs, 1) <= 0) {
                g_ipc->listeners[idx].active = 0;
            }
        } else if (g_fds[fd].sock_state == SOCK_CONNECTED && idx >= 0 && idx < MAX_IPC_CONNS) {
            if (g_fds[fd].is_server) {
                if (__sync_sub_and_fetch(&g_ipc->conns[idx].server_refs, 1) <= 0)
                    g_ipc->conns[idx].server_closed = 1;
            } else {
                if (__sync_sub_and_fetch(&g_ipc->conns[idx].client_refs, 1) <= 0)
                    g_ipc->conns[idx].client_closed = 1;
            }
            if (g_ipc->conns[idx].server_closed && g_ipc->conns[idx].client_closed) {
                g_ipc->conns[idx].state = CONN_FREE;
            }
        }
        g_fds[fd].is_open = 0;
        return 0;
    }

    if (g_fds[fd].is_eventfd && g_ipc) {
        int idx = g_fds[fd].ipc_idx;
        if (idx >= 0 && idx < MAX_IPC_EVENTFDS) {
            if (__sync_sub_and_fetch(&g_ipc->eventfds[idx].refs, 1) <= 0)
                g_ipc->eventfds[idx].in_use = 0;
        }
        g_fds[fd].is_open = 0;
        return 0;
    }

    if (g_fds[fd].is_epoll) {
        int idx = g_fds[fd].ipc_idx;
        if (idx >= 0 && idx < MAX_EPOLLS) g_epolls[idx].in_use = 0;
        g_fds[fd].is_open = 0;
        return 0;
    }

    if (g_fds[fd].is_inotify) {
        g_fds[fd].is_open = 0;
        return 0;
    }

    if (!g_fds[fd].is_console && !g_fds[fd].is_devnull && !g_fds[fd].is_xvfb_fb && g_fds[fd].h) {
        Nt_Close(g_fds[fd].h);
    }
    g_fds[fd].is_open = 0;
    g_fds[fd].h = NULL;
    g_fds[fd].dir_path[0] = '\0';
    return 0;
}

static long sys_lseek(int fd, s64 offset, int whence) {
    FILE_POSITION_INFORMATION fpi;
    FILE_STANDARD_INFORMATION fsi;
    IO_STATUS_BLOCK iosb;

    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;
    if (g_fds[fd].is_console || g_fds[fd].is_pipe || g_fds[fd].is_sock) return -LINUX_ESPIPE;
    if (g_fds[fd].is_xvfb_fb || g_fds[fd].is_devnull) {
        if (whence == 0) g_fds[fd].offset = (u64)offset;
        else if (whence == 1) g_fds[fd].offset += offset;
        return (long)g_fds[fd].offset;
    }

    if (whence == 0) fpi.CurrentByteOffset.QuadPart = offset;
    else if (whence == 1) fpi.CurrentByteOffset.QuadPart = (s64)g_fds[fd].offset + offset;
    else if (whence == 2) {
        Nt_QueryInformationFile(g_fds[fd].h, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
        fpi.CurrentByteOffset.QuadPart = fsi.EndOfFile.QuadPart + offset;
    } else return -LINUX_EINVAL;

    Nt_SetInformationFile(g_fds[fd].h, &iosb, &fpi, sizeof(fpi), FilePositionInformation);
    g_fds[fd].offset = (u64)fpi.CurrentByteOffset.QuadPart;
    return (long)fpi.CurrentByteOffset.QuadPart;
}

static long sys_brk(unsigned long addr) {
    if (addr == 0 || addr < g_brk_base) return g_brk_curr;
    if (addr > g_brk_limit) return g_brk_curr;

    if (addr > g_brk_curr) {
        unsigned long commit_base = g_brk_curr & ~4095UL;
        unsigned long commit_end  = (addr + 4095UL) & ~4095UL;
        if (commit_end > commit_base) {
            unsigned long size = commit_end - commit_base;
            void *base = (void *)commit_base;
            if (NT_SUCCESS(Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE))) {
                g_brk_curr = addr;
            }
        } else {
            g_brk_curr = addr;
        }
    } else {
        g_brk_curr = addr;
    }
    return g_brk_curr;
}

static u32 g_mmap_arena = 0x30000000;

static long sys_mmap2(void *addr, unsigned long len, int prot, int flags, int fd, unsigned long pgoff) {
    if (len == 0) return -LINUX_EINVAL;
    unsigned long size = (len + 4095UL) & ~4095UL;

    /* Shared Xvfb screen0 framebuffer mapping */
    if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && g_fds[fd].is_xvfb_fb && g_ipc) {
        g_ipc->xvfb_fb_size = (unsigned int)len;
        g_ipc->graphics_active = 1;
        shim_debug_print("[mmap xvfb_fb] ");
        shim_debug_print(g_current_exe_path);
        shim_debug_print("\n");
        return (long)g_ipc->xvfb_fb;
    }

    void *base = addr;
    NTSTATUS status = -1;

    if (flags & 0x10) { /* MAP_FIXED */
        void *page_base = (void *)((unsigned long)addr & ~4095UL);
        unsigned long page_size = (((unsigned long)addr + len + 4095UL) & ~4095UL) - (unsigned long)page_base;
        unsigned long alloc_size = page_size;
        base = page_base;
        status = Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &alloc_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(status)) {
            void *res_base = (void *)((unsigned long)addr & ~0xFFFFUL);
            unsigned long res_size = (((unsigned long)addr + len + 0xFFFFUL) & ~0xFFFFUL) - (unsigned long)res_base;
            status = Nt_AllocateVirtualMemory((HANDLE)-1, &res_base, 0, &res_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        }
        if (!NT_SUCCESS(status)) {
            unsigned long old_prot = 0;
            base = page_base;
            alloc_size = page_size;
            status = Nt_ProtectVirtualMemory((HANDLE)-1, &base, &alloc_size, PAGE_EXECUTE_READWRITE, &old_prot);
        }
        base = addr;
    } else {
        base = NULL;
        unsigned long alloc_size = size;
        status = Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &alloc_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }

    if (!NT_SUCCESS(status) || !base) {
        shim_debug_print("[mmap FAILED] ");
        shim_debug_print(g_current_exe_path);
        shim_debug_print("\n");
        return -LINUX_ENOMEM;
    }

    /* Zero memory before file read so .bss tails in MAP_FIXED library segments are clean */
    for (unsigned long k = 0; k < size; k++) {
        ((unsigned char *)base)[k] = 0;
    }

    if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && !(flags & 0x20) && g_fds[fd].h) {
        IO_STATUS_BLOCK iosb;
        LARGE_INTEGER li;
        li.QuadPart = (s64)pgoff * 4096LL;
        Nt_ReadFile(g_fds[fd].h, NULL, NULL, NULL, &iosb, base, len, &li, NULL);
    }

    return (long)base;
}

static long sys_mprotect(void *addr, unsigned long len, int prot) {
    void *base = (void *)((unsigned long)addr & ~4095UL);
    unsigned long size = (((unsigned long)addr + len + 4095UL) & ~4095UL) - (unsigned long)base;
    unsigned long old_prot = 0;
    if (size == 0) return 0;
    NTSTATUS status = Nt_ProtectVirtualMemory((HANDLE)-1, &base, &size, PAGE_EXECUTE_READWRITE, &old_prot);
    if (!NT_SUCCESS(status)) {
        unsigned long alloc_size = size;
        Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &alloc_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    return 0;
}

static void shim_clear_unmapped_tls(unsigned long start, unsigned long end);

static long sys_munmap(void *addr, unsigned long len) {
    if (!addr || len == 0) return 0;
    unsigned long start = (unsigned long)addr & ~4095UL;
    unsigned long end   = ((unsigned long)addr + len + 4095UL) & ~4095UL;
    if (start >= 0x10000UL && end > start) {
        shim_clear_unmapped_tls(start, end);
        if ((start & 0xFFFFUL) == 0) {
            void *rel_base = (void *)start;
            unsigned long rel_sz = 0;
            if (NT_SUCCESS(Nt_FreeVirtualMemory((HANDLE)-1, &rel_base, &rel_sz, 0x8000 /* MEM_RELEASE */))) {
                return 0;
            }
        }
        void *base = (void *)start;
        unsigned long sz = end - start;
        Nt_FreeVirtualMemory((HANDLE)-1, &base, &sz, MEM_DECOMMIT);
    }
    return 0;
}

#define LINUX_TCGETS     0x5401
#define LINUX_TCSETS     0x5402
#define LINUX_TCSETSW    0x5403
#define LINUX_TCSETSF    0x5404
#define LINUX_TIOCGWINSZ 0x5413
#define LINUX_FIONREAD   0x541B
#define LINUX_FIONBIO    0x5421

static long get_current_pid(void);

static long sys_ioctl(int fd, unsigned long req, void *arg) {
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;

    if (req == LINUX_FIONBIO) {
        if (arg) g_fds[fd].nonblock = (*(int *)arg) ? 1 : 0;
        return 0;
    }
    if (req == LINUX_FIONREAD) {
        int avail = 0;
        if (g_fds[fd].is_sock && g_ipc && g_fds[fd].sock_state == SOCK_CONNECTED) {
            SHIM_IPC_CONN *conn = &g_ipc->conns[g_fds[fd].ipc_idx];
            SHIM_IPC_RING *rx = g_fds[fd].is_server ? &conn->c2s : &conn->s2c;
            avail = (int)rx->count;
        } else if (g_fds[fd].is_pipe && g_ipc) {
            avail = (int)g_ipc->pipes[g_fds[fd].ipc_idx].count;
        }
        if (arg) *(int *)arg = avail;
        return 0;
    }
    if (req == 0x80045430UL /* TIOCGPTN */) {
        if (arg) *(int *)arg = g_fds[fd].ipc_idx;
        return 0;
    }
    if (req == 0x5420UL /* TIOCPKT */) {
        if (arg) g_fds[fd].pty_pkt = (*(int *)arg) ? 1 : 0;
        return 0;
    }
    if (req == 0x5441UL /* TIOCGPTPEER */ && g_fds[fd].is_pty && !g_fds[fd].is_server && g_ipc) {
        int cidx = g_fds[fd].ipc_idx;
        int flags = (int)(unsigned long)arg;
        if (cidx < 0 || cidx >= MAX_IPC_CONNS) return -LINUX_EINVAL;
        int sfd = -1;
        for (int i = 3; i < MAX_FD; i++) {
            if (!g_fds[i].is_open) { sfd = i; break; }
        }
        if (sfd < 0) return -LINUX_EMFILE;
        SHIM_IPC_CONN *conn = &g_ipc->conns[cidx];
        if (conn->listener_idx == -2) {
            conn->listener_idx = -3; /* First slave open claims initial server_ref */
        } else {
            __sync_fetch_and_add(&conn->server_refs, 1);
        }
        for (unsigned int k = 0; k < sizeof(SHIM_FD); k++) ((unsigned char *)&g_fds[sfd])[k] = 0;
        g_fds[sfd].is_open = 1;
        g_fds[sfd].is_sock = 1;
        g_fds[sfd].is_pty = 1;
        g_fds[sfd].is_server = 1;
        g_fds[sfd].sock_state = SOCK_CONNECTED;
        g_fds[sfd].ipc_idx = cidx;
        g_fds[sfd].nonblock = (flags & 00004000) ? 1 : 0;
        g_fds[sfd].cloexec  = (flags & 02000000) ? 1 : 0;
        shim_debug_print("[tiocgptpeer] ");
        shim_debug_print(g_current_exe_path);
        shim_debug_hex(" cidx=", (unsigned long)cidx);
        return sfd;
    }
    if (req == 0x40045431UL /* TIOCSPTLCK */ || req == 0x540EUL /* TIOCSCTTY */ ||
        req == 0x540FUL /* TIOCGPGRP */ || req == 0x5410UL /* TIOCSPGRP */ ||
        req == 0x5414UL /* TIOCSWINSZ */) {
        if (req == 0x540FUL && arg) *(int *)arg = (int)get_current_pid();
        return 0;
    }
    if (req == LINUX_TIOCGWINSZ) {
        struct linux_winsize *ws = (struct linux_winsize *)arg;
        if (ws) {
            ws->ws_row = 24;
            ws->ws_col = 80;
            ws->ws_xpixel = 640;
            ws->ws_ypixel = 480;
        }
        return 0;
    }
    if (req == LINUX_TCGETS) {
        if (!g_fds[fd].is_console && !g_fds[fd].is_pty &&
            (fd > 2 || g_fds[fd].is_pipe || g_fds[fd].is_sock || g_fds[fd].is_devnull || g_fds[fd].h))
            return -LINUX_ENOTTY;
        struct linux_termios *tio = (struct linux_termios *)arg;
        if (tio) {
            for (int i = 0; i < (int)sizeof(*tio); i++) ((char *)tio)[i] = 0;
            tio->c_iflag = 0x0500;
            tio->c_oflag = 0x0005;
            tio->c_cflag = 0x00BF;
            tio->c_lflag = 0x8A3B;
        }
        return 0;
    }
    if (req == LINUX_TCSETS || req == LINUX_TCSETSW || req == LINUX_TCSETSF) {
        return 0;
    }
    return 0;
}

static long sys_getdents64(int fd, void *dirp, unsigned int count) {
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    unsigned char *out_p = (unsigned char *)dirp;
    unsigned int out_bytes = 0;

    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;
    if (g_fds[fd].dir_eof) return 0;

    if (g_fds[fd].dir_first && g_fds[fd].dir_path[0] == '/' && g_fds[fd].dir_path[1] == '\0') {
        unsigned int rlen_dot = (sizeof(struct linux_dirent64) + 1 + 8) & ~7;
        unsigned int rlen_dotdot = (sizeof(struct linux_dirent64) + 2 + 8) & ~7;
        if (out_bytes + rlen_dot + rlen_dotdot <= count) {
            struct linux_dirent64 *d1 = (struct linux_dirent64 *)(out_p + out_bytes);
            d1->d_ino = 1; d1->d_off = out_bytes + rlen_dot;
            d1->d_reclen = (unsigned short)rlen_dot; d1->d_type = 4;
            d1->d_name[0] = '.'; d1->d_name[1] = '\0';
            out_bytes += rlen_dot;

            struct linux_dirent64 *d2 = (struct linux_dirent64 *)(out_p + out_bytes);
            d2->d_ino = 1; d2->d_off = out_bytes + rlen_dotdot;
            d2->d_reclen = (unsigned short)rlen_dotdot; d2->d_type = 4;
            d2->d_name[0] = '.'; d2->d_name[1] = '.'; d2->d_name[2] = '\0';
            out_bytes += rlen_dotdot;
        }
    }

    while (out_bytes < count) {
        status = Nt_QueryDirectoryFile(
            g_fds[fd].h, NULL, NULL, NULL, &iosb,
            g_fds[fd].dir_buffer, sizeof(g_fds[fd].dir_buffer),
            FileBothDirectoryInformation, 0, NULL, g_fds[fd].dir_first
        );
        g_fds[fd].dir_first = 0;
        if (!NT_SUCCESS(status) || iosb.Information == 0) {
            g_fds[fd].dir_eof = 1;
            break;
        }

        FILE_BOTH_DIR_INFORMATION *info = (FILE_BOTH_DIR_INFORMATION *)g_fds[fd].dir_buffer;
        while (info && out_bytes < count) {
            unsigned int name_len = info->FileNameLength / 2;
            unsigned int reclen = ((sizeof(struct linux_dirent64) + name_len + 8) & ~7);
            if (out_bytes + reclen > count) break;

            struct linux_dirent64 *d = (struct linux_dirent64 *)(out_p + out_bytes);
            d->d_ino = info->FileIndex ? info->FileIndex : 1;
            d->d_off = (s64)out_bytes + reclen;
            d->d_reclen = (unsigned short)reclen;
            d->d_type = (info->FileAttributes & 0x10) ? 4 : 8;
            for (unsigned int k = 0; k < name_len; k++) d->d_name[k] = (char)info->FileName[k];
            d->d_name[name_len] = '\0';
            out_bytes += reclen;

            if (info->NextEntryOffset == 0) break;
            info = (FILE_BOTH_DIR_INFORMATION *)((unsigned char *)info + info->NextEntryOffset);
        }
        if (iosb.Information < sizeof(g_fds[fd].dir_buffer)) break;
    }
    return (long)out_bytes;
}

static u64 hash_path_ino(const char *posix_path) {
    char can[260];
    CanonicalizePosixPath(posix_path, can, sizeof(can));
    u64 h = 14695981039346656037ULL;
    for (unsigned int i = 0; can[i]; i++) {
        unsigned char c = (unsigned char)can[i];
        if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
        h ^= (u64)c;
        h *= 1099511628211ULL;
    }
    return h ? h : 1ULL;
}

static long sys_fstat64_fd(int fd, struct linux_stat64 *st) {
    FILE_STANDARD_INFORMATION fsi;
    IO_STATUS_BLOCK iosb;
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open || !st) return -LINUX_EBADF;
    for (unsigned int k = 0; k < sizeof(*st); k++) ((unsigned char *)st)[k] = 0;
    st->st_dev = 1;
    st->st_ino = g_fds[fd].dir_path[0] ? hash_path_ino(g_fds[fd].dir_path) : (u64)(fd + 1000);
    st->st_nlink = 1;
    st->st_blksize = 4096;
    st->st_atim.tv_sec = 1700000000;
    st->st_mtim.tv_sec = 1700000000;
    st->st_ctim.tv_sec = 1700000000;
    if (g_fds[fd].is_console || g_fds[fd].is_devnull || g_fds[fd].is_pty) {
        st->st_mode = 0020666;
        return 0;
    }
    if (g_fds[fd].is_pipe || g_fds[fd].is_eventfd) {
        st->st_mode = 0010666;
        return 0;
    }
    if (g_fds[fd].is_sock) {
        st->st_mode = 0140666;
        return 0;
    }
    if (g_fds[fd].is_xvfb_fb) {
        st->st_mode = 0100666;
        st->st_size = (g_ipc && g_ipc->xvfb_fb_size) ? g_ipc->xvfb_fb_size : 1923232;
        return 0;
    }
    Nt_QueryInformationFile(g_fds[fd].h, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    st->st_mode = fsi.Directory ? 0040755 : 0100755;
    st->st_size = fsi.EndOfFile.QuadPart;
    st->st_blocks = (fsi.AllocationSize.QuadPart + 511) / 512;
    return 0;
}

static long sys_stat64(const char *path, struct linux_stat64 *st) {
    unsigned short nt_path[260];
    UNICODE_STRING u_name;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    FILE_STANDARD_INFORMATION fsi;
    NTSTATUS status;

    if (!path || !path[0]) path = ".";
    if (!st) return -LINUX_EFAULT;

    for (unsigned int k = 0; k < sizeof(*st); k++) ((unsigned char *)st)[k] = 0;
    u64 ino = hash_path_ino(path);

    if (shim_strcmp(path, "/dev/null") == 0 || shim_strcmp(path, "/dev/zero") == 0 ||
        shim_strcmp(path, "/dev/tty") == 0 || shim_strcmp(path, "/dev/ptmx") == 0 ||
        shim_strcmp(path, "/dev/fb0") == 0 || shim_strncmp(path, "/dev/pts/", 9) == 0) {
        st->st_dev = 1; st->st_ino = ino; st->st_mode = 0020666; st->st_nlink = 1;
        st->st_blksize = 4096;
        return 0;
    }
    if (shim_strcmp(path, "/dev/pts") == 0) {
        st->st_dev = 1; st->st_ino = ino; st->st_mode = 0040755; st->st_nlink = 2;
        st->st_blksize = 4096;
        return 0;
    }

    TranslatePathToNT(path, nt_path, 260);
    u_name.Length = 0;
    while (nt_path[u_name.Length / 2]) u_name.Length += 2;
    u_name.MaximumLength = u_name.Length + 2;
    u_name.Buffer = nt_path;

    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &u_name;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    status = Nt_OpenFile(&hFile, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) {
        status = Nt_OpenFile(&hFile, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    }
    if (!NT_SUCCESS(status) && g_root_drive == 'D') {
        TranslatePathToNTDrive(path, nt_path, 260, 'C');
        u_name.Length = 0;
        while (nt_path[u_name.Length / 2]) u_name.Length += 2;
        u_name.MaximumLength = u_name.Length + 2;
        status = Nt_OpenFile(&hFile, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_SYNCHRONOUS_IO_NONALERT);
        if (!NT_SUCCESS(status)) {
            status = Nt_OpenFile(&hFile, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        }
    }

    if (!NT_SUCCESS(status)) {
        char can[260];
        CanonicalizePosixPath(path, can, sizeof(can));
        if ((can[0] == '/' && can[1] == '\0') ||
            shim_strcmp(can, "/tmp") == 0 ||
            shim_strcmp(can, "/tmp/.X11-unix") == 0 ||
            shim_strcmp(can, "/tmp/.ICE-unix") == 0 ||
            shim_strcmp(can, "/var") == 0 ||
            shim_strcmp(can, "/var/tmp") == 0 ||
            shim_strcmp(can, "/root") == 0) {
            st->st_dev = 1; st->st_ino = ino; st->st_mode = 0041777;
            st->st_nlink = 2; st->st_size = 4096; st->st_blksize = 4096; st->st_blocks = 8;
            st->st_atim.tv_sec = 1700000000; st->st_mtim.tv_sec = 1700000000; st->st_ctim.tv_sec = 1700000000;
            return 0;
        }
        return -LINUX_ENOENT;
    }

    status = Nt_QueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    Nt_Close(hFile);
    if (!NT_SUCCESS(status)) return -LINUX_EIO;

    st->st_dev = 1;
    st->st_ino = ino;
    st->st_mode = fsi.Directory ? 0040755 : 0100755;
    st->st_nlink = fsi.NumberOfLinks ? fsi.NumberOfLinks : 1;
    st->st_size = fsi.EndOfFile.QuadPart;
    st->st_blksize = 4096;
    st->st_blocks = (fsi.AllocationSize.QuadPart + 511) / 512;
    st->st_atim.tv_sec = 1700000000;
    st->st_mtim.tv_sec = 1700000000;
    st->st_ctim.tv_sec = 1700000000;
    return 0;
}

static long sys_fstatat64(int dirfd, const char *path, struct linux_stat64 *st, int flags) {
    if ((flags & 0x1000 /* AT_EMPTY_PATH */) || !path || path[0] == '\0') {
        if (dirfd >= 0 && dirfd < MAX_FD && g_fds[dirfd].is_open) {
            return sys_fstat64_fd(dirfd, st);
        }
    }
    if (!path) return -LINUX_EINVAL;
    if (path[0] == '/' || dirfd == -100) return sys_stat64(path, st);
    if (dirfd >= 0 && dirfd < MAX_FD && g_fds[dirfd].is_open && g_fds[dirfd].dir_path[0]) {
        char full[512];
        unsigned int p = 0;
        const char *dp = g_fds[dirfd].dir_path;
        while (*dp && p < 250) full[p++] = *dp++;
        if (p > 0 && full[p - 1] != '/') full[p++] = '/';
        while (*path && p < 500) full[p++] = *path++;
        full[p] = '\0';
        return sys_stat64(full, st);
    }
    return sys_stat64(path, st);
}

static long sys_readlink(const char *path, char *buf, unsigned int bufsiz) {
    if (!path || !buf || bufsiz == 0) return -LINUX_EINVAL;
    char can[260];
    CanonicalizePosixPathNoSymlink(path, can, sizeof(can));
    if (shim_strcmp(can, "/proc/self/exe") == 0) {
        unsigned int len = shim_strlen(g_current_exe_path);
        if (len > bufsiz) len = bufsiz;
        for (unsigned int i = 0; i < len; i++) buf[i] = g_current_exe_path[i];
        return (long)len;
    }
    for (int i = 0; i < g_num_symlinks; i++) {
        if (shim_strcmp(can, g_symlinks[i].link) == 0) {
            unsigned int len = shim_strlen(g_symlinks[i].target);
            if (len > bufsiz) len = bufsiz;
            for (unsigned int k = 0; k < len; k++) buf[k] = g_symlinks[i].target[k];
            return (long)len;
        }
    }
    return -LINUX_EINVAL;
}

static long sys_getcwd(char *buf, unsigned long size) {
    unsigned long len = shim_strlen(g_cwd);
    if (len + 1 > size) return -LINUX_ERANGE;
    for (unsigned long i = 0; i <= len; i++) buf[i] = g_cwd[i];
    return (long)(len + 1);
}

static long sys_chdir(const char *path) {
    if (!path || !path[0]) return -LINUX_ENOENT;
    char can[260];
    CanonicalizePosixPath(path, can, sizeof(can));
    struct linux_stat64 st;
    if (sys_stat64(can, &st) < 0) return -LINUX_ENOENT;
    shim_strcpy(g_cwd, can, sizeof(g_cwd));
    return 0;
}

static long sys_mkdir_single(const char *pathname) {
    unsigned short nt_path[260];
    UNICODE_STRING u_name;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    TranslatePathToNT(pathname, nt_path, 260);
    u_name.Length = 0;
    while (nt_path[u_name.Length / 2]) u_name.Length += 2;
    u_name.MaximumLength = u_name.Length + 2;
    u_name.Buffer = nt_path;
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &u_name;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;
    NTSTATUS st = Nt_CreateFile(&h, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, NULL, 0,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) return -LINUX_EEXIST;
    Nt_Close(h);
    return 0;
}

static void EnsureParentDirsExist(const char *posix_path) {
    char can[260];
    CanonicalizePosixPath(posix_path, can, sizeof(can));
    for (unsigned int i = 1; can[i]; i++) {
        if (can[i] == '/') {
            can[i] = '\0';
            sys_mkdir_single(can);
            can[i] = '/';
        }
    }
}

static long sys_mkdir(const char *pathname, unsigned int mode) {
    (void)mode;
    EnsureParentDirsExist(pathname);
    return sys_mkdir_single(pathname);
}

static long sys_unlink(const char *pathname) {
    unsigned short nt_path[260];
    UNICODE_STRING u_name;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    TranslatePathToNT(pathname, nt_path, 260);
    u_name.Length = 0;
    while (nt_path[u_name.Length / 2]) u_name.Length += 2;
    u_name.MaximumLength = u_name.Length + 2;
    u_name.Buffer = nt_path;
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &u_name;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;
    NTSTATUS st = Nt_OpenFile(&h, DELETE | SYNCHRONIZE, &oa, &iosb,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(st)) return 0;
    FILE_DISPOSITION_INFORMATION disp;
    disp.DeleteFile = 1;
    Nt_SetInformationFile(h, &iosb, &disp, sizeof(disp), FileDispositionInformation);
    Nt_Close(h);
    return 0;
}

static long sys_rename(const char *oldpath, const char *newpath) {
    if (!oldpath || !newpath) return -LINUX_EINVAL;
    long rfd = sys_openat(-100, oldpath, 0, 0);
    if (rfd < 0) return rfd;
    sys_unlink(newpath);
    long wfd = sys_openat(-100, newpath, 00000100 | 00001000 | 00000001, 0644);
    if (wfd < 0) {
        sys_close((int)rfd);
        return wfd;
    }
    unsigned char buf[4096];
    for (;;) {
        long n = sys_read((int)rfd, buf, sizeof(buf));
        if (n <= 0) break;
        sys_write((int)wfd, buf, (unsigned int)n);
    }
    sys_close((int)rfd);
    sys_close((int)wfd);
    sys_unlink(oldpath);
    return 0;
}

static long sys_access(const char *pathname, int mode) {
    (void)mode;
    struct linux_stat64 st;
    return sys_stat64(pathname, &st);
}

#define LINUX_F_DUPFD         0
#define LINUX_F_GETFD         1
#define LINUX_F_SETFD         2
#define LINUX_F_GETFL         3
#define LINUX_F_SETFL         4
#define LINUX_F_DUPFD_CLOEXEC 1030

static void ShimDupHandleSlot(int newfd) {
    HANDLE src = g_fds[newfd].h, dst = NULL;
    if (g_fds[newfd].is_console || g_fds[newfd].is_pipe || g_fds[newfd].is_sock ||
        g_fds[newfd].is_eventfd || g_fds[newfd].is_epoll || g_fds[newfd].is_xvfb_fb ||
        g_fds[newfd].is_devnull || !src) {
        shim_fd_addref(&g_fds[newfd]);
        return;
    }
    if (NT_SUCCESS(Nt_DuplicateObject((HANDLE)-1, src, (HANDLE)-1, &dst, 0, 0, 2)) && dst) {
        g_fds[newfd].h = dst;
    }
}

static long sys_dup_min(int oldfd, int min_fd, int cloexec) {
    if (oldfd < 0 || oldfd >= MAX_FD || !g_fds[oldfd].is_open) return -LINUX_EBADF;
    if (min_fd < 0 || min_fd >= MAX_FD) return -LINUX_EINVAL;
    int newfd;
    for (newfd = min_fd; newfd < MAX_FD; newfd++) {
        if (!g_fds[newfd].is_open) break;
    }
    if (newfd >= MAX_FD) return -LINUX_EMFILE;
    g_fds[newfd] = g_fds[oldfd];
    g_fds[newfd].cloexec = (unsigned char)cloexec;
    ShimDupHandleSlot(newfd);
    return newfd;
}

static long sys_dup(int oldfd) {
    return sys_dup_min(oldfd, 0, 0);
}

static long sys_dup2(int oldfd, int newfd, int flags) {
    if (oldfd < 0 || oldfd >= MAX_FD || !g_fds[oldfd].is_open) return -LINUX_EBADF;
    if (newfd < 0 || newfd >= MAX_FD) return -LINUX_EBADF;
    if (oldfd == newfd) return newfd;
    if (g_fds[newfd].is_open) sys_close(newfd);
    g_fds[newfd] = g_fds[oldfd];
    g_fds[newfd].cloexec = (flags & 02000000) ? 1 : 0;
    ShimDupHandleSlot(newfd);
    return newfd;
}

static long sys_fcntl(int fd, int cmd, unsigned long arg) {
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;
    switch (cmd) {
        case LINUX_F_DUPFD:
            return sys_dup_min(fd, (int)arg, 0);
        case LINUX_F_DUPFD_CLOEXEC:
            return sys_dup_min(fd, (int)arg, 1);
        case LINUX_F_GETFD:
            return g_fds[fd].cloexec ? 1 : 0;
        case LINUX_F_SETFD:
            g_fds[fd].cloexec = (arg & 1) ? 1 : 0;
            return 0;
        case LINUX_F_GETFL:
            return 2 | (g_fds[fd].nonblock ? 00004000 : 0);
        case LINUX_F_SETFL:
            g_fds[fd].nonblock = (arg & 00004000) ? 1 : 0;
            return 0;
        default:
            return 0;
    }
}

static long sys_pipe2(int *pipefd, int flags) {
    if (!pipefd || !g_ipc) return -LINUX_EFAULT;
    int rfd = -1, wfd = -1;
    for (int i = 3; i < MAX_FD; i++) {
        if (!g_fds[i].is_open) {
            if (rfd < 0) rfd = i;
            else if (wfd < 0) { wfd = i; break; }
        }
    }
    if (rfd < 0 || wfd < 0) return -LINUX_EMFILE;

    int pidx = -1;
    for (int i = 0; i < MAX_IPC_PIPES; i++) {
        if (g_ipc->pipes[i].read_refs <= 0 && g_ipc->pipes[i].write_refs <= 0) {
            pidx = i;
            break;
        }
    }
    if (pidx < 0) pidx = 0;

    SHIM_IPC_PIPE *p = &g_ipc->pipes[pidx];
    p->lock = 0;
    p->head = 0;
    p->tail = 0;
    p->count = 0;
    p->read_refs = 1;
    p->write_refs = 1;

    for (unsigned int k = 0; k < sizeof(SHIM_FD); k++) {
        ((unsigned char *)&g_fds[rfd])[k] = 0;
        ((unsigned char *)&g_fds[wfd])[k] = 0;
    }
    g_fds[rfd].is_open = 1;
    g_fds[rfd].is_pipe = 1;
    g_fds[rfd].is_pipe_write = 0;
    g_fds[rfd].ipc_idx = pidx;
    g_fds[rfd].nonblock = (flags & 00004000) ? 1 : 0;
    g_fds[rfd].cloexec  = (flags & 02000000) ? 1 : 0;

    g_fds[wfd].is_open = 1;
    g_fds[wfd].is_pipe = 1;
    g_fds[wfd].is_pipe_write = 1;
    g_fds[wfd].ipc_idx = pidx;
    g_fds[wfd].nonblock = (flags & 00004000) ? 1 : 0;
    g_fds[wfd].cloexec  = (flags & 02000000) ? 1 : 0;

    pipefd[0] = rfd;
    pipefd[1] = wfd;
    return 0;
}

static long sys_eventfd2(unsigned int initval, int flags) {
    if (!g_ipc) return -LINUX_ENOMEM;
    int fd = -1;
    for (int i = 3; i < MAX_FD; i++) {
        if (!g_fds[i].is_open) { fd = i; break; }
    }
    if (fd < 0) return -LINUX_EMFILE;

    int eidx = -1;
    for (int i = 0; i < MAX_IPC_EVENTFDS; i++) {
        if (!g_ipc->eventfds[i].in_use) { eidx = i; break; }
    }
    if (eidx < 0) eidx = 0;

    g_ipc->eventfds[eidx].in_use = 1;
    g_ipc->eventfds[eidx].refs = 1;
    g_ipc->eventfds[eidx].counter = initval;

    for (unsigned int k = 0; k < sizeof(SHIM_FD); k++) ((unsigned char *)&g_fds[fd])[k] = 0;
    g_fds[fd].is_open = 1;
    g_fds[fd].is_eventfd = 1;
    g_fds[fd].ipc_idx = eidx;
    g_fds[fd].nonblock = (flags & 00004000) ? 1 : 0;
    g_fds[fd].cloexec  = (flags & 02000000) ? 1 : 0;
    return fd;
}

/* ========================================================================= */
/* Cross-Process Sockets (AF_UNIX /tmp/.X11-unix/X0 & AF_INET Loopback)      */
/* ========================================================================= */
struct linux_sockaddr_un {
    unsigned short sun_family;
    char sun_path[108];
};

struct linux_sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int   sin_addr;
    unsigned char  sin_zero[8];
};

struct linux_msghdr {
    void *msg_name;
    unsigned int msg_namelen;
    struct linux_iovec *msg_iov;
    unsigned int msg_iovlen;
    void *msg_control;
    unsigned int msg_controllen;
    unsigned int msg_flags;
};

static void NormalizeSockAddr(const void *addr, unsigned int addrlen, char *out_key) {
    out_key[0] = '\0';
    if (!addr || addrlen < 2) return;
    unsigned short fam = *(const unsigned short *)addr;
    if (fam == 1) { /* AF_UNIX */
        const struct linux_sockaddr_un *un = (const struct linux_sockaddr_un *)addr;
        const char *p = un->sun_path;
        unsigned int max_p = (addrlen > 2) ? (addrlen - 2) : 0;
        if (max_p > 106) max_p = 106;
        unsigned int out_i = 0;
        if (max_p > 0 && p[0] == '\0') {
            out_key[out_i++] = '@';
            p++;
            max_p--;
        }
        unsigned int k = 0;
        while (k < max_p && p[k]) {
            out_key[out_i++] = p[k];
            k++;
        }
        out_key[out_i] = '\0';
    } else if (fam == 2) { /* AF_INET */
        const struct linux_sockaddr_in *in = (const struct linux_sockaddr_in *)addr;
        unsigned int port = ((in->sin_port & 0xFF) << 8) | ((in->sin_port >> 8) & 0xFF);
        /* Map TCP 6000 (X11 :0) to the same listener or inet:port */
        if (port == 6000) {
            shim_strcpy(out_key, "/tmp/.X11-unix/X0", 108);
        } else {
            out_key[0] = 'i'; out_key[1] = 'n'; out_key[2] = 'e'; out_key[3] = 't'; out_key[4] = ':';
            out_key[5] = '0' + ((port / 10000) % 10);
            out_key[6] = '0' + ((port / 1000) % 10);
            out_key[7] = '0' + ((port / 100) % 10);
            out_key[8] = '0' + ((port / 10) % 10);
            out_key[9] = '0' + (port % 10);
            out_key[10] = '\0';
        }
    }
}

static long sys_socket(int domain, int type, int protocol) {
    (void)protocol;
    int fd = -1;
    for (int i = 3; i < MAX_FD; i++) {
        if (!g_fds[i].is_open) { fd = i; break; }
    }
    if (fd < 0) return -LINUX_EMFILE;

    for (unsigned int k = 0; k < sizeof(SHIM_FD); k++) ((unsigned char *)&g_fds[fd])[k] = 0;
    g_fds[fd].is_open = 1;
    g_fds[fd].is_sock = 1;
    g_fds[fd].sock_state = SOCK_CREATED;
    g_fds[fd].sock_domain = (unsigned char)domain;
    g_fds[fd].sock_type = (unsigned char)(type & 0xFF);
    g_fds[fd].nonblock = (type & 00004000) ? 1 : 0;
    g_fds[fd].cloexec  = (type & 02000000) ? 1 : 0;
    g_fds[fd].ipc_idx = -1;
    return fd;
}

static long sys_socketpair(int domain, int type, int protocol, int *sv) {
    if (!sv || !g_ipc) return -LINUX_EFAULT;
    long fd0 = sys_socket(domain, type, protocol);
    if (fd0 < 0) return fd0;
    long fd1 = sys_socket(domain, type, protocol);
    if (fd1 < 0) { sys_close((int)fd0); return fd1; }

    int cidx = -1;
    for (int i = 0; i < MAX_IPC_CONNS; i++) {
        if (__sync_bool_compare_and_swap(&g_ipc->conns[i].state, CONN_FREE, CONN_ESTABLISHED)) {
            cidx = i;
            break;
        }
    }
    if (cidx < 0) { sys_close((int)fd0); sys_close((int)fd1); return -LINUX_ENOMEM; }

    SHIM_IPC_CONN *conn = &g_ipc->conns[cidx];
    conn->listener_idx = -1;
    conn->client_refs = 1;
    conn->server_refs = 1;
    conn->client_closed = 0;
    conn->server_closed = 0;
    conn->c2s.lock = 0; conn->c2s.head = 0; conn->c2s.tail = 0; conn->c2s.count = 0;
    conn->s2c.lock = 0; conn->s2c.head = 0; conn->s2c.tail = 0; conn->s2c.count = 0;

    g_fds[fd0].sock_state = SOCK_CONNECTED;
    g_fds[fd0].is_server = 0;
    g_fds[fd0].ipc_idx = cidx;

    g_fds[fd1].sock_state = SOCK_CONNECTED;
    g_fds[fd1].is_server = 1;
    g_fds[fd1].ipc_idx = cidx;

    sv[0] = (int)fd0;
    sv[1] = (int)fd1;
    return 0;
}

static long sys_bind(int fd, const void *addr, unsigned int addrlen) {
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open || !g_fds[fd].is_sock || !g_ipc) return -LINUX_EBADF;
    char key[108];
    NormalizeSockAddr(addr, addrlen, key);
    if (!key[0]) return 0;

    /* Create dummy file if AF_UNIX path in /tmp */
    if (key[0] == '/') {
        EnsureParentDirsExist(key);
        long tmpfd = sys_openat(-100, key, 00000100 | 00000002, 0777);
        if (tmpfd >= 0) sys_close((int)tmpfd);
    }

    int lidx = -1;
    for (int i = 0; i < MAX_IPC_LISTENERS; i++) {
        if (g_ipc->listeners[i].active && shim_strcmp(g_ipc->listeners[i].addr, key) == 0) {
            lidx = i;
            break;
        }
    }
    if (lidx < 0) {
        for (int i = 0; i < MAX_IPC_LISTENERS; i++) {
            if (!g_ipc->listeners[i].active) { lidx = i; break; }
        }
    }
    if (lidx < 0) lidx = 0;

    shim_strcpy(g_ipc->listeners[lidx].addr, key, 108);
    g_ipc->listeners[lidx].refs = 1;
    g_ipc->listeners[lidx].active = 1;
    g_fds[fd].sock_state = SOCK_BOUND;
    g_fds[fd].ipc_idx = lidx;
    shim_debug_print("[bind] ");
    shim_debug_print(g_current_exe_path);
    shim_debug_print(" -> ");
    shim_debug_print(key);
    shim_debug_print("\n");
    return 0;
}

static long sys_listen(int fd, int backlog) {
    (void)backlog;
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open || !g_fds[fd].is_sock) return -LINUX_EBADF;
    g_fds[fd].sock_state = SOCK_LISTENING;
    return 0;
}

static long sys_connect(int fd, const void *addr, unsigned int addrlen) {
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open || !g_fds[fd].is_sock || !g_ipc) return -LINUX_EBADF;
    char key[108];
    NormalizeSockAddr(addr, addrlen, key);
    if (!key[0]) return -LINUX_ECONNREFUSED;

    int lidx = -1;
    for (int wait_try = 0; wait_try < 250; wait_try++) {
        for (int i = 0; i < MAX_IPC_LISTENERS; i++) {
            if (g_ipc->listeners[i].active && shim_strcmp(g_ipc->listeners[i].addr, key) == 0) {
                lidx = i;
                break;
            }
        }
        if (lidx >= 0) break;
        /* If connecting to X0 or dbus-session while server is still starting up, wait briefly */
        if (path_ends_with(key, "X0") || path_ends_with(key, "dbus-session")) {
            LARGE_INTEGER delay;
            delay.QuadPart = -200000LL; /* 20ms */
            Nt_DelayExecution(0, &delay);
        } else {
            break;
        }
    }
    if (lidx < 0) {
        shim_debug_print("[connect REFUSED] ");
        shim_debug_print(g_current_exe_path);
        shim_debug_print(" -> ");
        shim_debug_print(key);
        shim_debug_print("\n");
        return -LINUX_ECONNREFUSED;
    }

    int cidx = -1;
    for (int i = 0; i < MAX_IPC_CONNS; i++) {
        if (__sync_bool_compare_and_swap(&g_ipc->conns[i].state, CONN_FREE, CONN_ALLOCATING)) {
            cidx = i;
            break;
        }
    }
    if (cidx < 0) return -LINUX_EAGAIN;

    SHIM_IPC_CONN *conn = &g_ipc->conns[cidx];
    conn->client_refs = 1;
    conn->server_refs = 1;
    conn->client_closed = 0;
    conn->server_closed = 0;
    conn->c2s.lock = 0; conn->c2s.head = 0; conn->c2s.tail = 0; conn->c2s.count = 0;
    conn->s2c.lock = 0; conn->s2c.head = 0; conn->s2c.tail = 0; conn->s2c.count = 0;
    conn->listener_idx = lidx;
    __sync_synchronize();
    conn->state = CONN_SYN;

    g_fds[fd].sock_state = SOCK_CONNECTED;
    g_fds[fd].is_server = 0;
    g_fds[fd].ipc_idx = cidx;

    /* Wait up to 100ms for server accept, or proceed immediately since ring buffer is ready */
    s64 start_ms = shim_now_ms();
    for (int w = 0; shim_now_ms() - start_ms < 100; w++) {
        if (conn->state == CONN_ESTABLISHED) break;
        shim_ipc_wait(w);
    }
    shim_debug_print("[connect OK] ");
    shim_debug_print(g_current_exe_path);
    shim_debug_print(" -> ");
    shim_debug_print(key);
    shim_debug_print("\n");
    return 0;
}

static long sys_accept4(int fd, void *addr, unsigned int *addrlen, int flags) {
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open || !g_fds[fd].is_sock || !g_ipc) return -LINUX_EBADF;
    int lidx = g_fds[fd].ipc_idx;

    for (int wait_iter = 0; wait_iter < 64; wait_iter++) {
        for (int i = 0; i < MAX_IPC_CONNS; i++) {
            if (g_ipc->conns[i].listener_idx == lidx &&
                __sync_bool_compare_and_swap(&g_ipc->conns[i].state, CONN_SYN, CONN_ESTABLISHED)) {
                long newfd = sys_socket(g_fds[fd].sock_domain, g_fds[fd].sock_type | flags, 0);
                if (newfd < 0) return newfd;
                g_fds[newfd].sock_state = SOCK_CONNECTED;
                g_fds[newfd].is_server = 1;
                g_fds[newfd].ipc_idx = i;
                if (addr && addrlen && *addrlen >= 2) {
                    *(unsigned short *)addr = g_fds[fd].sock_domain;
                    *addrlen = 2;
                }
                shim_debug_print("[accept OK] ");
                shim_debug_print(g_current_exe_path);
                shim_debug_print(" <- ");
                if (lidx >= 0 && lidx < MAX_IPC_LISTENERS) shim_debug_print(g_ipc->listeners[lidx].addr);
                shim_debug_print("\n");
                return newfd;
            }
        }
        if (g_fds[fd].nonblock) return -LINUX_EAGAIN;
        shim_ipc_wait(wait_iter);
    }
    return -LINUX_EAGAIN;
}

static long sys_sendmsg(int fd, const struct linux_msghdr *msg, int flags) {
    if (!msg) return -LINUX_EFAULT;
    long total = 0;
    for (unsigned int i = 0; i < msg->msg_iovlen; i++) {
        if (msg->msg_iov[i].iov_len > 0 && msg->msg_iov[i].iov_base) {
            long r = sock_write_fd(fd, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, flags & 0x40);
            if (r < 0) return total > 0 ? total : r;
            total += r;
        }
    }
    return total;
}

static long sys_recvmsg(int fd, struct linux_msghdr *msg, int flags) {
    if (!msg) return -LINUX_EFAULT;
    msg->msg_controllen = 0;
    msg->msg_flags = 0;
    long total = 0;
    for (unsigned int i = 0; i < msg->msg_iovlen; i++) {
        if (msg->msg_iov[i].iov_len > 0 && msg->msg_iov[i].iov_base) {
            int dontwait = (flags & 0x40) || (total > 0);
            long r = sock_read_fd(fd, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, dontwait);
            if (r < 0) return total > 0 ? total : r;
            total += r;
            if (r < (long)msg->msg_iov[i].iov_len) break;
        }
    }
    return total;
}

static long sys_socketcall(int call, unsigned long *args) {
    if (!args) return -LINUX_EFAULT;
    switch (call) {
        case 1:  return sys_socket((int)args[0], (int)args[1], (int)args[2]);
        case 2:  return sys_bind((int)args[0], (const void *)args[1], (unsigned int)args[2]);
        case 3:  return sys_connect((int)args[0], (const void *)args[1], (unsigned int)args[2]);
        case 4:  return sys_listen((int)args[0], (int)args[1]);
        case 5:  return sys_accept4((int)args[0], (void *)args[1], (unsigned int *)args[2], 0);
        case 6:  /* getsockname */
        case 7:  /* getpeername */
            if (args[1] && args[2] && *(unsigned int *)args[2] >= 2) {
                *(unsigned short *)args[1] = 1;
                *(unsigned int *)args[2] = 2;
            }
            return 0;
        case 8:  return sys_socketpair((int)args[0], (int)args[1], (int)args[2], (int *)args[3]);
        case 9:  /* send */
        case 11: /* sendto */
            return sock_write_fd((int)args[0], (const void *)args[1], (unsigned int)args[2], (int)args[3] & 0x40);
        case 10: /* recv */
        case 12: /* recvfrom */
            return sock_read_fd((int)args[0], (void *)args[1], (unsigned int)args[2], (int)args[3] & 0x40);
        case 13: /* shutdown */
            return 0;
        case 14: /* setsockopt */
        case 15: /* getsockopt */
            if (call == 15 && args[3] && args[4]) {
                if (args[2] == 17 /* SO_PEERCRED */ && *(unsigned int *)args[4] >= 12) {
                    ((int *)args[3])[0] = 100; /* pid */
                    ((int *)args[3])[1] = 0;   /* uid */
                    ((int *)args[3])[2] = 0;   /* gid */
                    *(unsigned int *)args[4] = 12;
                } else if (*(unsigned int *)args[4] >= 4) {
                    *(int *)args[3] = 0;
                    *(unsigned int *)args[4] = 4;
                }
            }
            return 0;
        case 16: return sys_sendmsg((int)args[0], (const struct linux_msghdr *)args[1], (int)args[2]);
        case 17: return sys_recvmsg((int)args[0], (struct linux_msghdr *)args[1], (int)args[2]);
        case 18: return sys_accept4((int)args[0], (void *)args[1], (unsigned int *)args[2], (int)args[3]);
        default: return 0;
    }
}

/* ========================================================================= */
/* Poll / Select / Epoll Multiplexing                                        */
/* ========================================================================= */
static short shim_fd_poll_events(int fd, short req_events) {
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return 0x0020; /* POLLNVAL */
    short rev = 0;

    if (g_fds[fd].is_eventfd && g_ipc) {
        SHIM_IPC_EVENTFD *ev = &g_ipc->eventfds[g_fds[fd].ipc_idx];
        if ((req_events & 1) && ev->counter > 0) rev |= 1;
        if (req_events & 4) rev |= 4;
        return rev;
    }

    if (g_fds[fd].is_inotify) {
        return 0;
    }

    if (g_fds[fd].is_pipe && g_ipc) {
        SHIM_IPC_PIPE *p = &g_ipc->pipes[g_fds[fd].ipc_idx];
        if (!g_fds[fd].is_pipe_write) {
            if ((req_events & 1) && p->count > 0) rev |= 1;
            if (p->write_refs <= 0) rev |= 0x0010 | (req_events & 1);
        } else {
            if (p->read_refs <= 0) rev |= 0x0008 | 0x0010;
            else if ((req_events & 4) && p->count < IPC_PIPE_BUF_SIZE) rev |= 4;
        }
        return rev;
    }

    if (g_fds[fd].is_sock && g_ipc) {
        if (g_fds[fd].sock_state == SOCK_LISTENING) {
            int lidx = g_fds[fd].ipc_idx;
            for (int i = 0; i < MAX_IPC_CONNS; i++) {
                if (g_ipc->conns[i].listener_idx == lidx && g_ipc->conns[i].state == CONN_SYN) {
                    if (req_events & 1) rev |= 1;
                    break;
                }
            }
            return rev;
        }
        if (g_fds[fd].sock_state == SOCK_CONNECTED) {
            SHIM_IPC_CONN *conn = &g_ipc->conns[g_fds[fd].ipc_idx];
            SHIM_IPC_RING *rx = g_fds[fd].is_server ? &conn->c2s : &conn->s2c;
            SHIM_IPC_RING *tx = g_fds[fd].is_server ? &conn->s2c : &conn->c2s;
            int peer_closed = g_fds[fd].is_server ? (conn->client_closed || conn->client_refs <= 0)
                                                  : (conn->server_closed || conn->server_refs <= 0);
            if ((req_events & 1) && rx->count > 0) rev |= 1;
            if (peer_closed) rev |= 0x0010 | (req_events & 1);
            if (!peer_closed && (req_events & 4) && tx->count < IPC_RING_SIZE) rev |= 4;
            return rev;
        }
        return 0;
    }

    if (g_fds[fd].is_console) {
        if (req_events & 1) {
            PollKeyboard();
            if (g_InputHead != g_InputTail) rev |= 1;
        }
        if (req_events & 4) rev |= 4;
        return rev;
    }

    rev |= (req_events & (1 | 4));
    return rev;
}
/* ========================================================================= */
/* Real Xvfb <-> \Device\fb0 + PS/2 Mouse/Keyboard XTEST Bridge              */
/* ========================================================================= */
#define IOCTL_FB_PRESENT 0x83202008UL

#include "../../native/include/x11_input.h"

static long sock_read_all(int fd, void *buf, unsigned int count) {
    unsigned char *p = (unsigned char *)buf;
    unsigned int left = count;
    while (left > 0) {
        long r = sock_read_fd(fd, p, left, 0);
        if (r <= 0) return r < 0 ? r : -LINUX_EPIPE;
        p += r;
        left -= (unsigned int)r;
    }
    return (long)count;
}

static long x11_bridge_write(int fd, const void *buffer, unsigned int count) {
    return sock_write_fd(fd, buffer, count, 0);
}

static void xtest_send_event(int *xfd, unsigned char opcode, unsigned char type,
                             unsigned char detail, short rx, short ry) {
    if (*xfd < 0 || !opcode) return;
    if (x11_input_send(*xfd, opcode, type, detail, rx, ry, x11_bridge_write) < 0) {
        shim_debug_print("[x11_fb_bridge] Input connection lost; reconnecting\n");
        sys_close(*xfd);
        *xfd = -1;
    }
}

int x11_fb_bridge_main(int argc, char **argv) {
    (void)argc; (void)argv;
    IO_STATUS_BLOCK iosb;
    HANDLE hFb = NULL, hMouse = NULL, hKbd = NULL;

    if (!g_shim_initialized) InitShim();
    if (g_ipc) g_ipc->graphics_active = 1;
    g_graphics_mode_active = 1;

    /* Open \Device\fb0 */
    {
        unsigned short fb_w[] = L"\\Device\\fb0";
        UNICODE_STRING us = { sizeof(fb_w) - 2, sizeof(fb_w), fb_w };
        OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &us, OBJ_CASE_INSENSITIVE, NULL, NULL };
        NTSTATUS st = Nt_CreateFile(&hFb, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
                                    NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                                    FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        shim_debug_hex("[x11_fb_bridge] hFb st=", (unsigned long)st);
    }
    /* Open \Device\RawMouse */
    {
        unsigned short m_w[] = L"\\Device\\RawMouse";
        UNICODE_STRING us = { sizeof(m_w) - 2, sizeof(m_w), m_w };
        OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &us, OBJ_CASE_INSENSITIVE, NULL, NULL };
        NTSTATUS st = Nt_CreateFile(&hMouse, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
                                    NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                                    FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        shim_debug_hex("[x11_fb_bridge] hMouse st=", (unsigned long)st);
    }
    /* Open \Device\RawKeyboard */
    {
        unsigned short k_w[] = L"\\Device\\RawKeyboard";
        UNICODE_STRING us = { sizeof(k_w) - 2, sizeof(k_w), k_w };
        OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &us, OBJ_CASE_INSENSITIVE, NULL, NULL };
        NTSTATUS st = Nt_CreateFile(&hKbd, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
                                    NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                                    FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        shim_debug_hex("[x11_fb_bridge] hKbd st=", (unsigned long)st);
    }

    void *xvfb_shm = g_ipc ? (void *)g_ipc->xvfb_fb : NULL;
    void *comp_buf = NULL;
    unsigned long comp_sz = 800 * 600 * 4;
    Nt_AllocateVirtualMemory((HANDLE)-1, &comp_buf, 0, &comp_sz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    int mouse_x = 400, mouse_y = 300;
    int xfd = -1;
    unsigned char xtest_op = 0;
    unsigned char input_reply[32];
    unsigned int input_reply_size = 0;

    for (;;) {
        /* Connect to Xvfb for XTEST input injection once X0 listener is active */
        if (xfd < 0 && g_ipc) {
            for (int i = 0; i < MAX_IPC_LISTENERS; i++) {
                if (g_ipc->listeners[i].active && path_ends_with(g_ipc->listeners[i].addr, "X0")) {
                    struct linux_sockaddr_un sun;
                    sun.sun_family = 1;
                    shim_strcpy(sun.sun_path, "/tmp/.X11-unix/X0", sizeof(sun.sun_path));
                    long s = sys_socket(1, 1, 0);
                    if (s >= 0 && sys_connect((int)s, &sun, 2 + shim_strlen(sun.sun_path) + 1) == 0) {
                        unsigned char hs[12] = { 'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                        sock_write_fd((int)s, hs, 12, 0);
                        unsigned char hdr[8];
                        if (sock_read_all((int)s, hdr, 8) == 8 && hdr[0] == 1) {
                            unsigned int extra = (*(unsigned short *)(hdr + 6)) * 4;
                            static unsigned char drain[16384];
                            while (extra > 0) {
                                unsigned int chunk = extra > sizeof(drain) ? sizeof(drain) : extra;
                                long r = sock_read_all((int)s, drain, chunk);
                                if (r <= 0) break;
                                extra -= (unsigned int)r;
                            }
                            unsigned char qext[16] = { 98, 0, 4, 0, 5, 0, 0, 0, 'X', 'T', 'E', 'S', 'T', 0, 0, 0 };
                            sock_write_fd((int)s, qext, 16, 0);
                            unsigned char rep[32];
                            if (sock_read_all((int)s, rep, 32) == 32 && rep[8]) {
                                xtest_op = rep[9];
                                unsigned char gver[8] = { xtest_op, 0, 2, 0, 2, 0, 2, 0 };
                                sock_write_fd((int)s, gver, 8, 0);
                                sock_read_all((int)s, rep, 32);
                                xfd = (int)s;
                                input_reply_size = 0;
                                shim_debug_hex("[x11_fb_bridge] XTEST ready op=", (unsigned long)xtest_op);
                            } else {
                                sys_close((int)s);
                            }
                        } else {
                            sys_close((int)s);
                        }
                    } else if (s >= 0) {
                        sys_close((int)s);
                    }
                    break;
                }
            }
        }

        /* This client selects no events: any pending packet is an X11 error.
         * Preserve packet boundaries and report failures instead of discarding them. */
        if (xfd >= 0) {
            long n;
            while ((n = sock_read_fd(xfd, input_reply + input_reply_size,
                                     sizeof(input_reply) - input_reply_size, 1)) > 0) {
                input_reply_size += (unsigned int)n;
                if (input_reply_size == sizeof(input_reply)) {
                    if (input_reply[0] == 0) {
                        shim_debug_hex("[x11_fb_bridge] X11 input error=", input_reply[1]);
                        shim_debug_hex(" request=", input_reply[10]);
                    }
                    input_reply_size = 0;
                }
            }
            if (n == 0) { sys_close(xfd); xfd = -1; }
        }

        /* Poll PS/2 Mouse */
        if (hMouse) {
            static unsigned long prev_buttons = 0;
            MOUSE_INPUT_DATA_PKT mdata[16];
            LARGE_INTEGER off = { .QuadPart = 0 };
            if (NT_SUCCESS(Nt_ReadFile(hMouse, NULL, NULL, NULL, &iosb, mdata, sizeof(mdata), &off, NULL)) &&
                iosb.Information >= sizeof(MOUSE_INPUT_DATA_PKT)) {
                unsigned int cnt = (unsigned int)(iosb.Information / sizeof(MOUSE_INPUT_DATA_PKT));
                for (unsigned int i = 0; i < cnt; i++) {
                    if (mdata[i].DeltaX != 0 || mdata[i].DeltaY != 0) {
                        mouse_x += (int)mdata[i].DeltaX;
                        mouse_y += (int)mdata[i].DeltaY;
                        if (mouse_x < 0) mouse_x = 0;
                        if (mouse_x > 799) mouse_x = 799;
                        if (mouse_y < 0) mouse_y = 0;
                        if (mouse_y > 599) mouse_y = 599;
                        xtest_send_event(&xfd, xtest_op, 6, 0, (short)mouse_x, (short)mouse_y);
                    }
                    unsigned long btns = mdata[i].Buttons & 7;
                    unsigned long diff = btns ^ prev_buttons;
                    unsigned char wheel_button;
                    for (int w = x11_input_wheel(mdata[i].Buttons, &wheel_button); w > 0; w--) {
                        xtest_send_event(&xfd, xtest_op, 4, wheel_button, (short)mouse_x, (short)mouse_y);
                        xtest_send_event(&xfd, xtest_op, 5, wheel_button, (short)mouse_x, (short)mouse_y);
                    }
                    if (diff & 1) xtest_send_event(&xfd, xtest_op, (btns & 1) ? 4 : 5, 1, (short)mouse_x, (short)mouse_y);
                    if (diff & 2) xtest_send_event(&xfd, xtest_op, (btns & 2) ? 4 : 5, 3, (short)mouse_x, (short)mouse_y);
                    if (diff & 4) xtest_send_event(&xfd, xtest_op, (btns & 4) ? 4 : 5, 2, (short)mouse_x, (short)mouse_y);
                    prev_buttons = btns;
                }
            }
        }

        /* Poll PS/2 Keyboard */
        if (hKbd && xfd >= 0) {
            KEYBOARD_INPUT_DATA kdata[16];
            LARGE_INTEGER off = { .QuadPart = 0 };
            if (NT_SUCCESS(Nt_ReadFile(hKbd, NULL, NULL, NULL, &iosb, kdata, sizeof(kdata), &off, NULL)) &&
                iosb.Information >= sizeof(KEYBOARD_INPUT_DATA)) {
                unsigned int cnt = (unsigned int)(iosb.Information / sizeof(KEYBOARD_INPUT_DATA));
                for (unsigned int i = 0; i < cnt; i++) {
                    unsigned char keycode = x11_input_keycode(kdata[i].MakeCode,
                                                               (kdata[i].Flags & KEY_E0) != 0);
                    if (keycode)
                        xtest_send_event(&xfd, xtest_op, (kdata[i].Flags & KEY_BREAK) ? 3 : 2,
                                         keycode, (short)mouse_x, (short)mouse_y);
                }
            }
        }

        /* Present Xvfb 800x600x32bpp screen0 to \Device\fb0 */
        if (hFb && xvfb_shm && comp_buf && g_ipc && g_ipc->xvfb_fb_size >= 800 * 600 * 4) {
            unsigned int off = g_ipc->xvfb_fb_size - (800 * 600 * 4);
            const u32 *src = (const u32 *)((const unsigned char *)xvfb_shm + off);
            u32 *dst = (u32 *)comp_buf;
            for (unsigned int p = 0; p < 800 * 600; p++) {
                dst[p] = src[p] | 0xFF000000UL;
            }
            x11_input_draw_cursor(dst, 800, 600, mouse_x, mouse_y);
            struct {
                void *UserBuffer;
                unsigned long DstOffset;
                unsigned long ByteLength;
            } present_req = { comp_buf, 0, 800 * 600 * 4 };
            Nt_DeviceIoControlFile(hFb, NULL, NULL, NULL, &iosb,
                                   IOCTL_FB_PRESENT, &present_req, sizeof(present_req), NULL, 0);
        }

        LARGE_INTEGER delay = { .QuadPart = -300000LL }; /* 30ms (~33 FPS) */
        Nt_DelayExecution(0, &delay);
    }
    return 0;
}

/* ========================================================================= */
/* Dynamic ELF32 Loader & Multi-Process NT Execution Engine                  */
/* ========================================================================= */
static int MapElfFileImage(const char *posix_path, unsigned long load_bias,
                           Elf32_Ehdr *out_ehdr, char *out_interp, unsigned int max_interp) {
    long fd = sys_openat(-100, posix_path, 0, 0);
    if (fd < 0) return -1;

    if (sys_read((int)fd, out_ehdr, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
        sys_close((int)fd);
        return -1;
    }
    if (out_ehdr->e_ident[0] != 0x7F || out_ehdr->e_ident[1] != 'E' ||
        out_ehdr->e_ident[2] != 'L'  || out_ehdr->e_ident[3] != 'F') {
        sys_close((int)fd);
        return -1;
    }

    Elf32_Phdr phdrs[16];
    unsigned int phnum = out_ehdr->e_phnum;
    if (phnum > 16) phnum = 16;
    sys_lseek((int)fd, (s64)out_ehdr->e_phoff, 0);
    sys_read((int)fd, phdrs, phnum * sizeof(Elf32_Phdr));

    if (out_interp && max_interp > 0) out_interp[0] = '\0';

    unsigned long min_vaddr = 0xFFFFFFFFUL;
    unsigned long max_vaddr = 0;
    for (unsigned int i = 0; i < phnum; i++) {
        if (phdrs[i].p_type == 3 /* PT_INTERP */ && out_interp && max_interp > 1) {
            unsigned int ilen = phdrs[i].p_filesz;
            if (ilen >= max_interp) ilen = max_interp - 1;
            sys_lseek((int)fd, (s64)phdrs[i].p_offset, 0);
            sys_read((int)fd, out_interp, ilen);
            out_interp[ilen] = '\0';
        } else if (phdrs[i].p_type == 1 /* PT_LOAD */) {
            if (phdrs[i].p_vaddr < min_vaddr) min_vaddr = phdrs[i].p_vaddr;
            if (phdrs[i].p_vaddr + phdrs[i].p_memsz > max_vaddr)
                max_vaddr = phdrs[i].p_vaddr + phdrs[i].p_memsz;
        }
    }

    if (min_vaddr >= max_vaddr) {
        sys_close((int)fd);
        return -1;
    }

    unsigned long span_start = (load_bias + min_vaddr) & ~0xFFFFUL;
    unsigned long span_end   = (load_bias + max_vaddr + 0xFFFFUL) & ~0xFFFFUL;
    void *span_base = (void *)span_start;
    unsigned long span_size = span_end - span_start;

    NTSTATUS st = Nt_AllocateVirtualMemory((HANDLE)-1, &span_base, 0, &span_size,
                                           MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(st)) {
        span_base = (void *)span_start;
        span_size = span_end - span_start;
        st = Nt_AllocateVirtualMemory((HANDLE)-1, &span_base, 0, &span_size,
                                      MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    if (!NT_SUCCESS(st)) {
        sys_close((int)fd);
        return -1;
    }

    for (unsigned long k = 0; k < (span_end - span_start); k++) {
        ((unsigned char *)span_start)[k] = 0;
    }

    for (unsigned int i = 0; i < phnum; i++) {
        if (phdrs[i].p_type == 1 && phdrs[i].p_filesz > 0) {
            sys_lseek((int)fd, (s64)phdrs[i].p_offset, 0);
            unsigned char *dst = (unsigned char *)(load_bias + phdrs[i].p_vaddr);
            unsigned int rem = phdrs[i].p_filesz;
            while (rem > 0) {
                long r = sys_read((int)fd, dst, rem);
                if (r <= 0) break;
                dst += r;
                rem -= (unsigned int)r;
            }
        }
    }

    sys_close((int)fd);
    return 0;
}

static int g_is_dynamic_elf = 0;

int shim_exec_dynamic_elf(const char *elf_path, int argc, char **argv, char **envp) {
    shim_init_fpu();
    if (!g_shim_initialized) InitShim();

    /* Copy path, argv, envp to safe static storage before mapping segments */
    static char s_path[260];
    static char s_str_buf[8192];
    static char *s_argv[64];
    static char *s_envp[128];
    int s_argc = 0, s_envc = 0;
    unsigned int spos = 0;

    CanonicalizePosixPath(elf_path, s_path, sizeof(s_path));
    shim_strcpy(g_current_exe_path, s_path, sizeof(g_current_exe_path));
    shim_debug_print("[elf] exec: ");
    shim_debug_print(s_path);
    shim_debug_print("\n");

    for (int i = 0; i < argc && argv && argv[i] && s_argc < 62; i++) {
        unsigned int l = shim_strlen(argv[i]) + 1;
        if (spos + l < sizeof(s_str_buf)) {
            s_argv[s_argc++] = s_str_buf + spos;
            for (unsigned int k = 0; k < l; k++) s_str_buf[spos++] = argv[i][k];
        }
    }
    s_argv[s_argc] = NULL;
    for (int i = 0; i < s_argc; i++) {
        shim_debug_print("  arg: ");
        shim_debug_print(s_argv[i]);
        shim_debug_print("\n");
    }

    if (envp) {
        for (int i = 0; envp[i] && s_envc < 120; i++) {
            unsigned int l = shim_strlen(envp[i]) + 1;
            if (spos + l < sizeof(s_str_buf)) {
                s_envp[s_envc++] = s_str_buf + spos;
                for (unsigned int k = 0; k < l; k++) s_str_buf[spos++] = envp[i][k];
            }
        }
    }
    /* Ensure DISPLAY=:0 and LD_LIBRARY_PATH=/lib:/usr/lib are present */
    s_envp[s_envc++] = "DISPLAY=:0";
    s_envp[s_envc++] = "GDK_BACKEND=x11";
    s_envp[s_envc++] = "NO_AT_BRIDGE=1";
    s_envp[s_envc++] = "LD_LIBRARY_PATH=/lib:/usr/lib";
    s_envp[s_envc++] = "XDG_CONFIG_DIRS=/etc/xdg";
    s_envp[s_envc++] = "XDG_DATA_DIRS=/usr/share";
    s_envp[s_envc++] = "XDG_RUNTIME_DIR=/tmp";
    s_envp[s_envc++] = "DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/dbus-session";
    s_envp[s_envc++] = "HOME=/root";
    s_envp[s_envc++] = "USER=root";
    s_envp[s_envc++] = "PATH=/bin:/sbin:/usr/bin:/usr/sbin";
    s_envp[s_envc] = NULL;

    /* Close CLOEXEC file descriptors on exec */
    for (int i = 0; i < MAX_FD; i++) {
        if (g_fds[i].is_open && g_fds[i].cloexec) sys_close(i);
    }

    /* Peek e_type to pick load_bias */
    Elf32_Ehdr app_ehdr;
    long peek_fd = sys_openat(-100, s_path, 0, 0);
    if (peek_fd < 0) return 127;
    if (sys_read((int)peek_fd, &app_ehdr, sizeof(app_ehdr)) != sizeof(app_ehdr)) {
        sys_close((int)peek_fd);
        return 127;
    }
    sys_close((int)peek_fd);

    unsigned long app_bias = (app_ehdr.e_type == 3 /* ET_DYN */) ? 0x08048000UL : 0UL;
    char interp_path[128];
    if (MapElfFileImage(s_path, app_bias, &app_ehdr, interp_path, sizeof(interp_path)) < 0) {
        return 127;
    }

    unsigned long interp_bias = 0;
    unsigned long entry_addr  = app_bias + app_ehdr.e_entry;

    if (interp_path[0]) {
        Elf32_Ehdr interp_ehdr;
        interp_bias = 0x0B000000UL;
        if (MapElfFileImage("/lib/ld-musl-i386.so.1", interp_bias, &interp_ehdr, NULL, 0) < 0) {
            if (MapElfFileImage(interp_path, interp_bias, &interp_ehdr, NULL, 0) < 0) {
                return 127;
            }
        }
        entry_addr = interp_bias + interp_ehdr.e_entry;
        g_is_dynamic_elf = 1;
    }

    /* Set up initial TLS base before _dlstart so %gs:0x10 is valid immediately */
    static unsigned long dummy_tls[64];
    dummy_tls[0] = (unsigned long)dummy_tls;
    dummy_tls[4] = (unsigned long)&__kernel_vsyscall;
    shim_set_tls_base((unsigned long)dummy_tls);

    /* Allocate fresh 2 MB stack for ELF process */
    void *stack_alloc = NULL;
    unsigned long stack_size = 2 * 1024 * 1024;
    if (!NT_SUCCESS(Nt_AllocateVirtualMemory((HANDLE)-1, &stack_alloc, 0, &stack_size,
                                             MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))) {
        return 127;
    }

    unsigned long stack_top = (unsigned long)stack_alloc + stack_size;
    __asm__ volatile("movl %0, %%fs:0x04" : : "r"(stack_top));
    __asm__ volatile("movl %0, %%fs:0x08" : : "r"(stack_alloc));

    unsigned long sp = stack_top - 64;
    sp -= 16;
    unsigned long rand_ptr = sp;
    ((unsigned int *)rand_ptr)[0] = 0x12345678U;
    ((unsigned int *)rand_ptr)[1] = 0x9ABCDEF0U;
    ((unsigned int *)rand_ptr)[2] = 0x0FEDCBA9U;
    ((unsigned int *)rand_ptr)[3] = 0x87654321U;

    sp &= ~15UL;
    unsigned int total_words = 1 + (unsigned int)s_argc + 1 + (unsigned int)s_envc + 1 + 32;
    sp -= total_words * 4;
    sp &= ~15UL;

    unsigned long *ustk = (unsigned long *)sp;
    int wp = 0;
    ustk[wp++] = (unsigned long)s_argc;
    for (int i = 0; i < s_argc; i++) ustk[wp++] = (unsigned long)s_argv[i];
    ustk[wp++] = 0;
    for (int i = 0; i < s_envc; i++) ustk[wp++] = (unsigned long)s_envp[i];
    ustk[wp++] = 0;

    /* ELF Auxiliary Vector */
    ustk[wp++] = 3;  ustk[wp++] = app_bias + app_ehdr.e_phoff; /* AT_PHDR */
    ustk[wp++] = 4;  ustk[wp++] = app_ehdr.e_phentsize;        /* AT_PHENT */
    ustk[wp++] = 5;  ustk[wp++] = app_ehdr.e_phnum;            /* AT_PHNUM */
    ustk[wp++] = 6;  ustk[wp++] = 4096;                        /* AT_PAGESZ */
    ustk[wp++] = 7;  ustk[wp++] = interp_bias;                 /* AT_BASE */
    ustk[wp++] = 8;  ustk[wp++] = 0;                           /* AT_FLAGS */
    ustk[wp++] = 9;  ustk[wp++] = app_bias + app_ehdr.e_entry; /* AT_ENTRY */
    ustk[wp++] = 11; ustk[wp++] = 0;                           /* AT_UID */
    ustk[wp++] = 12; ustk[wp++] = 0;                           /* AT_EUID */
    ustk[wp++] = 13; ustk[wp++] = 0;                           /* AT_GID */
    ustk[wp++] = 14; ustk[wp++] = 0;                           /* AT_EGID */
    ustk[wp++] = 17; ustk[wp++] = 100;                         /* AT_CLKTCK */
    ustk[wp++] = 23; ustk[wp++] = 0;                           /* AT_SECURE */
    ustk[wp++] = 25; ustk[wp++] = rand_ptr;                    /* AT_RANDOM */
    ustk[wp++] = 31; ustk[wp++] = (unsigned long)s_path;       /* AT_EXECFN */
    ustk[wp++] = 32; ustk[wp++] = (unsigned long)&__kernel_vsyscall; /* AT_SYSINFO */
    ustk[wp++] = 0;  ustk[wp++] = 0;                           /* AT_NULL */

    __asm__ volatile(
        "movl %0, %%esp\n\t"
        "xorl %%edx, %%edx\n\t"
        "jmp *%1\n\t"
        : : "r"(sp), "r"(entry_addr) : "memory"
    );
    return 0;
}
/* ========================================================================= */
/* Multi-Process NT Spawning, Threading (CLONE_THREAD) & Cooperative vfork   */
/* ========================================================================= */
extern int setjmp(void *);
extern void longjmp(void *, int);
extern void __init_libc(char **envp, char *pn);
extern void __libc_start_init(void);
extern int main(int argc, char **argv, char **envp);
extern void exit(int status);

#define FAST_FUNC __attribute__((regparm(3),stdcall))
extern int FAST_FUNC find_applet_by_name(const char *name) __attribute__((weak));
extern void FAST_FUNC run_applet_no_and_exit(int applet_no, const char *name, char **argv) __attribute__((weak));
extern void *bb_get_ptr_to_globals(void) __attribute__((weak));
extern void bb_set_ptr_to_globals(void *p) __attribute__((weak));
extern const char *bb_get_applet_name(void) __attribute__((weak));
extern void bb_set_applet_name(const char *name) __attribute__((weak));
extern void *bb_get_die_func(void) __attribute__((weak));
extern void bb_set_die_func(void *f) __attribute__((weak));
extern int optind;

extern int gcc_main(int argc, char **argv);
extern int gxx_main(int argc, char **argv);
extern int cpp_main(int argc, char **argv);
extern int gdb_main(int argc, char **argv);
extern int test_cxx_main(int argc, char **argv);
extern int nttest_main(int argc, char **argv);
extern int insmod_main(int argc, char **argv);
extern int rmmod_main(int argc, char **argv);
extern int lsmod_main(int argc, char **argv);
extern int modinfo_main(int argc, char **argv);
extern int xddkctl_main(int argc, char **argv);
extern int net_applet_main(int argc, char **argv);
extern int sshd_main(int argc, char **argv);
extern int ssh_keygen_main(int argc, char **argv);
extern int ssh_main(int argc, char **argv);
extern int scp_main(int argc, char **argv);
extern int usb_applet_main(int argc, char **argv);

typedef int (*SHIM_TOOL_MAIN)(int, char **);
extern int xfce_probe_main(int, char **);
static SHIM_TOOL_MAIN shim_find_modtool(const char *name) {
    if (shim_strcmp(name, "xfce-probe") == 0) return xfce_probe_main;
    if (shim_strcmp(name, "insmod") == 0)  return insmod_main;
    if (shim_strcmp(name, "rmmod") == 0)   return rmmod_main;
    if (shim_strcmp(name, "lsmod") == 0)   return lsmod_main;
    if (shim_strcmp(name, "modinfo") == 0) return modinfo_main;
    if (shim_strcmp(name, "xddkctl") == 0) return xddkctl_main;
    if (shim_strcmp(name, "x11_fb_bridge") == 0) return x11_fb_bridge_main;
    if (shim_strcmp(name, "ifconfig") == 0)return net_applet_main;
    if (shim_strcmp(name, "ip") == 0)      return net_applet_main;
    if (shim_strcmp(name, "ping") == 0)    return net_applet_main;
    if (shim_strcmp(name, "nslookup") == 0)return net_applet_main;
    if (shim_strcmp(name, "wget") == 0)    return net_applet_main;
    if (shim_strcmp(name, "curl") == 0)    return net_applet_main;
    if (shim_strcmp(name, "route") == 0)   return net_applet_main;
    if (shim_strcmp(name, "netstat") == 0) return net_applet_main;
    if (shim_strcmp(name, "sshd") == 0)       return sshd_main;
    if (shim_strcmp(name, "ssh-keygen") == 0) return ssh_keygen_main;
    if (shim_strcmp(name, "ssh") == 0)        return ssh_main;
    if (shim_strcmp(name, "scp") == 0)        return scp_main;
    if (shim_strcmp(name, "lsusb") == 0 ||
        shim_strcmp(name, "usbinfo") == 0 ||
        shim_strcmp(name, "usbctl") == 0)     return usb_applet_main;
    return 0;
}

#define MAX_CHILD_PROCS 64
typedef struct _SHIM_CHILD_PROC {
    int    in_use;
    long   pid;
    HANDLE hProcess;
    HANDLE hThread;
    int    exited;
    int    exit_code;
} SHIM_CHILD_PROC;

static SHIM_CHILD_PROC g_child_procs[MAX_CHILD_PROCS];

static void __attribute__((noreturn)) shim_child_process_entry(void) {
    shim_init_fpu();
    InitShim();
    SHIM_SPAWN_INFO *info = (SHIM_SPAWN_INFO *)SHIM_SPAWN_INFO_ADDR;
    if (info->magic != SHIM_SPAWN_MAGIC) {
        Nt_TerminateProcess((HANDLE)-1, 127);
    }

    shim_strcpy(g_cwd, info->cwd, sizeof(g_cwd));
    shim_strcpy(g_current_exe_path, info->elf_path, sizeof(g_current_exe_path));

    for (int i = 0; i < MAX_FD; i++) {
        for (unsigned int k = 0; k < sizeof(SHIM_FD); k++) ((unsigned char *)&g_fds[i])[k] = 0;
        if (info->fds[i].is_open) {
            g_fds[i].h             = info->fds[i].h;
            g_fds[i].is_open       = 1;
            g_fds[i].is_dir        = info->fds[i].is_dir;
            g_fds[i].is_console    = info->fds[i].is_console;
            g_fds[i].is_pipe       = info->fds[i].is_pipe;
            g_fds[i].is_pipe_write = info->fds[i].is_pipe_write;
            g_fds[i].is_sock       = info->fds[i].is_sock;
            g_fds[i].is_server     = info->fds[i].is_server;
            g_fds[i].sock_state    = info->fds[i].sock_state;
            g_fds[i].sock_domain   = info->fds[i].sock_domain;
            g_fds[i].sock_type     = info->fds[i].sock_type;
            g_fds[i].is_eventfd    = info->fds[i].is_eventfd;
            g_fds[i].is_inotify    = info->fds[i].is_inotify;
            g_fds[i].is_xvfb_fb    = info->fds[i].is_xvfb_fb;
            g_fds[i].is_devnull    = info->fds[i].is_devnull;
            g_fds[i].is_pty        = info->fds[i].is_pty;
            g_fds[i].nonblock      = info->fds[i].nonblock;
            g_fds[i].ipc_idx       = info->fds[i].ipc_idx;
            g_fds[i].offset        = info->fds[i].offset;
            g_fds[i].dir_first     = 1;
            shim_strcpy(g_fds[i].dir_path, info->fds[i].dir_path, sizeof(g_fds[i].dir_path));
        }
    }

    static char *c_argv[64];
    static void *c_env_aux[256];
    static unsigned int c_rand[4] = { 0x12345678, 0x9ABCDEF0, 0x0FEDCBA9, 0x87654321 };
    for (int i = 0; i < info->argc && i < 62; i++) {
        c_argv[i] = info->str_pool + info->argv_off[i];
    }
    c_argv[info->argc] = NULL;

    int epos = 0;
    for (int i = 0; i < info->envc && epos < 120; i++) {
        c_env_aux[epos++] = info->str_pool + info->envp_off[i];
    }
    c_env_aux[epos++] = NULL;
    c_env_aux[epos++] = (void *)6;  c_env_aux[epos++] = (void *)4096;
    c_env_aux[epos++] = (void *)17; c_env_aux[epos++] = (void *)100;
    c_env_aux[epos++] = (void *)25; c_env_aux[epos++] = (void *)c_rand;
    c_env_aux[epos++] = (void *)31; c_env_aux[epos++] = (void *)info->elf_path;
    c_env_aux[epos++] = (void *)0;  c_env_aux[epos++] = (void *)0;

    if (info->is_applet) {
        __init_libc((char **)c_env_aux, c_argv[0] ? c_argv[0] : "busybox");
        __libc_start_init();
        const char *cmd = c_argv[0] ? c_argv[0] : "sh";
        const char *base = cmd;
        for (const char *p = cmd; *p; p++) {
            if (*p == '/' || *p == '\\') base = p + 1;
        }
        if (base[0] == '-') base++;
        if (shim_strcmp(base, "x11_fb_bridge") == 0 ||
            (shim_strcmp(base, "busybox") == 0 && info->argc >= 2 && shim_strcmp(c_argv[1], "x11_fb_bridge") == 0)) {
            int rc = x11_fb_bridge_main(info->argc, c_argv);
            for (int i = 0; i < MAX_FD; i++) if (g_fds[i].is_open) sys_close(i);
            Nt_TerminateProcess((HANDLE)-1, rc);
        }
        SHIM_TOOL_MAIN tool = shim_find_modtool(base);
        if (tool) {
            int rc = tool(info->argc, c_argv);
            for (int i = 0; i < MAX_FD; i++) if (g_fds[i].is_open) sys_close(i);
            Nt_TerminateProcess((HANDLE)-1, rc);
        }
        int rc = main(info->argc, c_argv, (char **)c_env_aux);
        for (int i = 0; i < MAX_FD; i++) if (g_fds[i].is_open) sys_close(i);
        Nt_TerminateProcess((HANDLE)-1, rc);
    } else {
        int rc = shim_exec_dynamic_elf(info->elf_path, info->argc, c_argv, (char **)c_env_aux);
        for (int i = 0; i < MAX_FD; i++) if (g_fds[i].is_open) sys_close(i);
        Nt_TerminateProcess((HANDLE)-1, rc);
    }
    for (;;) {}
}

static long shim_spawn_elf_process(const char *elf_path, int is_applet, int argc, char **argv, char **envp) {
    unsigned short smss_w[] = L"\\SystemRoot\\system32\\smss.exe";
    UNICODE_STRING u_img = { sizeof(smss_w) - 2, sizeof(smss_w), smss_w };
    OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &u_img, OBJ_CASE_INSENSITIVE, NULL, NULL };
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL, hSection = NULL, hProcess = NULL, hThread = NULL;
    NTSTATUS st;

    st = Nt_OpenFile(&hFile, SYNCHRONIZE | FILE_EXECUTE | FILE_READ_DATA, &oa, &iosb,
                     FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(st)) return -1;

    st = Nt_CreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, hFile);
    Nt_Close(hFile);
    if (!NT_SUCCESS(st)) return -1;

    st = Nt_CreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, (HANDLE)-1, 0, hSection, NULL, NULL, 0);
    if (!NT_SUCCESS(st)) {
        st = Nt_CreateProcess(&hProcess, PROCESS_ALL_ACCESS, NULL, (HANDLE)-1, 0, hSection, NULL, NULL);
    }
    Nt_Close(hSection);
    if (!NT_SUCCESS(st) || !hProcess) return -1;

    PROCESS_BASIC_INFORMATION pbi;
    for (unsigned int k = 0; k < sizeof(pbi); k++) ((unsigned char *)&pbi)[k] = 0;
    Nt_QueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

    /* Allocate [0x01000000, 0x01500000) in child process */
    void *child_bb = (void *)0x01000000UL;
    unsigned long child_bb_sz = 0x00500000UL;
    st = Nt_AllocateVirtualMemory(hProcess, &child_bb, 0, &child_bb_sz, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(st)) {
        Nt_TerminateProcess(hProcess, 1);
        Nt_Close(hProcess);
        return -1;
    }

    /* Copy busybox PT_LOAD segments (read-only from 0x01000000, writable from g_pristine_data) */
    const Elf32_Ehdr *eh = (const Elf32_Ehdr *)0x01000000UL;
    const Elf32_Phdr *ph = (const Elf32_Phdr *)(0x01000000UL + eh->e_phoff);
    unsigned int p_off = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == 1 && ph[i].p_filesz > 0) {
            if (ph[i].p_flags & 2) {
                Nt_WriteVirtualMemory(hProcess, (void *)ph[i].p_vaddr, g_pristine_data + p_off, ph[i].p_filesz, NULL);
                p_off += ph[i].p_filesz;
            } else {
                Nt_WriteVirtualMemory(hProcess, (void *)ph[i].p_vaddr, (const void *)ph[i].p_vaddr, ph[i].p_filesz, NULL);
            }
        }
    }

    /* Populate SHIM_SPAWN_INFO and write to 0x014F0000 in child process */
    static SHIM_SPAWN_INFO s_info;
    for (unsigned int k = 0; k < sizeof(s_info); k++) ((unsigned char *)&s_info)[k] = 0;
    s_info.magic = SHIM_SPAWN_MAGIC;
    s_info.is_applet = is_applet;
    shim_strcpy(s_info.elf_path, elf_path, sizeof(s_info.elf_path));
    shim_strcpy(s_info.cwd, g_cwd, sizeof(s_info.cwd));

    unsigned int spos = 0;
    int c_argc = 0, c_envc = 0;
    for (int i = 0; i < argc && argv && argv[i] && c_argc < 62; i++) {
        unsigned int l = shim_strlen(argv[i]) + 1;
        if (spos + l < sizeof(s_info.str_pool)) {
            s_info.argv_off[c_argc++] = (int)spos;
            for (unsigned int k = 0; k < l; k++) s_info.str_pool[spos++] = argv[i][k];
        }
    }
    s_info.argc = c_argc;

    if (envp) {
        for (int i = 0; envp[i] && c_envc < 120; i++) {
            unsigned int l = shim_strlen(envp[i]) + 1;
            if (spos + l < sizeof(s_info.str_pool)) {
                s_info.envp_off[c_envc++] = (int)spos;
                for (unsigned int k = 0; k < l; k++) s_info.str_pool[spos++] = envp[i][k];
            }
        }
    }
    s_info.envc = c_envc;

    for (int i = 0; i < MAX_FD; i++) {
        if (g_fds[i].is_open && !g_fds[i].cloexec) {
            /* Do not pass server listening/bound sockets into spawned child processes */
            if (g_fds[i].is_sock && (g_fds[i].sock_state == SOCK_LISTENING || g_fds[i].sock_state == SOCK_BOUND)) {
                continue;
            }
            s_info.fds[i].is_open       = 1;
            s_info.fds[i].is_dir        = g_fds[i].is_dir;
            s_info.fds[i].is_console    = g_fds[i].is_console;
            s_info.fds[i].is_pipe       = g_fds[i].is_pipe;
            s_info.fds[i].is_pipe_write = g_fds[i].is_pipe_write;
            s_info.fds[i].is_sock       = g_fds[i].is_sock;
            s_info.fds[i].is_server     = g_fds[i].is_server;
            s_info.fds[i].sock_state    = g_fds[i].sock_state;
            s_info.fds[i].sock_domain   = g_fds[i].sock_domain;
            s_info.fds[i].sock_type     = g_fds[i].sock_type;
            s_info.fds[i].is_eventfd    = g_fds[i].is_eventfd;
            s_info.fds[i].is_inotify    = g_fds[i].is_inotify;
            s_info.fds[i].is_xvfb_fb    = g_fds[i].is_xvfb_fb;
            s_info.fds[i].is_devnull    = g_fds[i].is_devnull;
            s_info.fds[i].is_pty        = g_fds[i].is_pty;
            s_info.fds[i].nonblock      = g_fds[i].nonblock;
            s_info.fds[i].ipc_idx       = g_fds[i].ipc_idx;
            s_info.fds[i].offset        = g_fds[i].offset;
            shim_strcpy(s_info.fds[i].dir_path, g_fds[i].dir_path, sizeof(s_info.fds[i].dir_path));

            if (g_fds[i].h && !g_fds[i].is_console && !g_fds[i].is_pipe && !g_fds[i].is_sock &&
                !g_fds[i].is_eventfd && !g_fds[i].is_inotify && !g_fds[i].is_xvfb_fb && !g_fds[i].is_devnull) {
                HANDLE dup_h = NULL;
                if (NT_SUCCESS(Nt_DuplicateObject((HANDLE)-1, g_fds[i].h, hProcess, &dup_h, 0, 0, 2))) {
                    s_info.fds[i].h = dup_h;
                }
            } else {
                shim_fd_addref(&g_fds[i]);
            }
        }
    }

    Nt_WriteVirtualMemory(hProcess, (void *)SHIM_SPAWN_INFO_ADDR, &s_info, sizeof(s_info), NULL);

    /* Allocate 512 KB initial stack in child process */
    void *stack_alloc = NULL;
    unsigned long stack_sz = 512 * 1024;
    if (!NT_SUCCESS(Nt_AllocateVirtualMemory(hProcess, &stack_alloc, 0, &stack_sz, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))) {
        Nt_TerminateProcess(hProcess, 1);
        Nt_Close(hProcess);
        return -1;
    }

    INITIAL_TEB init_teb;
    for (unsigned int k = 0; k < sizeof(init_teb); k++) ((unsigned char *)&init_teb)[k] = 0;
    init_teb.StackAllocationBase = stack_alloc;
    init_teb.StackBase = (unsigned char *)stack_alloc + stack_sz;
    init_teb.StackLimit = stack_alloc;

    CONTEXT ctx;
    for (unsigned int k = 0; k < sizeof(ctx); k++) ((unsigned char *)&ctx)[k] = 0;
    ctx.ContextFlags = 0x00010007UL;
    ctx.SegGs = 0;
    ctx.SegFs = 0x38;
    ctx.SegEs = 0x23;
    ctx.SegDs = 0x23;
    ctx.SegSs = 0x23;
    ctx.SegCs = 0x1B;
    ctx.EFlags = 0x200;
    ctx.Eip = (unsigned long)&shim_child_process_entry;
    ctx.Esp = (unsigned long)init_teb.StackBase - 16;

    CLIENT_ID cid;
    st = Nt_CreateThread(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, &cid, &ctx, &init_teb, 0);
    if (!NT_SUCCESS(st)) {
        Nt_TerminateProcess(hProcess, 1);
        Nt_Close(hProcess);
        return -1;
    }

    long child_pid = (long)pbi.UniqueProcessId;
    if (child_pid <= 0) {
        child_pid = g_ipc ? __sync_add_and_fetch(&g_ipc->next_pid, 1) : 300;
    }

    shim_debug_print("[spawn] ");
    shim_debug_print(g_current_exe_path);
    shim_debug_print(" -> ");
    shim_debug_print(elf_path);
    if (argc > 0 && argv && argv[0]) {
        shim_debug_print(" (");
        shim_debug_print(argv[0]);
        shim_debug_print(")");
    }
    shim_debug_print("\n");

    for (int i = 0; i < MAX_CHILD_PROCS; i++) {
        if (!g_child_procs[i].in_use) {
            g_child_procs[i].in_use    = 1;
            g_child_procs[i].pid       = child_pid;
            g_child_procs[i].hProcess  = hProcess;
            g_child_procs[i].hThread   = hThread;
            g_child_procs[i].exited    = 0;
            g_child_procs[i].exit_code = 0;
            break;
        }
    }
    return child_pid;
}

/* Multi-threading (CLONE_THREAD) via NtCreateThread in current process */
#define MAX_PTHREADS 32
typedef struct _SHIM_PTHREAD {
    int          in_use;
    volatile int ready;
    int          tid;
    int        (*fn)(void *);
    void        *arg;
    unsigned long tls_base;
    unsigned long child_esp;
    int         *ctid;
    void        *stack_alloc;
} SHIM_PTHREAD;

static SHIM_PTHREAD g_pthreads[MAX_PTHREADS];
static long g_main_tid = 0;

static void shim_clear_unmapped_tls(unsigned long start, unsigned long end) {
    for (int i = 0; i < MAX_PTHREADS; i++) {
        if (g_pthreads[i].in_use && g_pthreads[i].tls_base >= start && g_pthreads[i].tls_base < end) {
            g_pthreads[i].tls_base = 0;
        }
    }
}

static void __attribute__((noreturn)) shim_pthread_trampoline(void) {
    int slot = 0;
    __asm__ volatile("movl %%ebx, %0" : "=r"(slot));
    shim_init_fpu();
    SHIM_PTHREAD *pt = &g_pthreads[slot];
    if (pt->tls_base) {
        shim_set_tls_base(pt->tls_base);
    }
    while (!pt->ready) {
        shim_ipc_wait(0);
    }
    int rc = pt->fn(pt->arg);
    if (pt->ctid) *pt->ctid = 0;
    pt->in_use = 0;
    Nt_TerminateThread((HANDLE)-2, (NTSTATUS)rc);
    for (;;) {}
}

static long sys_clone_thread(unsigned long flags, unsigned long child_esp,
                             int *ptid, void *tls_desc, int *ctid, int (*fn)(void *)) {
    int slot = -1;
    for (int i = 0; i < MAX_PTHREADS; i++) {
        if (!g_pthreads[i].in_use) { slot = i; break; }
    }
    if (slot < 0) return -LINUX_EAGAIN;

    unsigned long tls_base = 0;
    if ((flags & 0x00080000UL) && tls_desc) {
        tls_base = ((unsigned long *)tls_desc)[1];
    }

    g_pthreads[slot].in_use    = 1;
    g_pthreads[slot].ready     = 0;
    g_pthreads[slot].tid       = 0;
    g_pthreads[slot].fn        = fn;
    g_pthreads[slot].arg       = *(void **)child_esp;
    g_pthreads[slot].tls_base  = tls_base;
    g_pthreads[slot].child_esp = child_esp;
    g_pthreads[slot].ctid      = (flags & 0x00200000UL /* CLONE_CHILD_CLEARTID */) ? ctid : NULL;

    void *stack_alloc = g_pthreads[slot].stack_alloc;
    unsigned long stack_sz = 256 * 1024;
    if (!stack_alloc) {
        if (!NT_SUCCESS(Nt_AllocateVirtualMemory((HANDLE)-1, &stack_alloc, 0, &stack_sz,
                                                 MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))) {
            g_pthreads[slot].in_use = 0;
            return -LINUX_ENOMEM;
        }
        g_pthreads[slot].stack_alloc = stack_alloc;
    }

    INITIAL_TEB init_teb;
    for (unsigned int k = 0; k < sizeof(init_teb); k++) ((unsigned char *)&init_teb)[k] = 0;
    init_teb.StackAllocationBase = stack_alloc;
    init_teb.StackBase = (unsigned char *)stack_alloc + stack_sz;
    init_teb.StackLimit = stack_alloc;

    CONTEXT ctx;
    for (unsigned int k = 0; k < sizeof(ctx); k++) ((unsigned char *)&ctx)[k] = 0;
    ctx.ContextFlags = 0x00010007UL;
    ctx.SegGs = 0x63;
    ctx.SegFs = 0x38;
    ctx.SegEs = 0x23;
    ctx.SegDs = 0x23;
    ctx.SegSs = 0x23;
    ctx.SegCs = 0x1B;
    ctx.EFlags = 0x200;
    ctx.Ebx = (unsigned long)slot;
    ctx.Eip = (unsigned long)&shim_pthread_trampoline;
    ctx.Esp = (unsigned long)init_teb.StackBase - 16;

    HANDLE hThread = NULL;
    CLIENT_ID cid = { 0, 0 };
    int fake_tid = 500 + slot;

    NTSTATUS st = Nt_CreateThread(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, &cid, &ctx, &init_teb, 0);
    if (!NT_SUCCESS(st)) {
        g_pthreads[slot].in_use = 0;
        return -LINUX_EAGAIN;
    }
    int real_tid = cid.UniqueThread ? (int)(unsigned long)cid.UniqueThread : fake_tid;
    g_pthreads[slot].tid = real_tid;
    if ((flags & 0x00100000UL /* CLONE_PARENT_SETTID */) && ptid) *ptid = real_tid;
    if ((flags & 0x01000000UL /* CLONE_CHILD_SETTID */) && ctid) *ctid = real_tid;
    __sync_synchronize();
    g_pthreads[slot].ready = 1;
    Nt_Close(hThread);

    shim_debug_print("[pthread_create] ");
    shim_debug_print(g_current_exe_path);
    shim_debug_hex(" tid=", (unsigned long)real_tid);
    return real_tid;
}

static unsigned long g_vfork_buf[16];
static int g_in_vfork = 0;
static long g_vfork_child_pid = 0;
static int g_child_exit_code = 0;
static int g_vfork_is_sync = 0;
/* In-process vfork children that exited but are not yet reaped by wait4: a
 * pipeline starts several children before the shell waits for any of them. */
#define MAX_EXITED_CHILDREN 32
static struct { long pid; int code; } g_exited_children[MAX_EXITED_CHILDREN];
static unsigned int g_exited_child_count = 0;

/* In-process vfork children share the parent's memory. An applet must start
 * as after a real exec: with clean stdio streams rather than an EOF flag or
 * buffered input left by an earlier child, and with zeroed BusyBox globals
 * (grep, for example, keeps its pattern list in bb_common_bufsiz1). */
typedef struct _IO_FILE SHIM_STDIO_FILE;
extern SHIM_STDIO_FILE *const stdin, *const stdout, *const stderr;
extern int fflush(SHIM_STDIO_FILE *);
extern void clearerr(SHIM_STDIO_FILE *);
#define SHIM_BB_COMMON_BUFSIZE 1024 /* BusyBox COMMON_BUFSIZE without FEATURE_USE_BSS_TAIL */
extern char bb_common_bufsiz1[] __attribute__((weak));
extern unsigned char xfunc_error_retval __attribute__((weak));
static char g_saved_common_bufsiz[SHIM_BB_COMMON_BUFSIZE];
static unsigned char g_saved_xfunc_error_retval;

static void shim_prepare_applet(void) {
    fflush(stdin);  /* musl discards unread input from a read-mode stream */
    clearerr(stdin);
    clearerr(stdout);
    clearerr(stderr);
    if (bb_common_bufsiz1)
        for (int i = 0; i < SHIM_BB_COMMON_BUFSIZE; i++) bb_common_bufsiz1[i] = 0;
    if (&xfunc_error_retval) xfunc_error_retval = 1; /* EXIT_FAILURE */
}
static SHIM_FD g_vfork_saved_fds[MAX_FD];
static void *g_saved_ptr_to_globals = NULL;
static const char *g_saved_applet_name = NULL;
static void *g_saved_die_func = NULL;
static int g_saved_optind = 1;
static long s_next_child_pid = 100;
static unsigned char g_saved_stack[65536];
static unsigned long g_saved_cur_tp = 0;
static unsigned char g_saved_tls[320];
static unsigned char g_saved_pthread_tls[MAX_PTHREADS][320];
static unsigned char g_saved_musl_rw[16384];
static void *g_saved_sp = NULL;
static unsigned long g_saved_stack_size = 0;
static unsigned long s_restore_idx = 0;

static void vfork_save_state(void) {
    for (int i = 0; i < MAX_FD; i++) {
        g_vfork_saved_fds[i] = g_fds[i];
        if (g_vfork_saved_fds[i].is_open) {
            ShimDupHandleSlot(i);
            /* g_fds[i] got the new handle/ref, g_vfork_saved_fds[i] keeps original */
        }
    }
    if (bb_get_ptr_to_globals) g_saved_ptr_to_globals = bb_get_ptr_to_globals();
    if (bb_get_applet_name) g_saved_applet_name = bb_get_applet_name();
    if (bb_get_die_func) g_saved_die_func = bb_get_die_func();
    g_saved_optind = optind;
    if (bb_common_bufsiz1)
        for (int i = 0; i < SHIM_BB_COMMON_BUFSIZE; i++) g_saved_common_bufsiz[i] = bb_common_bufsiz1[i];
    if (&xfunc_error_retval) g_saved_xfunc_error_retval = xfunc_error_retval;
    if (g_is_dynamic_elf) {
        unsigned long cur_tp = 0;
        __asm__ volatile("movl %%gs:0x0, %0" : "=r"(cur_tp));
        if (cur_tp <= 0x10000UL) cur_tp = g_current_tls_base;
        g_saved_cur_tp = cur_tp;
        if (cur_tp > 0x10000UL) {
            unsigned char *tp_src = (unsigned char *)(cur_tp - 64);
            for (int i = 0; i < 320; i++) g_saved_tls[i] = tp_src[i];
        }
        for (int i = 0; i < MAX_PTHREADS; i++) {
            if (g_pthreads[i].in_use && g_pthreads[i].tls_base > 0x10000UL) {
                unsigned char *pt_src = (unsigned char *)(g_pthreads[i].tls_base - 64);
                for (int k = 0; k < 320; k++) g_saved_pthread_tls[i][k] = pt_src[k];
            }
        }
        unsigned char *musl_rw = (unsigned char *)0x0B09B000UL;
        for (int k = 0; k < 16384; k++) g_saved_musl_rw[k] = musl_rw[k];
    } else if (g_current_tls_base) {
        for (int i = 0; i < 256; i++) g_saved_tls[i] = ((unsigned char *)g_current_tls_base)[i];
    }
}

static void vfork_restore_state(void) {
    for (int i = 0; i < MAX_FD; i++) {
        if (g_fds[i].is_open) sys_close(i);
        g_fds[i] = g_vfork_saved_fds[i];
    }
    if (bb_set_ptr_to_globals && g_saved_ptr_to_globals) bb_set_ptr_to_globals(g_saved_ptr_to_globals);
    if (bb_set_applet_name && g_saved_applet_name) bb_set_applet_name(g_saved_applet_name);
    if (bb_set_die_func && g_saved_die_func) bb_set_die_func(g_saved_die_func);
    optind = g_saved_optind;
    if (bb_common_bufsiz1)
        for (int i = 0; i < SHIM_BB_COMMON_BUFSIZE; i++) bb_common_bufsiz1[i] = g_saved_common_bufsiz[i];
    if (&xfunc_error_retval) xfunc_error_retval = g_saved_xfunc_error_retval;
    if (!g_is_dynamic_elf) {
        clearerr(stdin);
        clearerr(stdout);
        clearerr(stderr);
    }
    if (g_is_dynamic_elf) {
        if (g_saved_cur_tp > 0x10000UL) {
            unsigned char *tp_dst = (unsigned char *)(g_saved_cur_tp - 64);
            for (int i = 0; i < 320; i++) tp_dst[i] = g_saved_tls[i];
        }
        for (int i = 0; i < MAX_PTHREADS; i++) {
            if (g_pthreads[i].in_use && g_pthreads[i].tls_base > 0x10000UL) {
                unsigned char *pt_dst = (unsigned char *)(g_pthreads[i].tls_base - 64);
                for (int k = 0; k < 320; k++) pt_dst[k] = g_saved_pthread_tls[i][k];
            }
        }
        unsigned char *musl_rw = (unsigned char *)0x0B09B000UL;
        for (int k = 0; k < 16384; k++) {
            /* Preserve __malloc_context [0x0B09C720, 0x0B09C920) so child heap allocations stay consistent */
            if (k >= 0x1720 && k < 0x1920) continue;
            musl_rw[k] = g_saved_musl_rw[k];
        }
    } else if (g_current_tls_base) {
        for (int i = 0; i < 256; i++) ((unsigned char *)g_current_tls_base)[i] = g_saved_tls[i];
    }
}

static unsigned char g_vfork_helper_stack[8192] __attribute__((aligned(16)));

static void __attribute__((noinline)) vfork_restore_and_longjmp(void) {
    if (g_saved_stack_size > 0 && g_saved_sp) {
        for (s_restore_idx = 0; s_restore_idx < g_saved_stack_size; s_restore_idx++) {
            ((unsigned char *)g_saved_sp)[s_restore_idx] = g_saved_stack[s_restore_idx];
        }
    }
    vfork_restore_state();
    g_in_vfork = 0;
    longjmp(g_vfork_buf, 1);
}

static void __attribute__((noreturn)) vfork_longjmp_parent(void) {
    void *new_sp = g_vfork_helper_stack + sizeof(g_vfork_helper_stack) - 64;
    __asm__ volatile(
        "movl %0, %%esp\n\t"
        "call *%1\n\t"
        : : "r"(new_sp), "r"(&vfork_restore_and_longjmp) : "memory"
    );
    for (;;) {}
}

/* Parent side of a vfork: record a synchronous child's exit for wait4. */
static long shim_vfork_parent_result(void) {
    long pid = g_vfork_child_pid;
    if (g_vfork_is_sync && g_exited_child_count < MAX_EXITED_CHILDREN) {
        g_exited_children[g_exited_child_count].pid = pid;
        g_exited_children[g_exited_child_count].code = g_child_exit_code;
        g_exited_child_count++;
    }
    g_vfork_child_pid = 0;
    g_vfork_is_sync = 0;
    return pid;
}

static long sys_vfork(void) {
    /* Prevent dbus-daemon _dbus_spawn_async_with_babysitter double-fork from hijacking main loop */
    if (shim_strcmp(g_current_exe_path, "/usr/bin/dbus-daemon") == 0) {
        return -LINUX_EAGAIN;
    }
    shim_debug_print("[vfork] ");
    shim_debug_print(g_current_exe_path);
    shim_debug_print("\n");
    g_in_vfork = 1;
    g_vfork_child_pid = 0;
    g_vfork_is_sync = 0;
    vfork_save_state();

    void *stack_base = NULL;
    __asm__ volatile ("movl %%fs:0x04, %0" : "=r"(stack_base));
    void *current_sp;
    __asm__ volatile ("movl %%esp, %0" : "=r"(current_sp));

    unsigned char *save_base = (unsigned char *)current_sp - 256;
    unsigned long used = 0;
    if ((unsigned long)stack_base > (unsigned long)save_base) {
        used = (unsigned long)stack_base - (unsigned long)save_base;
    }
    if (used > sizeof(g_saved_stack)) used = sizeof(g_saved_stack);
    g_saved_stack_size = used;
    g_saved_sp = save_base;
    for (s_restore_idx = 0; s_restore_idx < used; s_restore_idx++) {
        g_saved_stack[s_restore_idx] = save_base[s_restore_idx];
    }

    if (setjmp(g_vfork_buf) == 0) {
        return 0;
    }

    if (!g_vfork_child_pid) {
        g_vfork_child_pid = ++s_next_child_pid;
        g_vfork_is_sync = 1;
    }
    shim_debug_print("[vfork->parent] ");
    shim_debug_print(g_current_exe_path);
    shim_debug_hex(" pid=", (unsigned long)g_vfork_child_pid);
    return shim_vfork_parent_result();
}

static long sys_clone(unsigned long flags, unsigned long child_esp,
                      int *ptid, void *tls_desc, int *ctid, int (*fn)(void *)) {
    /* 1. pthread_create (CLONE_THREAD) */
    if (flags & 0x00010000UL) {
        return sys_clone_thread(flags, child_esp, ptid, tls_desc, ctid, fn);
    }
    /* 2. posix_spawn (__clone with CLONE_VM | CLONE_VFORK and child_esp != 0, fn != 0) */
    if ((flags & 0x00004100UL) == 0x00004100UL && child_esp && fn) {
        g_in_vfork = 1;
        g_vfork_child_pid = 0;
        g_vfork_is_sync = 0;
        g_saved_stack_size = 0;
        vfork_save_state();
        if (setjmp(g_vfork_buf) == 0) {
            void *arg = *(void **)child_esp;
            int rc = fn(arg);
            g_child_exit_code = rc;
            g_vfork_is_sync = 1;
            vfork_longjmp_parent();
        }
        if (!g_vfork_child_pid) {
            g_vfork_child_pid = ++s_next_child_pid;
            g_vfork_is_sync = 1;
        }
        return shim_vfork_parent_result();
    }
    /* 3. Standard fork() / vfork() */
    return sys_vfork();
}

static void shim_exit_child(int code) {
    if (g_in_vfork) {
        g_child_exit_code = code;
        g_vfork_is_sync = 1;
        if (!g_vfork_child_pid) {
            g_vfork_child_pid = ++s_next_child_pid;
        }
        vfork_longjmp_parent();
    }
    for (int i = 0; i < MAX_FD; i++) {
        if (g_fds[i].is_open) sys_close(i);
    }
    Nt_TerminateProcess((HANDLE)-1, (NTSTATUS)code);
}

static long sys_execve(const char *filename, char **argv, char **envp) {
    if (!filename) return -LINUX_ENOENT;
    const char *prog = filename;
    for (const char *p = filename; *p; p++) {
        if (*p == '/' || *p == '\\') prog = p + 1;
    }

    const char *cmd = (argv && argv[0]) ? argv[0] : prog;
    const char *cmd_base = cmd;
    for (const char *p = cmd; *p; p++) {
        if (*p == '/' || *p == '\\') cmd_base = p + 1;
    }

    int argc = 0;
    if (argv) {
        while (argv[argc]) argc++;
    }

    /* 0. If x11_fb_bridge is launched in vfork, spawn as concurrent NT process! */
    if (g_in_vfork && (shim_strcmp(cmd_base, "x11_fb_bridge") == 0 || shim_strcmp(cmd_base, "xfce-probe") == 0 ||
        (shim_strcmp(cmd_base, "busybox") == 0 && argc >= 2 && shim_strcmp(argv[1], "x11_fb_bridge") == 0))) {
        long cpid = shim_spawn_elf_process("/bin/busybox", 1, argc, argv, envp);
        if (cpid > 0) {
            g_vfork_child_pid = cpid;
            g_vfork_is_sync = 0;
            vfork_longjmp_parent();
        }
    }

    /* 1. Builtin XDDK / network / SSH / USB / compiler tools */
    {
        SHIM_TOOL_MAIN tool = shim_find_modtool(cmd_base);
        if (!tool) tool = shim_find_modtool(prog);
        if (tool) shim_exit_child(tool(argc, argv));
    }
    if (shim_strcmp(cmd_base, "gcc") == 0 || shim_strcmp(prog, "gcc") == 0) shim_exit_child(gcc_main(argc, argv));
    if (shim_strcmp(cmd_base, "g++") == 0 || shim_strcmp(prog, "g++") == 0 ||
        shim_strcmp(cmd_base, "gxx") == 0 || shim_strcmp(prog, "gxx") == 0) shim_exit_child(gxx_main(argc, argv));
    if (shim_strcmp(cmd_base, "cpp") == 0 || shim_strcmp(prog, "cpp") == 0) shim_exit_child(cpp_main(argc, argv));
    if (shim_strcmp(cmd_base, "gdb") == 0 || shim_strcmp(prog, "gdb") == 0) shim_exit_child(gdb_main(argc, argv));
    if (shim_strcmp(cmd_base, "test_cxx") == 0 || shim_strcmp(prog, "test_cxx") == 0 ||
        shim_strcmp(cmd_base, "test_cxx.elf") == 0 || shim_strcmp(prog, "test_cxx.elf") == 0)
        shim_exit_child(test_cxx_main(argc, argv));
    if (shim_strcmp(cmd_base, "nttest") == 0 || shim_strcmp(prog, "nttest") == 0 ||
        shim_strcmp(cmd_base, "nttest.elf") == 0 || shim_strcmp(prog, "nttest.elf") == 0)
        shim_exit_child(nttest_main(argc, argv));

    /* 2. If /bin/sh (or -sh) is invoked via execve (e.g. Xvfb popen("xkbcomp") or xfce4-terminal / xterm PTY shell),
     * spawn it as a concurrent NT process so parent and child pipe/PTY I/O run in parallel! */
    if (g_in_vfork && (shim_strcmp(cmd_base, "sh") == 0 || shim_strcmp(cmd_base, "-sh") == 0 ||
                       shim_strcmp(prog, "sh") == 0)) {
        long cpid = shim_spawn_elf_process("/bin/busybox", 1, argc, argv, envp);
        if (cpid > 0) {
            g_vfork_child_pid = cpid;
            g_vfork_is_sync = 0;
            vfork_longjmp_parent();
        }
    }

    /* 3. Check if target is a real ELF binary or #! script on disk (unless it's /bin/busybox) */
    if (shim_strcmp(cmd_base, "busybox") != 0 && shim_strcmp(prog, "busybox") != 0) {
        char can_path[260];
        CanonicalizePosixPath(filename, can_path, sizeof(can_path));
        long efd = sys_openat(-100, can_path, 0, 0);
        if (efd < 0 && filename[0] != '/') {
            char try_usr[260] = "/usr/bin/";
            shim_strcpy(try_usr + 9, prog, sizeof(try_usr) - 9);
            CanonicalizePosixPath(try_usr, can_path, sizeof(can_path));
            efd = sys_openat(-100, can_path, 0, 0);
            if (efd < 0) {
                char try_bin[260] = "/bin/";
                shim_strcpy(try_bin + 5, prog, sizeof(try_bin) - 5);
                CanonicalizePosixPath(try_bin, can_path, sizeof(can_path));
                efd = sys_openat(-100, can_path, 0, 0);
            }
        }
        if (efd >= 0) {
            unsigned char hdr[128];
            for (int k = 0; k < 128; k++) hdr[k] = 0;
            long nread = sys_read((int)efd, hdr, sizeof(hdr) - 1);
            sys_close((int)efd);

            /* Shebang script (#!) */
            if (nread >= 2 && hdr[0] == '#' && hdr[1] == '!') {
                char *s_argv[64];
                int s_argc = 0;
                s_argv[s_argc++] = "/bin/sh";
                s_argv[s_argc++] = can_path;
                for (int i = 1; i < argc && s_argc < 62; i++) s_argv[s_argc++] = argv[i];
                s_argv[s_argc] = NULL;
                long cpid = shim_spawn_elf_process("/bin/busybox", 1, s_argc, s_argv, envp);
                if (g_in_vfork && cpid > 0) {
                    g_vfork_child_pid = cpid;
                    g_vfork_is_sync = 0;
                    vfork_longjmp_parent();
                }
            }

            /* Real ELF32 binary (not static /bin/busybox or hardlink to it) */
            if (nread >= 32 && hdr[0] == 0x7F && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F') {
                const Elf32_Ehdr *eh = (const Elf32_Ehdr *)hdr;
                int is_static_busybox = (eh->e_entry >= 0x01000000UL && eh->e_entry < 0x01500000UL);
                if (!is_static_busybox && shim_strcmp(can_path, "/bin/busybox") != 0) {
                    if (g_in_vfork) {
                        long cpid = shim_spawn_elf_process(can_path, 0, argc, argv, envp);
                        if (cpid > 0) {
                            g_vfork_child_pid = cpid;
                            g_vfork_is_sync = 0;
                            vfork_longjmp_parent();
                        }
                        shim_exit_child(127);
                    } else {
                        shim_exec_dynamic_elf(can_path, argc, argv, envp);
                    }
                }
            }
        }
    }

    /* 4. BusyBox built-in applets */
    if (find_applet_by_name && run_applet_no_and_exit) {
        int app_idx = -1;
        if (shim_strcmp(cmd_base, "busybox") == 0 && argv && argv[1]) {
            const char *sub = argv[1];
            for (const char *p = sub; *p; p++) {
                if (*p == '/' || *p == '\\') sub = p + 1;
            }
            if (shim_find_modtool(sub)) shim_exit_child(shim_find_modtool(sub)(argc - 1, argv + 1));
            if (shim_strcmp(sub, "gcc") == 0) shim_exit_child(gcc_main(argc - 1, argv + 1));
            if (shim_strcmp(sub, "g++") == 0 || shim_strcmp(sub, "gxx") == 0) shim_exit_child(gxx_main(argc - 1, argv + 1));
            if (shim_strcmp(sub, "cpp") == 0) shim_exit_child(cpp_main(argc - 1, argv + 1));
            if (shim_strcmp(sub, "gdb") == 0) shim_exit_child(gdb_main(argc - 1, argv + 1));
            if (shim_strcmp(sub, "test_cxx") == 0 || shim_strcmp(sub, "test_cxx.elf") == 0) shim_exit_child(test_cxx_main(argc - 1, argv + 1));
            if (shim_strcmp(sub, "nttest") == 0 || shim_strcmp(sub, "nttest.elf") == 0) shim_exit_child(nttest_main(argc - 1, argv + 1));

            app_idx = find_applet_by_name(sub);
            if (app_idx >= 0) {
                optind = 1;
                shim_prepare_applet();
                run_applet_no_and_exit(app_idx, sub, argv + 1);
            }
        }

        app_idx = find_applet_by_name(cmd_base);
        if (app_idx < 0) app_idx = find_applet_by_name(prog);
        if (app_idx >= 0) {
            optind = 1;
            shim_prepare_applet();
            run_applet_no_and_exit(app_idx, cmd_base, argv);
        }
    }

    if (g_in_vfork) {
        shim_exit_child(127);
    }
    return -LINUX_ENOENT;
}

static long sys_wait4(long pid, int *wstatus, int options, void *rusage) {
    (void)rusage;
    /* 1. Synchronous in-process vfork children */
    for (unsigned int i = 0; i < g_exited_child_count; i++) {
        if (pid > 0 && g_exited_children[i].pid != pid) continue;
        long ret = g_exited_children[i].pid;
        if (wstatus) *wstatus = (g_exited_children[i].code & 0xFF) << 8;
        g_exited_children[i] = g_exited_children[--g_exited_child_count];
        return ret;
    }

    /* 2. Asynchronous NT child processes */
    for (;;) {
        int any = 0;
        for (int i = 0; i < MAX_CHILD_PROCS; i++) {
            if (!g_child_procs[i].in_use) continue;
            if (pid > 0 && g_child_procs[i].pid != pid) continue;
            any = 1;

            if (!g_child_procs[i].exited) {
                LARGE_INTEGER zero_wait = { .QuadPart = 0 };
                NTSTATUS st = Nt_WaitForSingleObject(g_child_procs[i].hProcess, 0, &zero_wait);
                if (st == 0 /* STATUS_WAIT_0 */) {
                    PROCESS_BASIC_INFORMATION pbi;
                    g_child_procs[i].exited = 1;
                    if (NT_SUCCESS(Nt_QueryInformationProcess(g_child_procs[i].hProcess, 0, &pbi, sizeof(pbi), NULL))) {
                        g_child_procs[i].exit_code = (int)pbi.ExitStatus;
                    }
                }
            }

            if (g_child_procs[i].exited) {
                long done_pid = g_child_procs[i].pid;
                int code = g_child_procs[i].exit_code;
                if (g_child_procs[i].hThread) Nt_Close(g_child_procs[i].hThread);
                if (g_child_procs[i].hProcess) Nt_Close(g_child_procs[i].hProcess);
                g_child_procs[i].in_use = 0;
                if (g_vfork_child_pid == done_pid) g_vfork_child_pid = 0;
                if (wstatus) *wstatus = (code & 0xFF) << 8;
                return done_pid;
            }
        }

        if (!any) return -LINUX_ECHILD;
        if (options & 1 /* WNOHANG */) return 0;

        LARGE_INTEGER delay = { .QuadPart = -100000LL }; /* 10ms */
        Nt_DelayExecution(0, &delay);
    }
}
/* ========================================================================= */
/* Master System Call Dispatcher                                             */
/* ========================================================================= */
static long get_current_pid(void) {
    unsigned long pid = 0;
    __asm__ volatile("movl %%fs:0x20, %0" : "=r"(pid));
    return pid ? (long)pid : 100;
}

static long get_current_tid(void) {
    unsigned long tid = 0;
    __asm__ volatile("movl %%fs:0x24, %0" : "=r"(tid));
    return tid ? (long)tid : 100;
}

long __nt_linux_syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    if (!g_shim_initialized) InitShim();
    if (!g_main_tid) g_main_tid = get_current_tid();

    switch (n) {
        case LINUX_SYS_exit: {
            if (g_in_vfork) {
                g_child_exit_code = (int)a1;
                g_vfork_is_sync = 1;
                if (!g_vfork_child_pid) g_vfork_child_pid = ++s_next_child_pid;
                vfork_longjmp_parent();
            }
            /* Check if caller is a secondary pthread */
            long tid = get_current_tid();
            for (int i = 0; i < MAX_PTHREADS; i++) {
                if (g_pthreads[i].in_use && g_pthreads[i].tid == tid) {
                    if (g_pthreads[i].ctid) *g_pthreads[i].ctid = 0;
                    g_pthreads[i].in_use = 0;
                    shim_debug_print("[thread_exit] ");
                    shim_debug_print(g_current_exe_path);
                    shim_debug_hex(" tid=", (unsigned long)tid);
                    Nt_TerminateThread((HANDLE)-2, (NTSTATUS)a1);
                    return 0;
                }
            }
            if (g_main_tid && tid != g_main_tid) {
                shim_debug_print("[thread_exit_unmatched] ");
                shim_debug_print(g_current_exe_path);
                shim_debug_hex(" tid=", (unsigned long)tid);
                Nt_TerminateThread((HANDLE)-2, (NTSTATUS)a1);
                return 0;
            }
            if (g_current_exe_path[0]) {
                shim_debug_print("[exit] ");
                shim_debug_print(g_current_exe_path);
                shim_debug_print(a1 == 0 ? " code=0\n" : " code!=0\n");
            }
            for (int i = 0; i < MAX_FD; i++) {
                if (g_fds[i].is_open) sys_close(i);
            }
            Nt_TerminateProcess((HANDLE)-1, (NTSTATUS)a1);
            return 0;
        }

        case LINUX_SYS_exit_group: {
            if (g_in_vfork) {
                g_child_exit_code = (int)a1;
                g_vfork_is_sync = 1;
                if (!g_vfork_child_pid) g_vfork_child_pid = ++s_next_child_pid;
                vfork_longjmp_parent();
            }
            if (g_current_exe_path[0]) {
                shim_debug_print("[exit_group] ");
                shim_debug_print(g_current_exe_path);
                shim_debug_print(a1 == 0 ? " code=0\n" : " code!=0\n");
            }
            for (int i = 0; i < MAX_FD; i++) {
                if (g_fds[i].is_open) sys_close(i);
            }
            Nt_TerminateProcess((HANDLE)-1, (NTSTATUS)a1);
            return 0;
        }

        case LINUX_SYS_read:
            return sys_read((int)a1, (void *)a2, (unsigned int)a3);

        case LINUX_SYS_write:
            return sys_write((int)a1, (const void *)a2, (unsigned int)a3);

        case 180: /* pread64 */ {
            int fd = (int)a1;
            if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open || !g_fds[fd].h) return -LINUX_EBADF;
            IO_STATUS_BLOCK iosb;
            LARGE_INTEGER off;
            off.QuadPart = ((s64)a5 << 32) | (u32)a4;
            NTSTATUS st = Nt_ReadFile(g_fds[fd].h, NULL, NULL, NULL, &iosb, (void *)a2, (unsigned long)a3, &off, NULL);
            return NT_SUCCESS(st) ? (long)iosb.Information : 0;
        }

        case 181: /* pwrite64 */ {
            int fd = (int)a1;
            if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open || !g_fds[fd].h) return -LINUX_EBADF;
            IO_STATUS_BLOCK iosb;
            LARGE_INTEGER off;
            off.QuadPart = ((s64)a5 << 32) | (u32)a4;
            NTSTATUS st = Nt_WriteFile(g_fds[fd].h, NULL, NULL, NULL, &iosb, (void *)a2, (unsigned long)a3, &off, NULL);
            return NT_SUCCESS(st) ? (long)iosb.Information : -LINUX_EIO;
        }

        case LINUX_SYS_open:
            return sys_openat(-100, (const char *)a1, (int)a2, (unsigned int)a3);

        case LINUX_SYS_creat:
            return sys_openat(-100, (const char *)a1, 00000100 | 00001000 | 00000001, (unsigned int)a2);

        case LINUX_SYS_openat:
            return sys_openat((int)a1, (const char *)a2, (int)a3, (unsigned int)a4);

        case LINUX_SYS_close:
            return sys_close((int)a1);

        case LINUX_SYS_dup:
            return sys_dup((int)a1);

        case LINUX_SYS_dup2:
            return sys_dup2((int)a1, (int)a2, 0);

        case LINUX_SYS_dup3:
            return sys_dup2((int)a1, (int)a2, (int)a3);

        case LINUX_SYS_lseek:
            return sys_lseek((int)a1, (s64)(long)a2, (int)a3);

        case LINUX_SYS_llseek: {
            s64 off = ((s64)a2 << 32) | (u32)a3;
            long res = sys_lseek((int)a1, off, (int)a5);
            if (res >= 0 && a4) *(u64 *)a4 = (u64)res;
            return res < 0 ? res : 0;
        }

        case LINUX_SYS_brk:
            return sys_brk((unsigned long)a1);

        case LINUX_SYS_mmap: {
            unsigned long *ma = (unsigned long *)a1;
            if (!ma) return -LINUX_EFAULT;
            return sys_mmap2((void *)ma[0], ma[1], (int)ma[2], (int)ma[3], (int)ma[4], ma[5] >> 12);
        }

        case LINUX_SYS_mmap2:
            return sys_mmap2((void *)a1, (unsigned long)a2, (int)a3, (int)a4, (int)a5, (unsigned long)a6);

        case LINUX_SYS_mremap: {
            void *old_addr = (void *)a1;
            unsigned long old_sz = (unsigned long)a2;
            unsigned long new_sz = (unsigned long)a3;
            long new_addr = sys_mmap2(NULL, new_sz, 7, 0x22, -1, 0);
            if ((unsigned long)new_addr < (unsigned long)-4095L && old_addr) {
                unsigned long cp = old_sz < new_sz ? old_sz : new_sz;
                for (unsigned long k = 0; k < cp; k++) ((unsigned char *)new_addr)[k] = ((const unsigned char *)old_addr)[k];
            }
            return new_addr;
        }

        case LINUX_SYS_munmap:
            return sys_munmap((void *)a1, (unsigned long)a2);

        case LINUX_SYS_mprotect:
            return sys_mprotect((void *)a1, (unsigned long)a2, (int)a3);

        case LINUX_SYS_ioctl:
            return sys_ioctl((int)a1, (unsigned long)a2, (void *)a3);

        case LINUX_SYS_getdents64:
            return sys_getdents64((int)a1, (void *)a2, (unsigned int)a3);

        case LINUX_SYS_stat64:
        case LINUX_SYS_lstat64:
            return sys_stat64((const char *)a1, (struct linux_stat64 *)a2);

        case 300: /* fstatat64 */
            return sys_fstatat64((int)a1, (const char *)a2, (struct linux_stat64 *)a3, (int)a4);

        case 85:  /* readlink */
            return sys_readlink((const char *)a1, (char *)a2, (unsigned int)a3);

        case 305: /* readlinkat */
            return sys_readlink((const char *)a2, (char *)a3, (unsigned int)a4);

        case 291: /* inotify_init */
        case 332: /* inotify_init1 */ {
            int fd = -1;
            for (int i = 3; i < MAX_FD; i++) { if (!g_fds[i].is_open) { fd = i; break; } }
            if (fd < 0) return -LINUX_EMFILE;
            for (unsigned int k = 0; k < sizeof(SHIM_FD); k++) ((unsigned char *)&g_fds[fd])[k] = 0;
            g_fds[fd].is_open = 1;
            g_fds[fd].is_inotify = 1;
            if (n == 332) {
                g_fds[fd].nonblock = (a1 & 00004000) ? 1 : 0;
                g_fds[fd].cloexec  = (a1 & 02000000) ? 1 : 0;
            }
            return fd;
        }
        case 292: /* inotify_add_watch */ {
            static int s_next_wd = 1;
            return ++s_next_wd;
        }
        case 293: /* inotify_rm_watch */
            return 0;

        case 383: /* statx */
        case 321: /* signalfd */
        case 322: /* timerfd_create */
        case 325: /* timerfd_settime */
        case 326: /* timerfd_gettime */
        case 327: /* signalfd4 */
        case 338: /* fanotify_init */
        case 339: /* fanotify_mark */
        case 341: /* name_to_handle_at */
        case 342: /* open_by_handle_at */
        case 354: /* seccomp */
        case 357: /* bpf */
        case 374: /* userfaultfd */
        case 393: /* semget */
        case 394: /* semctl */
        case 395: /* shmget */
        case 396: /* shmctl */
        case 397: /* shmat */
        case 398: /* shmdt */
        case 424: /* pidfd_send_signal */
        case 425: /* io_uring_setup */
        case 426: /* io_uring_enter */
        case 427: /* io_uring_register */
        case 434: /* pidfd_open */
        case 435: /* clone3 */
        case 437: /* openat2 */
        case 438: /* pidfd_getfd */
        case 441: /* epoll_pwait2 */
            return -LINUX_ENOSYS;

        case 436: /* close_range(unsigned int first, unsigned int last, unsigned int flags) */ {
            unsigned int first = (unsigned int)a1;
            unsigned int last  = (unsigned int)a2;
            unsigned int cr_flags = (unsigned int)a3;
            if (first > last) return -LINUX_EINVAL;
            if (last >= MAX_FD) last = MAX_FD - 1;
            for (unsigned int i = first; i <= last; i++) {
                if (g_fds[i].is_open) {
                    if (cr_flags & 4 /* CLOSE_RANGE_CLOEXEC */) {
                        g_fds[i].cloexec = 1;
                    } else {
                        sys_close((int)i);
                    }
                }
            }
            return 0;
        }

        case 13: /* time */ {
            volatile LARGE_INTEGER *pTime = (volatile LARGE_INTEGER *)0x7FFE0014;
            long sec = (long)((pTime->QuadPart - 116444736000000000ULL) / 10000000ULL);
            if (a1) *(long *)a1 = sec;
            return sec;
        }

        case 403: /* clock_gettime64 */ {
            volatile LARGE_INTEGER *pTime = (volatile LARGE_INTEGER *)0x7FFE0014;
            s64 t100ns = pTime->QuadPart - 116444736000000000ULL;
            struct { s64 sec; s64 nsec; } *ts64 = (void *)a2;
            if (ts64) {
                ts64->sec = t100ns / 10000000ULL;
                ts64->nsec = (t100ns % 10000000ULL) * 100;
            }
            return 0;
        }

        case 406: /* clock_getres_time64 */ {
            struct { s64 sec; s64 nsec; } *ts64 = (void *)a2;
            if (ts64) { ts64->sec = 0; ts64->nsec = 1000000; }
            return 0;
        }

        case LINUX_SYS_fstat64:
            return sys_fstat64_fd((int)a1, (struct linux_stat64 *)a2);

        case LINUX_SYS_getcwd:
            return sys_getcwd((char *)a1, (unsigned long)a2);

        case LINUX_SYS_chdir:
            return sys_chdir((const char *)a1);

        case LINUX_SYS_fchdir: {
            int fd = (int)a1;
            if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && g_fds[fd].dir_path[0]) {
                shim_strcpy(g_cwd, g_fds[fd].dir_path, sizeof(g_cwd));
                return 0;
            }
            return 0;
        }

        case LINUX_SYS_mkdir:
            return sys_mkdir((const char *)a1, (unsigned int)a2);
        case LINUX_SYS_mkdirat:
            return sys_mkdir((const char *)a2, (unsigned int)a3);

        case LINUX_SYS_unlink:
        case LINUX_SYS_rmdir:
            return sys_unlink((const char *)a1);
        case LINUX_SYS_unlinkat:
            return sys_unlink((const char *)a2);

        case LINUX_SYS_rename:
            return sys_rename((const char *)a1, (const char *)a2);
        case LINUX_SYS_renameat:
        case 353: /* renameat2 */
            return sys_rename((const char *)a2, (const char *)a4);

        case LINUX_SYS_access:
            return sys_access((const char *)a1, (int)a2);
        case LINUX_SYS_faccessat:
        case 439: /* faccessat2 */
            return sys_access((const char *)a2, (int)a3);

        case LINUX_SYS_fcntl:
        case LINUX_SYS_fcntl64:
            return sys_fcntl((int)a1, (int)a2, (unsigned long)a3);

        case LINUX_SYS_pipe:
            return sys_pipe2((int *)a1, 0);
        case LINUX_SYS_pipe2:
            return sys_pipe2((int *)a1, (int)a2);

        case 323: /* eventfd */
            return sys_eventfd2((unsigned int)a1, 0);
        case 328: /* eventfd2 */
            return sys_eventfd2((unsigned int)a1, (int)a2);

        case 356: /* memfd_create */
            return sys_openat(-100, "/tmp/memfd_shm", 00000100 | 00001000 | 00000002, 0666);

        case 102: /* socketcall */
            return sys_socketcall((int)a1, (unsigned long *)a2);
        case 359: /* socket */
            return sys_socket((int)a1, (int)a2, (int)a3);
        case 360: /* socketpair */
            return sys_socketpair((int)a1, (int)a2, (int)a3, (int *)a4);
        case 361: /* bind */
            return sys_bind((int)a1, (const void *)a2, (unsigned int)a3);
        case 362: /* connect */
            return sys_connect((int)a1, (const void *)a2, (unsigned int)a3);
        case 363: /* listen */
            return sys_listen((int)a1, (int)a2);
        case 364: /* accept4 */
            return sys_accept4((int)a1, (void *)a2, (unsigned int *)a3, (int)a4);
        case 365: /* getsockopt */ {
            if (a4 && a5) {
                if (a3 == 17 /* SO_PEERCRED */ && *(unsigned int *)a5 >= 12) {
                    ((int *)a4)[0] = 100;
                    ((int *)a4)[1] = 0;
                    ((int *)a4)[2] = 0;
                    *(unsigned int *)a5 = 12;
                } else if (*(unsigned int *)a5 >= 4) {
                    *(int *)a4 = 0;
                    *(unsigned int *)a5 = 4;
                }
            }
            return 0;
        }
        case 366: /* setsockopt */
            return 0;
        case 367: /* getsockname */
        case 368: /* getpeername */ {
            if (a2 && a3 && *(unsigned int *)a3 >= 2) { *(unsigned short *)a2 = 1; *(unsigned int *)a3 = 2; }
            return 0;
        }
        case 369: /* sendto */
            return sock_write_fd((int)a1, (const void *)a2, (unsigned int)a3, (int)a4 & 0x40);
        case 370: /* sendmsg */
            return sys_sendmsg((int)a1, (const struct linux_msghdr *)a2, (int)a3);
        case 371: /* recvfrom */
            return sock_read_fd((int)a1, (void *)a2, (unsigned int)a3, (int)a4 & 0x40);
        case 372: /* recvmsg */
            return sys_recvmsg((int)a1, (struct linux_msghdr *)a2, (int)a3);
        case 373: /* shutdown */
            return 0;

        case 117: /* SYS_ipc (Return -ENOSYS so Cairo/GTK3/Xlib use standard X11 socket PutImage/XRender) */
            return -LINUX_ENOSYS;

        case LINUX_SYS_vfork:
        case LINUX_SYS_fork:
            return sys_vfork();

        case LINUX_SYS_clone:
            return sys_clone((unsigned long)a1, (unsigned long)a2, (int *)a3, (void *)a4, (int *)a5, (int (*)(void *))a6);

        case LINUX_SYS_execve:
            return sys_execve((const char *)a1, (char **)a2, (char **)a3);

        case LINUX_SYS_wait4:
            return sys_wait4((long)a1, (int *)a2, (int)a3, (void *)a4);
        case LINUX_SYS_waitpid:
            return sys_wait4((long)a1, (int *)a2, (int)a3, NULL);

        case LINUX_SYS_writev:
            return sys_writev((int)a1, (const struct linux_iovec *)a2, (int)a3);

        case LINUX_SYS_readv:
            return sys_readv((int)a1, (const struct linux_iovec *)a2, (int)a3);

        case LINUX_SYS_select:
        case LINUX_SYS__newselect:
        case LINUX_SYS_pselect6:
        case 414: /* pselect6_time64 */ {
            int nfds = (int)a1;
            unsigned long *rfds = (unsigned long *)a2;
            unsigned long *wfds = (unsigned long *)a3;
            unsigned long *efds = (unsigned long *)a4;
            int timeout_ms = -1;
            if ((n == LINUX_SYS__newselect || n == LINUX_SYS_select) && a5) {
                struct linux_timeval *tv = (struct linux_timeval *)a5;
                timeout_ms = (int)(tv->tv_sec * 1000 + tv->tv_usec / 1000);
                if (timeout_ms < 0) timeout_ms = 0;
            } else if ((n == LINUX_SYS_pselect6 || n == 414) && a5) {
                if (n == 414) {
                    s64 *ts64 = (s64 *)a5;
                    timeout_ms = (int)(ts64[0] * 1000 + ts64[1] / 1000000);
                } else {
                    struct linux_timespec *ts = (struct linux_timespec *)a5;
                    timeout_ms = (int)(ts->tv_sec * 1000 + ts->tv_nsec / 1000000);
                }
                if (timeout_ms < 0) timeout_ms = 0;
            }
            if (nfds > MAX_FD) nfds = MAX_FD;

            unsigned long in_r[4] = {0,0,0,0}, in_w[4] = {0,0,0,0};
            int words = (nfds + 31) / 32;
            for (int w = 0; w < words; w++) {
                if (rfds) in_r[w] = rfds[w];
                if (wfds) in_w[w] = wfds[w];
                if (efds) efds[w] = 0;
            }

            s64 start_ms = shim_now_ms();
            for (int iter = 0;; iter++) {
                int ready = 0;
                for (int w = 0; w < words; w++) {
                    if (rfds) rfds[w] = 0;
                    if (wfds) wfds[w] = 0;
                }
                for (int fd = 0; fd < nfds; fd++) {
                    int w = fd / 32;
                    unsigned long bit = 1UL << (fd % 32);
                    if (in_r[w] & bit) {
                        if (shim_fd_poll_events(fd, 1) & (1 | 0x10 | 0x08)) {
                            rfds[w] |= bit;
                            ready++;
                        }
                    }
                    if (in_w[w] & bit) {
                        if (shim_fd_poll_events(fd, 4) & (4 | 0x10 | 0x08)) {
                            wfds[w] |= bit;
                            ready++;
                        }
                    }
                }
                if (ready > 0 || (timeout_ms >= 0 && (shim_now_ms() - start_ms) >= timeout_ms)) return ready;
                shim_ipc_wait(iter);
            }
        }

        case LINUX_SYS_poll:
        case LINUX_SYS_ppoll:
        case 415: /* ppoll_time64 */ {
            struct linux_pollfd {
                int fd;
                short events;
                short revents;
            } *pfds = (struct linux_pollfd *)a1;
            int nfds = (int)a2;
            int timeout_ms = -1;
            if (n == LINUX_SYS_poll) {
                timeout_ms = (int)a3;
            } else if (a3) {
                if (n == 415) {
                    s64 *ts64 = (s64 *)a3;
                    timeout_ms = (int)(ts64[0] * 1000 + ts64[1] / 1000000);
                } else {
                    struct linux_timespec *ts = (struct linux_timespec *)a3;
                    timeout_ms = (int)(ts->tv_sec * 1000 + ts->tv_nsec / 1000000);
                }
                if (timeout_ms < 0) timeout_ms = 0;
            }

            s64 start_ms = shim_now_ms();
            for (int iter = 0;; iter++) {
                int ready = 0;
                for (int i = 0; i < nfds; i++) {
                    pfds[i].revents = 0;
                    if (pfds[i].fd < 0) continue;
                    short rev = shim_fd_poll_events(pfds[i].fd, pfds[i].events);
                    if (rev) {
                        pfds[i].revents = rev;
                        ready++;
                    }
                }
                if (ready > 0 || (timeout_ms >= 0 && (shim_now_ms() - start_ms) >= timeout_ms)) return ready;
                shim_ipc_wait(iter);
            }
        }

        case 254: /* epoll_create */
        case 329: /* epoll_create1 */ {
            int fd = -1, eidx = -1;
            for (int i = 3; i < MAX_FD; i++) { if (!g_fds[i].is_open) { fd = i; break; } }
            for (int i = 0; i < MAX_EPOLLS; i++) { if (!g_epolls[i].in_use) { eidx = i; break; } }
            if (fd < 0 || eidx < 0) return -LINUX_EMFILE;
            for (unsigned int k = 0; k < sizeof(SHIM_EPOLL); k++) ((unsigned char *)&g_epolls[eidx])[k] = 0;
            g_epolls[eidx].in_use = 1;
            for (unsigned int k = 0; k < sizeof(SHIM_FD); k++) ((unsigned char *)&g_fds[fd])[k] = 0;
            g_fds[fd].is_open = 1;
            g_fds[fd].is_epoll = 1;
            g_fds[fd].ipc_idx = eidx;
            return fd;
        }

        case 255: /* epoll_ctl */ {
            int epfd = (int)a1, op = (int)a2, fd = (int)a3;
            struct __attribute__((packed)) { u32 events; u64 data; } *ev = (void *)a4;
            if (epfd < 0 || epfd >= MAX_FD || !g_fds[epfd].is_open || !g_fds[epfd].is_epoll) return -LINUX_EBADF;
            SHIM_EPOLL *ep = &g_epolls[g_fds[epfd].ipc_idx];
            if (op == 1 /* ADD */ || op == 3 /* MOD */) {
                for (int i = 0; i < MAX_EPOLL_ITEMS; i++) {
                    if (ep->items[i].active && ep->items[i].fd == fd) {
                        if (ev) { ep->items[i].events = ev->events; ep->items[i].data = ev->data; }
                        return 0;
                    }
                }
                for (int i = 0; i < MAX_EPOLL_ITEMS; i++) {
                    if (!ep->items[i].active) {
                        ep->items[i].active = 1;
                        ep->items[i].fd = fd;
                        ep->items[i].events = ev ? ev->events : 1;
                        ep->items[i].data = ev ? ev->data : (u64)fd;
                        return 0;
                    }
                }
            } else if (op == 2 /* DEL */) {
                for (int i = 0; i < MAX_EPOLL_ITEMS; i++) {
                    if (ep->items[i].active && ep->items[i].fd == fd) ep->items[i].active = 0;
                }
            }
            return 0;
        }

        case 256: /* epoll_wait */
        case 319: /* epoll_pwait */ {
            int epfd = (int)a1;
            struct __attribute__((packed)) { u32 events; u64 data; } *evs = (void *)a2;
            int maxev = (int)a3;
            int timeout_ms = (int)a4;
            if (epfd < 0 || epfd >= MAX_FD || !g_fds[epfd].is_open || !g_fds[epfd].is_epoll) return -LINUX_EBADF;
            SHIM_EPOLL *ep = &g_epolls[g_fds[epfd].ipc_idx];

            s64 start_ms = shim_now_ms();
            for (int iter = 0;; iter++) {
                int cnt = 0;
                for (int i = 0; i < MAX_EPOLL_ITEMS && cnt < maxev; i++) {
                    if (!ep->items[i].active) continue;
                    short req = (short)(ep->items[i].events & 0xFFFF);
                    short rev = shim_fd_poll_events(ep->items[i].fd, req);
                    if (rev) {
                        evs[cnt].events = (u32)(unsigned short)rev;
                        evs[cnt].data   = ep->items[i].data;
                        cnt++;
                    }
                }
                if (cnt > 0 || (timeout_ms >= 0 && (shim_now_ms() - start_ms) >= timeout_ms)) return cnt;
                shim_ipc_wait(iter);
            }
        }

        case LINUX_SYS_getpid:
            return get_current_pid();

        case LINUX_SYS_gettid:
            return get_current_tid();

        case LINUX_SYS_set_tid_address: {
            long tid = get_current_tid();
            for (int i = 0; i < MAX_PTHREADS; i++) {
                if (g_pthreads[i].in_use && g_pthreads[i].tid == tid) {
                    g_pthreads[i].ctid = (int *)a1;
                    break;
                }
            }
            return tid;
        }

        case LINUX_SYS_set_thread_area: {
            if (!a1) return -LINUX_EFAULT;
            unsigned int *ud = (unsigned int *)a1;
            shim_set_tls_base(ud[1]);
            ud[0] = 12; /* GDT entry 12 -> selector 0x63 */
            return 0;
        }

        case LINUX_SYS_getppid:
            return 1;

        case LINUX_SYS_getpgrp:
        case 132: /* getpgid */
        case 147: /* getsid */
            return get_current_pid();

        case 57:  /* setpgid */
        case 66:  /* setsid */
        case 60:  /* umask */
            return 0;

        case 75:  /* setrlimit */
            return 0;
        case 76:  /* getrlimit */
        case 191: /* ugetrlimit */ {
            unsigned long *rl = (unsigned long *)a2;
            if (rl) {
                if (a1 == 7 /* RLIMIT_NOFILE */) { rl[0] = MAX_FD; rl[1] = MAX_FD; }
                else { rl[0] = 8 * 1024 * 1024; rl[1] = 0x7FFFFFFFUL; }
            }
            return 0;
        }
        case 340: /* prlimit64 */ {
            u64 *old_rl = (u64 *)a4;
            if (old_rl) {
                if (a2 == 7 /* RLIMIT_NOFILE */) { old_rl[0] = MAX_FD; old_rl[1] = MAX_FD; }
                else { old_rl[0] = 8 * 1024 * 1024; old_rl[1] = 0xFFFFFFFFFFFFFFFFULL; }
            }
            return 0;
        }

        case 99:  /* statfs */
        case 100: /* fstatfs */
        case 268: /* statfs64 */
        case 269: /* fstatfs64 */ {
            unsigned int *sf = (unsigned int *)((n == 268 || n == 269) ? a3 : a2);
            if (sf) {
                for (int i = 0; i < 20; i++) sf[i] = 0;
                sf[0] = 0xEF53U; sf[1] = 4096; sf[2] = 65536; sf[3] = 32768; sf[4] = 32768;
            }
            return 0;
        }

        case LINUX_SYS_getuid:
        case LINUX_SYS_geteuid:
        case LINUX_SYS_getgid:
        case LINUX_SYS_getegid:
        case 199: case 200: case 201: case 202: case 203: case 204:
        case 205: case 206: case 207: case 208: case 210: case 212:
        case 213: case 214: case 215: case 216:
        case 15:  case 94:  case 306: /* chmod/fchmod/fchmodat */
        case 16:  case 95:  case 182: case 298: /* chown */
        case 36:  case 118: case 148: /* sync/fsync/fdatasync */
        case 92:  case 93:  case 193: case 194: case 324: /* truncate/fallocate */
        case 143: case 144: /* flock/msync */
        case 37:  case 238: case 270: /* kill/tkill/tgkill */ {
            int sig = (n == 270) ? (int)a3 : (int)a2;
            if ((n == 238 || n == 270) && (sig == 6 /* SIGABRT */ || sig == 9 /* SIGKILL */)) {
                for (int i = 0; i < MAX_FD; i++) if (g_fds[i].is_open) sys_close(i);
                Nt_TerminateProcess((HANDLE)-1, 128 + sig);
            }
            return 0;
        }
        case 172: /* prctl */
            return 0;

        case 209:
        case 211: {
            if (a1) *(int *)a1 = 0;
            if (a2) *(int *)a2 = 0;
            if (a3) *(int *)a3 = 0;
            return 0;
        }

        case LINUX_SYS_uname: {
            struct linux_utsname *u = (struct linux_utsname *)a1;
            int i;
            const char *sys = "Linux";
            const char *node = "nt-embedded";
            const char *rel = "5.1.2600-musl";
            const char *ver = "#1 PREEMPT Windows XP NT 5.1 x86";
            const char *mach = "i686";
            if (!u) return -LINUX_EFAULT;
            for (i=0; sys[i]; i++) u->sysname[i] = sys[i]; u->sysname[i] = 0;
            for (i=0; node[i]; i++) u->nodename[i] = node[i]; u->nodename[i] = 0;
            for (i=0; rel[i]; i++) u->release[i] = rel[i]; u->release[i] = 0;
            for (i=0; ver[i]; i++) u->version[i] = ver[i]; u->version[i] = 0;
            for (i=0; mach[i]; i++) u->machine[i] = mach[i]; u->machine[i] = 0;
            return 0;
        }

        case LINUX_SYS_clock_gettime: {
            volatile LARGE_INTEGER *pTime = (volatile LARGE_INTEGER *)0x7FFE0014;
            s64 t100ns = pTime->QuadPart - 116444736000000000ULL;
            struct linux_timespec *ts = (struct linux_timespec *)a2;
            if (ts) {
                ts->tv_sec = (long)(t100ns / 10000000ULL);
                ts->tv_nsec = (long)((t100ns % 10000000ULL) * 100);
            }
            return 0;
        }

        case LINUX_SYS_clock_getres: {
            struct linux_timespec *ts = (struct linux_timespec *)a2;
            if (ts) { ts->tv_sec = 0; ts->tv_nsec = 1000000; }
            return 0;
        }

        case 407: /* SYS_clock_nanosleep_time64 */ {
            s64 *req64 = (s64 *)a3;
            LARGE_INTEGER li;
            if (!req64) return 0;
            li.QuadPart = -(req64[0] * 10000000LL + (req64[1] / 100));
            Nt_DelayExecution(0, &li);
            return 0;
        }

        case 355: /* SYS_getrandom */ {
            unsigned char *buf = (unsigned char *)a1;
            unsigned int buflen = (unsigned int)a2;
            volatile unsigned long *pTick = (volatile unsigned long *)0x7FFE0008;
            unsigned int seed = (unsigned int)(*pTick ^ 0xA55A3C69U);
            if (!buf) return -LINUX_EFAULT;
            for (unsigned int i = 0; i < buflen; i++) {
                seed = seed * 1664525U + 1013904223U + (unsigned int)(*pTick);
                buf[i] = (unsigned char)((seed >> 16) ^ (seed >> 8));
            }
            return (long)buflen;
        }

        case 240: /* SYS_futex */
        case 422: /* SYS_futex_time64 */ {
            volatile int *uaddr = (volatile int *)a1;
            int op = (int)(a2 & 0x7F);
            int val = (int)a3;
            if ((op == 0 || op == 9) && uaddr) {
                if (*uaddr != val) return -LINUX_EAGAIN;
                for (int w = 0; w < 20 && *uaddr == val; w++) {
                    LARGE_INTEGER delay = { .QuadPart = -10000LL };
                    Nt_DelayExecution(0, &delay);
                }
                return 0;
            }
            return 1;
        }

        case 219: /* SYS_madvise */
        case 241: /* SYS_sched_setaffinity */
            return 0;

        case 158: /* SYS_sched_yield */ {
            LARGE_INTEGER li = { .QuadPart = 0 };
            Nt_DelayExecution(0, &li);
            return 0;
        }

        case 242: /* SYS_sched_getaffinity */ {
            unsigned int cpusetsize = (unsigned int)a2;
            unsigned long *mask = (unsigned long *)a3;
            if (!mask || cpusetsize < 4) return -LINUX_EINVAL;
            mask[0] = 1;
            return 4;
        }

        case 116: { /* SYS_sysinfo */
            extern long nt_sysinfo(unsigned long *);
            return nt_sysinfo((unsigned long *)a1);
        }

        case LINUX_SYS_gettimeofday: {
            volatile LARGE_INTEGER *pTime = (volatile LARGE_INTEGER *)0x7FFE0014;
            s64 t100ns = pTime->QuadPart - 116444736000000000ULL;
            struct linux_timeval *tv = (struct linux_timeval *)a1;
            if (tv) {
                tv->tv_sec = (long)(t100ns / 10000000ULL);
                tv->tv_usec = (long)((t100ns % 10000000ULL) / 10);
            }
            return 0;
        }

        case LINUX_SYS_nanosleep:
        case LINUX_SYS_clock_nanosleep: {
            struct linux_timespec *req = (struct linux_timespec *)(n == LINUX_SYS_nanosleep ? a1 : a3);
            LARGE_INTEGER li;
            if (!req) return 0;
            li.QuadPart = -((s64)req->tv_sec * 10000000LL + (req->tv_nsec / 100));
            Nt_DelayExecution(0, &li);
            return 0;
        }

        case LINUX_SYS_rt_sigaction:
        case LINUX_SYS_rt_sigprocmask:
        case LINUX_SYS_sigprocmask:
        case LINUX_SYS_sigaltstack:
        case 9:   /* link */
        case 83:  /* symlink */
        case 303: /* linkat */
        case 304: /* symlinkat */
        case 30:  /* utime */
        case 96:  /* getpriority */
        case 97:  /* setpriority */
        case 104: /* setitimer */
        case 105: /* getitimer */
        case 150: /* mlock */
        case 151: /* munlock */
        case 152: /* mlockall */
        case 153: /* munlockall */
        case 154: /* sched_setparam */
        case 155: /* sched_getparam */
        case 156: /* sched_setscheduler */
        case 157: /* sched_getscheduler */
        case 250: /* fadvise64 */
        case 271: /* utimes */
        case 272: /* fadvise64_64 */
        case 299: /* futimesat */
        case 311: /* set_robust_list */
        case 312: /* get_robust_list */
        case 320: /* utimensat */
        case 375: /* membarrier */
        case 412: /* utimensat_time64 */
            return 0;

        default: {
            static unsigned char seen_unhandled[512];
            if (n >= 0 && n < 512 && !seen_unhandled[n]) {
                seen_unhandled[n] = 1;
                char ubuf[80];
                int up = 0;
                const char *pfx = "[unhandled syscall] ";
                while (*pfx) ubuf[up++] = *pfx++;
                long tmp = n;
                if (tmp >= 100) ubuf[up++] = '0' + (int)((tmp / 100) % 10);
                if (tmp >= 10)  ubuf[up++] = '0' + (int)((tmp / 10) % 10);
                ubuf[up++] = '0' + (int)(tmp % 10);
                ubuf[up++] = ' ';
                const char *ep = g_current_exe_path;
                while (*ep && up < 76) ubuf[up++] = *ep++;
                ubuf[up++] = '\n';
                ubuf[up] = '\0';
                shim_debug_print(ubuf);
            }
            return -LINUX_ENOSYS;
        }
    }
}

int sigsetjmp(void *env, int savesigs) {
    (void)savesigs;
    return setjmp(env);
}

int __sigsetjmp(void *env, int savesigs) {
    (void)savesigs;
    return setjmp(env);
}
