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

static long shim_process_exists(long pid) {
    HANDLE process = NULL;
    CLIENT_ID cid = { (HANDLE)(unsigned long)pid, NULL };
    OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, NULL, 0, NULL, NULL };
    unsigned long args[4] = {
        (unsigned long)&process, 0x00100400UL /* SYNCHRONIZE | PROCESS_QUERY_INFORMATION */,
        (unsigned long)&oa, (unsigned long)&cid
    };
    NTSTATUS st = (NTSTATUS)DoNtSyscall(122 /* NtOpenProcess */, args, 4);
    if (!NT_SUCCESS(st))
        return (unsigned long)st == 0xC0000022UL ? -1 /* EPERM */ : -3 /* ESRCH */;
    LARGE_INTEGER zero_wait = { .QuadPart = 0 };
    st = Nt_WaitForSingleObject(process, 0, &zero_wait);
    Nt_Close(process);
    if (st == 0) return -3; /* Process has exited. */
    return st == 0x102 /* STATUS_TIMEOUT */ ? 0 : -LINUX_EIO;
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
#define MAX_IPC_PIPES      128
#define IPC_PIPE_BUF_SIZE  32768
#define MAX_IPC_LISTENERS  32
#define MAX_IPC_CONNS      128
#define IPC_RING_SIZE      65536
#define MAX_IPC_EVENTFDS   128
#define MAX_IPC_SHMS       128

typedef struct _SHIM_IPC_PIPE {
    volatile long lock;
    unsigned char buf[IPC_PIPE_BUF_SIZE];
    volatile unsigned int head;
    volatile unsigned int tail;
    volatile unsigned int count;
    volatile int read_refs;
    volatile int write_refs;
} SHIM_IPC_PIPE;

typedef struct _SHIM_IPC_SCM_FD {
    unsigned char is_sock;
    unsigned char is_server;
    unsigned char sock_state;
    unsigned char sock_domain;
    unsigned char sock_type;
    unsigned char is_eventfd;
    unsigned char is_pipe;
    unsigned char is_pipe_write;
    unsigned char is_shm;
    unsigned char nonblock;
    unsigned char open_flags;
    int           ipc_idx;
    unsigned int  shm_size;
    unsigned int  shm_ino;
    unsigned long nt_handle;
    unsigned int  src_pid;
} SHIM_IPC_SCM_FD;

#define MAX_SCM_FDS 64

typedef struct _SHIM_IPC_RING {
    volatile long lock;
    unsigned char buf[IPC_RING_SIZE];
    volatile unsigned int head;
    volatile unsigned int tail;
    volatile unsigned int count;
    SHIM_IPC_SCM_FD scm_fds[MAX_SCM_FDS];
    volatile unsigned int scm_head;
    volatile unsigned int scm_tail;
    volatile unsigned int scm_count;
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
    /* AF_INET connections to non-local hosts are serviced by netd (see
     * netd.c): listener_idx == NETD_LISTENER, the daemon owns the "server"
     * side of the rings and speaks real TCP over the RTL8139 NIC. */
    volatile int net_eof;          /* remote sent FIN / connection ended */
    volatile int net_err;          /* Linux errno (ECONNREFUSED, ETIMEDOUT, ECONNRESET) */
    volatile unsigned int net_rip; /* remote IPv4, host byte order */
    volatile unsigned int net_rport;
    volatile unsigned int net_lport;
    SHIM_IPC_RING c2s;
    SHIM_IPC_RING s2c;
} SHIM_IPC_CONN;

#define NETD_LISTENER (-100)
#define MAX_NET_UDP   32

/* One UDP socket serviced by netd. Each ring carries whole datagrams framed
 * as [u32 ipv4 host-order][u16 port][u16 len][payload]. */
typedef struct _SHIM_NET_UDP {
    volatile int in_use;
    volatile int refs;
    volatile unsigned int lport;
    SHIM_IPC_RING rx;
    SHIM_IPC_RING tx;
} SHIM_NET_UDP;

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

#define MAX_SHIM_PAKS 30
typedef struct _SHIM_PAK_ENTRY {
    unsigned int start_lba;
    unsigned int size;
    char         path[120];
} SHIM_PAK_ENTRY;

typedef struct _LXSS_IPC_SECTION {
    volatile unsigned int magic;
    volatile int banner_printed;
    volatile int graphics_active;
    volatile unsigned int xvfb_fb_size;
    volatile int next_pid;
    volatile unsigned int pak_loaded;
    volatile unsigned int pak_count;
    SHIM_PAK_ENTRY    paks[MAX_SHIM_PAKS];
    SHIM_IPC_PIPE     pipes[MAX_IPC_PIPES];
    SHIM_IPC_LISTENER listeners[MAX_IPC_LISTENERS];
    SHIM_IPC_CONN     conns[MAX_IPC_CONNS];
    SHIM_IPC_EVENTFD  eventfds[MAX_IPC_EVENTFDS];
    SHIM_IPC_SHM      shms[MAX_IPC_SHMS];
    SHIM_NET_UDP      net_udp[MAX_NET_UDP];
    volatile int      netd_ready;
    volatile unsigned int net_ip, net_mask, net_gw, net_dns;
    volatile unsigned int net_next_port;
    unsigned char     xvfb_fb[2097152] __attribute__((aligned(4096)));
} LXSS_IPC_SECTION;

static LXSS_IPC_SECTION *g_ipc = NULL;

static void ipc_lock(volatile long *lk) {
    int spin = 0;
    while (__sync_lock_test_and_set(lk, 1)) {
        if (++spin > 64) {
            LARGE_INTEGER delay;
            delay.QuadPart = (spin > 2000) ? -10000LL : 0;
            Nt_DelayExecution(0, &delay);
        } else {
            __asm__ volatile("pause");
        }
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

static HANDLE OpenOrCreateShmSection(unsigned int shm_ino, unsigned long size_bytes) {
    unsigned short wname[48];
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    LARGE_INTEGER max_sz;
    HANDLE hSec = NULL;
    const char *pfx = "\\LxssShm_";
    int i = 0;
    while (pfx[i]) { wname[i] = (unsigned short)(unsigned char)pfx[i]; i++; }
    unsigned int tmp = shm_ino ? shm_ino : 1;
    char digits[16];
    int nd = 0;
    while (tmp > 0 && nd < 15) { digits[nd++] = (char)('0' + (tmp % 10)); tmp /= 10; }
    while (nd > 0) wname[i++] = (unsigned short)(unsigned char)digits[--nd];
    wname[i] = 0;
    us.Length = (unsigned short)(i * 2);
    us.MaximumLength = us.Length + 2;
    us.Buffer = wname;
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = OBJ_CASE_INSENSITIVE | OBJ_OPENIF;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;
    unsigned long sec_sz = size_bytes ? ((size_bytes + 4095UL) & ~4095UL) : 65536UL;
    if (sec_sz < 4096UL) sec_sz = 4096UL;
    max_sz.QuadPart = (s64)sec_sz;
    NTSTATUS st = Nt_OpenSection(&hSec, SECTION_ALL_ACCESS, &oa);
    if (!NT_SUCCESS(st) || !hSec) {
        st = Nt_CreateSection(&hSec, SECTION_ALL_ACCESS, &oa, &max_sz, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    }
    return NT_SUCCESS(st) ? hSec : NULL;
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
#define MAX_FD       512
#define MAX_SPAWN_FD 128

#define SOCK_UNUSED    0
#define SOCK_CREATED   1
#define SOCK_BOUND     2
#define SOCK_LISTENING 3
#define SOCK_CONNECTED 4

#define PROC_NONE         0
#define PROC_DEV_URANDOM  1
#define PROC_DEV_ZERO     2
#define PROC_CPUINFO      3
#define PROC_MEMINFO      4
#define PROC_STAT         5
#define PROC_VERSION      6
#define PROC_VMSTAT       7
#define PROC_SELF_STAT    8
#define PROC_SELF_STATUS  9
#define PROC_SELF_STATM   10
#define PROC_SELF_MAPS    11
#define PROC_SELF_CMDLINE 12
#define PROC_SYS_CPU_ONLN 13
#define PROC_SELF_LIMITS  14
#define PROC_INOTIFY_MAX  15

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
    unsigned char is_shm;
    unsigned char is_pak;
    unsigned char proc_type;
    unsigned char open_flags;
    unsigned char nonblock;
    unsigned char cloexec;
    unsigned char dir_first;
    unsigned char dir_eof;
    int           ipc_idx;
    unsigned int  shm_size;
    unsigned int  shm_ino;
    u64           offset;
    unsigned char is_netudp;      /* AF_INET SOCK_DGRAM routed via netd; ipc_idx = net_udp slot */
    unsigned int  net_rip;        /* connected UDP peer (host order) */
    unsigned short net_rport;
    char          dir_path[260];
} SHIM_FD;

#define MAX_EPOLLS 128
#define MAX_EPOLL_ITEMS 128

typedef struct _SHIM_EPOLL_ITEM {
    int   active;
    int   fd;
    u32   events;
    u64   data;
} SHIM_EPOLL_ITEM;

typedef struct _SHIM_EPOLL {
    volatile int in_use;
    SHIM_EPOLL_ITEM items[MAX_EPOLL_ITEMS];
} SHIM_EPOLL;

static SHIM_FD    g_fds[MAX_FD];
static SHIM_EPOLL g_epolls[MAX_EPOLLS];
static volatile long g_fd_lock = 0;

static int shim_alloc_fd(int min_fd) {
    if (min_fd < 0) min_fd = 0;
    ipc_lock(&g_fd_lock);
    int fd = -1;
    for (int i = min_fd; i < MAX_FD; i++) {
        if (!g_fds[i].is_open) {
            for (unsigned int k = 0; k < sizeof(SHIM_FD); k++) {
                ((unsigned char *)&g_fds[i])[k] = 0;
            }
            g_fds[i].is_open = 1;
            fd = i;
            break;
        }
    }
    ipc_unlock(&g_fd_lock);
    return fd;
}

static void shim_free_fd(int fd) {
    if (fd < 0 || fd >= MAX_FD) return;
    ipc_lock(&g_fd_lock);
    for (unsigned int k = 0; k < sizeof(SHIM_FD); k++) {
        ((unsigned char *)&g_fds[fd])[k] = 0;
    }
    ipc_unlock(&g_fd_lock);
}
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
    unsigned char is_shm;
    unsigned char is_pak;
    unsigned char proc_type;
    unsigned char open_flags;
    unsigned char nonblock;
    int           ipc_idx;
    unsigned int  shm_size;
    unsigned int  shm_ino;
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
    SHIM_SPAWN_FD fds[MAX_SPAWN_FD];
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
    g_fds[0].is_open = 1; g_fds[0].is_console = 1; g_fds[0].open_flags = 2;
    g_fds[1].is_open = 1; g_fds[1].is_console = 1; g_fds[1].open_flags = 2;
    g_fds[2].is_open = 1; g_fds[2].is_console = 1; g_fds[2].open_flags = 2;

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
#define IOCTL_FB_ATA_READ    0x83202018UL
static HANDLE g_hFbTls = NULL;
static unsigned long g_current_tls_base = 0;

static void shim_ensure_fb_handle(void) {
    if (!g_hFbTls) {
        IO_STATUS_BLOCK iosb;
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
}

static void shim_load_pak_table(void) {
    if (!g_ipc || g_ipc->pak_loaded) return;
    shim_ensure_fb_handle();
    if (!g_hFbTls) return;
    static unsigned char s_hdr_buf[4096];
    struct {
        unsigned long Lba;
        unsigned long Count;
        unsigned long UserBuffer;
    } req = { 2, 8, (unsigned long)s_hdr_buf };
    IO_STATUS_BLOCK iosb;
    NTSTATUS st = Nt_DeviceIoControlFile(g_hFbTls, NULL, NULL, NULL, &iosb,
                                         IOCTL_FB_ATA_READ, &req, sizeof(req),
                                         &req, sizeof(req));
    if (NT_SUCCESS(st)) {
        unsigned int magic = *(unsigned int *)(s_hdr_buf + 0);
        unsigned int count = *(unsigned int *)(s_hdr_buf + 4);
        if (magic == 0x5248434EU && count <= MAX_SHIM_PAKS) {
            const SHIM_PAK_ENTRY *src = (const SHIM_PAK_ENTRY *)(s_hdr_buf + 128);
            for (unsigned int i = 0; i < count; i++) {
                g_ipc->paks[i] = src[i];
            }
            g_ipc->pak_count = count;
        }
        g_ipc->pak_loaded = 1;
    }
}

static int shim_find_pak(const char *posix_path) {
    if (!g_ipc) return -1;
    if (shim_strncmp(posix_path, "/opt/chromium/", 14) != 0) return -1;
    if (!g_ipc->pak_loaded) shim_load_pak_table();
    unsigned int cnt = g_ipc->pak_count;
    for (unsigned int i = 0; i < cnt && i < MAX_SHIM_PAKS; i++) {
        if (shim_strcmp(posix_path, g_ipc->paks[i].path) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static unsigned long shim_read_pak(int pak_idx, void *buf, unsigned long count, u64 offset) {
    if (!g_ipc || pak_idx < 0 || (unsigned int)pak_idx >= g_ipc->pak_count) return 0;
    unsigned int file_sz = g_ipc->paks[pak_idx].size;
    unsigned int base_lba = g_ipc->paks[pak_idx].start_lba;
    if (offset >= (u64)file_sz || count == 0) return 0;
    if (offset + (u64)count > (u64)file_sz) {
        count = (unsigned long)((u64)file_sz - offset);
    }
    shim_ensure_fb_handle();
    if (!g_hFbTls) return 0;

    unsigned char *dst = (unsigned char *)buf;
    unsigned long done = 0;
    unsigned char Bounce[512];

    /* Unaligned head sector */
    if ((offset & 511ULL) != 0) {
        unsigned long lba = base_lba + (unsigned long)(offset >> 9);
        unsigned int sec_off = (unsigned int)(offset & 511ULL);
        unsigned int take = 512U - sec_off;
        if (take > count) take = (unsigned int)count;
        struct { unsigned long Lba; unsigned long Count; unsigned long UserBuffer; } req = { lba, 1, (unsigned long)Bounce };
        IO_STATUS_BLOCK iosb;
        if (!NT_SUCCESS(Nt_DeviceIoControlFile(g_hFbTls, NULL, NULL, NULL, &iosb, IOCTL_FB_ATA_READ, &req, sizeof(req), &req, sizeof(req))))
            return done;
        for (unsigned int k = 0; k < take; k++) dst[done + k] = Bounce[sec_off + k];
        done += take;
        offset += take;
    }

    /* Full sectors in chunks of up to 512 sectors (256 KB) */
    while (count - done >= 512UL) {
        unsigned long rem_secs = (count - done) >> 9;
        if (rem_secs > 512UL) rem_secs = 512UL;
        unsigned long lba = base_lba + (unsigned long)(offset >> 9);
        struct { unsigned long Lba; unsigned long Count; unsigned long UserBuffer; } req = { lba, rem_secs, (unsigned long)(dst + done) };
        IO_STATUS_BLOCK iosb;
        if (!NT_SUCCESS(Nt_DeviceIoControlFile(g_hFbTls, NULL, NULL, NULL, &iosb, IOCTL_FB_ATA_READ, &req, sizeof(req), &req, sizeof(req))))
            return done;
        unsigned long bytes = rem_secs << 9;
        done += bytes;
        offset += bytes;
    }

    /* Unaligned tail sector */
    if (done < count) {
        unsigned int rem = (unsigned int)(count - done);
        unsigned long lba = base_lba + (unsigned long)(offset >> 9);
        struct { unsigned long Lba; unsigned long Count; unsigned long UserBuffer; } req = { lba, 1, (unsigned long)Bounce };
        IO_STATUS_BLOCK iosb;
        if (!NT_SUCCESS(Nt_DeviceIoControlFile(g_hFbTls, NULL, NULL, NULL, &iosb, IOCTL_FB_ATA_READ, &req, sizeof(req), &req, sizeof(req))))
            return done;
        for (unsigned int k = 0; k < rem; k++) dst[done + k] = Bounce[k];
        done += rem;
    }
    return done;
}

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
static void ring_copy_bytes(unsigned char *d, const unsigned char *s, unsigned int n) {
    while (n >= 4) { *(unsigned int *)d = *(const unsigned int *)s; d += 4; s += 4; n -= 4; }
    while (n--) *d++ = *s++;
}

/* Chunked ring copies (at most two contiguous spans per call). */
static unsigned int ring_read_locked(SHIM_IPC_RING *r, unsigned char *p, unsigned int len, int consume) {
    unsigned int n = len < r->count ? len : r->count;
    unsigned int h = r->head;
    unsigned int first = IPC_RING_SIZE - h;
    if (first > n) first = n;
    ring_copy_bytes(p, r->buf + h, first);
    if (n > first) ring_copy_bytes(p + first, r->buf, n - first);
    if (consume) {
        r->head = (h + n) % IPC_RING_SIZE;
        r->count -= n;
    }
    return n;
}

static unsigned int ring_read(SHIM_IPC_RING *r, void *dst, unsigned int len) {
    ipc_lock(&r->lock);
    unsigned int n = ring_read_locked(r, (unsigned char *)dst, len, 1);
    ipc_unlock(&r->lock);
    return n;
}

static unsigned int ring_put_locked(SHIM_IPC_RING *r, const unsigned char *p, unsigned int len) {
    unsigned int space = IPC_RING_SIZE - r->count;
    unsigned int n = len < space ? len : space;
    unsigned int t = r->tail;
    unsigned int first = IPC_RING_SIZE - t;
    if (first > n) first = n;
    ring_copy_bytes(r->buf + t, p, first);
    if (n > first) ring_copy_bytes(r->buf, p + first, n - first);
    r->tail = (t + n) % IPC_RING_SIZE;
    __sync_synchronize();
    r->count += n;
    return n;
}

static unsigned int ring_write(SHIM_IPC_RING *r, const void *src, unsigned int len) {
    ipc_lock(&r->lock);
    unsigned int n = ring_put_locked(r, (const unsigned char *)src, len);
    ipc_unlock(&r->lock);
    return n;
}

/* Append header+payload as one indivisible record, or nothing if it does not fit. */
static int ring_write_record(SHIM_IPC_RING *r, const void *hdr, unsigned int hl,
                             const void *data, unsigned int dl) {
    ipc_lock(&r->lock);
    if (IPC_RING_SIZE - r->count < hl + dl) { ipc_unlock(&r->lock); return 0; }
    ring_put_locked(r, (const unsigned char *)hdr, hl);
    ring_put_locked(r, (const unsigned char *)data, dl);
    ipc_unlock(&r->lock);
    return 1;
}

static unsigned int ring_peek(SHIM_IPC_RING *r, void *dst, unsigned int len) {
    ipc_lock(&r->lock);
    unsigned int n = ring_read_locked(r, (unsigned char *)dst, len, 0);
    ipc_unlock(&r->lock);
    return n;
}

static void shim_fd_addref(const SHIM_FD *f) {
    if (!f || !f->is_open || !g_ipc) return;
    if (f->is_netudp) {
        if (f->ipc_idx >= 0 && f->ipc_idx < MAX_NET_UDP) __sync_fetch_and_add(&g_ipc->net_udp[f->ipc_idx].refs, 1);
        return;
    }
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

/* ------------------------------------------------------------------------- */
/* AF_INET to non-local hosts: routed to the netd daemon (netd.c)            */
/* ------------------------------------------------------------------------- */
static unsigned int net_be32(const unsigned char *p) {
    return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) | ((unsigned int)p[2] << 8) | p[3];
}

static int net_ip_is_local(unsigned int ip) {
    return ip == 0 || (ip >> 24) == 127 || (g_ipc && g_ipc->net_ip && ip == g_ipc->net_ip);
}

/* Parses an AF_INET sockaddr; returns 1 and host-order ip/port on success. */
static int net_parse_sin(const void *addr, unsigned int addrlen, unsigned int *ip, unsigned int *port) {
    const unsigned char *a = (const unsigned char *)addr;
    if (!a || addrlen < 8 || *(const unsigned short *)a != 2) return 0;
    *port = ((unsigned int)a[2] << 8) | a[3];
    *ip = net_be32(a + 4);
    return 1;
}

static void net_fill_sin(void *addr, unsigned int *addrlen, unsigned int ip, unsigned int port) {
    if (!addr || !addrlen) return;
    unsigned char tmp[16];
    for (int k = 0; k < 16; k++) tmp[k] = 0;
    *(unsigned short *)tmp = 2;
    tmp[2] = (unsigned char)(port >> 8); tmp[3] = (unsigned char)port;
    tmp[4] = (unsigned char)(ip >> 24); tmp[5] = (unsigned char)(ip >> 16);
    tmp[6] = (unsigned char)(ip >> 8);  tmp[7] = (unsigned char)ip;
    unsigned int n = *addrlen < 16 ? *addrlen : 16;
    for (unsigned int k = 0; k < n; k++) ((unsigned char *)addr)[k] = tmp[k];
    *addrlen = 16;
}

static unsigned int net_alloc_port(void) {
    unsigned int p = __sync_add_and_fetch(&g_ipc->net_next_port, 1);
    return 40000 + (p % 20000);
}

static int net_is_tcp_conn(int fd) {
    return g_fds[fd].is_sock && !g_fds[fd].is_netudp && g_fds[fd].sock_state == SOCK_CONNECTED &&
           g_fds[fd].ipc_idx >= 0 && g_fds[fd].ipc_idx < MAX_IPC_CONNS &&
           g_ipc->conns[g_fds[fd].ipc_idx].listener_idx == NETD_LISTENER;
}

static int net_udp_ensure(int fd) {
    if (g_fds[fd].is_netudp) return 0;
    for (int i = 0; i < MAX_NET_UDP; i++) {
        SHIM_NET_UDP *u = &g_ipc->net_udp[i];
        if (__sync_bool_compare_and_swap(&u->in_use, 0, 2)) {
            u->rx.lock = 0; u->rx.head = u->rx.tail = u->rx.count = 0;
            u->tx.lock = 0; u->tx.head = u->tx.tail = u->tx.count = 0;
            u->refs = 1;
            u->lport = net_alloc_port();
            __sync_synchronize();
            u->in_use = 1;
            g_fds[fd].is_netudp = 1;
            g_fds[fd].ipc_idx = i;
            return 0;
        }
    }
    return -1;
}

static long net_udp_send(int fd, const void *buf, unsigned int len, unsigned int ip, unsigned int port) {
    if (!g_ipc->netd_ready) return -101; /* ENETUNREACH */
    if (len > 1472) return -90;          /* EMSGSIZE: netd does not fragment */
    if (net_udp_ensure(fd) < 0) return -105; /* ENOBUFS */
    SHIM_NET_UDP *u = &g_ipc->net_udp[g_fds[fd].ipc_idx];
    unsigned char hdr[8];
    *(unsigned int *)hdr = ip;
    *(unsigned short *)(hdr + 4) = (unsigned short)port;
    *(unsigned short *)(hdr + 6) = (unsigned short)len;
    if (!ring_write_record(&u->tx, hdr, 8, buf, len)) return -LINUX_EAGAIN;
    return (long)len;
}

static long net_udp_recv(int fd, void *buf, unsigned int len, int flags, void *addr, unsigned int *addrlen) {
    SHIM_NET_UDP *u = &g_ipc->net_udp[g_fds[fd].ipc_idx];
    int nonblock = g_fds[fd].nonblock || (flags & 0x40);
    int peek = (flags & 0x02) != 0;
    static unsigned char tmp[1500 + 8];
    for (int iter = 0;; iter++) {
        ipc_lock(&u->rx.lock);
        if (u->rx.count >= 8) {
            unsigned char hdr[8];
            ring_read_locked(&u->rx, hdr, 8, 0);
            unsigned int dl = *(unsigned short *)(hdr + 6);
            unsigned int take = dl < len ? dl : len;
            if (take > 1500) take = 1500;
            ring_read_locked(&u->rx, tmp, 8 + take, 0);
            if (!peek) {
                unsigned int left = 8 + dl;
                while (left) {
                    unsigned char junk[256];
                    unsigned int k = left < sizeof(junk) ? left : sizeof(junk);
                    ring_read_locked(&u->rx, junk, k, 1);
                    left -= k;
                }
            }
            ipc_unlock(&u->rx.lock);
            for (unsigned int k = 0; k < take; k++) ((unsigned char *)buf)[k] = tmp[8 + k];
            net_fill_sin(addr, addrlen, *(unsigned int *)hdr, *(unsigned short *)(hdr + 4));
            return (long)take;
        }
        ipc_unlock(&u->rx.lock);
        if (nonblock) return -LINUX_EAGAIN;
        shim_ipc_wait(iter);
    }
}

static long net_tcp_connect(int fd, unsigned int ip, unsigned int port) {
    if (g_fds[fd].sock_state == SOCK_CONNECTED && net_is_tcp_conn(fd)) {
        SHIM_IPC_CONN *c = &g_ipc->conns[g_fds[fd].ipc_idx];
        if (c->net_err) return -(long)c->net_err;
        return c->state == CONN_ESTABLISHED ? -106 /* EISCONN */ : -114 /* EALREADY */;
    }
    if (!g_ipc->netd_ready) return -101; /* ENETUNREACH */
    int cidx = -1;
    for (int i = 0; i < MAX_IPC_CONNS; i++) {
        if (__sync_bool_compare_and_swap(&g_ipc->conns[i].state, CONN_FREE, CONN_ALLOCATING)) { cidx = i; break; }
    }
    if (cidx < 0) return -105; /* ENOBUFS */
    SHIM_IPC_CONN *conn = &g_ipc->conns[cidx];
    conn->client_refs = 1; conn->server_refs = 1;
    conn->client_closed = 0; conn->server_closed = 0;
    conn->net_eof = 0; conn->net_err = 0;
    conn->net_rip = ip; conn->net_rport = port; conn->net_lport = net_alloc_port();
    conn->c2s.lock = 0; conn->c2s.head = 0; conn->c2s.tail = 0; conn->c2s.count = 0;
    conn->c2s.scm_head = 0; conn->c2s.scm_tail = 0; conn->c2s.scm_count = 0;
    conn->s2c.lock = 0; conn->s2c.head = 0; conn->s2c.tail = 0; conn->s2c.count = 0;
    conn->s2c.scm_head = 0; conn->s2c.scm_tail = 0; conn->s2c.scm_count = 0;
    conn->listener_idx = NETD_LISTENER;
    __sync_synchronize();
    conn->state = CONN_SYN;
    g_fds[fd].sock_state = SOCK_CONNECTED;
    g_fds[fd].is_server = 0;
    g_fds[fd].ipc_idx = cidx;
    if (g_fds[fd].nonblock) return -115; /* EINPROGRESS */
    s64 start = shim_now_ms();
    for (int w = 0; shim_now_ms() - start < 75000; w++) {
        if (conn->net_err) return -(long)conn->net_err;
        if (conn->state == CONN_ESTABLISHED) return 0;
        shim_ipc_wait(w);
    }
    return -110; /* ETIMEDOUT */
}

static long sock_read_fd(int fd, void *buf, unsigned int count, int flags_dontwait) {
    if (!g_ipc) return -LINUX_EIO;
    if (g_fds[fd].is_netudp)
        return net_udp_recv(fd, buf, count, ((flags_dontwait & ~0x02) ? 0x40 : 0) | (flags_dontwait & 0x02), NULL, NULL);
    if (g_fds[fd].sock_state == SOCK_CONNECTED && g_fds[fd].ipc_idx < 0 && g_fds[fd].sock_type == 2)
        return -LINUX_EAGAIN;
    if (g_fds[fd].sock_state != SOCK_CONNECTED || g_fds[fd].ipc_idx < 0 || g_fds[fd].ipc_idx >= MAX_IPC_CONNS)
        return -LINUX_ENOTCONN;
    if (count == 0) return 0;

    SHIM_IPC_CONN *conn = &g_ipc->conns[g_fds[fd].ipc_idx];
    SHIM_IPC_RING *rx = g_fds[fd].is_server ? &conn->c2s : &conn->s2c;
    int nonblock = g_fds[fd].nonblock || ((flags_dontwait & ~0x02) != 0);
    int peek = ((flags_dontwait & 0x02) != 0);

    for (int iter = 0;; iter++) {
        if (g_fds[fd].is_pty && !g_fds[fd].is_server && g_fds[fd].pty_pkt) {
            if (count < 2) return 0;
            unsigned char *dst = (unsigned char *)buf;
            unsigned int got = peek ? ring_peek(rx, dst + 1, count - 1) : ring_read(rx, dst + 1, count - 1);
            if (got > 0) {
                dst[0] = 0; /* TIOCPKT_DATA */
                shim_debug_print("[pty_read_pkt] ");
                shim_debug_print(g_current_exe_path);
                shim_debug_hex(" got=", (unsigned long)(got + 1));
                return (long)(got + 1);
            }
        } else {
            unsigned int got = peek ? ring_peek(rx, buf, count) : ring_read(rx, buf, count);
            if (got > 0) {
                if (g_fds[fd].is_pty) {
                    shim_debug_print("[pty_read] ");
                    shim_debug_print(g_current_exe_path);
                    shim_debug_hex(" got=", (unsigned long)got);
                }
                return (long)got;
            }
        }
        int is_net = !g_fds[fd].is_server && conn->listener_idx == NETD_LISTENER;
        if (is_net && conn->net_err) return -(long)conn->net_err;
        int peer_closed = g_fds[fd].is_server ? (conn->client_closed || conn->client_refs <= 0)
                                              : (conn->server_closed || conn->server_refs <= 0 || (is_net && conn->net_eof));
        if (peer_closed) return 0;
        if (nonblock) return -LINUX_EAGAIN;
        shim_ipc_wait(iter);
    }
}

static long sys_openat(int dirfd, const char *pathname, int flags, unsigned int mode);
static long sys_read(int fd, void *buf, unsigned int count);
static long sys_close(int fd);

static long sock_write_fd(int fd, const void *buf, unsigned int count, int flags_dontwait) {
    if (!g_ipc) return -LINUX_EIO;
    if (g_fds[fd].is_netudp) {
        if (!g_fds[fd].net_rport) return -89; /* EDESTADDRREQ */
        return net_udp_send(fd, buf, count, g_fds[fd].net_rip, g_fds[fd].net_rport);
    }
    if (g_fds[fd].sock_state == SOCK_CONNECTED && g_fds[fd].ipc_idx < 0 && g_fds[fd].sock_type == 2)
        return (long)count;
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

    if (!g_fds[fd].is_server && conn->listener_idx == 0 && count >= 4 &&
        shim_strcmp(g_current_exe_path, "/opt/chromium/chrome") == 0) {
        static int s_putimg_log = 0;
        if ((src[0] == 72 || count >= 16384) && s_putimg_log < 10) {
            s_putimg_log++;
            shim_debug_hex("[x11-chrome-req] op=", (unsigned long)src[0]);
            shim_debug_hex(" len=", (unsigned long)count);
        }
    }

    for (int iter = 0; total < count; iter++) {
        int peer_closed = g_fds[fd].is_server ? (conn->client_closed || conn->client_refs <= 0)
                                              : (conn->server_closed || conn->server_refs <= 0);
        if (peer_closed) return total > 0 ? (long)total : -LINUX_EPIPE;
        if (!g_fds[fd].is_server && conn->listener_idx == NETD_LISTENER && conn->net_err)
            return total > 0 ? (long)total : -(long)conn->net_err;
        unsigned int put = ring_write(tx, src + total, count - total);
        total += put;
        if (total >= count) break;
        if (nonblock) return total > 0 ? (long)total : -LINUX_EAGAIN;
        if (put > 0) iter = 0;
        shim_ipc_wait(iter);
    }
    return (long)total;
}

static char g_cmdline_buf[4096];
static unsigned int g_cmdline_len = 0;
static unsigned long g_interp_bias = 0x0B000000UL;
static volatile unsigned int s_next_shm_ino = 50000;

static int match_proc_pid_subpath(const char *path, const char *subpath) {
    if (shim_strncmp(path, "/proc/", 6) != 0) return 0;
    const char *p = path + 6;
    if (shim_strncmp(p, "self/", 5) == 0) {
        p += 5;
    } else if (shim_strncmp(g_current_exe_path, "/opt/chromium/", 14) == 0 && *p >= '0' && *p <= '9') {
        while (*p >= '0' && *p <= '9') p++;
        if (*p != '/') return 0;
        p++;
    } else {
        return 0;
    }
    return shim_strcmp(p, subpath) == 0;
}

static int parse_proc_fd_link(const char *path) {
    if (shim_strncmp(path, "/proc/", 6) != 0) return -1;
    const char *p = path + 6;
    if (shim_strncmp(p, "self/fd/", 8) == 0) {
        p += 8;
    } else if (*p >= '0' && *p <= '9') {
        while (*p >= '0' && *p <= '9') p++;
        if (shim_strncmp(p, "/fd/", 4) != 0) return -1;
        p += 4;
    } else {
        return -1;
    }
    if (*p < '0' || *p > '9') return -1;
    int fd_num = 0;
    while (*p >= '0' && *p <= '9') {
        fd_num = fd_num * 10 + (*p - '0');
        p++;
    }
    return (*p == '\0') ? fd_num : -1;
}

static unsigned char resolve_proc_type(const char *path) {
    if (shim_strcmp(path, "/dev/urandom") == 0 || shim_strcmp(path, "/dev/random") == 0)
        return PROC_DEV_URANDOM;
    if (shim_strcmp(path, "/dev/zero") == 0)
        return PROC_DEV_ZERO;
    if (shim_strcmp(path, "/proc/cpuinfo") == 0)
        return PROC_CPUINFO;
    if (shim_strcmp(path, "/proc/meminfo") == 0)
        return PROC_MEMINFO;
    if (shim_strcmp(path, "/proc/stat") == 0)
        return PROC_STAT;
    if (shim_strcmp(path, "/proc/version") == 0)
        return PROC_VERSION;
    if (shim_strcmp(path, "/proc/vmstat") == 0)
        return PROC_VMSTAT;
    if (shim_strcmp(path, "/sys/devices/system/cpu/online") == 0 ||
        shim_strcmp(path, "/sys/devices/system/cpu/possible") == 0 ||
        shim_strcmp(path, "/sys/devices/system/cpu/present") == 0)
        return PROC_SYS_CPU_ONLN;
    if (shim_strcmp(path, "/proc/sys/fs/inotify/max_user_watches") == 0)
        return PROC_INOTIFY_MAX;
    if (match_proc_pid_subpath(path, "stat"))
        return PROC_SELF_STAT;
    if (match_proc_pid_subpath(path, "status"))
        return PROC_SELF_STATUS;
    if (match_proc_pid_subpath(path, "statm"))
        return PROC_SELF_STATM;
    if (match_proc_pid_subpath(path, "maps"))
        return PROC_SELF_MAPS;
    if (match_proc_pid_subpath(path, "cmdline"))
        return PROC_SELF_CMDLINE;
    if (match_proc_pid_subpath(path, "limits"))
        return PROC_SELF_LIMITS;
    return PROC_NONE;
}

static long read_proc_fd(int fd, void *buf, unsigned int count, u64 *pos_ptr) {
    unsigned char pt = g_fds[fd].proc_type;
    if (pt == PROC_DEV_URANDOM) {
        unsigned char *dst = (unsigned char *)buf;
        volatile unsigned long *pTick = (volatile unsigned long *)0x7FFE0008;
        static unsigned int s_rng = 0x9E3779B9U;
        unsigned int seed = s_rng ^ (unsigned int)(*pTick);
        for (unsigned int i = 0; i < count; i++) {
            seed = seed * 1664525U + 1013904223U + (unsigned int)(*pTick);
            dst[i] = (unsigned char)((seed >> 16) ^ (seed >> 8));
        }
        s_rng = seed;
        return (long)count;
    }
    if (pt == PROC_DEV_ZERO) {
        unsigned char *dst = (unsigned char *)buf;
        for (unsigned int i = 0; i < count; i++) dst[i] = 0;
        return (long)count;
    }
    const char *text = "";
    unsigned int tlen = 0;
    if (pt == PROC_SELF_CMDLINE) {
        if (g_cmdline_len > 0) {
            text = g_cmdline_buf;
            tlen = g_cmdline_len;
        } else {
            text = g_current_exe_path;
            tlen = shim_strlen(text) + 1;
        }
    } else {
        switch (pt) {
            case PROC_CPUINFO:
                text = "processor\t: 0\n"
                       "vendor_id\t: GenuineIntel\n"
                       "cpu family\t: 6\n"
                       "model\t\t: 6\n"
                       "model name\t: QEMU Virtual CPU version 2.5+\n"
                       "stepping\t: 3\n"
                       "cpu MHz\t\t: 2000.000\n"
                       "cache size\t: 4096 KB\n"
                       "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 sse3\n\n";
                break;
            case PROC_MEMINFO:
                text = "MemTotal:        2097152 kB\n"
                       "MemFree:         1572864 kB\n"
                       "MemAvailable:    1835008 kB\n"
                       "Buffers:           65536 kB\n"
                       "Cached:           262144 kB\n"
                       "Active(anon):     131072 kB\n"
                       "Inactive(anon):    32768 kB\n"
                       "Active(file):      65536 kB\n"
                       "Inactive(file):    65536 kB\n"
                       "SwapTotal:             0 kB\n"
                       "SwapFree:              0 kB\n"
                       "Dirty:                 0 kB\n"
                       "Shmem:             16384 kB\n"
                       "SReclaimable:      32768 kB\n";
                break;
            case PROC_STAT:
                text = "cpu  1000 0 500 50000 0 0 0 0 0 0\n"
                       "cpu0 1000 0 500 50000 0 0 0 0 0 0\n"
                       "intr 10000\n"
                       "ctxt 20000\n"
                       "btime 1700000000\n"
                       "processes 64\n"
                       "procs_running 1\n"
                       "procs_blocked 0\n";
                break;
            case PROC_VERSION:
                text = "Linux version 3.16.0-nt51 (nt51@embedded) (clang 19) #1 PREEMPT Windows XP NT 5.1 x86\n";
                break;
            case PROC_VMSTAT:
                text = "nr_free_pages 393216\n"
                       "pswpin 0\n"
                       "pswpout 0\n"
                       "pgmajfault 0\n"
                       "oom_kill 0\n";
                break;
            case PROC_SELF_STAT:
                text = "100 (chrome) R 1 100 100 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 100 268435456 16384 4294967295 134512640 135000000 3221225472 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
                break;
            case PROC_SELF_STATUS:
                text = "Name:\tchrome\n"
                       "State:\tR (running)\n"
                       "Tgid:\t100\n"
                       "Pid:\t100\n"
                       "PPid:\t1\n"
                       "VmPeak:\t262144 kB\n"
                       "VmSize:\t262144 kB\n"
                       "VmRSS:\t65536 kB\n"
                       "RssAnon:\t32768 kB\n"
                       "RssFile:\t32768 kB\n"
                       "RssShmem:\t0 kB\n"
                       "VmData:\t65536 kB\n"
                       "VmStk:\t4096 kB\n"
                       "VmExe:\t131072 kB\n"
                       "VmLib:\t16384 kB\n"
                       "VmSwap:\t0 kB\n"
                       "Threads:\t1\n";
                break;
            case PROC_SELF_STATM:
                text = "65536 16384 8192 4096 0 12288 0\n";
                break;
            case PROC_SELF_MAPS:
                text = "08048000-14000000 r-xp 00000000 00:01 100 /opt/chromium/chrome\n"
                       "7f000000-7f400000 rw-p 00000000 00:00 0 [stack]\n";
                break;
            case PROC_SYS_CPU_ONLN:
                text = "0\n";
                break;
            case PROC_SELF_LIMITS:
                text = "Limit                     Soft Limit           Hard Limit           Units\n"
                       "Max open files            512                  512                  files\n";
                break;
            case PROC_INOTIFY_MAX:
                text = "8192\n";
                break;
        }
        tlen = shim_strlen(text);
    }
    u64 off = *pos_ptr;
    if (off >= (u64)tlen) return 0;
    unsigned int avail = tlen - (unsigned int)off;
    if (count > avail) count = avail;
    unsigned char *dst = (unsigned char *)buf;
    for (unsigned int i = 0; i < count; i++) dst[i] = (unsigned char)text[off + i];
    *pos_ptr = off + count;
    return (long)count;
}

static unsigned long shim_chunked_read_file(HANDLE h, void *buf, unsigned long count, s64 *opt_offset) {
    unsigned char *dst = (unsigned char *)buf;
    unsigned long total = 0;
    while (total < count) {
        unsigned long chunk = count - total;
        if (chunk > 1048576UL) chunk = 1048576UL;
        IO_STATUS_BLOCK iosb;
        iosb.Status = 0;
        iosb.Information = 0;
        LARGE_INTEGER li;
        LARGE_INTEGER *pli = NULL;
        if (opt_offset) {
            li.QuadPart = *opt_offset + (s64)total;
            pli = &li;
        }
        NTSTATUS st = Nt_ReadFile(h, NULL, NULL, NULL, &iosb, dst + total, chunk, pli, NULL);
        if (!NT_SUCCESS(st) || iosb.Information == 0) break;
        total += (unsigned long)iosb.Information;
        if (iosb.Information < chunk) break;
    }
    return total;
}

static long sys_read(int fd, void *buf, unsigned int count) {
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;
    if (g_fds[fd].proc_type != PROC_NONE) {
        return read_proc_fd(fd, buf, count, &g_fds[fd].offset);
    }
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

    if (g_fds[fd].is_shm) {
        if (g_fds[fd].offset >= g_fds[fd].shm_size) return 0;
        unsigned long rem = g_fds[fd].shm_size - (unsigned long)g_fds[fd].offset;
        if (count > rem) count = (unsigned int)rem;
        for (unsigned int i = 0; i < count; i++) ((char *)buf)[i] = 0;
        g_fds[fd].offset += count;
        return (long)count;
    }

    if (g_fds[fd].is_pak && g_ipc) {
        unsigned long got = shim_read_pak(g_fds[fd].ipc_idx, buf, count, g_fds[fd].offset);
        g_fds[fd].offset += got;
        return (long)got;
    }

    unsigned long got = shim_chunked_read_file(g_fds[fd].h, buf, count, NULL);
    g_fds[fd].offset += got;
    return (long)got;
}

static long sys_write(int fd, const void *buf, unsigned int count) {
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;
    if (g_fds[fd].is_devnull) return (long)count;

    if (g_fds[fd].is_shm) {
        g_fds[fd].offset += count;
        if (g_fds[fd].offset > g_fds[fd].shm_size) {
            g_fds[fd].shm_size = (unsigned int)g_fds[fd].offset;
        }
        return (long)count;
    }

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

    fd = shim_alloc_fd(0);
    if (fd < 0) return -LINUX_EMFILE;

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

    g_fds[fd].open_flags = (unsigned char)(flags & 3);
    g_fds[fd].nonblock = (flags & 00004000) ? 1 : 0;
    g_fds[fd].cloexec  = (flags & 02000000) ? 1 : 0;
    CanonicalizePosixPath(resolved, g_fds[fd].dir_path, sizeof(g_fds[fd].dir_path));

    int proc_src_fd = parse_proc_fd_link(resolved);
    if (proc_src_fd >= 0) {
        if (proc_src_fd >= MAX_FD || !g_fds[proc_src_fd].is_open) {
            shim_free_fd(fd);
            return -LINUX_ENOENT;
        }
        g_fds[fd] = g_fds[proc_src_fd];
        g_fds[fd].is_open = 1;
        g_fds[fd].open_flags = (unsigned char)(flags & 3);
        g_fds[fd].nonblock = (flags & 00004000) ? 1 : 0;
        g_fds[fd].cloexec  = (flags & 02000000) ? 1 : 0;
        if (g_fds[fd].h && !g_fds[fd].is_console && !g_fds[fd].is_pipe && !g_fds[fd].is_sock &&
            !g_fds[fd].is_eventfd && !g_fds[fd].is_epoll && !g_fds[fd].is_xvfb_fb && !g_fds[fd].is_devnull) {
            HANDLE dst = NULL;
            if (NT_SUCCESS(Nt_DuplicateObject((HANDLE)-1, g_fds[fd].h, (HANDLE)-1, &dst, 0, 0, 2)) && dst) {
                g_fds[fd].h = dst;
            }
        } else {
            shim_fd_addref(&g_fds[fd]);
        }
        return fd;
    }

    unsigned char pt = resolve_proc_type(resolved);
    if (pt != PROC_NONE) {
        g_fds[fd].is_open = 1;
        g_fds[fd].proc_type = pt;
        return fd;
    }

    int pak_idx = shim_find_pak(g_fds[fd].dir_path);
    if (pak_idx >= 0) {
        g_fds[fd].is_open = 1;
        g_fds[fd].is_pak  = 1;
        g_fds[fd].ipc_idx = pak_idx;
        g_fds[fd].shm_size = g_ipc->paks[pak_idx].size;
        g_fds[fd].offset  = 0;
        return fd;
    }
    if ((flags & 00200000) &&
        (shim_strcmp(g_fds[fd].dir_path, "/opt") == 0 ||
         shim_strcmp(g_fds[fd].dir_path, "/opt/chromium") == 0 ||
         shim_strcmp(g_fds[fd].dir_path, "/opt/chromium/locales") == 0)) {
        g_fds[fd].is_open = 1;
        g_fds[fd].is_dir  = 1;
        g_fds[fd].dir_eof = 1;
        return fd;
    }

    if (shim_strncmp(resolved, "/dev/shm/", 9) == 0) {
        if (!(flags & 00000100)) {
            for (int i = 0; i < MAX_FD; i++) {
                if (g_fds[i].is_open && g_fds[i].is_shm && shim_strcmp(g_fds[i].dir_path, resolved) == 0) {
                    g_fds[fd] = g_fds[i];
                    g_fds[fd].is_open = 1;
                    g_fds[fd].open_flags = (unsigned char)(flags & 3);
                    g_fds[fd].nonblock = (flags & 00004000) ? 1 : 0;
                    g_fds[fd].cloexec  = (flags & 02000000) ? 1 : 0;
                    if (g_fds[fd].h) {
                        HANDLE dst = NULL;
                        if (NT_SUCCESS(Nt_DuplicateObject((HANDLE)-1, g_fds[fd].h, (HANDLE)-1, &dst, 0, 0, 2)) && dst) {
                            g_fds[fd].h = dst;
                        }
                    }
                    return fd;
                }
            }
        }
        static unsigned int s_next_devshm_ino = 50000;
        g_fds[fd].is_open = 1;
        g_fds[fd].is_shm = 1;
        g_fds[fd].shm_ino = __sync_add_and_fetch(&s_next_devshm_ino, 1);
        CanonicalizePosixPath(resolved, g_fds[fd].dir_path, sizeof(g_fds[fd].dir_path));
        return fd;
    }

    if (shim_strcmp(resolved, "/dev/null") == 0 || shim_strcmp(resolved, "/dev/zero") == 0 ||
        shim_strcmp(resolved, "/dev/tty") == 0) {
        if (shim_strcmp(resolved, "/dev/tty") == 0 && g_fds[0].is_open && g_fds[0].is_pty) {
            g_fds[fd] = g_fds[0];
            g_fds[fd].is_open = 1;
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
        if (cidx < 0) {
            shim_free_fd(fd);
            return -LINUX_ENOMEM;
        }
        SHIM_IPC_CONN *conn = &g_ipc->conns[cidx];
        conn->listener_idx = -2;
        conn->client_refs = 1;
        conn->server_refs = 1; /* Held until slave opens or master closes */
        conn->client_closed = 0;
        conn->server_closed = 0;
        conn->c2s.lock = 0; conn->c2s.head = 0; conn->c2s.tail = 0; conn->c2s.count = 0;
        conn->c2s.scm_head = 0; conn->c2s.scm_tail = 0; conn->c2s.scm_count = 0;
        conn->s2c.lock = 0; conn->s2c.head = 0; conn->s2c.tail = 0; conn->s2c.count = 0;
        conn->s2c.scm_head = 0; conn->s2c.scm_tail = 0; conn->s2c.scm_count = 0;
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
        if (cidx < 0 || cidx >= MAX_IPC_CONNS) {
            shim_free_fd(fd);
            return -LINUX_ENOENT;
        }
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


    if (!NT_SUCCESS(status) && !(flags & 00000100)) {
        char alt_drive = (g_root_drive == 'D') ? 'C' : 'D';
        TranslatePathToNTDrive(resolved, nt_path, 260, alt_drive);
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

    if (!NT_SUCCESS(status)) {
        shim_free_fd(fd);
        return -LINUX_ENOENT;
    }

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
    ipc_lock(&g_fd_lock);
    if (fd < 0 || fd >= MAX_FD || g_fds[fd].is_open != 1) {
        ipc_unlock(&g_fd_lock);
        return -LINUX_EBADF;
    }
    SHIM_FD f = g_fds[fd];
    g_fds[fd].is_open = 2; /* Closing in progress; prevents reuse until cleanup completes */
    ipc_unlock(&g_fd_lock);

    if (f.is_pipe && g_ipc) {
        int idx = f.ipc_idx;
        if (idx >= 0 && idx < MAX_IPC_PIPES) {
            if (f.is_pipe_write) __sync_fetch_and_sub(&g_ipc->pipes[idx].write_refs, 1);
            else __sync_fetch_and_sub(&g_ipc->pipes[idx].read_refs, 1);
        }
        shim_free_fd(fd);
        return 0;
    }

    if (f.is_netudp && g_ipc) {
        int idx = f.ipc_idx;
        if (idx >= 0 && idx < MAX_NET_UDP && __sync_sub_and_fetch(&g_ipc->net_udp[idx].refs, 1) <= 0)
            g_ipc->net_udp[idx].in_use = 0;
        shim_free_fd(fd);
        return 0;
    }

    if (f.is_sock && g_ipc) {
        int idx = f.ipc_idx;
        if ((f.sock_state == SOCK_LISTENING || f.sock_state == SOCK_BOUND) && idx >= 0 && idx < MAX_IPC_LISTENERS) {
            if (__sync_sub_and_fetch(&g_ipc->listeners[idx].refs, 1) <= 0) {
                g_ipc->listeners[idx].active = 0;
            }
        } else if (f.sock_state == SOCK_CONNECTED && idx >= 0 && idx < MAX_IPC_CONNS) {
            if (f.is_server) {
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
        shim_free_fd(fd);
        return 0;
    }

    if (f.is_eventfd && g_ipc) {
        int idx = f.ipc_idx;
        if (idx >= 0 && idx < MAX_IPC_EVENTFDS) {
            if (__sync_sub_and_fetch(&g_ipc->eventfds[idx].refs, 1) <= 0)
                g_ipc->eventfds[idx].in_use = 0;
        }
        shim_free_fd(fd);
        return 0;
    }

    if (f.is_epoll) {
        int idx = f.ipc_idx;
        if (idx >= 0 && idx < MAX_EPOLLS) g_epolls[idx].in_use = 0;
        shim_free_fd(fd);
        return 0;
    }

    if (f.is_inotify) {
        shim_free_fd(fd);
        return 0;
    }

    if (!f.is_console && !f.is_devnull && !f.is_xvfb_fb && f.h) {
        Nt_Close(f.h);
    }
    shim_free_fd(fd);
    return 0;
}

static long sys_lseek(int fd, s64 offset, int whence) {
    FILE_POSITION_INFORMATION fpi;
    FILE_STANDARD_INFORMATION fsi;
    IO_STATUS_BLOCK iosb;

    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;
    if (g_fds[fd].is_console || g_fds[fd].is_pipe || g_fds[fd].is_sock) return -LINUX_ESPIPE;
    if (g_fds[fd].is_xvfb_fb || g_fds[fd].is_devnull || g_fds[fd].proc_type != PROC_NONE || g_fds[fd].is_shm || g_fds[fd].is_pak) {
        if (whence == 0) g_fds[fd].offset = (u64)offset;
        else if (whence == 1) g_fds[fd].offset += offset;
        else if (whence == 2 && (g_fds[fd].is_shm || g_fds[fd].is_pak)) g_fds[fd].offset = (u64)g_fds[fd].shm_size + offset;
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

#define MAX_VALLOC_TRACK 4096
typedef struct {
    unsigned long alloc_base;
    unsigned long base;
    unsigned long size;
    unsigned char reserved_only;
} SHIM_VALLOC_ENTRY;
static SHIM_VALLOC_ENTRY g_valloc_track[MAX_VALLOC_TRACK];

static void shim_track_valloc(unsigned long base, unsigned long size, unsigned char reserved_only) {
    if (!base || !size) return;
    for (int i = 0; i < MAX_VALLOC_TRACK; i++) {
        if (g_valloc_track[i].alloc_base == base || g_valloc_track[i].base == base) {
            g_valloc_track[i].alloc_base = base;
            g_valloc_track[i].base = base;
            g_valloc_track[i].size = size;
            g_valloc_track[i].reserved_only = reserved_only;
            return;
        }
    }
    for (int i = 0; i < MAX_VALLOC_TRACK; i++) {
        if (g_valloc_track[i].base == 0) {
            g_valloc_track[i].alloc_base = base;
            g_valloc_track[i].base = base;
            g_valloc_track[i].size = size;
            g_valloc_track[i].reserved_only = reserved_only;
            return;
        }
    }
}

static void shim_mark_valloc_committed(unsigned long start, unsigned long end) {
    for (int i = 0; i < MAX_VALLOC_TRACK; i++) {
        unsigned long vbase = g_valloc_track[i].base;
        unsigned long vsize = g_valloc_track[i].size;
        if (!vbase || !vsize) continue;
        if (start < vbase + vsize && end > vbase) {
            g_valloc_track[i].reserved_only = 0;
        }
    }
}

static NTSTATUS shim_alloc_aligned_vm(unsigned long size, unsigned long align, unsigned long alloc_type, unsigned long protect, void **out_base) {
    if (align <= 0x10000UL || size == 0) return -1;
    unsigned long try_sz = size + align - 0x10000UL;
    void *tmp = NULL;
    NTSTATUS st = Nt_AllocateVirtualMemory((HANDLE)-1, &tmp, 0, &try_sz, MEM_RESERVE, PAGE_NOACCESS);
    if (!NT_SUCCESS(st) || !tmp) return -1;
    unsigned long aligned = ((unsigned long)tmp + align - 1UL) & ~(align - 1UL);
    unsigned long rel_sz = 0;
    Nt_FreeVirtualMemory((HANDLE)-1, &tmp, &rel_sz, 0x8000 /* MEM_RELEASE */);
    void *b = (void *)aligned;
    unsigned long sz = size;
    st = Nt_AllocateVirtualMemory((HANDLE)-1, &b, 0, &sz, alloc_type, protect);
    if (NT_SUCCESS(st) && b) {
        *out_base = b;
        return st;
    }
    return -1;
}

static NTSTATUS shim_commit_and_protect(unsigned long start, unsigned long end) {
    if (end <= start) return 0;
    shim_mark_valloc_committed(start, end);
    void *b = (void *)start;
    unsigned long sz = end - start;
    unsigned long old_prot = 0;
    NTSTATUS st = Nt_AllocateVirtualMemory((HANDLE)-1, &b, 0, &sz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(st)) {
        b = (void *)start; sz = end - start;
        Nt_ProtectVirtualMemory((HANDLE)-1, &b, &sz, PAGE_EXECUTE_READWRITE, &old_prot);
        return st;
    }
    b = (void *)start; sz = end - start;
    st = Nt_ProtectVirtualMemory((HANDLE)-1, &b, &sz, PAGE_EXECUTE_READWRITE, &old_prot);
    if (NT_SUCCESS(st)) return st;

    /* Fallback: page-by-page across adjacent VADs or section views */
    NTSTATUS last_st = st;
    for (unsigned long pg = start; pg < end; pg += 4096UL) {
        void *pb = (void *)pg;
        unsigned long ps = 4096UL;
        NTSTATUS pst = Nt_AllocateVirtualMemory((HANDLE)-1, &pb, 0, &ps, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        pb = (void *)pg; ps = 4096UL;
        NTSTATUS pst2 = Nt_ProtectVirtualMemory((HANDLE)-1, &pb, &ps, PAGE_EXECUTE_READWRITE, &old_prot);
        if (NT_SUCCESS(pst) || NT_SUCCESS(pst2)) last_st = 0;
    }
    return last_st;
}

static void shim_zero_committed_pages(unsigned long start, unsigned long end) {
    if (end <= start) return;
    unsigned long old_prot = 0;
    void *b = (void *)start;
    unsigned long sz = end - start;
    if (NT_SUCCESS(Nt_ProtectVirtualMemory((HANDLE)-1, &b, &sz, PAGE_EXECUTE_READWRITE, &old_prot))) {
        for (unsigned long p = start; p < end; p += 4UL) {
            *(unsigned int *)p = 0;
        }
        return;
    }
    for (unsigned long blk = start; blk < end; blk += 65536UL) {
        unsigned long blk_end = (blk + 65536UL <= end) ? (blk + 65536UL) : end;
        void *bb = (void *)blk;
        unsigned long bsz = blk_end - blk;
        if (NT_SUCCESS(Nt_ProtectVirtualMemory((HANDLE)-1, &bb, &bsz, PAGE_EXECUTE_READWRITE, &old_prot))) {
            for (unsigned long p = blk; p < blk_end; p += 4UL) {
                *(unsigned int *)p = 0;
            }
            continue;
        }
        for (unsigned long pg = blk; pg < blk_end; pg += 4096UL) {
            void *pb = (void *)pg;
            unsigned long ps = 4096UL;
            if (NT_SUCCESS(Nt_ProtectVirtualMemory((HANDLE)-1, &pb, &ps, PAGE_EXECUTE_READWRITE, &old_prot))) {
                for (unsigned long p = pg; p < pg + 4096UL; p += 4UL) {
                    *(unsigned int *)p = 0;
                }
            }
        }
    }
}

static void shim_decommit_or_zero_pages(unsigned long start, unsigned long end) {
    if (end <= start) return;
    void *b = (void *)start;
    unsigned long sz = end - start;
    if (NT_SUCCESS(Nt_FreeVirtualMemory((HANDLE)-1, &b, &sz, MEM_DECOMMIT))) {
        return;
    }
    shim_zero_committed_pages(start, end);
}

/* Summarize this process's NT address space when a mapping fails, to tell
 * exhausted or fragmented virtual address space from a commit shortage. */
static void shim_debug_vm_summary(void) {
    struct { unsigned long base, alloc_base, alloc_protect, size, state, protect, type; } mbi;
    unsigned long addr = 0x10000UL, free_total = 0, free_max = 0, commit = 0, reserve = 0;
    unsigned long image = 0, mapped = 0, small_allocs = 0, allocs = 0, last_alloc = 0;
    while (addr < 0x7FFF0000UL) {
        unsigned long ret_len = 0;
        unsigned long a[6] = { (unsigned long)(HANDLE)-1, addr, 0 /* MemoryBasicInformation */,
                               (unsigned long)&mbi, sizeof(mbi), (unsigned long)&ret_len };
        if (!NT_SUCCESS((NTSTATUS)DoNtSyscall(178 /* NtQueryVirtualMemory */, a, 6)) || !mbi.size) break;
        if (mbi.state == 0x10000 /* MEM_FREE */) {
            free_total += mbi.size;
            if (mbi.size > free_max) free_max = mbi.size;
        } else if (mbi.type == 0x1000000 /* MEM_IMAGE */) {
            image += mbi.size;
        } else if (mbi.type == 0x40000 /* MEM_MAPPED */) {
            mapped += mbi.size;
        } else {
            if (mbi.state == 0x1000 /* MEM_COMMIT */) commit += mbi.size; else reserve += mbi.size;
            if (mbi.alloc_base != last_alloc) {
                allocs++;
                last_alloc = mbi.alloc_base;
                if (mbi.size <= 0x10000UL) small_allocs++;
            }
        }
        if (mbi.base + mbi.size <= addr) break;
        addr = mbi.base + mbi.size;
    }
    shim_debug_hex("[vm] free_kb=", free_total >> 10);
    shim_debug_hex("[vm] largest_free_kb=", free_max >> 10);
    shim_debug_hex("[vm] private_commit_kb=", commit >> 10);
    shim_debug_hex("[vm] private_reserve_kb=", reserve >> 10);
    shim_debug_hex("[vm] mapped_kb=", mapped >> 10);
    shim_debug_hex("[vm] image_kb=", image >> 10);
    shim_debug_hex("[vm] private_allocations=", allocs);
    shim_debug_hex("[vm] small_private_allocations=", small_allocs);
}

static long sys_mmap2(void *addr, unsigned long len, int prot, int flags, int fd, unsigned long pgoff) {
    if (len == 0) return -LINUX_EINVAL;
    unsigned long size = (len + 4095UL) & ~4095UL;

    /* Anonymous non-fixed PROT_NONE mappings are address-space reservations (V8 cages,
     * PartitionAlloc super pages, thread guard regions). Reserve them without
     * committing, otherwise Chromium's multi-GiB reservations exhaust the NT
     * commit limit and starve every other process. mprotect() commits later. */
    if (prot == 0 && (flags & 0x20 /* MAP_ANONYMOUS */) && !(flags & 0x10 /* MAP_FIXED */)) {
        void *b = NULL;
        unsigned long sz = size;
        NTSTATUS st = -1;
        if (addr && ((unsigned long)addr & 0xFFFFUL) == 0 &&
            (unsigned long)addr >= 0x00100000UL && (unsigned long)addr < 0x70000000UL) {
            b = addr;
            st = Nt_AllocateVirtualMemory((HANDLE)-1, &b, 0, &sz, MEM_RESERVE, PAGE_NOACCESS);
            if (!NT_SUCCESS(st) || !b) {
                unsigned long align = (unsigned long)addr & -(unsigned long)addr;
                if (align > 0x400000UL) align = 0x400000UL;
                if (align > 0x10000UL) {
                    st = shim_alloc_aligned_vm(size, align, MEM_RESERVE, PAGE_NOACCESS, &b);
                }
            }
        }
        if (!NT_SUCCESS(st) || !b) {
            b = NULL; sz = size;
            st = Nt_AllocateVirtualMemory((HANDLE)-1, &b, 0, &sz, MEM_RESERVE, PAGE_NOACCESS);
        }
        if (NT_SUCCESS(st) && b) {
            shim_track_valloc((unsigned long)b, size, 1);
            return (long)b;
        }
    }

    /* MAP_FIXED PROT_NONE (DecommitAndZeroSystemPagesInternal): decommit or zero
     * already-committed pages without committing uncommitted MEM_RESERVE pages. */
    if (prot == 0 && (flags & 0x20 /* MAP_ANONYMOUS */) && (flags & 0x10 /* MAP_FIXED */) && addr) {
        unsigned long page_start = (unsigned long)addr & ~4095UL;
        unsigned long page_end   = ((unsigned long)addr + len + 4095UL) & ~4095UL;
        shim_decommit_or_zero_pages(page_start, page_end);
        return (long)addr;
    }

    /* Shared Xvfb screen0 framebuffer mapping */
    if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && g_fds[fd].is_xvfb_fb && g_ipc) {
        g_ipc->xvfb_fb_size = (unsigned int)len;
        g_ipc->graphics_active = 1;
        shim_debug_print("[mmap xvfb_fb] ");
        shim_debug_print(g_current_exe_path);
        shim_debug_print("\n");
        return (long)g_ipc->xvfb_fb;
    }

    /* Shared memory mapping (memfd_create / /dev/shm) backed by NT Section Object */
    if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && g_fds[fd].is_shm) {
        if (!g_fds[fd].h) {
            unsigned long sec_sz = g_fds[fd].shm_size ? g_fds[fd].shm_size : size;
            if (sec_sz < size) sec_sz = size;
            g_fds[fd].h = OpenOrCreateShmSection(g_fds[fd].shm_ino, sec_sz);
            if (g_fds[fd].h && !g_fds[fd].shm_size) g_fds[fd].shm_size = (unsigned int)((sec_sz + 4095UL) & ~4095UL);
        }
        if (g_fds[fd].h) {
            void *view_base = (flags & 0x10) ? addr : NULL;
            LARGE_INTEGER sec_off;
            sec_off.QuadPart = (s64)pgoff * 4096LL;
            unsigned long view_size = size;
            if (NT_SUCCESS(Nt_MapViewOfSection(g_fds[fd].h, (HANDLE)-1, &view_base, 0,
                                               size, &sec_off, &view_size, 1 /* ViewShare */, 0,
                                               PAGE_EXECUTE_READWRITE)) && view_base) {
                return (long)view_base;
            }
        }
    }

    void *base = addr;
    NTSTATUS status = -1;

    if (flags & 0x10) { /* MAP_FIXED */
        unsigned long page_start = (unsigned long)addr & ~4095UL;
        unsigned long page_end   = ((unsigned long)addr + len + 4095UL) & ~4095UL;
        status = shim_commit_and_protect(page_start, page_end);
        if (!NT_SUCCESS(status)) {
            void *res_base = (void *)((unsigned long)addr & ~0xFFFFUL);
            unsigned long res_size = (((unsigned long)addr + len + 0xFFFFUL) & ~0xFFFFUL) - (unsigned long)res_base;
            status = Nt_AllocateVirtualMemory((HANDLE)-1, &res_base, 0, &res_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (NT_SUCCESS(status) && res_base) {
                shim_track_valloc((unsigned long)res_base, res_size, 0);
            }
        }
        base = addr;
    } else {
        unsigned long alloc_size = size;
        if (addr && ((unsigned long)addr & 0xFFFFUL) == 0 &&
            (unsigned long)addr >= 0x00100000UL && (unsigned long)addr < 0x70000000UL) {
            base = addr;
            status = Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &alloc_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!NT_SUCCESS(status) || !base) {
                unsigned long align = (unsigned long)addr & -(unsigned long)addr;
                if (align > 0x400000UL) align = 0x400000UL;
                if (align > 0x10000UL) {
                    status = shim_alloc_aligned_vm(size, align, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, &base);
                }
            }
        }
        if (!NT_SUCCESS(status) || !base) {
            base = NULL;
            alloc_size = size;
            status = Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &alloc_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        }
        if (NT_SUCCESS(status) && base) {
            shim_track_valloc((unsigned long)base, size, 0);
        }
    }

    if (!NT_SUCCESS(status) || !base) {
        shim_debug_print("[mmap FAILED] ");
        shim_debug_print(g_current_exe_path);
        shim_debug_hex(" len=", size);
        shim_debug_hex(" prot=", (unsigned long)prot);
        shim_debug_hex(" flags=", (unsigned long)flags);
        shim_debug_hex(" st=", (unsigned long)status);
        static int vm_summaries = 0;
        if (vm_summaries < 2) { vm_summaries++; shim_debug_vm_summary(); }
        return -LINUX_ENOMEM;
    }

    /* Zero memory when reusing MAP_FIXED pages so .bss tails and recommitted spans are clean */
    if (flags & 0x10) {
        unsigned long zstart = (unsigned long)base & ~4095UL;
        unsigned long zend   = ((unsigned long)base + len + 4095UL) & ~4095UL;
        for (unsigned long k = zstart; k < zend; k++) {
            *(unsigned char *)k = 0;
        }
    }

    if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && !(flags & 0x20) && pgoff == 0 &&
        shim_strncmp(g_current_exe_path, "/opt/chromium/", 14) == 0 && size >= 65536) {
        /* Library load map for diagnosing Chromium (maps EIPs to DSOs). */
        shim_debug_print("[mmap-file] ");
        shim_debug_print(g_fds[fd].dir_path);
        shim_debug_hex(" base=", (unsigned long)base);
        shim_debug_hex(" len=", size);
    }
    if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && !(flags & 0x20)) {
        s64 file_off = (s64)pgoff * 4096LL;
        unsigned long read_len = len;
        if (g_fds[fd].is_pak && g_ipc) {
            if (pgoff == 0 && !(flags & 0x10) && read_len > 65536UL) {
                shim_read_pak(g_fds[fd].ipc_idx, base, 4096UL, 0);
                const Elf32_Ehdr *eh = (const Elf32_Ehdr *)base;
                if (eh->e_ident[0] == 0x7F && eh->e_ident[1] == 'E' &&
                    eh->e_ident[2] == 'L'  && eh->e_ident[3] == 'F' &&
                    eh->e_phoff > 0 && eh->e_phnum > 0 &&
                    eh->e_phoff + eh->e_phnum * sizeof(Elf32_Phdr) <= 4096UL) {
                    const Elf32_Phdr *ph = (const Elf32_Phdr *)((const unsigned char *)base + eh->e_phoff);
                    for (unsigned int i = 0; i < eh->e_phnum; i++) {
                        if (ph[i].p_type == 1 /* PT_LOAD */ && ph[i].p_offset == 0 && ph[i].p_filesz > 0) {
                            unsigned long seg0 = (ph[i].p_filesz + 4095UL) & ~4095UL;
                            if (seg0 < read_len) read_len = seg0;
                            break;
                        }
                    }
                }
                if (read_len > 4096UL) {
                    shim_read_pak(g_fds[fd].ipc_idx, (unsigned char *)base + 4096UL, read_len - 4096UL, 4096ULL);
                }
            } else {
                shim_read_pak(g_fds[fd].ipc_idx, base, read_len, (u64)file_off);
            }
        } else if (g_fds[fd].h) {
            shim_chunked_read_file(g_fds[fd].h, base, read_len, &file_off);
        }
    }

    return (long)base;
}

static long sys_mprotect(void *addr, unsigned long len, int prot) {
    if (len == 0) return 0;
    unsigned long start = (unsigned long)addr & ~4095UL;
    unsigned long end   = ((unsigned long)addr + len + 4095UL) & ~4095UL;
    if (prot == 0) {
        shim_decommit_or_zero_pages(start, end);
        return 0;
    }
    shim_commit_and_protect(start, end);
    return 0;
}

static void shim_clear_unmapped_tls(unsigned long start, unsigned long end);

static long sys_munmap(void *addr, unsigned long len) {
    if (!addr || len == 0) return 0;
    unsigned long start = (unsigned long)addr & ~4095UL;
    unsigned long end   = ((unsigned long)addr + len + 4095UL) & ~4095UL;
    if (start >= 0x10000UL && end > start) {
        unsigned long sz = end - start;
        shim_clear_unmapped_tls(start, end);

        /* Check tracked VAD reservations so partial TrimMapping munmap releases or decommits properly */
        for (int i = 0; i < MAX_VALLOC_TRACK; i++) {
            unsigned long vbase = g_valloc_track[i].base;
            unsigned long vsize = g_valloc_track[i].size;
            if (!vbase || !vsize) continue;
            if (start == vbase) {
                if (sz >= vsize) {
                    void *rel_base = (void *)g_valloc_track[i].alloc_base;
                    unsigned long rel_sz = 0;
                    g_valloc_track[i].alloc_base = 0;
                    g_valloc_track[i].base = 0;
                    g_valloc_track[i].size = 0;
                    g_valloc_track[i].reserved_only = 0;
                    if (NT_SUCCESS(Nt_FreeVirtualMemory((HANDLE)-1, &rel_base, &rel_sz, 0x8000 /* MEM_RELEASE */))) {
                        return 0;
                    }
                } else {
                    /* Leading slack trim (PartitionAlloc::TrimMapping pre_slack) */
                    unsigned long new_sz = vsize - sz;
                    if (g_valloc_track[i].reserved_only && g_valloc_track[i].alloc_base == vbase && (end & 0xFFFFUL) == 0) {
                        void *rel_base = (void *)vbase;
                        unsigned long rel_sz = 0;
                        if (NT_SUCCESS(Nt_FreeVirtualMemory((HANDLE)-1, &rel_base, &rel_sz, 0x8000 /* MEM_RELEASE */))) {
                            void *nb = (void *)end;
                            unsigned long nsz = new_sz;
                            Nt_AllocateVirtualMemory((HANDLE)-1, &nb, 0, &nsz, MEM_RESERVE, PAGE_NOACCESS);
                            g_valloc_track[i].alloc_base = end;
                            g_valloc_track[i].base = end;
                            g_valloc_track[i].size = new_sz;
                            return 0;
                        }
                    }
                    g_valloc_track[i].base = end;
                    g_valloc_track[i].size = new_sz;
                    void *base = (void *)start;
                    Nt_FreeVirtualMemory((HANDLE)-1, &base, &sz, MEM_DECOMMIT);
                    return 0;
                }
            } else if (start > vbase && end <= vbase + vsize) {
                /* Trailing/interior slack trim (PartitionAlloc::TrimMapping post_slack) */
                if (end == vbase + vsize) {
                    unsigned long keep_sz = start - vbase;
                    if (g_valloc_track[i].reserved_only && g_valloc_track[i].alloc_base == vbase) {
                        void *rel_base = (void *)vbase;
                        unsigned long rel_sz = 0;
                        if (NT_SUCCESS(Nt_FreeVirtualMemory((HANDLE)-1, &rel_base, &rel_sz, 0x8000 /* MEM_RELEASE */))) {
                            void *nb = (void *)vbase;
                            unsigned long nsz = keep_sz;
                            Nt_AllocateVirtualMemory((HANDLE)-1, &nb, 0, &nsz, MEM_RESERVE, PAGE_NOACCESS);
                            g_valloc_track[i].size = keep_sz;
                            return 0;
                        }
                    }
                    g_valloc_track[i].size = keep_sz;
                }
                void *base = (void *)start;
                Nt_FreeVirtualMemory((HANDLE)-1, &base, &sz, MEM_DECOMMIT);
                return 0;
            }
        }

        if ((start & 0xFFFFUL) == 0) {
            if (NT_SUCCESS(Nt_UnmapViewOfSection((HANDLE)-1, (void *)start))) {
                return 0;
            }
            void *rel_base = (void *)start;
            unsigned long rel_sz = 0;
            if (NT_SUCCESS(Nt_FreeVirtualMemory((HANDLE)-1, &rel_base, &rel_sz, 0x8000 /* MEM_RELEASE */))) {
                return 0;
            }
        }
        void *base = (void *)start;
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
        int sfd = shim_alloc_fd(3);
        if (sfd < 0) return -LINUX_EMFILE;
        SHIM_IPC_CONN *conn = &g_ipc->conns[cidx];
        if (conn->listener_idx == -2) {
            conn->listener_idx = -3; /* First slave open claims initial server_ref */
        } else {
            __sync_fetch_and_add(&conn->server_refs, 1);
        }
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

    __attribute__((aligned(4))) u8 dir_buffer[4096];

    while (out_bytes < count) {
        status = Nt_QueryDirectoryFile(
            g_fds[fd].h, NULL, NULL, NULL, &iosb,
            dir_buffer, sizeof(dir_buffer),
            FileBothDirectoryInformation, 0, NULL, g_fds[fd].dir_first
        );
        g_fds[fd].dir_first = 0;
        if (!NT_SUCCESS(status) || iosb.Information == 0) {
            g_fds[fd].dir_eof = 1;
            break;
        }

        FILE_BOTH_DIR_INFORMATION *info = (FILE_BOTH_DIR_INFORMATION *)dir_buffer;
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
        if (iosb.Information < sizeof(dir_buffer)) break;
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
    if (g_fds[fd].is_shm || g_fds[fd].is_pak) {
        st->st_mode = g_fds[fd].is_pak ? 0100755 : 0100666;
        if (!g_fds[fd].is_pak) {
            st->st_ino = g_fds[fd].shm_ino ? (u64)g_fds[fd].shm_ino : (u64)(fd + 50000);
        }
        st->st_size = (s64)g_fds[fd].shm_size;
        st->st_blocks = (st->st_size + 511) / 512;
        return 0;
    }
    if (g_fds[fd].proc_type != PROC_NONE) {
        st->st_mode = 0100444;
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

    {
        char can_p[260];
        CanonicalizePosixPath(path, can_p, sizeof(can_p));
        int pfd = parse_proc_fd_link(can_p);
        if (pfd >= 0) return sys_fstat64_fd(pfd, st);
        int pak_idx = shim_find_pak(can_p);
        if (pak_idx >= 0) {
            st->st_dev = 1; st->st_ino = ino; st->st_mode = 0100755; st->st_nlink = 1;
            st->st_size = (s64)g_ipc->paks[pak_idx].size;
            st->st_blksize = 4096;
            st->st_blocks = (st->st_size + 511) / 512;
            st->st_atim.tv_sec = 1700000000; st->st_mtim.tv_sec = 1700000000; st->st_ctim.tv_sec = 1700000000;
            return 0;
        }
        if (resolve_proc_type(can_p) != PROC_NONE) {
            st->st_dev = 1; st->st_ino = ino; st->st_mode = 0100444; st->st_nlink = 1;
            st->st_blksize = 4096;
            return 0;
        }
    }

    if (shim_strcmp(path, "/dev/null") == 0 || shim_strcmp(path, "/dev/zero") == 0 ||
        shim_strcmp(path, "/dev/urandom") == 0 || shim_strcmp(path, "/dev/random") == 0 ||
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
    if (!NT_SUCCESS(status)) {
        char alt_drive = (g_root_drive == 'D') ? 'C' : 'D';
        TranslatePathToNTDrive(path, nt_path, 260, alt_drive);
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
            shim_strcmp(can, "/dev/shm") == 0 ||
            shim_strcmp(can, "/proc") == 0 ||
            shim_strcmp(can, "/proc/self") == 0 ||
            shim_strcmp(can, "/proc/self/fd") == 0 ||
            shim_strcmp(can, "/sys") == 0 ||
            shim_strcmp(can, "/sys/devices") == 0 ||
            shim_strcmp(can, "/sys/devices/system") == 0 ||
            shim_strcmp(can, "/sys/devices/system/cpu") == 0 ||
            shim_strcmp(can, "/var") == 0 ||
            shim_strcmp(can, "/var/tmp") == 0 ||
            shim_strcmp(can, "/root") == 0 ||
            shim_strcmp(can, "/opt") == 0 ||
            shim_strcmp(can, "/opt/chromium") == 0 ||
            shim_strcmp(can, "/opt/chromium/locales") == 0) {
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
    {
        char can_m[260];
        CanonicalizePosixPathNoSymlink(path, can_m, sizeof(can_m));
        if (shim_strncmp(can_m, "/tmp/org.chromium.", 18) == 0 ||
            shim_strncmp(can_m, "/tmp/scoped_dir", 15) == 0 ||
            shim_strncmp(can_m, "/tmp/.org.chromium.", 19) == 0) {
            st->st_mode = fsi.Directory ? 0040700 : 0100700;
        } else {
            st->st_mode = fsi.Directory ? 0040755 : 0100755;
        }
    }
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

static long sys_symlink(const char *target, const char *linkpath) {
    if (!target || !linkpath || !target[0] || !linkpath[0]) return -LINUX_EINVAL;
    char can[260];
    CanonicalizePosixPathNoSymlink(linkpath, can, sizeof(can));
    for (int i = 0; i < g_num_symlinks; i++) {
        if (shim_strcmp(can, g_symlinks[i].link) == 0) {
            shim_strcpy(g_symlinks[i].target, target, sizeof(g_symlinks[i].target));
            return 0;
        }
    }
    if (g_num_symlinks < MAX_SYMLINKS) {
        shim_strcpy(g_symlinks[g_num_symlinks].link, can, sizeof(g_symlinks[g_num_symlinks].link));
        shim_strcpy(g_symlinks[g_num_symlinks].target, target, sizeof(g_symlinks[g_num_symlinks].target));
        g_num_symlinks++;
    }
    return 0;
}

static long sys_readlink(const char *path, char *buf, unsigned int bufsiz) {
    if (!path || !buf || bufsiz == 0) return -LINUX_EINVAL;
    char can[260];
    CanonicalizePosixPathNoSymlink(path, can, sizeof(can));
    int is_proc_exe = (shim_strcmp(can, "/proc/self/exe") == 0);
    if (!is_proc_exe && shim_strncmp(can, "/proc/", 6) == 0) {
        const char *p = can + 6;
        while (*p >= '0' && *p <= '9') p++;
        if (shim_strcmp(p, "/exe") == 0) is_proc_exe = 1;
    }
    if (is_proc_exe) {
        unsigned int len = shim_strlen(g_current_exe_path);
        if (len > bufsiz) len = bufsiz;
        for (unsigned int i = 0; i < len; i++) buf[i] = g_current_exe_path[i];
        return (long)len;
    }
    int pfd = parse_proc_fd_link(can);
    if (pfd >= 0 && pfd < MAX_FD && g_fds[pfd].is_open) {
        const char *target = g_fds[pfd].dir_path[0] ? g_fds[pfd].dir_path : "/dev/null";
        unsigned int len = shim_strlen(target);
        if (len > bufsiz) len = bufsiz;
        for (unsigned int i = 0; i < len; i++) buf[i] = target[i];
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
    struct linux_stat64 st;
    if (sys_stat64(can, &st) < 0) return -LINUX_ENOENT;
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
    if (pathname && pathname[0]) {
        char can[260];
        CanonicalizePosixPathNoSymlink(pathname, can, sizeof(can));
        for (int i = 0; i < g_num_symlinks; i++) {
            if (shim_strcmp(can, g_symlinks[i].link) == 0) {
                for (int k = i; k + 1 < g_num_symlinks; k++) {
                    g_symlinks[k] = g_symlinks[k + 1];
                }
                g_num_symlinks--;
                return 0;
            }
        }
    }
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
    if (!NT_SUCCESS(st)) {
        st = Nt_OpenFile(&h, DELETE | SYNCHRONIZE, &oa, &iosb,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    }
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
    if (min_fd >= 256) min_fd = 64;
    if (min_fd < 0 || min_fd >= MAX_FD) return -LINUX_EINVAL;
    int newfd = shim_alloc_fd(min_fd);
    if (newfd < 0) return -LINUX_EMFILE;
    g_fds[newfd] = g_fds[oldfd];
    g_fds[newfd].is_open = 1;
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
    ipc_lock(&g_fd_lock);
    g_fds[newfd] = g_fds[oldfd];
    g_fds[newfd].is_open = 1;
    g_fds[newfd].cloexec = (flags & 02000000) ? 1 : 0;
    ipc_unlock(&g_fd_lock);
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
            return (long)(g_fds[fd].open_flags & 3) | (g_fds[fd].nonblock ? 00004000 : 0);
        case LINUX_F_SETFL:
            g_fds[fd].nonblock = (arg & 00004000) ? 1 : 0;
            return 0;
        case 5:  /* F_GETLK */
        case 12: /* F_GETLK64 */
            if (arg) *(short *)arg = 2; /* F_UNLCK */
            return 0;
        case 6:  /* F_SETLK */
        case 7:  /* F_SETLKW */
        case 13: /* F_SETLK64 */
        case 14: /* F_SETLKW64 */
        case 1033: /* F_ADD_SEALS */
            return 0;
        case 1034: /* F_GET_SEALS */
            return 7; /* F_SEAL_SEAL(1) | F_SEAL_SHRINK(2) | F_SEAL_GROW(4) */
        default:
            return 0;
    }
}

static long sys_pipe2(int *pipefd, int flags) {
    if (!pipefd || !g_ipc) return -LINUX_EFAULT;
    int rfd = shim_alloc_fd(3);
    if (rfd < 0) return -LINUX_EMFILE;
    int wfd = shim_alloc_fd(3);
    if (wfd < 0) {
        shim_free_fd(rfd);
        return -LINUX_EMFILE;
    }

    int pidx = -1;
    for (int i = 0; i < MAX_IPC_PIPES; i++) {
        if (g_ipc->pipes[i].read_refs <= 0 && g_ipc->pipes[i].write_refs <= 0) {
            if (__sync_bool_compare_and_swap(&g_ipc->pipes[i].read_refs, 0, 1)) {
                pidx = i;
                break;
            }
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
    /* Validate flags: only EFD_SEMAPHORE(1) | EFD_NONBLOCK(04000) | EFD_CLOEXEC(02000000) are valid */
    if ((unsigned int)flags & ~(1U | 00004000U | 02000000U)) {
        return -LINUX_EINVAL;
    }
    int fd = shim_alloc_fd(3);
    if (fd < 0) return -LINUX_EMFILE;

    int eidx = -1;
    for (int i = 0; i < MAX_IPC_EVENTFDS; i++) {
        if (__sync_bool_compare_and_swap(&g_ipc->eventfds[i].in_use, 0, 1)) {
            eidx = i;
            break;
        }
    }
    if (eidx < 0) eidx = 0;

    g_ipc->eventfds[eidx].in_use = 1;
    g_ipc->eventfds[eidx].refs = 1;
    g_ipc->eventfds[eidx].counter = initval;

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

struct linux_cmsghdr {
    unsigned int cmsg_len;
    int          cmsg_level;
    int          cmsg_type;
};

static long get_current_pid(void);

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
    /* No IPv6 stack: report it so resolvers and Chromium use IPv4 only. */
    if (domain == 10 /* AF_INET6 */) return -97; /* EAFNOSUPPORT */
    int fd = shim_alloc_fd(3);
    if (fd < 0) return -LINUX_EMFILE;

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
    conn->net_eof = 0; conn->net_err = 0;
    conn->client_refs = 1;
    conn->server_refs = 1;
    conn->client_closed = 0;
    conn->server_closed = 0;
    conn->c2s.lock = 0; conn->c2s.head = 0; conn->c2s.tail = 0; conn->c2s.count = 0;
    conn->c2s.scm_head = 0; conn->c2s.scm_tail = 0; conn->c2s.scm_count = 0;
    conn->s2c.lock = 0; conn->s2c.head = 0; conn->s2c.tail = 0; conn->s2c.count = 0;
    conn->s2c.scm_head = 0; conn->s2c.scm_tail = 0; conn->s2c.scm_count = 0;

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
    /* UDP sockets bind implicitly to an ephemeral port in netd. */
    if (g_fds[fd].sock_domain == 2 && g_fds[fd].sock_type == 2) return 0;
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
    {
        unsigned int rip, rport;
        if (g_fds[fd].sock_domain == 2 && net_parse_sin(addr, addrlen, &rip, &rport) && !net_ip_is_local(rip)) {
            if (g_fds[fd].sock_type == 2) { /* UDP: just records the peer */
                if (net_udp_ensure(fd) < 0) return -105; /* ENOBUFS */
                g_fds[fd].net_rip = rip;
                g_fds[fd].net_rport = (unsigned short)rport;
                g_fds[fd].sock_state = SOCK_CONNECTED;
                return 0;
            }
            return net_tcp_connect(fd, rip, rport);
        }
    }
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
    /* Allow UDP (SOCK_DGRAM) connect to succeed without creating an IPC connection so RFC3484 AddressSorterPosix source-address probing works immediately */
    if (lidx < 0 && g_fds[fd].sock_type == 2 /* SOCK_DGRAM */) {
        g_fds[fd].sock_state = SOCK_CONNECTED;
        return 0;
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
    conn->net_eof = 0; conn->net_err = 0;
    conn->c2s.lock = 0; conn->c2s.head = 0; conn->c2s.tail = 0; conn->c2s.count = 0;
    conn->c2s.scm_head = 0; conn->c2s.scm_tail = 0; conn->c2s.scm_count = 0;
    conn->s2c.lock = 0; conn->s2c.head = 0; conn->s2c.tail = 0; conn->s2c.count = 0;
    conn->s2c.scm_head = 0; conn->s2c.scm_tail = 0; conn->s2c.scm_count = 0;
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

static long sys_sendto(int fd, const void *buf, unsigned int len, int flags, const void *addr, unsigned int addrlen) {
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open || !g_fds[fd].is_sock) return -LINUX_EBADF;
    unsigned int rip, rport;
    if (g_fds[fd].sock_domain == 2 && g_fds[fd].sock_type == 2) {
        if (addr && net_parse_sin(addr, addrlen, &rip, &rport)) {
            if (!net_ip_is_local(rip) || g_fds[fd].is_netudp) return net_udp_send(fd, buf, len, rip, rport);
        } else if (g_fds[fd].is_netudp) {
            return sock_write_fd(fd, buf, len, flags & 0x40);
        }
    }
    return sock_write_fd(fd, buf, len, flags & 0x40);
}

static long sys_recvfrom(int fd, void *buf, unsigned int len, int flags, void *addr, unsigned int *addrlen) {
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open || !g_fds[fd].is_sock) return -LINUX_EBADF;
    if (g_fds[fd].is_netudp) return net_udp_recv(fd, buf, len, flags, addr, addrlen);
    long r = sock_read_fd(fd, buf, len, flags & (0x40 | 0x02));
    if (r >= 0 && addr && addrlen && net_is_tcp_conn(fd)) {
        SHIM_IPC_CONN *c = &g_ipc->conns[g_fds[fd].ipc_idx];
        net_fill_sin(addr, addrlen, c->net_rip, c->net_rport);
    } else if (r >= 0 && addrlen) {
        *addrlen = 0;
    }
    return r;
}

static long sys_sendmsg(int fd, const struct linux_msghdr *msg, int flags) {
    if (!msg) return -LINUX_EFAULT;
    if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_sock && g_fds[fd].sock_domain == 2 && g_fds[fd].sock_type == 2 &&
        (g_fds[fd].is_netudp || msg->msg_name)) {
        unsigned char dg[1500];
        unsigned int n = 0;
        for (unsigned int i = 0; i < msg->msg_iovlen; i++) {
            unsigned int l = msg->msg_iov[i].iov_len;
            if (n + l > sizeof(dg)) return -90; /* EMSGSIZE */
            for (unsigned int k = 0; k < l; k++) dg[n + k] = ((const unsigned char *)msg->msg_iov[i].iov_base)[k];
            n += l;
        }
        return sys_sendto(fd, dg, n, flags, msg->msg_name, msg->msg_namelen);
    }

    int sent_fds[MAX_SCM_FDS];
    unsigned int num_sent_fds = 0;
    if (msg->msg_control && msg->msg_controllen >= sizeof(struct linux_cmsghdr)) {
        const unsigned char *cptr = (const unsigned char *)msg->msg_control;
        unsigned int clen = msg->msg_controllen;
        unsigned int off = 0;
        while (off + sizeof(struct linux_cmsghdr) <= clen) {
            const struct linux_cmsghdr *cmsg = (const struct linux_cmsghdr *)(cptr + off);
            if (cmsg->cmsg_len < sizeof(struct linux_cmsghdr) || off + cmsg->cmsg_len > clen) break;
            if (cmsg->cmsg_level == 1 /* SOL_SOCKET */ && cmsg->cmsg_type == 1 /* SCM_RIGHTS */) {
                unsigned int nfds = (cmsg->cmsg_len - sizeof(struct linux_cmsghdr)) / sizeof(int);
                const int *fds = (const int *)(cptr + off + sizeof(struct linux_cmsghdr));
                for (unsigned int k = 0; k < nfds && num_sent_fds < MAX_SCM_FDS; k++) {
                    sent_fds[num_sent_fds++] = fds[k];
                }
            }
            off += (cmsg->cmsg_len + 3U) & ~3U;
        }
    }

    if (num_sent_fds > 0 && fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && g_fds[fd].is_sock &&
        !g_fds[fd].is_netudp && !g_fds[fd].is_pty && g_fds[fd].sock_state == SOCK_CONNECTED &&
        g_fds[fd].ipc_idx >= 0 && g_fds[fd].ipc_idx < MAX_IPC_CONNS && g_ipc) {
        unsigned int total_bytes = 0;
        for (unsigned int i = 0; i < msg->msg_iovlen; i++) {
            if (msg->msg_iov[i].iov_len > 0 && msg->msg_iov[i].iov_base) {
                total_bytes += msg->msg_iov[i].iov_len;
            }
        }
        SHIM_IPC_CONN *conn = &g_ipc->conns[g_fds[fd].ipc_idx];
        SHIM_IPC_RING *tx = g_fds[fd].is_server ? &conn->s2c : &conn->c2s;
        int nonblock = g_fds[fd].nonblock || ((flags & 0x40) != 0);

        for (int iter = 0;; iter++) {
            int peer_closed = g_fds[fd].is_server ? (conn->client_closed || conn->client_refs <= 0)
                                                  : (conn->server_closed || conn->server_refs <= 0);
            if (peer_closed) return -LINUX_EPIPE;
            ipc_lock(&tx->lock);
            if ((IPC_RING_SIZE - tx->count) >= total_bytes && (MAX_SCM_FDS - tx->scm_count) >= num_sent_fds) {
                for (unsigned int k = 0; k < num_sent_fds; k++) {
                    int sfd = sent_fds[k];
                    if (sfd >= 0 && sfd < MAX_FD && g_fds[sfd].is_open) {
                        SHIM_IPC_SCM_FD scm;
                        for (unsigned int z = 0; z < sizeof(scm); z++) ((unsigned char *)&scm)[z] = 0;
                        scm.is_sock       = g_fds[sfd].is_sock;
                        scm.is_server     = g_fds[sfd].is_server;
                        scm.sock_state    = g_fds[sfd].sock_state;
                        scm.sock_domain   = g_fds[sfd].sock_domain;
                        scm.sock_type     = g_fds[sfd].sock_type;
                        scm.is_eventfd    = g_fds[sfd].is_eventfd;
                        scm.is_pipe       = g_fds[sfd].is_pipe;
                        scm.is_pipe_write = g_fds[sfd].is_pipe_write;
                        scm.is_shm        = g_fds[sfd].is_shm;
                        scm.nonblock      = g_fds[sfd].nonblock;
                        scm.open_flags    = g_fds[sfd].open_flags;
                        scm.ipc_idx       = g_fds[sfd].ipc_idx;
                        scm.shm_size      = g_fds[sfd].shm_size;
                        scm.shm_ino       = g_fds[sfd].shm_ino;
                        scm.nt_handle     = 0;
                        scm.src_pid       = (unsigned int)get_current_pid();
                        if (g_fds[sfd].h && !g_fds[sfd].is_console && !g_fds[sfd].is_pipe &&
                            !g_fds[sfd].is_sock && !g_fds[sfd].is_eventfd && !g_fds[sfd].is_epoll &&
                            !g_fds[sfd].is_xvfb_fb && !g_fds[sfd].is_devnull) {
                            HANDLE dst = NULL;
                            if (NT_SUCCESS(Nt_DuplicateObject((HANDLE)-1, g_fds[sfd].h, (HANDLE)-1, &dst, 0, 0, 2)) && dst) {
                                scm.nt_handle = (unsigned long)dst;
                            } else {
                                scm.nt_handle = (unsigned long)g_fds[sfd].h;
                            }
                        } else {
                            shim_fd_addref(&g_fds[sfd]);
                        }
                        tx->scm_fds[tx->scm_tail] = scm;
                        tx->scm_tail = (tx->scm_tail + 1) % MAX_SCM_FDS;
                        tx->scm_count++;
                        static int s_scm_send_log = 0;
                        if (s_scm_send_log < 16) {
                            s_scm_send_log++;
                            shim_debug_hex("[scm_send] sfd=", (unsigned long)sfd);
                        }
                    }
                }
                for (unsigned int i = 0; i < msg->msg_iovlen; i++) {
                    if (msg->msg_iov[i].iov_len > 0 && msg->msg_iov[i].iov_base) {
                        ring_put_locked(tx, (const unsigned char *)msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
                    }
                }
                ipc_unlock(&tx->lock);
                return (long)total_bytes;
            }
            ipc_unlock(&tx->lock);
            if (nonblock) return -LINUX_EAGAIN;
            shim_ipc_wait(iter);
        }
    }

    long total = 0;
    for (unsigned int i = 0; i < msg->msg_iovlen; i++) {
        if (msg->msg_iov[i].iov_len > 0 && msg->msg_iov[i].iov_base) {
            long r = sock_write_fd(fd, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, flags & 0x40);
            if (r < 0) return total > 0 ? total : r;
            total += r;
            if ((unsigned long)r < (unsigned long)msg->msg_iov[i].iov_len) break;
        }
    }
    return total;
}

static long sys_recvmsg(int fd, struct linux_msghdr *msg, int flags) {
    if (!msg) return -LINUX_EFAULT;
    unsigned int max_controllen = msg->msg_control ? msg->msg_controllen : 0;
    msg->msg_controllen = 0;
    msg->msg_flags = 0;
    if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_netudp) {
        unsigned char dg[1500];
        unsigned int alen = msg->msg_namelen;
        long r = net_udp_recv(fd, dg, sizeof(dg), flags, msg->msg_name, msg->msg_name ? &alen : NULL);
        if (r < 0) return r;
        if (msg->msg_name) msg->msg_namelen = alen;
        unsigned int off = 0;
        for (unsigned int i = 0; i < msg->msg_iovlen && off < (unsigned int)r; i++) {
            unsigned int l = msg->msg_iov[i].iov_len;
            if (l > (unsigned int)r - off) l = (unsigned int)r - off;
            for (unsigned int k = 0; k < l; k++) ((unsigned char *)msg->msg_iov[i].iov_base)[k] = dg[off + k];
            off += l;
        }
        return (long)off;
    }
    long total = 0;
    for (unsigned int i = 0; i < msg->msg_iovlen; i++) {
        if (msg->msg_iov[i].iov_len > 0 && msg->msg_iov[i].iov_base) {
            int dontwait = (flags & 0x40) || (total > 0) ? 0x40 : 0;
            long r = sock_read_fd(fd, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, dontwait | (flags & 0x02));
            if (r < 0) {
                if (total > 0) break;
                return r;
            }
            total += r;
            if (r < (long)msg->msg_iov[i].iov_len) break;
        }
    }
    if (total > 0 && !(flags & 0x02 /* MSG_PEEK */) &&
        max_controllen >= sizeof(struct linux_cmsghdr) + sizeof(int) &&
        fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && g_fds[fd].is_sock &&
        !g_fds[fd].is_netudp && g_fds[fd].sock_state == SOCK_CONNECTED &&
        g_fds[fd].ipc_idx >= 0 && g_fds[fd].ipc_idx < MAX_IPC_CONNS && g_ipc) {
        SHIM_IPC_CONN *conn = &g_ipc->conns[g_fds[fd].ipc_idx];
        SHIM_IPC_RING *rx = g_fds[fd].is_server ? &conn->c2s : &conn->s2c;
        if (rx->scm_count > 0) {
            unsigned int max_fds = (max_controllen - sizeof(struct linux_cmsghdr)) / sizeof(int);
            if (max_fds > MAX_SCM_FDS) max_fds = MAX_SCM_FDS;
            SHIM_IPC_SCM_FD got_scm[MAX_SCM_FDS];
            unsigned int got_n = 0;
            ipc_lock(&rx->lock);
            while (rx->scm_count > 0 && got_n < max_fds) {
                got_scm[got_n++] = rx->scm_fds[rx->scm_head];
                rx->scm_head = (rx->scm_head + 1) % MAX_SCM_FDS;
                rx->scm_count--;
            }
            ipc_unlock(&rx->lock);
            if (got_n > 0) {
                struct linux_cmsghdr *cmsg = (struct linux_cmsghdr *)msg->msg_control;
                int *out_fds = (int *)((unsigned char *)msg->msg_control + sizeof(struct linux_cmsghdr));
                unsigned int actual_n = 0;
                unsigned int my_pid = (unsigned int)get_current_pid();
                for (unsigned int k = 0; k < got_n; k++) {
                    int nfd = shim_alloc_fd(3);
                    if (nfd < 0) continue;
                    g_fds[nfd].is_open       = 1;
                    g_fds[nfd].is_sock       = got_scm[k].is_sock;
                    g_fds[nfd].is_server     = got_scm[k].is_server;
                    g_fds[nfd].sock_state    = got_scm[k].sock_state;
                    g_fds[nfd].sock_domain   = got_scm[k].sock_domain;
                    g_fds[nfd].sock_type     = got_scm[k].sock_type;
                    g_fds[nfd].is_eventfd    = got_scm[k].is_eventfd;
                    g_fds[nfd].is_pipe       = got_scm[k].is_pipe;
                    g_fds[nfd].is_pipe_write = got_scm[k].is_pipe_write;
                    g_fds[nfd].is_shm        = got_scm[k].is_shm;
                    g_fds[nfd].nonblock      = got_scm[k].nonblock;
                    g_fds[nfd].open_flags    = got_scm[k].open_flags;
                    g_fds[nfd].cloexec       = (flags & 0x40000000 /* MSG_CMSG_CLOEXEC */) ? 1 : 0;
                    g_fds[nfd].ipc_idx       = got_scm[k].ipc_idx;
                    g_fds[nfd].shm_size      = got_scm[k].shm_size;
                    g_fds[nfd].shm_ino       = got_scm[k].shm_ino;
                    if (got_scm[k].is_shm && got_scm[k].shm_ino != 0) {
                        if (got_scm[k].src_pid == my_pid && got_scm[k].nt_handle) {
                            g_fds[nfd].h = (HANDLE)got_scm[k].nt_handle;
                        } else {
                            g_fds[nfd].h = OpenOrCreateShmSection(got_scm[k].shm_ino, got_scm[k].shm_size ? got_scm[k].shm_size : 4096);
                        }
                    } else if (got_scm[k].nt_handle && got_scm[k].src_pid == my_pid) {
                        g_fds[nfd].h = (HANDLE)got_scm[k].nt_handle;
                    }
                    out_fds[actual_n++] = nfd;
                    static int s_scm_recv_log = 0;
                    if (s_scm_recv_log < 16) {
                        s_scm_recv_log++;
                        shim_debug_hex("[scm_recv] nfd=", (unsigned long)nfd);
                    }
                }
                if (actual_n > 0) {
                    cmsg->cmsg_len   = sizeof(struct linux_cmsghdr) + actual_n * sizeof(int);
                    cmsg->cmsg_level = 1; /* SOL_SOCKET */
                    cmsg->cmsg_type  = 1; /* SCM_RIGHTS */
                    msg->msg_controllen = cmsg->cmsg_len;
                }
            }
        }
    }
    return total;
}

static void shim_fill_sockaddr(int fd, int is_peer, void *addr, unsigned int *addrlen) {
    if (!addr || !addrlen) return;
    if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && g_fds[fd].is_netudp) {
        SHIM_NET_UDP *u = &g_ipc->net_udp[g_fds[fd].ipc_idx];
        if (is_peer) net_fill_sin(addr, addrlen, g_fds[fd].net_rip, g_fds[fd].net_rport);
        else net_fill_sin(addr, addrlen, g_ipc->net_ip, u->lport);
        return;
    }
    if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && net_is_tcp_conn(fd)) {
        SHIM_IPC_CONN *c = &g_ipc->conns[g_fds[fd].ipc_idx];
        if (is_peer) net_fill_sin(addr, addrlen, c->net_rip, c->net_rport);
        else net_fill_sin(addr, addrlen, g_ipc->net_ip, c->net_lport);
        return;
    }
    if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && g_fds[fd].is_sock && g_fds[fd].sock_domain == 2) {
        if (*addrlen >= 16) {
            struct linux_sockaddr_in *in = (struct linux_sockaddr_in *)addr;
            for (int k = 0; k < 16; k++) ((unsigned char *)in)[k] = 0;
            in->sin_family = 2;
            in->sin_port = is_peer ? 0x5000 /* htons(80) */ : 0x50C3 /* htons(50000) */;
            in->sin_addr = 0x0100007FU; /* 127.0.0.1 */
            *addrlen = 16;
            return;
        }
    }
    if (*addrlen >= 2) {
        *(unsigned short *)addr = 1;
        *addrlen = 2;
    }
}

static long sys_getsockopt(int fd, int level, int opt, void *val, unsigned int *lenp) {
    if (!val || !lenp) return 0;
    if (opt == 17 /* SO_PEERCRED */ && *lenp >= 12) {
        ((int *)val)[0] = 100; /* pid */
        ((int *)val)[1] = 0;   /* uid */
        ((int *)val)[2] = 0;   /* gid */
        *lenp = 12;
    } else if (level == 1 && opt == 4 /* SO_ERROR */ && *lenp >= 4) {
        int err = 0;
        if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && net_is_tcp_conn(fd))
            err = g_ipc->conns[g_fds[fd].ipc_idx].net_err;
        *(int *)val = err;
        *lenp = 4;
    } else if (*lenp >= 4) {
        *(int *)val = 0;
        *lenp = 4;
    }
    return 0;
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
            shim_fill_sockaddr((int)args[0], call == 7, (void *)args[1], (unsigned int *)args[2]);
            return 0;
        case 8:  return sys_socketpair((int)args[0], (int)args[1], (int)args[2], (int *)args[3]);
        case 9:  /* send */
            return sys_sendto((int)args[0], (const void *)args[1], (unsigned int)args[2], (int)args[3], NULL, 0);
        case 11: /* sendto */
            return sys_sendto((int)args[0], (const void *)args[1], (unsigned int)args[2], (int)args[3],
                              (const void *)args[4], (unsigned int)args[5]);
        case 10: /* recv */
            return sys_recvfrom((int)args[0], (void *)args[1], (unsigned int)args[2], (int)args[3], NULL, NULL);
        case 12: /* recvfrom */
            return sys_recvfrom((int)args[0], (void *)args[1], (unsigned int)args[2], (int)args[3],
                                (void *)args[4], (unsigned int *)args[5]);
        case 13: /* shutdown */
            return 0;
        case 14: /* setsockopt */
            return 0;
        case 15: /* getsockopt */
            return sys_getsockopt((int)args[0], (int)args[1], (int)args[2], (void *)args[3], (unsigned int *)args[4]);
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

    if (g_fds[fd].is_netudp && g_ipc) {
        SHIM_NET_UDP *u = &g_ipc->net_udp[g_fds[fd].ipc_idx];
        if ((req_events & 1) && u->rx.count >= 8) rev |= 1;
        if (req_events & 4) rev |= 4;
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
            if (g_fds[fd].ipc_idx < 0 || g_fds[fd].ipc_idx >= MAX_IPC_CONNS) {
                if (req_events & 4) rev |= 4;
                return rev;
            }
            SHIM_IPC_CONN *conn = &g_ipc->conns[g_fds[fd].ipc_idx];
            SHIM_IPC_RING *rx = g_fds[fd].is_server ? &conn->c2s : &conn->s2c;
            SHIM_IPC_RING *tx = g_fds[fd].is_server ? &conn->s2c : &conn->c2s;
            if (!g_fds[fd].is_server && conn->listener_idx == NETD_LISTENER) {
                if (conn->net_err) return (short)((req_events & (1 | 4)) | 0x0008 /* POLLERR */ | 0x0010 /* POLLHUP */);
                if (conn->state != CONN_ESTABLISHED) return 0; /* connect() in progress */
                if ((req_events & 1) && (rx->count > 0 || conn->net_eof)) rev |= 1;
                if (conn->net_eof) rev |= (short)(req_events & 0x2000); /* POLLRDHUP */
                if ((req_events & 4) && !conn->server_closed && tx->count < IPC_RING_SIZE) rev |= 4;
                return rev;
            }
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
                           Elf32_Ehdr *out_ehdr, char *out_interp, unsigned int max_interp,
                           unsigned long *out_span_end) {
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
    if (out_span_end) *out_span_end = span_end;
    void *span_base = (void *)span_start;
    unsigned long span_size = span_end - span_start;

    int reused_existing = 0;
    NTSTATUS st = Nt_AllocateVirtualMemory((HANDLE)-1, &span_base, 0, &span_size,
                                           MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(st)) {
        reused_existing = 1;
        span_base = (void *)span_start;
        span_size = span_end - span_start;
        st = Nt_AllocateVirtualMemory((HANDLE)-1, &span_base, 0, &span_size,
                                      MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    if (!NT_SUCCESS(st)) {
        shim_debug_print("[MapElfFileImage VALLOC FAILED] ");
        shim_debug_print(posix_path);
        shim_debug_hex(" st=", (unsigned long)st);
        sys_close((int)fd);
        return -1;
    }

    if (reused_existing) {
        for (unsigned long k = 0; k < (span_end - span_start); k++) {
            ((unsigned char *)span_start)[k] = 0;
        }
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
    static char s_str_buf[16384];
    static char *s_argv[128];
    static char *s_envp[160];
    int s_argc = 0, s_envc = 0;
    unsigned int spos = 0;

    CanonicalizePosixPath(elf_path, s_path, sizeof(s_path));
    shim_strcpy(g_current_exe_path, s_path, sizeof(g_current_exe_path));
    shim_debug_print("[elf] exec: ");
    shim_debug_print(s_path);
    shim_debug_print("\n");

    g_cmdline_len = 0;
    for (int i = 0; i < argc && argv && argv[i] && s_argc < 126; i++) {
        unsigned int l = shim_strlen(argv[i]) + 1;
        if (spos + l < sizeof(s_str_buf)) {
            s_argv[s_argc++] = s_str_buf + spos;
            for (unsigned int k = 0; k < l; k++) s_str_buf[spos++] = argv[i][k];
        }
        if (g_cmdline_len + l < sizeof(g_cmdline_buf)) {
            for (unsigned int k = 0; k < l; k++) g_cmdline_buf[g_cmdline_len++] = argv[i][k];
        }
    }
    s_argv[s_argc] = NULL;
    for (int i = 0; i < s_argc; i++) {
        shim_debug_print("  arg: ");
        shim_debug_print(s_argv[i]);
        shim_debug_print("\n");
    }

    /* Ensure LD_LIBRARY_PATH is placed BEFORE inherited envp so musl ldso uses the right search order */
    if (shim_strncmp(s_path, "/opt/chromium/", 14) == 0) {
        s_envp[s_envc++] = "LD_PRELOAD=ld-linux.so.2";
        s_envp[s_envc++] = "LD_LIBRARY_PATH=/opt/chromium:/lib:/usr/lib";
        s_envp[s_envc++] = "VK_ICD_FILENAMES=/opt/chromium/vk_swiftshader_icd.json";
    } else {
        s_envp[s_envc++] = "LD_LIBRARY_PATH=/lib:/usr/lib";
    }
    if (envp) {
        for (int i = 0; envp[i] && s_envc < 140; i++) {
            if (shim_strncmp(envp[i], "LD_LIBRARY_PATH=", 16) == 0 ||
                shim_strncmp(envp[i], "LD_PRELOAD=", 11) == 0) {
                continue;
            }
            unsigned int l = shim_strlen(envp[i]) + 1;
            if (spos + l < sizeof(s_str_buf)) {
                s_envp[s_envc++] = s_str_buf + spos;
                for (unsigned int k = 0; k < l; k++) s_str_buf[spos++] = envp[i][k];
            }
        }
    }
    /* Ensure DISPLAY=:0 and XDG vars are present */
    s_envp[s_envc++] = "DISPLAY=:0";
    s_envp[s_envc++] = "GDK_BACKEND=x11";
    s_envp[s_envc++] = "NO_AT_BRIDGE=1";
    s_envp[s_envc++] = "XDG_CONFIG_DIRS=/etc/xdg";
    s_envp[s_envc++] = "XDG_DATA_DIRS=/usr/share";
    s_envp[s_envc++] = "XDG_RUNTIME_DIR=/tmp";
    if (shim_strncmp(s_path, "/opt/chromium/", 14) != 0) {
        s_envp[s_envc++] = "DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/dbus-session";
    }
    s_envp[s_envc++] = "HOME=/root";
    s_envp[s_envc++] = "USER=root";
    s_envp[s_envc++] = "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/opt/chromium";
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

    unsigned long app_bias = (app_ehdr.e_type == 3 /* ET_DYN */) ? 0x08040000UL : 0UL;
    unsigned long app_span_end = 0;
    char interp_path[128];
    if (MapElfFileImage(s_path, app_bias, &app_ehdr, interp_path, sizeof(interp_path), &app_span_end) < 0) {
        return 127;
    }

    unsigned long interp_bias = 0;
    unsigned long entry_addr  = app_bias + app_ehdr.e_entry;

    if (interp_path[0]) {
        Elf32_Ehdr interp_ehdr;
        interp_bias = 0x0B000000UL;
        if (app_span_end >= interp_bias) {
            interp_bias = (app_span_end + 0x00100000UL) & ~0xFFFFUL;
        }
        g_interp_bias = interp_bias;
        if (MapElfFileImage("/lib/ld-musl-i386.so.1", interp_bias, &interp_ehdr, NULL, 0, NULL) < 0) {
            if (MapElfFileImage(interp_path, interp_bias, &interp_ehdr, NULL, 0, NULL) < 0) {
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

    /* Allocate fresh 4 MB stack for ELF process */
    void *stack_alloc = NULL;
    unsigned long stack_size = 4 * 1024 * 1024;
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
extern char bb_common_bufsiz1[] __attribute__((weak));

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

/* User-mode IPv4 TCP/UDP daemon for AF_INET sockets (see netd.c). */
#include "netd.c"

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
    if (shim_strcmp(name, "netd") == 0)    return netd_main;
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
        if (i < MAX_SPAWN_FD && info->fds[i].is_open) {
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
            g_fds[i].is_shm        = info->fds[i].is_shm;
            g_fds[i].is_pak        = info->fds[i].is_pak;
            g_fds[i].proc_type     = info->fds[i].proc_type;
            g_fds[i].open_flags    = info->fds[i].open_flags;
            g_fds[i].nonblock      = info->fds[i].nonblock;
            g_fds[i].ipc_idx       = info->fds[i].ipc_idx;
            g_fds[i].shm_size      = info->fds[i].shm_size;
            g_fds[i].shm_ino       = info->fds[i].shm_ino;
            g_fds[i].offset        = info->fds[i].offset;
            g_fds[i].dir_first     = 1;
            shim_strcpy(g_fds[i].dir_path, info->fds[i].dir_path, sizeof(g_fds[i].dir_path));
            if (g_fds[i].is_shm && !g_fds[i].h && g_fds[i].shm_size > 0) {
                g_fds[i].h = OpenOrCreateShmSection(g_fds[i].shm_ino, g_fds[i].shm_size);
            }
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

    /* Populate SHIM_SPAWN_INFO and write to SHIM_SPAWN_INFO_ADDR in child process */
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

    for (int i = 0; i < MAX_SPAWN_FD; i++) {
        if (g_fds[i].is_open && !g_fds[i].cloexec) {
            /* Do not pass server listening/bound sockets into spawned child processes */
            if (g_fds[i].is_sock && (g_fds[i].sock_state == SOCK_LISTENING || g_fds[i].sock_state == SOCK_BOUND)) {
                continue;
            }
            if (g_fds[i].is_netudp) continue;
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
            s_info.fds[i].is_shm        = g_fds[i].is_shm;
            s_info.fds[i].is_pak        = g_fds[i].is_pak;
            s_info.fds[i].proc_type     = g_fds[i].proc_type;
            s_info.fds[i].open_flags    = g_fds[i].open_flags;
            s_info.fds[i].nonblock      = g_fds[i].nonblock;
            s_info.fds[i].ipc_idx       = g_fds[i].ipc_idx;
            s_info.fds[i].shm_size      = g_fds[i].shm_size;
            s_info.fds[i].shm_ino       = g_fds[i].shm_ino;
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
#define MAX_PTHREADS 96
typedef struct _SHIM_PTHREAD {
    volatile int in_use; /* 0 free, 1 active, 2 retiring, 3 being reclaimed */
    volatile int ready;
    int          tid;
    int        (*fn)(void *);
    void        *arg;
    unsigned long tls_base;
    unsigned long child_esp;
    int         *ctid;
    void        *stack_alloc;
    HANDLE       thread_handle;
} SHIM_PTHREAD;

static SHIM_PTHREAD g_pthreads[MAX_PTHREADS];
#include "thread_slots.h"
#include "musl_thread_stack.h"
static long g_main_tid = 0;

static void shim_clear_unmapped_tls(unsigned long start, unsigned long end) {
    /* Detached musl threads unmap their TCB before SYS_exit. Linux ignores a
     * clear_child_tid pointer in unmapped memory; do not dereference it here. */
    shim_forget_unmapped_thread_memory(start, end);
}

static long shim_futex(volatile int *uaddr, int op, int val, const void *timeout, int time64);

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
    int rc = 0;
    int (*fn_ptr)(void *) = pt->fn;
    void *arg_ptr = pt->arg;
    __asm__ volatile(
        "movl %%esp, %%edi\n\t"
        "andl $-16, %%esp\n\t"
        "subl $12, %%esp\n\t"
        "pushl %2\n\t"
        "call *%1\n\t"
        "movl %%edi, %%esp\n\t"
        : "=a"(rc)
        : "r"(fn_ptr), "r"(arg_ptr)
        : "ecx", "edx", "edi", "memory", "cc"
    );
    int *ctid = pt->ctid;
    __sync_lock_test_and_set(&pt->in_use, 2);
    if (ctid) {
        *ctid = 0;
        shim_futex(ctid, 1, 1, NULL, 0);
    }
    Nt_TerminateThread((HANDLE)-2, (NTSTATUS)rc);
    for (;;) {}
}

static long sys_clone_thread(unsigned long flags, unsigned long child_esp,
                             int *ptid, void *tls_desc, int *ctid, int (*fn)(void *)) {
    int slot = shim_claim_pthread_slot();
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
    unsigned long stack_sz = 1024 * 1024;
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

    if (shim_strncmp(g_current_exe_path, "/opt/chromium/", 14) == 0 &&
        tls_base > 0x10000UL && ((unsigned long *)tls_base)[0] == tls_base) {
        shim_set_musl_i386_stack((unsigned int *)tls_base,
                                (unsigned int)init_teb.StackBase, stack_sz);
    }

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

    NTSTATUS st = Nt_CreateThread(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, &cid, &ctx, &init_teb, 0);
    if (!NT_SUCCESS(st)) {
        g_pthreads[slot].in_use = 0;
        return -LINUX_EAGAIN;
    }
    if (!cid.UniqueThread) {
        Nt_TerminateThread(hThread, 127);
        Nt_Close(hThread);
        g_pthreads[slot].in_use = 0;
        return -LINUX_EAGAIN;
    }
    int real_tid = (int)(unsigned long)cid.UniqueThread;
    g_pthreads[slot].tid = real_tid;
    g_pthreads[slot].thread_handle = hThread;
    if ((flags & 0x00100000UL /* CLONE_PARENT_SETTID */) && ptid) *ptid = real_tid;
    if ((flags & 0x01000000UL /* CLONE_CHILD_SETTID */) && ctid) *ctid = real_tid;
    __sync_synchronize();
    g_pthreads[slot].ready = 1;

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
static SHIM_FD *g_vfork_saved_fds = NULL;
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
    if (!g_vfork_saved_fds) {
        void *vf_base = NULL;
        unsigned long vf_sz = (sizeof(SHIM_FD) * MAX_FD + 4095UL) & ~4095UL;
        Nt_AllocateVirtualMemory((HANDLE)-1, &vf_base, 0, &vf_sz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        g_vfork_saved_fds = (SHIM_FD *)vf_base;
    }
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
        unsigned char *musl_rw = (unsigned char *)((g_interp_bias ? g_interp_bias : 0x0B000000UL) + 0x0009B000UL);
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
        unsigned char *musl_rw = (unsigned char *)((g_interp_bias ? g_interp_bias : 0x0B000000UL) + 0x0009B000UL);
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
        shim_strcmp(cmd_base, "netd") == 0 ||
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

/* ------------------------------------------------------------------------- */
/* futex(2): process-private wait/wake on hashed NT semaphores.               */
/* A waiter registers in its bucket before re-checking *uaddr, so a wake that  */
/* races with the check leaves a semaphore count behind instead of being lost. */
/* Waits are bounded (spurious wakeups are allowed by futex semantics), and    */
/* callers always re-check their condition.                                    */
/* ------------------------------------------------------------------------- */
#define SHIM_FUTEX_BUCKETS 64
static HANDLE g_futex_sem[SHIM_FUTEX_BUCKETS];
static volatile long g_futex_waiters[SHIM_FUTEX_BUCKETS];

static unsigned int shim_futex_bucket(volatile int *uaddr) {
    return (unsigned int)((((unsigned long)uaddr >> 2) * 2654435761UL) >> 26) & (SHIM_FUTEX_BUCKETS - 1);
}

static HANDLE shim_futex_sem(unsigned int b) {
    HANDLE h = g_futex_sem[b];
    if (h) return h;
    HANDLE nh = NULL;
    unsigned long a[5] = { (unsigned long)&nh, 0x001F0003UL /* SEMAPHORE_ALL_ACCESS */, 0, 0, 0x7FFFFFFFUL };
    if (!NT_SUCCESS(DoNtSyscall(51 /* NtCreateSemaphore */, a, 5)) || !nh) return NULL;
    if (!__sync_bool_compare_and_swap((volatile long *)&g_futex_sem[b], 0, (long)nh)) Nt_Close(nh);
    return g_futex_sem[b];
}

static long shim_futex(volatile int *uaddr, int op, int val, const void *timeout, int time64) {
    if (!uaddr) return -LINUX_EFAULT;
    unsigned int b = shim_futex_bucket(uaddr);
    if (op == 0 /* WAIT */ || op == 9 /* WAIT_BITSET */) {
        if (*uaddr != val) return -LINUX_EAGAIN;
        s64 slice = 1000000LL; /* 100 ms in 100 ns units */
        int bounded = 0;
        if (timeout) {
            s64 sec = time64 ? ((const s64 *)timeout)[0] : (s64)((const long *)timeout)[0];
            s64 nsec = time64 ? ((const s64 *)timeout)[1] : (s64)((const long *)timeout)[1];
            s64 rel = sec * 10000000LL + nsec / 100;
            if (op == 9 /* WAIT_BITSET: absolute deadline */) {
                volatile LARGE_INTEGER *pTime = (volatile LARGE_INTEGER *)0x7FFE0014;
                s64 now_100ns = pTime->QuadPart - 116444736000000000ULL;
                rel -= now_100ns;
            }
            if (rel <= 0) return -110; /* ETIMEDOUT */
            if (rel <= slice) { slice = rel; bounded = 1; }
        }
        HANDLE sem = shim_futex_sem(b);
        if (!sem) {
            LARGE_INTEGER d = { .QuadPart = -10000LL };
            Nt_DelayExecution(0, &d);
            return 0;
        }
        __sync_fetch_and_add(&g_futex_waiters[b], 1);
        if (*uaddr != val) { __sync_fetch_and_sub(&g_futex_waiters[b], 1); return -LINUX_EAGAIN; }
        LARGE_INTEGER to = { .QuadPart = -slice };
        NTSTATUS st = Nt_WaitForSingleObject(sem, 0, &to);
        __sync_fetch_and_sub(&g_futex_waiters[b], 1);
        if (st == 0x102 /* STATUS_TIMEOUT */ && bounded) return -110; /* ETIMEDOUT */
        return 0;
    }
    if (op == 1 /* WAKE */ || op == 10 /* WAKE_BITSET */ || op == 3 /* REQUEUE */ ||
        op == 4 /* CMP_REQUEUE */) {
        long w = g_futex_waiters[b];
        if (w <= 0) return 0;
        /* Requeue: wake everyone in the bucket; they re-check and re-wait. */
        long k = (op == 1 || op == 10) ? (val < w ? val : w) : w;
        if (k <= 0) return 0;
        HANDLE sem = shim_futex_sem(b);
        if (sem) {
            unsigned long a[3] = { (unsigned long)sem, (unsigned long)k, 0 };
            DoNtSyscall(189 /* NtReleaseSemaphore */, a, 3);
        }
        return k;
    }
    return -38; /* ENOSYS (PI futexes etc.) */
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
                if (g_pthreads[i].in_use == 1 && g_pthreads[i].tid == tid) {
                    int *ctid = g_pthreads[i].ctid;
                    __sync_lock_test_and_set(&g_pthreads[i].in_use, 2);
                    if (ctid) {
                        *ctid = 0;
                        shim_futex(ctid, 1, 1, NULL, 0);
                    }
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
            s64 pos = ((s64)a5 << 32) | (u32)a4;
            if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;
            if (g_fds[fd].proc_type != PROC_NONE) {
                u64 u_pos = (u64)pos;
                return read_proc_fd(fd, (void *)a2, (unsigned int)a3, &u_pos);
            }
            if (g_fds[fd].is_pak && g_ipc) {
                return (long)shim_read_pak(g_fds[fd].ipc_idx, (void *)a2, (unsigned long)a3, (u64)pos);
            }
            if (!g_fds[fd].h) return -LINUX_EBADF;
            return (long)shim_chunked_read_file(g_fds[fd].h, (void *)a2, (unsigned long)a3, &pos);
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
            int fd = shim_alloc_fd(3);
            if (fd < 0) return -LINUX_EMFILE;
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
        case 444: /* landlock_create_ruleset */
        case 445: /* landlock_add_rule */
        case 446: /* landlock_restrict_self */
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

        case 356: /* memfd_create */ {
            unsigned int mflags = (unsigned int)a2;
            if (mflags & ~0x001FUL) return -LINUX_EINVAL;
            int fd = shim_alloc_fd(0);
            if (fd < 0) return -LINUX_EMFILE;
            static unsigned int s_next_memfd_ino = 60000;
            g_fds[fd].is_open = 1;
            g_fds[fd].is_shm = 1;
            g_fds[fd].open_flags = 2; /* O_RDWR */
            g_fds[fd].shm_ino = __sync_add_and_fetch(&s_next_memfd_ino, 1);
            if (mflags & 0x0001) g_fds[fd].cloexec = 1; /* MFD_CLOEXEC */
            return fd;
        }

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
        case 365: /* getsockopt */
            return sys_getsockopt((int)a1, (int)a2, (int)a3, (void *)a4, (unsigned int *)a5);
        case 366: /* setsockopt */
            return 0;
        case 367: /* getsockname */
        case 368: /* getpeername */ {
            shim_fill_sockaddr((int)a1, n == 368, (void *)a2, (unsigned int *)a3);
            return 0;
        }
        case 369: /* sendto */
            return sys_sendto((int)a1, (const void *)a2, (unsigned int)a3, (int)a4, (const void *)a5, (unsigned int)a6);
        case 370: /* sendmsg */
            return sys_sendmsg((int)a1, (const struct linux_msghdr *)a2, (int)a3);
        case 371: /* recvfrom */
            return sys_recvfrom((int)a1, (void *)a2, (unsigned int)a3, (int)a4, (void *)a5, (unsigned int *)a6);
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

            unsigned long in_r[16] = {0}, in_w[16] = {0};
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
            int fd = shim_alloc_fd(3);
            if (fd < 0) return -LINUX_EMFILE;
            int eidx = -1;
            for (int i = 0; i < MAX_EPOLLS; i++) {
                if (__sync_bool_compare_and_swap(&g_epolls[i].in_use, 0, 1)) {
                    eidx = i;
                    break;
                }
            }
            if (eidx < 0) {
                shim_free_fd(fd);
                return -LINUX_EMFILE;
            }
            for (unsigned int k = 0; k < sizeof(g_epolls[eidx].items); k++) {
                ((unsigned char *)g_epolls[eidx].items)[k] = 0;
            }
            g_fds[fd].is_open = 1;
            g_fds[fd].is_epoll = 1;
            g_fds[fd].ipc_idx = eidx;
            if (n == 329) {
                g_fds[fd].cloexec = ((unsigned int)a1 & 02000000) ? 1 : 0;
            }
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
        case 77:  /* getrusage */ {
            if (a2) {
                for (int i = 0; i < 72; i++) ((unsigned char *)a2)[i] = 0;
            }
            return 0;
        }
        case 76:  /* getrlimit */
        case 191: /* ugetrlimit */ {
            unsigned long *rl = (unsigned long *)a2;
            if (!rl) return -LINUX_EFAULT;
            if (a1 == 6 /* RLIMIT_NPROC */ && ((unsigned long)rl & 4095UL) == 0) {
                return -LINUX_EFAULT;
            }
            if (a1 == 7 /* RLIMIT_NOFILE */) { rl[0] = MAX_FD; rl[1] = MAX_FD; }
            else { rl[0] = 8 * 1024 * 1024; rl[1] = 0x7FFFFFFFUL; }
            return 0;
        }
        case 340: /* prlimit64 */ {
            u64 *old_rl = (u64 *)a4;
            if (a2 == 6 /* RLIMIT_NPROC */ && old_rl && ((unsigned long)old_rl & 4095UL) == 0) {
                return -LINUX_EFAULT;
            }
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

        case 93:  /* ftruncate */
        case 194: /* ftruncate64 */
        case 324: /* fallocate */ {
            int fd = (int)a1;
            if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && g_fds[fd].is_shm) {
                unsigned long sz = 0;
                if (n == 93) sz = (unsigned long)a2;
                else if (n == 194) sz = (unsigned long)a2;
                else if (n == 324) sz = (unsigned long)a3 + (unsigned long)a5;
                if (sz > g_fds[fd].shm_size) g_fds[fd].shm_size = (unsigned int)sz;
                if (!g_fds[fd].h && g_fds[fd].shm_size > 0) {
                    g_fds[fd].h = OpenOrCreateShmSection(g_fds[fd].shm_ino, g_fds[fd].shm_size);
                }
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
        case 92:  case 193: /* truncate/truncate64 */
        case 143: case 144: /* flock/msync */
            return 0;
        case 37: /* sys_kill(pid, sig) */ {
            long target_pid = (long)a1;
            int sig = (int)a2;
            if (sig == 0 && target_pid > 0 && target_pid != get_current_pid()) {
                /* Existence check: report real liveness for children we spawned. */
                for (int i = 0; i < MAX_CHILD_PROCS; i++) {
                    if (!g_child_procs[i].in_use || g_child_procs[i].pid != target_pid) continue;
                    if (g_child_procs[i].exited) return -3; /* ESRCH */
                    LARGE_INTEGER zero_wait = { .QuadPart = 0 };
                    if (g_child_procs[i].hProcess &&
                        Nt_WaitForSingleObject(g_child_procs[i].hProcess, 0, &zero_wait) == 0) {
                        PROCESS_BASIC_INFORMATION pbi;
                        g_child_procs[i].exited = 1;
                        if (NT_SUCCESS(Nt_QueryInformationProcess(g_child_procs[i].hProcess, 0, &pbi, sizeof(pbi), NULL)))
                            g_child_procs[i].exit_code = (int)pbi.ExitStatus;
                        return -3; /* ESRCH */
                    }
                    return 0;
                }
                /* wait4 may already have reaped this child while the shell
                 * ran another command. Check NT instead of inventing liveness. */
                return shim_process_exists(target_pid);
            }
            if (sig == 9 || sig == 15 || sig == 6) {
                if (target_pid > 0) {
                    for (int i = 0; i < MAX_CHILD_PROCS; i++) {
                        if (g_child_procs[i].in_use && g_child_procs[i].pid == target_pid) {
                            if (g_child_procs[i].hProcess) {
                                Nt_TerminateProcess(g_child_procs[i].hProcess, 128 + sig);
                                g_child_procs[i].exited = 1;
                                g_child_procs[i].exit_code = 128 + sig;
                            }
                            return 0;
                        }
                    }
                }
                if (target_pid <= 0 || target_pid == get_current_pid()) {
                    for (int i = 0; i < MAX_FD; i++) if (g_fds[i].is_open) sys_close(i);
                    Nt_TerminateProcess((HANDLE)-1, 128 + sig);
                }
            }
            return 0;
        }
        case 238: case 270: /* tkill/tgkill */ {
            int sig = (n == 270) ? (int)a3 : (int)a2;
            if (sig == 6 /* SIGABRT */ || sig == 9 /* SIGKILL */) {
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
            const char *rel = "3.16.0-nt51";
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
        case 422: /* SYS_futex_time64 */
            return shim_futex((volatile int *)a1, (int)(a2 & 0x7F), (int)a3, (const void *)a4, n == 422);

        case 218: /* SYS_mincore */ {
            unsigned long len = (unsigned long)a2;
            unsigned char *vec = (unsigned char *)a3;
            if (!vec) return -LINUX_EFAULT;
            unsigned long pages = (len + 4095UL) >> 12;
            for (unsigned long i = 0; i < pages; i++) vec[i] = 1;
            return 0;
        }

        case 219: /* SYS_madvise */ {
            /* MADV_DONTNEED (4) / MADV_REMOVE (9): Linux guarantees that private
             * anonymous pages read back as zero afterwards, and allocators
             * (PartitionAlloc, V8) rely on it to skip clearing. Zero-fill only
             * already-committed pages in place without committing MEM_RESERVE ranges. */
            int advice = (int)a3;
            if ((advice == 4 || advice == 9) && a1 && a2) {
                unsigned long start = (unsigned long)a1 & ~4095UL;
                unsigned long end = ((unsigned long)a1 + (unsigned long)a2 + 4095UL) & ~4095UL;
                shim_zero_committed_pages(start, end);
            }
            return 0;
        }
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
            if (g_is_dynamic_elf) {
                unsigned long *si = (unsigned long *)a1;
                if (!si) return -LINUX_EFAULT;
                for (int i = 0; i < 16; i++) si[i] = 0;
                volatile unsigned long *pTick = (volatile unsigned long *)0x7FFE0008;
                si[0] = (*pTick * 15) / 1000; /* uptime */
                si[4] = 1024UL * 1024UL * 1024UL; /* totalram = 1 GB */
                si[5] = 768UL * 1024UL * 1024UL;  /* freeram = 768 MB */
                si[6] = 64UL * 1024UL * 1024UL;   /* sharedram */
                si[7] = 32UL * 1024UL * 1024UL;   /* bufferram */
                *(unsigned short *)&si[10] = 12;  /* procs */
                si[13] = 1;                       /* mem_unit = 1 byte */
                return 0;
            }
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

        case 83:  /* symlink */
            return sys_symlink((const char *)a1, (const char *)a2);
        case 304: /* symlinkat */
            return sys_symlink((const char *)a1, (const char *)a3);

        case LINUX_SYS_rt_sigaction:
        case LINUX_SYS_rt_sigprocmask:
        case LINUX_SYS_sigprocmask:
        case LINUX_SYS_sigaltstack:
        case 9:   /* link */
        case 303: /* linkat */
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
