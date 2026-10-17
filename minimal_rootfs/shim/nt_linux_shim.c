/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * minimal_rootfs/shim/nt_linux_shim.c
 * Linux i386 to Windows NT Native System Call Translation Bridge
 * Supports MUSL libc 1.2.5, upstream BusyBox 1.36.1, and native NT 5.1 kernel
 */

#include "nt_linux_shim.h"

/* ========================================================================= */
/* Windows NT Types & Constants                                              */
/* ========================================================================= */
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

#define KEY_MAKE  0
#define KEY_BREAK 1
#define KEY_E0    2
#define KEY_E1    4

#define OBJ_CASE_INSENSITIVE 0x00000040L

#define FILE_READ_DATA        0x0001
#define FILE_WRITE_DATA       0x0002
#define FILE_APPEND_DATA      0x0004
#define FILE_LIST_DIRECTORY   0x0001
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

#define FileBasicInformation         4
#define FileStandardInformation      5
#define FilePositionInformation     14
#define FileDispositionInformation  13
#define FileBothDirectoryInformation 3

/* ========================================================================= */
/* Direct NT System Call Gateways (Windows XP NT 5.1 x86)                    */
/* ========================================================================= */
extern long DoNtSyscall(unsigned long id, void *args, unsigned int num_args);

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

static NTSTATUS Nt_Close(HANDLE Handle) {
    unsigned long a[1] = { (unsigned long)Handle };
    return (NTSTATUS)DoNtSyscall(25, a, 1);
}

static NTSTATUS Nt_DeviceIoControlFile(
    HANDLE FileHandle, HANDLE Event, void *ApcRoutine, void *ApcContext,
    IO_STATUS_BLOCK *IoStatusBlock, unsigned long IoControlCode,
    void *InputBuffer, unsigned long InputBufferLength,
    void *OutputBuffer, unsigned long OutputBufferLength
) {
    unsigned long a[10] = {
        (unsigned long)FileHandle, (unsigned long)Event, (unsigned long)ApcRoutine, (unsigned long)ApcContext,
        (unsigned long)IoStatusBlock, IoControlCode,
        (unsigned long)InputBuffer, InputBufferLength,
        (unsigned long)OutputBuffer, OutputBufferLength
    };
    return (NTSTATUS)DoNtSyscall(66, a, 10);
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

static NTSTATUS Nt_DelayExecution(unsigned char Alertable, LARGE_INTEGER *DelayInterval) {
    unsigned long a[2] = { (unsigned long)Alertable, (unsigned long)DelayInterval };
    return (NTSTATUS)DoNtSyscall(59, a, 2);
}

static NTSTATUS Nt_DisplayString(UNICODE_STRING *String) {
    unsigned long a[1] = { (unsigned long)String };
    return (NTSTATUS)DoNtSyscall(67, a, 1);
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

static void ConsoleWriteBuffer(const char *buf, unsigned int count) {
    unsigned int i;
    unsigned short ubuf[256];
    unsigned int upos = 0;
    static int ansi_state = 0; /* 0: normal, 1: ESC, 2: CSI, 3: OSC */

    for (i = 0; i < count; i++) {
        unsigned char ch = (unsigned char)buf[i];

        /* Filter ANSI escape sequences from VGA screen output (Nt_DisplayString) */
        if (ansi_state == 0) {
            if (ch == 0x1B) {
                ansi_state = 1;
                continue;
            }
        } else if (ansi_state == 1) {
            if (ch == '[') {
                ansi_state = 2;
                continue;
            } else if (ch == ']') {
                ansi_state = 3;
                continue;
            } else {
                ansi_state = 0;
                continue;
            }
        } else if (ansi_state == 2) {
            if (ch >= 0x40 && ch <= 0x7E) {
                ansi_state = 0;
            }
            continue;
        } else if (ansi_state == 3) {
            if (ch == 0x07 || ch == 0x1B) {
                ansi_state = 0;
            }
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
    shim_debug_hex("[kbd] Open st=", (unsigned long)st);
    if (!NT_SUCCESS(st)) {
        const char *dev2 = "\\Device\\KeyboardClass0";
        for (i = 0; dev2[i]; i++) kbd_name[i] = (unsigned short)(unsigned char)dev2[i];
        kbd_name[i] = 0;
        u_kbd.Length = (unsigned short)(i * 2);
        u_kbd.MaximumLength = u_kbd.Length + 2;
        st = Nt_CreateFile(&g_hKeyboard, 0x80000000 | SYNCHRONIZE, &oa, &iosb, NULL, 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        shim_debug_hex("[kbd] Open kbdclass st=", (unsigned long)st);
    }
    shim_debug_hex("[kbd] g_hKeyboard=", (unsigned long)g_hKeyboard);
}

static void PollKeyboard(void) {
    KEYBOARD_INPUT_DATA kbdData[16];
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    NTSTATUS st;
    unsigned int i, count;

    if (!g_hKeyboard) OpenKeyboard();
    if (!g_hKeyboard) return;

    offset.QuadPart = 0;
    st = Nt_ReadFile(g_hKeyboard, NULL, NULL, NULL, &iosb, kbdData, sizeof(kbdData), &offset, NULL);
    if (NT_SUCCESS(st) && iosb.Information >= sizeof(KEYBOARD_INPUT_DATA)) {
        count = iosb.Information / sizeof(KEYBOARD_INPUT_DATA);
        shim_debug_hex("[kbd] Got keys count=", (unsigned long)count);
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
                    case 0x48: EnqueueInputByte(27); EnqueueInputByte('['); EnqueueInputByte('A'); break; /* Up */
                    case 0x50: EnqueueInputByte(27); EnqueueInputByte('['); EnqueueInputByte('B'); break; /* Down */
                    case 0x4D: EnqueueInputByte(27); EnqueueInputByte('['); EnqueueInputByte('C'); break; /* Right */
                    case 0x4B: EnqueueInputByte(27); EnqueueInputByte('['); EnqueueInputByte('D'); break; /* Left */
                    case 0x53: EnqueueInputByte(127); break; /* Delete */
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

static void PollSerial(void) {
    /* COM1 Serial port is configured for logging output only in this environment.
     * Reading from synchronous serial device without non-blocking timeouts blocks the thread. */
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
        PollSerial();
        net_poll_once();

        if (g_InputHead != g_InputTail) {
            unsigned char c = g_InputQueue[g_InputHead];
            g_InputHead = (g_InputHead + 1) & 255;
            return (int)c;
        }

        LARGE_INTEGER delay;
        delay.QuadPart = -100000LL; /* 10ms */
        Nt_DelayExecution(0, &delay);
    }
}

/* ========================================================================= */
/* File Descriptor Table & Pipe Management                                   */
/* ========================================================================= */
#define MAX_FD 128

/* A vfork child runs to completion before its parent resumes, so a pipeline's
 * writer cannot wait for its reader: the buffer must hold the whole output. */
#define SHIM_PIPE_SIZE (4UL * 1024 * 1024)

typedef struct _SHIM_PIPE {
    unsigned char *buf;
    unsigned int head;
    unsigned int tail;
    unsigned int count;
    unsigned int readers;  /* open descriptors per end, across dup and vfork */
    unsigned int writers;
    unsigned char write_closed;
    unsigned char read_closed;
} SHIM_PIPE;

typedef struct _SHIM_FD {
    HANDLE        h;
    unsigned char is_open;
    unsigned char is_dir;
    unsigned char is_console;
    unsigned char is_pipe;
    unsigned char is_pipe_write;
    unsigned char dir_first;
    unsigned char dir_eof;
    SHIM_PIPE    *pipe;
    u64           offset;
    char          dir_path[260];
    __attribute__((aligned(4))) u8 dir_buffer[4096];
} SHIM_FD;

static SHIM_FD g_fds[MAX_FD];
static unsigned char g_shim_initialized = 0;
static char g_cwd[260] = "/";

/* Heap arena for brk */
static u32 g_brk_base = 0;
static u32 g_brk_curr = 0;
static u32 g_brk_limit = 0;

static void InitShim(void) {
    int i;
    void *base = (void *)0x20000000;
    unsigned long size = 64 * 1024 * 1024; /* 64 MB heap arena */

    if (g_shim_initialized) return;

    for (i = 0; i < MAX_FD; i++) {
        g_fds[i].is_open = 0;
    }

    /* stdin, stdout, stderr */
    g_fds[0].is_open = 1;
    g_fds[0].is_console = 1;
    g_fds[1].is_open = 1;
    g_fds[1].is_console = 1;
    g_fds[2].is_open = 1;
    g_fds[2].is_console = 1;

    /* Reserve brk arena */
    if (NT_SUCCESS(Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &size, MEM_RESERVE, PAGE_READWRITE))) {
        g_brk_base = (u32)base;
        g_brk_curr = (u32)base;
        g_brk_limit = (u32)base + size;
    }

    g_shim_initialized = 1;


}

/* ========================================================================= */
/* Path Translation: POSIX (/bin/sh) -> NT (\??\C:\bin\sh)                   */
/* ========================================================================= */
static void CanonicalizePosixPath(const char *in_path, char *out_path, unsigned int max_out) {
    char raw[512];
    unsigned int rlen = 0;

    if (!in_path || !in_path[0]) {
        in_path = ".";
    }

    if (in_path[0] != '/') {
        const char *cwd = g_cwd;
        while (*cwd && rlen < sizeof(raw) - 2) {
            raw[rlen++] = (*cwd == '\\') ? '/' : *cwd;
            cwd++;
        }
        if (rlen > 0 && raw[rlen - 1] != '/') {
            raw[rlen++] = '/';
        }
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
                while (out_len > 1 && out_path[out_len - 1] != '/') {
                    out_len--;
                }
                if (out_len > 1 && out_path[out_len - 1] == '/') {
                    out_len--;
                }
                out_path[out_len] = '\0';
            }
        } else {
            if (out_len > 1 && out_len < max_out - 1) {
                out_path[out_len++] = '/';
            }
            for (unsigned int k = 0; k < seg_len && out_len < max_out - 1; k++) {
                out_path[out_len++] = seg[k];
            }
            out_path[out_len] = '\0';
        }
    }
}

static int shim_strcmp(const char *s1, const char *s2);

static void TranslatePathToNT(const char *posix_path, unsigned short *nt_buf, unsigned int max_chars) {
    char clean[260];
    unsigned int p = 0, i = 0;

    if (!posix_path || !posix_path[0]) {
        posix_path = "/";
    }

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

        if (shim_strcmp(can, "/dev/eth0") == 0 || shim_strcmp(can, "/dev/net0") == 0) {
            const char *dev = "\\DosDevices\\net0";
            while (*dev && p < 250) clean[p++] = *dev++;
            clean[p] = '\0';
        } else if (shim_strcmp(can, "/dev/usb0") == 0) {
            const char *dev = "\\DosDevices\\usb0";
            while (*dev && p < 250) clean[p++] = *dev++;
            clean[p] = '\0';
        } else if (shim_strcmp(can, "/dev/sda") == 0) {
            const char *dev = "\\DosDevices\\sda";
            while (*dev && p < 250) clean[p++] = *dev++;
            clean[p] = '\0';
        } else if (shim_strcmp(can, "/dev/kbd0") == 0) {
            const char *dev = "\\DosDevices\\kbd0";
            while (*dev && p < 250) clean[p++] = *dev++;
            clean[p] = '\0';
        } else if (shim_strcmp(can, "/dev/mouse0") == 0) {
            const char *dev = "\\DosDevices\\mouse0";
            while (*dev && p < 250) clean[p++] = *dev++;
            clean[p] = '\0';
        } else {
            clean[p++] = '\\'; clean[p++] = '?'; clean[p++] = '?'; clean[p++] = '\\';
            clean[p++] = 'C'; clean[p++] = ':'; clean[p++] = '\\';

            if (can[0] == '/' && can[1] == '\0') {
                /* Root of C: drive requires trailing backslash: \??\C:\ */
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
    }

    for (i = 0; clean[i] && i < max_chars - 1; i++) {
        nt_buf[i] = (unsigned short)(unsigned char)clean[i];
    }
    nt_buf[i] = 0;
}

/* Exported for modtools.c (insmod needs the NT path of a module file) */
void shim_translate_path(const char *posix_path, unsigned short *nt_buf, unsigned int max_chars) {
    TranslatePathToNT(posix_path, nt_buf, max_chars);
}

/* ========================================================================= */
/* Syscall Implementations                                                   */
/* ========================================================================= */

static long sys_read(int fd, void *buf, unsigned int count) {
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;

    if (g_fds[fd].is_console) {
        if (count == 0) return 0;
        char *p = (char *)buf;
        int c = ConsoleGetByte(0);
        if (c < 0) return 0;
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

    if (g_fds[fd].is_pipe) {
        SHIM_PIPE *p = g_fds[fd].pipe;
        if (!p) return -LINUX_EBADF;
        while (p->count == 0 && !p->write_closed) {
            LARGE_INTEGER delay;
            delay.QuadPart = -10000LL; /* 1ms */
            Nt_DelayExecution(0, &delay);
        }
        if (p->count == 0 && p->write_closed) return 0;
        unsigned int n = 0;
        char *dst = (char *)buf;
        while (n < count && p->count > 0) {
            dst[n++] = p->buf[p->head];
            p->head = (p->head + 1) % SHIM_PIPE_SIZE;
            p->count--;
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

    if (g_fds[fd].is_console ||
        ((fd == 1 || fd == 2) && !g_fds[fd].is_pipe && !g_fds[fd].h)) {
        ConsoleWriteBuffer((const char *)buf, count);
        return (long)count;
    }

    if (g_fds[fd].is_pipe) {
        SHIM_PIPE *p = g_fds[fd].pipe;
        if (!p || p->read_closed) return -LINUX_EPIPE;
        const char *src = (const char *)buf;
        unsigned int n = 0;
        while (n < count) {
            if (p->count < SHIM_PIPE_SIZE) {
                p->buf[p->tail] = src[n++];
                p->tail = (p->tail + 1) % SHIM_PIPE_SIZE;
                p->count++;
            } else {
                LARGE_INTEGER delay;
                delay.QuadPart = -10000LL; /* 1ms */
                Nt_DelayExecution(0, &delay);
            }
        }
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
        }
    }
    return total;
}

static long sys_readv(int fd, const struct linux_iovec *iov, int iovcnt) {
    if (!iov || iovcnt < 0) return -LINUX_EINVAL;
    long total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len > 0 && iov[i].iov_base) {
            if (total > 0 && fd >= 0 && fd < MAX_FD && g_fds[fd].is_console && g_InputHead == g_InputTail) {
                break;
            }
            long ret = sys_read(fd, iov[i].iov_base, (unsigned int)iov[i].iov_len);
            if (ret < 0) return total > 0 ? total : ret;
            total += ret;
            if (ret < (long)iov[i].iov_len) break;
            if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_console && ret > 0 &&
                ((const char *)iov[i].iov_base)[ret - 1] == '\n') {
                break;
            }
        }
    }
    return total;
}

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
        while (*pathname && p < 500) {
            resolved[p++] = *pathname++;
        }
        resolved[p] = '\0';
    }

    TranslatePathToNT(resolved, nt_path, 260);

    /* /dev/<name>: try the DOS device link \??\<name> created by a kernel module */
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
                g_fds[fd].is_console = 0;
                g_fds[fd].is_pipe = 0;
                g_fds[fd].offset = 0;
                g_fds[fd].is_dir = 0;
                g_fds[fd].dir_first = 1;
                g_fds[fd].dir_eof = 0;
                g_fds[fd].dir_path[0] = '\0';
                return fd;
            }
        }
    }

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
    g_fds[fd].is_console = 0;
    g_fds[fd].is_pipe = 0;
    g_fds[fd].offset = 0;
    g_fds[fd].is_dir = (flags & 00200000) ? 1 : 0;
    g_fds[fd].dir_first = 1;
    g_fds[fd].dir_eof = 0;
    if (flags & 00200000) {
        CanonicalizePosixPath(resolved, g_fds[fd].dir_path, sizeof(g_fds[fd].dir_path));
    } else {
        g_fds[fd].dir_path[0] = '\0';
    }

    return fd;
}

static long sys_close(int fd) {
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;

    if (g_fds[fd].is_pipe) {
        SHIM_PIPE *p = g_fds[fd].pipe;
        if (p) {
            if (g_fds[fd].is_pipe_write) {
                if (p->writers && --p->writers == 0) p->write_closed = 1;
            } else if (p->readers && --p->readers == 0) {
                p->read_closed = 1;
            }
            if (!p->readers && !p->writers && p->buf) {
                unsigned long size = 0;
                void *base = p->buf;
                Nt_FreeVirtualMemory((HANDLE)-1, &base, &size, MEM_RELEASE);
                p->buf = NULL;
            }
        }
        g_fds[fd].is_open = 0;
        return 0;
    }

    if (!g_fds[fd].is_console && g_fds[fd].h) {
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
    if (g_fds[fd].is_console || g_fds[fd].is_pipe) return -LINUX_ESPIPE;

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
    shim_debug_hex("[brk] in addr=", addr);
    if (addr == 0 || addr < g_brk_base) {
        shim_debug_hex("[brk] out=", g_brk_curr);
        return g_brk_curr;
    }
    if (addr > g_brk_limit) {
        shim_debug_hex("[brk] out limit=", g_brk_curr);
        return g_brk_curr;
    }

    if (addr > g_brk_curr) {
        unsigned long size = (addr - g_brk_curr + 4095) & ~4095;
        void *base = (void *)g_brk_curr;
        if (NT_SUCCESS(Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &size, MEM_COMMIT, PAGE_READWRITE))) {
            g_brk_curr = addr;
        }
    } else {
        g_brk_curr = addr;
    }
    shim_debug_hex("[brk] out=", g_brk_curr);
    return g_brk_curr;
}

static unsigned long LinuxProtToNtProt(int prot) {
    if (prot & 4) {
        if (prot & 2) return PAGE_EXECUTE_READWRITE;
        if (prot & 1) return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    }
    if (prot & 2) return PAGE_READWRITE;
    if (prot & 1) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

static u32 g_mmap_arena = 0x30000000;

static long sys_mmap2(void *addr, unsigned long len, int prot, int flags, int fd, unsigned long pgoff) {
    void *base = addr;
    unsigned long size = (len + 4095) & ~4095;
    unsigned long nt_prot = LinuxProtToNtProt(prot);
    NTSTATUS status = 0;

    shim_debug_hex("[mmap2] in addr=", (unsigned long)addr);
    shim_debug_hex("[mmap2] in len=", len);
    shim_debug_hex("[mmap2] in flags=", (unsigned long)flags);

    if (flags & 0x10) { /* MAP_FIXED */
        unsigned long alloc_size = size;
        status = Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &alloc_size, MEM_COMMIT, nt_prot);
        if (!NT_SUCCESS(status)) {
            alloc_size = size;
            base = addr;
            status = Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &alloc_size, MEM_RESERVE | MEM_COMMIT, nt_prot);
        }
        if (!NT_SUCCESS(status)) {
            unsigned long old_prot = 0;
            alloc_size = size;
            base = addr;
            status = Nt_ProtectVirtualMemory((HANDLE)-1, &base, &alloc_size, nt_prot, &old_prot);
        }
    } else {
        if (base) {
            unsigned long alloc_size = size;
            status = Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &alloc_size, MEM_RESERVE | MEM_COMMIT, nt_prot);
            if (!NT_SUCCESS(status)) {
                base = NULL;
            }
        }
        if (!base) {
            base = (void *)g_mmap_arena;
            unsigned long alloc_size = size;
            status = Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &alloc_size, MEM_RESERVE | MEM_COMMIT, nt_prot);
            if (NT_SUCCESS(status)) {
                g_mmap_arena = ((u32)base + alloc_size + 0xFFFF) & ~0xFFFF;
            } else {
                base = NULL;
                alloc_size = size;
                status = Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &alloc_size, MEM_RESERVE | MEM_COMMIT, nt_prot);
            }
        }
    }

    if (!NT_SUCCESS(status)) {
        shim_debug_hex("[mmap2] failed status=", (unsigned long)status);
        return -LINUX_ENOMEM;
    }

    shim_debug_hex("[mmap2] out base=", (unsigned long)base);

    if (fd >= 0 && fd < MAX_FD && g_fds[fd].is_open && !(flags & 0x20)) {
        IO_STATUS_BLOCK iosb;
        LARGE_INTEGER li;
        li.QuadPart = (s64)pgoff * 4096;
        Nt_ReadFile(g_fds[fd].h, NULL, NULL, NULL, &iosb, base, len, &li, NULL);
    }

    return (long)base;
}

static long sys_mprotect(void *addr, unsigned long len, int prot) {
    void *base = (void *)((unsigned long)addr & ~4095);
    unsigned long size = ((unsigned long)addr + len + 4095) & ~4095;
    size -= (unsigned long)base;
    unsigned long nt_prot = LinuxProtToNtProt(prot);
    unsigned long old_prot = 0;

    shim_debug_hex("[mprotect] addr=", (unsigned long)base);
    shim_debug_hex("[mprotect] size=", size);
    shim_debug_hex("[mprotect] prot=", nt_prot);

    NTSTATUS status = Nt_ProtectVirtualMemory((HANDLE)-1, &base, &size, nt_prot, &old_prot);
    if (!NT_SUCCESS(status)) {
        unsigned long alloc_size = size;
        status = Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &alloc_size, MEM_COMMIT, nt_prot);
    }
    shim_debug_hex("[mprotect] status=", (unsigned long)status);
    return NT_SUCCESS(status) ? 0 : -LINUX_ENOMEM;
}

static long sys_munmap(void *addr, unsigned long len) {
    void *base = addr;
    unsigned long size = 0;
    NTSTATUS status = Nt_FreeVirtualMemory((HANDLE)-1, &base, &size, MEM_RELEASE);
    if (!NT_SUCCESS(status)) {
        base = addr;
        size = (len + 4095) & ~4095;
        Nt_FreeVirtualMemory((HANDLE)-1, &base, &size, MEM_DECOMMIT);
    }
    return 0;
}

#define LINUX_TCGETS     0x5401
#define LINUX_TCSETS     0x5402
#define LINUX_TCSETSW    0x5403
#define LINUX_TCSETSF    0x5404
#define LINUX_TIOCGWINSZ 0x5413


static long sys_ioctl(int fd, unsigned long req, void *arg) {
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;

    /* Standard descriptors without a handle are the console; redirected ones are not terminals. */
    if (g_fds[fd].is_console || (fd <= 2 && !g_fds[fd].is_pipe && !g_fds[fd].h)) {
        if (req == LINUX_TIOCGWINSZ) {
            struct linux_winsize *ws = (struct linux_winsize *)arg;
            if (ws) {
                ws->ws_row = 25;
                ws->ws_col = 80;
                ws->ws_xpixel = 640;
                ws->ws_ypixel = 400;
            }
            return 0;
        }
        if (req == LINUX_TCGETS) {
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
    }
    if (req == LINUX_TCGETS || req == LINUX_TCSETS || req == LINUX_TCSETSW ||
        req == LINUX_TCSETSF || req == LINUX_TIOCGWINSZ)
        return -LINUX_ENOTTY;

    if (g_fds[fd].h && req >= 0x220000) {
        IO_STATUS_BLOCK iosb;
        NTSTATUS st = Nt_DeviceIoControlFile(
            g_fds[fd].h, NULL, NULL, NULL, &iosb,
            req, arg, 64, arg, 64
        );
        return NT_SUCCESS(st) ? 0 : -LINUX_EINVAL;
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

    /* For FAT root directory "/", synthesize "." and ".." on first read since FAT has no . or .. in root */
    if (g_fds[fd].dir_first && g_fds[fd].dir_path[0] == '/' && g_fds[fd].dir_path[1] == '\0') {
        unsigned int rlen_dot = (sizeof(struct linux_dirent64) + 1 + 8) & ~7;
        unsigned int rlen_dotdot = (sizeof(struct linux_dirent64) + 2 + 8) & ~7;
        if (out_bytes + rlen_dot + rlen_dotdot <= count) {
            struct linux_dirent64 *d1 = (struct linux_dirent64 *)(out_p + out_bytes);
            d1->d_ino = 1;
            d1->d_off = out_bytes + rlen_dot;
            d1->d_reclen = (unsigned short)rlen_dot;
            d1->d_type = 4; /* DT_DIR */
            d1->d_name[0] = '.';
            d1->d_name[1] = '\0';
            out_bytes += rlen_dot;

            struct linux_dirent64 *d2 = (struct linux_dirent64 *)(out_p + out_bytes);
            d2->d_ino = 1;
            d2->d_off = out_bytes + rlen_dotdot;
            d2->d_reclen = (unsigned short)rlen_dotdot;
            d2->d_type = 4; /* DT_DIR */
            d2->d_name[0] = '.';
            d2->d_name[1] = '.';
            d2->d_name[2] = '\0';
            out_bytes += rlen_dotdot;
        }
    }

    while (out_bytes < count) {
        status = Nt_QueryDirectoryFile(
            g_fds[fd].h, NULL, NULL, NULL, &iosb,
            g_fds[fd].dir_buffer, sizeof(g_fds[fd].dir_buffer),
            FileBothDirectoryInformation,
            0, NULL, g_fds[fd].dir_first
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

            for (unsigned int k = 0; k < name_len; k++) {
                d->d_name[k] = (char)info->FileName[k];
            }
            d->d_name[name_len] = '\0';
            out_bytes += reclen;

            if (info->NextEntryOffset == 0) break;
            info = (FILE_BOTH_DIR_INFORMATION *)((unsigned char *)info + info->NextEntryOffset);
        }

        if (iosb.Information < sizeof(g_fds[fd].dir_buffer)) break;
    }

    return (long)out_bytes;
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
        char can[260];
        CanonicalizePosixPath(path, can, sizeof(can));
        if (can[0] == '/' && can[1] == '\0') {
            st->st_dev = 1;
            st->st_ino = 1;
            st->st_mode = 0040755;
            st->st_nlink = 2;
            st->st_uid = 0;
            st->st_gid = 0;
            st->st_size = 4096;
            st->st_blksize = 4096;
            st->st_blocks = 8;
            st->st_atim.tv_sec = 1700000000;
            st->st_atim.tv_nsec = 0;
            st->st_mtim.tv_sec = 1700000000;
            st->st_mtim.tv_nsec = 0;
            st->st_ctim.tv_sec = 1700000000;
            st->st_ctim.tv_nsec = 0;
            return 0;
        }

        /* Fallback: DOS device link \??\<name> under /dev/<name> */
        if (path[0] == '/' && path[1] == 'd' && path[2] == 'e' &&
            path[3] == 'v' && path[4] == '/' && path[5]) {
            unsigned short dev_path[64];
            const char *dn = path + 5;
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
                status = Nt_OpenFile(&hFile, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa_dev, &iosb,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
                if (NT_SUCCESS(status)) {
                    Nt_Close(hFile);
                    st->st_dev = 1;
                    st->st_ino = 1;
                    st->st_mode = 0020666; /* Character device */
                    st->st_nlink = 1;
                    st->st_uid = 0;
                    st->st_gid = 0;
                    st->st_size = 0;
                    st->st_blksize = 4096;
                    st->st_blocks = 0;
                    st->st_atim.tv_sec = 1700000000;
                    st->st_atim.tv_nsec = 0;
                    st->st_mtim.tv_sec = 1700000000;
                    st->st_mtim.tv_nsec = 0;
                    st->st_ctim.tv_sec = 1700000000;
                    st->st_ctim.tv_nsec = 0;
                    return 0;
                }
            }
        }
        return -LINUX_ENOENT;
    }

    status = Nt_QueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    Nt_Close(hFile);

    if (!NT_SUCCESS(status)) return -LINUX_EIO;

    st->st_dev = 1;
    st->st_ino = 1;
    st->st_mode = fsi.Directory ? 0040755 : 0100755;
    st->st_nlink = fsi.NumberOfLinks ? fsi.NumberOfLinks : 1;
    st->st_uid = 0;
    st->st_gid = 0;
    st->st_size = fsi.EndOfFile.QuadPart;
    st->st_blksize = 4096;
    st->st_blocks = (fsi.AllocationSize.QuadPart + 511) / 512;
    st->st_atim.tv_sec = 1700000000;
    st->st_atim.tv_nsec = 0;
    st->st_mtim.tv_sec = 1700000000;
    st->st_mtim.tv_nsec = 0;
    st->st_ctim.tv_sec = 1700000000;
    st->st_ctim.tv_nsec = 0;

    return 0;
}

static long sys_fstatat64(int dirfd, const char *path, struct linux_stat64 *st, int flags) {
    if (!path) return -LINUX_EINVAL;
    if (path[0] == '/' || dirfd == -100 /* AT_FDCWD */) {
        return sys_stat64(path, st);
    }
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

static long sys_getcwd(char *buf, unsigned long size) {
    unsigned long len = 0;
    while (g_cwd[len]) len++;
    if (len + 1 > size) return -LINUX_ERANGE;
    for (unsigned long i = 0; i <= len; i++) {
        buf[i] = g_cwd[i];
    }
    return (long)(len + 1);
}

static long sys_chdir(const char *path) {
    if (!path || !path[0]) return -LINUX_ENOENT;

    char can[260];
    CanonicalizePosixPath(path, can, sizeof(can));

    if (can[0] == '/' && can[1] == '\0') {
        g_cwd[0] = '/';
        g_cwd[1] = '\0';
        return 0;
    }

    unsigned short nt_path[260];
    TranslatePathToNT(can, nt_path, 260);

    UNICODE_STRING u_name;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hDir = NULL;
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

    NTSTATUS st = Nt_OpenFile(&hDir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(st)) return -LINUX_ENOENT;
    Nt_Close(hDir);

    unsigned int p = 0;
    while (can[p] && p < sizeof(g_cwd) - 1) {
        g_cwd[p] = can[p];
        p++;
    }
    g_cwd[p] = '\0';
    return 0;
}

static long sys_mkdir(const char *pathname, unsigned int mode) {
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
                                FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE,
                                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) return -LINUX_EEXIST;
    Nt_Close(h);
    return 0;
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
    if (!NT_SUCCESS(st)) return -LINUX_ENOENT;
    FILE_DISPOSITION_INFORMATION disp;
    disp.DeleteFile = 1;
    Nt_SetInformationFile(h, &iosb, &disp, sizeof(disp), FileDispositionInformation);
    Nt_Close(h);
    return 0;
}

static long sys_access(const char *pathname, int mode) {
    struct linux_stat64 st;
    return sys_stat64(pathname, &st);
}

#define LINUX_F_DUPFD         0
#define LINUX_F_GETFD         1
#define LINUX_F_SETFD         2
#define LINUX_F_GETFL         3
#define LINUX_F_SETFL         4
#define LINUX_F_DUPFD_CLOEXEC 1030

/* dup/dup2 give the new fd its own NT handle (same file object) or pipe-end
 * reference, so closing one descriptor leaves the other one usable. */
static void ShimDupHandleSlot(int newfd) {
    HANDLE src = g_fds[newfd].h, dst = NULL;
    unsigned long a[7];
    if (g_fds[newfd].is_pipe && g_fds[newfd].pipe) {
        if (g_fds[newfd].is_pipe_write) g_fds[newfd].pipe->writers++;
        else g_fds[newfd].pipe->readers++;
        return;
    }
    if (g_fds[newfd].is_console || !src) return;
    a[0] = (unsigned long)(HANDLE)-1; a[1] = (unsigned long)src;
    a[2] = (unsigned long)(HANDLE)-1; a[3] = (unsigned long)&dst;
    a[4] = 0; a[5] = 0; a[6] = 2; /* DUPLICATE_SAME_ACCESS */
    if (NT_SUCCESS((NTSTATUS)DoNtSyscall(68, a, 7)) && dst) g_fds[newfd].h = dst;
}

static long sys_dup_min(int oldfd, int min_fd) {
    if (oldfd < 0 || oldfd >= MAX_FD || !g_fds[oldfd].is_open) return -LINUX_EBADF;
    if (min_fd < 0 || min_fd >= MAX_FD) return -LINUX_EINVAL;
    int newfd;
    for (newfd = min_fd; newfd < MAX_FD; newfd++) {
        if (!g_fds[newfd].is_open) break;
    }
    if (newfd >= MAX_FD) return -LINUX_EMFILE;
    g_fds[newfd] = g_fds[oldfd];
    ShimDupHandleSlot(newfd);
    return newfd;
}

static long sys_dup(int oldfd) {
    return sys_dup_min(oldfd, 0);
}

static long sys_dup2(int oldfd, int newfd) {
    if (oldfd < 0 || oldfd >= MAX_FD || !g_fds[oldfd].is_open) return -LINUX_EBADF;
    if (newfd < 0 || newfd >= MAX_FD) return -LINUX_EBADF;
    if (oldfd == newfd) return newfd;
    if (g_fds[newfd].is_open) sys_close(newfd);
    g_fds[newfd] = g_fds[oldfd];
    ShimDupHandleSlot(newfd);
    return newfd;
}

static long sys_fcntl(int fd, int cmd, unsigned long arg) {
    if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;
    switch (cmd) {
        case LINUX_F_DUPFD:
        case LINUX_F_DUPFD_CLOEXEC:
            return sys_dup_min(fd, (int)arg);
        case LINUX_F_GETFD: return 0;
        case LINUX_F_SETFD: return 0;
        case LINUX_F_GETFL: return 2; /* O_RDWR */
        case LINUX_F_SETFL: return 0;
        default: return 0;
    }
}

static SHIM_PIPE g_pipe_pool[16];

static long sys_pipe(int *pipefd) {
    if (!pipefd) return -LINUX_EFAULT;
    int rfd = -1, wfd = -1;
    for (int i = 3; i < MAX_FD; i++) {
        if (!g_fds[i].is_open) {
            if (rfd < 0) rfd = i;
            else if (wfd < 0) { wfd = i; break; }
        }
    }
    if (rfd < 0 || wfd < 0) return -LINUX_EMFILE;

    SHIM_PIPE *p = NULL;
    for (int i = 0; i < 16; i++) {
        if (!g_pipe_pool[i].readers && !g_pipe_pool[i].writers) { p = &g_pipe_pool[i]; break; }
    }
    if (!p) return -LINUX_EMFILE;
    void *base = NULL;
    unsigned long size = SHIM_PIPE_SIZE;
    if (!NT_SUCCESS(Nt_AllocateVirtualMemory((HANDLE)-1, &base, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
        return -LINUX_ENOMEM;
    p->buf = (unsigned char *)base;
    p->head = 0;
    p->tail = 0;
    p->count = 0;
    p->readers = 1;
    p->writers = 1;
    p->write_closed = 0;
    p->read_closed = 0;

    g_fds[rfd].is_open = 1;
    g_fds[rfd].is_console = 0;
    g_fds[rfd].is_pipe = 1;
    g_fds[rfd].is_pipe_write = 0;
    g_fds[rfd].pipe = p;

    g_fds[wfd].is_open = 1;
    g_fds[wfd].is_console = 0;
    g_fds[wfd].is_pipe = 1;
    g_fds[wfd].is_pipe_write = 1;
    g_fds[wfd].pipe = p;

    pipefd[0] = rfd;
    pipefd[1] = wfd;
    return 0;
}

/* ========================================================================= */
/* Process Management: Cooperative vfork + Applet/ELF Dispatch               */
/* ========================================================================= */
extern int setjmp(void *);
extern void longjmp(void *, int);

static int shim_strcmp(const char *s1, const char *s2) {
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

/* BusyBox applet table hooks */
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

/* Native Toolchain and C++ ABI entry points */
extern int gcc_main(int argc, char **argv);
extern int gxx_main(int argc, char **argv);
extern int cpp_main(int argc, char **argv);
extern int gdb_main(int argc, char **argv);
extern int test_cxx_main(int argc, char **argv);
extern int nttest_main(int argc, char **argv);
/* XDDK module tools (modtools.c) */
extern int insmod_main(int argc, char **argv);
extern int rmmod_main(int argc, char **argv);
extern int lsmod_main(int argc, char **argv);
extern int modinfo_main(int argc, char **argv);
extern int xddkctl_main(int argc, char **argv);
extern int net_applet_main(int argc, char **argv);
extern int openssh_applet_main(int argc, char **argv);
extern int usb_applet_main(int argc, char **argv);

typedef int (*SHIM_TOOL_MAIN)(int, char **);
static SHIM_TOOL_MAIN shim_find_modtool(const char *name) {
    if (shim_strcmp(name, "insmod") == 0)     return insmod_main;
    if (shim_strcmp(name, "rmmod") == 0)      return rmmod_main;
    if (shim_strcmp(name, "lsmod") == 0)      return lsmod_main;
    if (shim_strcmp(name, "modinfo") == 0)    return modinfo_main;
    if (shim_strcmp(name, "xddkctl") == 0)    return xddkctl_main;
    if (shim_strcmp(name, "ifconfig") == 0 ||
        shim_strcmp(name, "ping") == 0 ||
        shim_strcmp(name, "route") == 0 ||
        shim_strcmp(name, "netstat") == 0 ||
        shim_strcmp(name, "nslookup") == 0 ||
        shim_strcmp(name, "wget") == 0 ||
        shim_strcmp(name, "curl") == 0)       return net_applet_main;
    if (shim_strcmp(name, "sshd") == 0 ||
        shim_strcmp(name, "ssh-keygen") == 0 ||
        shim_strcmp(name, "ssh") == 0 ||
        shim_strcmp(name, "scp") == 0)        return openssh_applet_main;
    if (shim_strcmp(name, "lsusb") == 0 ||
        shim_strcmp(name, "usbinfo") == 0 ||
        shim_strcmp(name, "usbctl") == 0)     return usb_applet_main;
    return 0;
}
extern void exit(int status);

static unsigned long g_vfork_buf[16];
static int g_in_vfork = 0;
static long g_vfork_child_pid = 0;
static int g_child_exit_code = 0;
/* Exited vfork children not yet reaped by wait4: a pipeline starts several
 * children before the shell waits for any of them. */
#define MAX_EXITED_CHILDREN 32
static struct { long pid; int code; } g_exited_children[MAX_EXITED_CHILDREN];
static unsigned int g_exited_child_count = 0;

/* vfork children share the parent's memory. An applet must start as after a
 * real exec: with clean stdio streams rather than an EOF flag or buffered input
 * left by an earlier child, and with zeroed BusyBox globals (grep, for example,
 * keeps its pattern list in bb_common_bufsiz1 without clearing it). */
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
static SHIM_FD g_saved_fds[MAX_FD];
static void *g_saved_ptr_to_globals = NULL;
static const char *g_saved_applet_name = NULL;
static void *g_saved_die_func = NULL;
static int g_saved_optind = 1;
static long s_next_child_pid = 100;
static unsigned char g_saved_stack[65536];
static void *g_saved_sp = NULL;
static unsigned long g_saved_stack_size = 0;
static unsigned long s_restore_idx = 0;

static long sys_vfork(void) {
    shim_debug_print("[vfork] enter\n");
    g_in_vfork = 1;
    g_vfork_child_pid = ++s_next_child_pid;

    /* Save the parent's descriptor table. Like fork, the child gets its own
     * handle or pipe-end reference for every open descriptor, so its dup2 and
     * close calls cannot close the parent's descriptors or pipe ends. */
    for (int i = 0; i < MAX_FD; i++) {
        g_saved_fds[i] = g_fds[i];
        if (g_fds[i].is_open) ShimDupHandleSlot(i);
    }

    /* Save parent global state */
    if (bb_get_ptr_to_globals) g_saved_ptr_to_globals = bb_get_ptr_to_globals();
    if (bb_get_applet_name) g_saved_applet_name = bb_get_applet_name();
    if (bb_get_die_func) g_saved_die_func = bb_get_die_func();
    g_saved_optind = optind;
    if (bb_common_bufsiz1)
        for (int i = 0; i < SHIM_BB_COMMON_BUFSIZE; i++) g_saved_common_bufsiz[i] = bb_common_bufsiz1[i];
    if (&xfunc_error_retval) g_saved_xfunc_error_retval = xfunc_error_retval;

    /* Save parent stack frame */
    void *stack_base = NULL;
    __asm__ volatile ("movl %%fs:0x04, %0" : "=r"(stack_base));
    void *current_sp;
    __asm__ volatile ("movl %%esp, %0" : "=r"(current_sp));

    shim_debug_hex("[vfork] stack_base=", (unsigned long)stack_base);
    shim_debug_hex("[vfork] current_sp=", (unsigned long)current_sp);

    unsigned long used = 0;
    if ((unsigned long)stack_base > (unsigned long)current_sp) {
        used = (unsigned long)stack_base - (unsigned long)current_sp;
    }
    if (used > sizeof(g_saved_stack)) {
        used = sizeof(g_saved_stack);
    }
    g_saved_stack_size = used;
    g_saved_sp = current_sp;
    if (used > 0) {
        for (s_restore_idx = 0; s_restore_idx < used; s_restore_idx++) {
            g_saved_stack[s_restore_idx] = ((unsigned char *)current_sp)[s_restore_idx];
        }
    }

    if (setjmp(g_vfork_buf) == 0) {
        shim_debug_print("[vfork] returning 0 to child\n");
        return 0; /* Child returns 0 */
    }

    shim_debug_print("[vfork] parent resumed after longjmp!\n");

    /* Parent restores entire stack before child ran! */
    if (g_saved_stack_size > 0 && g_saved_sp) {
        for (s_restore_idx = 0; s_restore_idx < g_saved_stack_size; s_restore_idx++) {
            ((unsigned char *)g_saved_sp)[s_restore_idx] = g_saved_stack[s_restore_idx];
        }
    }

    /* Release everything the child still holds, then restore the parent's table. */
    for (int i = 0; i < MAX_FD; i++) {
        if (g_fds[i].is_open) sys_close(i);
        g_fds[i] = g_saved_fds[i];
    }

    /* Parent restores global state */
    if (bb_set_ptr_to_globals && g_saved_ptr_to_globals) {
        bb_set_ptr_to_globals(g_saved_ptr_to_globals);
    }
    if (bb_set_applet_name && g_saved_applet_name) {
        bb_set_applet_name(g_saved_applet_name);
    }
    if (bb_set_die_func && g_saved_die_func) {
        bb_set_die_func(g_saved_die_func);
    }
    optind = g_saved_optind;
    if (bb_common_bufsiz1)
        for (int i = 0; i < SHIM_BB_COMMON_BUFSIZE; i++) bb_common_bufsiz1[i] = g_saved_common_bufsiz[i];
    if (&xfunc_error_retval) xfunc_error_retval = g_saved_xfunc_error_retval;
    g_in_vfork = 0;
    clearerr(stdin);
    clearerr(stdout);
    clearerr(stderr);

    long child_pid = g_vfork_child_pid;
    g_vfork_child_pid = 0;
    if (g_exited_child_count < MAX_EXITED_CHILDREN) {
        g_exited_children[g_exited_child_count].pid = child_pid;
        g_exited_children[g_exited_child_count].code = g_child_exit_code;
        g_exited_child_count++;
    }
    shim_debug_hex("[vfork] parent returning child_pid=", (unsigned long)child_pid);
    return child_pid;
}

static void shim_exit_child(int code) {
    if (g_in_vfork) {
        g_child_exit_code = code;
        if (!g_vfork_child_pid) {
            g_vfork_child_pid = ++s_next_child_pid;
        }
        shim_debug_print("[execve] child finished, longjmp to parent\n");
        longjmp(g_vfork_buf, 1);
    }
    Nt_TerminateProcess((HANDLE)-1, (NTSTATUS)code);
}

static long sys_execve(const char *filename, char **argv, char **envp) {
    const char *prog = filename;
    const char *p;

    shim_debug_print("[execve] filename=");
    if (filename) shim_debug_print(filename);
    shim_debug_print(" argv0=");
    if (argv && argv[0]) shim_debug_print(argv[0]);
    shim_debug_print("\n");

    /* Extract base name e.g. /bin/ls -> ls */
    for (p = filename; *p; p++) {
        if (*p == '/' || *p == '\\') prog = p + 1;
    }

    /* Also extract base name from argv[0] */
    const char *cmd = (argv && argv[0]) ? argv[0] : prog;
    const char *cmd_base = cmd;
    for (p = cmd; *p; p++) {
        if (*p == '/' || *p == '\\') cmd_base = p + 1;
    }

    int argc = 0;
    if (argv) {
        while (argv[argc]) argc++;
    }

    /* 0. XDDK module tools */
    {
        SHIM_TOOL_MAIN tool = shim_find_modtool(cmd_base);
        if (!tool) tool = shim_find_modtool(prog);
        if (tool) shim_exit_child(tool(argc, argv));
    }

    /* 1. Check native toolchain and C++ test commands */
    if (shim_strcmp(cmd_base, "gcc") == 0 || shim_strcmp(prog, "gcc") == 0) {
        int code = gcc_main(argc, argv);
        shim_exit_child(code);
    }
    if (shim_strcmp(cmd_base, "g++") == 0 || shim_strcmp(prog, "g++") == 0 ||
        shim_strcmp(cmd_base, "gxx") == 0 || shim_strcmp(prog, "gxx") == 0) {
        int code = gxx_main(argc, argv);
        shim_exit_child(code);
    }
    if (shim_strcmp(cmd_base, "cpp") == 0 || shim_strcmp(prog, "cpp") == 0) {
        int code = cpp_main(argc, argv);
        shim_exit_child(code);
    }
    if (shim_strcmp(cmd_base, "gdb") == 0 || shim_strcmp(prog, "gdb") == 0) {
        int code = gdb_main(argc, argv);
        shim_exit_child(code);
    }
    if (shim_strcmp(cmd_base, "test_cxx") == 0 || shim_strcmp(prog, "test_cxx") == 0 ||
        shim_strcmp(cmd_base, "test_cxx.elf") == 0 || shim_strcmp(prog, "test_cxx.elf") == 0) {
        int code = test_cxx_main(argc, argv);
        shim_exit_child(code);
    }
    if (shim_strcmp(cmd_base, "nttest") == 0 || shim_strcmp(prog, "nttest") == 0 ||
        shim_strcmp(cmd_base, "nttest.elf") == 0 || shim_strcmp(prog, "nttest.elf") == 0) {
        int code = nttest_main(argc, argv);
        shim_exit_child(code);
    }

    /* 2. If executing busybox with an applet name */
    if (find_applet_by_name && run_applet_no_and_exit) {
        int app_idx = -1;
        if (shim_strcmp(cmd_base, "busybox") == 0 && argv && argv[1]) {
            const char *sub = argv[1];
            for (p = sub; *p; p++) {
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
                shim_debug_print("[execve] running busybox subapplet: ");
                shim_debug_print(sub);
                shim_debug_print("\n");
                run_applet_no_and_exit(app_idx, sub, argv + 1);
            }
        }

        app_idx = find_applet_by_name(cmd_base);
        if (app_idx < 0) {
            app_idx = find_applet_by_name(prog);
        }
        shim_debug_hex("[execve] found app_idx=", (unsigned long)app_idx);
        if (app_idx >= 0) {
            optind = 1;
            shim_prepare_applet();
            shim_debug_print("[execve] running applet: ");
            shim_debug_print(cmd_base);
            shim_debug_print("\n");
            run_applet_no_and_exit(app_idx, cmd_base, argv);
            /* run_applet_no_and_exit calls exit(), reaching sys_exit */
        }
    }

    /* External command: if in vfork, return failure */
    if (g_in_vfork) {
        g_child_exit_code = 127;
        if (!g_vfork_child_pid) {
            g_vfork_child_pid = ++s_next_child_pid;
        }
        shim_debug_print("[execve] command not found, longjmp to parent\n");
        longjmp(g_vfork_buf, 1);
    }
    return -LINUX_ENOENT;
}

static long sys_wait4(long pid, int *wstatus, int options, void *rusage) {
    for (unsigned int i = 0; i < g_exited_child_count; i++) {
        if (pid > 0 && g_exited_children[i].pid != pid) continue;
        long ret = g_exited_children[i].pid;
        if (wstatus) *wstatus = (g_exited_children[i].code & 0xFF) << 8;
        g_exited_children[i] = g_exited_children[--g_exited_child_count];
        return ret;
    }
    /* vfork children always finish before the parent resumes. */
    return -LINUX_ECHILD;
}

/* ========================================================================= */
/* Master System Call Dispatcher                                             */
/* ========================================================================= */
long __nt_linux_syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    if (!g_shim_initialized) InitShim();
    shim_debug_hex("[sys] n=", (unsigned long)n);

    switch (n) {
        case LINUX_SYS_exit:
        case LINUX_SYS_exit_group: {
            shim_debug_hex("[sys] EXIT code=", (unsigned long)a1);
            if (g_in_vfork) {
                g_child_exit_code = (int)a1;
                if (!g_vfork_child_pid) {
                    g_vfork_child_pid = ++s_next_child_pid;
                }
                longjmp(g_vfork_buf, 1);
            }
            Nt_TerminateProcess((HANDLE)-1, (NTSTATUS)a1);
            return 0;
        }

        case LINUX_SYS_read: {
            long ret = sys_read((int)a1, (void *)a2, (unsigned int)a3);
            if (ret < 0) {
                shim_debug_hex("[read] ERR on fd=", (unsigned long)a1);
            }
            return ret;
        }

        case LINUX_SYS_write:
            return sys_write((int)a1, (const void *)a2, (unsigned int)a3);

        case LINUX_SYS_open: {
            shim_debug_print("[open] path=");
            if (a1) shim_debug_print((const char *)a1);
            shim_debug_print("\n");
            long fd = sys_openat(-100, (const char *)a1, (int)a2, (unsigned int)a3);
            shim_debug_hex("[open] ret fd=", (unsigned long)fd);
            return fd;
        }

        case LINUX_SYS_openat: {
            shim_debug_print("[openat] path=");
            if (a2) shim_debug_print((const char *)a2);
            shim_debug_print("\n");
            long fda = sys_openat((int)a1, (const char *)a2, (int)a3, (unsigned int)a4);
            shim_debug_hex("[openat] ret fd=", (unsigned long)fda);
            return fda;
        }

        case LINUX_SYS_close:
            shim_debug_hex("[close] fd=", (unsigned long)a1);
            return sys_close((int)a1);

        case LINUX_SYS_dup: {
            long d = sys_dup((int)a1);
            shim_debug_hex("[dup] from=", (unsigned long)a1);
            shim_debug_hex("[dup] to=", (unsigned long)d);
            return d;
        }
        case LINUX_SYS_dup2:
        case LINUX_SYS_dup3: {
            long d = sys_dup2((int)a1, (int)a2);
            shim_debug_hex("[dup2] from=", (unsigned long)a1);
            shim_debug_hex("[dup2] to=", (unsigned long)d);
            return d;
        }

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

        case LINUX_SYS_mmap2:
            return sys_mmap2((void *)a1, (unsigned long)a2, (int)a3, (int)a4, (int)a5, (unsigned long)a6);

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
        case 305: /* readlinkat */
            return -LINUX_EINVAL;

        case 383: /* statx */
            return -LINUX_ENOSYS;

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

        case LINUX_SYS_fstat64: {
            int fd = (int)a1;
            FILE_STANDARD_INFORMATION fsi;
            IO_STATUS_BLOCK iosb;
            struct linux_stat64 *st = (struct linux_stat64 *)a2;
            if (fd < 0 || fd >= MAX_FD || !g_fds[fd].is_open) return -LINUX_EBADF;
            if (g_fds[fd].is_console) {
                st->st_mode = 0020666;
                st->st_size = 0;
                return 0;
            }
            if (g_fds[fd].is_pipe) {
                st->st_mode = 0010666; /* FIFO/pipe */
                st->st_size = 0;
                return 0;
            }
            Nt_QueryInformationFile(g_fds[fd].h, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
            st->st_mode = fsi.Directory ? 0040755 : 0100755;
            st->st_size = fsi.EndOfFile.QuadPart;
            return 0;
        }

        case LINUX_SYS_getcwd:
            return sys_getcwd((char *)a1, (unsigned long)a2);

        case LINUX_SYS_chdir:
            return sys_chdir((const char *)a1);

        case LINUX_SYS_mkdir:
        case LINUX_SYS_mkdirat:
            return sys_mkdir((const char *)a1, (unsigned int)a2);

        case LINUX_SYS_unlink:
        case LINUX_SYS_unlinkat:
        case LINUX_SYS_rmdir:
            return sys_unlink((const char *)a1);

        case LINUX_SYS_access:
        case LINUX_SYS_faccessat:
            return sys_access((const char *)a1, (int)a2);



        case LINUX_SYS_fcntl:
        case LINUX_SYS_fcntl64:
            return sys_fcntl((int)a1, (int)a2, (unsigned long)a3);

        case LINUX_SYS_pipe:
        case LINUX_SYS_pipe2:
            return sys_pipe((int *)a1);

        case LINUX_SYS_vfork:
        case LINUX_SYS_fork:
        case LINUX_SYS_clone:
            return sys_vfork();

        case LINUX_SYS_execve:
            return sys_execve((const char *)a1, (char **)a2, (char **)a3);

        case LINUX_SYS_wait4:
        case LINUX_SYS_waitpid:
            return sys_wait4((long)a1, (int *)a2, (int)a3, (void *)a4);

        case LINUX_SYS_writev:
            return sys_writev((int)a1, (const struct linux_iovec *)a2, (int)a3);

        case LINUX_SYS_readv:
            return sys_readv((int)a1, (const struct linux_iovec *)a2, (int)a3);

        case LINUX_SYS_select:
        case LINUX_SYS__newselect:
        case LINUX_SYS_pselect6: {
            unsigned long *readfds = (unsigned long *)a2;
            unsigned long *writefds = (unsigned long *)a3;
            int ready = 0;
            if (writefds) ready++;
            if (readfds && (*readfds & 1)) {
                PollKeyboard();
                PollSerial();
                if (g_InputHead != g_InputTail) {
                    ready++;
                } else {
                    int c = ConsoleGetByte(0);
                    if (c >= 0) {
                        g_InputHead = (g_InputHead - 1) & 255;
                        g_InputQueue[g_InputHead] = (unsigned char)c;
                        ready++;
                    } else {
                        *readfds &= ~1UL;
                    }
                }
            }
            return ready;
        }

        case LINUX_SYS_poll:
        case LINUX_SYS_ppoll: {
            struct linux_pollfd {
                int fd;
                short events;
                short revents;
            } *pfds = (struct linux_pollfd *)a1;
            int nfds = (int)a2;
            int timeout = (int)a3;

            shim_debug_hex("[poll] nfds=", (unsigned long)nfds);
            shim_debug_hex("[poll] timeout=", (unsigned long)timeout);
            if (pfds && nfds > 0) {
                shim_debug_hex("[poll] fd0=", (unsigned long)pfds[0].fd);
                shim_debug_hex("[poll] ev0=", (unsigned long)pfds[0].events);
            }

            for (int i = 0; i < nfds; i++) {
                pfds[i].revents = 0;
                if (pfds[i].fd == 1 || pfds[i].fd == 2) {
                    pfds[i].revents |= 4; /* POLLOUT */
                }
            }

            if (timeout >= 0) {
                /* Finite timeout in ms */
                int elapsed_ms = 0;
                for (;;) {
                    PollKeyboard();
                    if (g_InputHead != g_InputTail) break;
                    if (elapsed_ms >= timeout) break;
                    LARGE_INTEGER delay;
                    delay.QuadPart = -100000LL; /* 10ms */
                    Nt_DelayExecution(0, &delay);
                    elapsed_ms += 10;
                }
                int ready = 0;
                for (int i = 0; i < nfds; i++) {
                    if (pfds[i].fd == 0 && (pfds[i].events & 1)) {
                        if (g_InputHead != g_InputTail) {
                            pfds[i].revents |= 1; /* POLLIN */
                            ready++;
                        }
                    } else if (pfds[i].revents) {
                        ready++;
                    }
                }
                return ready;
            } else {
                /* Infinite timeout (timeout < 0) */
                int c = ConsoleGetByte(0);
                if (c >= 0) {
                    /* Put byte back */
                    g_InputHead = (g_InputHead - 1) & 255;
                    g_InputQueue[g_InputHead] = (unsigned char)c;
                    int ready = 0;
                    for (int i = 0; i < nfds; i++) {
                        if (pfds[i].fd == 0 && (pfds[i].events & 1)) {
                            pfds[i].revents |= 1; /* POLLIN */
                            ready++;
                        } else if (pfds[i].revents) {
                            ready++;
                        }
                    }
                    return ready > 0 ? ready : 1;
                }
                return 0;
            }
        }

        case LINUX_SYS_getpid:
        case LINUX_SYS_gettid:
            return 100;

        case LINUX_SYS_getppid:
            return 4;

        case LINUX_SYS_getpgrp:
        case 132: /* getpgid */
            return 100;

        case 57:  /* setpgid */
        case 66:  /* setsid */
            return 0;

        case 147: /* getsid */
            return 100;

        case LINUX_SYS_getuid:
        case LINUX_SYS_geteuid:
        case LINUX_SYS_getgid:
        case LINUX_SYS_getegid:
        case 199: /* getuid32 */
        case 200: /* getgid32 */
        case 201: /* geteuid32 */
        case 202: /* getegid32 */
        case 203: /* setreuid32 */
        case 204: /* setregid32 */
        case 205: /* getgroups32 */
        case 206: /* setgroups32 */
        case 207: /* fchown32 */
        case 208: /* setresuid32 */
        case 210: /* setresgid32 */
        case 212: /* chown32 */
        case 213: /* setuid32 */
        case 214: /* setgid32 */
        case 215: /* setfsuid32 */
        case 216: /* setfsgid32 */
            return 0; /* root */

        case 209: /* getresuid32 */
        case 211: /* getresgid32 */ {
            if (a1) *(int *)a1 = 0;
            if (a2) *(int *)a2 = 0;
            if (a3) *(int *)a3 = 0;
            return 0;
        }

        case 172: /* prctl */
            return 0;

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
        case 219: /* SYS_madvise */
        case 241: /* SYS_sched_setaffinity */
        case 255: /* SYS_epoll_ctl */
            return 0;

        case 158: /* SYS_sched_yield */ {
            LARGE_INTEGER li;
            li.QuadPart = 0;
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

        case 254: /* SYS_epoll_create */
        case 329: /* SYS_epoll_create1 */
        case 328: /* SYS_eventfd2 */
            return -LINUX_ENOSYS;

        case 256: /* SYS_epoll_wait */
            return -LINUX_ENOSYS;

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

        case LINUX_SYS_nanosleep: {
            struct linux_timespec *req = (struct linux_timespec *)a1;
            LARGE_INTEGER li;
            if (!req) return -LINUX_EFAULT;
            li.QuadPart = -((s64)req->tv_sec * 10000000LL + (req->tv_nsec / 100));
            Nt_DelayExecution(0, &li);
            return 0;
        }

        case LINUX_SYS_set_tid_address:
        case LINUX_SYS_set_thread_area:
        case LINUX_SYS_rt_sigaction:
        case LINUX_SYS_rt_sigprocmask:
        case LINUX_SYS_sigprocmask:
            return 0; /* Graceful no-op */

        default:
            shim_debug_hex("[sys] UNHANDLED n=", (unsigned long)n);
            return -LINUX_ENOSYS;
    }
}

int sigsetjmp(void *env, int savesigs) {
    return setjmp(env);
}

int __sigsetjmp(void *env, int savesigs) {
    return setjmp(env);
}
