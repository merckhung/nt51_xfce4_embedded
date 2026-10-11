/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * native/libntc/console.c
 * Dual-Head Console Engine (VGA NtDisplayString + PS/2 Keyboard + COM1 Serial)
 */

#include "../include/ntnative.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define IOCTL_SERIAL_SET_BAUD_RATE      0x001B0004UL
#define IOCTL_SERIAL_SET_LINE_CONTROL   0x001B000CUL
#define IOCTL_SERIAL_SET_TIMEOUTS       0x001B001CUL
#define IOCTL_SERIAL_SET_DTR            0x001B0024UL
#define IOCTL_SERIAL_SET_RTS            0x001B0030UL

#ifndef ProcessUserModeIOPL
#define ProcessUserModeIOPL ((PROCESSINFOCLASS)16)
#endif
#ifndef SE_TCB_PRIVILEGE
#define SE_TCB_PRIVILEGE    7UL
#endif

typedef struct _SERIAL_BAUD_RATE {
    ULONG BaudRate;
} SERIAL_BAUD_RATE;

typedef struct _SERIAL_LINE_CONTROL {
    UCHAR StopBits;
    UCHAR Parity;
    UCHAR WordLength;
} SERIAL_LINE_CONTROL;

typedef struct _SERIAL_TIMEOUTS {
    ULONG ReadIntervalTimeout;
    ULONG ReadTotalTimeoutMultiplier;
    ULONG ReadTotalTimeoutConstant;
    ULONG WriteTotalTimeoutMultiplier;
    ULONG WriteTotalTimeoutConstant;
} SERIAL_TIMEOUTS;

static BOOLEAN g_ConsoleInitialized = FALSE;
static HANDLE  g_hSerial = NULL;
static HANDLE  g_hKeyboard = NULL;

static BOOLEAN g_ShiftDown = FALSE;
static BOOLEAN g_CtrlDown  = FALSE;
static BOOLEAN g_AltDown   = FALSE;
static BOOLEAN g_CapsLock  = FALSE;

/* Queue for multi-byte sequences (e.g. arrow keys -> ESC [ A) */
static unsigned char g_InputQueue[64];
static int g_InputHead = 0;
static int g_InputTail = 0;

static void EnqueueInputByte(unsigned char b) {
    int next = (g_InputTail + 1) & 63;
    if (next != g_InputHead) {
        g_InputQueue[g_InputTail] = b;
        g_InputTail = next;
    }
}

/* Set-1 XT Scancode tables */
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

static void ProcessKeyboardPacket(const KEYBOARD_INPUT_DATA *pkt) {
    USHORT sc = pkt->MakeCode;
    BOOLEAN is_break = (pkt->Flags & KEY_BREAK) != 0;
    BOOLEAN is_e0 = (pkt->Flags & KEY_E0) != 0;

    /* Left Shift (0x2A) or Right Shift (0x36) */
    if (sc == 0x2A || sc == 0x36) {
        g_ShiftDown = !is_break;
        return;
    }
    /* Left/Right Ctrl (0x1D) */
    if (sc == 0x1D) {
        g_CtrlDown = !is_break;
        return;
    }
    /* Left/Right Alt (0x38) */
    if (sc == 0x38) {
        g_AltDown = !is_break;
        return;
    }
    /* Caps Lock (0x3A) */
    if (sc == 0x3A && !is_break) {
        g_CapsLock = !g_CapsLock;
        return;
    }

    if (is_break) {
        return;
    }

    /* Extended E0 navigation keys */
    if (is_e0) {
        switch (sc) {
            case 0x1C: /* Keypad Enter */
                EnqueueInputByte('\n');
                return;
            case 0x35: /* Keypad / */
                EnqueueInputByte('/');
                return;
            case 0x48: /* Up Arrow */
                EnqueueInputByte(27); EnqueueInputByte('['); EnqueueInputByte('A');
                return;
            case 0x50: /* Down Arrow */
                EnqueueInputByte(27); EnqueueInputByte('['); EnqueueInputByte('B');
                return;
            case 0x4D: /* Right Arrow */
                EnqueueInputByte(27); EnqueueInputByte('['); EnqueueInputByte('C');
                return;
            case 0x4B: /* Left Arrow */
                EnqueueInputByte(27); EnqueueInputByte('['); EnqueueInputByte('D');
                return;
            case 0x47: /* Home */
                EnqueueInputByte(1); /* Ctrl+A */
                return;
            case 0x4F: /* End */
                EnqueueInputByte(5); /* Ctrl+E */
                return;
            case 0x53: /* Delete */
                EnqueueInputByte(127);
                return;
            default:
                return;
        }
    }

    if (sc < 88) {
        char ch = g_ShiftDown ? g_ScanShift[sc] : g_ScanNormal[sc];
        if (!ch) return;
        if (g_CapsLock) {
            if (ch >= 'a' && ch <= 'z') ch -= ('a' - 'A');
            else if (ch >= 'A' && ch <= 'Z') ch += ('a' - 'A');
        }
        if (g_CtrlDown) {
            if (ch >= 'a' && ch <= 'z') ch = (char)(ch - 'a' + 1);
            else if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 1);
        }
        EnqueueInputByte((unsigned char)ch);
    }
}

static void OpenKeyboard(void) {
    UNICODE_STRING u_kbd;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    NTSTATUS st;

    if (g_hKeyboard) return;

    RtlInitUnicodeString(&u_kbd, L"\\Device\\RawKeyboard");
    InitializeObjectAttributes(&oa, &u_kbd, OBJ_CASE_INSENSITIVE, NULL, NULL);
    st = NtCreateFile(
        &g_hKeyboard,
        GENERIC_READ | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if (!NT_SUCCESS(st)) {
        /* Fallback to KeyboardClass0 */
        RtlInitUnicodeString(&u_kbd, L"\\Device\\KeyboardClass0");
        InitializeObjectAttributes(&oa, &u_kbd, OBJ_CASE_INSENSITIVE, NULL, NULL);
        st = NtCreateFile(
            &g_hKeyboard,
            GENERIC_READ | SYNCHRONIZE,
            &oa,
            &iosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );
    }
}

static void PollKeyboard(void) {
    KEYBOARD_INPUT_DATA kbdData[16];
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    NTSTATUS st;
    ULONG i, count;

    if (!g_hKeyboard) {
        OpenKeyboard();
    }
    if (!g_hKeyboard) return;

    offset.QuadPart = 0;
    st = NtReadFile(
        g_hKeyboard,
        NULL,
        NULL,
        NULL,
        &iosb,
        kbdData,
        sizeof(kbdData),
        &offset,
        NULL
    );
    if (NT_SUCCESS(st) && iosb.Information >= sizeof(KEYBOARD_INPUT_DATA)) {
        count = (ULONG)(iosb.Information / sizeof(KEYBOARD_INPUT_DATA));
        for (i = 0; i < count; i++) {
            ProcessKeyboardPacket(&kbdData[i]);
        }
    }
}

static void OpenAndConfigureSerial(void) {
    UNICODE_STRING u_ser;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    NTSTATUS st;

    if (g_hSerial) return;
    RtlInitUnicodeString(&u_ser, L"\\Device\\Serial0");
    InitializeObjectAttributes(&oa, &u_ser, OBJ_CASE_INSENSITIVE, NULL, NULL);
    st = NtCreateFile(
        &g_hSerial,
        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if (NT_SUCCESS(st) && g_hSerial) {
        SERIAL_BAUD_RATE baud;
        SERIAL_LINE_CONTROL lctrl;
        SERIAL_TIMEOUTS timeouts;

        baud.BaudRate = 115200;
        NtDeviceIoControlFile(g_hSerial, NULL, NULL, NULL, &iosb,
                              IOCTL_SERIAL_SET_BAUD_RATE, &baud, sizeof(baud), NULL, 0);

        lctrl.StopBits = 0;   /* STOP_BIT_1 */
        lctrl.Parity = 0;     /* NO_PARITY */
        lctrl.WordLength = 8; /* 8 bits */
        NtDeviceIoControlFile(g_hSerial, NULL, NULL, NULL, &iosb,
                              IOCTL_SERIAL_SET_LINE_CONTROL, &lctrl, sizeof(lctrl), NULL, 0);

        /* Non-blocking immediate read timeout (ReadIntervalTimeout = MAXULONG, 0, 0) */
        timeouts.ReadIntervalTimeout = 0xFFFFFFFFUL;
        timeouts.ReadTotalTimeoutMultiplier = 0;
        timeouts.ReadTotalTimeoutConstant = 0;
        timeouts.WriteTotalTimeoutMultiplier = 0;
        timeouts.WriteTotalTimeoutConstant = 500;
        NtDeviceIoControlFile(g_hSerial, NULL, NULL, NULL, &iosb,
                              IOCTL_SERIAL_SET_TIMEOUTS, &timeouts, sizeof(timeouts), NULL, 0);

        NtDeviceIoControlFile(g_hSerial, NULL, NULL, NULL, &iosb,
                              IOCTL_SERIAL_SET_DTR, NULL, 0, NULL, 0);
        NtDeviceIoControlFile(g_hSerial, NULL, NULL, NULL, &iosb,
                              IOCTL_SERIAL_SET_RTS, NULL, 0, NULL, 0);
    }
}

static void PollSerial(void) {
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    unsigned char buf[16];
    NTSTATUS st;

    if (!g_hSerial) {
        OpenAndConfigureSerial();
    }
    if (!g_hSerial) return;

    offset.QuadPart = 0;
    st = NtReadFile(g_hSerial, NULL, NULL, NULL, &iosb, buf, sizeof(buf), &offset, NULL);
    if (NT_SUCCESS(st) && iosb.Information > 0) {
        ULONG i;
        for (i = 0; i < iosb.Information; i++) {
            unsigned char c = buf[i];
            if (c == '\r') c = '\n';
            EnqueueInputByte(c);
        }
    }
}

void __cdecl nt_console_init(void) {
    if (g_ConsoleInitialized) return;
    OpenAndConfigureSerial();
    OpenKeyboard();
    PollKeyboard();
    g_ConsoleInitialized = TRUE;
}

void __cdecl nt_console_write(const char *buf, size_t len) {
    WCHAR wbuf[256];
    char sbuf[512];
    size_t i = 0;

    if (!buf || len == 0) return;
    if (!g_ConsoleInitialized) {
        nt_console_init();
    }

    while (i < len) {
        size_t chunk = 0;
        size_t s_idx = 0;

        while (i < len && chunk < 250 && s_idx < 508) {
            unsigned char c = (unsigned char)buf[i++];
            wbuf[chunk++] = (WCHAR)c;
            if (c == '\n') {
                sbuf[s_idx++] = '\r';
            }
            sbuf[s_idx++] = (char)c;
        }
        wbuf[chunk] = L'\0';

        /* 1. Write to kernel bootvid VGA screen via NtDisplayString */
        {
            UNICODE_STRING u_str;
            u_str.Buffer = wbuf;
            u_str.Length = (USHORT)(chunk * sizeof(WCHAR));
            u_str.MaximumLength = (USHORT)((chunk + 1) * sizeof(WCHAR));
            NtDisplayString(&u_str);
        }

        /* 2. Write to COM1 Serial (\Device\Serial0) */
        if (g_hSerial && s_idx > 0) {
            IO_STATUS_BLOCK iosb;
            LARGE_INTEGER offset;
            offset.QuadPart = 0;
            NtWriteFile(g_hSerial, NULL, NULL, NULL, &iosb, sbuf, (ULONG)s_idx, &offset, NULL);
        }
    }
}

void __cdecl nt_console_puts(const char *s) {
    if (!s) return;
    nt_console_write(s, strlen(s));
}

void __cdecl nt_console_clear(void) {
    if (g_hSerial) {
        static const char vt_clear[] = "\033[2J\033[H";
        IO_STATUS_BLOCK iosb;
        LARGE_INTEGER offset;
        offset.QuadPart = 0;
        NtWriteFile(g_hSerial, NULL, NULL, NULL, &iosb, (PVOID)vt_clear, sizeof(vt_clear) - 1, &offset, NULL);
    }
    {
        UNICODE_STRING u_nl;
        RtlInitUnicodeString(&u_nl, L"\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n");
        NtDisplayString(&u_nl);
    }
}

int __cdecl nt_console_getc(int nonblocking) {
    if (!g_ConsoleInitialized) {
        nt_console_init();
    }

    for (;;) {
        if (g_InputHead != g_InputTail) {
            unsigned char c = g_InputQueue[g_InputHead];
            g_InputHead = (g_InputHead + 1) & 63;
            return (int)c;
        }

        PollKeyboard();
        PollSerial();

        if (g_InputHead != g_InputTail) {
            unsigned char c = g_InputQueue[g_InputHead];
            g_InputHead = (g_InputHead + 1) & 63;
            return (int)c;
        }

        if (nonblocking) {
            return -1;
        }

        /* Sleep 10ms between polls */
        {
            LARGE_INTEGER delay;
            delay.QuadPart = -100000i64; /* 10ms in 100ns units */
            NtDelayExecution(FALSE, &delay);
        }
    }
}

/*----------------------------------------------------------------------------
 * Interactive Line Editor with 32-Entry Command History
 *----------------------------------------------------------------------------*/
#define HISTORY_MAX   32
#define LINE_MAX_LEN  256

static char g_History[HISTORY_MAX][LINE_MAX_LEN];
static int  g_HistoryCount = 0;

static void AddToHistory(const char *line) {
    int i;
    if (!line || !line[0]) return;
    for (i = 0; line[i]; i++) {
        if (!isspace((unsigned char)line[i])) break;
    }
    if (!line[i]) return;

    if (g_HistoryCount > 0 && strcmp(g_History[g_HistoryCount - 1], line) == 0) {
        return;
    }
    if (g_HistoryCount < HISTORY_MAX) {
        strncpy(g_History[g_HistoryCount], line, LINE_MAX_LEN - 1);
        g_History[g_HistoryCount][LINE_MAX_LEN - 1] = '\0';
        g_HistoryCount++;
    } else {
        for (i = 1; i < HISTORY_MAX; i++) {
            strcpy(g_History[i - 1], g_History[i]);
        }
        strncpy(g_History[HISTORY_MAX - 1], line, LINE_MAX_LEN - 1);
        g_History[HISTORY_MAX - 1][LINE_MAX_LEN - 1] = '\0';
    }
}

static void ReplaceLineDisplay(const char *prompt, char *buf, size_t *len_io, const char *new_str) {
    size_t old_len = *len_io;
    size_t i;

    /* Erase on COM1 serial */
    if (g_hSerial) {
        for (i = 0; i < old_len; i++) {
            IO_STATUS_BLOCK iosb;
            LARGE_INTEGER offset;
            offset.QuadPart = 0;
            NtWriteFile(g_hSerial, NULL, NULL, NULL, &iosb, "\b \b", 3, &offset, NULL);
        }
    }

    strncpy(buf, new_str, LINE_MAX_LEN - 1);
    buf[LINE_MAX_LEN - 1] = '\0';
    *len_io = strlen(buf);

    if (g_hSerial && *len_io > 0) {
        IO_STATUS_BLOCK iosb;
        LARGE_INTEGER offset;
        offset.QuadPart = 0;
        NtWriteFile(g_hSerial, NULL, NULL, NULL, &iosb, buf, (ULONG)*len_io, &offset, NULL);
    }

    /* Redraw on VGA screen */
    {
        UNICODE_STRING u_str;
        WCHAR w_str[512];
        int wlen = 0;
        size_t j;
        const char *p = prompt ? prompt : "";
        w_str[wlen++] = L'\r';
        while (*p && wlen < 200) w_str[wlen++] = (WCHAR)*p++;
        for (j = 0; j < old_len && wlen < 350; j++) w_str[wlen++] = L' ';
        w_str[wlen++] = L'\r';
        p = prompt ? prompt : "";
        while (*p && wlen < 400) w_str[wlen++] = (WCHAR)*p++;
        for (j = 0; j < *len_io && wlen < 480; j++) w_str[wlen++] = (WCHAR)buf[j];
        w_str[wlen] = L'\0';
        u_str.Buffer = w_str;
        u_str.Length = (USHORT)(wlen * sizeof(WCHAR));
        u_str.MaximumLength = (USHORT)((wlen + 1) * sizeof(WCHAR));
        NtDisplayString(&u_str);
    }
}

int __cdecl nt_console_readline(const char *prompt, char *buf, size_t maxlen) {
    size_t len = 0;
    int hist_idx = g_HistoryCount;

    if (!buf || maxlen == 0) return -1;
    buf[0] = '\0';

    if (prompt && prompt[0]) {
        nt_console_puts(prompt);
    }

    for (;;) {
        int c = nt_console_getc(0);
        if (c < 0) continue;

        /* Ctrl+C */
        if (c == 3) {
            nt_console_puts("^C\n");
            buf[0] = '\0';
            return 0;
        }
        /* Ctrl+D on empty line -> EOF */
        if (c == 4) {
            if (len == 0) {
                nt_console_puts("\n");
                return -1;
            }
            continue;
        }
        /* Ctrl+L -> Clear screen */
        if (c == 12) {
            nt_console_clear();
            if (prompt) nt_console_puts(prompt);
            if (len > 0) nt_console_write(buf, len);
            continue;
        }
        /* Enter / Newline */
        if (c == '\n' || c == '\r') {
            nt_console_write("\n", 1);
            buf[len] = '\0';
            AddToHistory(buf);
            return (int)len;
        }
        /* Backspace or DEL */
        if (c == '\b' || c == 127) {
            if (len > 0) {
                len--;
                buf[len] = '\0';
                /* COM1 Serial VT100 backspace */
                if (g_hSerial) {
                    IO_STATUS_BLOCK iosb;
                    LARGE_INTEGER offset;
                    offset.QuadPart = 0;
                    NtWriteFile(g_hSerial, NULL, NULL, NULL, &iosb, "\b \b", 3, &offset, NULL);
                }
                /* VGA bootvid redraw without deleted character */
                {
                    UNICODE_STRING u_bs;
                    WCHAR w_bs[512];
                    int wlen = 0;
                    size_t j;
                    const char *p = prompt ? prompt : "";
                    w_bs[wlen++] = L'\r';
                    while (*p && wlen < 200) w_bs[wlen++] = (WCHAR)*p++;
                    for (j = 0; j < len && wlen < 350; j++) w_bs[wlen++] = (WCHAR)buf[j];
                    w_bs[wlen++] = L' ';
                    w_bs[wlen++] = L'\r';
                    p = prompt ? prompt : "";
                    while (*p && wlen < 400) w_bs[wlen++] = (WCHAR)*p++;
                    for (j = 0; j < len && wlen < 480; j++) w_bs[wlen++] = (WCHAR)buf[j];
                    w_bs[wlen] = L'\0';
                    u_bs.Buffer = w_bs;
                    u_bs.Length = (USHORT)(wlen * sizeof(WCHAR));
                    u_bs.MaximumLength = (USHORT)((wlen + 1) * sizeof(WCHAR));
                    NtDisplayString(&u_bs);
                }
            }
            continue;
        }
        /* Escape sequences (Arrow keys: ESC [ A / B / C / D) */
        if (c == 27) {
            int c2 = nt_console_getc(0);
            if (c2 == '[') {
                int c3 = nt_console_getc(0);
                if (c3 == 'A') { /* Up Arrow */
                    if (hist_idx > 0) {
                        hist_idx--;
                        ReplaceLineDisplay(prompt, buf, &len, g_History[hist_idx]);
                    }
                } else if (c3 == 'B') { /* Down Arrow */
                    if (hist_idx < g_HistoryCount - 1) {
                        hist_idx++;
                        ReplaceLineDisplay(prompt, buf, &len, g_History[hist_idx]);
                    } else if (hist_idx == g_HistoryCount - 1) {
                        hist_idx = g_HistoryCount;
                        ReplaceLineDisplay(prompt, buf, &len, "");
                    }
                }
            }
            continue;
        }
        /* Tab -> spaces or simple completion */
        if (c == '\t') {
            c = ' ';
        }
        /* Printable characters */
        if (c >= 0x20 && c <= 0x7E) {
            if (len + 1 < maxlen) {
                char ch = (char)c;
                buf[len++] = ch;
                buf[len] = '\0';
                nt_console_write(&ch, 1);
            }
        }
    }
}
