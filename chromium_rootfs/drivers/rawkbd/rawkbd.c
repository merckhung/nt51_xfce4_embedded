/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rootfs/drivers/rawkbd/rawkbd.c
 * Unified PS/2 Keyboard + PS/2 Mouse + COM1 Serial Input Driver for Windows XP (NT 5.1)
 * Creates:
 *   \Device\RawKeyboard (\DosDevices\RawKeyboard, \DosDevices\kbd0)
 *   \Device\RawMouse    (\DosDevices\RawMouse,    \DosDevices\mouse0)
 *   \Device\Serial0     (\DosDevices\COM1)
 */

#include <ntddk.h>

#define RAWKBD_BUFFER_SIZE   256
#define RAWMOUSE_BUFFER_SIZE 256

typedef struct _KEYBOARD_INPUT_DATA {
    USHORT UnitId;
    USHORT MakeCode;
    USHORT Flags;
    USHORT Reserved;
    ULONG  ExtraInformation;
} KEYBOARD_INPUT_DATA, *PKEYBOARD_INPUT_DATA;

typedef struct _MOUSE_INPUT_DATA_PKT {
    LONG   DeltaX;      /* Signed X movement (+right, -left) */
    LONG   DeltaY;      /* Signed Y movement (+down, -up) */
    ULONG  Buttons;     /* Bit 0: Left, Bit 1: Right, Bit 2: Middle; bits 8-15: signed wheel delta */
    ULONG  RawStatus;   /* Raw PS/2 byte 0 */
} MOUSE_INPUT_DATA_PKT, *PMOUSE_INPUT_DATA_PKT;

#define KEY_MAKE   0
#define KEY_BREAK  1
#define KEY_E0     2
#define KEY_E1     4

#define FILE_DEVICE_RAWINPUT 0x00008321
#define IOCTL_MOUSE_INJECT   CTL_CODE(FILE_DEVICE_RAWINPUT, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KBD_INJECT     CTL_CODE(FILE_DEVICE_RAWINPUT, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef enum _DEVICE_KIND {
    DEV_KEYBOARD = 1,
    DEV_SERIAL   = 2,
    DEV_MOUSE    = 3
} DEVICE_KIND;

typedef struct _RAWKBD_DEVEXT {
    DEVICE_KIND    Kind;
    PDEVICE_OBJECT DeviceObject;
    PKINTERRUPT    InterruptObject;
} RAWKBD_DEVEXT, *PRAWKBD_DEVEXT;

/* Shared i8042 + Serial Hardware State */
typedef struct _SHARED_INPUT_STATE {
    KSPIN_LOCK           Lock;
    PKINTERRUPT          KbdInterrupt;
    PKINTERRUPT          MouseInterrupt;
    PKINTERRUPT          SerInterrupt;

    /* PS/2 Keyboard ring buffer */
    KEYBOARD_INPUT_DATA  KbdBuffer[RAWKBD_BUFFER_SIZE];
    ULONG                KbdHead;
    ULONG                KbdTail;
    BOOLEAN              ExtPrefix;
    int                  PauseSkip;

    /* PS/2 Mouse packet state & ring buffer */
    MOUSE_INPUT_DATA_PKT MouseBuffer[RAWMOUSE_BUFFER_SIZE];
    ULONG                MouseHead;
    ULONG                MouseTail;
    UCHAR                MouseBytes[3];
    ULONG                MouseCycle;
    ULONG                MousePacketSize; /* 3, or 4 with an IntelliMouse wheel */

    /* COM1 Serial ring buffer */
    UCHAR                SerBuffer[RAWKBD_BUFFER_SIZE];
    ULONG                SerHead;
    ULONG                SerTail;
} SHARED_INPUT_STATE;

static SHARED_INPUT_STATE g_Input;

static void SerDbgPutc(char c) {
    int timeout = 50000;
    while (!(READ_PORT_UCHAR((PUCHAR)0x3FD) & 0x20) && --timeout > 0);
    WRITE_PORT_UCHAR((PUCHAR)0x3F8, (UCHAR)c);
}

static void SerDbgPrint(const char *s) {
    while (*s) {
        if (*s == '\n') SerDbgPutc('\r');
        SerDbgPutc(*s++);
    }
}

static void SerDbgHex(UCHAR val) {
    static const char hex[] = "0123456789ABCDEF";
    SerDbgPutc(hex[(val >> 4) & 0xF]);
    SerDbgPutc(hex[val & 0xF]);
}

static void I8042WaitWrite(void) {
    int limit = 25000;
    while ((READ_PORT_UCHAR((PUCHAR)0x64) & 2) && --limit > 0);
}

static BOOLEAN I8042WaitRead(void) {
    int limit = 25000;
    while (!(READ_PORT_UCHAR((PUCHAR)0x64) & 1) && --limit > 0);
    return (limit > 0) ? TRUE : FALSE;
}

static void I8042WriteMouseCmd(UCHAR cmd) {
    I8042WaitWrite();
    WRITE_PORT_UCHAR((PUCHAR)0x64, 0xD4);
    I8042WaitWrite();
    WRITE_PORT_UCHAR((PUCHAR)0x60, cmd);
    if (I8042WaitRead()) {
        (void)READ_PORT_UCHAR((PUCHAR)0x60); /* Read 0xFA ACK */
    }
}

/*
 * Initialize i8042 PS/2 Controller for BOTH Keyboard (Port 1, IRQ 1)
 * and Auxiliary PS/2 Mouse (Port 2, IRQ 12).
 */
static void InitI8042AndMouse(void) {
    int limit;
    UCHAR ccb = 0;

    SerDbgPrint("[rawkbd] InitI8042AndMouse: configuring PS/2 Keyboard + Mouse...\n");

    /* 1. Flush output buffer */
    limit = 2000;
    while ((READ_PORT_UCHAR((PUCHAR)0x64) & 1) && --limit > 0) {
        (void)READ_PORT_UCHAR((PUCHAR)0x60);
    }

    /* 2. Enable Keyboard interface (0xAE) and Aux Mouse interface (0xA8) */
    I8042WaitWrite();
    WRITE_PORT_UCHAR((PUCHAR)0x64, 0xAE);
    I8042WaitWrite();
    WRITE_PORT_UCHAR((PUCHAR)0x64, 0xA8);

    /* 3. Read CCB (cmd 0x20) */
    I8042WaitWrite();
    WRITE_PORT_UCHAR((PUCHAR)0x64, 0x20);
    if (I8042WaitRead()) {
        ccb = READ_PORT_UCHAR((PUCHAR)0x60);
    }

    /* 4. Modify CCB:
     * Bit 0 (0x01): Enable Keyboard IRQ 1
     * Bit 1 (0x02): Enable Mouse IRQ 12
     * Bit 4 (0x10): Clear to enable Keyboard Clock
     * Bit 5 (0x20): Clear to enable Mouse Clock
     * Bit 6 (0x40): Enable Set 1 XT Scancode Translation
     */
    ccb |= 0x01 | 0x02 | 0x40;
    ccb &= ~(0x10 | 0x20);

    I8042WaitWrite();
    WRITE_PORT_UCHAR((PUCHAR)0x64, 0x60);
    I8042WaitWrite();
    WRITE_PORT_UCHAR((PUCHAR)0x60, ccb);

    SerDbgPrint("[rawkbd] InitI8042AndMouse: CCB = 0x");
    SerDbgHex(ccb);
    SerDbgPrint("\n");

    /* 5. Enable Keyboard scanning (0xF4) */
    I8042WaitWrite();
    WRITE_PORT_UCHAR((PUCHAR)0x60, 0xF4);
    if (I8042WaitRead()) {
        (void)READ_PORT_UCHAR((PUCHAR)0x60);
    }

    /* 6. Initialize PS/2 Mouse: Set Defaults (0xF6), unlock the IntelliMouse
     * wheel with the 200/100/80 sample-rate sequence, then read its ID (0xF2). */
    I8042WriteMouseCmd(0xF6);
    I8042WriteMouseCmd(0xF3); I8042WriteMouseCmd(200);
    I8042WriteMouseCmd(0xF3); I8042WriteMouseCmd(100);
    I8042WriteMouseCmd(0xF3); I8042WriteMouseCmd(80);
    I8042WriteMouseCmd(0xF2);
    g_Input.MousePacketSize = 3;
    if (I8042WaitRead() && READ_PORT_UCHAR((PUCHAR)0x60) == 0x03) {
        g_Input.MousePacketSize = 4;
    }
    SerDbgPrint("[rawkbd] PS/2 mouse packet size = 0x");
    SerDbgHex((UCHAR)g_Input.MousePacketSize);
    SerDbgPrint("\n");
    I8042WriteMouseCmd(0xF4);

    /* 7. Final flush of any pending ACK bytes */
    limit = 2000;
    while ((READ_PORT_UCHAR((PUCHAR)0x64) & 1) && --limit > 0) {
        (void)READ_PORT_UCHAR((PUCHAR)0x60);
    }

    SerDbgPrint("[rawkbd] InitI8042AndMouse: Keyboard & PS/2 Mouse ready.\n");
}

/*
 * Drain all available bytes from i8042 port 0x60, demultiplexing
 * Keyboard scancodes (status bit 5 == 0) and PS/2 Mouse packets (status bit 5 == 1).
 */
static void DrainI8042Hardware(void) {
    UCHAR status, b;
    ULONG next;

    while ((status = READ_PORT_UCHAR((PUCHAR)0x64)) & 1) {
        b = READ_PORT_UCHAR((PUCHAR)0x60);

        if (status & 0x20) {
            /* PS/2 Mouse byte (AUX port) */
            if (g_Input.MouseCycle == 0) {
                /* Ignore bare 0xFA ACK or out-of-sync bytes without bit 3 set */
                if (b == 0xFA || (b & 0x08) == 0 || (b & 0xC0) != 0) {
                    continue;
                }
                g_Input.MouseBytes[0] = b;
                g_Input.MouseCycle = 1;
            } else if (g_Input.MouseCycle == 1) {
                g_Input.MouseBytes[1] = b;
                g_Input.MouseCycle = 2;
            } else if (g_Input.MouseCycle == 2 && g_Input.MousePacketSize == 4) {
                g_Input.MouseBytes[2] = b;
                g_Input.MouseCycle = 3;
            } else {
                LONG dx, dy;
                ULONG buttons;
                UCHAR b0 = g_Input.MouseBytes[0];
                UCHAR b1 = g_Input.MouseBytes[1];
                UCHAR b2 = (g_Input.MouseCycle == 3) ? g_Input.MouseBytes[2] : b;
                UCHAR wheel = (g_Input.MouseCycle == 3) ? b : 0;
                g_Input.MouseCycle = 0;

                dx = (LONG)b1 - ((b0 & 0x10) ? 256 : 0);
                dy = (LONG)b2 - ((b0 & 0x20) ? 256 : 0);
                dy = -dy; /* Invert Y so +dy is downward on screen */
                buttons = (ULONG)(b0 & 0x07) | ((ULONG)wheel << 8);

                /* Coalesce with latest unread packet if button state matches */
                next = (g_Input.MouseTail + 1) % RAWMOUSE_BUFFER_SIZE;
                if (next != g_Input.MouseHead) {
                    PMOUSE_INPUT_DATA_PKT mp = &g_Input.MouseBuffer[g_Input.MouseTail];
                    mp->DeltaX    = dx;
                    mp->DeltaY    = dy;
                    mp->Buttons   = buttons;
                    mp->RawStatus = (ULONG)b0;
                    g_Input.MouseTail = next;
                }
            }
        } else {
            /* PS/2 Keyboard scancode */
            PKEYBOARD_INPUT_DATA pkt;

            if (b == 0xFA || b == 0xFE) {
                continue;
            }
            if (g_Input.PauseSkip > 0) {
                g_Input.PauseSkip--;
                continue;
            }
            if (b == 0xE1) {
                g_Input.PauseSkip = 5;
                continue;
            }
            if (b == 0xE0) {
                g_Input.ExtPrefix = TRUE;
                continue;
            }

            next = (g_Input.KbdTail + 1) % RAWKBD_BUFFER_SIZE;
            if (next != g_Input.KbdHead) {
                pkt = &g_Input.KbdBuffer[g_Input.KbdTail];
                pkt->UnitId = 0;
                pkt->MakeCode = (USHORT)(b & 0x7F);
                pkt->Flags = (b & 0x80) ? KEY_BREAK : KEY_MAKE;
                if (g_Input.ExtPrefix) {
                    pkt->Flags |= KEY_E0;
                    g_Input.ExtPrefix = FALSE;
                }
                pkt->Reserved = 0;
                pkt->ExtraInformation = 0;
                g_Input.KbdTail = next;
            }
        }
    }
}

static void DrainSerHardware(void) {
    UCHAR c;
    ULONG next;

    while (READ_PORT_UCHAR((PUCHAR)0x3FD) & 1) {
        c = READ_PORT_UCHAR((PUCHAR)0x3F8);
        next = (g_Input.SerTail + 1) % RAWKBD_BUFFER_SIZE;
        if (next != g_Input.SerHead) {
            g_Input.SerBuffer[g_Input.SerTail] = c;
            g_Input.SerTail = next;
        }
    }
}

static BOOLEAN I8042Isr(PKINTERRUPT Interrupt, PVOID ServiceContext) {
    (void)Interrupt;
    (void)ServiceContext;
    KeAcquireSpinLockAtDpcLevel(&g_Input.Lock);
    DrainI8042Hardware();
    KeReleaseSpinLockFromDpcLevel(&g_Input.Lock);
    return TRUE;
}

static BOOLEAN SerIsr(PKINTERRUPT Interrupt, PVOID ServiceContext) {
    (void)Interrupt;
    (void)ServiceContext;
    KeAcquireSpinLockAtDpcLevel(&g_Input.Lock);
    DrainSerHardware();
    KeReleaseSpinLockFromDpcLevel(&g_Input.Lock);
    return TRUE;
}

static NTSTATUS RawKbdCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS RawKbdRead(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PRAWKBD_DEVEXT devExt = (PRAWKBD_DEVEXT)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG bytesReq = irpSp->Parameters.Read.Length;
    KIRQL oldIrql;

    if (devExt->Kind == DEV_KEYBOARD) {
        PKEYBOARD_INPUT_DATA outBuf = (PKEYBOARD_INPUT_DATA)Irp->AssociatedIrp.SystemBuffer;
        ULONG itemsReq = bytesReq / sizeof(KEYBOARD_INPUT_DATA);
        ULONG itemsCopied = 0;

        if (bytesReq < sizeof(KEYBOARD_INPUT_DATA) || !outBuf) {
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_BUFFER_TOO_SMALL;
        }

        KeAcquireSpinLock(&g_Input.Lock, &oldIrql);
        DrainI8042Hardware();
        while (itemsCopied < itemsReq && g_Input.KbdHead != g_Input.KbdTail) {
            outBuf[itemsCopied++] = g_Input.KbdBuffer[g_Input.KbdHead];
            g_Input.KbdHead = (g_Input.KbdHead + 1) % RAWKBD_BUFFER_SIZE;
        }
        KeReleaseSpinLock(&g_Input.Lock, oldIrql);

        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = itemsCopied * sizeof(KEYBOARD_INPUT_DATA);
        IoCompleteRequest(Irp, (itemsCopied > 0) ? IO_KEYBOARD_INCREMENT : IO_NO_INCREMENT);
        return STATUS_SUCCESS;

    } else if (devExt->Kind == DEV_MOUSE) {
        PMOUSE_INPUT_DATA_PKT outBuf = (PMOUSE_INPUT_DATA_PKT)Irp->AssociatedIrp.SystemBuffer;
        ULONG itemsReq = bytesReq / sizeof(MOUSE_INPUT_DATA_PKT);
        ULONG itemsCopied = 0;

        if (bytesReq < sizeof(MOUSE_INPUT_DATA_PKT) || !outBuf) {
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_BUFFER_TOO_SMALL;
        }

        KeAcquireSpinLock(&g_Input.Lock, &oldIrql);
        DrainI8042Hardware();
        while (itemsCopied < itemsReq && g_Input.MouseHead != g_Input.MouseTail) {
            outBuf[itemsCopied++] = g_Input.MouseBuffer[g_Input.MouseHead];
            g_Input.MouseHead = (g_Input.MouseHead + 1) % RAWMOUSE_BUFFER_SIZE;
        }
        KeReleaseSpinLock(&g_Input.Lock, oldIrql);

        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = itemsCopied * sizeof(MOUSE_INPUT_DATA_PKT);
        IoCompleteRequest(Irp, (itemsCopied > 0) ? IO_MOUSE_INCREMENT : IO_NO_INCREMENT);
        return STATUS_SUCCESS;

    } else if (devExt->Kind == DEV_SERIAL) {
        PUCHAR outBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        ULONG bytesCopied = 0;

        KeAcquireSpinLock(&g_Input.Lock, &oldIrql);
        DrainSerHardware();
        while (bytesCopied < bytesReq && g_Input.SerHead != g_Input.SerTail && outBuf) {
            outBuf[bytesCopied++] = g_Input.SerBuffer[g_Input.SerHead];
            g_Input.SerHead = (g_Input.SerHead + 1) % RAWKBD_BUFFER_SIZE;
        }
        KeReleaseSpinLock(&g_Input.Lock, oldIrql);

        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = bytesCopied;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS RawKbdWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PRAWKBD_DEVEXT devExt = (PRAWKBD_DEVEXT)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG bytesToWrite = irpSp->Parameters.Write.Length;
    PUCHAR inBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    ULONG i;

    if (devExt->Kind == DEV_SERIAL && inBuf && bytesToWrite > 0) {
        for (i = 0; i < bytesToWrite; i++) {
            int timeout = 50000;
            while (!(READ_PORT_UCHAR((PUCHAR)0x3FD) & 0x20) && --timeout > 0);
            WRITE_PORT_UCHAR((PUCHAR)0x3F8, inBuf[i]);
        }
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = bytesToWrite;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS RawKbdDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    KIRQL oldIrql;

    (void)DeviceObject;

    if (code == IOCTL_MOUSE_INJECT && inLen >= sizeof(MOUSE_INPUT_DATA_PKT) && buf) {
        PMOUSE_INPUT_DATA_PKT inPkt = (PMOUSE_INPUT_DATA_PKT)buf;
        ULONG next;
        KeAcquireSpinLock(&g_Input.Lock, &oldIrql);
        next = (g_Input.MouseTail + 1) % RAWMOUSE_BUFFER_SIZE;
        if (next != g_Input.MouseHead) {
            g_Input.MouseBuffer[g_Input.MouseTail] = *inPkt;
            g_Input.MouseTail = next;
        }
        KeReleaseSpinLock(&g_Input.Lock, oldIrql);
    } else if (code == IOCTL_KBD_INJECT && inLen >= sizeof(KEYBOARD_INPUT_DATA) && buf) {
        PKEYBOARD_INPUT_DATA inKey = (PKEYBOARD_INPUT_DATA)buf;
        ULONG next;
        KeAcquireSpinLock(&g_Input.Lock, &oldIrql);
        next = (g_Input.KbdTail + 1) % RAWKBD_BUFFER_SIZE;
        if (next != g_Input.KbdHead) {
            g_Input.KbdBuffer[g_Input.KbdTail] = *inKey;
            g_Input.KbdTail = next;
        }
        KeReleaseSpinLock(&g_Input.Lock, oldIrql);
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING kbdName, kbdSym, kbdSym2;
    UNICODE_STRING mouName, mouSym, mouSym2;
    UNICODE_STRING serName, serSym;
    PDEVICE_OBJECT kbdDev = NULL, mouDev = NULL, serDev = NULL;
    PRAWKBD_DEVEXT kbdExt, mouExt, serExt;
    NTSTATUS status;
    ULONG vector;
    KIRQL irql;
    KAFFINITY affinity;

    (void)RegistryPath;

    RtlZeroMemory(&g_Input, sizeof(g_Input));
    KeInitializeSpinLock(&g_Input.Lock);

    SerDbgPrint("\n=======================================================\n");
    SerDbgPrint("[rawkbd] Initializing Keyboard + Mouse + Serial Driver\n");
    SerDbgPrint("=======================================================\n");

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = RawKbdCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = RawKbdCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = RawKbdCreateClose;
    DriverObject->MajorFunction[IRP_MJ_READ]           = RawKbdRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE]          = RawKbdWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RawKbdDeviceControl;

    /* 1. Create \Device\RawKeyboard */
    RtlInitUnicodeString(&kbdName, L"\\Device\\RawKeyboard");
    RtlInitUnicodeString(&kbdSym,  L"\\DosDevices\\RawKeyboard");
    RtlInitUnicodeString(&kbdSym2, L"\\DosDevices\\kbd0");
    status = IoCreateDevice(DriverObject, sizeof(RAWKBD_DEVEXT), &kbdName, FILE_DEVICE_KEYBOARD, 0, FALSE, &kbdDev);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    kbdDev->Flags |= DO_BUFFERED_IO;
    kbdExt = (PRAWKBD_DEVEXT)kbdDev->DeviceExtension;
    RtlZeroMemory(kbdExt, sizeof(RAWKBD_DEVEXT));
    kbdExt->Kind = DEV_KEYBOARD;
    kbdExt->DeviceObject = kbdDev;
    IoCreateSymbolicLink(&kbdSym, &kbdName);
    IoCreateSymbolicLink(&kbdSym2, &kbdName);

    /* 2. Create \Device\RawMouse */
    RtlInitUnicodeString(&mouName, L"\\Device\\RawMouse");
    RtlInitUnicodeString(&mouSym,  L"\\DosDevices\\RawMouse");
    RtlInitUnicodeString(&mouSym2, L"\\DosDevices\\mouse0");
    status = IoCreateDevice(DriverObject, sizeof(RAWKBD_DEVEXT), &mouName, FILE_DEVICE_MOUSE, 0, FALSE, &mouDev);
    if (NT_SUCCESS(status) && mouDev) {
        mouDev->Flags |= DO_BUFFERED_IO;
        mouExt = (PRAWKBD_DEVEXT)mouDev->DeviceExtension;
        RtlZeroMemory(mouExt, sizeof(RAWKBD_DEVEXT));
        mouExt->Kind = DEV_MOUSE;
        mouExt->DeviceObject = mouDev;
        IoCreateSymbolicLink(&mouSym, &mouName);
        IoCreateSymbolicLink(&mouSym2, &mouName);
        mouDev->Flags &= ~DO_DEVICE_INITIALIZING;
    }

    /* Initialize i8042 hardware (Keyboard + PS/2 Auxiliary Mouse) */
    InitI8042AndMouse();

    /* Connect IRQ 1 (Keyboard) */
    vector = HalGetInterruptVector(Isa, 0, 1, 1, &irql, &affinity);
    if (vector) {
        IoConnectInterrupt(&g_Input.KbdInterrupt, I8042Isr, NULL, NULL, vector, irql, irql, Latched, FALSE, affinity, FALSE);
    }

    /* Connect IRQ 12 (PS/2 Mouse) */
    vector = HalGetInterruptVector(Isa, 0, 12, 12, &irql, &affinity);
    if (vector) {
        IoConnectInterrupt(&g_Input.MouseInterrupt, I8042Isr, NULL, NULL, vector, irql, irql, Latched, FALSE, affinity, FALSE);
    }

    kbdDev->Flags &= ~DO_DEVICE_INITIALIZING;

    /* 3. Create \Device\Serial0 */
    RtlInitUnicodeString(&serName, L"\\Device\\Serial0");
    RtlInitUnicodeString(&serSym,  L"\\DosDevices\\COM1");
    status = IoCreateDevice(DriverObject, sizeof(RAWKBD_DEVEXT), &serName, FILE_DEVICE_SERIAL_PORT, 0, FALSE, &serDev);
    if (NT_SUCCESS(status) && serDev) {
        serDev->Flags |= DO_BUFFERED_IO;
        serExt = (PRAWKBD_DEVEXT)serDev->DeviceExtension;
        RtlZeroMemory(serExt, sizeof(RAWKBD_DEVEXT));
        serExt->Kind = DEV_SERIAL;
        serExt->DeviceObject = serDev;
        IoCreateSymbolicLink(&serSym, &serName);

        vector = HalGetInterruptVector(Isa, 0, 4, 4, &irql, &affinity);
        if (vector) {
            IoConnectInterrupt(&g_Input.SerInterrupt, SerIsr, NULL, NULL, vector, irql, irql, Latched, FALSE, affinity, FALSE);
            WRITE_PORT_UCHAR((PUCHAR)0x3F9, 0x01);
            WRITE_PORT_UCHAR((PUCHAR)0x3FC, 0x0B);
        }
        serDev->Flags &= ~DO_DEVICE_INITIALIZING;
    }

    SerDbgPrint("[rawkbd] DriverEntry completed (Kbd + Mouse + COM1 active).\n");
    return STATUS_SUCCESS;
}
