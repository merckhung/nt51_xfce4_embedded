/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * minimal_rootfs/drivers/rawkbd/rawkbd.c
 * Native Console Input Driver for Embedded Windows XP (NT 5.1)
 * Creates \Device\RawKeyboard (PS/2 i8042) and \Device\Serial0 (COM1 16550 UART)
 */

#include <ntddk.h>

#define RAWKBD_BUFFER_SIZE 256

typedef struct _KEYBOARD_INPUT_DATA {
    USHORT UnitId;
    USHORT MakeCode;
    USHORT Flags;
    USHORT Reserved;
    ULONG  ExtraInformation;
} KEYBOARD_INPUT_DATA, *PKEYBOARD_INPUT_DATA;

#define KEY_MAKE   0
#define KEY_BREAK  1
#define KEY_E0     2
#define KEY_E1     4

typedef enum _DEVICE_KIND {
    DEV_KEYBOARD = 1,
    DEV_SERIAL   = 2
} DEVICE_KIND;

typedef struct _RAWKBD_DEVEXT {
    DEVICE_KIND Kind;
    PDEVICE_OBJECT DeviceObject;
    PKINTERRUPT InterruptObject;
    KSPIN_LOCK SpinLock;

    /* PS/2 Keyboard state */
    KEYBOARD_INPUT_DATA KbdBuffer[RAWKBD_BUFFER_SIZE];
    ULONG KbdHead;
    ULONG KbdTail;
    BOOLEAN ExtPrefix;
    int     PauseSkip;

    /* COM1 Serial state */
    UCHAR SerBuffer[RAWKBD_BUFFER_SIZE];
    ULONG SerHead;
    ULONG SerTail;
} RAWKBD_DEVEXT, *PRAWKBD_DEVEXT;

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

/*
 * Hardware i8042 PS/2 controller initialization:
 * 1. Flush any unread bytes in output buffer (port 0x60).
 * 2. Read Controller Command Byte (CCB) via command 0x20.
 * 3. Enable IRQ 1 (bit 0), enable clock (clear bit 4), enable translation to Set 1 (bit 6).
 * 4. Write CCB back via command 0x60.
 * 5. Enable keyboard interface via command 0xAE.
 * 6. Send 0xF4 (Enable scanning) to keyboard data port 0x60.
 */
static void InitI8042(void) {
    int limit;
    UCHAR ccb = 0;

    SerDbgPrint("[rawkbd] InitI8042: configuring PS/2 controller...\n");

    /* 1. Flush output buffer */
    limit = 2000;
    while ((READ_PORT_UCHAR((PUCHAR)0x64) & 1) && --limit > 0) {
        READ_PORT_UCHAR((PUCHAR)0x60);
    }

    /* 2. Read CCB (cmd 0x20) */
    limit = 20000;
    while ((READ_PORT_UCHAR((PUCHAR)0x64) & 2) && --limit > 0);
    WRITE_PORT_UCHAR((PUCHAR)0x64, 0x20);

    limit = 20000;
    while (!(READ_PORT_UCHAR((PUCHAR)0x64) & 1) && --limit > 0);
    if (limit > 0) {
        ccb = READ_PORT_UCHAR((PUCHAR)0x60);
        SerDbgPrint("[rawkbd] InitI8042: read CCB = 0x");
        SerDbgHex(ccb);
        SerDbgPrint("\n");
    }

    /* 3. Modify CCB:
     * Bit 0: Enable Keyboard Interrupt (1)
     * Bit 4: Disable Keyboard Clock (0 = enable)
     * Bit 6: Enable Translation (1 = Set 1 XT translation)
     */
    ccb |= 0x01;  /* Enable IRQ 1 */
    ccb &= ~0x10; /* Enable keyboard clock */
    ccb |= 0x40;  /* Enable translation to Set 1 */

    /* 4. Write CCB (cmd 0x60) */
    limit = 20000;
    while ((READ_PORT_UCHAR((PUCHAR)0x64) & 2) && --limit > 0);
    WRITE_PORT_UCHAR((PUCHAR)0x64, 0x60);

    limit = 20000;
    while ((READ_PORT_UCHAR((PUCHAR)0x64) & 2) && --limit > 0);
    WRITE_PORT_UCHAR((PUCHAR)0x60, ccb);

    SerDbgPrint("[rawkbd] InitI8042: wrote new CCB = 0x");
    SerDbgHex(ccb);
    SerDbgPrint("\n");

    /* 5. Enable Keyboard interface (cmd 0xAE) */
    limit = 20000;
    while ((READ_PORT_UCHAR((PUCHAR)0x64) & 2) && --limit > 0);
    WRITE_PORT_UCHAR((PUCHAR)0x64, 0xAE);

    /* 6. Send 0xF4 (Enable scanning) to keyboard data port */
    limit = 20000;
    while ((READ_PORT_UCHAR((PUCHAR)0x64) & 2) && --limit > 0);
    WRITE_PORT_UCHAR((PUCHAR)0x60, 0xF4);

    SerDbgPrint("[rawkbd] InitI8042: initialization complete.\n");
}

/*
 * Low-level routine to drain scancodes from i8042 hardware ports into ring buffer
 */
static void DrainKbdHardwareLocked(PRAWKBD_DEVEXT devExt) {
    UCHAR status, sc;
    ULONG next;
    PKEYBOARD_INPUT_DATA pkt;

    while ((status = READ_PORT_UCHAR((PUCHAR)0x64)) & 1) {
        sc = READ_PORT_UCHAR((PUCHAR)0x60);

        /* Ignore PS/2 mouse bytes (AUX bit 5) */
        if (status & 0x20) {
            continue;
        }

        if (devExt->PauseSkip > 0) {
            devExt->PauseSkip--;
            continue;
        }
        if (sc == 0xE1) {
            devExt->PauseSkip = 5;
            continue;
        }
        if (sc == 0xE0) {
            devExt->ExtPrefix = TRUE;
            continue;
        }

        next = (devExt->KbdTail + 1) % RAWKBD_BUFFER_SIZE;
        if (next != devExt->KbdHead) {
            pkt = &devExt->KbdBuffer[devExt->KbdTail];
            pkt->UnitId = 0;
            pkt->MakeCode = (USHORT)(sc & 0x7F);
            pkt->Flags = (sc & 0x80) ? KEY_BREAK : KEY_MAKE;
            if (devExt->ExtPrefix) {
                pkt->Flags |= KEY_E0;
                devExt->ExtPrefix = FALSE;
            }
            pkt->Reserved = 0;
            pkt->ExtraInformation = 0;
            devExt->KbdTail = next;

            SerDbgPrint("[rawkbd] Key: sc=0x");
            SerDbgHex(sc);
            SerDbgPrint((sc & 0x80) ? " (break)\n" : " (make)\n");
        }
    }
}

/*
 * Low-level routine to drain serial bytes from COM1 UART ports into ring buffer
 */
static void DrainSerHardwareLocked(PRAWKBD_DEVEXT devExt) {
    UCHAR c;
    ULONG next;

    while (READ_PORT_UCHAR((PUCHAR)0x3FD) & 1) {
        c = READ_PORT_UCHAR((PUCHAR)0x3F8);
        next = (devExt->SerTail + 1) % RAWKBD_BUFFER_SIZE;
        if (next != devExt->SerHead) {
            devExt->SerBuffer[devExt->SerTail] = c;
            devExt->SerTail = next;
        }
    }
}

static BOOLEAN KbdIsr(PKINTERRUPT Interrupt, PVOID ServiceContext) {
    PRAWKBD_DEVEXT devExt = (PRAWKBD_DEVEXT)ServiceContext;
    (void)Interrupt;

    DrainKbdHardwareLocked(devExt);
    return TRUE;
}

static BOOLEAN SerIsr(PKINTERRUPT Interrupt, PVOID ServiceContext) {
    PRAWKBD_DEVEXT devExt = (PRAWKBD_DEVEXT)ServiceContext;
    (void)Interrupt;

    DrainSerHardwareLocked(devExt);
    return TRUE;
}

/* Context for KeSynchronizeExecution with KbdIsr */
typedef struct _KBD_READ_SYNC_CTX {
    PRAWKBD_DEVEXT devExt;
    PKEYBOARD_INPUT_DATA outBuf;
    ULONG itemsReq;
    ULONG itemsCopied;
} KBD_READ_SYNC_CTX, *PKBD_READ_SYNC_CTX;

static BOOLEAN SyncKbdRead(PVOID Context) {
    PKBD_READ_SYNC_CTX ctx = (PKBD_READ_SYNC_CTX)Context;
    PRAWKBD_DEVEXT devExt = ctx->devExt;
    ULONG itemsAvail, toCopy, i;

    /* Always drain any pending hardware bytes first */
    DrainKbdHardwareLocked(devExt);

    if (devExt->KbdHead == devExt->KbdTail) {
        ctx->itemsCopied = 0;
        return TRUE;
    }

    itemsAvail = (devExt->KbdTail >= devExt->KbdHead) ?
                 (devExt->KbdTail - devExt->KbdHead) :
                 (RAWKBD_BUFFER_SIZE - devExt->KbdHead + devExt->KbdTail);

    toCopy = (ctx->itemsReq < itemsAvail) ? ctx->itemsReq : itemsAvail;
    for (i = 0; i < toCopy; i++) {
        ctx->outBuf[i] = devExt->KbdBuffer[devExt->KbdHead];
        devExt->KbdHead = (devExt->KbdHead + 1) % RAWKBD_BUFFER_SIZE;
    }
    ctx->itemsCopied = toCopy;
    return TRUE;
}

/* Context for KeSynchronizeExecution with SerIsr */
typedef struct _SER_READ_SYNC_CTX {
    PRAWKBD_DEVEXT devExt;
    PUCHAR outBuf;
    ULONG bytesReq;
    ULONG bytesCopied;
} SER_READ_SYNC_CTX, *PSER_READ_SYNC_CTX;

static BOOLEAN SyncSerRead(PVOID Context) {
    PSER_READ_SYNC_CTX ctx = (PSER_READ_SYNC_CTX)Context;
    PRAWKBD_DEVEXT devExt = ctx->devExt;
    ULONG bytesAvail, toCopy, i;

    /* Always drain any pending hardware serial bytes first */
    DrainSerHardwareLocked(devExt);

    if (devExt->SerHead == devExt->SerTail) {
        ctx->bytesCopied = 0;
        return TRUE;
    }

    bytesAvail = (devExt->SerTail >= devExt->SerHead) ?
                 (devExt->SerTail - devExt->SerHead) :
                 (RAWKBD_BUFFER_SIZE - devExt->SerHead + devExt->SerTail);

    toCopy = (ctx->bytesReq < bytesAvail) ? ctx->bytesReq : bytesAvail;
    for (i = 0; i < toCopy; i++) {
        ctx->outBuf[i] = devExt->SerBuffer[devExt->SerHead];
        devExt->SerHead = (devExt->SerHead + 1) % RAWKBD_BUFFER_SIZE;
    }
    ctx->bytesCopied = toCopy;
    return TRUE;
}

static NTSTATUS RawKbdCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS RawKbdCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
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

    if (devExt->Kind == DEV_KEYBOARD) {
        KBD_READ_SYNC_CTX ctx;

        if (bytesReq < sizeof(KEYBOARD_INPUT_DATA)) {
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_BUFFER_TOO_SMALL;
        }

        ctx.devExt = devExt;
        ctx.outBuf = (PKEYBOARD_INPUT_DATA)Irp->AssociatedIrp.SystemBuffer;
        ctx.itemsReq = bytesReq / sizeof(KEYBOARD_INPUT_DATA);
        ctx.itemsCopied = 0;

        if (devExt->InterruptObject) {
            KeSynchronizeExecution(devExt->InterruptObject, SyncKbdRead, &ctx);
        } else {
            KIRQL oldIrql;
            KeAcquireSpinLock(&devExt->SpinLock, &oldIrql);
            SyncKbdRead(&ctx);
            KeReleaseSpinLock(&devExt->SpinLock, oldIrql);
        }

        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = ctx.itemsCopied * sizeof(KEYBOARD_INPUT_DATA);
        IoCompleteRequest(Irp, (ctx.itemsCopied > 0) ? IO_KEYBOARD_INCREMENT : IO_NO_INCREMENT);
        return STATUS_SUCCESS;

    } else if (devExt->Kind == DEV_SERIAL) {
        SER_READ_SYNC_CTX ctx;

        ctx.devExt = devExt;
        ctx.outBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        ctx.bytesReq = bytesReq;
        ctx.bytesCopied = 0;

        if (devExt->InterruptObject) {
            KeSynchronizeExecution(devExt->InterruptObject, SyncSerRead, &ctx);
        } else {
            KIRQL oldIrql;
            KeAcquireSpinLock(&devExt->SpinLock, &oldIrql);
            SyncSerRead(&ctx);
            KeReleaseSpinLock(&devExt->SpinLock, oldIrql);
        }

        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = ctx.bytesCopied;
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
    (void)DeviceObject;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING kbdName, kbdSym, serName, serSym;
    PDEVICE_OBJECT kbdDev = NULL, serDev = NULL;
    PRAWKBD_DEVEXT kbdExt, serExt;
    NTSTATUS status;
    ULONG vector;
    KIRQL irql;
    KAFFINITY affinity;

    (void)RegistryPath;

    SerDbgPrint("\n=======================================================\n");
    SerDbgPrint("[rawkbd] DriverEntry: initializing native input driver\n");
    SerDbgPrint("=======================================================\n");

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = RawKbdCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = RawKbdCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = RawKbdCleanup;
    DriverObject->MajorFunction[IRP_MJ_READ]           = RawKbdRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE]          = RawKbdWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RawKbdDeviceControl;

    /* 1. Create \Device\RawKeyboard */
    RtlInitUnicodeString(&kbdName, L"\\Device\\RawKeyboard");
    RtlInitUnicodeString(&kbdSym,  L"\\DosDevices\\RawKeyboard");
    status = IoCreateDevice(
        DriverObject,
        sizeof(RAWKBD_DEVEXT),
        &kbdName,
        FILE_DEVICE_KEYBOARD,
        0,
        FALSE,
        &kbdDev
    );
    if (!NT_SUCCESS(status)) {
        SerDbgPrint("[rawkbd] ERROR: failed to create \\Device\\RawKeyboard\n");
        return status;
    }

    kbdDev->Flags |= DO_BUFFERED_IO;
    kbdExt = (PRAWKBD_DEVEXT)kbdDev->DeviceExtension;
    RtlZeroMemory(kbdExt, sizeof(RAWKBD_DEVEXT));
    kbdExt->Kind = DEV_KEYBOARD;
    kbdExt->DeviceObject = kbdDev;
    KeInitializeSpinLock(&kbdExt->SpinLock);

    IoCreateSymbolicLink(&kbdSym, &kbdName);

    /* Initialize i8042 controller and keyboard hardware */
    InitI8042();

    /* Connect IRQ 1 for keyboard */
    vector = HalGetInterruptVector(Isa, 0, 1, 1, &irql, &affinity);
    SerDbgPrint("[rawkbd] Keyboard IRQ 1 vector = ");
    SerDbgHex((UCHAR)vector);
    SerDbgPrint(", irql = ");
    SerDbgHex((UCHAR)irql);
    SerDbgPrint("\n");

    if (vector) {
        status = IoConnectInterrupt(
            &kbdExt->InterruptObject,
            KbdIsr,
            kbdExt,
            NULL,
            vector,
            irql,
            irql,
            Latched,
            FALSE,
            affinity,
            FALSE
        );
        if (NT_SUCCESS(status)) {
            SerDbgPrint("[rawkbd] Successfully connected to IRQ 1 interrupt!\n");
        } else {
            SerDbgPrint("[rawkbd] WARNING: IoConnectInterrupt(IRQ 1) status = 0x");
            SerDbgHex((UCHAR)(status >> 24));
            SerDbgHex((UCHAR)(status >> 16));
            SerDbgHex((UCHAR)(status >> 8));
            SerDbgHex((UCHAR)status);
            SerDbgPrint("\n");
            kbdExt->InterruptObject = NULL;
        }
    }
    kbdDev->Flags &= ~DO_DEVICE_INITIALIZING;

    /* 2. Create \Device\Serial0 */
    RtlInitUnicodeString(&serName, L"\\Device\\Serial0");
    RtlInitUnicodeString(&serSym,  L"\\DosDevices\\COM1");
    status = IoCreateDevice(
        DriverObject,
        sizeof(RAWKBD_DEVEXT),
        &serName,
        FILE_DEVICE_SERIAL_PORT,
        0,
        FALSE,
        &serDev
    );
    if (NT_SUCCESS(status) && serDev) {
        serDev->Flags |= DO_BUFFERED_IO;
        serExt = (PRAWKBD_DEVEXT)serDev->DeviceExtension;
        RtlZeroMemory(serExt, sizeof(RAWKBD_DEVEXT));
        serExt->Kind = DEV_SERIAL;
        serExt->DeviceObject = serDev;
        KeInitializeSpinLock(&serExt->SpinLock);

        IoCreateSymbolicLink(&serSym, &serName);

        /* Connect IRQ 4 for COM1 serial */
        vector = HalGetInterruptVector(Isa, 0, 4, 4, &irql, &affinity);
        if (vector) {
            status = IoConnectInterrupt(
                &serExt->InterruptObject,
                SerIsr,
                serExt,
                NULL,
                vector,
                irql,
                irql,
                Latched,
                FALSE,
                affinity,
                FALSE
            );
            if (NT_SUCCESS(status)) {
                SerDbgPrint("[rawkbd] Successfully connected to IRQ 4 interrupt!\n");
            } else {
                serExt->InterruptObject = NULL;
            }
            /* Enable Received Data Interrupt (IER = 1) and OUT2 (MCR = 0x0B) */
            WRITE_PORT_UCHAR((PUCHAR)0x3F9, 0x01);
            WRITE_PORT_UCHAR((PUCHAR)0x3FC, 0x0B);
        }
        serDev->Flags &= ~DO_DEVICE_INITIALIZING;
    }

    SerDbgPrint("[rawkbd] DriverEntry completed successfully.\n");
    return STATUS_SUCCESS;
}
