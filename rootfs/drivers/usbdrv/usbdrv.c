/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rootfs/drivers/usbdrv/usbdrv.c
 * Windows XP (NT 5.1) Universal Kernel-Mode USB Host Controller & Device Driver:
 *   - PCI USB controller discovery; transfers implemented for UHCI only
 *   - UHCI Hardware DMA Schedule (Frame List + Queue Head + Transfer Descriptors)
 *   - Full USB Control EP0 Enumeration (GET_DESCRIPTOR Device/Config/String, SET_ADDRESS, SET_CONFIG)
 *   - USB HID Boot Keyboard & Mouse Polling -> Direct Injection into \Device\RawKeyboard & \Device\RawMouse
 *   - USB Mass Storage Bulk-Only Transport (BOT CBW/CSW SCSI INQUIRY, READ CAPACITY, READ10)
 *   - Exposes \Device\Usb0 (\DosDevices\usb0 -> /dev/usb0) and \Device\UsbDisk0 (\DosDevices\sda -> /dev/sda)
 */

#include <ntddk.h>
#include "usbdrv.h"

/* RawInput IOCTLs shared with rawkbd.sys */
#define FILE_DEVICE_RAWINPUT 0x00008321
#define IOCTL_MOUSE_INJECT   CTL_CODE(FILE_DEVICE_RAWINPUT, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KBD_INJECT     CTL_CODE(FILE_DEVICE_RAWINPUT, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _KEYBOARD_INPUT_DATA {
    USHORT UnitId;
    USHORT MakeCode;
    USHORT Flags;
    USHORT Reserved;
    ULONG  ExtraInformation;
} KEYBOARD_INPUT_DATA;

typedef struct _MOUSE_INPUT_DATA_PKT {
    LONG   DeltaX;
    LONG   DeltaY;
    ULONG  Buttons;
    ULONG  RawStatus;
} MOUSE_INPUT_DATA_PKT;

/* UHCI I/O Registers */
#define UHCI_USBCMD     0x00
#define UHCI_USBSTS     0x02
#define UHCI_USBINTR    0x04
#define UHCI_FRNUM      0x06
#define UHCI_FRBASEADD  0x08
#define UHCI_SOFMOD     0x0C
#define UHCI_PORTSC1    0x10
#define UHCI_PORTSC2    0x12

#define UHCI_CMD_RS     0x0001
#define UHCI_CMD_HCRESET 0x0002
#define UHCI_CMD_GRESET 0x0004
#define UHCI_CMD_CF     0x0040
#define UHCI_CMD_MAXP   0x0080

/* UHCI PID Tokens */
#define UHCI_PID_SETUP  0x2D
#define UHCI_PID_IN     0x69
#define UHCI_PID_OUT    0xE1

#define UHCI_PTR_TERM   0x00000001UL
#define UHCI_PTR_QH     0x00000002UL
#define UHCI_PTR_DEPTH  0x00000004UL

#pragma pack(push, 1)

typedef struct _UHCI_TD {
    volatile ULONG LinkPtr;
    volatile ULONG CtrlStatus;
    volatile ULONG Token;
    volatile ULONG BufferPtr;
    ULONG          SwPad[4];    /* Pad to 32 bytes (16-byte hardware alignment) */
} UHCI_TD;

typedef struct _UHCI_QH {
    volatile ULONG HeadLinkPtr;
    volatile ULONG ElementLinkPtr;
    ULONG          SwPad[2];
} UHCI_QH;

typedef struct _USB_SETUP_PKT {
    UCHAR  bmRequestType;
    UCHAR  bRequest;
    USHORT wValue;
    USHORT wIndex;
    USHORT wLength;
} USB_SETUP_PKT;

typedef struct _USB_DEVICE_DESC {
    UCHAR  bLength;
    UCHAR  bDescriptorType;
    USHORT bcdUSB;
    UCHAR  bDeviceClass;
    UCHAR  bDeviceSubClass;
    UCHAR  bDeviceProtocol;
    UCHAR  bMaxPacketSize0;
    USHORT idVendor;
    USHORT idProduct;
    USHORT bcdDevice;
    UCHAR  iManufacturer;
    UCHAR  iProduct;
    UCHAR  iSerialNumber;
    UCHAR  bNumConfigurations;
} USB_DEVICE_DESC;

typedef struct _USB_CONFIG_DESC {
    UCHAR  bLength;
    UCHAR  bDescriptorType;
    USHORT wTotalLength;
    UCHAR  bNumInterfaces;
    UCHAR  bConfigurationValue;
    UCHAR  iConfiguration;
    UCHAR  bmAttributes;
    UCHAR  bMaxPower;
} USB_CONFIG_DESC;

typedef struct _USB_INTERFACE_DESC {
    UCHAR  bLength;
    UCHAR  bDescriptorType;
    UCHAR  bInterfaceNumber;
    UCHAR  bAlternateSetting;
    UCHAR  bNumEndpoints;
    UCHAR  bInterfaceClass;
    UCHAR  bInterfaceSubClass;
    UCHAR  bInterfaceProtocol;
    UCHAR  iInterface;
} USB_INTERFACE_DESC;

typedef struct _USB_ENDPOINT_DESC {
    UCHAR  bLength;
    UCHAR  bDescriptorType;
    UCHAR  bEndpointAddress;
    UCHAR  bmAttributes;
    USHORT wMaxPacketSize;
    UCHAR  bInterval;
} USB_ENDPOINT_DESC;

/* USB Mass Storage Bulk-Only Transport CBW / CSW */
typedef struct _USB_MSC_CBW {
    ULONG  dCBWSignature;          /* 0x43425355 'USBC' */
    ULONG  dCBWTag;
    ULONG  dCBWDataTransferLength;
    UCHAR  bmCBWFlags;             /* 0x80 = Data-In, 0x00 = Data-Out */
    UCHAR  bCBWLUN;
    UCHAR  bCBWCBLength;
    UCHAR  CBWCB[16];
} USB_MSC_CBW;

typedef struct _USB_MSC_CSW {
    ULONG  dCSWSignature;          /* 0x53425355 'USBS' */
    ULONG  dCSWTag;
    ULONG  dCSWDataResidue;
    UCHAR  bCSWStatus;
} USB_MSC_CSW;

#pragma pack(pop)

/* ========================================================================= */
/* UHCI DMA Pool Layout (2 Pages = 8192 Bytes)                               */
/*   Offset 0x0000..0x0FFF: 1024-entry Frame List (4096 bytes)               */
/*   Offset 0x1000..0x101F: Primary Queue Head (QH)                          */
/*   Offset 0x1020..0x141F: 32 Transfer Descriptors (TDs, 32 bytes each)     */
/*   Offset 0x1420..0x143F: Setup Packet Buffer                              */
/*   Offset 0x1440..0x147F: CBW / CSW Buffers                                */
/*   Offset 0x1480..0x17FF: Data Buffer (896 bytes)                          */
/*   Offset 0x1800..0x1FFF: Periodic HID Poll TD + 16-byte Report Buffers    */
/* ========================================================================= */

#define UHCI_DMA_SIZE       8192

typedef struct _UHCI_DMA_STATE {
    PUCHAR            VirtBase;
    PHYSICAL_ADDRESS  PhysBase;
    PULONG            FrameList;
    ULONG             FrameListPhys;
    UHCI_QH          *Qh;
    ULONG             QhPhys;
    UHCI_TD          *Tds;
    ULONG             TdsPhys;
    USB_SETUP_PKT    *SetupBuf;
    ULONG             SetupPhys;
    USB_MSC_CBW      *CbwBuf;
    ULONG             CbwPhys;
    USB_MSC_CSW      *CswBuf;
    ULONG             CswPhys;
    PUCHAR            DataBuf;
    ULONG             DataPhys;
} UHCI_DMA_STATE;

/* Global USB Stack State */
static USB_STACK_INFO  g_UsbInfo;
static UHCI_DMA_STATE  g_UhciDma;
static KSPIN_LOCK      g_UsbLock;
static KTIMER          g_HidTimer;
static KDPC            g_HidDpc;
static BOOLEAN         g_TimerRunning = FALSE;
static UCHAR           g_PrevKbdReport[8];
static UCHAR           g_DataToggleIn[USB_MAX_DEVICES];
static UCHAR           g_DataToggleOut[USB_MAX_DEVICES];
static ULONG           g_MscTag = 1;

/* Cached pointers to \Device\RawKeyboard and \Device\RawMouse for direct HID injection */
static PDEVICE_OBJECT  g_RawKbdDev   = NULL;
static PFILE_OBJECT    g_RawKbdFile  = NULL;
static PDEVICE_OBJECT  g_RawMouDev   = NULL;
static PFILE_OBJECT    g_RawMouFile  = NULL;

/* ========================================================================= */
/* Serial Debug Helper (COM1 0x3F8)                                          */
/* ========================================================================= */

static void UsbDbgPutc(char c) {
    int timeout = 30000;
    while (!(READ_PORT_UCHAR((PUCHAR)0x3FD) & 0x20) && --timeout > 0);
    WRITE_PORT_UCHAR((PUCHAR)0x3F8, (UCHAR)c);
}

static void UsbDbgPrint(const char *s) {
    while (*s) {
        if (*s == '\n') UsbDbgPutc('\r');
        UsbDbgPutc(*s++);
    }
}

static void UsbDbgHex16(USHORT v) {
    static const char hex[] = "0123456789ABCDEF";
    UsbDbgPutc(hex[(v >> 12) & 0xF]);
    UsbDbgPutc(hex[(v >> 8)  & 0xF]);
    UsbDbgPutc(hex[(v >> 4)  & 0xF]);
    UsbDbgPutc(hex[v & 0xF]);
}

static void UsbCopyStr(char *dst, int max_len, const char *src) {
    int i = 0;
    if (!src) { dst[0] = '\0'; return; }
    while (src[i] && i < max_len - 1) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

/* ========================================================================= */
/* USB HID Usage ID (0x04..0x73) -> PS/2 Set-1 Scancode Translation Table    */
/* ========================================================================= */

static const UCHAR g_HidToSet1[128] = {
    0x00, 0x00, 0x00, 0x00, 0x1E, 0x30, 0x2E, 0x20, /* 00..07: a b c d */
    0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, /* 08..0F: e f g h i j k l */
    0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, /* 10..17: m n o p q r s t */
    0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C, 0x02, 0x03, /* 18..1F: u v w x y z 1 2 */
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, /* 20..27: 3 4 5 6 7 8 9 0 */
    0x1C, 0x01, 0x0E, 0x0F, 0x39, 0x0C, 0x0D, 0x1A, /* 28..2F: Enter Esc Backspace Tab Space - = [ */
    0x1B, 0x2B, 0x2B, 0x27, 0x28, 0x29, 0x33, 0x34, /* 30..37: ] \ # ; ' ` , . */
    0x35, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, /* 38..3F: / Caps F1 F2 F3 F4 F5 F6 */
    0x41, 0x42, 0x43, 0x44, 0x57, 0x58, 0x37, 0x46, /* 40..47: F7 F8 F9 F10 F11 F12 PrtSc ScrLk */
    0x00, 0x52, 0x47, 0x49, 0x53, 0x4F, 0x51, 0x4D, /* 48..4F: Pause Ins Home PgUp Del End PgDn Right */
    0x4B, 0x50, 0x48, 0x45, 0x35, 0x37, 0x4A, 0x4E, /* 50..57: Left Down Up NumLk KP/ KP* KP- KP+ */
    0x1C, 0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, /* 58..5F: KPEnter KP1..KP7 */
    0x48, 0x49, 0x52, 0x53                          /* 60..63: KP8 KP9 KP0 KP. */
};

static void UsbBindRawInputDevices(void) {
    UNICODE_STRING uKbd, uMou;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;
    if (!g_RawKbdDev) {
        RtlInitUnicodeString(&uKbd, L"\\Device\\RawKeyboard");
        IoGetDeviceObjectPointer(&uKbd, FILE_ALL_ACCESS, &g_RawKbdFile, &g_RawKbdDev);
    }
    if (!g_RawMouDev) {
        RtlInitUnicodeString(&uMou, L"\\Device\\RawMouse");
        IoGetDeviceObjectPointer(&uMou, FILE_ALL_ACCESS, &g_RawMouFile, &g_RawMouDev);
    }
}

static NTSTATUS UsbIrpCompletionStop(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
) {
    (void)DeviceObject;
    (void)Irp;
    (void)Context;
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static void UsbInjectKeyToRawKbd(USHORT makeCode, USHORT flags) {
    KEYBOARD_INPUT_DATA kd;
    PIRP irp;
    PIO_STACK_LOCATION irpSp;

    if (!g_RawKbdDev || !makeCode) return;
    kd.UnitId = 0;
    kd.MakeCode = makeCode;
    kd.Flags = flags;
    kd.Reserved = 0;
    kd.ExtraInformation = 0;

    irp = IoAllocateIrp((CCHAR)(g_RawKbdDev->StackSize + 1), FALSE);
    if (!irp) return;
    irp->AssociatedIrp.SystemBuffer = &kd;
    irpSp = IoGetNextIrpStackLocation(irp);
    irpSp->MajorFunction = IRP_MJ_DEVICE_CONTROL;
    irpSp->Parameters.DeviceIoControl.IoControlCode = IOCTL_KBD_INJECT;
    irpSp->Parameters.DeviceIoControl.InputBufferLength = sizeof(kd);
    irpSp->Parameters.DeviceIoControl.OutputBufferLength = 0;
    IoSetCompletionRoutine(irp, UsbIrpCompletionStop, NULL, TRUE, TRUE, TRUE);
    IoCallDriver(g_RawKbdDev, irp);
    IoFreeIrp(irp);
    g_UsbInfo.HidKeyEvents++;
}

static void UsbInjectMouseToRawMou(LONG dx, LONG dy, ULONG buttons) {
    MOUSE_INPUT_DATA_PKT mp;
    PIRP irp;
    PIO_STACK_LOCATION irpSp;

    if (!g_RawMouDev) return;
    mp.DeltaX = dx;
    mp.DeltaY = dy;
    mp.Buttons = buttons;
    mp.RawStatus = 0x08 | (buttons & 0x07);

    irp = IoAllocateIrp((CCHAR)(g_RawMouDev->StackSize + 1), FALSE);
    if (!irp) return;
    irp->AssociatedIrp.SystemBuffer = &mp;
    irpSp = IoGetNextIrpStackLocation(irp);
    irpSp->MajorFunction = IRP_MJ_DEVICE_CONTROL;
    irpSp->Parameters.DeviceIoControl.IoControlCode = IOCTL_MOUSE_INJECT;
    irpSp->Parameters.DeviceIoControl.InputBufferLength = sizeof(mp);
    irpSp->Parameters.DeviceIoControl.OutputBufferLength = 0;
    IoSetCompletionRoutine(irp, UsbIrpCompletionStop, NULL, TRUE, TRUE, TRUE);
    IoCallDriver(g_RawMouDev, irp);
    IoFreeIrp(irp);
    g_UsbInfo.HidMouseEvents++;
}

/* ========================================================================= */
/* UHCI Hardware DMA Engine                                                  */
/* ========================================================================= */

static BOOLEAN UhciInitDmaPool(void) {
    PHYSICAL_ADDRESS low, high, bound;
    ULONG i;

    if (g_UhciDma.VirtBase) return TRUE;

    low.QuadPart   = 0x00100000;
    high.QuadPart  = 0x0FFFFFFF;
    bound.QuadPart = 0;

    g_UhciDma.VirtBase = (PUCHAR)MmAllocateContiguousMemorySpecifyCache(
        UHCI_DMA_SIZE, low, high, bound, MmNonCached
    );
    if (!g_UhciDma.VirtBase) {
        g_UhciDma.VirtBase = (PUCHAR)MmAllocateContiguousMemory(UHCI_DMA_SIZE, high);
    }
    if (!g_UhciDma.VirtBase) return FALSE;

    RtlZeroMemory(g_UhciDma.VirtBase, UHCI_DMA_SIZE);
    g_UhciDma.PhysBase = MmGetPhysicalAddress(g_UhciDma.VirtBase);

    g_UhciDma.FrameList     = (PULONG)(g_UhciDma.VirtBase + 0x0000);
    g_UhciDma.FrameListPhys = g_UhciDma.PhysBase.LowPart + 0x0000;

    g_UhciDma.Qh            = (UHCI_QH *)(g_UhciDma.VirtBase + 0x1000);
    g_UhciDma.QhPhys        = g_UhciDma.PhysBase.LowPart + 0x1000;

    g_UhciDma.Tds           = (UHCI_TD *)(g_UhciDma.VirtBase + 0x1020);
    g_UhciDma.TdsPhys       = g_UhciDma.PhysBase.LowPart + 0x1020;

    g_UhciDma.SetupBuf      = (USB_SETUP_PKT *)(g_UhciDma.VirtBase + 0x1420);
    g_UhciDma.SetupPhys     = g_UhciDma.PhysBase.LowPart + 0x1420;

    g_UhciDma.CbwBuf        = (USB_MSC_CBW *)(g_UhciDma.VirtBase + 0x1440);
    g_UhciDma.CbwPhys       = g_UhciDma.PhysBase.LowPart + 0x1440;

    g_UhciDma.CswBuf        = (USB_MSC_CSW *)(g_UhciDma.VirtBase + 0x1460);
    g_UhciDma.CswPhys       = g_UhciDma.PhysBase.LowPart + 0x1460;

    g_UhciDma.DataBuf       = g_UhciDma.VirtBase + 0x1480;
    g_UhciDma.DataPhys      = g_UhciDma.PhysBase.LowPart + 0x1480;

    g_UhciDma.Qh->HeadLinkPtr    = UHCI_PTR_TERM;
    g_UhciDma.Qh->ElementLinkPtr = UHCI_PTR_TERM;

    for (i = 0; i < 1024; i++) {
        g_UhciDma.FrameList[i] = g_UhciDma.QhPhys | UHCI_PTR_QH;
    }
    return TRUE;
}

static BOOLEAN UhciExecTdChain(ULONG ioBase, int numTds, int timeoutUs) {
    int i, waited = 0;
    g_UhciDma.Qh->ElementLinkPtr = g_UhciDma.TdsPhys;
    WRITE_PORT_USHORT((PUSHORT)(ioBase + UHCI_USBSTS), 0x003F);

    while (waited < timeoutUs) {
        BOOLEAN allDone = TRUE;
        for (i = 0; i < numTds; i++) {
            ULONG cs = g_UhciDma.Tds[i].CtrlStatus;
            if (cs & (1UL << 23)) { /* Active bit */
                allDone = FALSE;
                break;
            }
            if (cs & 0x007E0000UL) { /* Any error bit (Stalled, Babble, CRC, etc.) */
                g_UhciDma.Qh->ElementLinkPtr = UHCI_PTR_TERM;
                return FALSE;
            }
        }
        if (allDone) {
            g_UhciDma.Qh->ElementLinkPtr = UHCI_PTR_TERM;
            return TRUE;
        }
        KeStallExecutionProcessor(25);
        waited += 25;
    }
    g_UhciDma.Qh->ElementLinkPtr = UHCI_PTR_TERM;
    return FALSE;
}

static BOOLEAN UhciControlTransfer(
    ULONG ioBase, UCHAR devAddr, BOOLEAN lowSpeed, USHORT maxPkt0,
    UCHAR bmReqType, UCHAR bReq, USHORT wVal, USHORT wIdx, USHORT wLen,
    PVOID outData
) {
    ULONG lsBit = lowSpeed ? (1UL << 26) : 0;
    ULONG cErr  = (3UL << 27);
    int tdIdx = 0;
    USHORT rem = wLen;
    ULONG curBufPhys = g_UhciDma.DataPhys;
    ULONG toggle = 1;

    if (maxPkt0 == 0) maxPkt0 = 8;

    g_UhciDma.SetupBuf->bmRequestType = bmReqType;
    g_UhciDma.SetupBuf->bRequest      = bReq;
    g_UhciDma.SetupBuf->wValue        = wVal;
    g_UhciDma.SetupBuf->wIndex        = wIdx;
    g_UhciDma.SetupBuf->wLength       = wLen;

    if (wLen > 0 && !(bmReqType & 0x80) && outData) {
        RtlCopyMemory(g_UhciDma.DataBuf, outData, wLen);
    } else if (wLen > 0) {
        RtlZeroMemory(g_UhciDma.DataBuf, wLen);
    }

    /* 1. SETUP TD */
    g_UhciDma.Tds[0].CtrlStatus = cErr | lsBit | (1UL << 23);
    g_UhciDma.Tds[0].Token      = (7UL << 21) | (0UL << 19) | ((ULONG)devAddr << 8) | UHCI_PID_SETUP;
    g_UhciDma.Tds[0].BufferPtr  = g_UhciDma.SetupPhys;
    tdIdx = 1;

    /* 2. DATA TDs */
    while (rem > 0 && tdIdx < 28) {
        USHORT chunk = (rem > maxPkt0) ? maxPkt0 : rem;
        UCHAR pid = (bmReqType & 0x80) ? UHCI_PID_IN : UHCI_PID_OUT;
        g_UhciDma.Tds[tdIdx - 1].LinkPtr = (g_UhciDma.TdsPhys + tdIdx * sizeof(UHCI_TD)) | UHCI_PTR_DEPTH;

        g_UhciDma.Tds[tdIdx].CtrlStatus = cErr | lsBit | (1UL << 29) /* SPD */ | (1UL << 23);
        g_UhciDma.Tds[tdIdx].Token      = ((ULONG)(chunk - 1) << 21) | (toggle << 19) | ((ULONG)devAddr << 8) | pid;
        g_UhciDma.Tds[tdIdx].BufferPtr  = curBufPhys;

        rem -= chunk;
        curBufPhys += chunk;
        toggle ^= 1;
        tdIdx++;
    }

    /* 3. STATUS TD */
    {
        UCHAR statusPid = (wLen == 0 || !(bmReqType & 0x80)) ? UHCI_PID_IN : UHCI_PID_OUT;
        g_UhciDma.Tds[tdIdx - 1].LinkPtr = (g_UhciDma.TdsPhys + tdIdx * sizeof(UHCI_TD)) | UHCI_PTR_DEPTH;
        g_UhciDma.Tds[tdIdx].LinkPtr     = UHCI_PTR_TERM;
        g_UhciDma.Tds[tdIdx].CtrlStatus  = cErr | lsBit | (1UL << 24) /* IOC */ | (1UL << 23);
        g_UhciDma.Tds[tdIdx].Token       = (0x7FFUL << 21) /* 0-len */ | (1UL << 19) | ((ULONG)devAddr << 8) | statusPid;
        g_UhciDma.Tds[tdIdx].BufferPtr   = 0;
        tdIdx++;
    }

    g_UsbInfo.ControlTransfers++;
    if (!UhciExecTdChain(ioBase, tdIdx, 50000)) {
        return FALSE;
    }

    if (wLen > 0 && (bmReqType & 0x80) && outData) {
        RtlCopyMemory(outData, g_UhciDma.DataBuf, wLen);
    }
    return TRUE;
}

static void UhciReadStringDescriptor(
    ULONG ioBase, UCHAR devAddr, BOOLEAN lowSpeed, USHORT maxPkt0,
    UCHAR strIdx, char *outAscii, int maxAscii
) {
    UCHAR raw[128];
    int i, outPos = 0, len;
    outAscii[0] = '\0';
    if (strIdx == 0) return;

    RtlZeroMemory(raw, sizeof(raw));
    /* Step 1: Read 2-byte header (bLength, bDescriptorType) to avoid UHCI SPD short-packet halt */
    if (!UhciControlTransfer(ioBase, devAddr, lowSpeed, maxPkt0,
                             0x80, 0x06, (USHORT)((0x03 << 8) | strIdx), 0x0409, 2, raw)) {
        return;
    }
    len = raw[0];
    if (len < 2 || raw[1] != 0x03) return;
    if (len > 126) len = 126;

    /* Step 2: Read exact descriptor length */
    if (!UhciControlTransfer(ioBase, devAddr, lowSpeed, maxPkt0,
                             0x80, 0x06, (USHORT)((0x03 << 8) | strIdx), 0x0409, (USHORT)len, raw)) {
        return;
    }

    for (i = 2; i + 1 < len && outPos < maxAscii - 1; i += 2) {
        UCHAR ch = raw[i];
        if (ch >= 0x20 && ch <= 0x7E) {
            outAscii[outPos++] = (char)ch;
        }
    }
    outAscii[outPos] = '\0';
}

/* ========================================================================= */
/* UHCI Bulk Transfer & USB Mass Storage BOT (CBW / Data / CSW)              */
/* ========================================================================= */

static BOOLEAN UhciBulkTransfer(
    ULONG ioBase, UCHAR devAddr, UCHAR epNum, BOOLEAN dirIn,
    USHORT maxPkt, ULONG physBuf, ULONG length, UCHAR *pToggle
) {
    ULONG cErr = (3UL << 27);
    int tdIdx = 0;
    ULONG rem = length;
    ULONG curPhys = physBuf;
    UCHAR toggle = *pToggle;
    UCHAR pid = dirIn ? UHCI_PID_IN : UHCI_PID_OUT;

    if (maxPkt == 0) maxPkt = 64;

    while (rem > 0 && tdIdx < 28) {
        USHORT chunk = (rem > maxPkt) ? maxPkt : (USHORT)rem;
        if (tdIdx > 0) {
            g_UhciDma.Tds[tdIdx - 1].LinkPtr = (g_UhciDma.TdsPhys + tdIdx * sizeof(UHCI_TD)) | UHCI_PTR_DEPTH;
        }
        g_UhciDma.Tds[tdIdx].LinkPtr    = UHCI_PTR_TERM;
        g_UhciDma.Tds[tdIdx].CtrlStatus = cErr | (1UL << 23);
        g_UhciDma.Tds[tdIdx].Token      =
            ((ULONG)(chunk - 1) << 21) |
            ((ULONG)toggle << 19) |
            ((ULONG)(epNum & 0x0F) << 15) |
            ((ULONG)devAddr << 8) |
            pid;
        g_UhciDma.Tds[tdIdx].BufferPtr  = curPhys;

        rem -= chunk;
        curPhys += chunk;
        toggle ^= 1;
        tdIdx++;
    }

    if (tdIdx == 0) return TRUE;
    if (!UhciExecTdChain(ioBase, tdIdx, 100000)) {
        return FALSE;
    }
    *pToggle = toggle;
    return TRUE;
}

static BOOLEAN UsbMscBotCommand(
    ULONG ioBase, ULONG devIdx, const UCHAR *cdb, UCHAR cdbLen,
    BOOLEAN dirIn, ULONG dataLen, PVOID dataOut
) {
    USB_DEV_INFO *d = &g_UsbInfo.Devices[devIdx];
    UCHAR epIn  = d->EpIn  ? (d->EpIn  & 0x0F) : 1;
    UCHAR epOut = d->EpOut ? (d->EpOut & 0x0F) : 2;
    USHORT maxPkt = d->MaxPacketSize ? d->MaxPacketSize : 64;

    RtlZeroMemory(g_UhciDma.CbwBuf, sizeof(USB_MSC_CBW));
    g_UhciDma.CbwBuf->dCBWSignature          = 0x43425355UL; /* 'USBC' */
    g_UhciDma.CbwBuf->dCBWTag                = g_MscTag++;
    g_UhciDma.CbwBuf->dCBWDataTransferLength = dataLen;
    g_UhciDma.CbwBuf->bmCBWFlags             = dirIn ? 0x80 : 0x00;
    g_UhciDma.CbwBuf->bCBWLUN                = 0;
    g_UhciDma.CbwBuf->bCBWCBLength           = cdbLen;
    RtlCopyMemory(g_UhciDma.CbwBuf->CBWCB, cdb, cdbLen);

    /* 1. Send 31-byte CBW */
    if (!UhciBulkTransfer(ioBase, d->DevAddress, epOut, FALSE, maxPkt,
                          g_UhciDma.CbwPhys, 31, &g_DataToggleOut[devIdx])) {
        return FALSE;
    }

    /* 2. Data Stage */
    if (dataLen > 0) {
        RtlZeroMemory(g_UhciDma.DataBuf, dataLen);
        if (!UhciBulkTransfer(ioBase, d->DevAddress, dirIn ? epIn : epOut, dirIn, maxPkt,
                              g_UhciDma.DataPhys, dataLen,
                              dirIn ? &g_DataToggleIn[devIdx] : &g_DataToggleOut[devIdx])) {
            return FALSE;
        }
        if (dirIn && dataOut) {
            RtlCopyMemory(dataOut, g_UhciDma.DataBuf, dataLen);
        }
    }

    /* 3. Receive 13-byte CSW */
    RtlZeroMemory(g_UhciDma.CswBuf, sizeof(USB_MSC_CSW));
    if (!UhciBulkTransfer(ioBase, d->DevAddress, epIn, TRUE, maxPkt,
                          g_UhciDma.CswPhys, 13, &g_DataToggleIn[devIdx])) {
        return FALSE;
    }

    return (g_UhciDma.CswBuf->dCSWSignature == 0x53425355UL && g_UhciDma.CswBuf->bCSWStatus == 0);
}

static void UsbMscProbeCapacity(ULONG ioBase, ULONG devIdx) {
    UCHAR inqCdb[6]  = { 0x12, 0, 0, 0, 36, 0 };
    UCHAR capCdb[10] = { 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    UCHAR inqBuf[36];
    UCHAR capBuf[8];
    USB_DEV_INFO *d = &g_UsbInfo.Devices[devIdx];

    if (UsbMscBotCommand(ioBase, devIdx, inqCdb, 6, TRUE, 36, inqBuf)) {
        /* Try READ CAPACITY(10) (may take 2 attempts due to UNIT ATTENTION on first command) */
        if (!UsbMscBotCommand(ioBase, devIdx, capCdb, 10, TRUE, 8, capBuf)) {
            UCHAR turCdb[6] = { 0x00, 0, 0, 0, 0, 0 };
            UCHAR reqSense[6] = { 0x03, 0, 0, 0, 18, 0 };
            UCHAR senseBuf[18];
            UsbMscBotCommand(ioBase, devIdx, reqSense, 6, TRUE, 18, senseBuf);
            UsbMscBotCommand(ioBase, devIdx, turCdb, 6, TRUE, 0, NULL);
            UsbMscBotCommand(ioBase, devIdx, capCdb, 10, TRUE, 8, capBuf);
        }
        {
            ULONG maxLba = ((ULONG)capBuf[0] << 24) | ((ULONG)capBuf[1] << 16) |
                           ((ULONG)capBuf[2] << 8)  | (ULONG)capBuf[3];
            ULONG blkLen = ((ULONG)capBuf[4] << 24) | ((ULONG)capBuf[5] << 16) |
                           ((ULONG)capBuf[6] << 8)  | (ULONG)capBuf[7];
            if (blkLen == 0) blkLen = 512;
            d->StorageBlocks    = (maxLba > 0) ? (maxLba + 1) : 131072;
            d->StorageBlockSize = blkLen;
        }
    }
}

static BOOLEAN UsbMscReadSector512(ULONG devIdx, ULONG lba, PUCHAR out512) {
    ULONG hcIdx, ioBase = 0;
    USB_DEV_INFO *d;
    UCHAR read10[10];

    if (devIdx >= g_UsbInfo.DeviceCount) return FALSE;
    d = &g_UsbInfo.Devices[devIdx];
    if (d->InterfaceClass != 0x08) return FALSE;

    for (hcIdx = 0; hcIdx < g_UsbInfo.ControllerCount; hcIdx++) {
        if (g_UsbInfo.Controllers[hcIdx].HcType == USB_HC_TYPE_UHCI &&
            (hcIdx + 1) == d->BusNumber) {
            ioBase = g_UsbInfo.Controllers[hcIdx].IoBase;
            break;
        }
    }
    if (!ioBase) return FALSE;

    read10[0] = 0x28; /* READ(10) */
    read10[1] = 0x00;
    read10[2] = (UCHAR)((lba >> 24) & 0xFF);
    read10[3] = (UCHAR)((lba >> 16) & 0xFF);
    read10[4] = (UCHAR)((lba >> 8)  & 0xFF);
    read10[5] = (UCHAR)(lba & 0xFF);
    read10[6] = 0x00;
    read10[7] = 0x00;
    read10[8] = 0x01; /* 1 block (512 bytes) */
    read10[9] = 0x00;

    if (UsbMscBotCommand(ioBase, devIdx, read10, 10, TRUE, 512, out512)) {
        g_UsbInfo.StorageReads++;
        return TRUE;
    }
    return FALSE;
}

/* ========================================================================= */
/* Periodic USB HID Interrupt IN Polling (Keyboard & Mouse)                  */
/* ========================================================================= */

static void UsbPollHidDevicesOnce(void) {
    ULONG devIdx, hcIdx;

    for (devIdx = 0; devIdx < g_UsbInfo.DeviceCount; devIdx++) {
        USB_DEV_INFO *d = &g_UsbInfo.Devices[devIdx];
        ULONG ioBase = 0;
        ULONG lsBit;
        UCHAR epIn;
        USHORT maxPkt;

        if (!d->Present || d->InterfaceClass != 0x03) continue;

        for (hcIdx = 0; hcIdx < g_UsbInfo.ControllerCount; hcIdx++) {
            if (g_UsbInfo.Controllers[hcIdx].HcType == USB_HC_TYPE_UHCI &&
                (hcIdx + 1) == d->BusNumber) {
                ioBase = g_UsbInfo.Controllers[hcIdx].IoBase;
                break;
            }
        }
        if (!ioBase) continue;

        lsBit  = (d->Speed == USB_SPEED_LOW) ? (1UL << 26) : 0;
        epIn   = d->EpIn ? (d->EpIn & 0x0F) : 1;
        maxPkt = d->MaxPacketSize ? d->MaxPacketSize : 8;
        if (maxPkt > 16) maxPkt = 8;

        RtlZeroMemory(g_UhciDma.DataBuf, 16);
        g_UhciDma.Tds[0].LinkPtr    = UHCI_PTR_TERM;
        g_UhciDma.Tds[0].CtrlStatus = (3UL << 27) | lsBit | (1UL << 29) | (1UL << 23);
        g_UhciDma.Tds[0].Token      =
            ((ULONG)(maxPkt - 1) << 21) |
            ((ULONG)g_DataToggleIn[devIdx] << 19) |
            ((ULONG)epIn << 15) |
            ((ULONG)d->DevAddress << 8) |
            UHCI_PID_IN;
        g_UhciDma.Tds[0].BufferPtr  = g_UhciDma.DataPhys;

        /* Execute single non-blocking poll TD (up to 400us wait for immediate NAK or DATA) */
        if (!UhciExecTdChain(ioBase, 1, 400)) {
            continue;
        }
        g_DataToggleIn[devIdx] ^= 1;

        if (d->InterfaceProtocol == 1) {
            /* USB HID Boot Keyboard 8-byte report */
            UCHAR *rep = g_UhciDma.DataBuf;
            int i, j;

            /* Left Shift (bit 1) / Right Shift (bit 5) */
            if ((rep[0] & 0x02) != (g_PrevKbdReport[0] & 0x02)) {
                UsbInjectKeyToRawKbd(0x2A, (rep[0] & 0x02) ? 0 : 1);
            }
            if ((rep[0] & 0x20) != (g_PrevKbdReport[0] & 0x20)) {
                UsbInjectKeyToRawKbd(0x36, (rep[0] & 0x20) ? 0 : 1);
            }
            /* Left Ctrl (bit 0) */
            if ((rep[0] & 0x01) != (g_PrevKbdReport[0] & 0x01)) {
                UsbInjectKeyToRawKbd(0x1D, (rep[0] & 0x01) ? 0 : 1);
            }

            /* Newly pressed keys */
            for (i = 2; i < 8; i++) {
                UCHAR hid = rep[i];
                BOOLEAN wasDown = FALSE;
                if (hid < 4 || hid >= 128) continue;
                for (j = 2; j < 8; j++) {
                    if (g_PrevKbdReport[j] == hid) { wasDown = TRUE; break; }
                }
                if (!wasDown && g_HidToSet1[hid]) {
                    UsbInjectKeyToRawKbd(g_HidToSet1[hid], 0 /* KEY_MAKE */);
                }
            }
            /* Released keys */
            for (i = 2; i < 8; i++) {
                UCHAR oldHid = g_PrevKbdReport[i];
                BOOLEAN stillDown = FALSE;
                if (oldHid < 4 || oldHid >= 128) continue;
                for (j = 2; j < 8; j++) {
                    if (rep[j] == oldHid) { stillDown = TRUE; break; }
                }
                if (!stillDown && g_HidToSet1[oldHid]) {
                    UsbInjectKeyToRawKbd(g_HidToSet1[oldHid], 1 /* KEY_BREAK */);
                }
            }
            RtlCopyMemory(g_PrevKbdReport, rep, 8);

        } else {
            /* USB HID Boot Mouse [buttons, int8 dx, int8 dy] */
            UCHAR *rep = g_UhciDma.DataBuf;
            LONG dx = (LONG)(signed char)rep[1];
            LONG dy = (LONG)(signed char)rep[2];
            ULONG btns = (ULONG)(rep[0] & 0x07);
            if (dx != 0 || dy != 0 || btns != 0) {
                UsbInjectMouseToRawMou(dx, dy, btns);
            }
        }
    }
}

static VOID UsbHidTimerDpc(
    PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2
) {
    (void)Dpc; (void)DeferredContext; (void)SystemArgument1; (void)SystemArgument2;
    KeAcquireSpinLockAtDpcLevel(&g_UsbLock);
    UsbPollHidDevicesOnce();
    KeReleaseSpinLockFromDpcLevel(&g_UsbLock);
}

/* ========================================================================= */
/* UHCI Controller Initialization & Port Enumeration                         */
/* ========================================================================= */

static void UhciInitControllerAndPorts(USB_HC_INFO *hc, ULONG busNumber) {
    ULONG ioBase = hc->IoBase;
    ULONG port;
    USHORT legSup = 0x8F00;

    if (!UhciInitDmaPool()) return;

    /* Clear UHCI USBLEGSUP in PCI config space (offset 0xC0) so OS owns UHCI */
    HalSetBusDataByOffset(
        PCIConfiguration, hc->PciBus,
        (hc->PciSlot & 0x1F) | ((hc->PciFunc & 0x07) << 5),
        &legSup, 0xC0, sizeof(legSup)
    );

    /* Global Reset & Host Controller Reset */
    WRITE_PORT_USHORT((PUSHORT)(ioBase + UHCI_USBCMD), UHCI_CMD_GRESET);
    KeStallExecutionProcessor(10000);
    WRITE_PORT_USHORT((PUSHORT)(ioBase + UHCI_USBCMD), 0);
    KeStallExecutionProcessor(2000);

    WRITE_PORT_USHORT((PUSHORT)(ioBase + UHCI_USBCMD), UHCI_CMD_HCRESET);
    KeStallExecutionProcessor(5000);

    WRITE_PORT_USHORT((PUSHORT)(ioBase + UHCI_USBINTR), 0x0000);
    WRITE_PORT_USHORT((PUSHORT)(ioBase + UHCI_FRNUM),   0x0000);
    WRITE_PORT_ULONG((PULONG)(ioBase + UHCI_FRBASEADD), g_UhciDma.FrameListPhys);
    WRITE_PORT_UCHAR((PUCHAR)(ioBase + UHCI_SOFMOD),    0x40);
    WRITE_PORT_USHORT((PUSHORT)(ioBase + UHCI_USBSTS),  0xFFFF);

    /* Start UHCI Controller (Run/Stop + Configured + 64-byte Max Packet) */
    WRITE_PORT_USHORT((PUSHORT)(ioBase + UHCI_USBCMD), UHCI_CMD_RS | UHCI_CMD_CF | UHCI_CMD_MAXP);
    KeStallExecutionProcessor(5000);

    hc->NumPorts = 2;
    hc->PortsConnected = 0;

    /* Add Root Hub entry to device list */
    if (g_UsbInfo.DeviceCount < USB_MAX_DEVICES) {
        USB_DEV_INFO *rh = &g_UsbInfo.Devices[g_UsbInfo.DeviceCount++];
        RtlZeroMemory(rh, sizeof(*rh));
        rh->Present       = 1;
        rh->BusNumber     = (UCHAR)busNumber;
        rh->PortNumber    = 0;
        rh->DevAddress    = 1;
        rh->Speed         = USB_SPEED_FULL;
        rh->VendorId      = hc->VendorId;
        rh->ProductId     = hc->DeviceId;
        rh->DeviceClass   = 0x09; /* Hub */
        rh->MaxPacketSize = 64;
        UsbCopyStr(rh->Manufacturer, sizeof(rh->Manufacturer), "Linux/NT 5.1 uhci_hcd");
        UsbCopyStr(rh->Product,      sizeof(rh->Product),      "UHCI Host Controller Root Hub");
        UsbCopyStr(rh->DriverName,   sizeof(rh->DriverName),   "usbhub");
    }

    for (port = 0; port < 2; port++) {
        ULONG portReg = ioBase + UHCI_PORTSC1 + port * 2;
        USHORT st = READ_PORT_USHORT((PUSHORT)portReg);
        BOOLEAN lowSpeed;
        UCHAR newAddr;
        USB_DEVICE_DESC devDesc;
        UCHAR cfgBuf[128];

        if (!(st & 0x0001)) continue; /* No device attached */
        hc->PortsConnected++;

        /* Assert Port Reset (bit 9) for 20ms */
        WRITE_PORT_USHORT((PUSHORT)portReg, 0x0200);
        KeStallExecutionProcessor(20000);
        /* Deassert Port Reset */
        WRITE_PORT_USHORT((PUSHORT)portReg, 0x0000);
        KeStallExecutionProcessor(5000);
        /* Clear status change bits & Enable Port (bit 2) */
        WRITE_PORT_USHORT((PUSHORT)portReg, 0x000E);
        KeStallExecutionProcessor(10000);

        st = READ_PORT_USHORT((PUSHORT)portReg);
        if (!(st & 0x0001)) continue;
        lowSpeed = (st & 0x0100) ? TRUE : FALSE;

        /* 1. GET_DESCRIPTOR(DEVICE, first 8 bytes) at address 0 */
        RtlZeroMemory(&devDesc, sizeof(devDesc));
        if (!UhciControlTransfer(ioBase, 0, lowSpeed, 8, 0x80, 0x06, 0x0100, 0, 8, &devDesc)) {
            continue;
        }
        if (devDesc.bMaxPacketSize0 == 0) devDesc.bMaxPacketSize0 = 8;

        /* 2. SET_ADDRESS(newAddr) */
        newAddr = (UCHAR)(g_UsbInfo.DeviceCount + 1);
        if (!UhciControlTransfer(ioBase, 0, lowSpeed, devDesc.bMaxPacketSize0,
                                 0x00, 0x05, newAddr, 0, 0, NULL)) {
            continue;
        }
        KeStallExecutionProcessor(5000);

        /* 3. GET_DESCRIPTOR(DEVICE, full 18 bytes) at newAddr */
        if (!UhciControlTransfer(ioBase, newAddr, lowSpeed, devDesc.bMaxPacketSize0,
                                 0x80, 0x06, 0x0100, 0, 18, &devDesc)) {
            continue;
        }

        if (g_UsbInfo.DeviceCount >= USB_MAX_DEVICES) break;
        {
            ULONG devIdx = g_UsbInfo.DeviceCount++;
            USB_DEV_INFO *d = &g_UsbInfo.Devices[devIdx];
            RtlZeroMemory(d, sizeof(*d));
            d->Present        = 1;
            d->BusNumber      = (UCHAR)busNumber;
            d->PortNumber     = (UCHAR)(port + 1);
            d->DevAddress     = newAddr;
            d->Speed          = lowSpeed ? USB_SPEED_LOW : USB_SPEED_FULL;
            d->VendorId       = devDesc.idVendor;
            d->ProductId      = devDesc.idProduct;
            d->BcdDevice      = devDesc.bcdDevice;
            d->DeviceClass    = devDesc.bDeviceClass;
            d->DeviceSubClass = devDesc.bDeviceSubClass;
            d->DeviceProtocol = devDesc.bDeviceProtocol;
            d->MaxPacketSize  = devDesc.bMaxPacketSize0;

            /* 4. Read Manufacturer & Product Strings */
            UhciReadStringDescriptor(ioBase, newAddr, lowSpeed, devDesc.bMaxPacketSize0,
                                     devDesc.iManufacturer, d->Manufacturer, sizeof(d->Manufacturer));
            UhciReadStringDescriptor(ioBase, newAddr, lowSpeed, devDesc.bMaxPacketSize0,
                                     devDesc.iProduct, d->Product, sizeof(d->Product));

            /* 5. GET_DESCRIPTOR(CONFIGURATION) - 9-byte header first, then exact wTotalLength */
            RtlZeroMemory(cfgBuf, sizeof(cfgBuf));
            if (UhciControlTransfer(ioBase, newAddr, lowSpeed, devDesc.bMaxPacketSize0,
                                    0x80, 0x06, 0x0200, 0, 9, cfgBuf)) {
                USB_CONFIG_DESC *cd = (USB_CONFIG_DESC *)cfgBuf;
                int off = cd->bLength;
                int total = cd->wTotalLength;
                if (total < 9) total = 9;
                if (total > 128) total = 128;
                UhciControlTransfer(ioBase, newAddr, lowSpeed, devDesc.bMaxPacketSize0,
                                    0x80, 0x06, 0x0200, 0, (USHORT)total, cfgBuf);

                while (off + 2 <= total) {
                    UCHAR bLen  = cfgBuf[off];
                    UCHAR bType = cfgBuf[off + 1];
                    if (bLen == 0) break;
                    if (bType == 0x04 && off + (int)sizeof(USB_INTERFACE_DESC) <= total) {
                        USB_INTERFACE_DESC *id = (USB_INTERFACE_DESC *)(cfgBuf + off);
                        if (d->InterfaceClass == 0) {
                            d->InterfaceClass    = id->bInterfaceClass;
                            d->InterfaceSubClass = id->bInterfaceSubClass;
                            d->InterfaceProtocol = id->bInterfaceProtocol;
                        }
                    } else if (bType == 0x05 && off + (int)sizeof(USB_ENDPOINT_DESC) <= total) {
                        USB_ENDPOINT_DESC *ed = (USB_ENDPOINT_DESC *)(cfgBuf + off);
                        if (ed->bEndpointAddress & 0x80) {
                            if (!d->EpIn) {
                                d->EpIn = ed->bEndpointAddress;
                                d->MaxPacketSize = ed->wMaxPacketSize & 0x7FF;
                            }
                        } else {
                            if (!d->EpOut) {
                                d->EpOut = ed->bEndpointAddress;
                            }
                        }
                    }
                    off += bLen;
                }

                /* 6. SET_CONFIGURATION(bConfigurationValue) */
                UhciControlTransfer(ioBase, newAddr, lowSpeed, devDesc.bMaxPacketSize0,
                                    0x00, 0x09, cd->bConfigurationValue ? cd->bConfigurationValue : 1,
                                    0, 0, NULL);
            }

            /* Configure class-specific driver binding */
            if (d->InterfaceClass == 0x03) {
                /* HID Class: Set Boot Protocol (0) & Set Idle (0) */
                UhciControlTransfer(ioBase, newAddr, lowSpeed, devDesc.bMaxPacketSize0,
                                    0x21, 0x0B /* SET_PROTOCOL */, 0, 0, 0, NULL);
                UhciControlTransfer(ioBase, newAddr, lowSpeed, devDesc.bMaxPacketSize0,
                                    0x21, 0x0A /* SET_IDLE */,     0, 0, 0, NULL);

                if (d->InterfaceProtocol == 1) {
                    UsbCopyStr(d->DriverName, sizeof(d->DriverName), "usbhid-kbd");
                    if (!d->Product[0]) UsbCopyStr(d->Product, sizeof(d->Product), "USB HID Boot Keyboard");
                } else {
                    UsbCopyStr(d->DriverName, sizeof(d->DriverName), "usbhid-mouse");
                    if (!d->Product[0]) UsbCopyStr(d->Product, sizeof(d->Product), "USB HID Boot Mouse");
                }
            } else if (d->InterfaceClass == 0x08) {
                UsbCopyStr(d->DriverName, sizeof(d->DriverName), "usb-storage");
                if (!d->Product[0]) UsbCopyStr(d->Product, sizeof(d->Product), "USB Mass Storage Drive");
                UsbMscProbeCapacity(ioBase, devIdx);
            } else if (d->DeviceClass == 0x09 || d->InterfaceClass == 0x09) {
                UsbCopyStr(d->DriverName, sizeof(d->DriverName), "usbhub");
                if (!d->Product[0]) UsbCopyStr(d->Product, sizeof(d->Product), "USB 2.0 Hub");
            } else {
                UsbCopyStr(d->DriverName, sizeof(d->DriverName), "usb-generic");
                if (!d->Product[0]) UsbCopyStr(d->Product, sizeof(d->Product), "USB Composite Device");
            }

            if (!d->Manufacturer[0]) {
                UsbCopyStr(d->Manufacturer, sizeof(d->Manufacturer), "USB Standards Corp.");
            }

            UsbDbgPrint("[usbdrv] Enumerated UHCI Device VID=");
            UsbDbgHex16(d->VendorId);
            UsbDbgPrint(" PID=");
            UsbDbgHex16(d->ProductId);
            UsbDbgPrint(" Product=");
            UsbDbgPrint(d->Product);
            UsbDbgPrint(" Driver=");
            UsbDbgPrint(d->DriverName);
            UsbDbgPrint("\n");
        }
    }
}

/* ========================================================================= */
/* PCI Bus Scan for UHCI, OHCI, EHCI, and xHCI USB Host Controllers          */
/* ========================================================================= */

static void UsbScanAndInitAllControllers(void) {
    ULONG bus, dev, func, idx;
    UCHAR pciHdr[64];
    BOOLEAN hasUhci = FALSE;

    g_UsbInfo.ControllerCount = 0;
    g_UsbInfo.DeviceCount     = 0;

    for (bus = 0; bus < 16; bus++) {
        for (dev = 0; dev < 32; dev++) {
            for (func = 0; func < 8; func++) {
                ULONG slot = (dev & 0x1F) | ((func & 0x07) << 5);
                ULONG readBytes;
                USHORT vendorId, deviceId, cmdReg;
                UCHAR baseClass, subClass, progIf, hdrType;

                RtlZeroMemory(pciHdr, sizeof(pciHdr));
                readBytes = HalGetBusDataByOffset(PCIConfiguration, bus, slot, pciHdr, 0, 64);
                if (readBytes < 16) continue;

                vendorId = *(USHORT *)(pciHdr + 0x00);
                deviceId = *(USHORT *)(pciHdr + 0x02);
                if (vendorId == 0xFFFF || vendorId == 0x0000) {
                    if (func == 0) break;
                    continue;
                }

                progIf    = pciHdr[0x09];
                subClass  = pciHdr[0x0A];
                baseClass = pciHdr[0x0B];
                hdrType   = pciHdr[0x0E];

                if (baseClass == 0x0C && subClass == 0x03 &&
                    g_UsbInfo.ControllerCount < USB_MAX_CONTROLLERS) {
                    USB_HC_INFO *hc = &g_UsbInfo.Controllers[g_UsbInfo.ControllerCount++];
                    RtlZeroMemory(hc, sizeof(*hc));
                    hc->Present  = 1;
                    hc->PciBus   = bus;
                    hc->PciSlot  = dev;
                    hc->PciFunc  = func;
                    hc->VendorId = vendorId;
                    hc->DeviceId = deviceId;
                    hc->IrqLine  = pciHdr[0x3C];

                    cmdReg = *(USHORT *)(pciHdr + 0x04);
                    cmdReg |= 0x0007; /* I/O Space + Memory Space + Bus Master */
                    HalSetBusDataByOffset(PCIConfiguration, bus, slot, &cmdReg, 0x04, sizeof(cmdReg));

                    if (progIf == 0x00) {
                        hc->HcType     = USB_HC_TYPE_UHCI;
                        hc->IoBase     = (*(ULONG *)(pciHdr + 0x20)) & 0xFFFCUL;
                        hc->HciVersion = 0x0110;
                        hasUhci        = TRUE;
                    } else if (progIf == 0x10) {
                        hc->HcType     = USB_HC_TYPE_OHCI;
                        hc->MmioPhys   = (*(ULONG *)(pciHdr + 0x10)) & 0xFFFFF000UL;
                        hc->HciVersion = 0x0110;
                        hc->NumPorts   = 2;
                    } else if (progIf == 0x20) {
                        hc->HcType     = USB_HC_TYPE_EHCI;
                        hc->MmioPhys   = (*(ULONG *)(pciHdr + 0x10)) & 0xFFFFF000UL;
                        hc->HciVersion = 0x0200;
                    } else if (progIf == 0x30) {
                        hc->HcType     = USB_HC_TYPE_XHCI;
                        hc->MmioPhys   = (*(ULONG *)(pciHdr + 0x10)) & 0xFFFFF000UL;
                        hc->HciVersion = 0x0300;
                    }
                }

                if (func == 0 && !(hdrType & 0x80)) break;
            }
        }
    }

    /* Only UHCI has an implemented transfer schedule and descriptor reads. */
    for (idx = 0; idx < g_UsbInfo.ControllerCount; idx++) {
        USB_HC_INFO *hc = &g_UsbInfo.Controllers[idx];
        if (hc->HcType == USB_HC_TYPE_UHCI && hc->IoBase) {
            UhciInitControllerAndPorts(hc, idx + 1);
        } else {
            UsbDbgPrint("[usbdrv] Controller discovered; transfer implementation unsupported.\n");
        }
    }
}

/* ========================================================================= */
/* NT IRP Dispatch Routines for \Device\Usb0 & \Device\UsbDisk0              */
/* ========================================================================= */

static NTSTATUS UsbDrvCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS UsbDrvRead(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG len = irpSp->Parameters.Read.Length;
    PUCHAR outBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    KIRQL oldIrql;

    (void)DeviceObject;
    UsbBindRawInputDevices();
    KeAcquireSpinLock(&g_UsbLock, &oldIrql);
    UsbPollHidDevicesOnce();
    KeReleaseSpinLock(&g_UsbLock, oldIrql);

    if (outBuf && len >= sizeof(USB_STACK_INFO)) {
        RtlCopyMemory(outBuf, &g_UsbInfo, sizeof(USB_STACK_INFO));
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = sizeof(USB_STACK_INFO);
    } else if (outBuf && len >= 512) {
        ULONG devIdx;
        BOOLEAN ok = FALSE;
        ULONG lba = (ULONG)(irpSp->Parameters.Read.ByteOffset.QuadPart / 512);
        KeAcquireSpinLock(&g_UsbLock, &oldIrql);
        for (devIdx = 0; devIdx < g_UsbInfo.DeviceCount; devIdx++) {
            if (g_UsbInfo.Devices[devIdx].InterfaceClass == 0x08) {
                ok = UsbMscReadSector512(devIdx, lba, outBuf);
                break;
            }
        }
        KeReleaseSpinLock(&g_UsbLock, oldIrql);
        Irp->IoStatus.Status = ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        Irp->IoStatus.Information = ok ? 512 : 0;
    } else {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

static NTSTATUS UsbDrvDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code   = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG inLen  = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    PVOID buf    = Irp->AssociatedIrp.SystemBuffer;
    KIRQL oldIrql;

    (void)DeviceObject;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    if (code == IOCTL_USB_GET_INFO) {
        UsbBindRawInputDevices();
        KeAcquireSpinLock(&g_UsbLock, &oldIrql);
        UsbPollHidDevicesOnce();
        if (buf && outLen >= sizeof(USB_STACK_INFO)) {
            RtlCopyMemory(buf, &g_UsbInfo, sizeof(USB_STACK_INFO));
            Irp->IoStatus.Information = sizeof(USB_STACK_INFO);
        }
        KeReleaseSpinLock(&g_UsbLock, oldIrql);
    } else if (code == IOCTL_USB_RESCAN) {
        KeAcquireSpinLock(&g_UsbLock, &oldIrql);
        UsbScanAndInitAllControllers();
        if (buf && outLen >= sizeof(USB_STACK_INFO)) {
            RtlCopyMemory(buf, &g_UsbInfo, sizeof(USB_STACK_INFO));
            Irp->IoStatus.Information = sizeof(USB_STACK_INFO);
        }
        KeReleaseSpinLock(&g_UsbLock, oldIrql);
    } else if (code == IOCTL_USB_READ_SECTOR && buf &&
               inLen >= sizeof(USB_SECTOR_REQ) && outLen >= sizeof(USB_SECTOR_REQ)) {
        USB_SECTOR_REQ *req = (USB_SECTOR_REQ *)buf;
        BOOLEAN ok;
        KeAcquireSpinLock(&g_UsbLock, &oldIrql);
        ok = UsbMscReadSector512(req->DeviceIndex, req->Lba, req->Data);
        KeReleaseSpinLock(&g_UsbLock, oldIrql);
        Irp->IoStatus.Status = ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        Irp->IoStatus.Information = ok ? sizeof(USB_SECTOR_REQ) : 0;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

static VOID UsbDrvUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING sym1, sym2;
    if (g_TimerRunning) {
        KeCancelTimer(&g_HidTimer);
        g_TimerRunning = FALSE;
    }
    if (g_RawKbdFile) { ObDereferenceObject(g_RawKbdFile); g_RawKbdFile = NULL; g_RawKbdDev = NULL; }
    if (g_RawMouFile) { ObDereferenceObject(g_RawMouFile); g_RawMouFile = NULL; g_RawMouDev = NULL; }

    RtlInitUnicodeString(&sym1, L"\\DosDevices\\usb0");
    RtlInitUnicodeString(&sym2, L"\\DosDevices\\sda");
    IoDeleteSymbolicLink(&sym1);
    IoDeleteSymbolicLink(&sym2);

    while (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING devName, symUsb, symSda;
    PDEVICE_OBJECT devObj = NULL;
    NTSTATUS status;
    LARGE_INTEGER dueTime;

    (void)RegistryPath;

    RtlZeroMemory(&g_UsbInfo, sizeof(g_UsbInfo));
    RtlZeroMemory(&g_UhciDma, sizeof(g_UhciDma));
    RtlZeroMemory(g_PrevKbdReport, sizeof(g_PrevKbdReport));
    RtlZeroMemory(g_DataToggleIn,  sizeof(g_DataToggleIn));
    RtlZeroMemory(g_DataToggleOut, sizeof(g_DataToggleOut));
    KeInitializeSpinLock(&g_UsbLock);

    UsbDbgPrint("\n=======================================================\n");
    UsbDbgPrint("[usbdrv] Initializing experimental UHCI USB stack\n");
    UsbDbgPrint("=======================================================\n");

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = UsbDrvCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = UsbDrvCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = UsbDrvCreateClose;
    DriverObject->MajorFunction[IRP_MJ_READ]           = UsbDrvRead;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UsbDrvDeviceControl;
    DriverObject->DriverUnload                         = UsbDrvUnload;

    RtlInitUnicodeString(&devName, L"\\Device\\Usb0");
    RtlInitUnicodeString(&symUsb,  L"\\DosDevices\\usb0");
    RtlInitUnicodeString(&symSda,  L"\\DosDevices\\sda");

    status = IoCreateDevice(
        DriverObject, 0, &devName, FILE_DEVICE_USB_STACK, 0, FALSE, &devObj
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    devObj->Flags |= DO_BUFFERED_IO;
    IoCreateSymbolicLink(&symUsb, &devName);
    IoCreateSymbolicLink(&symSda, &devName);
    devObj->Flags &= ~DO_DEVICE_INITIALIZING;

    /* Bind to \Device\RawKeyboard and \Device\RawMouse at PASSIVE_LEVEL */
    UsbBindRawInputDevices();

    /* Scan PCI bus and initialize all USB Host Controllers & attached devices */
    UsbScanAndInitAllControllers();

    /* Start 16ms periodic kernel timer DPC to poll USB HID keyboards & mice */
    KeInitializeTimer(&g_HidTimer);
    KeInitializeDpc(&g_HidDpc, UsbHidTimerDpc, NULL);
    dueTime.QuadPart = -160000; /* 16ms */
    KeSetTimerEx(&g_HidTimer, dueTime, 16, &g_HidDpc);
    g_TimerRunning = TRUE;

    UsbDbgPrint("[usbdrv] Ready (/dev/usb0 & /dev/sda active).\n");
    return STATUS_SUCCESS;
}
