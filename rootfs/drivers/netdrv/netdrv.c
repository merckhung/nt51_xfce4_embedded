/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rootfs/drivers/netdrv/netdrv.c
 * Realtek RTL8139 PCI Fast Ethernet Kernel Driver for Windows XP (NT 5.1 x86)
 * Creates \Device\Net0 and \DosDevices\net0 + \DosDevices\eth0 (/dev/net0, /dev/eth0)
 */

#include <ntddk.h>
#include "netdrv_ioctl.h"

/* RTL8139 Register Offsets from BAR0 IoBase */
#define RTL_REG_IDR0        0x00    /* 6-byte MAC Address */
#define RTL_REG_MAR0        0x08    /* 8-byte Multicast Filter */
#define RTL_REG_TSD0        0x10    /* Transmit Status Descriptors 0..3 (4 bytes each) */
#define RTL_REG_TSAD0       0x20    /* Transmit Start Address Descriptors 0..3 (4 bytes each) */
#define RTL_REG_RBSTART     0x30    /* Receive Buffer Start Physical Address (4 bytes) */
#define RTL_REG_CMD         0x37    /* Command Register (1 byte: bit 0=BUFE, bit 2=TE, bit 3=RE, bit 4=RST) */
#define RTL_REG_CAPR        0x38    /* Current Address of Packet Read (2 bytes) */
#define RTL_REG_CBR         0x3A    /* Current Buffer Address (2 bytes) */
#define RTL_REG_IMR         0x3C    /* Interrupt Mask Register (2 bytes) */
#define RTL_REG_ISR         0x3E    /* Interrupt Status Register (2 bytes) */
#define RTL_REG_TCR         0x40    /* Transmit Configuration Register (4 bytes) */
#define RTL_REG_RCR         0x44    /* Receive Configuration Register (4 bytes) */
#define RTL_REG_CONFIG1     0x52    /* Config 1 Register (1 byte: 0x00 = Power On) */
#define RTL_REG_MSR         0x58    /* Media Status Register (1 byte: bit 2 = LinkB inverted) */

#define RTL_CMD_BUFE        0x01
#define RTL_CMD_TE          0x04
#define RTL_CMD_RE          0x08
#define RTL_CMD_RST         0x10

#define RTL_RX_RING_SIZE    8192
#define RTL_RX_ALLOC_SIZE   (RTL_RX_RING_SIZE + 16 + 2048)
#define RTL_TX_BUF_SIZE     2048
#define RTL_DMA_TOTAL_SIZE  (16384 + 4 * RTL_TX_BUF_SIZE)

typedef struct _NETDRV_EXT {
    PDEVICE_OBJECT DeviceObject;
    USHORT         IoBase;
    UCHAR          IrqLine;
    BOOLEAN        HardwarePresent;
    USHORT         PciVendorId;
    USHORT         PciDeviceId;
    UCHAR          MacAddress[6];

    PUCHAR         DmaVirtBase;
    ULONG          DmaPhysBase;

    PUCHAR         RxRingVirt;
    ULONG          RxRingPhys;
    ULONG          RxReadOffset;

    PUCHAR         TxBufVirt[4];
    ULONG          TxBufPhys[4];
    ULONG          TxCurDesc;

    ULONG          TxPackets;
    ULONG          RxPackets;
    ULONG          TxBytes;
    ULONG          RxBytes;
} NETDRV_EXT, *PNETDRV_EXT;

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

static void SerDbgHex8(UCHAR val) {
    static const char hex[] = "0123456789ABCDEF";
    SerDbgPutc(hex[(val >> 4) & 0xF]);
    SerDbgPutc(hex[val & 0xF]);
}

static void SerDbgHex32(ULONG val) {
    static const char hex[] = "0123456789ABCDEF";
    int i;
    for (i = 28; i >= 0; i -= 4) {
        SerDbgPutc(hex[(val >> i) & 0xF]);
    }
}

static ULONG PciReadConfig32(UCHAR bus, UCHAR slot, UCHAR func, UCHAR offset) {
    ULONG addr = 0x80000000UL
               | ((ULONG)bus << 16)
               | ((ULONG)(slot & 0x1F) << 11)
               | ((ULONG)(func & 0x07) << 8)
               | ((ULONG)(offset & 0xFC));
    WRITE_PORT_ULONG((PULONG)0x0CF8, addr);
    return READ_PORT_ULONG((PULONG)0x0CFC);
}

static void PciWriteConfig32(UCHAR bus, UCHAR slot, UCHAR func, UCHAR offset, ULONG val) {
    ULONG addr = 0x80000000UL
               | ((ULONG)bus << 16)
               | ((ULONG)(slot & 0x1F) << 11)
               | ((ULONG)(func & 0x07) << 8)
               | ((ULONG)(offset & 0xFC));
    WRITE_PORT_ULONG((PULONG)0x0CF8, addr);
    WRITE_PORT_ULONG((PULONG)0x0CFC, val);
}

static BOOLEAN ProbeAndInitRtl8139(PNETDRV_EXT ext) {
    UCHAR slot;
    PHYSICAL_ADDRESS maxPhys;
    PHYSICAL_ADDRESS phys;
    int i, timeout;

    for (slot = 0; slot < 32; slot++) {
        ULONG id = PciReadConfig32(0, slot, 0, 0x00);
        if (id == 0xFFFFFFFFUL || id == 0) continue;

        /* Match Realtek RTL8139 (Vendor 0x10EC, Device 0x8139) */
        if (id == 0x813910ECUL) {
            ULONG bar0 = PciReadConfig32(0, slot, 0, 0x10);
            ULONG cmd  = PciReadConfig32(0, slot, 0, 0x04);
            ULONG intr = PciReadConfig32(0, slot, 0, 0x3C);

            /* Enable PCI I/O Space (bit 0) + Memory Space (bit 1) + Bus Master DMA (bit 2) */
            PciWriteConfig32(0, slot, 0, 0x04, cmd | 0x07);

            ext->IoBase      = (USHORT)(bar0 & 0xFFFCU);
            ext->IrqLine     = (UCHAR)(intr & 0xFFU);
            ext->PciVendorId = 0x10EC;
            ext->PciDeviceId = 0x8139;
            break;
        }
    }

    if (ext->IoBase == 0) {
        SerDbgPrint("[netdrv] WARNING: RTL8139 PCI NIC not found on Bus 0, using fallback MAC.\n");
        ext->MacAddress[0] = 0x52;
        ext->MacAddress[1] = 0x54;
        ext->MacAddress[2] = 0x00;
        ext->MacAddress[3] = 0x12;
        ext->MacAddress[4] = 0x34;
        ext->MacAddress[5] = 0x56;
        ext->HardwarePresent = FALSE;
        return FALSE;
    }

    /* Allocate physically contiguous DMA memory below 4 GB */
    maxPhys.LowPart  = 0x0FFFFFFFUL;
    maxPhys.HighPart = 0;
    ext->DmaVirtBase = (PUCHAR)MmAllocateContiguousMemory(RTL_DMA_TOTAL_SIZE, maxPhys);
    if (!ext->DmaVirtBase) {
        SerDbgPrint("[netdrv] ERROR: MmAllocateContiguousMemory failed!\n");
        return FALSE;
    }

    RtlZeroMemory(ext->DmaVirtBase, RTL_DMA_TOTAL_SIZE);
    phys = MmGetPhysicalAddress(ext->DmaVirtBase);
    ext->DmaPhysBase = phys.LowPart;

    ext->RxRingVirt   = ext->DmaVirtBase;
    ext->RxRingPhys   = ext->DmaPhysBase;
    ext->RxReadOffset = 0;

    for (i = 0; i < 4; i++) {
        ext->TxBufVirt[i] = ext->DmaVirtBase + 16384 + (i * RTL_TX_BUF_SIZE);
        ext->TxBufPhys[i] = ext->DmaPhysBase + 16384 + (i * RTL_TX_BUF_SIZE);
    }
    ext->TxCurDesc = 0;

    /* 1. Power on RTL8139 (CONFIG1 = 0x00) */
    WRITE_PORT_UCHAR((PUCHAR)(ULONG)(ext->IoBase + RTL_REG_CONFIG1), 0x00);

    /* 2. Software Reset (CMD = 0x10) and wait for RST bit to clear */
    WRITE_PORT_UCHAR((PUCHAR)(ULONG)(ext->IoBase + RTL_REG_CMD), RTL_CMD_RST);
    timeout = 100000;
    while ((READ_PORT_UCHAR((PUCHAR)(ULONG)(ext->IoBase + RTL_REG_CMD)) & RTL_CMD_RST) && --timeout > 0);

    /* 3. Read 6-byte hardware MAC address from IDR0..5 */
    for (i = 0; i < 6; i++) {
        ext->MacAddress[i] = READ_PORT_UCHAR((PUCHAR)(ULONG)(ext->IoBase + RTL_REG_IDR0 + i));
    }

    /* 4. Accept all multicast frames */
    WRITE_PORT_ULONG((PULONG)(ULONG)(ext->IoBase + RTL_REG_MAR0), 0xFFFFFFFFUL);
    WRITE_PORT_ULONG((PULONG)(ULONG)(ext->IoBase + RTL_REG_MAR0 + 4), 0xFFFFFFFFUL);

    /* 5. Program Receive Buffer Physical Start Address (RBSTART) */
    WRITE_PORT_ULONG((PULONG)(ULONG)(ext->IoBase + RTL_REG_RBSTART), ext->RxRingPhys);

    /* 6. Clear pending interrupts and set IMR = 0 (we use high-speed deterministic polling) */
    WRITE_PORT_USHORT((PUSHORT)(ULONG)(ext->IoBase + RTL_REG_IMR), 0x0000);
    WRITE_PORT_USHORT((PUSHORT)(ULONG)(ext->IoBase + RTL_REG_ISR), 0xFFFF);

    /* 7. Enable Receiver and Transmitter in Command Register BEFORE configuring RCR/TCR */
    WRITE_PORT_UCHAR((PUCHAR)(ULONG)(ext->IoBase + RTL_REG_CMD), RTL_CMD_RE | RTL_CMD_TE);

    /* 8. Configure RCR: Accept Broadcast(AB=0x08) + Multicast(AM=0x04) + Physical Match(APM=0x02) + All(AAP=0x01) + WRAP(0x80) */
    WRITE_PORT_ULONG((PULONG)(ULONG)(ext->IoBase + RTL_REG_RCR), 0x0000008FUL);

    /* 9. Configure TCR: Standard IFG + 1024-byte DMA burst */
    WRITE_PORT_ULONG((PULONG)(ULONG)(ext->IoBase + RTL_REG_TCR), 0x03000700UL);

    /* 10. Reset CAPR to 0xFFF0 (-16) */
    WRITE_PORT_USHORT((PUSHORT)(ULONG)(ext->IoBase + RTL_REG_CAPR), 0xFFF0);

    ext->HardwarePresent = TRUE;

    SerDbgPrint("[netdrv] RTL8139 PCI Fast Ethernet initialized at IoBase=0x");
    SerDbgHex32(ext->IoBase);
    SerDbgPrint(" IRQ=");
    SerDbgHex8(ext->IrqLine);
    SerDbgPrint(" MAC=");
    for (i = 0; i < 6; i++) {
        SerDbgHex8(ext->MacAddress[i]);
        if (i < 5) SerDbgPutc(':');
    }
    SerDbgPrint("\n");
    return TRUE;
}

static NTSTATUS Rtl8139TransmitFrame(PNETDRV_EXT ext, PUCHAR frameData, ULONG frameLen) {
    ULONG desc;
    ULONG sendLen;
    USHORT tsdPort, tsadPort;
    int timeout;

    if (!ext->HardwarePresent || !frameData || frameLen == 0 || frameLen > NET_MAX_PACKET_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    desc = ext->TxCurDesc & 3;
    ext->TxCurDesc = (desc + 1) & 3;

    RtlZeroMemory(ext->TxBufVirt[desc], 64);
    RtlCopyMemory(ext->TxBufVirt[desc], frameData, frameLen);
    sendLen = (frameLen < 60) ? 60 : frameLen;

    tsadPort = (USHORT)(ext->IoBase + RTL_REG_TSAD0 + (desc * 4));
    tsdPort  = (USHORT)(ext->IoBase + RTL_REG_TSD0  + (desc * 4));

    WRITE_PORT_ULONG((PULONG)(ULONG)tsadPort, ext->TxBufPhys[desc]);
    /* Writing length (bits 0..12) with OWN=0 starts PCI Bus Master DMA transmit */
    WRITE_PORT_ULONG((PULONG)(ULONG)tsdPort, sendLen & 0x1FFFUL);

    /* Wait briefly for OWN (bit 13) or TOK (bit 15) */
    timeout = 50000;
    while (--timeout > 0) {
        ULONG tsd = READ_PORT_ULONG((PULONG)(ULONG)tsdPort);
        if (tsd & 0xA000UL) break;
    }

    /* Acknowledge TOK/TER in ISR */
    WRITE_PORT_USHORT((PUSHORT)(ULONG)(ext->IoBase + RTL_REG_ISR), 0x000C);

    ext->TxPackets++;
    ext->TxBytes += frameLen;
    return STATUS_SUCCESS;
}

static ULONG Rtl8139ReceiveFrame(PNETDRV_EXT ext, PUCHAR outBuf, ULONG maxLen) {
    UCHAR cmd;
    ULONG offset;
    PUCHAR pktHdr;
    USHORT rxStatus;
    USHORT rxLen;
    ULONG payloadLen = 0;

    if (!ext->HardwarePresent || !outBuf || maxLen == 0) {
        return 0;
    }

    /* Check Command Register bit 0 (BUFE: 1 = RX Buffer Empty) */
    cmd = READ_PORT_UCHAR((PUCHAR)(ULONG)(ext->IoBase + RTL_REG_CMD));
    if (cmd & RTL_CMD_BUFE) {
        return 0;
    }

    offset = ext->RxReadOffset;
    pktHdr = ext->RxRingVirt + offset;
    rxStatus = *(USHORT *)pktHdr;
    rxLen    = *(USHORT *)(pktHdr + 2);

    /* Validate header: bit 0 = ROK, length 18..1536 */
    if ((rxStatus & 0x0001) == 0 || rxLen < 18 || rxLen > 1536) {
        /* Reset RX ring on corrupted header */
        ext->RxReadOffset = 0;
        WRITE_PORT_UCHAR((PUCHAR)(ULONG)(ext->IoBase + RTL_REG_CMD), RTL_CMD_TE);
        WRITE_PORT_ULONG((PULONG)(ULONG)(ext->IoBase + RTL_REG_RBSTART), ext->RxRingPhys);
        WRITE_PORT_USHORT((PUSHORT)(ULONG)(ext->IoBase + RTL_REG_CAPR), 0xFFF0);
        WRITE_PORT_UCHAR((PUCHAR)(ULONG)(ext->IoBase + RTL_REG_CMD), RTL_CMD_RE | RTL_CMD_TE);
        WRITE_PORT_ULONG((PULONG)(ULONG)(ext->IoBase + RTL_REG_RCR), 0x0000008FUL);
        WRITE_PORT_USHORT((PUSHORT)(ULONG)(ext->IoBase + RTL_REG_ISR), 0xFFFF);
        return 0;
    }

    /* Exclude 4-byte Ethernet CRC */
    payloadLen = (ULONG)(rxLen - 4);
    if (payloadLen > maxLen) {
        payloadLen = maxLen;
    }

    /* Because RCR has WRAP=1 (0x80), RTL8139 writes overflowing packets contiguously past 8K */
    RtlCopyMemory(outBuf, pktHdr + 4, payloadLen);

    /* Advance RxReadOffset (4-byte aligned) and update CAPR */
    offset = (offset + rxLen + 4 + 3) & ~3UL;
    offset %= RTL_RX_RING_SIZE;
    ext->RxReadOffset = offset;

    WRITE_PORT_USHORT((PUSHORT)(ULONG)(ext->IoBase + RTL_REG_CAPR), (USHORT)((offset - 16) & 0xFFFFU));
    WRITE_PORT_USHORT((PUSHORT)(ULONG)(ext->IoBase + RTL_REG_ISR), 0x0013);

    ext->RxPackets++;
    ext->RxBytes += payloadLen;
    return payloadLen;
}

static NTSTATUS NetCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS NetRead(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PNETDRV_EXT ext = (PNETDRV_EXT)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG outLen = irpSp->Parameters.Read.Length;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    ULONG got = 0;

    if (buf && outLen > 0) {
        got = Rtl8139ReceiveFrame(ext, (PUCHAR)buf, outLen);
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = got;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS NetWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PNETDRV_EXT ext = (PNETDRV_EXT)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG inLen = irpSp->Parameters.Write.Length;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;

    if (buf && inLen > 0) {
        status = Rtl8139TransmitFrame(ext, (PUCHAR)buf, inLen);
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = NT_SUCCESS(status) ? inLen : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS NetDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PNETDRV_EXT ext = (PNETDRV_EXT)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG info = 0;

    switch (code) {
    case IOCTL_NET_GET_INFO:
        if (outLen < sizeof(NET_ADAPTER_INFO) || !buf) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            PNET_ADAPTER_INFO ni = (PNET_ADAPTER_INFO)buf;
            RtlCopyMemory(ni->MacAddress, ext->MacAddress, 6);
            ni->IoBase       = ext->IoBase;
            ni->IrqLine      = ext->IrqLine;
            ni->LinkUp       = ext->HardwarePresent ? 1 : 0;
            ni->PciVendorId  = ext->PciVendorId;
            ni->PciDeviceId  = ext->PciDeviceId;
            ni->Ipv4Addr     = 0x0A00020FUL; /* 10.0.2.15 */
            ni->Ipv4Netmask  = 0xFFFFFF00UL; /* 255.255.255.0 */
            ni->Ipv4Gateway  = 0x0A000202UL; /* 10.0.2.2 */
            ni->Ipv4Dns      = 0x0A000203UL; /* 10.0.2.3 */
            ni->TxPackets    = ext->TxPackets;
            ni->RxPackets    = ext->RxPackets;
            ni->TxBytes      = ext->TxBytes;
            ni->RxBytes      = ext->RxBytes;
            info = sizeof(NET_ADAPTER_INFO);
        }
        break;

    case IOCTL_NET_SEND_PACKET:
        if (!buf || inLen == 0) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            status = Rtl8139TransmitFrame(ext, (PUCHAR)buf, inLen);
            if (NT_SUCCESS(status)) info = inLen;
        }
        break;

    case IOCTL_NET_RECV_PACKET:
        if (!buf || outLen == 0) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            info = Rtl8139ReceiveFrame(ext, (PUCHAR)buf, outLen);
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static void NetUnload(PDRIVER_OBJECT DriverObject) {
    PDEVICE_OBJECT devObj = DriverObject->DeviceObject;
    UNICODE_STRING sym0, sym1;

    RtlInitUnicodeString(&sym0, L"\\DosDevices\\net0");
    RtlInitUnicodeString(&sym1, L"\\DosDevices\\eth0");
    IoDeleteSymbolicLink(&sym0);
    IoDeleteSymbolicLink(&sym1);

    if (devObj) {
        PNETDRV_EXT ext = (PNETDRV_EXT)devObj->DeviceExtension;
        if (ext->HardwarePresent && ext->IoBase) {
            WRITE_PORT_UCHAR((PUCHAR)(ULONG)(ext->IoBase + RTL_REG_CMD), 0x00);
        }
        if (ext->DmaVirtBase) {
            MmFreeContiguousMemory(ext->DmaVirtBase);
            ext->DmaVirtBase = NULL;
        }
        IoDeleteDevice(devObj);
    }
    SerDbgPrint("[netdrv] Unloaded RTL8139 driver.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING devName, sym0, sym1;
    PDEVICE_OBJECT devObj = NULL;
    PNETDRV_EXT ext;
    NTSTATUS status;

    (void)RegistryPath;

    SerDbgPrint("\n=======================================================\n");
    SerDbgPrint("[netdrv] Initializing RTL8139 PCI Fast Ethernet Driver\n");
    SerDbgPrint("=======================================================\n");

    RtlInitUnicodeString(&devName, L"\\Device\\Net0");
    RtlInitUnicodeString(&sym0,    L"\\DosDevices\\net0");
    RtlInitUnicodeString(&sym1,    L"\\DosDevices\\eth0");

    status = IoCreateDevice(
        DriverObject,
        sizeof(NETDRV_EXT),
        &devName,
        FILE_DEVICE_NETDRV,
        0,
        FALSE,
        &devObj
    );
    if (!NT_SUCCESS(status)) {
        SerDbgPrint("[netdrv] ERROR: IoCreateDevice failed!\n");
        return status;
    }

    devObj->Flags |= DO_BUFFERED_IO;
    ext = (PNETDRV_EXT)devObj->DeviceExtension;
    RtlZeroMemory(ext, sizeof(NETDRV_EXT));
    ext->DeviceObject = devObj;

    ProbeAndInitRtl8139(ext);

    IoCreateSymbolicLink(&sym0, &devName);
    IoCreateSymbolicLink(&sym1, &devName);

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = NetCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = NetCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = NetCreateClose;
    DriverObject->MajorFunction[IRP_MJ_READ]           = NetRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE]          = NetWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NetDeviceControl;
    DriverObject->DriverUnload                         = NetUnload;

    devObj->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
