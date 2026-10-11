/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _USBDRV_H_
#define _USBDRV_H_

/*
 * minimal_rootfs/drivers/usbdrv/usbdrv.h
 * Shared Kernel/Userspace Header for Windows XP (NT 5.1) Universal USB Stack:
 *   - PCI USB Host Controllers: UHCI (1.1), OHCI (1.1), EHCI (2.0), xHCI (3.x)
 *   - USB Hub & Device Enumeration (Control EP0 GET_DESCRIPTOR / SET_ADDRESS / SET_CONFIG)
 *   - USB HID Boot Keyboard & Mouse Driver (auto-injected into \Device\RawKeyboard & \Device\RawMouse)
 *   - USB Mass Storage Bulk-Only Transport (BOT SCSI INQUIRY / READ CAPACITY / READ10)
 */

#define FILE_DEVICE_USB_STACK   0x00008000
#define IOCTL_USB_GET_INFO      0x00222804UL
#define IOCTL_USB_RESCAN        0x00222808UL
#define IOCTL_USB_READ_SECTOR   0x0022280CUL

#define USB_HC_TYPE_UHCI        1   /* PCI Class 0C:03:00 (USB 1.1) */
#define USB_HC_TYPE_OHCI        2   /* PCI Class 0C:03:10 (USB 1.1) */
#define USB_HC_TYPE_EHCI        3   /* PCI Class 0C:03:20 (USB 2.0) */
#define USB_HC_TYPE_XHCI        4   /* PCI Class 0C:03:30 (USB 3.x) */

#define USB_SPEED_LOW           1   /* 1.5 Mbps  */
#define USB_SPEED_FULL          2   /* 12 Mbps   */
#define USB_SPEED_HIGH          3   /* 480 Mbps  */
#define USB_SPEED_SUPER         4   /* 5000 Mbps */

#define USB_MAX_CONTROLLERS     8
#define USB_MAX_DEVICES         16

#pragma pack(push, 1)

typedef struct _USB_HC_INFO {
    unsigned long  Present;
    unsigned long  HcType;          /* USB_HC_TYPE_* */
    unsigned long  PciBus;
    unsigned long  PciSlot;
    unsigned long  PciFunc;
    unsigned short VendorId;
    unsigned short DeviceId;
    unsigned long  IoBase;          /* I/O BAR for UHCI */
    unsigned long  MmioPhys;        /* MMIO BAR for OHCI/EHCI/xHCI */
    unsigned long  IrqLine;
    unsigned long  NumPorts;
    unsigned long  PortsConnected;
    unsigned long  BiosLegacyActive;
    unsigned short HciVersion;
    unsigned short Reserved;
} USB_HC_INFO;

typedef struct _USB_DEV_INFO {
    unsigned long  Present;
    unsigned char  BusNumber;       /* Controller index (1..N) */
    unsigned char  PortNumber;      /* Root hub port (1..N) */
    unsigned char  DevAddress;      /* Assigned USB address (1..127) */
    unsigned char  Speed;           /* USB_SPEED_* */
    unsigned short VendorId;
    unsigned short ProductId;
    unsigned short BcdDevice;
    unsigned char  DeviceClass;
    unsigned char  DeviceSubClass;
    unsigned char  DeviceProtocol;
    unsigned char  InterfaceClass;
    unsigned char  InterfaceSubClass;
    unsigned char  InterfaceProtocol;
    unsigned char  EpIn;
    unsigned char  EpOut;
    unsigned short MaxPacketSize;
    unsigned long  StorageBlocks;   /* For USB Mass Storage (0x08) */
    unsigned long  StorageBlockSize;
    char           Manufacturer[32];
    char           Product[40];
    char           DriverName[16];  /* "usbhub", "usbhid-kbd", "usbhid-mouse", "usb-storage" */
} USB_DEV_INFO;

typedef struct _USB_STACK_INFO {
    unsigned long  ControllerCount;
    unsigned long  DeviceCount;
    unsigned long  HidKeyEvents;
    unsigned long  HidMouseEvents;
    unsigned long  StorageReads;
    unsigned long  ControlTransfers;
    USB_HC_INFO    Controllers[USB_MAX_CONTROLLERS];
    USB_DEV_INFO   Devices[USB_MAX_DEVICES];
} USB_STACK_INFO;

typedef struct _USB_SECTOR_REQ {
    unsigned long  DeviceIndex;
    unsigned long  Lba;
    unsigned char  Data[512];
} USB_SECTOR_REQ;

#pragma pack(pop)

#endif /* _USBDRV_H_ */
