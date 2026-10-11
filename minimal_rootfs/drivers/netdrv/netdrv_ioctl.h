/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * minimal_rootfs/drivers/netdrv/netdrv_ioctl.h
 * Shared Kernel/Userspace IOCTL definitions for RTL8139 PCI Fast Ethernet Driver
 * Exposes \Device\Net0 and \DosDevices\net0 (/dev/net0, /dev/eth0)
 */

#ifndef _NETDRV_IOCTL_H_
#define _NETDRV_IOCTL_H_

#define FILE_DEVICE_NETDRV      0x00008020

#define IOCTL_NET_GET_INFO      0x80202004UL  /* CTL_CODE(0x8020, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) */
#define IOCTL_NET_SEND_PACKET   0x80202008UL  /* CTL_CODE(0x8020, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) */
#define IOCTL_NET_RECV_PACKET   0x8020200CUL  /* CTL_CODE(0x8020, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS) */
#define IOCTL_NET_RESET         0x80202010UL  /* CTL_CODE(0x8020, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS) */

#define NET_MAX_PACKET_SIZE     1536

#pragma pack(push, 1)
typedef struct _NET_ADAPTER_INFO {
    unsigned char  MacAddress[6];
    unsigned short IoBase;
    unsigned char  IrqLine;
    unsigned char  LinkUp;
    unsigned short PciVendorId;
    unsigned short PciDeviceId;
    unsigned long  Ipv4Addr;       /* Host byte order: 0x0A00020F = 10.0.2.15 */
    unsigned long  Ipv4Netmask;    /* Host byte order: 0xFFFFFF00 = 255.255.255.0 */
    unsigned long  Ipv4Gateway;    /* Host byte order: 0x0A000202 = 10.0.2.2 */
    unsigned long  Ipv4Dns;        /* Host byte order: 0x0A000203 = 10.0.2.3 */
    unsigned long  TxPackets;
    unsigned long  RxPackets;
    unsigned long  TxBytes;
    unsigned long  RxBytes;
} NET_ADAPTER_INFO, *PNET_ADAPTER_INFO;
#pragma pack(pop)

#endif /* _NETDRV_IOCTL_H_ */
