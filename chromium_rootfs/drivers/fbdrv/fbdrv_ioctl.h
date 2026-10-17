/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FBDRV_IOCTL_H
#define FBDRV_IOCTL_H

/*
 * rootfs/drivers/fbdrv/fbdrv_ioctl.h
 * Shared user/kernel header for Bochs/QEMU VBE Linear Framebuffer Driver (fbdrv.sys)
 * Device: \Device\fb0, Symlink: \DosDevices\fb0 (POSIX: /dev/fb0)
 */

#define FILE_DEVICE_FRAMEBUFFER 0x00008320

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#define METHOD_BUFFERED   0
#define METHOD_IN_DIRECT  1
#define METHOD_OUT_DIRECT 2
#define METHOD_NEITHER    3
#define FILE_ANY_ACCESS   0
#endif

#define IOCTL_FB_GET_INFO    CTL_CODE(FILE_DEVICE_FRAMEBUFFER, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FB_SET_MODE    CTL_CODE(FILE_DEVICE_FRAMEBUFFER, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FB_PRESENT     CTL_CODE(FILE_DEVICE_FRAMEBUFFER, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FB_MAP_USER    CTL_CODE(FILE_DEVICE_FRAMEBUFFER, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FB_FILL_RECT   CTL_CODE(FILE_DEVICE_FRAMEBUFFER, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FB_SET_TLS_GDT CTL_CODE(FILE_DEVICE_FRAMEBUFFER, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FB_ATA_READ    CTL_CODE(FILE_DEVICE_FRAMEBUFFER, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _FB_ATA_READ_REQ {
    unsigned long Lba;
    unsigned long Count;
    void         *UserBuffer;
} FB_ATA_READ_REQ, *PFB_ATA_READ_REQ;

typedef struct _FB_TLS_GDT_REQ {
    unsigned long BaseAddr;
    unsigned long VsyscallAddr;
    unsigned long EntryNumber;
} FB_TLS_GDT_REQ, *PFB_TLS_GDT_REQ;

typedef struct _FB_MODE_INFO {
    unsigned long Width;
    unsigned long Height;
    unsigned long Bpp;
    unsigned long Pitch;
    unsigned long SizeBytes;
    unsigned long PhysAddr;
    unsigned long VbeVersion;
    unsigned long UserMappedVa;
} FB_MODE_INFO, *PFB_MODE_INFO;

typedef struct _FB_PRESENT_REQ {
    void         *UserBuffer;  /* Pointer to userspace pixel data */
    unsigned long DstOffset;   /* Byte offset into framebuffer */
    unsigned long ByteLength;  /* Number of bytes to copy */
} FB_PRESENT_REQ, *PFB_PRESENT_REQ;

typedef struct _FB_RECT_REQ {
    unsigned long X;
    unsigned long Y;
    unsigned long Width;
    unsigned long Height;
    unsigned long Color;       /* 0x00RRGGBB */
} FB_RECT_REQ, *PFB_RECT_REQ;

#endif /* FBDRV_IOCTL_H */
