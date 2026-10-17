/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rootfs/usb/usb_stack.c
 * Userspace USB Stack Interface & lsusb / usbinfo Utilities for Windows XP (NT 5.1)
 * Communicates with kernel-mode usbdrv.sys via /dev/usb0 (\Device\Usb0) & /dev/sda
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "usb_stack.h"

static int g_usb_fd = -1;

const char *usb_hc_type_name(uint32_t hc_type) {
    switch (hc_type) {
        case USB_HC_TYPE_UHCI: return "UHCI (USB 1.1)";
        case USB_HC_TYPE_OHCI: return "OHCI (USB 1.1)";
        case USB_HC_TYPE_EHCI: return "EHCI (USB 2.0)";
        case USB_HC_TYPE_XHCI: return "xHCI (USB 3.x)";
        default:               return "USB Host";
    }
}

const char *usb_speed_name(uint32_t speed) {
    switch (speed) {
        case USB_SPEED_LOW:   return "1.5M";
        case USB_SPEED_FULL:  return "12M";
        case USB_SPEED_HIGH:  return "480M";
        case USB_SPEED_SUPER: return "5000M";
        default:              return "12M";
    }
}

int usb_stack_init(void) {
    if (g_usb_fd < 0) {
        g_usb_fd = open("/dev/usb0", O_RDWR);
    }
    return (g_usb_fd >= 0) ? 0 : -1;
}

int usb_get_stack_info(USB_STACK_INFO *out_info) {
    if (!out_info) return -1;
    memset(out_info, 0, sizeof(*out_info));
    if (g_usb_fd < 0) {
        g_usb_fd = open("/dev/usb0", O_RDWR);
    }
    if (g_usb_fd >= 0) {
        ssize_t r = read(g_usb_fd, out_info, sizeof(*out_info));
        if (r >= (ssize_t)sizeof(uint32_t) * 6) {
            return 0;
        }
    }
    return -1;
}

int usb_rescan_bus(USB_STACK_INFO *out_info) {
    if (!out_info) return -1;
    memset(out_info, 0, sizeof(*out_info));
    if (g_usb_fd < 0) {
        g_usb_fd = open("/dev/usb0", O_RDWR);
    }
    if (g_usb_fd >= 0) {
        ioctl(g_usb_fd, IOCTL_USB_RESCAN, out_info);
        read(g_usb_fd, out_info, sizeof(*out_info));
        return 0;
    }
    return -1;
}

int usb_read_storage_sector(uint32_t dev_idx, uint32_t lba, uint8_t out_sector[512]) {
    (void)dev_idx;
    if (g_usb_fd < 0) {
        g_usb_fd = open("/dev/usb0", O_RDWR);
    }
    if (g_usb_fd < 0) return -1;
    lseek(g_usb_fd, (off_t)lba * 512, SEEK_SET);
    ssize_t r = read(g_usb_fd, out_sector, 512);
    return (r == 512) ? 0 : -1;
}

int usb_applet_main(int argc, char **argv) {
    const char *prog = (argc > 0 && argv[0]) ? argv[0] : "lsusb";
    const char *slash = strrchr(prog, '/');
    if (slash) prog = slash + 1;

    USB_STACK_INFO info;
    if (usb_get_stack_info(&info) < 0) {
        printf("[usb] /dev/usb0 not open; load usbdrv.sys via 'insmod /lib/modules/usbdrv.sys'\n");
        return 1;
    }

    int opt_tree = 0;
    int opt_verbose = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tree") == 0) opt_tree = 1;
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) opt_verbose = 1;
        if (strcmp(argv[i], "rescan") == 0) usb_rescan_bus(&info);
    }

    if (strcmp(prog, "usbinfo") == 0 || strcmp(prog, "usbctl") == 0 || opt_verbose) {
        printf("==========================================================================\n");
        printf("  Windows XP (NT 5.1) Experimental USB stack (UHCI transfers only)\n");
        printf("  Controllers: %lu | Devices: %lu | Control Transfers: %lu | HID Events: %lu\n",
               (unsigned long)info.ControllerCount,
               (unsigned long)info.DeviceCount,
               (unsigned long)info.ControlTransfers,
               (unsigned long)(info.HidKeyEvents + info.HidMouseEvents));
        printf("==========================================================================\n");
        for (uint32_t i = 0; i < info.ControllerCount; i++) {
            const USB_HC_INFO *hc = &info.Controllers[i];
            printf("  [Bus %03u] %s PCI %02lx:%02lx.%lu (%04x:%04x) ",
                   i + 1, usb_hc_type_name(hc->HcType),
                   (unsigned long)hc->PciBus, (unsigned long)hc->PciSlot, (unsigned long)hc->PciFunc,
                   hc->VendorId, hc->DeviceId);
            if (hc->IoBase) {
                printf("IO=0x%04lx ", (unsigned long)hc->IoBase);
            } else {
                printf("MMIO=0x%08lx ", (unsigned long)hc->MmioPhys);
            }
            printf("IRQ=%lu Ports=%lu (Connected=%lu)%s\n",
                   (unsigned long)hc->IrqLine,
                   (unsigned long)hc->NumPorts,
                   (unsigned long)hc->PortsConnected,
                   hc->BiosLegacyActive ? " [BIOS-SMM-Active]" : "");
        }
        printf("--------------------------------------------------------------------------\n");
        for (uint32_t i = 0; i < info.DeviceCount; i++) {
            const USB_DEV_INFO *d = &info.Devices[i];
            printf("  Bus %03u Port %u Dev %03u: ID %04x:%04x %s %s (%s, Driver=%s)",
                   d->BusNumber, d->PortNumber, d->DevAddress,
                   d->VendorId, d->ProductId,
                   d->Manufacturer, d->Product,
                   usb_speed_name(d->Speed), d->DriverName);
            if (d->InterfaceClass == 0x08 && d->StorageBlocks > 0) {
                printf(" [%lu MB]", (unsigned long)((d->StorageBlocks / 2048)));
            }
            printf("\n");
        }
        return 0;
    }

    if (opt_tree) {
        for (uint32_t b = 0; b < info.ControllerCount; b++) {
            const USB_HC_INFO *hc = &info.Controllers[b];
            printf("/:  Bus %02u.Port 1: Dev 1, Class=root_hub, Driver=%s/%lup, %s\n",
                   b + 1,
                   (hc->HcType == USB_HC_TYPE_UHCI) ? "nt51-uhci" : "unsupported",
                   (unsigned long)hc->NumPorts,
                   (hc->HcType == USB_HC_TYPE_XHCI) ? "5000M" :
                   (hc->HcType == USB_HC_TYPE_EHCI) ? "480M" : "12M");
            for (uint32_t i = 0; i < info.DeviceCount; i++) {
                const USB_DEV_INFO *d = &info.Devices[i];
                if (d->BusNumber == (b + 1) && d->PortNumber > 0) {
                    printf("    |__ Port %u: Dev %u, If 0, Class=0x%02x, Driver=%s, %s (%04x:%04x %s)\n",
                           d->PortNumber, d->DevAddress, d->InterfaceClass,
                           d->DriverName, usb_speed_name(d->Speed),
                           d->VendorId, d->ProductId, d->Product);
                }
            }
        }
        return 0;
    }

    /* Standard Linux 'lsusb' output */
    for (uint32_t i = 0; i < info.DeviceCount; i++) {
        const USB_DEV_INFO *d = &info.Devices[i];
        printf("Bus %03u Device %03u: ID %04x:%04x %s %s [%s, %s]\n",
               d->BusNumber, d->DevAddress,
               d->VendorId, d->ProductId,
               d->Manufacturer, d->Product,
               d->DriverName, usb_speed_name(d->Speed));
    }
    return 0;
}
