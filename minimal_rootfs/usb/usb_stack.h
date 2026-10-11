/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _USB_STACK_H_
#define _USB_STACK_H_

#include <stdint.h>
#include "../drivers/usbdrv/usbdrv.h"

#ifdef __cplusplus
extern "C" {
#endif

int  usb_stack_init(void);
int  usb_get_stack_info(USB_STACK_INFO *out_info);
int  usb_rescan_bus(USB_STACK_INFO *out_info);
int  usb_read_storage_sector(uint32_t dev_idx, uint32_t lba, uint8_t out_sector[512]);
const char *usb_hc_type_name(uint32_t hc_type);
const char *usb_speed_name(uint32_t speed);

/* CLI Applets: lsusb, lsusb -t, lsusb -v, usbinfo, usbctl */
int  usb_applet_main(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* _USB_STACK_H_ */
