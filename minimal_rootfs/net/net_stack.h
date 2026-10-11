/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * minimal_rootfs/net/net_stack.h
 * TCP/IP + ARP + ICMP + UDP/DNS + HTTP/1.1
 * Network Stack for Windows XP Embedded 3 (over rtl8139.sys / \DosDevices\net0)
 */

#ifndef _EMBEDDED3_NET_STACK_H_
#define _EMBEDDED3_NET_STACK_H_

#include <stdint.h>
#include "../drivers/netdrv/netdrv_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HTTP_MAX_HEADERS_LEN  2048
#define HTTP_MAX_BODY_LEN     16384

typedef struct _NET_HTTP_RESPONSE {
    int      status_code;
    uint32_t resolved_ip;
    uint16_t remote_port;
    int      rtt_ms;
    int      tx_frames;
    int      rx_frames;
    int      bytes_received;
    char     host[128];
    char     path[256];
    char     request_headers[1024];
    char     response_headers[HTTP_MAX_HEADERS_LEN];
    char     body[HTTP_MAX_BODY_LEN];
} NET_HTTP_RESPONSE;

/* Initialize and query RTL8139 adapter status */
int  net_stack_init(void);
int  net_get_adapter_info(NET_ADAPTER_INFO *out_info);
void net_format_ip(uint32_t ip_host_order, char *buf, int buf_len);
int  net_parse_ipv4(const char *str, uint32_t *out_ip);

/* Protocol operations over \DosDevices\net0 (rtl8139.sys) */
int  net_arp_resolve(uint32_t target_ip, uint8_t out_mac[6]);
int  net_icmp_ping(uint32_t dst_ip, uint16_t seq, int *out_rtt_ms, int *out_ttl);
int  net_dns_resolve(const char *hostname, uint32_t *out_ip);
int  net_tcp_http_get(const char *url, NET_HTTP_RESPONSE *resp);

/* CLI Applets (ifconfig, ping, nslookup, wget, route, netstat) */
int  net_applet_main(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* _EMBEDDED3_NET_STACK_H_ */
