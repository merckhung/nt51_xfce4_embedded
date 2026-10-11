/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rootfs/net/net_stack.c
 * Complete Ethernet II + ARP + IPv4 + ICMP + UDP/DNS + TCP + HTTP/1.1 Stack
 *
 * for Windows XP Embedded 3 (over rtl8139.sys / \DosDevices\net0)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "net_stack.h"

/* ========================================================================= */
/* Direct NT 5.1 System Call Interface                                       */
/* ========================================================================= */

typedef long NTSTATUS;
typedef void *HANDLE;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

typedef struct _NT_UNICODE_STRING {
    uint16_t Length;
    uint16_t MaximumLength;
    uint16_t *Buffer;
} NT_UNICODE_STRING;

typedef struct _NT_OBJECT_ATTRIBUTES {
    unsigned long Length;
    HANDLE RootDirectory;
    NT_UNICODE_STRING *ObjectName;
    unsigned long Attributes;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
} NT_OBJECT_ATTRIBUTES;

typedef struct _NT_IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        void *Pointer;
    };
    unsigned long Information;
} NT_IO_STATUS_BLOCK;

typedef union _NT_LARGE_INTEGER {
    struct {
        unsigned long LowPart;
        long HighPart;
    };
    long long QuadPart;
} NT_LARGE_INTEGER;

#define NTSYS_Close                 25
#define NTSYS_CreateFile            37
#define NTSYS_DelayExecution        59
#define NTSYS_DeviceIoControlFile   66

extern long DoNtSyscall(unsigned long id, const unsigned long *args, unsigned int count);

static void net_init_ustr(NT_UNICODE_STRING *u, uint16_t *buf, const char *ascii) {
    int i = 0;
    while (ascii[i]) {
        buf[i] = (uint16_t)(unsigned char)ascii[i];
        i++;
    }
    buf[i] = 0;
    u->Length = (uint16_t)(i * 2);
    u->MaximumLength = (uint16_t)((i + 1) * 2);
    u->Buffer = buf;
}

static HANDLE g_hNetDev = NULL;
static NET_ADAPTER_INFO g_NetInfo;
static int g_NetInitialized = 0;
static uint8_t g_GatewayMac[6] = { 0x52, 0x54, 0x00, 0x12, 0x35, 0x02 };
static int g_GatewayMacResolved = 0;
static uint16_t g_IpIdCounter = 0x1337;
static uint16_t g_EphemeralPort = 49152;

static void net_sleep_ms(int ms) {
    NT_LARGE_INTEGER delay;
    delay.QuadPart = -((long long)ms * 10000LL);
    unsigned long a[2] = { 0, (unsigned long)&delay };
    DoNtSyscall(NTSYS_DelayExecution, a, 2);
}

static NTSTATUS net_ioctl(unsigned long code, void *inBuf, unsigned long inLen, void *outBuf, unsigned long outLen, unsigned long *outBytes) {
    if (!g_hNetDev) return -1;
    NT_IO_STATUS_BLOCK iosb;
    memset(&iosb, 0, sizeof(iosb));
    unsigned long a[10] = {
        (unsigned long)g_hNetDev, 0, 0, 0,
        (unsigned long)&iosb,
        code,
        (unsigned long)inBuf, inLen,
        (unsigned long)outBuf, outLen
    };
    NTSTATUS st = DoNtSyscall(NTSYS_DeviceIoControlFile, a, 10);
    if (outBytes) *outBytes = iosb.Information;
    return st;
}

int net_stack_init(void) {
    if (g_hNetDev) {
        unsigned long got = 0;
        net_ioctl(IOCTL_NET_GET_INFO, NULL, 0, &g_NetInfo, sizeof(g_NetInfo), &got);
        return 0;
    }

    uint16_t wbuf[64];
    NT_UNICODE_STRING u;
    NT_OBJECT_ATTRIBUTES oa;
    NT_IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;

    net_init_ustr(&u, wbuf, "\\DosDevices\\net0");
    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.Attributes = 0x40; /* OBJ_CASE_INSENSITIVE */
    oa.ObjectName = &u;
    memset(&iosb, 0, sizeof(iosb));

    unsigned long a[11] = {
        (unsigned long)&h,
        0xC0100000UL, /* GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE */
        (unsigned long)&oa,
        (unsigned long)&iosb,
        0, 0,
        3, /* FILE_SHARE_READ | FILE_SHARE_WRITE */
        1, /* FILE_OPEN */
        0x00000020UL, /* FILE_SYNCHRONOUS_IO_NONALERT */
        0, 0
    };
    NTSTATUS st = DoNtSyscall(NTSYS_CreateFile, a, 11);
    if (!NT_SUCCESS(st) || !h) {
        /* Fallback defaults if driver not yet loaded */
        g_NetInfo.MacAddress[0] = 0x52; g_NetInfo.MacAddress[1] = 0x54;
        g_NetInfo.MacAddress[2] = 0x00; g_NetInfo.MacAddress[3] = 0x12;
        g_NetInfo.MacAddress[4] = 0x34; g_NetInfo.MacAddress[5] = 0x56;
        g_NetInfo.IoBase      = 0xC100;
        g_NetInfo.IrqLine     = 11;
        g_NetInfo.LinkUp      = 1;
        g_NetInfo.PciVendorId = 0x10EC;
        g_NetInfo.PciDeviceId = 0x8139;
        g_NetInfo.Ipv4Addr    = 0x0A00020FUL;
        g_NetInfo.Ipv4Netmask = 0xFFFFFF00UL;
        g_NetInfo.Ipv4Gateway = 0x0A000202UL;
        g_NetInfo.Ipv4Dns     = 0x0A000203UL;
        return -1;
    }

    g_hNetDev = h;
    unsigned long got = 0;
    net_ioctl(IOCTL_NET_GET_INFO, NULL, 0, &g_NetInfo, sizeof(g_NetInfo), &got);
    g_NetInitialized = 1;
    return 0;
}

int net_get_adapter_info(NET_ADAPTER_INFO *out_info) {
    net_stack_init();
    if (out_info) {
        memcpy(out_info, &g_NetInfo, sizeof(NET_ADAPTER_INFO));
    }
    return g_hNetDev ? 0 : -1;
}

void net_format_ip(uint32_t ip, char *buf, int buf_len) {
    snprintf(buf, buf_len, "%u.%u.%u.%u",
             (unsigned)((ip >> 24) & 0xFF),
             (unsigned)((ip >> 16) & 0xFF),
             (unsigned)((ip >> 8)  & 0xFF),
             (unsigned)(ip & 0xFF));
}

int net_parse_ipv4(const char *str, uint32_t *out_ip) {
    if (!str || !out_ip) return -1;
    unsigned int a = 0, b = 0, c = 0, d = 0;
    int dots = 0;
    const char *p = str;
    while (*p) {
        if (*p == '.') dots++;
        else if (*p < '0' || *p > '9') return -1;
        p++;
    }
    if (dots != 3) return -1;
    if (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        if (a <= 255 && b <= 255 && c <= 255 && d <= 255) {
            *out_ip = ((a & 0xFF) << 24) | ((b & 0xFF) << 16) | ((c & 0xFF) << 8) | (d & 0xFF);
            return 0;
        }
    }
    return -1;
}

/* ========================================================================= */
/* Byte-Order & Checksum Helpers                                             */
/* ========================================================================= */

static uint16_t bswap16(uint16_t v) {
    return (uint16_t)((v >> 8) | (v << 8));
}

static uint32_t bswap32(uint32_t v) {
    return ((v >> 24) & 0x000000FFUL)
         | ((v >> 8)  & 0x0000FF00UL)
         | ((v << 8)  & 0x00FF0000UL)
         | ((v << 24) & 0xFF000000UL);
}

static uint16_t ip_checksum(const void *data, int len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += ((uint16_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len > 0) {
        sum += ((uint16_t)p[0] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return bswap16((uint16_t)(~sum));
}

static uint16_t tcp_udp_checksum(uint32_t src_ip_host, uint32_t dst_ip_host, uint8_t proto, const void *payload, int len) {
    uint32_t sum = 0;
    const uint8_t *p = (const uint8_t *)payload;
    int i;

    sum += (src_ip_host >> 16) & 0xFFFF;
    sum += src_ip_host & 0xFFFF;
    sum += (dst_ip_host >> 16) & 0xFFFF;
    sum += dst_ip_host & 0xFFFF;
    sum += proto;
    sum += (uint16_t)len;

    for (i = 0; i + 1 < len; i += 2) {
        sum += ((uint16_t)p[i] << 8) | p[i + 1];
    }
    if (len & 1) {
        sum += ((uint16_t)p[len - 1] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    uint16_t res = (uint16_t)(~sum);
    if (res == 0 && proto == 17) res = 0xFFFF;
    return bswap16(res);
}

/* ========================================================================= */
/* Packet Headers (Ethernet II, ARP, IPv4, ICMP, UDP, TCP)                   */
/* ========================================================================= */

#pragma pack(push, 1)
typedef struct {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
} ETH_HDR;

typedef struct {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  sha[6];
    uint32_t spa;
    uint8_t  tha[6];
    uint32_t tpa;
} ARP_PKT;

typedef struct {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} IPV4_HDR;

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} ICMP_HDR;

typedef struct {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} UDP_HDR;

typedef struct {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  doff_res;
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} TCP_HDR;
#pragma pack(pop)

#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10

static int tx_eth_frame(const void *frame, int len) {
    net_stack_init();
    if (!g_hNetDev) return -1;
    unsigned long sent = 0;
    NTSTATUS st = net_ioctl(IOCTL_NET_SEND_PACKET, (void *)frame, (unsigned long)len, NULL, 0, &sent);
    return NT_SUCCESS(st) ? (int)sent : -1;
}

static int rx_eth_frame(uint8_t *buf, int max_len) {
    net_stack_init();
    if (!g_hNetDev) return 0;
    unsigned long got = 0;
    NTSTATUS st = net_ioctl(IOCTL_NET_RECV_PACKET, NULL, 0, buf, (unsigned long)max_len, &got);
    if (!NT_SUCCESS(st) || got < 14) return 0;

    /* Automatically reply to incoming ARP requests for our IP (10.0.2.15) */
    ETH_HDR *eth = (ETH_HDR *)buf;
    if (bswap16(eth->ethertype) == 0x0806 && got >= sizeof(ETH_HDR) + sizeof(ARP_PKT)) {
        ARP_PKT *arp = (ARP_PKT *)(buf + sizeof(ETH_HDR));
        if (bswap16(arp->oper) == 1 && bswap32(arp->tpa) == g_NetInfo.Ipv4Addr) {
            uint8_t reply[64];
            memset(reply, 0, sizeof(reply));
            ETH_HDR *reth = (ETH_HDR *)reply;
            ARP_PKT *rarp = (ARP_PKT *)(reply + sizeof(ETH_HDR));
            memcpy(reth->dst, arp->sha, 6);
            memcpy(reth->src, g_NetInfo.MacAddress, 6);
            reth->ethertype = bswap16(0x0806);
            rarp->htype = bswap16(1);
            rarp->ptype = bswap16(0x0800);
            rarp->hlen  = 6;
            rarp->plen  = 4;
            rarp->oper  = bswap16(2);
            memcpy(rarp->sha, g_NetInfo.MacAddress, 6);
            rarp->spa   = bswap32(g_NetInfo.Ipv4Addr);
            memcpy(rarp->tha, arp->sha, 6);
            rarp->tpa   = arp->spa;
            tx_eth_frame(reply, sizeof(ETH_HDR) + sizeof(ARP_PKT));
        }
    }
    return (int)got;
}

/* ========================================================================= */
/* ARP Resolution                                                            */
/* ========================================================================= */

int net_arp_resolve(uint32_t target_ip, uint8_t out_mac[6]) {
    net_stack_init();
    uint32_t next_hop = target_ip;
    if ((target_ip & g_NetInfo.Ipv4Netmask) != (g_NetInfo.Ipv4Addr & g_NetInfo.Ipv4Netmask)) {
        next_hop = g_NetInfo.Ipv4Gateway;
    }

    if (next_hop == g_NetInfo.Ipv4Gateway && g_GatewayMacResolved) {
        memcpy(out_mac, g_GatewayMac, 6);
        return 0;
    }

    uint8_t pkt[64];
    memset(pkt, 0, sizeof(pkt));
    ETH_HDR *eth = (ETH_HDR *)pkt;
    ARP_PKT *arp = (ARP_PKT *)(pkt + sizeof(ETH_HDR));

    memset(eth->dst, 0xFF, 6);
    memcpy(eth->src, g_NetInfo.MacAddress, 6);
    eth->ethertype = bswap16(0x0806);

    arp->htype = bswap16(1);
    arp->ptype = bswap16(0x0800);
    arp->hlen  = 6;
    arp->plen  = 4;
    arp->oper  = bswap16(1); /* ARP Request */
    memcpy(arp->sha, g_NetInfo.MacAddress, 6);
    arp->spa   = bswap32(g_NetInfo.Ipv4Addr);
    memset(arp->tha, 0x00, 6);
    arp->tpa   = bswap32(next_hop);

    int attempt, wait_iter;
    uint8_t rxbuf[1536];
    for (attempt = 0; attempt < 3; attempt++) {
        tx_eth_frame(pkt, sizeof(ETH_HDR) + sizeof(ARP_PKT));
        for (wait_iter = 0; wait_iter < 40; wait_iter++) {
            int n = rx_eth_frame(rxbuf, sizeof(rxbuf));
            if (n >= (int)(sizeof(ETH_HDR) + sizeof(ARP_PKT))) {
                ETH_HDR *reth = (ETH_HDR *)rxbuf;
                if (bswap16(reth->ethertype) == 0x0806) {
                    ARP_PKT *rarp = (ARP_PKT *)(rxbuf + sizeof(ETH_HDR));
                    if (bswap16(rarp->oper) == 2 && bswap32(rarp->spa) == next_hop) {
                        memcpy(out_mac, rarp->sha, 6);
                        if (next_hop == g_NetInfo.Ipv4Gateway) {
                            memcpy(g_GatewayMac, rarp->sha, 6);
                            g_GatewayMacResolved = 1;
                        }
                        return 0;
                    }
                }
            }
            net_sleep_ms(2);
        }
    }

    /* A missing ARP reply cannot establish the next-hop address. */
    return -1;
}

/* ========================================================================= */
/* ICMP Echo Request / Reply (ping)                                          */
/* ========================================================================= */

int net_icmp_ping(uint32_t dst_ip, uint16_t seq, int *out_rtt_ms, int *out_ttl) {
    net_stack_init();
    uint8_t dst_mac[6];
    if (net_arp_resolve(dst_ip, dst_mac) < 0) return -1;

    uint8_t pkt[128];
    memset(pkt, 0, sizeof(pkt));
    ETH_HDR  *eth  = (ETH_HDR *)pkt;
    IPV4_HDR *ip   = (IPV4_HDR *)(pkt + sizeof(ETH_HDR));
    ICMP_HDR *icmp = (ICMP_HDR *)(pkt + sizeof(ETH_HDR) + sizeof(IPV4_HDR));
    uint8_t  *data = pkt + sizeof(ETH_HDR) + sizeof(IPV4_HDR) + sizeof(ICMP_HDR);

    memcpy(eth->dst, dst_mac, 6);
    memcpy(eth->src, g_NetInfo.MacAddress, 6);
    eth->ethertype = bswap16(0x0800);

    int payload_len = 32;
    int ip_len = sizeof(IPV4_HDR) + sizeof(ICMP_HDR) + payload_len;

    ip->ver_ihl  = 0x45;
    ip->tos      = 0;
    ip->tot_len  = bswap16((uint16_t)ip_len);
    ip->id       = bswap16(++g_IpIdCounter);
    ip->frag_off = bswap16(0x4000);
    ip->ttl      = 64;
    ip->protocol = 1; /* ICMP */
    ip->saddr    = bswap32(g_NetInfo.Ipv4Addr);
    ip->daddr    = bswap32(dst_ip);
    ip->check    = 0;
    ip->check    = ip_checksum(ip, sizeof(IPV4_HDR));

    icmp->type     = 8; /* Echo Request */
    icmp->code     = 0;
    icmp->id       = bswap16(0x5150);
    icmp->sequence = bswap16(seq);
    memcpy(data, "WindowsXP-NT5.1-RTL8139-PingTest", 32);
    icmp->checksum = 0;
    icmp->checksum = ip_checksum(icmp, sizeof(ICMP_HDR) + payload_len);

    if (tx_eth_frame(pkt, sizeof(ETH_HDR) + ip_len) < 0) {
        return -1;
    }

    uint8_t rxbuf[1536];
    int wait_ms;
    for (wait_ms = 0; wait_ms < 250; wait_ms += 2) {
        int n = rx_eth_frame(rxbuf, sizeof(rxbuf));
        if (n >= (int)(sizeof(ETH_HDR) + sizeof(IPV4_HDR) + sizeof(ICMP_HDR))) {
            ETH_HDR *reth = (ETH_HDR *)rxbuf;
            if (bswap16(reth->ethertype) == 0x0800) {
                IPV4_HDR *rip = (IPV4_HDR *)(rxbuf + sizeof(ETH_HDR));
                if (rip->protocol == 1) {
                    ICMP_HDR *ricmp = (ICMP_HDR *)(rxbuf + sizeof(ETH_HDR) + ((rip->ver_ihl & 0x0F) * 4));
                    if (ricmp->type == 0 && bswap16(ricmp->id) == 0x5150 && bswap16(ricmp->sequence) == seq) {
                        if (out_rtt_ms) *out_rtt_ms = (wait_ms == 0) ? 1 : wait_ms;
                        if (out_ttl)    *out_ttl    = rip->ttl;
                        return 0;
                    }
                }
            }
        }
        net_sleep_ms(2);
    }
    return -1;
}

/* ========================================================================= */
/* UDP DNS Resolver (Queries 10.0.2.3:53 over RTL8139)                       */
/* ========================================================================= */

int net_dns_resolve(const char *hostname, uint32_t *out_ip) {
    if (!hostname || !out_ip) return -1;
    if (net_parse_ipv4(hostname, out_ip) == 0) {
        return 0;
    }
    if (strcmp(hostname, "localhost") == 0 || strcmp(hostname, "host.qemu") == 0) {
        *out_ip = 0x0A000202UL; /* 10.0.2.2 */
        return 0;
    }

    net_stack_init();
    uint8_t dst_mac[6];
    net_arp_resolve(g_NetInfo.Ipv4Dns, dst_mac);

    uint8_t pkt[512];
    memset(pkt, 0, sizeof(pkt));
    ETH_HDR  *eth = (ETH_HDR *)pkt;
    IPV4_HDR *ip  = (IPV4_HDR *)(pkt + sizeof(ETH_HDR));
    UDP_HDR  *udp = (UDP_HDR *)(pkt + sizeof(ETH_HDR) + sizeof(IPV4_HDR));
    uint8_t  *dns = pkt + sizeof(ETH_HDR) + sizeof(IPV4_HDR) + sizeof(UDP_HDR);

    /* Build DNS Header (12 bytes) */
    uint16_t dns_id = 0x4242 + (++g_IpIdCounter & 0xFF);
    dns[0] = (uint8_t)(dns_id >> 8);
    dns[1] = (uint8_t)(dns_id & 0xFF);
    dns[2] = 0x01; /* Flags: Standard Query, Recursion Desired */
    dns[3] = 0x00;
    dns[4] = 0x00; dns[5] = 0x01; /* QDCOUNT = 1 */

    /* Encode QNAME labels */
    int qpos = 12;
    const char *p = hostname;
    while (*p) {
        const char *dot = strchr(p, '.');
        int lbl_len = dot ? (int)(dot - p) : (int)strlen(p);
        if (lbl_len <= 0 || lbl_len > 63 || qpos + lbl_len + 6 >= 256) break;
        dns[qpos++] = (uint8_t)lbl_len;
        memcpy(&dns[qpos], p, lbl_len);
        qpos += lbl_len;
        if (!dot) break;
        p = dot + 1;
    }
    dns[qpos++] = 0x00; /* Root label */
    dns[qpos++] = 0x00; dns[qpos++] = 0x01; /* QTYPE = A (1) */
    dns[qpos++] = 0x00; dns[qpos++] = 0x01; /* QCLASS = IN (1) */

    int udp_len = sizeof(UDP_HDR) + qpos;
    int ip_len  = sizeof(IPV4_HDR) + udp_len;

    memcpy(eth->dst, dst_mac, 6);
    memcpy(eth->src, g_NetInfo.MacAddress, 6);
    eth->ethertype = bswap16(0x0800);

    ip->ver_ihl  = 0x45;
    ip->tos      = 0;
    ip->tot_len  = bswap16((uint16_t)ip_len);
    ip->id       = bswap16(++g_IpIdCounter);
    ip->frag_off = bswap16(0x4000);
    ip->ttl      = 64;
    ip->protocol = 17; /* UDP */
    ip->saddr    = bswap32(g_NetInfo.Ipv4Addr);
    ip->daddr    = bswap32(g_NetInfo.Ipv4Dns);
    ip->check    = 0;
    ip->check    = ip_checksum(ip, sizeof(IPV4_HDR));

    uint16_t sport = ++g_EphemeralPort;
    udp->source = bswap16(sport);
    udp->dest   = bswap16(53);
    udp->len    = bswap16((uint16_t)udp_len);
    udp->check  = 0;
    udp->check  = tcp_udp_checksum(g_NetInfo.Ipv4Addr, g_NetInfo.Ipv4Dns, 17, udp, udp_len);

    tx_eth_frame(pkt, sizeof(ETH_HDR) + ip_len);

    uint8_t rxbuf[1536];
    int wait_ms;
    for (wait_ms = 0; wait_ms < 400; wait_ms += 4) {
        int n = rx_eth_frame(rxbuf, sizeof(rxbuf));
        if (n >= (int)(sizeof(ETH_HDR) + sizeof(IPV4_HDR) + sizeof(UDP_HDR) + 12)) {
            ETH_HDR *reth = (ETH_HDR *)rxbuf;
            if (bswap16(reth->ethertype) == 0x0800) {
                IPV4_HDR *rip = (IPV4_HDR *)(rxbuf + sizeof(ETH_HDR));
                int ihl = (rip->ver_ihl & 0x0F) * 4;
                if (rip->protocol == 17) {
                    UDP_HDR *rudp = (UDP_HDR *)(rxbuf + sizeof(ETH_HDR) + ihl);
                    if (bswap16(rudp->source) == 53 && bswap16(rudp->dest) == sport) {
                        uint8_t *rdns = (uint8_t *)rudp + sizeof(UDP_HDR);
                        int rdns_len = n - (int)(sizeof(ETH_HDR) + ihl + sizeof(UDP_HDR));
                        uint16_t r_id = ((uint16_t)rdns[0] << 8) | rdns[1];
                        uint16_t ancount = ((uint16_t)rdns[6] << 8) | rdns[7];
                        if (r_id == dns_id && ancount > 0) {
                            /* Scan answer section for TYPE A (0x0001) CLASS IN (0x0001) RDLENGTH 4 (0x0004) */
                            int idx;
                            for (idx = qpos; idx + 14 <= rdns_len; idx++) {
                                if (rdns[idx] == 0x00 && rdns[idx + 1] == 0x01 &&
                                    rdns[idx + 2] == 0x00 && rdns[idx + 3] == 0x01 &&
                                    rdns[idx + 8] == 0x00 && rdns[idx + 9] == 0x04) {
                                    *out_ip = ((uint32_t)rdns[idx + 10] << 24)
                                            | ((uint32_t)rdns[idx + 11] << 16)
                                            | ((uint32_t)rdns[idx + 12] << 8)
                                            | ((uint32_t)rdns[idx + 13]);
                                    return 0;
                                }
                            }
                        }
                    }
                }
            }
        }
        net_sleep_ms(4);
    }

    *out_ip = 0;
    return -1;
}

/* ========================================================================= */
/* Real TCP Client State Machine & HTTP/1.1 Engine over RTL8139              */
/* ========================================================================= */

static void send_tcp_segment(
    const uint8_t dst_mac[6],
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t seq,
    uint32_t ack,
    uint8_t  flags,
    const void *payload,
    int payload_len
) {
    uint8_t pkt[1536];
    memset(pkt, 0, sizeof(pkt));
    ETH_HDR  *eth = (ETH_HDR *)pkt;
    IPV4_HDR *ip  = (IPV4_HDR *)(pkt + sizeof(ETH_HDR));
    TCP_HDR  *tcp = (TCP_HDR *)(pkt + sizeof(ETH_HDR) + sizeof(IPV4_HDR));
    uint8_t  *dat = pkt + sizeof(ETH_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR);

    memcpy(eth->dst, dst_mac, 6);
    memcpy(eth->src, g_NetInfo.MacAddress, 6);
    eth->ethertype = bswap16(0x0800);

    int tcp_len = sizeof(TCP_HDR) + payload_len;
    int ip_len  = sizeof(IPV4_HDR) + tcp_len;

    ip->ver_ihl  = 0x45;
    ip->tos      = 0;
    ip->tot_len  = bswap16((uint16_t)ip_len);
    ip->id       = bswap16(++g_IpIdCounter);
    ip->frag_off = bswap16(0x4000);
    ip->ttl      = 64;
    ip->protocol = 6; /* TCP */
    ip->saddr    = bswap32(g_NetInfo.Ipv4Addr);
    ip->daddr    = bswap32(dst_ip);
    ip->check    = 0;
    ip->check    = ip_checksum(ip, sizeof(IPV4_HDR));

    tcp->source   = bswap16(src_port);
    tcp->dest     = bswap16(dst_port);
    tcp->seq      = bswap32(seq);
    tcp->ack_seq  = bswap32(ack);
    tcp->doff_res = (5 << 4); /* 20 bytes */
    tcp->flags    = flags;
    tcp->window   = bswap16(16384);
    tcp->urg_ptr  = 0;
    if (payload && payload_len > 0) {
        memcpy(dat, payload, payload_len);
    }
    tcp->check = 0;
    tcp->check = tcp_udp_checksum(g_NetInfo.Ipv4Addr, dst_ip, 6, tcp, tcp_len);

    tx_eth_frame(pkt, sizeof(ETH_HDR) + ip_len);
}

int net_tcp_http_get(const char *url, NET_HTTP_RESPONSE *resp) {
    if (!url || !resp) return -1;
    memset(resp, 0, sizeof(NET_HTTP_RESPONSE));

    net_stack_init();
    NET_ADAPTER_INFO info_before, info_after;
    net_get_adapter_info(&info_before);

    /* Parse URL: http://host[:port][/path] */
    const char *p = url;
    if (strncmp(p, "http://", 7) == 0) p += 7;
    else if (strncmp(p, "https://", 8) == 0) {
        fprintf(stderr, "TLS is unsupported by this experimental network stack\n");
        return -1;
    }

    const char *slash = strchr(p, '/');
    int host_len = slash ? (int)(slash - p) : (int)strlen(p);
    if (host_len <= 0 || host_len >= (int)sizeof(resp->host)) host_len = sizeof(resp->host) - 1;
    memcpy(resp->host, p, host_len);
    resp->host[host_len] = '\0';

    snprintf(resp->path, sizeof(resp->path), "%s", slash ? slash : "/");
    resp->remote_port = 80;

    char *colon = strchr(resp->host, ':');
    if (colon) {
        *colon = '\0';
        resp->remote_port = (uint16_t)atoi(colon + 1);
        if (resp->remote_port == 0) resp->remote_port = 80;
    }

    snprintf(resp->request_headers, sizeof(resp->request_headers),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: NT51Embedded/0.1\r\n"
        "Connection: close\r\n\r\n", resp->path, resp->host);

    /* 1. DNS Resolution over RTL8139 */
    uint32_t dst_ip = 0x0A000202UL;
    if (net_dns_resolve(resp->host, &dst_ip) < 0) return -1;
    resp->resolved_ip = dst_ip;

    /* 2. ARP Resolution for Gateway / Next Hop */
    uint8_t dst_mac[6];
    if (net_arp_resolve(dst_ip, dst_mac) < 0) return -1;

    /* 3. TCP 3-Way Handshake (SYN -> SYN-ACK -> ACK) over RTL8139 */
    uint16_t sport = ++g_EphemeralPort;
    uint32_t my_seq = 0x10203040UL + (sport * 1024);
    uint32_t srv_seq = 0;
    int connected = 0;

    send_tcp_segment(dst_mac, dst_ip, sport, resp->remote_port, my_seq, 0, TCP_SYN, NULL, 0);

    uint8_t rxbuf[1536];
    int wait_ms;
    for (wait_ms = 0; wait_ms < 450; wait_ms += 3) {
        int n = rx_eth_frame(rxbuf, sizeof(rxbuf));
        if (n >= (int)(sizeof(ETH_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR))) {
            ETH_HDR *reth = (ETH_HDR *)rxbuf;
            if (bswap16(reth->ethertype) == 0x0800) {
                IPV4_HDR *rip = (IPV4_HDR *)(rxbuf + sizeof(ETH_HDR));
                int ihl = (rip->ver_ihl & 0x0F) * 4;
                if (rip->protocol == 6 && bswap32(rip->saddr) == dst_ip) {
                    TCP_HDR *rtcp = (TCP_HDR *)(rxbuf + sizeof(ETH_HDR) + ihl);
                    if (bswap16(rtcp->dest) == sport && bswap16(rtcp->source) == resp->remote_port) {
                        if ((rtcp->flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
                            srv_seq = bswap32(rtcp->seq) + 1;
                            my_seq  = bswap32(rtcp->ack_seq);
                            send_tcp_segment(dst_mac, dst_ip, sport, resp->remote_port, my_seq, srv_seq, TCP_ACK, NULL, 0);
                            connected = 1;
                            resp->rtt_ms = (wait_ms == 0) ? 2 : wait_ms;
                            break;
                        } else if (rtcp->flags & TCP_RST) {
                            break;
                        }
                    }
                }
            }
        }
        net_sleep_ms(3);
    }

    char raw_http[HTTP_MAX_HEADERS_LEN + HTTP_MAX_BODY_LEN];
    int  raw_len = 0;
    memset(raw_http, 0, sizeof(raw_http));

    if (connected) {
        /* 4. Send HTTP/1.1 GET Request over TCP (PSH | ACK) */
        int req_len = (int)strlen(resp->request_headers);
        send_tcp_segment(dst_mac, dst_ip, sport, resp->remote_port, my_seq, srv_seq, TCP_PSH | TCP_ACK, resp->request_headers, req_len);
        my_seq += (uint32_t)req_len;

        /* 5. Receive TCP Data Segments until FIN or timeout */
        for (wait_ms = 0; wait_ms < 800; wait_ms += 3) {
            int n = rx_eth_frame(rxbuf, sizeof(rxbuf));
            if (n >= (int)(sizeof(ETH_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR))) {
                ETH_HDR *reth = (ETH_HDR *)rxbuf;
                if (bswap16(reth->ethertype) == 0x0800) {
                    IPV4_HDR *rip = (IPV4_HDR *)(rxbuf + sizeof(ETH_HDR));
                    int ihl = (rip->ver_ihl & 0x0F) * 4;
                    int ip_tot = bswap16(rip->tot_len);
                    if (rip->protocol == 6 && bswap32(rip->saddr) == dst_ip) {
                        TCP_HDR *rtcp = (TCP_HDR *)(rxbuf + sizeof(ETH_HDR) + ihl);
                        int tcph_len = ((rtcp->doff_res >> 4) & 0x0F) * 4;
                        if (bswap16(rtcp->dest) == sport && bswap16(rtcp->source) == resp->remote_port) {
                            int seg_len = ip_tot - ihl - tcph_len;
                            uint8_t *seg_data = (uint8_t *)rtcp + tcph_len;
                            if (seg_len > 0) {
                                uint32_t rseq = bswap32(rtcp->seq);
                                if (rseq == srv_seq) {
                                    int copy = seg_len;
                                    if (raw_len + copy >= (int)sizeof(raw_http) - 1) {
                                        copy = (int)sizeof(raw_http) - 1 - raw_len;
                                    }
                                    if (copy > 0) {
                                        memcpy(raw_http + raw_len, seg_data, copy);
                                        raw_len += copy;
                                        raw_http[raw_len] = '\0';
                                    }
                                    srv_seq += (uint32_t)seg_len;
                                }
                                send_tcp_segment(dst_mac, dst_ip, sport, resp->remote_port, my_seq, srv_seq, TCP_ACK, NULL, 0);
                            }
                            if (rtcp->flags & TCP_FIN) {
                                srv_seq++;
                                send_tcp_segment(dst_mac, dst_ip, sport, resp->remote_port, my_seq, srv_seq, TCP_FIN | TCP_ACK, NULL, 0);
                                break;
                            }
                        }
                    }
                }
            }
            net_sleep_ms(3);
        }
    }

    net_get_adapter_info(&info_after);
    resp->tx_frames = (int)(info_after.TxPackets - info_before.TxPackets);
    resp->rx_frames = (int)(info_after.RxPackets - info_before.RxPackets);

    if (raw_len > 0) {
        if (raw_len < 12 || strncmp(raw_http, "HTTP/1.", 7) != 0) return -1;
        resp->status_code = atoi(raw_http + 9);
        if (resp->status_code < 100 || resp->status_code > 599) return -1;
        char *hdr_end = strstr(raw_http, "\r\n\r\n");
        if (hdr_end) {
            int hlen = (int)(hdr_end - raw_http);
            if (hlen >= HTTP_MAX_HEADERS_LEN) hlen = HTTP_MAX_HEADERS_LEN - 1;
            memcpy(resp->response_headers, raw_http, hlen);
            resp->response_headers[hlen] = '\0';
            snprintf(resp->body, HTTP_MAX_BODY_LEN, "%s", hdr_end + 4);
        } else {
            snprintf(resp->body, HTTP_MAX_BODY_LEN, "%s", raw_http);
        }
        resp->bytes_received = raw_len;
        return 0;
    }

    resp->status_code = 0;
    resp->body[0] = 0;
    resp->bytes_received = 0;
    return -1;
}

/* ========================================================================= */
/* CLI Network Applets (ifconfig, ip, ping, nslookup, wget, route, netstat)  */
/* ========================================================================= */

int net_applet_main(int argc, char **argv) {
    const char *prog = (argc > 0 && argv[0]) ? argv[0] : "ifconfig";
    const char *slash = strrchr(prog, '/');
    if (slash) prog = slash + 1;

    NET_ADAPTER_INFO ni;
    net_get_adapter_info(&ni);

    if (strcmp(prog, "ifconfig") == 0 || strcmp(prog, "ip") == 0) {
        char ip_s[20], mask_s[20], gw_s[20];
        net_format_ip(ni.Ipv4Addr, ip_s, sizeof(ip_s));
        net_format_ip(ni.Ipv4Netmask, mask_s, sizeof(mask_s));
        net_format_ip(ni.Ipv4Gateway, gw_s, sizeof(gw_s));
        printf("eth0      Link encap:Ethernet  HWaddr %02X:%02X:%02X:%02X:%02X:%02X\n",
               ni.MacAddress[0], ni.MacAddress[1], ni.MacAddress[2],
               ni.MacAddress[3], ni.MacAddress[4], ni.MacAddress[5]);
        printf("          inet addr:%s  Bcast:10.0.2.255  Mask:%s\n", ip_s, mask_s);
        printf("          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n");
        printf("          RX packets:%lu bytes:%lu  TX packets:%lu bytes:%lu\n",
               ni.RxPackets, ni.RxBytes, ni.TxPackets, ni.TxBytes);
        printf("          driver:rtl8139.sys (PCI %04X:%04X) Base port:0x%04X IRQ:%u\n\n",
               ni.PciVendorId, ni.PciDeviceId, ni.IoBase, ni.IrqLine);
        printf("lo        Link encap:Local Loopback\n");
        printf("          inet addr:127.0.0.1  Mask:255.0.0.0\n");
        printf("          UP LOOPBACK RUNNING  MTU:65536  Metric:1\n");
        return 0;
    }

    if (strcmp(prog, "route") == 0) {
        printf("Kernel IP routing table (Windows XP NT 5.1 TCP/IP Stack)\n");
        printf("Destination     Gateway         Genmask         Flags Metric Ref Use Iface\n");
        printf("0.0.0.0         10.0.2.2        0.0.0.0         UG    0      0     0 eth0\n");
        printf("10.0.2.0        0.0.0.0         255.255.255.0   U     0      0     0 eth0\n");
        printf("127.0.0.0       0.0.0.0         255.0.0.0       U     0      0     0 lo\n");
        return 0;
    }

    if (strcmp(prog, "netstat") == 0) {
        fprintf(stderr, "Connection enumeration is unsupported\n");
        return 1;
    }

    if (strcmp(prog, "ping") == 0) {
        const char *target = (argc > 1) ? argv[1] : "10.0.2.2";
        if (strcmp(target, "-c") == 0 && argc > 3) target = argv[3];
        uint32_t dst_ip = 0x0A000202UL;
        if (net_dns_resolve(target, &dst_ip) < 0) { fprintf(stderr, "DNS resolution failed: %s\n", target); return 1; }
        char ip_s[24];
        net_format_ip(dst_ip, ip_s, sizeof(ip_s));
        printf("PING %s (%s): 56 data bytes via eth0 (rtl8139.sys)\n", target, ip_s);
        int i, ok = 0;
        for (i = 1; i <= 4; i++) {
            int rtt = 1, ttl = 64;
            if (net_icmp_ping(dst_ip, (uint16_t)i, &rtt, &ttl) == 0) {
                printf("64 bytes from %s: seq=%d ttl=%d time=%d ms\n", ip_s, i, ttl, rtt);
                ok++;
            } else {
                printf("Request timeout for icmp_seq %d\n", i);
            }
        }
        printf("--- %s ping statistics ---\n", target);
        printf("4 packets transmitted, %d packets received, %d%% packet loss\n", ok, (4 - ok) * 25);
        return ok ? 0 : 1;
    }

    if (strcmp(prog, "nslookup") == 0) {
        const char *host = (argc > 1) ? argv[1] : "example.com";
        uint32_t ip = 0;
        if (net_dns_resolve(host, &ip) < 0) { fprintf(stderr, "DNS resolution failed: %s\n", host); return 1; }
        char ip_s[24];
        net_format_ip(ip, ip_s, sizeof(ip_s));
        printf("Server:    10.0.2.3\n");
        printf("Address 1: 10.0.2.3#53\n\n");
        printf("Name:      %s\n", host);
        printf("Address 1: %s\n", ip_s);
        return 0;
    }

    if (strcmp(prog, "wget") == 0 || strcmp(prog, "curl") == 0) {
        const char *url = (argc > 1) ? argv[1] : "http://10.0.2.2:8080/";
        NET_HTTP_RESPONSE *resp = (NET_HTTP_RESPONSE *)malloc(sizeof(NET_HTTP_RESPONSE));
        if (!resp) return 1;
        int rc = net_tcp_http_get(url, resp);
        if (rc < 0) {
            fprintf(stderr, "HTTP request failed (TLS is unsupported): %s\n", url);
            free(resp);
            return 1;
        }
        printf("HTTP status %d (%d received bytes, TX=%d frames, RX=%d frames)\n",
               resp->status_code, resp->bytes_received, resp->tx_frames, resp->rx_frames);
        printf("%s\n", resp->body);
        int failed = resp->status_code >= 400;
        free(resp);
        return failed;
    }

    return 0;
}

/* ========================================================================= */
/* Experimental ARP and ICMP polling. */
void net_poll_once(void) {
    net_stack_init();

    uint8_t rxbuf[1536];
    int loops;
    for (loops = 0; loops < 4; loops++) {
        int n = rx_eth_frame(rxbuf, sizeof(rxbuf));
        if (n < (int)(sizeof(ETH_HDR) + sizeof(IPV4_HDR))) break;

        ETH_HDR *reth = (ETH_HDR *)rxbuf;
        if (bswap16(reth->ethertype) != 0x0800) continue;

        IPV4_HDR *rip = (IPV4_HDR *)(rxbuf + sizeof(ETH_HDR));
        int ihl = (rip->ver_ihl & 0x0F) * 4;
        int ip_tot = bswap16(rip->tot_len);
        uint32_t src_ip = bswap32(rip->saddr);
        uint32_t dst_ip = bswap32(rip->daddr);

        /* 1. Respond to incoming ICMP Echo Request (ping to 10.0.2.15) */
        if (rip->protocol == 1 && dst_ip == g_NetInfo.Ipv4Addr &&
            n >= (int)(sizeof(ETH_HDR) + ihl + sizeof(ICMP_HDR))) {
            ICMP_HDR *ricmp = (ICMP_HDR *)(rxbuf + sizeof(ETH_HDR) + ihl);
            if (ricmp->type == 8) {
                uint8_t txpkt[1536];
                if (n <= (int)sizeof(txpkt)) {
                    memcpy(txpkt, rxbuf, n);
                    ETH_HDR  *teth  = (ETH_HDR *)txpkt;
                    IPV4_HDR *tip   = (IPV4_HDR *)(txpkt + sizeof(ETH_HDR));
                    ICMP_HDR *ticmp = (ICMP_HDR *)(txpkt + sizeof(ETH_HDR) + ihl);
                    memcpy(teth->dst, reth->src, 6);
                    memcpy(teth->src, g_NetInfo.MacAddress, 6);
                    tip->saddr = bswap32(g_NetInfo.Ipv4Addr);
                    tip->daddr = bswap32(src_ip);
                    tip->check = 0;
                    tip->check = ip_checksum(tip, ihl);
                    ticmp->type = 0; /* Echo Reply */
                    ticmp->checksum = 0;
                    ticmp->checksum = ip_checksum(ticmp, ip_tot - ihl);
                    tx_eth_frame(txpkt, n);
                }
            }
            continue;
        }

    }
}
