/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * chromium_rootfs/shim/netd.c  (#included by nt_linux_shim.c)
 *
 * netd: a small user-mode IPv4 stack that gives AF_INET sockets real network
 * connectivity through the RTL8139 driver (rtl8139.sys, \Device\Net0).
 *
 *   Linux process (e.g. Chromium)            netd process              QEMU NIC
 *   connect()/send()/recv() --shim-->  SHIM_IPC_CONN rings  --TCP-->  RTL8139
 *   sendto()/recvfrom()     --shim-->  SHIM_NET_UDP rings   --UDP-->  (slirp)
 *
 * The shim turns connect() to a non-loopback IPv4 address into an IPC
 * connection whose listener_idx is NETD_LISTENER. netd claims it, performs
 * the TCP handshake with the remote host, and then shuttles bytes between the
 * connection's rings and TCP segments. UDP sockets get a SHIM_NET_UDP slot
 * whose rings carry framed datagrams. Nothing is answered locally: every
 * byte a client reads came from a packet received on the NIC.
 *
 * Deliberately simple TCP: no window scaling/SACK/timestamps, go-back-N
 * retransmission, in-order receive only (out-of-order segments are dropped
 * and re-ACKed), immediate ACKs. That is sufficient for QEMU user-mode
 * networking, which terminates TCP on the host.
 */

#define NETD_MAX_TCB     64
#define NETD_SNDBUF      32768
#define NETD_MSS         1460
#define NETD_RTO_INIT_MS 500
#define NETD_RTO_MAX_MS  8000

#define NETD_IOCTL_GET_INFO    0x80202004UL
#define NETD_IOCTL_SEND_PACKET 0x80202008UL
#define NETD_IOCTL_RECV_PACKET 0x8020200CUL

#define NETD_TCP_FIN 0x01
#define NETD_TCP_SYN 0x02
#define NETD_TCP_RST 0x04
#define NETD_TCP_PSH 0x08
#define NETD_TCP_ACK 0x10

typedef struct __attribute__((packed)) {
    unsigned char  mac[6];
    unsigned short io_base;
    unsigned char  irq;
    unsigned char  link_up;
    unsigned short vendor, device;
    unsigned long  ip, mask, gw, dns;
    unsigned long  tx_packets, rx_packets, tx_bytes, rx_bytes;
} NETD_ADAPTER_INFO;

enum { TCB_FREE = 0, TCB_SYN_SENT, TCB_EST };

typedef struct {
    int state;
    int cidx;
    unsigned int rip;
    unsigned short rport, lport;
    unsigned int iss, snd_una, snd_nxt, rcv_nxt;
    unsigned int peer_wnd, mss;
    unsigned int sndlen;            /* bytes in sndbuf, starting at seq snd_una */
    int fin_queued, fin_sent, fin_acked, peer_fin;
    unsigned int fin_seq;
    s64 rto_at;
    int rto_ms, retries;
    s64 linger_at;
    unsigned int last_adv;
    unsigned int bytes_in, bytes_out, snd_max;
    unsigned char sndbuf[NETD_SNDBUF];
} NETD_TCB;

typedef struct { unsigned int ip; unsigned char mac[6]; int valid; } NETD_ARP;

static HANDLE g_nd_dev = NULL;
static unsigned char g_nd_mac[6];
static unsigned int g_nd_ip, g_nd_mask, g_nd_gw, g_nd_dns;
static unsigned short g_nd_ipid = 1;
static NETD_TCB g_tcb[NETD_MAX_TCB];
static NETD_ARP g_nd_arp[8];
static unsigned char g_nd_frame[1600];
static unsigned long g_nd_stat_rx, g_nd_stat_tx, g_nd_stat_conns;

static void nd_put16(unsigned char *p, unsigned int v) { p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v; }
static void nd_put32(unsigned char *p, unsigned int v) { nd_put16(p, v >> 16); nd_put16(p + 2, v); }
static unsigned int nd_get16(const unsigned char *p) { return ((unsigned int)p[0] << 8) | p[1]; }
static unsigned int nd_get32(const unsigned char *p) { return (nd_get16(p) << 16) | nd_get16(p + 2); }
static int nd_seq_lt(unsigned int a, unsigned int b) { return (int)(a - b) < 0; }
static int nd_seq_le(unsigned int a, unsigned int b) { return (int)(a - b) <= 0; }

static unsigned int nd_sum(const unsigned char *p, int len, unsigned int sum) {
    while (len > 1) { sum += ((unsigned int)p[0] << 8) | p[1]; p += 2; len -= 2; }
    if (len > 0) sum += (unsigned int)p[0] << 8;
    return sum;
}
static unsigned int nd_fold(unsigned int sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (~sum) & 0xFFFF;
}

static void nd_print_ip(const char *pfx, unsigned int ip, unsigned int port) {
    char b[48];
    int n = 0;
    for (int i = 3; i >= 0; i--) {
        unsigned int o = (ip >> (i * 8)) & 0xFF;
        if (o >= 100) b[n++] = (char)('0' + o / 100);
        if (o >= 10) b[n++] = (char)('0' + (o / 10) % 10);
        b[n++] = (char)('0' + o % 10);
        if (i) b[n++] = '.';
    }
    if (port) {
        char d[6]; int nd = 0;
        b[n++] = ':';
        while (port) { d[nd++] = (char)('0' + port % 10); port /= 10; }
        while (nd) b[n++] = d[--nd];
    }
    b[n++] = '\n'; b[n] = 0;
    shim_debug_print(pfx);
    shim_debug_print(b);
}

static int nd_tx(const unsigned char *frame, unsigned int len) {
    IO_STATUS_BLOCK iosb;
    NTSTATUS st = Nt_DeviceIoControlFile(g_nd_dev, NULL, NULL, NULL, &iosb, NETD_IOCTL_SEND_PACKET,
                                         (void *)frame, len, NULL, 0);
    if (NT_SUCCESS(st)) g_nd_stat_tx++;
    return NT_SUCCESS(st) ? 0 : -1;
}

static int nd_rx(unsigned char *buf, unsigned int max) {
    IO_STATUS_BLOCK iosb;
    iosb.Information = 0;
    NTSTATUS st = Nt_DeviceIoControlFile(g_nd_dev, NULL, NULL, NULL, &iosb, NETD_IOCTL_RECV_PACKET,
                                         NULL, 0, buf, max);
    if (!NT_SUCCESS(st)) return 0;
    return (int)iosb.Information;
}

/* ---- ARP ---------------------------------------------------------------- */

static void nd_arp_send(unsigned int oper, const unsigned char *dmac, unsigned int tip, const unsigned char *tmac) {
    unsigned char f[60];
    for (int i = 0; i < 60; i++) f[i] = 0;
    for (int i = 0; i < 6; i++) { f[i] = dmac ? dmac[i] : 0xFF; f[6 + i] = g_nd_mac[i]; }
    nd_put16(f + 12, 0x0806);
    unsigned char *a = f + 14;
    nd_put16(a, 1); nd_put16(a + 2, 0x0800); a[4] = 6; a[5] = 4; nd_put16(a + 6, oper);
    for (int i = 0; i < 6; i++) a[8 + i] = g_nd_mac[i];
    nd_put32(a + 14, g_nd_ip);
    for (int i = 0; i < 6; i++) a[18 + i] = tmac ? tmac[i] : 0;
    nd_put32(a + 24, tip);
    nd_tx(f, 42);
}

static void nd_arp_learn(unsigned int ip, const unsigned char *mac) {
    int slot = -1;
    for (int i = 0; i < 8; i++) {
        if (g_nd_arp[i].valid && g_nd_arp[i].ip == ip) { slot = i; break; }
        if (!g_nd_arp[i].valid && slot < 0) slot = i;
    }
    if (slot < 0) slot = (int)(ip & 7);
    g_nd_arp[slot].ip = ip;
    for (int i = 0; i < 6; i++) g_nd_arp[slot].mac[i] = mac[i];
    g_nd_arp[slot].valid = 1;
}

static const unsigned char *nd_nexthop_mac(unsigned int dst) {
    unsigned int hop = ((dst & g_nd_mask) == (g_nd_ip & g_nd_mask)) ? dst : g_nd_gw;
    for (int i = 0; i < 8; i++)
        if (g_nd_arp[i].valid && g_nd_arp[i].ip == hop) return g_nd_arp[i].mac;
    static s64 last_req;
    s64 now = shim_now_ms();
    if (now - last_req > 200) { nd_arp_send(1, NULL, hop, NULL); last_req = now; }
    return NULL;
}

static void nd_handle_arp(const unsigned char *a, int len) {
    if (len < 28 || nd_get16(a) != 1 || nd_get16(a + 2) != 0x0800) return;
    unsigned int oper = nd_get16(a + 6);
    unsigned int sip = nd_get32(a + 14), tip = nd_get32(a + 24);
    if (sip) nd_arp_learn(sip, a + 8);
    if (oper == 1 && tip == g_nd_ip) nd_arp_send(2, a + 8, sip, a + 8);
}

/* ---- IPv4 output -------------------------------------------------------- */

/* Builds Ethernet + IPv4 headers in g_nd_frame around an L4 payload that the
 * caller has already written at g_nd_frame + 34, then transmits. */
static int nd_ip_output(unsigned int dst, unsigned char proto, unsigned int l4len) {
    const unsigned char *dmac = nd_nexthop_mac(dst);
    if (!dmac || 34 + l4len > 1514) return -1;
    unsigned char *f = g_nd_frame;
    for (int i = 0; i < 6; i++) { f[i] = dmac[i]; f[6 + i] = g_nd_mac[i]; }
    nd_put16(f + 12, 0x0800);
    unsigned char *ip = f + 14;
    ip[0] = 0x45; ip[1] = 0;
    nd_put16(ip + 2, 20 + l4len);
    nd_put16(ip + 4, g_nd_ipid++);
    nd_put16(ip + 6, 0x4000);
    ip[8] = 64; ip[9] = proto;
    nd_put16(ip + 10, 0);
    nd_put32(ip + 12, g_nd_ip);
    nd_put32(ip + 16, dst);
    nd_put16(ip + 10, nd_fold(nd_sum(ip, 20, 0)));
    return nd_tx(f, 34 + l4len);
}

static unsigned int nd_pseudo(unsigned int src, unsigned int dst, unsigned int proto, unsigned int len) {
    return (src >> 16) + (src & 0xFFFF) + (dst >> 16) + (dst & 0xFFFF) + proto + len;
}

/* ---- UDP ---------------------------------------------------------------- */

static void nd_udp_output(unsigned int lport, unsigned int dst, unsigned int dport,
                          const unsigned char *data, unsigned int dlen) {
    if (dlen > 1472) return;
    unsigned char *u = g_nd_frame + 34;
    nd_put16(u, lport); nd_put16(u + 2, dport); nd_put16(u + 4, 8 + dlen); nd_put16(u + 6, 0);
    for (unsigned int i = 0; i < dlen; i++) u[8 + i] = data[i];
    unsigned int c = nd_fold(nd_sum(u, 8 + dlen, nd_pseudo(g_nd_ip, dst, 17, 8 + dlen)));
    nd_put16(u + 6, c ? c : 0xFFFF);
    nd_ip_output(dst, 17, 8 + dlen);
}

static void nd_handle_udp(unsigned int src, const unsigned char *u, int len) {
    if (len < 8) return;
    unsigned int sport = nd_get16(u), dport = nd_get16(u + 2), ulen = nd_get16(u + 4);
    if (ulen < 8 || (int)ulen > len) return;
    for (int i = 0; i < MAX_NET_UDP; i++) {
        SHIM_NET_UDP *s = &g_ipc->net_udp[i];
        if (!s->in_use || s->lport != dport) continue;
        unsigned char hdr[8];
        unsigned int dl = ulen - 8;
        unsigned short p16 = (unsigned short)sport, l16 = (unsigned short)dl;
        *(unsigned int *)hdr = src;
        *(unsigned short *)(hdr + 4) = p16;
        *(unsigned short *)(hdr + 6) = l16;
        ring_write_record(&s->rx, hdr, 8, u + 8, dl);
        return;
    }
}

static int nd_service_udp(void) {
    int work = 0;
    static unsigned char dg[1600];
    for (int i = 0; i < MAX_NET_UDP; i++) {
        SHIM_NET_UDP *s = &g_ipc->net_udp[i];
        if (!s->in_use) continue;
        for (;;) {
            unsigned char hdr[8];
            ipc_lock(&s->tx.lock);
            if (s->tx.count < 8) { ipc_unlock(&s->tx.lock); break; }
            ring_read_locked(&s->tx, hdr, 8, 0);
            unsigned int dl = *(unsigned short *)(hdr + 6);
            if (s->tx.count < 8 + dl) { ipc_unlock(&s->tx.lock); break; }
            ring_read_locked(&s->tx, hdr, 8, 1);
            unsigned int take = dl < sizeof(dg) ? dl : sizeof(dg);
            ring_read_locked(&s->tx, dg, take, 1);
            if (dl > take) { unsigned char junk[64]; unsigned int left = dl - take;
                while (left) { unsigned int k = left < 64 ? left : 64; ring_read_locked(&s->tx, junk, k, 1); left -= k; } }
            ipc_unlock(&s->tx.lock);
            nd_udp_output(s->lport, *(unsigned int *)hdr, *(unsigned short *)(hdr + 4), dg, take);
            work++;
        }
    }
    return work;
}

/* ---- TCP ---------------------------------------------------------------- */

static unsigned int nd_rcv_window(NETD_TCB *t, int nactive) {
    SHIM_IPC_CONN *c = &g_ipc->conns[t->cidx];
    unsigned int freeb = IPC_RING_SIZE - c->s2c.count;
    /* The NIC ring is 32 KiB and shared by all connections: keep the sum of
     * advertised windows below it so bursts are not dropped in hardware. */
    unsigned int cap = 28000 / (unsigned int)(nactive > 0 ? nactive : 1);
    if (cap < 4 * NETD_MSS) cap = 4 * NETD_MSS;
    if (c->client_closed || c->client_refs <= 0) return cap; /* data is discarded */
    if (freeb > cap) freeb = cap;
    return freeb;
}

static int g_nd_nactive = 1;

static void nd_tcp_output(NETD_TCB *t, unsigned int flags, unsigned int seq,
                          const unsigned char *data, unsigned int dlen) {
    unsigned char *h = g_nd_frame + 34;
    unsigned int hl = (flags & NETD_TCP_SYN) ? 24 : 20;
    nd_put16(h, t->lport); nd_put16(h + 2, t->rport);
    nd_put32(h + 4, seq);
    nd_put32(h + 8, (flags & NETD_TCP_ACK) ? t->rcv_nxt : 0);
    h[12] = (unsigned char)((hl / 4) << 4);
    h[13] = (unsigned char)flags;
    unsigned int wnd = (t->state == TCB_FREE) ? 0 : nd_rcv_window(t, g_nd_nactive);
    if (wnd > 65535) wnd = 65535;
    t->last_adv = wnd;
    nd_put16(h + 14, wnd);
    nd_put16(h + 16, 0); nd_put16(h + 18, 0);
    if (hl == 24) { h[20] = 2; h[21] = 4; nd_put16(h + 22, NETD_MSS); }
    for (unsigned int i = 0; i < dlen; i++) h[hl + i] = data[i];
    nd_put16(h + 16, nd_fold(nd_sum(h, hl + dlen, nd_pseudo(g_nd_ip, t->rip, 6, hl + dlen))));
    nd_ip_output(t->rip, 6, hl + dlen);
}

static void nd_tcp_rst(unsigned int dst, unsigned int sport, unsigned int dport,
                       unsigned int seq, unsigned int ack, int with_ack) {
    NETD_TCB tmp;
    tmp.state = TCB_FREE; tmp.rip = dst; tmp.lport = (unsigned short)sport; tmp.rport = (unsigned short)dport;
    tmp.rcv_nxt = ack;
    nd_tcp_output(&tmp, NETD_TCP_RST | (with_ack ? NETD_TCP_ACK : 0), seq, NULL, 0);
}

/* Detach a TCB from its IPC connection. err == 0 means a normal close. */
static void nd_tcb_release(NETD_TCB *t, int err) {
    SHIM_IPC_CONN *c = &g_ipc->conns[t->cidx];
    nd_print_ip("[netd] tcp closed ", t->rip, t->rport);
    shim_debug_hex("[netd]   bytes_out=", t->bytes_out);
    shim_debug_hex("[netd]   bytes_in=", t->bytes_in);
    if (err) shim_debug_hex("[netd]   errno=", (unsigned long)err);
    if (err) c->net_err = err;
    c->net_eof = 1;
    __sync_synchronize();
    c->server_closed = 1;
    __sync_synchronize();
    if (c->client_closed || c->client_refs <= 0) {
        c->listener_idx = -1;
        c->state = CONN_FREE;
    }
    t->state = TCB_FREE;
}

static int nd_claim_new_conns(void) {
    int work = 0;
    for (int i = 0; i < MAX_IPC_CONNS; i++) {
        SHIM_IPC_CONN *c = &g_ipc->conns[i];
        if (c->listener_idx != NETD_LISTENER || c->state != CONN_SYN || c->server_closed) continue;
        int owned = 0, freeslot = -1;
        for (int k = 0; k < NETD_MAX_TCB; k++) {
            if (g_tcb[k].state != TCB_FREE && g_tcb[k].cidx == i) { owned = 1; break; }
            if (g_tcb[k].state == TCB_FREE && freeslot < 0) freeslot = k;
        }
        if (owned) continue;
        if (freeslot < 0) break;
        NETD_TCB *t = &g_tcb[freeslot];
        t->state = TCB_SYN_SENT;
        t->cidx = i;
        t->rip = c->net_rip; t->rport = (unsigned short)c->net_rport; t->lport = (unsigned short)c->net_lport;
        t->iss = (unsigned int)shim_now_ms() * 2654435761U ^ ((unsigned int)i << 16);
        t->snd_una = t->iss; t->snd_nxt = t->iss + 1; t->rcv_nxt = 0;
        t->peer_wnd = 0; t->mss = 536; t->sndlen = 0;
        t->fin_queued = t->fin_sent = t->fin_acked = t->peer_fin = 0;
        t->rto_ms = 1000; t->retries = 0; t->linger_at = 0;
        t->bytes_in = t->bytes_out = 0;
        t->rto_at = shim_now_ms() + t->rto_ms;
        nd_tcp_output(t, NETD_TCP_SYN, t->iss, NULL, 0);
        g_nd_stat_conns++;
        nd_print_ip("[netd] tcp connect ", t->rip, t->rport);
        work++;
    }
    return work;
}

static void nd_handle_tcp(unsigned int src, const unsigned char *h, int len) {
    if (len < 20) return;
    unsigned int sport = nd_get16(h), dport = nd_get16(h + 2);
    unsigned int seq = nd_get32(h + 4), ack = nd_get32(h + 8);
    unsigned int hl = (h[12] >> 4) * 4, flags = h[13], wnd = nd_get16(h + 14);
    if (hl < 20 || (int)hl > len) return;
    const unsigned char *data = h + hl;
    unsigned int dlen = (unsigned int)len - hl;

    NETD_TCB *t = NULL;
    for (int k = 0; k < NETD_MAX_TCB; k++) {
        NETD_TCB *x = &g_tcb[k];
        if (x->state != TCB_FREE && x->rip == src && x->rport == sport && x->lport == dport) { t = x; break; }
    }
    if (!t) {
        if (!(flags & NETD_TCP_RST)) {
            if (flags & NETD_TCP_ACK) nd_tcp_rst(src, dport, sport, ack, 0, 0);
            else nd_tcp_rst(src, dport, sport, 0, seq + dlen + ((flags & NETD_TCP_SYN) ? 1 : 0), 1);
        }
        return;
    }
    SHIM_IPC_CONN *c = &g_ipc->conns[t->cidx];

    if (flags & NETD_TCP_RST) {
        nd_print_ip(t->state == TCB_SYN_SENT ? "[netd] tcp refused " : "[netd] tcp reset ", t->rip, t->rport);
        nd_tcb_release(t, t->state == TCB_SYN_SENT ? 111 /* ECONNREFUSED */ : 104 /* ECONNRESET */);
        return;
    }

    if (t->state == TCB_SYN_SENT) {
        if ((flags & (NETD_TCP_SYN | NETD_TCP_ACK)) == (NETD_TCP_SYN | NETD_TCP_ACK) && ack == t->iss + 1) {
            t->rcv_nxt = seq + 1;
            t->snd_una = t->snd_nxt = t->snd_max = ack;
            t->peer_wnd = wnd;
            t->mss = 536;
            for (unsigned int o = 20; o + 1 < hl;) {
                unsigned int kind = h[o];
                if (kind == 0) break;
                if (kind == 1) { o++; continue; }
                unsigned int ol = h[o + 1];
                if (ol < 2) break;
                if (kind == 2 && ol == 4) t->mss = nd_get16(h + o + 2);
                o += ol;
            }
            if (t->mss > NETD_MSS) t->mss = NETD_MSS;
            t->state = TCB_EST;
            t->rto_ms = NETD_RTO_INIT_MS; t->rto_at = 0; t->retries = 0;
            __sync_synchronize();
            c->state = CONN_ESTABLISHED;
            nd_print_ip("[netd] tcp established ", t->rip, t->rport);
            nd_tcp_output(t, NETD_TCP_ACK, t->snd_nxt, NULL, 0);
        }
        return;
    }

    /* ESTABLISHED (possibly half-closed in either direction) */
    if (flags & NETD_TCP_ACK) {
        unsigned int max_ack = t->snd_una + t->sndlen + (t->fin_sent ? 1 : 0);
        if (nd_seq_lt(t->snd_una, ack) && nd_seq_le(ack, max_ack)) {
            unsigned int acked = ack - t->snd_una;
            unsigned int dacked = acked > t->sndlen ? t->sndlen : acked;
            if (t->fin_sent && ack == t->fin_seq + 1) t->fin_acked = 1;
            if (dacked) {
                unsigned int rest = t->sndlen - dacked;
                for (unsigned int i = 0; i < rest; i++) t->sndbuf[i] = t->sndbuf[dacked + i];
                t->sndlen = rest;
            }
            t->snd_una = ack;
            if (nd_seq_lt(t->snd_nxt, t->snd_una)) t->snd_nxt = t->snd_una;
            t->retries = 0;
            t->rto_ms = NETD_RTO_INIT_MS;
            t->rto_at = (t->snd_nxt != t->snd_una) ? shim_now_ms() + t->rto_ms : 0;
        }
        if (nd_seq_le(t->snd_una, ack)) t->peer_wnd = wnd;
    }

    int fin = (flags & NETD_TCP_FIN) != 0;
    if (dlen > 0 || fin) {
        if (nd_seq_lt(seq, t->rcv_nxt)) {
            unsigned int skip = t->rcv_nxt - seq;
            if (skip >= dlen + (unsigned int)fin) { nd_tcp_output(t, NETD_TCP_ACK, t->snd_nxt, NULL, 0); return; }
            if (skip > dlen) { dlen = 0; } else { data += skip; dlen -= skip; }
            seq = t->rcv_nxt;
        }
        if (seq == t->rcv_nxt && !t->peer_fin) {
            unsigned int took = dlen;
            if (dlen && !(c->client_closed || c->client_refs <= 0)) took = ring_write(&c->s2c, data, dlen);
            if (took && !t->bytes_in) nd_print_ip("[netd] tcp received data ", t->rip, t->rport);
            t->rcv_nxt += took;
            t->bytes_in += took;
            if (fin && took == dlen) {
                t->rcv_nxt++;
                t->peer_fin = 1;
                __sync_synchronize();
                c->net_eof = 1;
            }
        }
        nd_tcp_output(t, NETD_TCP_ACK, t->snd_nxt, NULL, 0);
    }
}

static void nd_handle_ip(const unsigned char *ip, int len) {
    if (len < 20 || (ip[0] >> 4) != 4) return;
    unsigned int ihl = (ip[0] & 0x0F) * 4, tot = nd_get16(ip + 2);
    if (ihl < 20 || tot < ihl || (int)tot > len) return;
    if (nd_get16(ip + 6) & 0x3FFF) return; /* fragments are not reassembled */
    if (nd_get32(ip + 16) != g_nd_ip) return;
    unsigned int src = nd_get32(ip + 12);
    if (ip[9] == 6) nd_handle_tcp(src, ip + ihl, (int)(tot - ihl));
    else if (ip[9] == 17) nd_handle_udp(src, ip + ihl, (int)(tot - ihl));
}

static int nd_service_tcbs(void) {
    int work = 0, nactive = 0;
    s64 now = shim_now_ms();
    for (int k = 0; k < NETD_MAX_TCB; k++) if (g_tcb[k].state == TCB_EST) nactive++;
    g_nd_nactive = nactive;

    for (int k = 0; k < NETD_MAX_TCB; k++) {
        NETD_TCB *t = &g_tcb[k];
        if (t->state == TCB_FREE) continue;
        SHIM_IPC_CONN *c = &g_ipc->conns[t->cidx];
        int client_gone = c->client_closed || c->client_refs <= 0;

        if (t->state == TCB_SYN_SENT) {
            if (client_gone) { nd_tcb_release(t, 0); work++; continue; }
            if (now >= t->rto_at) {
                if (++t->retries > 5) {
                    nd_print_ip("[netd] tcp connect timed out ", t->rip, t->rport);
                    nd_tcb_release(t, 110 /* ETIMEDOUT */);
                    continue;
                }
                t->rto_ms *= 2;
                t->rto_at = now + t->rto_ms;
                nd_tcp_output(t, NETD_TCP_SYN, t->iss, NULL, 0);
                work++;
            }
            continue;
        }

        /* Pull application data into the send buffer. */
        if (!t->fin_queued) {
            unsigned int space = NETD_SNDBUF - t->sndlen;
            if (space && c->c2s.count) {
                unsigned int n = ring_read(&c->c2s, t->sndbuf + t->sndlen, space);
                t->sndlen += n;
                if (n) work++;
            }
            if (client_gone && c->c2s.count == 0) t->fin_queued = 1;
        }

        /* Retransmission timeout: go back to snd_una. */
        int outstanding = t->snd_nxt != t->snd_una;
        int zero_wnd_probe = (t->peer_wnd == 0 && t->sndlen > 0);
        if ((outstanding || zero_wnd_probe) && t->rto_at && now >= t->rto_at) {
            if (++t->retries > 12) {
                nd_print_ip("[netd] tcp retransmit limit ", t->rip, t->rport);
                nd_tcp_output(t, NETD_TCP_RST | NETD_TCP_ACK, t->snd_nxt, NULL, 0);
                nd_tcb_release(t, 110 /* ETIMEDOUT */);
                continue;
            }
            t->snd_nxt = t->snd_una;
            if (t->fin_sent && !t->fin_acked) t->fin_sent = 0;
            if (zero_wnd_probe) {
                nd_tcp_output(t, NETD_TCP_ACK, t->snd_una, t->sndbuf, 1);
            }
            t->rto_ms = t->rto_ms * 2 > NETD_RTO_MAX_MS ? NETD_RTO_MAX_MS : t->rto_ms * 2;
            t->rto_at = now + t->rto_ms;
            work++;
        } else if (zero_wnd_probe && !t->rto_at) {
            t->rto_at = now + t->rto_ms;
        }

        /* Transmit new data within the peer's window. */
        unsigned int wnd = t->peer_wnd < NETD_SNDBUF ? t->peer_wnd : NETD_SNDBUF;
        for (;;) {
            unsigned int off = t->snd_nxt - t->snd_una;
            if (off >= t->sndlen || off >= wnd) break;
            unsigned int n = t->sndlen - off;
            if (n > t->mss) n = t->mss;
            if (n > wnd - off) n = wnd - off;
            nd_tcp_output(t, NETD_TCP_ACK | NETD_TCP_PSH, t->snd_nxt, t->sndbuf + off, n);
            if (nd_seq_lt(t->snd_max, t->snd_nxt + n)) { t->bytes_out += t->snd_nxt + n - t->snd_max; t->snd_max = t->snd_nxt + n; }
            t->snd_nxt += n;
            if (!t->rto_at) t->rto_at = now + t->rto_ms;
            work++;
        }
        if (t->fin_queued && !t->fin_sent && (t->snd_nxt - t->snd_una) == t->sndlen) {
            t->fin_seq = t->snd_nxt;
            nd_tcp_output(t, NETD_TCP_FIN | NETD_TCP_ACK, t->snd_nxt, NULL, 0);
            t->snd_nxt++;
            t->fin_sent = 1;
            if (!t->rto_at) t->rto_at = now + t->rto_ms;
            work++;
        }

        /* Window update once the reader has drained the receive ring. */
        if (!t->peer_fin && t->last_adv < 2 * NETD_MSS && nd_rcv_window(t, nactive) >= 4 * NETD_MSS) {
            nd_tcp_output(t, NETD_TCP_ACK, t->snd_nxt, NULL, 0);
            work++;
        }

        /* Teardown. */
        if (t->fin_acked && t->peer_fin) { nd_tcb_release(t, 0); work++; continue; }
        if (t->fin_acked && !t->peer_fin) {
            if (!t->linger_at) t->linger_at = now + 10000;
            else if (now >= t->linger_at) {
                nd_tcp_output(t, NETD_TCP_RST | NETD_TCP_ACK, t->snd_nxt, NULL, 0);
                nd_tcb_release(t, 0);
                continue;
            }
        }
    }
    return work;
}

static HANDLE nd_open_device(void) {
    static const char *names[] = { "\\Device\\Net0", "\\DosDevices\\net0" };
    for (int n = 0; n < 2; n++) {
        unsigned short w[32];
        int i = 0;
        for (; names[n][i]; i++) w[i] = (unsigned short)(unsigned char)names[n][i];
        w[i] = 0;
        UNICODE_STRING us = { (unsigned short)(i * 2), (unsigned short)(i * 2 + 2), w };
        OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &us, OBJ_CASE_INSENSITIVE, NULL, NULL };
        IO_STATUS_BLOCK iosb;
        HANDLE h = NULL;
        NTSTATUS st = Nt_CreateFile(&h, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
                                    NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                                    FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (NT_SUCCESS(st) && h) return h;
    }
    return NULL;
}

int netd_main(int argc, char **argv) {
    (void)argc; (void)argv;
    if (!g_shim_initialized) InitShim();
    if (!g_ipc) { shim_debug_print("[netd] no IPC section\n"); return 1; }

    for (int tries = 0; !g_nd_dev && tries < 50; tries++) {
        g_nd_dev = nd_open_device();
        if (!g_nd_dev) { LARGE_INTEGER d = { .QuadPart = -1000000LL }; Nt_DelayExecution(0, &d); }
    }
    if (!g_nd_dev) { shim_debug_print("[netd] cannot open \\Device\\Net0 (rtl8139.sys loaded?)\n"); return 1; }

    NETD_ADAPTER_INFO info;
    IO_STATUS_BLOCK iosb;
    for (unsigned int k = 0; k < sizeof(info); k++) ((unsigned char *)&info)[k] = 0;
    NTSTATUS info_status = Nt_DeviceIoControlFile(g_nd_dev, NULL, NULL, NULL, &iosb, NETD_IOCTL_GET_INFO, NULL, 0, &info, sizeof(info));
    if (!NT_SUCCESS(info_status) || iosb.Information < sizeof(info) || !info.link_up) {
        shim_debug_print("[netd] adapter query failed or hardware unavailable\n");
        return 1;
    }
    for (int i = 0; i < 6; i++) g_nd_mac[i] = info.mac[i];
    g_nd_ip = (unsigned int)info.ip; g_nd_mask = (unsigned int)info.mask;
    g_nd_gw = (unsigned int)info.gw;  g_nd_dns = (unsigned int)info.dns;
    if (!g_nd_ip || !g_nd_mask || !g_nd_gw) { shim_debug_print("[netd] adapter has no IPv4 configuration\n"); return 1; }
    nd_print_ip("[netd] ip ", g_nd_ip, 0);
    nd_print_ip("[netd] gateway ", g_nd_gw, 0);
    nd_print_ip("[netd] dns ", g_nd_dns, 0);

    /* Resolve the gateway (and the DNS server) before accepting sockets. */
    static unsigned char rxbuf[1600];
    s64 start = shim_now_ms(), last = 0;
    for (;;) {
        int have_gw = 0, have_dns = 0;
        for (int i = 0; i < 8; i++) {
            if (g_nd_arp[i].valid && g_nd_arp[i].ip == g_nd_gw) have_gw = 1;
            if (g_nd_arp[i].valid && g_nd_arp[i].ip == g_nd_dns) have_dns = 1;
        }
        if (have_gw && (have_dns || !g_nd_dns || (g_nd_dns & g_nd_mask) != (g_nd_ip & g_nd_mask))) break;
        s64 now = shim_now_ms();
        if (now - last > 300) {
            if (!have_gw) nd_arp_send(1, NULL, g_nd_gw, NULL);
            if (!have_dns && g_nd_dns) nd_arp_send(1, NULL, g_nd_dns, NULL);
            last = now;
        }
        if (now - start > 30000) { shim_debug_print("[netd] ARP for gateway timed out\n"); return 1; }
        int n = nd_rx(rxbuf, sizeof(rxbuf));
        if (n >= 14 && nd_get16(rxbuf + 12) == 0x0806) nd_handle_arp(rxbuf + 14, n - 14);
        if (n <= 0) { LARGE_INTEGER d = { .QuadPart = -100000LL }; Nt_DelayExecution(0, &d); }
    }
    for (int i = 0; i < 8; i++) {
        if (g_nd_arp[i].valid && g_nd_arp[i].ip == g_nd_gw) {
            char b[40]; int p = 0; const char *hx = "0123456789abcdef";
            for (int j = 0; j < 6; j++) { b[p++] = hx[g_nd_arp[i].mac[j] >> 4]; b[p++] = hx[g_nd_arp[i].mac[j] & 15]; if (j < 5) b[p++] = ':'; }
            b[p++] = '\n'; b[p] = 0;
            shim_debug_print("[netd] gateway MAC "); shim_debug_print(b);
        }
    }

    g_ipc->net_ip = g_nd_ip; g_ipc->net_mask = g_nd_mask;
    g_ipc->net_gw = g_nd_gw; g_ipc->net_dns = g_nd_dns;
    __sync_synchronize();
    g_ipc->netd_ready = 1;
    shim_debug_print("[netd] ready\n");

    int idle = 0;
    s64 last_stat = shim_now_ms();
    for (;;) {
        int work = 0;
        for (int k = 0; k < 64; k++) {
            int n = nd_rx(rxbuf, sizeof(rxbuf));
            if (n < 14) break;
            g_nd_stat_rx++;
            unsigned int et = nd_get16(rxbuf + 12);
            if (et == 0x0806) nd_handle_arp(rxbuf + 14, n - 14);
            else if (et == 0x0800) nd_handle_ip(rxbuf + 14, n - 14);
            work++;
        }
        work += nd_claim_new_conns();
        work += nd_service_tcbs();
        work += nd_service_udp();

        s64 now = shim_now_ms();
        if (now - last_stat > 15000) {
            shim_debug_hex("[netd] stats rx_frames=", g_nd_stat_rx);
            shim_debug_hex("[netd] stats tx_frames=", g_nd_stat_tx);
            shim_debug_hex("[netd] stats tcp_connects=", g_nd_stat_conns);
            {
                /* SystemPerformanceInformation: AvailablePages, CommittedPages, CommitLimit */
                unsigned long perf[128], rl = 0;
                unsigned long a[4] = { 2, (unsigned long)perf, sizeof(perf), (unsigned long)&rl };
                if (NT_SUCCESS(DoNtSyscall(173, a, 4)) && rl >= 60) {
                    shim_debug_hex("[mem] avail_kb=", perf[11] * 4);
                    shim_debug_hex("[mem] committed_kb=", perf[12] * 4);
                    shim_debug_hex("[mem] commit_limit_kb=", perf[13] * 4);
                }
            }
            last_stat = now;
        }

        LARGE_INTEGER d;
        if (work) { idle = 0; d.QuadPart = 0; }
        else { idle++; d.QuadPart = idle < 8 ? 0 : -10000LL; }
        Nt_DelayExecution(0, &d);
    }
    return 0;
}
