# SPDX-License-Identifier: GPL-2.0-only
"""Exercise adapter failure paths with an explicit mock NT syscall boundary."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "net_stack.c"
static int mode;
static unsigned char echo_frame[1536];
static unsigned echo_len;
long DoNtSyscall(unsigned long id, const unsigned long *args, unsigned int count) {
    (void)count;
    if (id == NTSYS_CreateFile) {
        if (mode == 0) return -1;
        *(HANDLE *)args[0] = (HANDLE)1;
        return 0;
    }
    if (id == NTSYS_DeviceIoControlFile) {
        NT_IO_STATUS_BLOCK *iosb = (NT_IO_STATUS_BLOCK *)args[4];
        if (args[5] == IOCTL_NET_SEND_PACKET) {
            echo_len = args[7];
            memcpy(echo_frame, (void *)args[6], echo_len);
            IPV4_HDR *ip = (IPV4_HDR *)(echo_frame + sizeof(ETH_HDR));
            uint32_t source = ip->saddr;
            ip->saddr = ip->daddr;
            ip->daddr = source;
            ip->ttl = 57;
            ip->check = 0;
            ip->check = ip_checksum(ip, sizeof(*ip));
            ICMP_HDR *icmp = (ICMP_HDR *)((uint8_t *)ip + sizeof(*ip));
            icmp->type = 0;
            if (mode == 6) ((uint8_t *)icmp)[sizeof(*icmp)] ^= 1;
            icmp->checksum = 0;
            icmp->checksum = ip_checksum(icmp, sizeof(*icmp) + 32);
            if (mode == 8) icmp->checksum ^= 1;
            if (mode == 5) ip->ver_ihl = 0x4f;
            iosb->Information = args[7];
            return 0;
        }
        if (args[5] == IOCTL_NET_RECV_PACKET) {
            unsigned length = mode == 7 ? 40 : echo_len;
            memcpy((void *)args[8], echo_frame, length);
            iosb->Information = length;
            return 0;
        }
        if (mode == 1) return -1;
        NET_ADAPTER_INFO *info = (NET_ADAPTER_INFO *)args[8];
        memset(info, 0, sizeof(*info));
        info->LinkUp = 1;
        info->Ipv4Addr = 0x0a00020f;
        info->Ipv4Netmask = 0xffffff00;
        ((NT_IO_STATUS_BLOCK *)args[4])->Information = mode == 2 ? 1 : sizeof(*info);
        return 0;
    }
    return 0;
}
int main(void) {
    NET_ADAPTER_INFO info;
    uint32_t ip;
    /* A TXT record contains bytes resembling an A-record header; only the
       following actual A record may supply the address. */
    uint8_t dns[] = {
        0x12,0x34,0x81,0x80,0,1,0,2,0,0,0,0, 1,'x',0,0,1,0,1,
        0xc0,12,0,16,0,1,0,0,0,60,0,15,
        14,0,1,0,1,0,0,0,0,0,4,203,0,113,7,
        0xc0,12,0,1,0,1,0,0,0,60,0,4,192,0,2,99
    };
    if (dns_read_address(dns, sizeof(dns), 0x1234, &ip) || ip != 0xc0000263) return 4;
    if (dns_read_address(dns, sizeof(dns)-1, 0x1234, &ip) != -1) return 5;
    if (dns_read_address(dns, sizeof(dns), 0x1235, &ip) != -1) return 6;
    dns[3] = 0x83;
    if (dns_read_address(dns, sizeof(dns), 0x1234, &ip) != -1) return 7;
    dns[3] = 0x80;
    dns[20] = 255;
    if (dns_read_address(dns, sizeof(dns), 0x1234, &ip) != -1) return 8;
    if (net_dns_resolve("localhost", &ip) || ip != 0x7f000001) return 1;
    if (net_dns_resolve("host.qemu", &ip) || ip != 0x0a000202) return 2;
    mode = 0;
    if (net_dns_resolve("example.invalid", &ip) != -1 || ip != 0) return 3;
    for (mode = 0; mode < 3; mode++) {
        g_hNetDev = NULL;
        memset(&info, 0xff, sizeof(info));
        if (net_get_adapter_info(&info) != -1) return 10 + mode;
        if (info.LinkUp || info.Ipv4Addr || info.MacAddress[0]) return 20 + mode;
    }
    mode = 3;
    if (net_get_adapter_info(&info) || !info.LinkUp || info.Ipv4Addr != 0x0a00020f) return 30;
    mode = 1;
    if (net_get_adapter_info(&info) != -1 || info.LinkUp) return 31;
    mode = 3;
    char *modify[] = { "ifconfig", "eth0", "up" };
    if (net_applet_main(3, modify) != 1) return 32;
    char *route[] = { "route", "add" };
    if (net_applet_main(2, route) != 1) return 33;
    g_GatewayMacResolved = 1;
    int poll_wait = -1, ttl = -1;
    mode = 4;
    if (net_icmp_ping(0x01010101, 12, &poll_wait, &ttl) || ttl != 57 || poll_wait != 0) return 34;
    for (mode = 5; mode <= 8; mode++) {
        if (net_icmp_ping(0x01010101, 12, &poll_wait, &ttl) != -1) return 35 + mode;
    }
    return 0;
}
'''


class AdapterTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "requires a host C compiler")
    def test_each_variant_rejects_missing_or_invalid_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "adapter.c"
            binary = Path(directory) / "adapter"
            source.write_text(HARNESS)
            for variant in ("minimal_rootfs", "rootfs", "chromium_rootfs"):
                with self.subTest(variant=variant):
                    subprocess.run(["cc", "-I", str(PROJECT / variant / "net"),
                                    str(source), "-o", str(binary)], check=True,
                                   capture_output=True, text=True)
                    result = subprocess.run([str(binary)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
