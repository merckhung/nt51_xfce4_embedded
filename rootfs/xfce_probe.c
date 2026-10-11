/* SPDX-License-Identifier: GPL-2.0-only */
/* Observe real mapped X11 windows; starting processes is not desktop readiness.
 * Wire layouts: https://cgit.freedesktop.org/xorg/proto/xproto/tree/Xproto.h
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

static uint16_t u16(const unsigned char *p) { return p[0] | (uint16_t)p[1] << 8; }
static uint32_t u32(const unsigned char *p) { return u16(p) | (uint32_t)u16(p + 2) << 16; }
static void put16(unsigned char *p, unsigned value) { p[0] = value; p[1] = value >> 8; }
static void put32(unsigned char *p, uint32_t value) { put16(p, value); put16(p + 2, value >> 16); }

static int transfer(int fd, void *buffer, unsigned count, int writing) {
    unsigned char *p = buffer;
    while (count) {
        int n = writing ? write(fd, p, count) : read(fd, p, count);
        if (n <= 0) return -1;
        p += n; count -= n;
    }
    return 0;
}

static int request(int fd, void *packet, unsigned count, unsigned char *reply, unsigned capacity) {
    if (transfer(fd, packet, count, 1) || transfer(fd, reply, 32, 0)) return -1;
    if (reply[0] != 1) return -1;
    unsigned extra = u32(reply + 4) * 4;
    if (extra > capacity - 32) return -1;
    return transfer(fd, reply + 32, extra, 0);
}

static int connect_x11(uint32_t *root) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, "/tmp/.X11-unix/X0");
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address))) { close(fd); return -1; }
    unsigned char hello[12] = { 'l', 0, 11, 0 }, prefix[8], setup[16384];
    if (transfer(fd, hello, sizeof(hello), 1) || transfer(fd, prefix, 8, 0) || prefix[0] != 1) goto fail;
    unsigned length = u16(prefix + 6) * 4;
    if (length < 32 || length > sizeof(setup) || transfer(fd, setup, length, 0)) goto fail;
    unsigned screen = 32 + ((u16(setup + 16) + 3) & ~3) + setup[21] * 8;
    if (!setup[20] || screen + 40 > length) goto fail;
    *root = u32(setup + screen);
    return fd;
fail:
    close(fd); return -1;
}

struct observed { unsigned top, bottom, terminal, desktop, budget; };

static int inspect(int fd, uint32_t window, uint32_t wm_class, int parent_y,
                   unsigned depth, struct observed *found) {
    if (depth > 3 || !found->budget) return 0;
    found->budget--;
    unsigned char packet[24] = {0}, reply[4096];
    packet[0] = 3; put16(packet + 2, 2); put32(packet + 4, window);
    if (request(fd, packet, 8, reply, sizeof(reply))) return -1;
    if (reply[26] != 2) return 0; /* IsViewable, including mapped ancestors */

    packet[0] = 14;
    if (request(fd, packet, 8, reply, sizeof(reply))) return -1;
    int y = parent_y + (int16_t)u16(reply + 14);
    unsigned width = u16(reply + 16), height = u16(reply + 18);

    packet[0] = 20; put16(packet + 2, 6); put32(packet + 8, wm_class);
    put32(packet + 12, 0); put32(packet + 16, 0); put32(packet + 20, 128);
    if (request(fd, packet, 24, reply, sizeof(reply))) return -1;
    if (reply[1] == 8) {
        unsigned n = u32(reply + 16);
        if (n > 512) return -1;
        reply[32 + n] = 0;
        if (strstr((char *)reply + 32, "xfce4-panel") && width && height) {
            if (y < 40) found->top++;
            if (y >= 480) found->bottom++;
        }
        if (strstr((char *)reply + 32, "xfce4-terminal")) found->terminal++;
        if (strstr((char *)reply + 32, "xfdesktop")) found->desktop++;
    }

    memset(packet, 0, sizeof(packet));
    packet[0] = 15; put16(packet + 2, 2); put32(packet + 4, window);
    if (request(fd, packet, 8, reply, sizeof(reply))) return -1;
    unsigned children = u16(reply + 16);
    if (children > 256 || 32 + children * 4 > sizeof(reply)) return -1;
    uint32_t ids[256];
    for (unsigned i = 0; i < children; i++) ids[i] = u32(reply + 32 + i * 4);
    for (unsigned i = 0; i < children; i++)
        if (inspect(fd, ids[i], wm_class, y, depth + 1, found)) return -1;
    return 0;
}

int xfce_probe_main(int argc, char **argv) {
    (void)argc; (void)argv;
    for (unsigned attempt = 0; attempt < 120; attempt++) {
        uint32_t root;
        int fd = connect_x11(&root);
        if (fd >= 0) {
            unsigned char atom_request[16] = {16, 0, 4, 0, 8, 0, 0, 0,
                                             'W','M','_','C','L','A','S','S'};
            unsigned char reply[32];
            struct observed found = { .budget = 256 };
            if (!request(fd, atom_request, 16, reply, sizeof(reply)) &&
                !inspect(fd, root, u32(reply + 8), 0, 0, &found) &&
                found.top && found.bottom && found.terminal && found.desktop) {
                printf("[xfce-probe] READY top_panel=%u bottom_panel=%u terminal=%u desktop=%u\n",
                       found.top, found.bottom, found.terminal, found.desktop);
                close(fd); return 0;
            }
            close(fd);
        }
        sleep(1);
    }
    fprintf(stderr, "[xfce-probe] FAILED: required visible XFCE windows were not observed\n");
    return 1;
}
