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

struct observed {
    unsigned top, bottom, terminal, desktop, chromium, budget;
    char chromium_title[256];
};
static uint32_t g_wm_name_atom = 39; /* XA_WM_NAME */
static const char *g_expect_title = NULL;

/* Reads WM_NAME (Chromium sets it to "<page title> - Chromium"). */
static void read_title(int fd, uint32_t window, char *out, unsigned cap) {
    unsigned char packet[24] = {0}, reply[4096];
    packet[0] = 20; put16(packet + 2, 6); put32(packet + 4, window); put32(packet + 8, g_wm_name_atom);
    put32(packet + 12, 0); put32(packet + 16, 0); put32(packet + 20, 256);
    out[0] = 0;
    if (request(fd, packet, 24, reply, sizeof(reply)) || reply[1] != 8) return;
    unsigned n = u32(reply + 16);
    if (n >= cap) n = cap - 1;
    memcpy(out, reply + 32, n);
    out[n] = 0;
}

/* Sample horizontal strips in the Chromium webpage content area (below the
 * ~90px tab/omnibox bar) via X11 GetImage (opcode 73, ZPixmap) so READY is
 * only reported once non-blank page content has been painted. This does not
 * identify the renderer or validate TLS certificates. */
static int content_painted(int fd, uint32_t window, unsigned width, unsigned height) {
    if (width < 300 || height < 300) return 0;
    const unsigned sample_w = 128;
    const unsigned sample_x = (width > sample_w + 80) ? 60 : 16;
    /* Cover the body below the browser controls, including content beneath
     * large blank advertisement slots. A single colored strip still fails. */
    const unsigned ys[] = { 120, 160, 200, 240, 280, 320, 360, 400, 440, 480 };
    unsigned non_white_rows = 0;
    unsigned total_transitions = 0;
    for (unsigned r = 0; r < sizeof(ys) / sizeof(ys[0]); r++) {
        if (ys[r] + 1 >= height) continue;
        unsigned char req[20] = {0}, reply[32 + 128 * 4];
        req[0] = 73; /* X_GetImage */
        req[1] = 2;  /* ZPixmap */
        put16(req + 2, 5);
        put32(req + 4, window);
        put16(req + 8, sample_x);
        put16(req + 10, ys[r]);
        put16(req + 12, sample_w);
        put16(req + 14, 1);
        put32(req + 16, 0xFFFFFFFFU);
        if (request(fd, req, 20, reply, sizeof(reply))) continue;
        unsigned extra = u32(reply + 4) * 4;
        if (extra < sample_w * 4) continue;
        const unsigned char *px = reply + 32;
        uint32_t prev = u32(px) & 0x00FFFFFFU;
        unsigned row_transitions = 0;
        unsigned row_non_white = 0;
        for (unsigned i = 0; i < sample_w; i++) {
            uint32_t c = u32(px + i * 4) & 0x00FFFFFFU;
            if (c != 0x00FFFFFFU && c != 0x00000000U) row_non_white++;
            if (c != prev) {
                row_transitions++;
                prev = c;
            }
        }
        if (row_non_white >= 4 && row_transitions >= 2) {
            non_white_rows++;
            total_transitions += row_transitions;
        }
    }
    return (non_white_rows >= 2 && total_transitions >= 12);
}

static void inspect(int fd, uint32_t window, uint32_t wm_class, int parent_y,
                    unsigned depth, struct observed *found) {
    if (depth > 6 || !found->budget) return;
    found->budget--;
    unsigned char packet[24] = {0}, reply[4096];
    packet[0] = 3; put16(packet + 2, 2); put32(packet + 4, window);
    if (request(fd, packet, 8, reply, sizeof(reply))) return;
    if (reply[26] != 2) return; /* IsViewable, including mapped ancestors */

    packet[0] = 14;
    if (request(fd, packet, 8, reply, sizeof(reply))) return;
    int y = parent_y + (int16_t)u16(reply + 14);
    unsigned width = u16(reply + 16), height = u16(reply + 18);

    packet[0] = 20; put16(packet + 2, 6); put32(packet + 8, wm_class);
    put32(packet + 12, 0); put32(packet + 16, 0); put32(packet + 20, 128);
    if (request(fd, packet, 24, reply, sizeof(reply)) == 0 && reply[1] == 8) {
        unsigned n = u32(reply + 16);
        if (n <= 512) {
            reply[32 + n] = 0;
            char *prop = (char *)reply + 32;
            /* WM_CLASS is "instance\0class\0"; join so both names are searchable. */
            for (unsigned k = 0; k < n; k++) {
                if (prop[k] == '\0') prop[k] = ' ';
            }
            if (strstr(prop, "xfce4-panel") && width && height) {
                if (y < 40) found->top++;
                if (y >= 480) found->bottom++;
            }
            if (strstr(prop, "xfce4-terminal")) found->terminal++;
            if (strstr(prop, "xfdesktop")) found->desktop++;
            if ((strstr(prop, "chromium") || strstr(prop, "Chromium") ||
                 strstr(prop, "chrome") || strstr(prop, "Chrome")) &&
                width >= 200 && height >= 150) {
                char title[256];
                read_title(fd, window, title, sizeof(title));
                if (title[0]) memcpy(found->chromium_title, title, sizeof(title));
                if ((!g_expect_title || strstr(title, g_expect_title)) &&
                    content_painted(fd, window, width, height)) {
                    found->chromium++;
                }
            }
        }
    }

    memset(packet, 0, sizeof(packet));
    packet[0] = 15; put16(packet + 2, 2); put32(packet + 4, window);
    if (request(fd, packet, 8, reply, sizeof(reply))) return;
    unsigned children = u16(reply + 16);
    if (children > 256 || 32 + children * 4 > sizeof(reply)) return;
    uint32_t ids[256];
    for (unsigned i = 0; i < children; i++) ids[i] = u32(reply + 32 + i * 4);
    for (unsigned i = 0; i < children; i++)
        inspect(fd, ids[i], wm_class, y, depth + 1, found);
}

/* Usage: xfce-probe [--expect-title SUBSTRING]
 * Prints READY only once the four XFCE components and a mapped Chromium
 * window are visible; with --expect-title the Chromium window title (taken
 * from the loaded page's <title>) must contain SUBSTRING. */
int xfce_probe_main(int argc, char **argv) {
    unsigned ready_streak = 0;
    for (int i = 1; i + 1 < argc; i++)
        if (strcmp(argv[i], "--expect-title") == 0) g_expect_title = argv[i + 1];
    for (unsigned attempt = 0; attempt < 1500; attempt++) {
        uint32_t root;
        int fd = connect_x11(&root);
        if (fd >= 0) {
            unsigned char atom_request[16] = {16, 0, 4, 0, 8, 0, 0, 0,
                                             'W','M','_','C','L','A','S','S'};
            unsigned char reply[32];
            struct observed found = { .budget = 512 };
            if (!request(fd, atom_request, 16, reply, sizeof(reply))) {
                inspect(fd, root, u32(reply + 8), 0, 0, &found);
                if (found.top && found.bottom && found.terminal && found.desktop && found.chromium) {
                    ready_streak++;
                    if (ready_streak >= 3) {
                        printf("[xfce-probe] CHROMIUM_TITLE=%s\n", found.chromium_title);
                        printf("[xfce-probe] READY top_panel=%u bottom_panel=%u terminal=%u desktop=%u chromium=%u\n",
                               found.top, found.bottom, found.terminal, found.desktop, found.chromium);
                        fflush(stdout);
                        close(fd); return 0;
                    }
                } else {
                    ready_streak = 0;
                }
            }
            if (attempt > 0 && attempt % 10 == 0) {
                printf("[xfce-probe] Waiting (attempt %u/1500): top=%u bottom=%u term=%u desk=%u chrom=%u title='%s'\n",
                       attempt, found.top, found.bottom, found.terminal, found.desktop, found.chromium,
                       found.chromium_title);
                fflush(stdout);
            }
            close(fd);
        }
        sleep(1);
    }
    fprintf(stderr, "[xfce-probe] FAILED: required visible XFCE + Chromium windows were not observed\n");
    return 1;
}
