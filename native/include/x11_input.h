/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NT51_X11_INPUT_H
#define NT51_X11_INPUT_H

/* XTEST 2.2 FakeInput, encoded explicitly for the little-endian X11 client. */
static int x11_input_send(int fd, unsigned char opcode, unsigned char type,
                          unsigned char detail, short x, short y,
                          long (*write_bytes)(int, const void *, unsigned int)) {
    unsigned char packet[36] = {0};
    unsigned int done = 0;
    if (fd < 0 || !opcode) return -1;
    packet[0] = opcode; packet[1] = 2; packet[2] = 9;
    packet[4] = type; packet[5] = detail;
    packet[24] = (unsigned char)x; packet[25] = (unsigned short)x >> 8;
    packet[26] = (unsigned char)y; packet[27] = (unsigned short)y >> 8;
    while (done < sizeof(packet)) {
        long n = write_bytes(fd, packet + done, sizeof(packet) - done);
        if (n <= 0 || (unsigned long)n > sizeof(packet) - done) return -1;
        done += (unsigned int)n;
    }
    return 0;
}

static unsigned char x11_input_keycode(unsigned short scancode, int extended) {
    if (!scancode || scancode > 0x58) return 0;
    if (!extended) return (unsigned char)(scancode + 8);
    switch (scancode) {
    case 0x1c: return 104; /* keypad Enter */
    case 0x1d: return 105; /* right Control */
    case 0x35: return 106; /* keypad Divide */
    case 0x37: return 107; /* Print Screen */
    case 0x38: return 108; /* right Alt */
    case 0x47: return 110; /* Home */
    case 0x48: return 111; /* Up */
    case 0x49: return 112; /* Page Up */
    case 0x4b: return 113; /* Left */
    case 0x4d: return 114; /* Right */
    case 0x4f: return 115; /* End */
    case 0x50: return 116; /* Down */
    case 0x51: return 117; /* Page Down */
    case 0x52: return 118; /* Insert */
    case 0x53: return 119; /* Delete */
    case 0x5b: return 133; /* left Super */
    case 0x5c: return 134; /* right Super */
    case 0x5d: return 135; /* Menu */
    default: return 0;    /* Ignore synthetic Print Screen shift prefixes. */
    }
}

/* RawMouse packets carry a signed IntelliMouse wheel delta in Buttons bits 8-15.
 * Returns the number of X11 wheel clicks; core button 4 scrolls up, 5 down. */
static int x11_input_wheel(unsigned long buttons, unsigned char *button) {
    int delta = (signed char)((buttons >> 8) & 0xff);
    *button = delta < 0 ? 4 : 5; /* PS/2 negative Z is wheel up. */
    return delta < 0 ? -delta : delta;
}

static void x11_input_draw_cursor(unsigned int *pixels, int width, int height, int x, int y) {
    static const unsigned short mask[16] = {
        0x8000,0xc000,0xe000,0xf000,0xf800,0xfc00,0xfe00,0xff00,
        0xff80,0xfc00,0xdc00,0x8e00,0x0e00,0x0700,0x0700,0
    };
    static const unsigned short fill[16] = {
        0,0x4000,0x6000,0x7000,0x7800,0x7c00,0x7e00,0x7f00,
        0x7f80,0x7800,0x4c00,0x0600,0x0600,0x0300,0x0300,0
    };
    for (int row = 0; row < 16; row++) {
        for (int col = 0; col < 16; col++) {
            int px = x + col, py = y + row;
            if (px < 0 || py < 0 || px >= width || py >= height) continue;
            if (mask[row] & (0x8000U >> col))
                pixels[py * width + px] = (fill[row] & (0x8000U >> col)) ? 0xffffffffU : 0xff000000U;
        }
    }
}
#endif
