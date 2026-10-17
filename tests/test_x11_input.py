# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the framebuffer bridge's XTEST encoding, key, wheel and cursor helpers."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include <assert.h>
#include <string.h>
#include "x11_input.h"
static unsigned char sent[64];
static unsigned sent_size;
static int short_writes;
static long capture(int fd, const void *data, unsigned int count) {
    (void)fd;
    if (short_writes && count > 7) count = 7; /* The sender must finish partial writes. */
    memcpy(sent + sent_size, data, count);
    sent_size += count;
    return count;
}
static long failing(int fd, const void *data, unsigned int count) {
    (void)fd; (void)data; (void)count;
    return -1;
}
int main(void) {
    unsigned char button = 0;
    unsigned int pixels[20 * 20];

    for (short_writes = 0; short_writes < 2; short_writes++) {
        sent_size = 0;
        assert(x11_input_send(3, 131, 4, 5, 300, -2, capture) == 0);
        assert(sent_size == 36);
        assert(sent[0] == 131 && sent[1] == 2 && sent[2] == 9 && sent[4] == 4 && sent[5] == 5);
        assert(sent[24] == 0x2c && sent[25] == 0x01); /* x = 300, little-endian */
        assert(sent[26] == 0xfe && sent[27] == 0xff); /* y = -2 */
    }
    assert(x11_input_send(3, 131, 6, 0, 0, 0, failing) < 0);
    assert(x11_input_send(-1, 131, 6, 0, 0, 0, capture) < 0);
    assert(x11_input_send(3, 0, 6, 0, 0, 0, capture) < 0);

    assert(x11_input_keycode(0x1e, 0) == 38);   /* A */
    assert(x11_input_keycode(0x48, 1) == 111);  /* Up */
    assert(x11_input_keycode(0x49, 1) == 112);  /* Page Up */
    assert(x11_input_keycode(0x2a, 1) == 0);    /* Print Screen's fake shift */
    assert(x11_input_keycode(0, 0) == 0 && x11_input_keycode(0x59, 0) == 0);

    assert(x11_input_wheel(0x0001, &button) == 0);              /* Left button only */
    assert(x11_input_wheel(0xff00, &button) == 1 && button == 4); /* One click up */
    assert(x11_input_wheel(0x0304, &button) == 3 && button == 5); /* Three clicks down */

    memset(pixels, 0x11, sizeof(pixels));
    x11_input_draw_cursor(pixels, 20, 20, 10, 10);
    assert(pixels[10 * 20 + 10] == 0xff000000u);       /* Outline at the hot spot */
    assert(pixels[12 * 20 + 11] == 0xffffffffu);       /* Fill */
    assert(pixels[9 * 20 + 10] == 0x11111111u);        /* Untouched above */
    x11_input_draw_cursor(pixels, 20, 20, -5, 19);     /* Clipped without overrun */
    return 0;
}
'''


class X11InputTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which('cc'), 'host C compiler required')
    def test_xtest_keys_wheel_and_cursor(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'input.c'
            executable = Path(directory)/'input'
            source.write_text(HARNESS)
            # native/include also holds freestanding libc headers; take only this one.
            shutil.copy(PROJECT/'native/include/x11_input.h', directory)
            subprocess.run(['cc', '-O2', '-std=c11', '-Wall', '-Werror', '-fsanitize=address,undefined',
                            '-o', str(executable), str(source)], check=True)
            subprocess.run([str(executable)], check=True)


if __name__ == '__main__':
    unittest.main()
