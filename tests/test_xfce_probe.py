# SPDX-License-Identifier: GPL-2.0-only
"""Exercise real X11 pixel sampling against explicit mock wire replies."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#define read probe_read
#define write probe_write
#include "xfce_probe.c"
#undef read
#undef write
#include <assert.h>
static unsigned char response[32 + 128 * 4];
static unsigned response_offset;
static int mode;
ssize_t probe_write(int fd, const void *data, size_t length) {
    (void)fd;
    const unsigned char *req = data;
    assert(length == 20 && req[0] == 73);
    unsigned y = u16(req + 10);
    memset(response, 0, sizeof(response));
    response[0] = 1;
    put32(response + 4, 128);
    for (unsigned i = 0; i < 128; i++) {
        int painted = (mode == 1 && y >= 400) || (mode == 2 && y == 240) ||
                      (mode == 3 && y < 90);
        put32(response + 32 + i * 4, painted ? (i % 2 ? 0x123456 : 0xabcdef) : 0xffffff);
    }
    response_offset = 0;
    return length;
}
ssize_t probe_read(int fd, void *data, size_t length) {
    (void)fd;
    assert(response_offset + length <= sizeof(response));
    memcpy(data, response + response_offset, length);
    response_offset += length;
    return length;
}
int main(void) {
    mode = 0; assert(!content_painted(1, 42, 764, 536)); /* Blank body. */
    mode = 1; assert(content_painted(1, 42, 764, 536)); /* Photo below ad slot. */
    mode = 2; assert(!content_painted(1, 42, 764, 536)); /* One strip is insufficient. */
    mode = 3; assert(!content_painted(1, 42, 764, 536)); /* Browser controls alone. */
    mode = 1; assert(!content_painted(1, 42, 764, 300)); /* Bounds exclude the photo. */
}
'''


class PixelProbeTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which('cc'), 'host C compiler required')
    def test_sparse_page_and_blank_content(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'probe.c'
            executable = Path(directory)/'probe'
            source.write_text(HARNESS)
            subprocess.run(['cc', '-O2', '-std=c11',
                            '-I'+str(PROJECT/'chromium_rootfs'), str(source),
                            '-o', str(executable)], check=True, capture_output=True)
            subprocess.run([str(executable)], check=True, timeout=10)
