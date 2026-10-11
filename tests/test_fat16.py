# SPDX-License-Identifier: GPL-2.0-only
"""Check on-disk FAT names independently of the writer's naming helpers."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from fat16 import Fat16Volume


def read_names(image):
    reserved = struct.unpack_from("<H", image, 14)[0]
    fats = image[16]
    entries = struct.unpack_from("<H", image, 17)[0]
    sectors_per_fat = struct.unpack_from("<H", image, 22)[0]
    root = (reserved + fats * sectors_per_fat) * 512
    names = []
    fragments = {}
    checksums = []
    for offset in range(root, root + entries * 32, 32):
        record = image[offset:offset + 32]
        if record[0] == 0:
            break
        if record[11] == 15:
            fragments[record[0] & 31] = (
                record[1:11] + record[14:26] + record[28:32]
            ).decode("utf-16-le")
            checksums.append(record[13])
            continue
        short = record[:11]
        # A period belongs between the two fields, never inside either field.
        for byte in short:
            if byte < 32 or byte in b'"*+,./:;<=>?[\\]|':
                raise AssertionError("Illegal DOS short name: " + repr(short))
        checksum = 0
        for byte in short:
            checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 255
        if any(value != checksum for value in checksums):
            raise AssertionError("VFAT checksum mismatch")
        base = short[:8].decode("ascii").rstrip()
        ext = short[8:].decode("ascii").rstrip()
        name = ("".join(fragments[key] for key in sorted(fragments)).split("\0")[0]
                if fragments else base + ("." + ext if ext else ""))
        names.append((name, short))
        fragments = {}
        checksums = []
    return names


class FatNamesTest(unittest.TestCase):
    def test_version_directories_and_file_extensions(self):
        volume = Fat16Volume(8192, bytes(512), sectors_per_cluster=1)
        expected = ["2.10.0", "800x600", "GLIBC.2.3", "foo.bar.baz", "NTLDR", "a+b.txt"]
        for name in expected:
            volume.add_file(name, b"test")
        records = read_names(volume.finalize())
        self.assertEqual([name for name, _ in records], expected)
        self.assertEqual(len({short for _, short in records}), len(expected))

    def test_many_colliding_aliases_remain_unique(self):
        volume = Fat16Volume(8192, bytes(512), sectors_per_cluster=1)
        expected = ["longfilename%03d.txt" % number for number in range(100)]
        for name in expected:
            volume.add_file(name, b"x")
        records = read_names(volume.finalize())
        self.assertEqual([name for name, _ in records], expected)
        self.assertEqual(len({short for _, short in records}), len(expected))


if __name__ == "__main__":
    unittest.main()
