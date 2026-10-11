#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""FAT16 image writer with VFAT names."""

import json
import os
import posixpath
import re
import struct
import sys


def parse_c_byte_array(header_path: str, array_name: str) -> bytes:
    with open(header_path, "r", encoding="latin1") as f:
        text = f.read()
    m = re.search(rf"{array_name}\s*\[\s*\]\s*=\s*\{{([^}}]+)\}}", text, re.S)
    if not m:
        raise ValueError(f"Could not find {array_name}[] in {header_path}")
    nums = [int(x.strip(), 0) for x in m.group(1).replace("\n", " ").split(",") if x.strip()]
    if len(nums) != 512:
        raise ValueError(f"Expected 512 bytes for {array_name}, got {len(nums)}")
    return bytes(nums)


def lfn_checksum(short_name_11: bytes) -> int:
    s = 0
    for b in short_name_11:
        s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    return s


class Fat16Volume:
    """In-memory FAT16 filesystem image builder with 8.3 + VFAT LFN support."""

    def __init__(
        self,
        total_sectors: int,
        boot_sector_template: bytes,
        hidden_sectors: int = 0,
        sectors_per_cluster: int = 4,
        root_entries: int = 512,
        heads: int = 16,
        sectors_per_track: int = 63,
        volume_label: bytes = b"NT51_EMBED3",
    ):
        self.sector_size = 512
        self.total_sectors = total_sectors
        self.hidden_sectors = hidden_sectors
        self.spc = sectors_per_cluster
        self.reserved_sectors = 1
        self.num_fats = 2
        self.root_entries = root_entries
        self.root_dir_sectors = (root_entries * 32 + 511) // 512
        self.heads = heads
        self.spt = sectors_per_track
        self.volume_label = volume_label.ljust(11, b" ")[:11]

        data_sectors_est = total_sectors - self.reserved_sectors - self.root_dir_sectors
        clusters_est = data_sectors_est // self.spc
        self.sectors_per_fat = max(16, (clusters_est * 2 + 511 + 512) // 512)

        self.fat1_sector = self.reserved_sectors
        self.fat2_sector = self.fat1_sector + self.sectors_per_fat
        self.root_dir_sector = self.fat2_sector + self.sectors_per_fat
        self.data_start_sector = self.root_dir_sector + self.root_dir_sectors
        self.total_clusters = (self.total_sectors - self.data_start_sector) // self.spc
        if self.total_clusters < 4085 or self.total_clusters >= 65525:
            raise ValueError(
                f"Cluster count {self.total_clusters} outside FAT16 range (4085..65524)."
            )

        self.image = bytearray(self.total_sectors * self.sector_size)
        self.fat = [0] * (self.total_clusters + 2)
        self.fat[0] = 0xFFF8
        self.fat[1] = 0xFFFF
        self.next_free_cluster = 2

        self.dirs = {
            "": {
                "cluster": 0,
                "entries": bytearray(),
                "short_used": set(),
            }
        }
        self.file_map = {}

        self._init_boot_sector(boot_sector_template)

    def _init_boot_sector(self, tmpl: bytes):
        bs = bytearray(tmpl)
        struct.pack_into("<H", bs, 0x0B, self.sector_size)
        struct.pack_into("<B", bs, 0x0D, self.spc)
        struct.pack_into("<H", bs, 0x0E, self.reserved_sectors)
        struct.pack_into("<B", bs, 0x10, self.num_fats)
        struct.pack_into("<H", bs, 0x11, self.root_entries)
        if self.total_sectors <= 65535:
            struct.pack_into("<H", bs, 0x13, self.total_sectors)
            struct.pack_into("<I", bs, 0x20, 0)
        else:
            struct.pack_into("<H", bs, 0x13, 0)
            struct.pack_into("<I", bs, 0x20, self.total_sectors)
        struct.pack_into("<B", bs, 0x15, 0xF8)
        struct.pack_into("<H", bs, 0x16, self.sectors_per_fat)
        struct.pack_into("<H", bs, 0x18, self.spt)
        struct.pack_into("<H", bs, 0x1A, self.heads)
        struct.pack_into("<I", bs, 0x1C, self.hidden_sectors)
        struct.pack_into("<B", bs, 0x24, 0x80)
        struct.pack_into("<B", bs, 0x25, 0x00)
        struct.pack_into("<B", bs, 0x26, 0x29)
        struct.pack_into("<I", bs, 0x27, 0x20261010)
        bs[0x2B:0x36] = self.volume_label
        bs[0x36:0x3E] = b"FAT16   "
        bs[0x1FE:0x200] = b"\x55\xAA"
        self.image[0:512] = bs

    def _alloc_clusters(self, size_bytes: int) -> int:
        if size_bytes == 0:
            return 0
        cluster_bytes = self.spc * self.sector_size
        num_clusters = (size_bytes + cluster_bytes - 1) // cluster_bytes
        first_cl = self.next_free_cluster
        prev_cl = None
        for i in range(num_clusters):
            cl = self.next_free_cluster
            self.next_free_cluster += 1
            if self.next_free_cluster >= self.total_clusters + 2:
                raise RuntimeError("FAT16 volume out of space!")
            if prev_cl is not None:
                self.fat[prev_cl] = cl
            self.fat[cl] = 0xFFFF
            prev_cl = cl
        return first_cl

    def _cluster_to_offset(self, cl: int) -> int:
        return (self.data_start_sector + (cl - 2) * self.spc) * self.sector_size

    def _write_cluster_chain(self, start_cl: int, data: bytes):
        cl = start_cl
        off = 0
        cluster_bytes = self.spc * self.sector_size
        while cl != 0xFFFF and off < len(data):
            chunk = data[off : off + cluster_bytes]
            disk_off = self._cluster_to_offset(cl)
            self.image[disk_off : disk_off + len(chunk)] = chunk
            off += len(chunk)
            cl = self.fat[cl]

    def _make_short_name(self, filename: str, used_set: set) -> bytes:
        fname = filename.upper()
        if "." in fname:
            base, ext = fname.rsplit(".", 1)
        else:
            base, ext = fname, ""
        clean_base = re.sub(r"[^A-Z0-9$%'_@~`!(){}^#&-]", "", base)
        clean_ext = re.sub(r"[^A-Z0-9$%'_@~`!(){}^#&-]", "", ext)[:3]
        if not clean_base:
            clean_base = "FILE"

        if len(base) <= 8 and len(ext) <= 3 and base == clean_base and ext == clean_ext:
            short = clean_base.ljust(8) + clean_ext.ljust(3)
            short_b = short.encode("ascii", "replace")
            if short_b not in used_set:
                used_set.add(short_b)
                return short_b

        for num in range(1, 1000):
            tag = f"~{num}"
            s_base = clean_base[: 8 - len(tag)] + tag
            short = s_base.ljust(8) + clean_ext.ljust(3)
            short_b = short.encode("ascii", "replace")
            if short_b not in used_set:
                used_set.add(short_b)
                return short_b
        raise RuntimeError(f"Cannot generate unique short name for {filename}")

    def _encode_dir_entry(
        self,
        long_name: str,
        attr: int,
        start_cluster: int,
        file_size: int,
        used_set: set,
    ) -> bytearray:
        short_11 = self._make_short_name(long_name, used_set)
        chk = lfn_checksum(short_11)

        result = bytearray()
        short_base = short_11[:8].decode("ascii").rstrip()
        short_ext = short_11[8:].decode("ascii").rstrip()
        short_display = short_base + ("." + short_ext if short_ext else "")
        # Only omit VFAT entries when the exact name has a valid 8.3 encoding.
        # Numeric version directories such as 2.10.0 still require a long name.
        is_exact_short = long_name == short_display
        if not is_exact_short:
            utf16 = long_name.encode("utf-16le")
            chars = [utf16[i : i + 2] for i in range(0, len(utf16), 2)]
            chars.append(b"\x00\x00")
            while len(chars) % 13 != 0:
                chars.append(b"\xFF\xFF")

            num_lfn = len(chars) // 13
            for seq in range(num_lfn, 0, -1):
                idx = (seq - 1) * 13
                chunk = chars[idx : idx + 13]
                seq_byte = seq | (0x40 if seq == num_lfn else 0)
                lfn_ent = bytearray(32)
                lfn_ent[0] = seq_byte
                lfn_ent[1:11] = b"".join(chunk[0:5])
                lfn_ent[11] = 0x0F
                lfn_ent[12] = 0x00
                lfn_ent[13] = chk
                lfn_ent[14:26] = b"".join(chunk[5:11])
                lfn_ent[26:28] = b"\x00\x00"
                lfn_ent[28:32] = b"".join(chunk[11:13])
                result.extend(lfn_ent)

        s_ent = struct.pack(
            "<11sBBBHHHHHHHI",
            short_11,
            attr,
            0x00,
            0,
            0x6000,
            0x5D4A,
            0x5D4A,
            0,
            0x6000,
            0x5D4A,
            start_cluster,
            file_size,
        )
        result.extend(s_ent)
        return result

    def mkdir(self, path: str):
        norm = path.strip("/\\").replace("\\", "/")
        if not norm:
            return
        parts = norm.split("/")
        cur = ""
        for p in parts:
            parent = cur
            cur = f"{parent}/{p}" if parent else p
            key = cur.upper()
            if key not in self.dirs:
                parent_key = parent.upper()
                parent_dir = self.dirs[parent_key]
                cl = self._alloc_clusters(self.spc * self.sector_size)
                dot_entries = bytearray()
                dot_entries.extend(
                    struct.pack(
                        "<11sBBBHHHHHHHI",
                        b".          ", 0x10, 0, 0, 0x6000, 0x5D4A, 0x5D4A, 0, 0x6000, 0x5D4A, cl, 0
                    )
                )
                dot_entries.extend(
                    struct.pack(
                        "<11sBBBHHHHHHHI",
                        b"..         ", 0x10, 0, 0, 0x6000, 0x5D4A, 0x5D4A, 0, 0x6000, 0x5D4A, parent_dir["cluster"], 0
                    )
                )
                self.dirs[key] = {
                    "cluster": cl,
                    "entries": dot_entries,
                    "short_used": set(),
                }
                parent_dir["entries"].extend(
                    self._encode_dir_entry(p, 0x10, cl, 0, parent_dir["short_used"])
                )

    def add_file(self, dst_path: str, data: bytes, attr: int = 0x20):
        norm = dst_path.strip("/\\").replace("\\", "/")
        if norm.upper() in self.file_map:
            return
        if "/" in norm:
            dir_part, fname = norm.rsplit("/", 1)
            self.mkdir(dir_part)
            parent_dir = self.dirs[dir_part.upper()]
        else:
            fname = norm
            parent_dir = self.dirs[""]

        if len(data) > 0:
            start_cl = self._alloc_clusters(len(data))
            self._write_cluster_chain(start_cl, data)
        else:
            start_cl = 0

        parent_dir["entries"].extend(
            self._encode_dir_entry(fname, attr, start_cl, len(data), parent_dir["short_used"])
        )
        self.file_map[norm.upper()] = (start_cl, len(data))

    def add_link(self, dst_path: str, src_path: str, attr: int = 0x20):
        norm_dst = dst_path.strip("/\\").replace("\\", "/")
        norm_src = src_path.strip("/\\").replace("\\", "/")
        if norm_dst.upper() in self.file_map:
            return
        if norm_src.upper() not in self.file_map:
            raise KeyError(f"Source file {norm_src} not found in volume for linking to {norm_dst}")
        start_cl, size = self.file_map[norm_src.upper()]
        if "/" in norm_dst:
            dir_part, fname = norm_dst.rsplit("/", 1)
            self.mkdir(dir_part)
            parent_dir = self.dirs[dir_part.upper()]
        else:
            fname = norm_dst
            parent_dir = self.dirs[""]
        parent_dir["entries"].extend(
            self._encode_dir_entry(fname, attr, start_cl, size, parent_dir["short_used"])
        )
        self.file_map[norm_dst.upper()] = (start_cl, size)

    def add_host_file(self, dst_path: str, host_path: str, attr: int = 0x20):
        with open(host_path, "rb") as f:
            data = f.read()
        self.add_file(dst_path, data, attr)

    def finalize(self) -> bytes:
        cluster_bytes = self.spc * self.sector_size
        for key, d in self.dirs.items():
            if key == "":
                continue
            entries_data = d["entries"]
            if len(entries_data) > cluster_bytes:
                extra_needed = len(entries_data) - cluster_bytes
                extra_start = self._alloc_clusters(extra_needed)
                self.fat[d["cluster"]] = extra_start
            self._write_cluster_chain(d["cluster"], entries_data)

        root_bytes = self.dirs[""]["entries"]
        max_root_bytes = self.root_dir_sectors * self.sector_size
        if len(root_bytes) > max_root_bytes:
            raise RuntimeError(f"Root directory overflow: {len(root_bytes)} > {max_root_bytes}")
        root_off = self.root_dir_sector * self.sector_size
        self.image[root_off : root_off + len(root_bytes)] = root_bytes

        fat_bytes = bytearray(self.sectors_per_fat * self.sector_size)
        for i, val in enumerate(self.fat):
            struct.pack_into("<H", fat_bytes, i * 2, val & 0xFFFF)

        fat1_off = self.fat1_sector * self.sector_size
        fat2_off = self.fat2_sector * self.sector_size
        self.image[fat1_off : fat1_off + len(fat_bytes)] = fat_bytes
        self.image[fat2_off : fat2_off + len(fat_bytes)] = fat_bytes

        return bytes(self.image)


