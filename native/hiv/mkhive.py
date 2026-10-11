#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
mkhive.py - Standalone Windows NT/XP (regf v1.3) Registry Hive Generator & Verifier

Generates the binary SYSTEM registry hive
without requiring Administrator privileges or NtLoadKey, and verifies all
invariants checked by ntldr (BlScanRegistry) and ntoskrnl.exe
(HvpHeaderCheckSum, HvCheckHive, HvCheckBin, CmpValidateHiveSecurityDescriptors,
CmpCheckRegistry2, CmpCheckKey, CmpCheckValueList, and CmpFindSubKeyByName).
"""

import os
import sys
import struct

REG_NONE                       = 0
REG_SZ                         = 1
REG_EXPAND_SZ                  = 2
REG_BINARY                     = 3
REG_DWORD                      = 4
REG_LINK                       = 6
REG_MULTI_SZ                   = 7
REG_RESOURCE_LIST              = 8
REG_FULL_RESOURCE_DESCRIPTOR   = 9
REG_RESOURCE_REQUIREMENTS_LIST = 10

HBASE_BLOCK_SIGNATURE          = 0x66676572  # "regf"
HBIN_SIGNATURE                 = 0x6e696268  # "hbin"
CM_KEY_NODE_SIGNATURE          = 0x6b6e      # "nk"
CM_KEY_VALUE_SIGNATURE         = 0x6b76      # "vk"
CM_KEY_SECURITY_SIGNATURE      = 0x6b73      # "sk"
CM_KEY_INDEX_LEAF              = 0x696c      # "li"
CM_KEY_VALUE_SPECIAL_SIZE      = 0x80000000
HCELL_NIL                      = 0xFFFFFFFF

KEY_HIVE_ENTRY                 = 0x0004
KEY_NO_DELETE                  = 0x0008


def reg_sz(s: str):
    return (REG_SZ, (s + "\x00").encode("utf-16le"))


def reg_expand_sz(s: str):
    return (REG_EXPAND_SZ, (s + "\x00").encode("utf-16le"))


def reg_dword(v: int):
    return (REG_DWORD, struct.pack("<I", v & 0xFFFFFFFF))


def reg_binary(b: bytes):
    return (REG_BINARY, bytes(b))


def reg_binary_ulongs(*ulongs):
    return (REG_BINARY, b"".join(struct.pack("<I", u & 0xFFFFFFFF) for u in ulongs))


def reg_multi_sz(strings):
    if not strings:
        return (REG_MULTI_SZ, b"\x00\x00")
    encoded = b"".join((s + "\x00").encode("utf-16le") for s in strings) + b"\x00\x00"
    return (REG_MULTI_SZ, encoded)


def reg_resource_requirements(*ulongs):
    data = b"".join(struct.pack("<I", u & 0xFFFFFFFF) for u in ulongs)
    return (REG_RESOURCE_REQUIREMENTS_LIST, data)


def reg_resource_list(*ulongs):
    data = b"".join(struct.pack("<I", u & 0xFFFFFFFF) for u in ulongs)
    return (REG_RESOURCE_LIST, data)


class RegKey:
    def __init__(self, name: str, is_root: bool = False):
        self.name = name
        self.is_root = is_root
        self.subkeys = {}   # upcase_name -> RegKey
        self.values = []    # list of (name_str, reg_type, data_bytes)
        self.cell_index = HCELL_NIL

    def sub(self, path: str) -> "RegKey":
        cur = self
        for part in path.split("\\"):
            if not part:
                continue
            up = part.upper()
            if up not in cur.subkeys:
                cur.subkeys[up] = RegKey(part)
            cur = cur.subkeys[up]
        return cur

    def val(self, name: str, typed_val):
        reg_type, data_bytes = typed_val
        for i, (existing_name, _, _) in enumerate(self.values):
            if existing_name.upper() == name.upper():
                self.values[i] = (name, reg_type, data_bytes)
                return self
        self.values.append((name, reg_type, data_bytes))
        return self


def build_security_descriptor() -> bytes:
    """
    Builds a self-relative SECURITY_DESCRIPTOR_RELATIVE (Revision 1)
    with Owner=LOCAL_SYSTEM (S-1-5-18), Group=LOCAL_SYSTEM (S-1-5-18),
    and a valid DACL granting KEY_ALL_ACCESS to LOCAL_SYSTEM and Everyone.
    Passes SeValidSecurityDescriptor and RtlValidAcl.
    """
    system_sid = struct.pack("<BBBBBBIB", 1, 1, 0, 0, 0, 0, 0, 5) + struct.pack("<I", 18)
    # Wait: SID header is Revision(1), SubAuthorityCount(1), IdentifierAuthority(6 bytes) = 8 bytes,
    # followed by SubAuthority[0] (4 bytes) = 12 bytes total.
    system_sid = bytes([1, 1, 0, 0, 0, 0, 0, 5]) + struct.pack("<I", 18)
    world_sid  = bytes([1, 1, 0, 0, 0, 0, 0, 1]) + struct.pack("<I", 0)
    assert len(system_sid) == 12
    assert len(world_sid) == 12

    # ACCESS_ALLOWED_ACE: AceType(1)=0, AceFlags(1)=2 (CONTAINER_INHERIT_ACE),
    # AceSize(2)=20, Mask(4)=0x000F003F (KEY_ALL_ACCESS), Sid(12)
    ace_sys   = struct.pack("<BBHI", 0, 2, 20, 0x000F003F) + system_sid
    ace_world = struct.pack("<BBHI", 0, 2, 20, 0x000F003F) + world_sid
    acl_bytes = struct.pack("<BBHHH", 2, 0, 8 + len(ace_sys) + len(ace_world), 2, 0) + ace_sys + ace_world
    assert len(acl_bytes) == 48

    # SECURITY_DESCRIPTOR_RELATIVE (20 bytes):
    # Revision=1, Sbz1=0, Control=0x8004 (SE_SELF_RELATIVE | SE_DACL_PRESENT),
    # Owner=20, Group=32, Sacl=0, Dacl=44
    sd_hdr = struct.pack("<BBHIIII", 1, 0, 0x8004, 20, 32, 0, 44)
    sd = sd_hdr + system_sid + system_sid + acl_bytes
    assert len(sd) == 92
    return sd


class HiveBuilder:
    def __init__(self):
        self.cells = bytearray()  # Starts at offset 0x20 inside HBIN (after 32-byte HBIN header)

    @property
    def current_hcell(self) -> int:
        return 0x20 + len(self.cells)

    def alloc_cell(self, payload: bytes) -> int:
        cell_idx = self.current_hcell
        total_len = (4 + len(payload) + 7) & ~7
        if total_len < 8:
            total_len = 8
        pad_len = total_len - 4 - len(payload)
        self.cells += struct.pack("<i", -total_len)
        self.cells += payload
        if pad_len > 0:
            self.cells += b"\x00" * pad_len
        return cell_idx

    def patch_cell(self, cell_idx: int, payload: bytes):
        off = cell_idx - 0x20
        neg_size = struct.unpack_from("<i", self.cells, off)[0]
        alloc_size = -neg_size
        assert 4 + len(payload) <= alloc_size
        self.cells[off + 4 : off + 4 + len(payload)] = payload

    def build(self, root_key: RegKey) -> bytes:
        # Count total keys for security ReferenceCount
        def count_keys(k: RegKey) -> int:
            return 1 + sum(count_keys(c) for c in k.subkeys.values())

        total_keys = count_keys(root_key)
        TIMESTAMP = 0x01C2700000000000  # Fixed valid NT FILETIME (year ~2002)

        # Reserve root key node at HCELL_INDEX 0x20 (required by BaseBlock->RootCell = 0x20)
        root_name_utf16 = root_key.name.encode("utf-16le")
        dummy_root_payload = b"\x00" * (76 + len(root_name_utf16))
        root_cell = self.alloc_cell(dummy_root_payload)
        assert root_cell == 0x20

        # Allocate shared CM_KEY_SECURITY cell right after root
        sd_bytes = build_security_descriptor()
        sec_cell_idx = self.current_hcell
        sec_payload = struct.pack(
            "<HHIIII",
            CM_KEY_SECURITY_SIGNATURE,
            0,
            sec_cell_idx,
            sec_cell_idx,
            total_keys,
            len(sd_bytes),
        ) + sd_bytes
        alloc_sec = self.alloc_cell(sec_payload)
        assert alloc_sec == sec_cell_idx

        def emit_key(k: RegKey, parent_cell: int, preallocated_cell: int = HCELL_NIL) -> int:
            name_bytes = k.name.encode("utf-16le")
            if preallocated_cell != HCELL_NIL:
                my_cell = preallocated_cell
            else:
                my_cell = self.alloc_cell(b"\x00" * (76 + len(name_bytes)))
            k.cell_index = my_cell

            # 1. Emit values
            val_cells = []
            max_val_name_len = 0
            max_val_data_len = 0
            for vname, vtype, vdata in k.values:
                vname_bytes = vname.encode("utf-16le")
                if len(vname_bytes) > max_val_name_len:
                    max_val_name_len = len(vname_bytes)
                if len(vdata) > max_val_data_len:
                    max_val_data_len = len(vdata)

                if len(vdata) == 0:
                    data_len_field = CM_KEY_VALUE_SPECIAL_SIZE
                    data_cell_field = HCELL_NIL
                elif len(vdata) <= 4:
                    data_len_field = len(vdata) | CM_KEY_VALUE_SPECIAL_SIZE
                    data_cell_field = struct.unpack("<I", vdata.ljust(4, b"\x00"))[0]
                else:
                    data_len_field = len(vdata)
                    data_cell_field = self.alloc_cell(vdata)

                vk_payload = struct.pack(
                    "<HHIIIHH",
                    CM_KEY_VALUE_SIGNATURE,
                    len(vname_bytes),
                    data_len_field,
                    data_cell_field,
                    vtype,
                    0,  # Flags (uncompressed UTF-16LE name)
                    0,  # Spare
                ) + vname_bytes
                val_cells.append(self.alloc_cell(vk_payload))

            if val_cells:
                vlist_payload = b"".join(struct.pack("<I", vc) for vc in val_cells)
                vlist_cell = self.alloc_cell(vlist_payload)
            else:
                vlist_cell = HCELL_NIL

            # 2. Emit subkeys sorted case-insensitively by uppercase name
            sorted_children = [
                k.subkeys[up_name] for up_name in sorted(k.subkeys.keys())
            ]
            child_cells = []
            max_subkey_name_len = 0
            for child in sorted_children:
                child_name_len = len(child.name.encode("utf-16le"))
                if child_name_len > max_subkey_name_len:
                    max_subkey_name_len = child_name_len
                c_cell = emit_key(child, my_cell)
                child_cells.append(c_cell)

            if child_cells:
                # CM_KEY_INDEX_LEAF ("li" = 0x696c) works across all NT hive versions
                idx_payload = struct.pack(
                    "<HH", CM_KEY_INDEX_LEAF, len(child_cells)
                ) + b"".join(struct.pack("<I", cc) for cc in child_cells)
                subkeys_list_cell = self.alloc_cell(idx_payload)
            else:
                subkeys_list_cell = HCELL_NIL

            flags = (KEY_HIVE_ENTRY | KEY_NO_DELETE) if k.is_root else 0
            nk_payload = struct.pack(
                "<HHQ15IHH",
                CM_KEY_NODE_SIGNATURE,
                flags,
                TIMESTAMP,
                0,                      # Spare
                parent_cell,            # Parent
                len(child_cells),       # SubKeyCounts[Stable]
                0,                      # SubKeyCounts[Volatile]
                subkeys_list_cell,      # SubKeyLists[Stable]
                HCELL_NIL,              # SubKeyLists[Volatile]
                len(val_cells),         # ValueList.Count
                vlist_cell,             # ValueList.List
                sec_cell_idx,           # Security
                HCELL_NIL,              # Class
                max_subkey_name_len,    # MaxNameLen
                0,                      # MaxClassLen
                max_val_name_len,       # MaxValueNameLen
                max_val_data_len,       # MaxValueDataLen
                0,                      # WorkVar
                len(name_bytes),        # NameLength
                0,                      # ClassLength
            ) + name_bytes

            self.patch_cell(my_cell, nk_payload)
            return my_cell

        emit_key(root_key, HCELL_NIL, preallocated_cell=0x20)

        # Construct single contiguous HBIN aligned to 4096 (0x1000) bytes
        raw_used = 0x20 + len(self.cells)
        bin_size = (raw_used + 0xFFF) & ~0xFFF
        if bin_size - raw_used < 8:
            bin_size += 0x1000

        hbin = bytearray(bin_size)
        struct.pack_into(
            "<IIIiiII",
            hbin,
            0,
            HBIN_SIGNATURE,
            0,          # FileOffset = 0
            bin_size,   # Size
            0,
            0,
            0,
            0,
        )
        hbin[0x20 : 0x20 + len(self.cells)] = self.cells
        if raw_used < bin_size:
            free_rem = bin_size - raw_used
            struct.pack_into("<i", hbin, raw_used, free_rem)

        # Construct 4096-byte HBASE_BLOCK
        base_block = bytearray(0x1000)
        struct.pack_into(
            "<IIIQIIIIIII",
            base_block,
            0,
            HBASE_BLOCK_SIGNATURE,
            1,          # Sequence1
            1,          # Sequence2
            TIMESTAMP,  # TimeStamp
            1,          # Major = HSYS_MAJOR (1)
            3,          # Minor = HSYS_MINOR (3)
            0,          # Type = HFILE_TYPE_PRIMARY (0)
            1,          # Format = HBASE_FORMAT_MEMORY (1)
            0x20,       # RootCell = 0x20
            bin_size,   # Length = total HBINs size
            1,          # Cluster = 1
        )
        fname_bytes = "SYSTEM\x00".encode("utf-16le")
        base_block[0x30 : 0x30 + len(fname_bytes)] = fname_bytes

        # HvpHeaderCheckSum: XOR first 127 ULONGs (0x000..0x1FB)
        csum = 0
        for i in range(127):
            u = struct.unpack_from("<I", base_block, i * 4)[0]
            csum ^= u
        if csum == 0xFFFFFFFF:
            csum = 0xFFFFFFFE
        elif csum == 0:
            csum = 1
        struct.pack_into("<I", base_block, 0x1FC, csum)

        return bytes(base_block) + bytes(hbin)


def verify_hive(hive_bytes: bytes, root_key: RegKey):
    """
    Verifies the generated hive against all checks in:
      - HvpHeaderCheckSum (hivesum.c)
      - HvCheckHive / HvCheckBin (hivechek.c)
      - CmpValidateHiveSecurityDescriptors / SeValidSecurityDescriptor (cmchek2.c / capture.c)
      - CmpCheckRegistry2 / CmpCheckKey / CmpCheckValueList (cmchek.c)
      - CmpFindSubKeyByName binary search (cmindex.c)
    """
    assert len(hive_bytes) >= 0x2000 and (len(hive_bytes) & 0xFFF) == 0
    sig, seq1, seq2, ts, major, minor, htype, hfmt, root_cell, length, cluster = struct.unpack_from(
        "<IIIQIIIIIII", hive_bytes, 0
    )
    assert sig == HBASE_BLOCK_SIGNATURE
    assert seq1 == seq2 == 1
    assert major == 1 and minor == 3
    assert htype == 0 and hfmt == 1
    assert root_cell == 0x20
    assert length == len(hive_bytes) - 0x1000

    # Checksum check
    csum = 0
    for i in range(127):
        csum ^= struct.unpack_from("<I", hive_bytes, i * 4)[0]
    if csum == 0xFFFFFFFF:
        csum = 0xFFFFFFFE
    elif csum == 0:
        csum = 1
    stored_csum = struct.unpack_from("<I", hive_bytes, 0x1FC)[0]
    assert csum == stored_csum, f"Checksum mismatch: {csum:#x} != {stored_csum:#x}"

    # HBIN check (HvCheckBin)
    bins_buf = memoryview(hive_bytes)[0x1000:]
    b_sig, b_off, b_size = struct.unpack_from("<III", bins_buf, 0)
    assert b_sig == HBIN_SIGNATURE and b_off == 0 and b_size == length

    p = 0x20
    allocated = 0
    freespace = 0
    allocated_cells = {}
    while p < b_size:
        c_size = struct.unpack_from("<i", bins_buf, p)[0]
        if c_size < 0:
            actual = -c_size
            assert actual >= 8 and (actual & 7) == 0
            assert p + actual <= b_size
            allocated += actual
            allocated_cells[p] = bytes(bins_buf[p + 4 : p + actual])
            p += actual
        else:
            assert c_size > 0 and (c_size & 7) == 0
            assert p + c_size <= b_size
            freespace += c_size
            p += c_size
    assert allocated + freespace + 0x20 == b_size

    def get_cell(cell_idx: int) -> bytes:
        assert cell_idx in allocated_cells, f"Unallocated cell {cell_idx:#x}"
        return allocated_cells[cell_idx]

    # Verify security cell
    root_data = get_cell(root_cell)
    sec_cell = struct.unpack_from("<I", root_data, 0x2C)[0]
    sec_data = get_cell(sec_cell)
    sec_sig, _, flink, blink, refcnt, sd_len = struct.unpack_from("<HHIIII", sec_data, 0)
    assert sec_sig == CM_KEY_SECURITY_SIGNATURE
    assert flink == sec_cell and blink == sec_cell and refcnt > 0
    sd = sec_data[20 : 20 + sd_len]
    rev, sbz1, ctrl, owner, group, sacl, dacl = struct.unpack_from("<BBHIIII", sd, 0)
    assert rev == 1 and (ctrl & 0x8000) != 0 and owner != 0

    # Verify tree and CmpFindSubKeyInLeaf binary search on every key
    def check_node(cell_idx: int, expected_parent: int):
        data = get_cell(cell_idx)
        (
            nk_sig,
            flags,
            last_write,
            spare,
            parent,
            subcnt_s,
            subcnt_v,
            sublist_s,
            sublist_v,
            val_cnt,
            val_list,
            sec,
            cls,
            max_name,
            max_cls,
            max_vname,
            max_vdata,
            workvar,
            name_len,
            cls_len,
        ) = struct.unpack_from("<HHQ15IHH", data, 0)
        assert nk_sig == CM_KEY_NODE_SIGNATURE
        assert parent == expected_parent
        assert name_len > 0 and 76 + name_len <= len(data)
        assert sec == sec_cell
        assert subcnt_v == 0 and sublist_v == HCELL_NIL

        # Check values
        if val_cnt > 0:
            vlist_bytes = get_cell(val_list)
            assert val_cnt * 4 <= len(vlist_bytes)
            for i in range(val_cnt):
                vcell = struct.unpack_from("<I", vlist_bytes, i * 4)[0]
                vdata = get_cell(vcell)
                vk_sig, vn_len, vd_len, vd_cell, vtype, vflags, vspare = struct.unpack_from(
                    "<HHIIIHH", vdata, 0
                )
                assert vk_sig == CM_KEY_VALUE_SIGNATURE
                assert 20 + vn_len <= len(vdata)
                if vd_len < CM_KEY_VALUE_SPECIAL_SIZE and vd_len > 0:
                    raw_val = get_cell(vd_cell)
                    assert len(raw_val) >= vd_len

        # Check subkeys and test CmpFindSubKeyInLeaf binary search
        if subcnt_s > 0:
            idx_bytes = get_cell(sublist_s)
            idx_sig, idx_cnt = struct.unpack_from("<HH", idx_bytes, 0)
            assert idx_sig == CM_KEY_INDEX_LEAF and idx_cnt == subcnt_s
            child_names = []
            for i in range(idx_cnt):
                ccell = struct.unpack_from("<I", idx_bytes, 4 + i * 4)[0]
                cdata = get_cell(ccell)
                cn_len = struct.unpack_from("<H", cdata, 72)[0]
                cname = cdata[76 : 76 + cn_len].decode("utf-16le")
                child_names.append((cname, ccell))
                check_node(ccell, cell_idx)

            # Verify sorted order and binary search (CmpFindSubKeyInLeaf)
            for target_name, target_cell in child_names:
                high = idx_cnt - 1
                low = 0
                can = high // 2
                found = HCELL_NIL
                while True:
                    cand_name, cand_cell = child_names[can]
                    t_up = target_name.upper()
                    c_up = cand_name.upper()
                    if t_up == c_up:
                        found = cand_cell
                        break
                    elif t_up < c_up:
                        high = can
                    else:
                        low = can
                    if (high - low) <= 1:
                        break
                    can = ((high - low) // 2) + low
                if found == HCELL_NIL:
                    if target_name.upper() == child_names[low][0].upper():
                        found = child_names[low][1]
                    elif target_name.upper() == child_names[high][0].upper():
                        found = child_names[high][1]
                assert found == target_cell, f"Binary search failed for {target_name}"

    check_node(root_cell, HCELL_NIL)


def populate_system_hive() -> RegKey:
    root = RegKey("$$$PROTO.HIV", is_root=True)

    # 1. Select
    sel = root.sub("Select")
    sel.val("Current", reg_dword(1))
    sel.val("Default", reg_dword(1))
    sel.val("LastKnownGood", reg_dword(1))
    sel.val("Failed", reg_dword(0))

    # 2. Setup
    setup = root.sub("Setup")
    setup.val("SystemSetupInProgress", reg_dword(0))
    setup.val("SetupType", reg_dword(0))
    setup.val("CmdLine", reg_sz(""))
    setup.val("OsLoaderPath", reg_sz("\\"))
    setup.val("SystemPartition", reg_sz("\\Device\\Harddisk0\\Partition1"))
    setup.val("SystemPrefix", reg_binary(b"\xd5\x03\x00\x00\x00\x00\x00\x00"))

    # 3. ControlSet001\Control
    ctrl = root.sub("ControlSet001\\Control")
    ctrl.val("CurrentUser", reg_sz("USERNAME"))
    ctrl.val("SystemStartOptions", reg_sz(""))
    ctrl.val("WaitToKillServiceTimeout", reg_sz("20000"))

    # 3a. Control\Arbiters (from Source\XPSP1\NT\base\ntsetup\hives\setupreg.ini)
    # Required by ArbInitializeArbiterInstance in ntoskrnl (IopPortInitialize,
    # IopMemInitialize, IopDmaInitialize, IopIrqInitialize, IopBusNumberInitialize)
    # and pci.sys!
    alloc_order = ctrl.sub("Arbiters\\AllocationOrder")
    alloc_order.val("Pci", reg_resource_requirements(
        0x00000248, 0, 0, 0, 0, 0, 0, 1, 0x00010001, 0x00000011,
        0x0100, 0, 0, 0, 0x00010000, 0, 0xffffffff, 0,
        0x0108, 0, 0, 0, 0x00000500, 0, 0x0000ffff, 0,
        0x0108, 0, 0, 0, 0x00000140, 0, 0x0000017F, 0,
        0x0108, 0, 0, 0, 0x00000200, 0, 0x000002FF, 0,
        0x0108, 0, 0, 0, 0x00000300, 0, 0x0000036F, 0,
        0x0108, 0, 0, 0, 0x00000378, 0, 0x0000037A, 0,
        0x0108, 0, 0, 0, 0x000002E8, 0, 0x000002FF, 0,
        0x0108, 0, 0, 0, 0x000001F0, 0, 0x000001F8, 0,
        0x0108, 0, 0, 0, 0x000003B0, 0, 0x000003CF, 0,
        0x0108, 0, 0, 0, 0x000003E8, 0, 0x000003FF, 0,
        0x0108, 0, 0, 0, 0x000001CE, 0, 0x000001CF, 0,
        0x0108, 0, 0, 0, 0x00000100, 0, 0x000003FF, 0,
        0x0300, 0, 0, 0, 0x00100000, 0, 0xFFFFFFFF, 0,
        0x0308, 0, 0, 0, 0x000F0000, 0, 0x000FFFFF, 0,
        0x0308, 0, 0, 0, 0x00080000, 0, 0x000BFFFF, 0,
        0x0308, 0, 0, 0, 0x00080000, 0, 0x000FFFFF, 0,
        0x0308, 0, 0, 0, 0x00080000, 0, 0xFFBFFFFF, 0,
    ))
    alloc_order.val("Root", reg_resource_requirements(
        0x00000468, 0, 0, 0, 0, 0, 0, 1, 0x00010001, 0x00000022,
        0x0100, 0, 0, 0, 0x0500, 0, 0xFFFF, 0,
        0x0108, 0, 0, 0, 0x0140, 0, 0x017F, 0,
        0x0108, 0, 0, 0, 0x0200, 0, 0x02FF, 0,
        0x0108, 0, 0, 0, 0x0300, 0, 0x036F, 0,
        0x0108, 0, 0, 0, 0x0378, 0, 0x037A, 0,
        0x0108, 0, 0, 0, 0x02E8, 0, 0x02FF, 0,
        0x0108, 0, 0, 0, 0x01F0, 0, 0x01F8, 0,
        0x0108, 0, 0, 0, 0x03B0, 0, 0x03CF, 0,
        0x0108, 0, 0, 0, 0x03E8, 0, 0x03FF, 0,
        0x0108, 0, 0, 0, 0x01CE, 0, 0x01CF, 0,
        0x0108, 0, 0, 0, 0x0100, 0, 0x03FF, 0,
        0x0208, 0, 0x09, 0x09, 0, 0, 0, 0,
        0x0208, 0, 0x08, 0x08, 0, 0, 0, 0,
        0x0208, 0, 0x07, 0x07, 0, 0, 0, 0,
        0x0208, 0, 0x0B, 0x0B, 0, 0, 0, 0,
        0x0208, 0, 0x0A, 0x0A, 0, 0, 0, 0,
        0x0208, 0, 0x02, 0x02, 0, 0, 0, 0,
        0x0200, 0, 0x03, 0x03, 0, 0, 0, 0,
        0x0208, 0, 0x05, 0x05, 0, 0, 0, 0,
        0x0208, 0, 0x04, 0x04, 0, 0, 0, 0,
        0x0208, 0, 0x0F, 0x0F, 0, 0, 0, 0,
        0x0208, 0, 0x0D, 0x0D, 0, 0, 0, 0,
        0x0208, 0, 0x0E, 0x0E, 0, 0, 0, 0,
        0x0208, 0, 0x06, 0x06, 0, 0, 0, 0,
        0x0208, 0, 0x0C, 0x0C, 0, 0, 0, 0,
        0x0208, 0, 0x01, 0x01, 0, 0, 0, 0,
        0x0300, 0, 0, 0, 0x00100000, 0, 0xFFFFFFFF, 0,
        0x0308, 0, 0, 0, 0x000F0000, 0, 0x000FFFFF, 0,
        0x0308, 0, 0, 0, 0x00080000, 0, 0x000BFFFF, 0,
        0x0308, 0, 0, 0, 0x00080000, 0, 0x000FFFFF, 0,
        0x0308, 0, 0, 0, 0x00080000, 0, 0xFFBFFFFF, 0,
        0x0400, 0, 0x06, 0x0F, 0, 0, 0, 0,
        0x0408, 0, 0x03, 0x04, 0, 0, 0, 0,
        0x0408, 0, 0x00, 0x0F, 0, 0, 0, 0,
    ))

    res_res = ctrl.sub("Arbiters\\ReservedResources")
    res_res.val("PCStandard", reg_resource_requirements(
        0x00000108, 0, 0, 0, 0, 0, 0, 1, 0x00010001, 0x00000007,
        0x0100, 0, 0, 0, 0x02F8, 0, 0x02FF, 0,
        0x0108, 0, 0, 0, 0x03B0, 0, 0x03BB, 0,
        0x0108, 0, 0, 0, 0x03BC, 0, 0x03BE, 0,
        0x0108, 0, 0, 0, 0x03C0, 0, 0x03DF, 0,
        0x0108, 0, 0, 0, 0x03F8, 0, 0x03FF, 0,
        0x0300, 0, 0, 0, 0x000A0000, 0, 0x000BFFFF, 0,
        0x0308, 0, 0, 0, 0xFFF00000, 0, 0xFFFFFFFF, 0,
    ))
    res_res.val("Root", reg_sz("PCStandard"))
    res_res.val("Pci", reg_sz("PCStandard"))

    # 3b. Control\SystemResources
    bus_vals = ctrl.sub("SystemResources\\BusValues")
    for bname, b0, b1 in [
        ("Internal", 0, 0),
        ("Isa", 1, 0),
        ("Eisa", 2, 1),
        ("MCA", 3, 1),
        ("TurboChannel", 4, 0),
        ("PCI", 5, 1),
        ("VME", 6, 0),
        ("NuBus", 7, 0),
        ("PCMCIA", 8, 1),
        ("CBus", 9, 0),
        ("MPI", 10, 0),
        ("MPSA", 11, 0),
    ]:
        bus_vals.val(bname, reg_binary_ulongs(b0, b1))

    sys_assign = ctrl.sub("SystemResources\\AssignmentOrdering")
    sys_assign.val("Isa", reg_sz("PCFlat"))
    sys_assign.val("Eisa", reg_sz("PCFlat"))
    sys_assign.val("MCA", reg_sz("PCFlat"))
    sys_assign.val("PCMCIA", reg_sz("PCFlat"))
    sys_assign.val("PCFlat", reg_resource_requirements(
        0x000004A8, 0, 0, 0, 0, 0, 0, 1, 0x00010001, 0x00000024,
        0x0100, 0, 0, 0, 0x0500, 0, 0xFFFF, 0,
        0x0108, 0, 0, 0, 0x0140, 0, 0x017F, 0,
        0x0108, 0, 0, 0, 0x0200, 0, 0x02FF, 0,
        0x0108, 0, 0, 0, 0x0300, 0, 0x036F, 0,
        0x0108, 0, 0, 0, 0x0378, 0, 0x037A, 0,
        0x0108, 0, 0, 0, 0x02E8, 0, 0x02FF, 0,
        0x0108, 0, 0, 0, 0x01F0, 0, 0x01F8, 0,
        0x0108, 0, 0, 0, 0x03B0, 0, 0x03CF, 0,
        0x0108, 0, 0, 0, 0x03E8, 0, 0x03FF, 0,
        0x0108, 0, 0, 0, 0x01CE, 0, 0x01CF, 0,
        0x0108, 0, 0, 0, 0x0100, 0, 0x03FF, 0,
        0x0200, 0, 0x0F, 0x0F, 0, 0, 0, 0,
        0x0208, 0, 0x0D, 0x0D, 0, 0, 0, 0,
        0x0208, 0, 0x0C, 0x0C, 0, 0, 0, 0,
        0x0208, 0, 0x09, 0x09, 0, 0, 0, 0,
        0x0208, 0, 0x08, 0x08, 0, 0, 0, 0,
        0x0208, 0, 0x07, 0x07, 0, 0, 0, 0,
        0x0208, 0, 0x0B, 0x0B, 0, 0, 0, 0,
        0x0208, 0, 0x0A, 0x0A, 0, 0, 0, 0,
        0x0208, 0, 0x02, 0x02, 0, 0, 0, 0,
        0x0208, 0, 0x05, 0x05, 0, 0, 0, 0,
        0x0208, 0, 0x03, 0x03, 0, 0, 0, 0,
        0x0208, 0, 0x04, 0x04, 0, 0, 0, 0,
        0x0208, 0, 0x0E, 0x0E, 0, 0, 0, 0,
        0x0208, 0, 0x06, 0x06, 0, 0, 0, 0,
        0x0208, 0, 0x0C, 0x0C, 0, 0, 0, 0,
        0x0208, 0, 0x01, 0x01, 0, 0, 0, 0,
        0x0208, 0, 0x00, 0x0F, 0, 0, 0, 0,
        0x0300, 0, 0, 0, 0x00100000, 0, 0xFFFFFFFF, 0,
        0x0308, 0, 0, 0, 0x000F0000, 0, 0x000FFFFF, 0,
        0x0308, 0, 0, 0, 0x00080000, 0, 0x000BFFFF, 0,
        0x0308, 0, 0, 0, 0x00080000, 0, 0x000FFFFF, 0,
        0x0308, 0, 0, 0, 0x00080000, 0, 0xFFBFFFFF, 0,
        0x0400, 0, 0x06, 0x0F, 0, 0, 0, 0,
        0x0408, 0, 0x03, 0x04, 0, 0, 0, 0,
        0x0408, 0, 0x00, 0x0F, 0, 0, 0, 0,
    ))
    sys_assign.val("PCI", reg_resource_requirements(
        0x00000128, 0, 0, 0, 0, 0, 0, 1, 0x00010001, 0x00000008,
        0x0100, 0, 0, 0, 0x0500, 0, 0xFFFF, 0,
        0x0200, 0, 0x00, 0xFF, 0, 0, 0, 0,
        0x0300, 0, 0, 0, 0x00100000, 0, 0xFFFFFFFF, 0,
        0x0308, 0, 0, 0, 0x000F0000, 0, 0x000FFFFF, 0,
        0x0308, 0, 0, 0, 0x00080000, 0, 0x000BFFFF, 0,
        0x0308, 0, 0, 0, 0x00080000, 0, 0x000FFFFF, 0,
        0x0308, 0, 0, 0, 0x00080000, 0, 0xFFBFFFFF, 0,
        0x0400, 0, 0x06, 0xFF, 0, 0, 0, 0,
    ))
    ctrl.sub("SystemResources\\ReservedResources")

    # 3c. Session Manager
    sm = ctrl.sub("Session Manager")
    sm.val("BootExecute", reg_multi_sz([]))
    sm.val("ObjectDirectories", reg_multi_sz(["\\Windows", "\\RPC Control"]))
    sm.val("ProtectionMode", reg_dword(0))
    sm.val("GlobalFlag", reg_dword(0))
    sm.val("NumberOfInitialSessions", reg_dword(2))

    dosdev = sm.sub("DOS Devices")
    dosdev.val("AUX", reg_sz("\\DosDevices\\COM1"))
    dosdev.val("MAILSLOT", reg_sz("\\Device\\MailSlot"))
    dosdev.val("NUL", reg_sz("\\Device\\Null"))
    dosdev.val("PIPE", reg_sz("\\Device\\NamedPipe"))
    dosdev.val("PRN", reg_sz("\\DosDevices\\LPT1"))
    dosdev.val("UNC", reg_sz("\\Device\\Mup"))

    mm = sm.sub("Memory Management")
    mm.val("PagingFiles", reg_multi_sz([]))
    mm.val("DisablePagingExecutive", reg_dword(1))
    mm.val("LargeSystemCache", reg_dword(0))
    mm.val("PagedPoolSize", reg_dword(0))
    mm.val("NonPagedPoolSize", reg_dword(0))

    env = sm.sub("Environment")
    env.val("ComSpec", reg_expand_sz("\\SystemRoot\\system32\\smss.exe"))
    env.val("Path", reg_expand_sz("\\bin;\\SystemRoot\\system32;\\SystemRoot"))
    env.val("PATHEXT", reg_sz(".EXE;.ELF;.SH;.BAT;.CMD"))
    env.val("OS", reg_sz("Windows_NT"))
    env.val("PROCESSOR_ARCHITECTURE", reg_sz("x86"))
    env.val("TEMP", reg_expand_sz("\\tmp"))
    env.val("TMP", reg_expand_sz("\\tmp"))

    kdll = sm.sub("KnownDLLs")
    kdll.val("DllDirectory", reg_expand_sz("%SystemRoot%\\system32"))

    subsys = sm.sub("SubSystems")
    subsys.val("Required", reg_multi_sz([]))
    subsys.val("Optional", reg_multi_sz([]))

    sm.sub("Executive")
    sm.sub("FileRenameOperations")
    sm.sub("Power")
    sm.sub("WPA")

    # 3d. NLS (CodePage and Language)
    cp = ctrl.sub("NLS\\CodePage")
    cp.val("1252", reg_sz("c_1252.nls"))
    cp.val("437", reg_sz("c_437.nls"))
    cp.val("10000", reg_sz("c_10000.nls"))
    cp.val("ACP", reg_sz("1252"))
    cp.val("OEMCP", reg_sz("437"))
    cp.val("MACCP", reg_sz("10000"))

    lang = ctrl.sub("NLS\\Language")
    lang.val("0409", reg_sz("l_intl.nls"))
    lang.val("Default", reg_sz("0409"))
    lang.val("InstallLanguage", reg_sz("0409"))

    loc = ctrl.sub("NLS\\Locale")
    loc.val("00000409", reg_sz("1"))

    # 3e. ProductOptions, Windows, CrashControl, FileSystem, TimeZone, Priority, Lsa
    po = ctrl.sub("ProductOptions")
    po.val("ProductType", reg_sz("WinNT"))
    po.val("ProductSuite", reg_multi_sz([]))

    win = ctrl.sub("Windows")
    win.val("Directory", reg_expand_sz("%SystemRoot%"))
    win.val("SystemDirectory", reg_expand_sz("%SystemRoot%\\system32"))
    win.val("NoPopUpsOnBoot", reg_dword(1))
    win.val("ErrorMode", reg_dword(2))
    win.val("CSDVersion", reg_dword(0x100))

    cc = ctrl.sub("CrashControl")
    cc.val("AutoReboot", reg_dword(0))
    cc.val("CrashDumpEnabled", reg_dword(0))
    cc.val("LogEvent", reg_dword(0))
    cc.val("SendAlert", reg_dword(0))

    fs = ctrl.sub("FileSystem")
    fs.val("NtfsDisable8dot3NameCreation", reg_dword(0))
    fs.val("Win31FileSystem", reg_dword(0))
    fs.val("Win95TruncatedExtensions", reg_dword(1))

    tz = ctrl.sub("TimeZoneInformation")
    tz.val("ActiveTimeBias", reg_dword(0))
    tz.val("Bias", reg_dword(0))
    tz.val("StandardName", reg_sz("UTC"))
    tz.val("StandardBias", reg_dword(0))
    tz.val("DaylightName", reg_sz("UTC"))
    tz.val("DaylightBias", reg_dword(0))

    pc = ctrl.sub("PriorityControl")
    pc.val("Win32PrioritySeparation", reg_dword(2))

    lsa = ctrl.sub("Lsa")
    lsa.val("Authentication Packages", reg_multi_sz([]))
    lsa.val("Notification Packages", reg_multi_sz([]))
    lsa.val("Security Packages", reg_multi_sz([]))
    lsa.val("AuditBaseObjects", reg_dword(0))
    lsa.val("FullPrivilegeAuditing", reg_binary(b"\x00"))

    gd = ctrl.sub("GraphicsDrivers")
    gd.val("DisableUSWC", reg_dword(0))

    sb = ctrl.sub("SafeBoot")
    sb.val("AlternateShell", reg_sz("smss.exe"))
    sb.sub("Minimal")
    sb.sub("Network")

    idcfg = ctrl.sub("IDConfigDB")
    idcfg.val("CurrentConfig", reg_dword(1))
    idcfg.val("UserWaitInterval", reg_dword(30))
    hwp0 = idcfg.sub("Hardware Profiles\\0000")
    hwp0.val("PreferenceOrder", reg_dword(0xFFFFFFFF))
    hwp0.val("Pristine", reg_dword(1))
    hwp0.val("Aliasable", reg_dword(0))
    hwp1 = idcfg.sub("Hardware Profiles\\0001")
    hwp1.val("PreferenceOrder", reg_dword(0))
    hwp1.val("FriendlyName", reg_sz("Default"))
    hwp1.val("Aliasable", reg_dword(0))

    pnp = ctrl.sub("PnP")
    pnp_pir = pnp.sub("PciIrqRouting")
    pnp_pir.val("Options", reg_dword(0x0F))
    pnp_pir.sub("IrqRoutingTables")
    pnp_pir.sub("IrqMiniports")

    ctrl.sub("BiosInfo")
    ctrl.sub("HAL")
    ctrl.sub("WMI")
    ctrl.sub("COM Name Arbiter")
    ctrl.sub("DeviceClasses")
    cn = ctrl.sub("ComputerName\\ComputerName")
    cn.val("ComputerName", reg_sz("NTBOX"))
    acn = ctrl.sub("ComputerName\\ActiveComputerName")
    acn.val("ComputerName", reg_sz("NTBOX"))

    # 3f. ServiceGroupOrder & GroupOrderList
    sgo = ctrl.sub("ServiceGroupOrder")
    sgo.val("List", reg_multi_sz([
        "System Reserved",
        "Boot Bus Extender",
        "System Bus Extender",
        "SCSI Miniport",
        "Port",
        "Primary Disk",
        "SCSI Class",
        "SCSI CDROM Class",
        "FSFilter Infrastructure",
        "Filter",
        "Boot File System",
        "Base",
        "Keyboard Port",
        "Keyboard Class",
        "Pointer Port",
        "Pointer Class",
        "Input Device Support",
        "Extended Base",
        "File System",
    ]))

    gol = ctrl.sub("GroupOrderList")
    gol.val("Boot Bus Extender", reg_binary_ulongs(5, 1, 2, 3, 5, 4))
    gol.val("System Bus Extender", reg_binary_ulongs(11, 3, 4, 1, 8, 9, 10, 11, 12, 13, 14, 15))
    gol.val("SCSI Miniport", reg_binary_ulongs(2, 1, 2))
    gol.val("Port", reg_binary_ulongs(2, 1, 2))
    gol.val("Primary Disk", reg_binary_ulongs(1, 1))
    gol.val("SCSI Class", reg_binary_ulongs(2, 1, 2))
    gol.val("Base", reg_binary_ulongs(2, 1, 2))
    gol.val("Keyboard Port", reg_binary_ulongs(1, 1))
    gol.val("Keyboard Class", reg_binary_ulongs(1, 1))
    gol.val("Input Device Support", reg_binary_ulongs(7, 1, 2, 3, 4, 5, 6, 7))

    # 3g. Control\Class (PnP Device Classes and UpperFilters)
    cls_root = ctrl.sub("Class")
    c_cdrom = cls_root.sub("{4D36E965-E325-11CE-BFC1-08002BE10318}")
    c_cdrom.val("Class", reg_sz("CDROM"))
    c_disk = cls_root.sub("{4D36E967-E325-11CE-BFC1-08002BE10318}")
    c_disk.val("Class", reg_sz("DiskDrive"))
    c_disk.val("UpperFilters", reg_multi_sz(["PartMgr"]))
    c_hdc = cls_root.sub("{4D36E96A-E325-11CE-BFC1-08002BE10318}")
    c_hdc.val("Class", reg_sz("hdc"))
    c_kbd = cls_root.sub("{4D36E96B-E325-11CE-BFC1-08002BE10318}")
    c_kbd.val("Class", reg_sz("Keyboard"))
    c_kbd.val("UpperFilters", reg_multi_sz(["kbdclass"]))
    c_ports = cls_root.sub("{4D36E978-E325-11CE-BFC1-08002BE10318}")
    c_ports.val("Class", reg_sz("Ports"))
    c_sys = cls_root.sub("{4D36E97D-E325-11CE-BFC1-08002BE10318}")
    c_sys.val("Class", reg_sz("System"))
    c_vol = cls_root.sub("{71A27CDD-812A-11D0-BEC7-08002BE2092F}")
    c_vol.val("Class", reg_sz("Volume"))

    # 3h. Control\CriticalDeviceDatabase
    cddb = ctrl.sub("CriticalDeviceDatabase")
    for dev_id, svc, guid in [
        ("*pnp0a03", "pci", "{4D36E97D-E325-11CE-BFC1-08002BE10318}"),
        ("*pnp0a00", "isapnp", "{4D36E97D-E325-11CE-BFC1-08002BE10318}"),
        ("pci#cc_0604", "pci", "{4D36E97D-E325-11CE-BFC1-08002BE10318}"),
        ("pci#cc_0601", "isapnp", "{4D36E97D-E325-11CE-BFC1-08002BE10318}"),
        ("pci#cc_0101", "pciide", "{4D36E96A-E325-11CE-BFC1-08002BE10318}"),
        ("pci#ven_8086&dev_7010", "intelide", "{4D36E96A-E325-11CE-BFC1-08002BE10318}"),
        ("pci#ven_8086&dev_7111", "intelide", "{4D36E96A-E325-11CE-BFC1-08002BE10318}"),
        ("*pnp0600", "atapi", "{4D36E96A-E325-11CE-BFC1-08002BE10318}"),
        ("primary_ide_channel", "atapi", "{4D36E96A-E325-11CE-BFC1-08002BE10318}"),
        ("secondary_ide_channel", "atapi", "{4D36E96A-E325-11CE-BFC1-08002BE10318}"),
        ("gendisk", "disk", "{4D36E967-E325-11CE-BFC1-08002BE10318}"),
        ("*pnp0303", "i8042prt", "{4D36E96B-E325-11CE-BFC1-08002BE10318}"),
        ("*pnp030b", "i8042prt", "{4D36E96B-E325-11CE-BFC1-08002BE10318}"),
        ("ps2_keyboard", "i8042prt", "{4D36E96B-E325-11CE-BFC1-08002BE10318}"),
        ("*pnp0501", "serial", "{4D36E978-E325-11CE-BFC1-08002BE10318}"),
        ("*pnp0500", "serial", "{4D36E978-E325-11CE-BFC1-08002BE10318}"),
        ("ramdisk", "ramdisk", "{4D36E967-E325-11CE-BFC1-08002BE10318}"),
    ]:
        dk = cddb.sub(dev_id)
        dk.val("Service", reg_sz(svc))
        dk.val("ClassGUID", reg_sz(guid))

    # 4. ControlSet001\Enum
    enum_root = root.sub("ControlSet001\\Enum")
    htree = enum_root.sub("HTREE\\ROOT\\0")
    htree.val("Capabilities", reg_dword(0))
    rd_dev = enum_root.sub("Root\\ramdisk\\0000")
    rd_dev.val("Service", reg_sz("ramdisk"))
    rd_dev.val("Class", reg_sz("DiskDrive"))
    rd_dev.val("ClassGUID", reg_sz("{4D36E967-E325-11CE-BFC1-08002BE10318}"))
    rd_dev.val("ConfigFlags", reg_dword(0))
    rd_dev.val("HardwareID", reg_multi_sz(["ramdisk"]))

    # 5. ControlSet001\Hardware Profiles
    hp = root.sub("ControlSet001\\Hardware Profiles")
    hp.sub("0000\\System\\CurrentControlSet\\Control")
    hp.sub("0000\\System\\CurrentControlSet\\Services")
    hp.sub("0000\\Software")
    hp.sub("0001\\System\\CurrentControlSet\\Control")
    hp.sub("0001\\System\\CurrentControlSet\\Services")
    hp.sub("Current\\System\\CurrentControlSet\\Control")
    hp.sub("Current\\System\\CurrentControlSet\\Services")

    # 6. ControlSet001\Services
    svcs = root.sub("ControlSet001\\Services")

    def add_svc(name, stype, start, err, group=None, tag=None, img=None):
        sk = svcs.sub(name)
        sk.val("Type", reg_dword(stype))
        sk.val("Start", reg_dword(start))
        sk.val("ErrorControl", reg_dword(err))
        if group is not None:
            sk.val("Group", reg_sz(group))
        if tag is not None:
            sk.val("Tag", reg_dword(tag))
        if img is not None:
            sk.val("ImagePath", reg_expand_sz(img))
        return sk

    s_pci = add_svc("pci", 1, 0, 1, "Boot Bus Extender", 2, "system32\\drivers\\pci.sys")
    s_pci_p = s_pci.sub("Parameters")
    s_pci_p.val("80867010", reg_binary_ulongs(4, 0))
    s_pci_p.val("80867113", reg_binary_ulongs(8, 0))
    s_pci_p.val("8086122E", reg_binary_ulongs(0x80000, 0))
    s_pci_p.val("80867000", reg_binary_ulongs(0x80000, 0))
    s_pci_p.val("80867110", reg_binary_ulongs(0x80000, 0))

    s_isa = add_svc("isapnp", 1, 0, 1, "Boot Bus Extender", 3, "system32\\drivers\\isapnp.sys")
    s_isa.sub("Parameters")

    add_svc("mountmgr", 1, 0, 1, "System Bus Extender", 8, "system32\\drivers\\mountmgr.sys")
    add_svc("partmgr", 1, 0, 1, "System Bus Extender", 10, "system32\\drivers\\partmgr.sys")
    s_ramdisk = add_svc("ramdisk", 1, 0, 1, "Boot Bus Extender", 4, "system32\\drivers\\ramdisk.sys")
    s_ramdisk_p = s_ramdisk.sub("Parameters")
    s_ramdisk_p.val("ReportDetectedDevice", reg_dword(1))
    add_svc("pciide", 1, 0, 1, "System Bus Extender", 3, "system32\\drivers\\pciide.sys")
    add_svc("intelide", 1, 0, 1, "System Bus Extender", 4, "system32\\drivers\\intelide.sys")
    add_svc("pciidex", 1, 0, 1, "System Bus Extender", 5, "system32\\drivers\\pciidex.sys")

    s_atapi = add_svc("atapi", 1, 0, 1, "SCSI Miniport", 1, "system32\\drivers\\atapi.sys")
    s_atapi_p = s_atapi.sub("Parameters")
    s_atapi_p.val("LegacyDetection", reg_dword(1))

    add_svc("disk", 1, 0, 1, "SCSI Class", 1, "system32\\drivers\\disk.sys")
    add_svc("classpnp", 1, 0, 1, "SCSI Class", 2, "system32\\drivers\\classpnp.sys")
    add_svc("fastfat", 2, 0, 1, "Boot File System", None, "system32\\drivers\\fastfat.sys")
    add_svc("npfs", 2, 1, 1, "File System", None, "system32\\drivers\\npfs.sys")

    s_rawkbd = add_svc("rawkbd", 1, 0, 1, "Keyboard Port", 1, "system32\\drivers\\rawkbd.sys")

    s_i8042 = add_svc("i8042prt", 1, 4, 1, "Keyboard Port", 1, "system32\\drivers\\i8042prt.sys")
    s_i8042_p = s_i8042.sub("Parameters")
    s_i8042_p.val("LayerDriver JPN", reg_sz("kbd101.dll"))
    s_i8042_p.val("LayerDriver KOR", reg_sz("kbd101a.dll"))
    s_i8042_p.val("EnableWheelDetection", reg_dword(0))

    s_kbd = add_svc("kbdclass", 1, 4, 1, "Keyboard Class", 1, "system32\\drivers\\kbdclass.sys")
    s_kbd_p = s_kbd.sub("Parameters")
    s_kbd_p.val("ConnectMultiplePorts", reg_dword(1))
    s_kbd_p.val("KeyboardDeviceBaseName", reg_sz("KeyboardClass"))

    s_ser = add_svc("serial", 1, 4, 1, "Extended Base", 1, "system32\\drivers\\serial.sys")
    s_ser_p = s_ser.sub("Parameters")
    s_ser_p.val("ForceFifoEnable", reg_dword(1))

    add_svc("serenum", 1, 1, 1, "Extended Base", 2, "system32\\drivers\\serenum.sys")
    add_svc("null", 1, 1, 1, "Base", 1, "system32\\drivers\\null.sys")
    add_svc("beep", 1, 1, 1, "Base", 2, "system32\\drivers\\beep.sys")

    s_evt = add_svc("EventLog", 16, 4, 1)
    s_evt.sub("System")
    s_evt.sub("Application")
    s_evt.sub("Security")

    return root


def main():
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "SYSTEM")
    if len(sys.argv) > 1:
        out_path = os.path.abspath(sys.argv[1])

    root = populate_system_hive()
    builder = HiveBuilder()
    hive_bytes = builder.build(root)
    verify_hive(hive_bytes, root)

    with open(out_path, "wb") as f:
        f.write(hive_bytes)
    print(f"[mkhive] Successfully generated and verified SYSTEM hive: {out_path} ({len(hive_bytes)} bytes)")


if __name__ == "__main__":
    main()
