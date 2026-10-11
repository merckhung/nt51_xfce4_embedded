#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
minimal_rootfs/musl/gen_headers.py
Generate bits/alltypes.h, bits/syscall.h, and copy arch-specific headers for i386.
"""

import os
import re
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ARCH_DIR = os.path.join(BASE_DIR, "arch", "i386")
INC_DIR = os.path.join(BASE_DIR, "include")
BITS_DIR = os.path.join(INC_DIR, "bits")

os.makedirs(BITS_DIR, exist_ok=True)

# 1. Copy arch/generic/bits/*.h first, then overlay arch/i386/bits/*.h
generic_bits = os.path.join(BASE_DIR, "arch", "generic", "bits")
if os.path.exists(generic_bits):
    for f in os.listdir(generic_bits):
        if f.endswith(".h") and not f.endswith(".in"):
            src = os.path.join(generic_bits, f)
            dst = os.path.join(BITS_DIR, f)
            shutil.copy2(src, dst)

arch_bits = os.path.join(ARCH_DIR, "bits")
for f in os.listdir(arch_bits):
    if f.endswith(".h") and not f.endswith(".in"):
        src = os.path.join(arch_bits, f)
        dst = os.path.join(BITS_DIR, f)
        shutil.copy2(src, dst)
        print(f"Copied {f} to include/bits/")

# 2. Generate bits/syscall.h from arch/i386/bits/syscall.h.in
src_sys = os.path.join(arch_bits, "syscall.h.in")
dst_sys = os.path.join(BITS_DIR, "syscall.h")
with open(src_sys, "r") as f:
    sys_content = f.read()

# Append SYS_ aliases
sys_aliases = re.sub(r"#define\s+__NR_([a-zA-Z0-9_]+)", r"#define SYS_\1", sys_content)
with open(dst_sys, "w") as f:
    f.write(sys_content)
    f.write("\n/* SYS_ aliases */\n")
    f.write(sys_aliases)
print("Generated include/bits/syscall.h")

# 3. Generate bits/alltypes.h from arch/i386/bits/alltypes.h.in + include/alltypes.h.in
arch_alltypes = os.path.join(arch_bits, "alltypes.h.in")
inc_alltypes = os.path.join(INC_DIR, "alltypes.h.in")

with open(arch_alltypes, "r") as f:
    arch_lines = f.readlines()
with open(inc_alltypes, "r") as f:
    inc_lines = f.readlines()

all_lines = arch_lines + inc_lines
out_lines = []

for line in all_lines:
    line_clean = line.rstrip("\r\n")
    # TYPEDEF (.*) ([^ ]*);$
    m = re.match(r"^TYPEDEF\s+(.*)\s+([a-zA-Z0-9_]+);$", line_clean)
    if m:
        ty, name = m.group(1), m.group(2)
        out_lines.append(f"#if defined(__NEED_{name}) && !defined(__DEFINED_{name})\n")
        out_lines.append(f"typedef {ty} {name};\n")
        out_lines.append(f"#define __DEFINED_{name}\n")
        out_lines.append("#endif\n")
        continue

    # STRUCT * ([^ ]*) (.*);$
    m = re.match(r"^STRUCT\s+([a-zA-Z0-9_]+)\s+(.*);$", line_clean)
    if m:
        name, body = m.group(1), m.group(2)
        out_lines.append(f"#if defined(__NEED_struct_{name}) && !defined(__DEFINED_struct_{name})\n")
        out_lines.append(f"struct {name} {body};\n")
        out_lines.append(f"#define __DEFINED_struct_{name}\n")
        out_lines.append("#endif\n")
        continue

    # UNION * ([^ ]*) (.*);$
    m = re.match(r"^UNION\s+([a-zA-Z0-9_]+)\s+(.*);$", line_clean)
    if m:
        name, body = m.group(1), m.group(2)
        out_lines.append(f"#if defined(__NEED_union_{name}) && !defined(__DEFINED_union_{name})\n")
        out_lines.append(f"union {name} {body};\n")
        out_lines.append(f"#define __DEFINED_union_{name}\n")
        out_lines.append("#endif\n")
        continue

    out_lines.append(line)

dst_alltypes = os.path.join(BITS_DIR, "alltypes.h")
with open(dst_alltypes, "w") as f:
    f.writelines(out_lines)
print("Generated include/bits/alltypes.h")
print("[SUCCESS] All MUSL headers successfully generated!")
