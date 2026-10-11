# SPDX-License-Identifier: GPL-2.0-only
import os,re
BB_DIR=None
def discover_sources():
    config = {}
    with open(os.path.join(BB_DIR, ".config")) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip('"')

    subdirs = [
        "applets",
        "archival",
        "archival/libarchive",
        "console-tools",
        "coreutils",
        "coreutils/libcoreutils",
        "debianutils",
        "klibc-utils",
        "e2fsprogs",
        "editors",
        "findutils",
        "init",
        "libbb",
        "libpwdgrp",
        "loginutils",
        "mailutils",
        "miscutils",
        "modutils",
        "networking",
        "networking/libiproute",
        "networking/udhcp",
        "printutils",
        "procps",
        "runit",
        "selinux",
        "shell",
        "sysklogd",
        "util-linux",
        "util-linux/volume_id",
    ]

    sources = []
    for sd in subdirs:
        kb_path = os.path.join(BB_DIR, sd, "Kbuild")
        if not os.path.exists(kb_path):
            continue
            
        with open(kb_path) as f:
            raw_content = f.read()

        # Join line continuations with backslash
        raw_lines = raw_content.replace("\\\n", " ").splitlines()
        
        # Local Makefile variables in this Kbuild
        kb_vars = {}
        
        for line in raw_lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
                
            # Check for variable assignment e.g. COMMON_FILES := ...
            var_m = re.match(r"^([A-Za-z0-9_]+)\s*[:+]?=\s*(.*)$", line)
            if var_m:
                vname, val = var_m.groups()
                # Expand any $(VAR) inside val
                for vk, vv in kb_vars.items():
                    val = val.replace(f"$({vk})", vv)
                if line.startswith(f"{vname} +="):
                    kb_vars[vname] = (kb_vars.get(vname, "") + " " + val).strip()
                else:
                    kb_vars[vname] = val.strip()

            # Check for lib-y, obj-y, lib-$(CONFIG_...), obj-$(CONFIG_...)
            m = re.match(r"^(lib|obj)-([^:=+\s]+)\s*[:+]?=\s*(.*)$", line)
            if m:
                kind, cond, objs = m.groups()
                
                # Expand variables in objs
                for vk, vv in kb_vars.items():
                    objs = objs.replace(f"$({vk})", vv)
                    
                matched = False
                if cond == "y":
                    matched = True
                elif cond.startswith("$(CONFIG_") and cond.endswith(")"):
                    var = cond[2:-1]
                    if config.get(var) == "y":
                        matched = True
                        
                if matched:
                    for obj in objs.split():
                        if obj.endswith(".o"):
                            stem = obj[:-2]
                            c_file = os.path.join(BB_DIR, sd, stem + ".c")
                            s_file = os.path.join(BB_DIR, sd, stem + ".S")
                            if os.path.exists(c_file):
                                sources.append((sd, c_file))
                            elif os.path.exists(s_file):
                                sources.append((sd, s_file))

    # Also add applets/applets.c
    applets_c = os.path.join(BB_DIR, "applets", "applets.c")
    if os.path.exists(applets_c) and ("applets", applets_c) not in sources:
        sources.append(("applets", applets_c))

    # Deduplicate preserving order
    seen = set()
    unique_sources = []
    for sd, src in sources:
        if src not in seen:
            seen.add(src)
            unique_sources.append((sd, src))

    return unique_sources

