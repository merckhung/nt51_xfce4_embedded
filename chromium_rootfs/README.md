<!-- SPDX-License-Identifier: GPL-2.0-only -->
# Chromium 32-bit (`x86_32`) on Windows XP (NT 5.1) + Linux Syscall Shim (`chromium_rootfs`)

Build and runtime verification records are in [../docs/verification.json](../docs/verification.json), including a separate record for the Chromium rebuild. The earlier Chromium report is retained as unverified in [../docs/verification.json](../docs/verification.json), because the old launch script overwrote a killed browser’s exit status with zero. The current checks require an actual exit status of zero, a complete DOM containing the exact computed result, and observed TCP establishment and received data. Browser title and viewport pixels do not prove TLS certificate validation.

This directory (`chromium_rootfs/`) implements the **3rd rootfs** for `nt51_xfce4_embedded`:
- **Kernel**: Windows XP SP1 (`NT 5.1.2600`) 32-bit x86 (`ntoskrnl.exe`, `hal.dll`)
- **Syscall Layer**: [`chromium_rootfs/shim/nt_linux_shim.c`](shim/nt_linux_shim.c) + [`chromium_rootfs/shim/netd.c`](shim/netd.c) + `musl` (`ld-musl-i386.so.1`) + [`chromium_rootfs/shim/gcompat.c`](shim/gcompat.c) (`libgcompat.so` / `libc.so.6` ABI bridge)
- **Networking**: RTL8139 kernel driver ([`chromium_rootfs/drivers/netdrv/netdrv.c`](drivers/netdrv/netdrv.c) -> `rtl8139.sys`, `\Device\Net0`) + `netd` user-mode IPv4 TCP/UDP stack providing real DNS and HTTPS/TLS connectivity over the QEMU NIC
- **Desktop Environment**: Alpine Linux 3.18 32-bit `i386` **XFCE 4.18** (`xfwm4`, `xfdesktop`, `xfce4-panel`, `xfce4-terminal`) running over `Xvfb :0` (`800x600x24`) and `x11_fb_bridge` (`/dev/fb0` -> `fbdrv.sys`; PS/2 keyboard, mouse and wheel -> XTEST)
- **Writable RAM disk**: 192 MiB FAT16 (`NTBOOT.IMG`), large enough for the GUI and headless profiles under `/tmp`
- **Browser (Both Pre-built Variants Included)**:
  1. **GUI Browser (`chrome`)**: Pre-built 32-bit (`x86`) Chromium `158.0.8107.0` (`/opt/chromium/chrome`) using Chromium Aura Views + `FallbackLinuxUi` over Ozone/X11, navigating to `https://www.yahoo.com/` over live DNS + HTTPS
  2. **Headless Shell (`headless_shell`)**: Pre-built 32-bit (`x86`) Chromium `158.0.8107.0` (`/opt/chromium/headless_shell` + `headless_lib_data.pak` + `headless_lib_strings.pak`) running `--headless --dump-dom`
- **Graphics Stack** (probe and headless launcher; the GUI disables GPU/SwiftShader and uses CPU rendering): SwiftShader Vulkan ICD (`libvk_swiftshader.so`, `vk_swiftshader_icd.json`) + ANGLE OpenGL ES 3.1 (`libEGL.so`, `libGLESv2.so`) + Skia software compositor presenting over X11 `PutImage`

---

## 1. Architecture Summary

### 1.1 NT 5.1 Linux Syscall Shim & Memory/IPC Architecture ([`nt_linux_shim.c`](shim/nt_linux_shim.c))
- **Zero Wine**: No Wine is used anywhere in the guest. Chromium (`chrome` and `headless_shell`) is compiled as a 32-bit (`i686`/`x86`) Linux ELF binary and executed directly by the NT 5.1 native subsystem (`smss.exe` / `elfloader.exe`) via `nt_linux_shim.c`.
- **Shared Memory & Mojo `SCM_RIGHTS` (`DirectReceiver` / `ThreadLocalNode`)**:
  - `memfd_create` (`SYS_memfd_create = 356`), `/dev/shm/*`, `ftruncate` (`93`/`194`), `fallocate` (`324`), and `mmap2` (`192`) are backed by named NT Section Objects (`\LxssShm_<ino>` via `NtCreateSection` / `NtOpenSection` / `NtMapViewOfSection` / `NtUnmapViewOfSection`), sized at 4 KB page granularity.
  - `sendmsg` (`370`) and `recvmsg` (`372`) implement atomic `SCM_RIGHTS` file-descriptor passing (`SOL_SOCKET = 1`, `SCM_RIGHTS = 1`) across connected `AF_UNIX` / `socketpair` rings (`SHIM_IPC_RING::scm_fds`), preserving `O_NONBLOCK` and descriptor refcounts so Mojo `ipcz` `ThreadLocalNode` (`DirectReceiver`) transfers `CompositorFrameSinkClient` portals to the `Compositor` thread cleanly.
- **Aligned Virtual Memory Reservation (`PartitionAlloc` & `V8`)**:
  - `shim_alloc_aligned_vm`, `sys_mmap2`, and `sys_munmap` honour aligned `mmap` hint addresses (such as PartitionAlloc 2 MiB superpages and V8 cage reservations) without 64 KB alignment slack and release `MEM_RESERVE` regions when `munmap` trims leading/trailing reservation slack.
- **Real TCP/UDP Networking ([`netd.c`](shim/netd.c) & [`netdrv.c`](drivers/netdrv/netdrv.c))**:
  - Non-loopback `AF_INET` `SOCK_STREAM` (`connect`/`send`/`recv`) and `SOCK_DGRAM` (`sendto`/`recvfrom`) sockets are serviced by `netd` over `\Device\Net0` (`rtl8139.sys`), speaking real ARP, IPv4, UDP (DNS via `10.0.2.3:53`), and TCP (HTTPS port `443` and HTTP port `80`).
- **Process & Thread Management (`//base/process` & `//base/threading`)**:
  - `MAX_FD = 512`, `MAX_EPOLLS = 128`, `MAX_EPOLL_ITEMS = 128`, `MAX_PTHREADS = 96`.
  - `pthread_getattr_np` in [`gcompat.c`](shim/gcompat.c) inspects the NT 32-bit TEB (`%fs:0x04` `StackBase` and `%fs:0x08` `StackLimit`) for PartitionAlloc / Blink Oilpan stack scanning.

---

## 2. Directory Layout

- [`chromium_rootfs/shim/nt_linux_shim.c`](shim/nt_linux_shim.c): NT 5.1 -> Linux i386 syscall & dynamic ELF compatibility layer.
- [`chromium_rootfs/shim/netd.c`](shim/netd.c): User-mode IPv4 TCP/UDP/ARP network daemon over `rtl8139.sys`.
- [`chromium_rootfs/shim/gcompat.c`](shim/gcompat.c): 32-bit glibc (`libc.so.6`) compatibility shim compiled into `/lib/libgcompat.so` on top of `ld-musl-i386.so.1`.
- [`chromium_rootfs/shim/swiftshader_probe.c`](shim/swiftshader_probe.c): Standalone 32-bit EGL/GLESv2 probe (`/opt/chromium/swiftshader_probe`) verifying ANGLE + SwiftShader Vulkan rendering.
- [`chromium_rootfs/xfce_probe.c`](xfce_probe.c): X11 window tree and pixel verifier confirming `top_panel`, `bottom_panel`, `terminal`, `desktop`, and `chromium` (with `Yahoo` title and rendered webpage viewport pixels via `X_GetImage`) are viewable.
- [`chromium_rootfs/patches/chromium_nt51_x86.patch`](patches/chromium_nt51_x86.patch) & [`chromium_rootfs/patches/README.md`](patches/README.md): Chromium `158.0.8107.0` source patch and developer rebuild guide.
- `chromium_rootfs/pkg/opt/chromium/`: Pre-built 32-bit Chromium binaries for both variants (`chrome` and `headless_shell`), SwiftShader Vulkan ICD (`libvk_swiftshader.so`, `vk_swiftshader_icd.json`), ANGLE (`libEGL.so`, `libGLESv2.so`), `libvulkan.so.1`, `icudtl.dat`, `v8_context_snapshot.bin`, and `.pak` bundles (`chrome_100_percent.pak`, `chrome_200_percent.pak`, `resources.pak`, `headless_lib_data.pak`, `headless_lib_strings.pak`, `locales/en-US.pak`).
- `chromium_rootfs/overlay/`: Rootfs configuration (`etc/rc.sysinit`, `usr/bin/chromium`, `usr/bin/chromium-headless`, `opt/chromium/headless_test.html`, XFCE 4.18 panel config).

---

## 3. Rebuilding 32-bit Chromium (`chrome` & `headless_shell`)

Chromium is **not** rebuilt during the Bazel build of this repository. Rebuilt binaries for both `chrome` and `headless_shell` are supplied under `chromium_rootfs/pkg/opt/chromium/`. The [provenance manifest](pkg/opt/chromium-build.json) records the source and dependency revisions, build configuration, artifact hashes and privacy scan results. To rebuild them from a Chromium source checkout (commit `7cc9d0d833549df75d31f9049130b05e3d1c9f84`, version `158.0.8107.0`), follow [`chromium_rootfs/patches/README.md`](patches/README.md).

---

## 4. Building & Verifying the 3rd Rootfs Image in QEMU (`qemu-system-i386`)

```bash
# Build the 3rd rootfs disk image (bazel-bin/chromium_rootfs/usb_image.files/chromium_usb.img)
bazel build //chromium_rootfs:usb_image

# Boot in QEMU (32-bit i386 PC) and verify NT kernel tests, SwiftShader, headless_shell, and GUI Chromium on www.yahoo.com
python3 tools/qemu.py chromium --headless --verify --timeout 1800
```

The 2026-10-18 run passed every check with the supplied prebuilt binaries (`current_review` in [../docs/verification.json](../docs/verification.json)). The mouse wheel scrolls the page through the PS/2 IntelliMouse driver and the X11 bridge's XTEST button 4/5 events, and keyboard input reaches page text fields. The geolocated city in Yahoo's weather and events cards is masked in these captures; they are otherwise unedited.

![Chromium showing yahoo.com in the XFCE desktop](../docs/screenshots/xfce-chromium.png)

![Yahoo after scrolling down with the mouse wheel](../docs/screenshots/chromium-scroll-down.png)

USB boot can start NT and XFCE, but the browser assets use the IDE raw-sector transport and are unavailable on USB. Use the default IDE attachment for Chromium verification.
