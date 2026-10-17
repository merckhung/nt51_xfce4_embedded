<!-- SPDX-License-Identifier: GPL-2.0-only -->
# Chromium 158.0.8107.0 for Windows XP NT 5.1 Embedded (32-bit x86)

This directory contains the Chromium source patch ([`chromium_nt51_x86.patch`](chromium_nt51_x86.patch)) and developer build instructions supplied alongside the pre-built 32-bit x86 Chromium binaries (`chrome` and `headless_shell`) in `chromium_rootfs/pkg/opt/chromium/`.

Chromium is **not** built in-tree during the Bazel build of `nt51_xfce4_embedded`. Instead, the stripped pre-built binaries and `.pak` resources are provided in `chromium_rootfs/pkg/opt/chromium/`, and developers who wish to rebuild Chromium from source can apply [`chromium_nt51_x86.patch`](chromium_nt51_x86.patch) using the instructions below.

---

## 1. Summary of [`chromium_nt51_x86.patch`](chromium_nt51_x86.patch)

Base Chromium revision: [`7cc9d0d833549df75d31f9049130b05e3d1c9f84`](https://chromium.googlesource.com/chromium/src/+/7cc9d0d833549df75d31f9049130b05e3d1c9f84) (`158.0.8107.0`). This is the source revision used for the supplied binaries. The original patch was supplied against `3bb54dbfa29e4506909fb9d289ad1a28ab76fceb`; it also applies cleanly to this revision. Build provenance and installed artifact hashes are recorded in `../pkg/opt/chromium-build.json`.

1. **32-bit x86 Linux Target Enablement (`BUILD.gn`)**:
   - Enables `target_cpu = "x86"` when targeting `target_os = "linux"` in full Chromium builds.
2. **Inotify Watcher Thread Bypass (`base/files/file_path_watcher_inotify.cc`)**:
   - Avoids spawning a permanent inotify polling thread on the NT 5.1 FAT16/RAMDisk filesystem.
3. **Physical Memory Fallbacks (`base/system/sys_info_linux.cc`)**:
   - Provides non-zero physical and available memory fallbacks (`1536 MiB` total / `1024 MiB` available) so PartitionAlloc and V8 initialize cleanly on minimal `/proc`.
4. **NSS-Free Linux Client Certificate & Chrome Root Store Support (`chrome/browser/net/profile_network_context_service.cc`, `chrome/browser/ui/webui/certificate_manager/client_cert_sources.cc`, `chrome/utility/importer/nss_decryptor.*`, `net/cert/*`)**:
   - Allows building on Linux with `use_nss_certs = false` and `chrome_root_store_only = true` so BoringSSL + Chrome Root Store verify TLS/HTTPS certificates (`https://www.yahoo.com/`) without external NSS shared libraries.
5. **Graceful Crashpad Startup (`components/crash/core/app/crashpad_linux.cc`)**:
   - Continues browser startup with a warning if the out-of-process Crashpad handler is disabled or unavailable.
6. **Headless SwiftShader Vulkan Display on Ozone/X11 (`ui/gl/gl_display.cc`, `ui/ozone/platform/x11/x11_surface_factory.cc`)**:
   - Configures ANGLE SwiftShader Vulkan to use `EGL_PLATFORM_VULKAN_DISPLAY_MODE_HEADLESS_ANGLE` and `EGL_DEFAULT_DISPLAY` when running on Xvfb (`:0`).

---

## 2. Prerequisites

- Linux x86_64 host with `depot_tools` on `PATH`
- Chromium checkout at revision `7cc9d0d833549df75d31f9049130b05e3d1c9f84` (`158.0.8107.0`) with i386 sysroot (`build/linux/sysroot_scripts/install-sysroot.py --arch=i386`)

```bash
cd /path/to/chromium/src
git checkout 7cc9d0d833549df75d31f9049130b05e3d1c9f84
git apply /path/to/nt51_xfce4_embedded/chromium_rootfs/patches/chromium_nt51_x86.patch
```

---

## 3. GN Configuration (`out/nt51_x86/args.gn`)

```bash
mkdir -p out/nt51_x86
cat > out/nt51_x86/args.gn << 'EOF'
target_os = "linux"
target_cpu = "x86"
is_debug = false
is_component_build = false
is_official_build = false
dcheck_always_on = false
symbol_level = 0
blink_symbol_level = 0
v8_symbol_level = 0
use_remoteexec = false
use_siso = false
use_aura = true
toolkit_views = true
use_ozone = true
ozone_auto_platforms = false
ozone_platform = "x11"
ozone_platform_x11 = true
ozone_platform_headless = true
ozone_platform_wayland = false
use_glib = false
use_gtk = false
use_qt5 = false
use_qt6 = false
use_gio = false
use_cups = false
use_pulseaudio = false
use_alsa = false
use_kerberos = false
use_vaapi = false
use_v4l2_codec = false
use_libpci = false
use_nss_client_certs = false
use_nss_server_certs = false
use_nss_certs = false
enable_vr = false
enable_swiftshader = true
angle_enable_vulkan = true
angle_enable_swiftshader = true
angle_enable_gl = false
angle_enable_wgpu = false
angle_enable_vulkan_validation_layers = false
angle_use_x11 = true
use_dawn = false
skia_use_dawn = false
chrome_root_store_only = true
enable_library_cdms = false
rtc_use_pipewire = false
EOF

gn gen out/nt51_x86
```

---

## 4. Building Both Variants (`chrome` and `headless_shell`) + SwiftShader & ANGLE

```bash
autoninja -C out/nt51_x86 \
  chrome \
  headless:headless_shell \
  third_party/angle:libEGL \
  third_party/angle:libGLESv2 \
  third_party/swiftshader/src/Vulkan:swiftshader_libvulkan \
  third_party/vulkan-loader/src:libvulkan
```

---

## 5. Stripping and Installing Pre-builts into `chromium_rootfs/pkg/opt/chromium/`

```bash
STRIP=third_party/llvm-build/Release+Asserts/bin/llvm-strip
DEST=/path/to/nt51_xfce4_embedded/chromium_rootfs/pkg/opt/chromium
mkdir -p "$DEST/locales"

"$STRIP" --strip-all -o "$DEST/chrome" out/nt51_x86/chrome
"$STRIP" --strip-all -o "$DEST/headless_shell" out/nt51_x86/headless_shell
"$STRIP" --strip-all -o "$DEST/libEGL.so" out/nt51_x86/libEGL_test.so
"$STRIP" --strip-all -o "$DEST/libGLESv2_test.so" out/nt51_x86/libGLESv2_test.so
"$STRIP" --strip-all -o "$DEST/libvk_swiftshader.so" out/nt51_x86/libvk_swiftshader.so
"$STRIP" --strip-all -o "$DEST/libvulkan.so.1" out/nt51_x86/libvulkan.so.1

# Use a guest path rather than the output directory's relative library path.
python3 - "$DEST/vk_swiftshader_icd.json" <<'PYTHON'
import json, pathlib, sys
icd = json.loads(pathlib.Path('out/nt51_x86/vk_swiftshader_icd.json').read_text())
icd['ICD']['library_path'] = '/opt/chromium/libvk_swiftshader.so'
pathlib.Path(sys.argv[1]).write_text(json.dumps(icd) + '\n')
PYTHON
cp out/nt51_x86/icudtl.dat "$DEST/"
cp out/nt51_x86/v8_context_snapshot.bin "$DEST/"
cp out/nt51_x86/chrome_100_percent.pak \
   out/nt51_x86/chrome_200_percent.pak \
   out/nt51_x86/resources.pak \
   out/nt51_x86/headless_command_resources.pak \
   out/nt51_x86/headless_lib_data.pak \
   out/nt51_x86/headless_lib_strings.pak \
   "$DEST/"
cp out/nt51_x86/locales/en-US.pak "$DEST/locales/"
```

With static ANGLE enabled (the default), Chromium generates placeholder `libEGL.so` and `libGLESv2.so` files. The real ANGLE shared libraries are `libEGL_test.so` and `libGLESv2_test.so`; install the former as `libEGL.so` as shown above. Do not package the placeholders. `libGLESv2_test.so` is the rebuilt GLES library. The image builder aliases it as `/opt/chromium/libGLESv2.so`, including in the raw disk lookup table.

Then rebuild and verify the disk image:

```bash
bazel build //:chromium_image
python3 tools/qemu.py chromium --headless --verify --timeout 1800
```
