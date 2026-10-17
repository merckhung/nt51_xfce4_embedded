<!-- SPDX-License-Identifier: GPL-2.0-only -->
The project build scripts, embedded runtime adaptations, tests and documentation are distributed under GPL-2.0-only; see LICENSE. Existing copyright notices remain applicable.

NT source and the historical Microsoft tools are fetched from the pinned external `nt51` Git repository. They are not hosted in this project, and this project's GPL license does not relicense them. `patches/nt51-bazel.patch` adds adapted Bazel build definitions and small compatibility fixes.

The NT source drop lacks source for the Executive's `exinit.obj` and `systime.obj` seed objects. The kernel also links the upstream published binary CRT library `libcntpr.lib`. These inputs are explicitly retained from the pinned dependency. "Build from source" here means compiling all available kernel sources, not reconstructing these missing sources. Other published import/support libraries are inputs to the original boot and driver toolchain.

musl 1.2.5 is downloaded from its official release site, under its MIT license and component notices. BusyBox 1.36.1 is downloaded from its official release site, under GPL-2.0-only. The NT adaptations are stored as patches. Generated BusyBox configuration headers are retained as build inputs.

The BusyBox patch routes `ps` to the project's NT process-query backend because Linux procfs is absent. The shared sysinfo adapter translates available NT counters. The X11 desktop probe uses the documented X.Org wire protocol to observe mapped windows; it does not generate a desktop image.

XFCE, Xvfb, D-Bus, GTK and their dependencies are pinned Alpine v3.18 x86 binary packages, not rebuilt from source by this project. The manifest records every URL and SHA-256. Their upstream component licenses apply. A two-byte, explicitly checked xfconfd keepalive patch is applied during image creation; the port does not implement the Linux signal behavior it normally uses.

The native runtime, Linux syscall shim, custom drivers and FAT16 image writer implement the embedded port. In `chromium_rootfs/`, pre-built 32-bit x86 Chromium 158.0.8107.0 binaries (`chrome` and `headless_shell`), ANGLE (`libEGL.so`, `libGLESv2.so`), and SwiftShader (`libvk_swiftshader.so`) are included under `chromium_rootfs/pkg/opt/chromium/` subject to their upstream Chromium/BSD-3-Clause/Apache-2.0 licenses, with source patches and rebuild instructions in `chromium_rootfs/patches/`. Source revisions, build configuration and artifact hashes are recorded in [the build provenance](chromium_rootfs/pkg/opt/chromium-build.json). Upstream Google/Chromium copyright and product strings are retained. Unsupported GCC, GDB and SSH dispatch hooks return errors. Those earlier demonstration implementations are excluded.

The complete GPL-2.0-only text is in `LICENSES/GPL-2.0-only.txt`.
`licenses/musl-COPYRIGHT` and `LICENSES/LicenseRef-musl-notices.txt` retain
musl's component notices. The Chromium notice collection in
`LICENSES/LicenseRef-Chromium-Bundle.txt` was generated with upstream's
`tools/licenses/licenses.py license_file --format=txt` from the pinned
source revision. It includes shipped-license metadata across the source
checkout, a superset of the bundled target's dependencies. An identical
copy is packaged at `/usr/share/licenses/chromium/NOTICE`.
`LicenseRef-Chromium-Bundle` records this collection rather than applying
the project's GPL license to the Chromium binaries or resources.

REUSE metadata describes the files in this repository. It does not grant
rights to the separately fetched NT dependency or its historical tools.

Each image includes the GPL-2.0-only text and musl component notices under
`/usr/share/licenses/`. Chromium's additional notice collection is included
in its image under that directory as well.
