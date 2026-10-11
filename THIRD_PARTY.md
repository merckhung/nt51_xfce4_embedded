<!-- SPDX-License-Identifier: GPL-2.0-only -->
The project build scripts, embedded runtime adaptations, tests and documentation are distributed under GPL-2.0-only; see LICENSE. Existing copyright notices remain applicable.

NT source and the historical Microsoft tools are fetched from the pinned external `nt51` Git repository. They are not hosted in this project, and this project's GPL license does not relicense them. `patches/nt51-bazel.patch` adds adapted Bazel build definitions and small compatibility fixes.

The NT source drop lacks source for the Executive's `exinit.obj` and `systime.obj` seed objects. The kernel also links the upstream published binary CRT library `libcntpr.lib`. These inputs are explicitly retained from the pinned dependency. "Build from source" here means compiling all available kernel sources, not reconstructing these missing sources. Other published import/support libraries are inputs to the original boot and driver toolchain.

musl 1.2.5 is downloaded from its official release site, under its MIT license and component notices. BusyBox 1.36.1 is downloaded from its official release site, under GPL-2.0-only. The NT adaptations are stored as patches. Generated BusyBox configuration headers are retained as build inputs.

The BusyBox patch routes `ps` to the project's NT process-query backend because Linux procfs is absent. The shared sysinfo adapter translates available NT counters. The X11 desktop probe uses the documented X.Org wire protocol to observe mapped windows; it does not generate a desktop image.

XFCE, Xvfb, D-Bus, GTK and their dependencies are pinned Alpine v3.18 x86 binary packages, not rebuilt from source by this project. The manifest records every URL and SHA-256. Their upstream component licenses apply. A two-byte, explicitly checked xfconfd keepalive patch is applied during image creation; the port does not implement the Linux signal behavior it normally uses.

The native runtime, Linux syscall shim, custom drivers and FAT16 image writer implement the embedded port. Unsupported GCC, GDB and SSH dispatch hooks return errors. Those earlier demonstration implementations are excluded.
