<!-- SPDX-License-Identifier: GPL-2.0-only -->
# NT 5.1 Embedded with XFCE

An experimental Windows XP SP1 x86 kernel system with a native init process, an NT-to-Linux syscall translation layer, musl 1.2.5 and BusyBox 1.36.1. The larger image runs Alpine's XFCE 4.18 applications and Xvfb through the translation layer and a QEMU framebuffer bridge.

This repository contains build definitions, patches and the embedded port. NT source is a pinned external Bazel dependency fetched from [vipinkiruba/kernel-NT5.1](https://github.com/vipinkiruba/kernel-NT5.1/tree/1b390dddff9fe017e9c11a7845c67a887c3483dc), patched during repository initialization. Kernel source and generated binaries are excluded from Git.

## Build on Windows

Install Git, Bazel 9.2.0, Python 3.13 or newer, and LLVM with clang, ld.lld, llvm-ar and llvm-strip. Put their executables on PATH. The NT dependency supplies its historical x86 compiler and assembler. Use a short directory path without spaces for the legacy tools.

```powershell
cd nt51_xfce4_embedded
$buildCache = Join-Path $env:SystemDrive 'nt51-bazel'
bazel --output_user_root="$buildCache" build //:kernel_bundle
bazel --output_user_root="$buildCache" build //:minimal_image
bazel --output_user_root="$buildCache" build //:xfce_image
```

The XFCE target depends on the minimal image, so its graph builds the kernel and boot support, native runtime, minimal system/image, and then the XFCE system/image. musl and BusyBox release archives and every Alpine package are checked against pinned SHA-256 hashes.

Optionally pass `--repo_env=NT51_GIT_CACHE=<existing-clone>` to use an existing Git object cache. It contributes committed objects at the pinned revision; modified working files and prior build artifacts are never copied. Without the option, the dependency is fetched from GitHub.

The native Bazel kernel rules compile available C and assembly sources into individual declared objects and libraries. Boot support uses the original build.exe/nmake toolchain inside a writable copy of the external dependency. Failures and missing outputs stop the build. Its outputs include the freshly built NT loader, detector, storage/filesystem/bus drivers and NLS data. Both rootfs actions compile their own libc, shim, BusyBox, drivers, init and NT test suite.

Host Python and LLVM are selected from PATH. This is a Windows local build, not a fully hermetic cross-platform toolchain. Clean the Bazel outputs when changing host tool versions.

## Images and QEMU

Outputs:

* `bazel-bin/minimal_rootfs/usb_image.files/minimal_usb.img`
* `bazel-bin/rootfs/usb_image.files/xfce_usb.img`

Each raw disk contains an MBR, FAT16 boot partition, NTLDR, NTDETECT and a FAT16 RAM disk. The image action also writes a rootfs manifest with file hashes. The minimal disk is 192 MiB; the XFCE disk is 384 MiB.

Install QEMU with SDL support, then put qemu-system-i386 on PATH or set `QEMU_BINARY` to its executable. The launcher opens a window on the interactive Windows desktop and uses snapshot mode.

```powershell
python tools/qemu.py minimal --verify
python tools/qemu.py xfce --verify
```

Boot init runs `nttest.elf all`. Verification requires nine completed suites, nonzero individual tests, zero failures and exit status zero. Serial logs, screenshots, image hashes and verification JSON are saved under `runtime/minimal` and `runtime/xfce`. A timeout or absent summary fails verification.

Both images also run `ps aux` at startup and require exit status zero. XFCE verification additionally queries the actual X11 window tree and requires viewable windows for the top panel, bottom dock, terminal and desktop. Starting Xvfb or obtaining XTEST support alone does not pass this check.

To exercise USB storage boot instead of the default IDE attachment:

```powershell
python tools/qemu.py minimal --usb --verify --timeout 360
python tools/qemu.py xfce --usb --verify --timeout 360
```

The launcher uses QEMU's UHCI USB controller and USB mass storage device. These runs save evidence in `runtime/minimal-usb` and `runtime/xfce-usb`. Snapshot mode preserves the built disk. The launcher copies it into the runtime directory so the Bazel output remains rebuildable while QEMU is running.

## Guest commands and verification

```sh
ps aux
ps -ef
nttest all
expr 137 - 29
```

`ps` uses a live `NtQuerySystemInformation` process snapshot instead of Linux `/proc`. It reads the port's actual spawn arguments or the native process command line, NT token ownership, cumulative CPU time, virtual size and working set. `%CPU` is lifetime CPU usage; `%MEM` uses physical memory reported by NT. `START` interprets the NT timestamp as UTC. `STAT` shows `R` for ready/running NT threads and `W` for waiting threads. Unavailable fields, including TTY, show `?`; non-System owners are identified by their SID's final component. The supported options are `aux`, `-ef`, `-A`, `-e`, `-l` and `-w`. All enumerate the NT process snapshot; this is a small NT backend, not the full GNU ps implementation.

The sysinfo translation obtains memory totals, available pages, process count and uptime from NT. It does not provide Linux load averages, cache categories or swap accounting; those fields are zero. No Linux procfs is mounted. Utilities that require `/proc`, including the upstream BusyBox `free` and `top`, remain unsupported.

The image writer has regression checks for VFAT filenames, including numeric version directories such as `2.10.0`, and colliding DOS aliases:

```powershell
python -m unittest discover -s tests -p test_*.py
```

The kernel patch restores the embedded ELF thread's GS/TLS descriptor during context switches. This replaces the former framebuffer driver's brittle patches at fixed kernel addresses. The FAT writer emits valid long filenames, so GTK can find its image loaders. Startup generates the MIME, GDK image loader and GSettings caches with the packaged utilities.

Verified on Windows on 2026-10-11 with Bazel 9.2.0, LLVM 22.1.0 and QEMU 11.1.0:

| Image | Boot attachment | NT tests | `ps aux` | XFCE windows |
| --- | --- | --- | --- | --- |
| Minimal | IDE | 54/54, nine suites | Exit 0 | — |
| Minimal | UHCI USB storage | 54/54, nine suites | Exit 0 | — |
| XFCE | IDE | 54/54, nine suites | Exit 0 | Top panel, bottom dock, terminal, desktop |
| XFCE | UHCI USB storage | 54/54, nine suites | Exit 0 | Top panel, bottom dock, terminal, desktop |

The original IDE and USB runs used identical image hashes for each variant. [Verification records](docs/verification.json) contain those hashes and the observed results. Keyboard input was checked with `expr 137 - 29`, which returned `108`. Both FAT filename regression tests passed.

After the license and source sanitation review, `bazel clean --expunge` removed the build outputs. A fresh build of all three targets completed 1,591 actions. Both rebuilt images passed 54/54 NT tests and `ps aux` through IDE boot, and XFCE's mapped windows and visible QEMU window were confirmed. The `clean_rebuild` entry in the verification records contains these newer image hashes and results. USB results above refer to the original images.

These are actual QEMU captures:

![Minimal image running the NT kernel tests](docs/screenshots/minimal-tests.png)

![XFCE with the top taskbar, bottom dock and terminal](docs/screenshots/xfce-desktop.png)

![Live NT process snapshot and ps aux output excerpt in XFCE](docs/screenshots/xfce-ps.png)

## Commands in the XFCE terminal

These screenshots were captured from the running XFCE terminal in QEMU using the clean-build XFCE image recorded in [docs/verification.json](docs/verification.json). The commands executed in the guest; the images are unedited framebuffer captures.

### Loaded embedded drivers: `lsmod`

```sh
lsmod
```

The port's [module-query implementation](rootfs/shim/modtools.c) calls NT's `NtQuerySystemInformation(SystemModuleInformation)`. The default listing shows the four loaded embedded drivers and reports that 18 kernel and boot modules are hidden. `lsmod -a`, shown below, includes them.

![lsmod in the XFCE terminal showing loaded embedded NT drivers](docs/screenshots/xfce-lsmod.png)

### Compatibility identity: `uname -a`

```sh
uname -a
```

This output is supplied by the [Linux syscall compatibility shim](rootfs/shim/nt_linux_shim.c). Its `Linux`, release and `PREEMPT` fields are hardcoded compatibility strings, so this command does not identify the underlying kernel. The screenshot preserves the actual output. The live NT module query and NT syscall tests provide the kernel evidence.

![Actual uname -a compatibility output in the XFCE terminal](docs/screenshots/xfce-uname.png)

### NT kernel syscall tests: `nttest`

`nttest` with no arguments runs all nine suites. The output is saved and its final 19 lines displayed so the command, exit status and complete summary fit in one capture:

```sh
nttest > /tmp/nttest-capture.txt
echo "nttest exit=$?"
tail -n 19 /tmp/nttest-capture.txt
```

The run completed with exit status 0, nine suites passed and 54/54 executed tests passed.

![nttest executed in the XFCE terminal with 54 of 54 NT tests passed](docs/screenshots/xfce-nttest.png)

### Kernel and driver files in `WINDOWS/system32`

```sh
cd /WINDOWS/system32
pwd
ls
```

The directory contains `ntoskrnl.exe`, `hal.dll`, `ntdll.dll`, `bootvid.dll`, `kdcom.dll`, the native `smss.exe`, registry configuration and boot drivers.

![WINDOWS system32 listing with the NT kernel and native runtime files](docs/screenshots/xfce-system32.png)

```sh
cd /WINDOWS/system32/drivers
pwd
ls
```

The driver directory includes NT's storage, filesystem, bus and input drivers, alongside the embedded port's drivers.

![Complete WINDOWS system32 drivers filename listing in the XFCE terminal](docs/screenshots/xfce-drivers.png)

### Further NT kernel evidence

`lsmod -a` queries all loaded NT modules, including the running `ntoskrnl.exe`, `hal.dll`, `KDCOM.DLL`, `BOOTVID.dll` and `.sys` boot drivers, with their actual image sizes and load addresses:

```sh
lsmod -a
```

![Live NT kernel and boot module list with image sizes and base addresses](docs/screenshots/xfce-nt-modules.png)

The [registry tests](tests/test_cm.c) exercise NT's Configuration Manager through `NtOpenKey`, `NtCreateKey`, `NtSetValueKey`, `NtQueryValueKey`, enumeration and deletion. This run passed all five tests:

```sh
nttest cm
```

![Five NT registry tests passed in the XFCE terminal](docs/screenshots/xfce-registry.png)

The [security tests](tests/test_se.c) query NT process tokens, user SIDs, groups and privileges, and exercise token duplication and invalid-token handling. All six tests passed:

```sh
nttest se
```

![Six NT security and access token tests passed in the XFCE terminal](docs/screenshots/xfce-security.png)

The [process-query backend](native/ntps.c) reads the live NT process snapshot. This excerpt includes NT's idle process, `System` and the native session manager, alongside the XFCE processes:

```sh
ps aux > /tmp/ps-capture.txt
head -n 8 /tmp/ps-capture.txt
```

![Live NT process snapshot including System and smss.exe in the XFCE terminal](docs/screenshots/xfce-nt-processes.png)

## Scope and limitations

The source drop contains binary-only Executive seed objects and published runtime/support libraries. They remain explicit external inputs; see [THIRD_PARTY.md](THIRD_PARTY.md). The build cannot reconstruct their missing source.

XFCE and its Linux dependencies are pinned Alpine binaries. This project builds the NT kernel and embedded runtime from available source; it does not rebuild Alpine. The syscall port implements a subset of Linux behavior and retains compatibility no-ops for some signals, permissions and scheduling operations. It is not a complete Linux ABI or a production OS. Unknown calls return ENOSYS. The minimal image also rejects unimplemented epoll/eventfd operations instead of returning a fabricated descriptor.

The graphics bridge targets QEMU's standard VGA/Bochs framebuffer and PS/2 input. The custom USB driver is experimental; controller enumeration is not proof of complete USB device support. Physical hardware boot is unverified. Networking and TLS are incomplete.

XFCE runs through a session D-Bus daemon, without a complete Linux service environment. System D-Bus, login/power services and some thumbnailing/service activation are unavailable. The default panel omits plugins that require those services. The NT tests cover 54 executed assertions across nine suites; passing them does not establish complete kernel or Linux compatibility.

Earlier embedded scripts simulated compiler/debugger success, SSH authentication/file transfer, and successful HTTP replies after connection failure. Those compiler/SSH implementations and their image aliases are excluded. Their retained dispatch hooks return an unavailable error. HTTP failures remain failures, HTTPS is rejected, and canned netstat connections are removed. Chromium and the synthetic desktop/browser demonstration objects are excluded.

Guessed USB devices, fallback DNS answers and fabricated successful ping/HTTP results are removed. Only UHCI transfers are implemented by the custom USB driver; other controller types are reported as unsupported. This does not make the remaining experimental drivers complete.

## Layout and license

* `minimal_rootfs/`: minimal embedded system.
* `rootfs/`: XFCE embedded system and pinned Alpine manifest.
* `native/`: shared native ntdll, libc support and registry hive generator.
* `tests/`: direct NT syscall assertions for nine subsystems.
* `bazel/`, `patches/`, `tools/`: dependency initialization, build actions, packaging and QEMU validation.

Project code is GPL-2.0-only. Upstream component licenses remain applicable; [THIRD_PARTY.md](THIRD_PARTY.md) describes the boundaries. Build outputs, runtime logs and downloaded external source are ignored by Git.

The [license header review](docs/license-audit.md) documents the coverage and preserved upstream files. `REUSE.toml` supplies license metadata for project files whose formats cannot accept comments.
