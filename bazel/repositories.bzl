# SPDX-License-Identifier: GPL-2.0-only
"""Fetch pinned NT sources and apply the build overlay during repository init."""

def _run(ctx, args):
    result = ctx.execute(args, timeout = 3600, quiet = True)
    if result.return_code:
        fail("%s\n%s\n%s" % (args, result.stdout, result.stderr))

def _nt51_repository_impl(ctx):
    git = ctx.which("git")
    if not git:
        fail("Git must be on PATH")
    cache = ctx.os.environ.get("NT51_GIT_CACHE", "")
    source = cache if cache else ctx.attr.remote
    clone = [str(git), "clone", "--no-checkout"]
    if cache:
        # A cache supplies committed objects only; working-tree outputs are never used.
        clone.append("--shared")
    clone.extend([source, "."])
    _run(ctx, clone)
    parts = ["tools", "public", "base/ntos", "base/hals", "base/boot", "base/published", "base/busdrv", "base/fs", "base/inc", "base/win32/inc", "base/win32/winnls/data", "drivers", "ds/security", "windows/appcompat/sdbapi", "sdktools/mc"]
    _run(ctx, [str(git), "sparse-checkout", "set"] + ["Source/XPSP1/NT/" + p for p in parts])
    _run(ctx, [str(git), "checkout", "--detach", ctx.attr.commit])
    for patch in ctx.attr.patches:
        ctx.read(patch)
        _run(ctx, [str(git), "apply", "--whitespace=nowarn", str(ctx.path(patch))])
    for variant in ["picacpi", "apic", "mpapic"]:
        ctx.file("Source/XPSP1/NT/base/hals/halacpi/" + variant + "/empty.src", "")
    if "linux" in ctx.os.name.lower():
        wibo = ctx.os.environ.get("WIBO", "") or ctx.which("wibo")
        if not wibo:
            fail("Linux kernel builds require wibo on PATH or --repo_env=WIBO=/path/to/wibo")
        wibo_path = str(wibo).replace("'", "'\"'\"'")
        wibo_hdr = "#!/usr/bin/env bash\nset -euo pipefail\nif [ -z \"${WIBO:-}\" ]; then WIBO='" + wibo_path + "'; fi\n"
        wine = ctx.os.environ.get("WINE", "") or ctx.which("wine")
        if not wine:
            fail("Linux resource/message compilation requires Wine on PATH or --repo_env=WINE=/path/to/wine")
        wine_path = str(wine).replace("'", "'\"'\"'")
        wine_hdr = "#!/usr/bin/env bash\nset -euo pipefail\nexport WINEDEBUG=-all\nexport WINEDLLOVERRIDES=\"mscoree,mshtml=;${WINEDLLOVERRIDES:-}\"\nexport WINEPREFIX=\"${WINEPREFIX:-$HOME/.cache/nt51-wine-prefixes/messages}\"\nmkdir -p \"$(dirname \"$WINEPREFIX\")\"\nWINE='" + wine_path + "'\n"
        ctx.file("bazel/legacy/cl_wrapper.cmd", wibo_hdr + 'export PATH="$1:$PATH"\nexec "$WIBO" "$1/cl.exe" @"$2"\n', executable = True)
        ctx.file("bazel/legacy/lib_wrapper.cmd", wibo_hdr + 'export PATH="$1:$PATH"\nexec "$WIBO" "$1/lib.exe" @"$2"\n', executable = True)
        ctx.file("bazel/legacy/ml_wrapper.cmd", wibo_hdr + 'export PATH="$1:$PATH"\nexec "$WIBO" "$1/ml.exe" @"$2"\n', executable = True)
        ctx.file("bazel/legacy/genlvl_wrapper.cmd", wibo_hdr + 'TOOL="$(realpath "$1")"\nINDIR="$(realpath "$2")"\nmkdir -p "$3"\nOUTDIR="$(realpath --relative-to="$2" "$3")"\nexport PATH="$(dirname "$TOOL"):$PATH"\ncd "$INDIR"\nexec "$WIBO" "$TOOL" -t "$OUTDIR"\n', executable = True)
        ctx.file("bazel/legacy/ke_services_wrapper.cmd", wibo_hdr + 'TOOLDIR="$(realpath "$1")"\nSRC="$2"\nmkdir -p "$3"\nOUTDIR="$3"\nSTUBDIR="$4"\nexport PATH="$TOOLDIR:$PATH"\n"$WIBO" "$TOOLDIR/cl.exe" /nologo /EP /D_X86_=1 /Di386=1 "$SRC" > "$OUTDIR/services.tab"\ncp -f "$STUBDIR/table.stb" "$OUTDIR/table.stb"\ncp -f "$STUBDIR/services.stb" "$OUTDIR/services.stb"\ncd "$OUTDIR"\nexec "$WIBO" "$TOOLDIR/gensrv.exe" -e asm -g .\n', executable = True)
        # The linker maps temporary files at addresses returned by VirtualAlloc;
        # wibo's arena allocator cannot currently remap those released ranges.
        ctx.file("bazel/legacy/kernel_link_wrapper.cmd", wine_hdr + '''export PATH="$1:$PATH"
# Each Bazel action must own its Wine services: another action's process
# cleanup would otherwise kill the shared server during a link.
if [ "$WINEPREFIX" = "$HOME/.cache/nt51-wine-prefixes/messages" ]; then
    export WINEPREFIX="$HOME/.cache/nt51-wine-prefixes/link-$(basename "$3")"
fi
mkdir -p "$(dirname "$WINEPREFIX")"
rm -f -- "$3"
"$WINE" "$1/link.exe" @"$2"
"$WINE" "$1/link.exe" -edit -nologo -section:.rsrc,!d "$3"
python3 - "$3" <<'PY'
import struct, sys
from pathlib import Path
data = Path(sys.argv[1]).read_bytes()
if len(data) < 64 or data[:2] != b'MZ':
    raise SystemExit('Linker did not produce a DOS/PE header: ' + sys.argv[1])
offset = struct.unpack_from('<I', data, 60)[0]
if offset + 26 > len(data) or data[offset:offset + 4] != bytes([80, 69, 0, 0]):
    raise SystemExit('Linker did not produce a valid PE signature: ' + sys.argv[1])
if struct.unpack_from('<H', data, offset + 4)[0] != 0x14c:
    raise SystemExit('Linker did not produce an i386 PE image: ' + sys.argv[1])
PY
''', executable = True)
        ctx.file("bazel/legacy/preprocess_wrapper.cmd", wibo_hdr + 'export PATH="$1:$PATH"\nif [ -n "${5:-}" ]; then cat "$4" "$5" > "$3.pp"; fi\nrc=0\n"$WIBO" "$1/cl.exe" @"$2" > "$3" || rc=$?\nrm -f "$3.pp"\nexit $rc\n', executable = True)
        # RC requires a wibo version with CharNextA and Wine CRT DLL support.
        ctx.file("bazel/legacy/rc_wrapper.cmd", wibo_hdr + '''TOOLDIR="$(echo external/*nt51*/Source/XPSP1/NT/tools/x86)"
export PATH="$TOOLDIR:$PATH"
ARGS=("$@")
OUTPUT=''
for ((i=0;i<${#ARGS[@]}-1;i++)); do
    if [ "${ARGS[i],,}" = /fo ]; then OUTPUT="${ARGS[i+1]}"; fi
done
"$WIBO" "$TOOLDIR/rc.exe" "$@"
test -n "$OUTPUT" && test -s "$OUTPUT"
''', executable = True)
        # The historical MC uses the wrong CharPrev buffer for -r/-x paths.
        # Run in the declared output directory with short, local filenames.
        ctx.file("bazel/legacy/mc_wrapper.cmd", wine_hdr + '''TOOLDIR="$(echo external/*nt51*/Source/XPSP1/NT/tools/x86)"
TOOL="$(realpath "$TOOLDIR/mc.exe")"
ARGS=("$@")
SOURCE="$(realpath "${ARGS[-1]}")"
NAME="$(basename "$SOURCE")"
mkdir -p "$2"
cp "$SOURCE" "$2/$NAME"
cd "$2"
ARGS[1]='.'
ARGS[3]='./'
ARGS[${#ARGS[@]}-1]="$NAME"
"$WINE" "$TOOL" "${ARGS[@]//\\//\\\\}"
test -s "${NAME%.*}.h"
test -s "${NAME%.*}.rc"
rm -- "$NAME"
''', executable = True)
        ctx.file("bazel/legacy/generr_wrapper.cmd", wibo_hdr + 'TOOLDIR="$(echo external/*nt51*/Source/XPSP1/NT/tools/x86)"\nmkdir -p "$(dirname "$2")"\nexport PATH="$TOOLDIR:$PATH"\nexec "$WIBO" "$TOOLDIR/generr.exe" "$@"\n', executable = True)
        bzl_build = ctx.read("bazel/legacy/BUILD.bazel").replace(
            '"ml_wrapper.cmd",',
            '"ml_wrapper.cmd",\n    "rc_wrapper.cmd",\n    "mc_wrapper.cmd",\n    "generr_wrapper.cmd",',
        )
        ctx.file("bazel/legacy/BUILD.bazel", bzl_build)
        rules_bzl = ctx.read("bazel/legacy/nt5_rules.bzl")
        for tool_name in ["rc", "mc", "generr"]:
            rules_bzl = rules_bzl.replace(
                'Label("//Source/XPSP1/NT/tools/x86:' + tool_name + '.exe")',
                'Label("//bazel/legacy:' + tool_name + '_wrapper.cmd")',
            )
        rules_bzl = rules_bzl.replace("use_default_shell_env = False", "use_default_shell_env = True")
        ctx.file("bazel/legacy/nt5_rules.bzl", rules_bzl)
    ctx.file("UPSTREAM_COMMIT", ctx.attr.commit + "\n")

nt51_repository = repository_rule(
    implementation = _nt51_repository_impl,
    attrs = {
        "remote": attr.string(mandatory = True),
        "commit": attr.string(mandatory = True),
        "patches": attr.label_list(allow_files = True),
    },
    environ = ["NT51_GIT_CACHE", "WIBO", "WINE"],
)

def _release_repository_impl(ctx):
    ctx.download_and_extract(
        url = ctx.attr.urls,
        sha256 = ctx.attr.sha256,
        stripPrefix = ctx.attr.strip_prefix,
    )
    for patch in ctx.attr.patches:
        ctx.patch(ctx.path(patch), strip = 1)
    ctx.file("BUILD.bazel", "package(default_visibility=[\"//visibility:public\"])\nexports_files([\"RELEASE\"])\nfilegroup(name=\"sources\",srcs=glob([\"**\"],exclude=[\"BUILD.bazel\"]))\n")
    ctx.file("RELEASE", ctx.attr.strip_prefix + "\n")

release_repository = repository_rule(
    implementation = _release_repository_impl,
    attrs = {
        "urls": attr.string_list(mandatory = True),
        "sha256": attr.string(mandatory = True),
        "strip_prefix": attr.string(mandatory = True),
        "patches": attr.label_list(allow_files = True),
    },
)

def _alpine_repository_impl(ctx):
    entries = json.decode(ctx.read(ctx.attr.manifest))
    for pkg in entries:
        ctx.download(url = pkg["url"], output = "apks/" + pkg["file"], sha256 = pkg["sha256"])
    ctx.file("BUILD.bazel", "package(default_visibility=[\"//visibility:public\"])\nexports_files([\"RELEASE\"])\nfilegroup(name=\"apks\",srcs=glob([\"apks/*.apk\"]))\n")
    ctx.file("RELEASE", "Alpine v3.18 x86\n")

alpine_repository = repository_rule(
    implementation = _alpine_repository_impl,
    attrs = {"manifest": attr.label(allow_single_file = True, mandatory = True)},
)
