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
    parts = ["tools", "public", "base/ntos", "base/hals", "base/boot", "base/published", "base/busdrv", "base/fs", "base/inc", "base/win32/inc", "base/win32/winnls/data", "drivers", "ds/security", "windows/appcompat/sdbapi"]
    _run(ctx, [str(git), "sparse-checkout", "set"] + ["Source/XPSP1/NT/" + p for p in parts])
    _run(ctx, [str(git), "checkout", "--detach", ctx.attr.commit])
    for patch in ctx.attr.patches:
        ctx.read(patch)
        _run(ctx, [str(git), "apply", "--whitespace=nowarn", str(ctx.path(patch))])
    for variant in ["picacpi", "apic", "mpapic"]:
        ctx.file("Source/XPSP1/NT/base/hals/halacpi/" + variant + "/empty.src", "")
    ctx.file("UPSTREAM_COMMIT", ctx.attr.commit + "\n")

nt51_repository = repository_rule(
    implementation = _nt51_repository_impl,
    attrs = {
        "remote": attr.string(mandatory = True),
        "commit": attr.string(mandatory = True),
        "patches": attr.label_list(allow_files = True),
    },
    environ = ["NT51_GIT_CACHE"],
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
