# SPDX-License-Identifier: GPL-2.0-only
"""Declared Bazel actions for boot support, native runtime and the two root filesystems."""

def _build_impl(ctx):
    output = ctx.actions.declare_directory(ctx.label.name + ".files")
    args = [ctx.file._builder.path, ctx.attr.operation, "--out", output.path, "--config", ctx.file.config.path]
    # A JSON argument file avoids Windows command line limits and shell quoting.
    config = ctx.actions.declare_file(ctx.label.name + ".inputs.json")
    values = {"operation": ctx.attr.operation, "out": output.path, "handler": ctx.file.handler.path}
    for name in ["nt", "musl", "busybox", "alpine"]:
        marker = getattr(ctx.file, name)
        if marker:
            values[name] = marker.dirname
    values["project"] = ctx.file.config.dirname + "/.."
    values["deps"] = [f.path for dep in ctx.attr.deps for f in dep[DefaultInfo].files.to_list()]
    ctx.actions.write(config, json.encode(values))
    ctx.actions.run(
        executable = ctx.executable._runner,
        arguments = [ctx.file._builder.path, config.path],
        inputs = depset([config, ctx.file._builder, ctx.file._common, ctx.file.handler, ctx.file.config] + ctx.files.srcs, transitive = [dep[DefaultInfo].files for dep in ctx.attr.deps]),
        outputs = [output],
        mnemonic = "Nt51Embedded",
        progress_message = "Building %s from declared inputs" % ctx.label,
        use_default_shell_env = True,
    )
    return [DefaultInfo(files = depset([output]))]

embedded_build = rule(
    implementation = _build_impl,
    attrs = {
        "operation": attr.string(mandatory = True),
        "handler": attr.label(allow_single_file = True, mandatory = True),
        "config": attr.label(allow_single_file = True, mandatory = True),
        "srcs": attr.label_list(allow_files = True),
        "deps": attr.label_list(),
        "nt": attr.label(allow_single_file = True),
        "musl": attr.label(allow_single_file = True),
        "busybox": attr.label(allow_single_file = True),
        "alpine": attr.label(allow_single_file = True),
        "_builder": attr.label(default = "//tools:build.py", allow_single_file = True),
        "_common": attr.label(default = "//tools:build_common.py", allow_single_file = True),
        "_runner": attr.label(default = "//tools:run.cmd", executable = True, cfg = "exec", allow_single_file = True),
    },
)
