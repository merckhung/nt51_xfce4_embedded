<!-- SPDX-License-Identifier: GPL-2.0-only -->
# License header review

The review covered the 188 files originally tracked in this repository. It classified files by origin and format before adding license notices.

| Files | Treatment |
| --- | --- |
| 147 project source, build, configuration, documentation and patch files | GPL-2.0-only SPDX headers using the file format's comment syntax |
| 13 project data and image files | GPL-2.0-only metadata in `REUSE.toml`, preserving the required file contents |
| 28 upstream or upstream-derived inputs and license texts | Preserved byte for byte |

The preserved inputs are the 22 generated BusyBox headers, both BusyBox configurations, the GNU license text, musl's copyright notice, the D-Bus session configuration and XFWM defaults. They retain their upstream licensing; the project header rule does not relicense these inputs. The NT source dependency, downloaded musl and BusyBox sources, and Alpine packages are outside this repository and retain their component licenses.

Patch headers apply to the project's changes. Upstream source context in a patch retains its original license. The native syscall generator emits license headers in its generated assembly, export definition and C header. The musl header generator preserves musl's licensing for generated musl declarations.

Shebangs and XML declarations stay first. Strict JSON, version files, account data, machine identifiers, message text and PNG assets use metadata rather than injected comments. No copyright owner or authorship was invented.

Project comments and documentation use repository-relative locations and portable build examples. The QEMU launcher discovers the executable through `PATH` or `QEMU_BINARY`. Absolute guest NT paths are part of the operating system's runtime behavior.

The audit report and its `REUSE.toml` metadata are also GPL-2.0-only. See [THIRD_PARTY.md](../THIRD_PARTY.md) for component boundaries and external binary build inputs.
