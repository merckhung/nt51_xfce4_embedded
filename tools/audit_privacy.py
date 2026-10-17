# SPDX-License-Identifier: GPL-2.0-only
"""Check publishable files without printing matched private data."""
import argparse
import json
from pathlib import Path
import re
import socket
import subprocess


PATTERNS = {
    "private_key": rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "credential": rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35})",
    "personal_path": rb"(?<![A-Za-z0-9:/])/(?:home|Users)/([^/\s\x00]+)/|[A-Za-z]:[\\/](?:Users|home)[\\/][^\\/\s\x00]+[\\/]",
}
PRIVATE_METADATA_KEYS = {"source_directory", "build_host", "build_environment", "hostname"}


def scan_bytes(data, forbidden_addresses=(), machine_names=(), chromium_runtime=False):
    findings = set()
    # Removing NUL bytes also exposes ASCII identifiers stored as UTF-16.
    for content in (data, data.replace(b"\0", b"")):
        for category, pattern in PATTERNS.items():
            for match in re.finditer(pattern, content):
                # This is an upstream ChromeOS runtime path, not a build path.
                if category == "personal_path" and chromium_runtime and match.group(1) == b"cid":
                    continue
                findings.add(category)
        lower = content.lower()
        if any(address.lower() in lower for address in forbidden_addresses):
            findings.add("personal_email")
        if any(re.search(rb"(?<![A-Za-z0-9_-])" + re.escape(name) + rb"(?![A-Za-z0-9_-])", content, re.I)
               for name in machine_names):
            findings.add("machine_identifier")
    return findings


def has_private_metadata(value):
    if isinstance(value, dict):
        return bool(PRIVATE_METADATA_KEYS.intersection(value)) or any(has_private_metadata(v) for v in value.values())
    return isinstance(value, list) and any(has_private_metadata(v) for v in value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print only categories and repository-relative filenames")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=root)
    files = set(git("ls-files", "--cached", "--others", "--exclude-standard", "-z").decode().split("\0")) - {""}
    emails = set(git("log", "--all", "--format=%ae%n%ce").lower().splitlines())
    forbidden = {email.partition(b"@")[0] + b"@google.com" for email in emails if b"@" in email}
    name = socket.gethostname().encode()
    machines = [name] if len(name) >= 6 and name.lower() not in (b"localhost", b"localhost.localdomain") else []
    findings = {}
    for relative in sorted(files):
        path = root / relative
        if not path.is_file():
            continue
        content = path.read_bytes()
        categories = scan_bytes(content, forbidden, machines,
                                chromium_runtime=relative.startswith("chromium_rootfs/pkg/opt/chromium/"))
        if path.suffix == ".json" and has_private_metadata(json.loads(content)):
            categories.add("private_metadata")
        if categories:
            findings[relative] = sorted(categories)
    if emails.intersection(forbidden):
        findings["<reachable commit metadata>"] = ["personal_email"]
    result = {"passed": not findings, "files_checked": sum((root / p).is_file() for p in files), "findings": findings}
    print(json.dumps(result, indent=2) if args.json else
          ("Privacy audit passed" if result["passed"] else "Privacy audit failed: " + json.dumps(findings)))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
