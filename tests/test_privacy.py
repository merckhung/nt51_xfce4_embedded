# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("audit_privacy", Path(__file__).resolve().parents[1] / "tools/audit_privacy.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class PrivacyTests(unittest.TestCase):
    def test_personal_paths_in_both_encodings(self):
        text = "/" + "home/" + "example-builder/project/file.cc"
        for encoding in ("utf-8", "utf-16le"):
            self.assertIn("personal_path", audit.scan_bytes(text.encode(encoding)))

    def test_windows_and_mapped_unix_paths(self):
        for directory in ("Users", "home"):
            text = "Z:" + chr(92) + directory + chr(92) + "example-builder" + chr(92) + "project"
            for encoding in ("utf-8", "utf-16le"):
                self.assertIn("personal_path", audit.scan_bytes(text.encode(encoding)))

    def test_credentials_are_detected_without_reporting_values(self):
        token = b"ghp_" + b"A" * 36
        self.assertEqual({"credential"}, audit.scan_bytes(token))
        self.assertEqual({"credential"}, audit.scan_bytes(token.decode().encode("utf-16le")))

    def test_identity_checks_are_case_insensitive(self):
        address = b"developer" + b"@example.invalid"
        self.assertEqual({"personal_email"}, audit.scan_bytes(address.upper(), [address]))
        self.assertEqual({"machine_identifier"}, audit.scan_bytes(b"BUILD-NODE", machine_names=[b"build-node"]))

    def test_product_urls_and_copyright_are_retained(self):
        text = b"Copyright The Chromium Authors; Google Inc.; https://example.invalid/home/help/"
        self.assertEqual(set(), audit.scan_bytes(text))
        runtime_path = b"/" + b"home/cid/"
        self.assertEqual(set(), audit.scan_bytes(runtime_path, chromium_runtime=True))
        self.assertIn("personal_path", audit.scan_bytes(runtime_path))

    def test_nested_machine_metadata_is_rejected(self):
        self.assertTrue(audit.has_private_metadata({"records": [{"build_host": "example"}]}))
        self.assertFalse(audit.has_private_metadata({"target": {"os": "linux", "cpu": "x86"}}))
