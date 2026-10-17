# SPDX-License-Identifier: GPL-2.0-only
"""Verifier rejection tests using synthetic serial logs, not guest evidence."""
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "qemu", Path(__file__).resolve().parents[1] / "tools/qemu.py")
qemu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qemu)

BASE = """Subsystem Suites: 9 total | 9 passed | 0 failed
Individual Tests: 54 total | 54 passed | 0 failed
[init] NTTEST_EXIT=0
[rc.sysinit] PS_AUX_EXIT=0
[x11_fb_bridge] XTEST ready op=1
[rc.sysinit] SWIFTSHADER_PROBE_EXIT=0
[rc.sysinit] CHROMIUM_HEADLESS_EXIT=0
[rc.sysinit] CHROMIUM_HEADLESS_TIMED_OUT=0
[rc.sysinit] Headless DOM: NT51_JS_RESULT_42_71
[rc.sysinit] CHROMIUM_HEADLESS_DOM_VALID=1
[xfce-probe] CHROMIUM_TITLE=Yahoo - Chromium
[netd] ready
[netd] tcp connect 1.2.3.4:443
[netd] tcp established 1.2.3.4:443
[netd] tcp received data 1.2.3.4:443
[xfce-probe] READY top_panel=1 bottom_panel=1 terminal=1 desktop=1 chromium=1
"""


class VerifierTest(unittest.TestCase):
    def verify(self, serial):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "tools").mkdir()
            image = project / "test.img"
            image.write_bytes(b"test image")

            def spawn(command, cwd):
                (project / "runtime/chromium/serial.log").write_text(serial)
                return 123

            with patch.object(qemu, "__file__", str(project / "tools/qemu.py")), \
                 patch.object(sys, "argv", ["qemu.py", "chromium", "--verify", "--headless", "--image", str(image)]), \
                 patch.dict(qemu.os.environ, {"QEMU_BINARY": sys.executable}), \
                 patch.object(qemu, "spawn", side_effect=spawn), \
                 patch.object(qemu, "QMP"), \
                 patch.object(qemu.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
                try:
                    qemu.main()
                except SystemExit as error:
                    self.assertEqual(error.code, 1)
            return json.loads((project / "runtime/chromium/verification.json").read_text())

    def test_complete_evidence_passes(self):
        self.assertTrue(self.verify(BASE)["passed"])

    def test_unavailable_browser_launcher_fails(self):
        result = self.verify(BASE + 'sh: /opt/chromium/run_chromium.sh: No such file or directory\n')
        self.assertFalse(result['passed'])
        self.assertIn('launcher unavailable', result['error'])

    def test_missing_or_wrong_browser_evidence_fails(self):
        replacements = [
            ("CHROMIUM_HEADLESS_EXIT=0", "CHROMIUM_HEADLESS_EXIT=137"),
            ("CHROMIUM_HEADLESS_TIMED_OUT=0", "CHROMIUM_HEADLESS_TIMED_OUT=1"),
            ("[rc.sysinit] CHROMIUM_HEADLESS_TIMED_OUT=0", ""),
            ("Headless DOM: NT51_JS_RESULT_42_71", "Headless DOM: NT51_JS_RESULT_42_99"),
            ("CHROMIUM_HEADLESS_DOM_VALID=1", "CHROMIUM_HEADLESS_DOM_VALID=0"),
            ("CHROMIUM_TITLE=Yahoo - Chromium", "CHROMIUM_TITLE=Error - Chromium"),
            ("[netd] tcp established 1.2.3.4:443", ""),
            ("[netd] tcp received data 1.2.3.4:443", ""),
            ("[netd] ready", ""),
            ("chromium=1", "chromium=0"),
        ]
        for before, after in replacements:
            with self.subTest(missing=before):
                self.assertFalse(self.verify(BASE.replace(before, after))["passed"])


if __name__ == "__main__":
    unittest.main()
