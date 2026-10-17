# SPDX-License-Identifier: GPL-2.0-only
"""Run the boot script against fake executables to audit reported statuses."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


class HeadlessStatusTest(unittest.TestCase):
    def run_script(self, dom, status, force_timeout=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, body in {
                "chrome": "exit 0",
                "swiftshader_probe": "exit 0",
                "chromium": "exit 0",
                "chromium-headless": "cat <<'DOM'\n" + dom + "\nDOM\nexit " + str(status),
                "sleep": 'case "$1" in 1) exec /bin/sleep 0.01;; esac',
            }.items():
                path = root / name
                path.write_text("#!/bin/sh\n" + body + "\n")
                path.chmod(0o755)
            script = (PROJECT / "chromium_rootfs/overlay/opt/chromium/run_chromium.sh").read_text()
            script = script.replace("/tmp/", str(root) + "/")
            script = script.replace("/opt/chromium", str(root))
            script = script.replace("/usr/bin/chromium", str(root / "chromium"))
            if force_timeout:
                script = 'kill() { return 0; }\n' + script
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"])
            return subprocess.run(["sh"], input=script, env=env, text=True,
                                  capture_output=True, timeout=10).stdout

    def test_valid_dom_does_not_replace_failed_exit(self):
        output = self.run_script('<html><div id="r">NT51_JS_RESULT_42_71</div></html>', 7)
        self.assertIn("CHROMIUM_HEADLESS_DOM_VALID=1", output)
        self.assertIn("CHROMIUM_HEADLESS_EXIT=7", output)

    def test_clean_exit_does_not_replace_missing_dom(self):
        output = self.run_script('<html><div id="r">pending</div></html>', 0)
        self.assertIn("CHROMIUM_HEADLESS_DOM_VALID=0", output)
        self.assertIn("CHROMIUM_HEADLESS_EXIT=0", output)

    def test_watchdog_is_reported_even_with_zero_exit_and_valid_dom(self):
        output = self.run_script('<html><div id="r">NT51_JS_RESULT_42_71</div></html>', 0,
                                 force_timeout=True)
        self.assertIn('CHROMIUM_HEADLESS_DOM_VALID=1', output)
        self.assertIn('CHROMIUM_HEADLESS_EXIT=0', output)
        self.assertIn('CHROMIUM_HEADLESS_TIMED_OUT=1', output)


if __name__ == "__main__":
    unittest.main()
