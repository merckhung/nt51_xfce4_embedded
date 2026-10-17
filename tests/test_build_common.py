# SPDX-License-Identifier: GPL-2.0-only
import os
import signal
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from build_common import run


class CommandOutputTest(unittest.TestCase):
    def test_service_child_does_not_hold_tool_output_open(self):
        with tempfile.TemporaryDirectory() as directory:
            done = Path(directory) / "service-finished"
            child = "import time; from pathlib import Path; time.sleep(5); Path(%r).touch()" % str(done)
            parent = "import subprocess, sys; p=subprocess.Popen([sys.executable, '-c', %r]); print(p.pid, flush=True)" % child
            pid = int(run([sys.executable, "-c", parent]).strip())
            try:
                self.assertFalse(done.exists(), "tool output waited for the service process")
            finally:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass

    def test_failure_preserves_stdout_and_stderr(self):
        with self.assertRaisesRegex(RuntimeError, "tool failed"):
            run([sys.executable, "-c", "import sys; print('tool failed', file=sys.stderr); sys.exit(7)"])


if __name__ == "__main__":
    unittest.main()
