"""Verify the CLI result when its host supplies standard-library streams."""

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ethercat_unit"))
try:
    from support import OfflineCase, ec
finally:
    sys.path.pop(0)


class StreamBoundaryTests(OfflineCase):
    def test_cli_classifies_a_real_buffered_write_failure(self):
        stderr = io.StringIO()
        backing = io.BytesIO()
        with io.TextIOWrapper(backing, encoding="utf-8") as stdout:
            with backing.getbuffer(), redirect_stdout(stdout), redirect_stderr(stderr):
                code = ec.main(("-c", "capabilities"))
        self.assertEqual(code, 4)
        self.assertIn("ERROR LOCAL_ERROR", stderr.getvalue())
        self.assertIn("BufferError", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_help_uses_healthy_stdout_with_a_detached_original_wrapper(self):
        # An embedding host can replace stdout after detaching its old wrapper.
        original = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        actual = io.StringIO()
        diagnostics = io.StringIO()
        with original.detach():
            with patch.object(sys, "__stdout__", original), redirect_stdout(actual), redirect_stderr(diagnostics):
                code = ec.main(("--help",))
        self.assertEqual(code, 0)
        self.assertIn("usage: ethercat_master.py", actual.getvalue())
        self.assertIn("--command", actual.getvalue())
        self.assertEqual(diagnostics.getvalue(), "")
