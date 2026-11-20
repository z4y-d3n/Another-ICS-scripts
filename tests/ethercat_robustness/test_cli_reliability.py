"""Reliability checks for the offline command line and its output streams."""

from contextlib import redirect_stderr, redirect_stdout
import io
import logging
from pathlib import Path
import sys
from unittest import TestCase
from unittest.mock import Mock, patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ethercat_integration"))
try:
    from integration_support import OfflineCase, ec, run_cli, vectors
finally:
    sys.path.pop(0)


OUTPUT_LIMIT = 16 * 1024
CAPABILITIES_DEBUG = ("-c", "capabilities", "--debug")


class CliReliabilityTests(OfflineCase):
    def invoke(self, args, *, stdout=None, stderr=None):
        stdout = io.StringIO() if stdout is None else stdout
        stderr = io.StringIO() if stderr is None else stderr
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = ec.main(args)
        self.assertIs(type(code), int)
        return code, stdout, stderr

    def assert_usage_error(self, args, reason):
        code, stdout, stderr = self.invoke(args)
        err = stderr.getvalue()
        self.assertEqual((code, stdout.getvalue()), (2, ""))
        self.assertIn("usage:", err)
        self.assertNotIn("Traceback", err)
        self.assertLessEqual(len(err.encode("utf-8")), OUTPUT_LIMIT)
        diagnostic = err.splitlines()[-1]
        self.assertTrue(diagnostic.startswith("ERROR USAGE_ERROR "))
        self.assertIn(reason, diagnostic)

    def test_invalid_argument_values_stop_before_offline_operations(self):
        inspect_args = ("-c", "inspect")
        timeout_args = ("-c", "simulate", "--scenario", "timeout")
        cases = (
            (inspect_args + ("--hex",), "expected one argument"),
            (inspect_args + ("--hex=",), "2..3028"),
            (inspect_args + ("--hex", "０１"), "ASCII hexadecimal"),
            (("-c", "capabilities", "--command=capabilities"), "only once"),
            (timeout_args + ("--timeout=",), "timeout requires decimal seconds"),
            (timeout_args + ("--timeout=NaN",), "timeout requires decimal seconds"),
            (timeout_args + ("--timeout=-Infinity",), "timeout requires decimal seconds"),
            (timeout_args + ("--timeout=1,0",), "timeout requires decimal seconds"),
            (timeout_args + ("--timeout=10.000000000000000001",), "finite and between"),
        )
        operations = {
            name: Mock(side_effect=AssertionError(f"usage error invoked {name}"))
            for name in ("inspect_frame", "simulate", "report_capabilities")
        }
        with patch.multiple(ec, **operations):
            for args, reason in cases:
                with self.subTest(args=args):
                    self.assert_usage_error(args, reason)
        for operation in operations.values():
            operation.assert_not_called()

    def test_argument_budget_counts_attached_options_and_accepts_exact_limits(self):
        frame = vectors.single_payload(bytes(1486)).hex()
        self.assertEqual(len(frame), 3028)
        compact = ("--command=inspect", f"--hex={frame}") + ("--debug",) * 14
        self.assertEqual(len(compact), 16)
        separate = ("-c", "inspect", "--hex", frame, "--debug")
        code, stdout, stderr = self.invoke(separate)
        self.assertEqual(code, 0)
        self.assertIn("OK (0) mode=inspect source=offline-input phase=inspect", stdout.getvalue())
        self.assertIn("Len=1486", stdout.getvalue())
        self.assertIn("structural inspection completed", stderr.getvalue())
        expected = stdout.getvalue(), stderr.getvalue()
        self.assertLessEqual(sum(len(text.encode("utf-8")) for text in expected), OUTPUT_LIMIT)
        code, stdout, stderr = self.invoke(compact)
        self.assertEqual((code, stdout.getvalue(), stderr.getvalue()), (0, *expected))

        for boundary, args, reason in (
            ("count", compact + ("--debug",), "CLI limits"),
            ("attached token", ("-c", "inspect", f"--hex={frame}0"), "CLI limits"),
            ("separate value", ("-c", "inspect", "--hex", f"{frame}0"), "2..3028"),
        ):
            with self.subTest(boundary=boundary):
                self.assert_usage_error(args, reason)

    def test_cli_diagnostics_are_independent_of_host_logging_cutoff(self):
        root = logging.getLogger()
        self.addCleanup(logging.disable, root.manager.disable)
        self.addCleanup(logging.setLogRecordFactory, logging.getLogRecordFactory())
        host_factory = Mock(side_effect=AssertionError("CLI reached the host's log record factory"))
        logging.setLogRecordFactory(host_factory)
        root_state = (root.level, root.handlers[:], root.filters[:], root.disabled, root.propagate)
        cases = (
            (("--unknown-option",), 2, ("ERROR USAGE_ERROR", "unrecognized arguments")),
            (CAPABILITIES_DEBUG, 0, ("INFO OK", "DEBUG phase=report source=local")),
            (("-c", "capabilities"), 0, ()),
        )
        for args, expected_code, diagnostics in cases:
            with self.subTest(args=args):
                outputs = []
                for cutoff in (logging.NOTSET, logging.CRITICAL):
                    logging.disable(cutoff)
                    code, stdout, stderr = self.invoke(args)
                    self.assertEqual(code, expected_code)
                    self.assertEqual(root.manager.disable, cutoff)
                    self.assertIs(logging.getLogRecordFactory(), host_factory)
                    self.assertEqual((root.level, root.handlers, root.filters, root.disabled, root.propagate), root_state)
                    outputs.append((stdout.getvalue(), stderr.getvalue()))
                self.assertEqual(outputs[0], outputs[1])
                for diagnostic in diagnostics:
                    self.assertEqual(outputs[1][1].count(diagnostic), 1)
                if not diagnostics:
                    self.assertEqual(outputs[1][1], "")
        host_factory.assert_not_called()

    def test_stream_encoding_preserves_whole_utf8_characters_or_reports_the_cause(self):
        content = "CLI fixture\n" + "🙂" * 4200
        marker = "\n[output limited]\n"
        for encoding, expected_code in (("utf-8", 0), ("ascii", 4)):
            with self.subTest(encoding=encoding):
                buffer = io.BytesIO()
                with io.TextIOWrapper(buffer, encoding=encoding, newline="\n") as stream:
                    with patch.object(ec, "format_result", return_value=content):
                        code, _, stderr = self.invoke(CAPABILITIES_DEBUG, stdout=stream)
                    self.assertFalse(stream.closed)
                    output_bytes = buffer.getvalue()
                err = stderr.getvalue()
                self.assertEqual(code, expected_code)
                self.assertLessEqual(len(output_bytes) + len(err.encode("utf-8")), OUTPUT_LIMIT)
                self.assertNotIn("Traceback", err)
                if encoding == "utf-8":
                    # 12 KiB minus the 12-byte prefix and 18-byte marker fit 3064 whole emoji.
                    self.assertEqual(output_bytes.decode("utf-8"), "CLI fixture\n" + "🙂" * 3064 + marker)
                    self.assertIn("DEBUG phase=report source=local", err)
                else:
                    self.assertEqual(output_bytes, b"")
                    self.assertIn("ERROR LOCAL_ERROR UnicodeEncodeError:", err)

    def test_owned_handler_is_closed_if_diagnostic_flush_fails_or_is_interrupted(self):
        root = logging.getLogger()
        host_output = io.StringIO()
        host_handler = logging.StreamHandler(host_output)
        self.addCleanup(host_handler.close)
        root.addHandler(host_handler)
        self.addCleanup(root.removeHandler, host_handler)
        root_handlers = root.handlers[:]

        for fault, expected_code, fallback in (
            (OSError("diagnostic flush failed"), 4, ("ERROR LOCAL_ERROR OSError: diagnostic flush failed",)),
            (KeyboardInterrupt(), 130, ()),
        ):
            with self.subTest(fault=type(fault).__name__):
                stderr = io.StringIO()
                handler = ec._DiagnosticHandler(stderr)
                with (
                    patch.object(ec, "_DiagnosticHandler", return_value=handler),
                    patch.object(handler, "close", wraps=handler.close) as close,
                    patch.object(stderr, "flush", side_effect=(fault, None)),
                ):
                    code, stdout, _ = self.invoke(CAPABILITIES_DEBUG, stderr=stderr)
                    close.assert_called_once_with()
                self.assertEqual(code, expected_code)
                self.assertIn("OK (0) mode=capabilities", stdout.getvalue())
                self.assertEqual(
                    stderr.getvalue().splitlines(),
                    ["INFO OK [capabilities] local capability report", *fallback],
                )
                self.assertFalse(stdout.closed)
                self.assertFalse(stderr.closed)
                self.assertEqual(root.handlers, root_handlers)
                self.assertEqual(host_output.getvalue(), "")


class CliArgvProcessTests(TestCase):
    def test_empty_value_and_bounded_unicode_diagnostic_cross_os_argv(self):
        cases = (
            (("-c", "inspect", "--hex", ""), "hex input must contain 2..3028", False),
            (("--démo-漢🙂=" + "x" * 300,), "unrecognized arguments: --d?mo-??=", True),
        )
        for args, expected, clipped in cases:
            with self.subTest(diagnostic=expected):
                code, stdout, stderr = run_cli(args)
                self.assertEqual((code, stdout), (2, b""))
                self.assertLessEqual(len(stdout) + len(stderr), OUTPUT_LIMIT)
                err = stderr.decode("utf-8")
                for marker in ("Traceback", "Exception ignored", "OFFLINE GUARD", "prohibited effects"):
                    self.assertNotIn(marker, err)
                self.assertIn("usage:", err)
                diagnostic = err.splitlines()[-1]
                self.assertTrue(diagnostic.startswith("ERROR USAGE_ERROR "))
                self.assertIn(expected, diagnostic)
                if clipped:
                    self.assertTrue(diagnostic.endswith("..."))
                    self.assertLessEqual(len(diagnostic), 262)
