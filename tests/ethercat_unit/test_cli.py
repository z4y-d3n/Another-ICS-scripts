import ast
from contextlib import redirect_stderr, redirect_stdout
import io
import logging
import runpy
import signal
import sys
from unittest.mock import Mock, patch

from linux_fakes import linux_symbols
from support import OfflineCase, SOURCE, ec, load_client
from vectors import CHAINED, MIN_FRAME, nop_chain, single_payload, wrap_chain


class CommandLineTests(OfflineCase):
    def invoke(self, arguments, stdout=None, stderr=None):
        stdout = io.StringIO() if stdout is None else stdout
        stderr = io.StringIO() if stderr is None else stderr
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = ec.main(arguments)
        self.assertIs(type(result), int)
        return result, stdout, stderr

    def test_exit_status_numbers_are_the_public_contract(self):
        self.assertEqual({member.name: int(member) for member in ec.Status}, {
            "OK": 0, "USAGE_ERROR": 2, "UNSUPPORTED": 3, "LOCAL_ERROR": 4, "PROTOCOL_ERROR": 5,
            "TIMEOUT": 6, "UNCORRELATED": 7, "INDETERMINATE": 8, "REJECTED": 9, "INTERRUPTED": 130,
        })

    def test_help_and_default_argv_are_bounded_and_have_no_dispatch(self):
        for flag in ("-h", "--help"):
            with self.subTest(flag=flag):
                with patch.object(sys, "argv", ["ethercat_master.py", flag]), patch.object(ec, "_dispatch") as dispatch:
                    status, out, err = self.invoke(None)
                self.assertEqual((status, err.getvalue()), (0, ""))
                self.assertIn("Diagnose is disabled pending physical interoperability validation", out.getvalue())
                self.assertIn("Exit codes", out.getvalue())
                self.assertLessEqual(len(out.getvalue().encode("utf8")), 16384)
                dispatch.assert_not_called()
        help_output = io.StringIO()
        ec._make_parser().print_help(help_output)
        self.assertIn("Examples", help_output.getvalue())

    def test_bad_arguments_are_rejected_with_usage_without_entering_operational_modes(self):
        cases = (
            ([], "select a mode"),
            (["--unknown"], "unrecognized arguments"),
            (["--scen", "timeout"], "unrecognized arguments"),
            (["-c", "bad"], "invalid choice"),
            (["-c"], "expected one argument"),
            (["-c", "inspect"], "inspect requires --hex"),
            (["-c", "simulate"], "simulate requires --scenario"),
            (["-c", "simulate", "--scenario", "not-known"], "invalid choice"),
            (["-c", "inspect", "--hex", "0"], "even number"),
            (["-c", "inspect", "--hex", "ff", "--hex", "00"], "only once"),
            (["-c", "inspect", "--hex", "ff", "--padding", "unknown"], "invalid choice"),
            (["-c", "inspect", "--timeout", "1", "--hex", "ff"], "--timeout belongs to simulate"),
            (["-c", "simulate", "--scenario", "success", "--padding", "retained"], "--padding belongs to inspect"),
            (["-c", "capabilities", "--hex", "00"], "--hex belongs to inspect"),
            (["-c", "capabilities", "--confirm-bench"], "--confirm-bench belongs to diagnose"),
            (["-c", "capabilities", "-c", "simulate"], "only once"),
            (["-c", "capabilities", "--", "-h"], "unrecognized arguments"),
            (["--debug"] * 17, "CLI limits"),
            (["X" * 3035], "CLI limits"),
            ([42], "CLI limits"),
        )
        replacements = {name: Mock(side_effect=AssertionError(f"unexpected {name}"))
                        for name in ("inspect_frame", "simulate", "report_capabilities", "_LinuxPacketTransport")}
        with patch.multiple(ec, **replacements):
            for args, message in cases:
                with self.subTest(args=args[:5], message=message):
                    status, out, err = self.invoke(args)
                    self.assertEqual((status, out.getvalue()), (2, ""))
                    self.assertIn("usage:", err.getvalue())
                    self.assertIn("ERROR USAGE_ERROR", err.getvalue())
                    self.assertIn(message, err.getvalue())
        for mocked in replacements.values():
            mocked.assert_not_called()

    def test_hex_parser_continuous_ascii_and_size_boundaries(self):
        self.assertEqual(ec.parse_hex("0aFf"), b"\x0a\xff")
        self.assertEqual(ec.parse_hex("f0" * 1514), b"\xf0" * 1514)
        for text, reason in (
            ("", "2..3028"), ("a", "even number"), ("a1f", "even number"), ("a" * 3029, "2..3028"),
            ("0x01", "ASCII hexadecimal"), ("AA BB ", "ASCII hexadecimal"), ("aa:0", "ASCII hexadecimal"),
            ("+001", "ASCII hexadecimal"), ("aa\n ", "ASCII hexadecimal"), ("aa\t ", "ASCII hexadecimal"),
            ("０１", "ASCII hexadecimal"), ("ＡF", "ASCII hexadecimal"), ("aaé0", "ASCII hexadecimal"),
            (None, "2..3028"), (b"00", "2..3028"),
        ):
            with self.subTest(reason=reason, size=len(text) if text is not None else None):
                with self.assertRaisesRegex(ec.UsageError, reason):
                    ec.parse_hex(text)

    def test_decimal_parser_resolves_exact_boundaries_before_float_conversion(self):
        for text, expected in (("0.001", 0.001), (".0010000000000000001", 0.001),
                               ("+1.e-3", 0.001), ("1E+1", 10), ("9.999999999999999999", 10)):
            with self.subTest(text=text):
                self.assertEqual(ec._parse_timeout(text), expected)
        for text in ("NaN", "Inf", "-Infinity", " 1", "1 ", "1_0", "１", "1,0", ".", "1e", ""):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ec.UsageError, "decimal seconds"):
                    ec._parse_timeout(text)
        for text in ("0.000999999999999999999", "10.000000000000000001", "-0.001", "0", "1e999999999999999999999999"):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ec.UsageError, "finite and between"):
                    ec._parse_timeout(text)
        status, out, err = self.invoke(["-c", "simulate", "--scenario", "timeout", "--timeout=1e-3", "--debug"])
        self.assertEqual(status, 6)
        self.assertIn("source=synthetic phase=receive", out.getvalue())
        self.assertIn("elapsed_ns=1000000", err.getvalue())
        status, out, err = self.invoke(["-c", "simulate", "--scenario", "timeout", "--timeout=0.000999999999999999999"])
        self.assertEqual((status, out.getvalue()), (2, ""))
        self.assertIn("finite and between", err.getvalue())

    def test_inspect_structural_result_is_distinct_from_unsupported_and_invalid(self):
        for raw, padding, status, fragment in (
            (CHAINED, [], 0, "logical=0x12345678"),
            (MIN_FRAME + bytes(32), ["--padding", "retained"], 0, "padding=retained (32 bytes)"),
            (MIN_FRAME[:-1], [], 5, "PROTOCOL_ERROR (5)"),
            (MIN_FRAME + bytes(32), [], 5, "PROTOCOL_ERROR (5)"),
            (MIN_FRAME[:12] + b"\x81\x00", [], 3, "UNSUPPORTED (3)"),
        ):
            with self.subTest(status=status, fragment=fragment):
                rc, out, err = self.invoke(["-c", "inspect", f"--hex={raw.hex()}", *padding])
                self.assertEqual(rc, status)
                self.assertIn(fragment, out.getvalue())
                self.assertIn("mode=inspect source=offline-input phase=inspect", out.getvalue())
                if status == 0:
                    self.assertEqual(err.getvalue(), "")
                else:
                    self.assertIn("ERROR" if status == 5 else "WARNING", err.getvalue())
        max_raw = single_payload(b"\x9a" * 1486)
        rc, out, err = self.invoke(["-c", "inspect", "--hex=" + max_raw.hex(), "--debug"])
        self.assertEqual(rc, 0)
        self.assertIn("Len=1486", out.getvalue())
        self.assertNotIn("9a" * 64, out.getvalue() + err.getvalue())
        self.assertLess(len((out.getvalue() + err.getvalue()).encode("utf8")), 16384)

    def test_cli_simulation_status_and_logging_levels_are_contextual(self):
        for scenario, code, level, detail in (
            ("success", 0, "INFO", "WKC expected=1 observed=1"),
            ("timeout", 6, "WARNING", "observed=unavailable"),
            ("uncorrelated", 7, "WARNING", "attribution=foreign"),
            ("wkc-mismatch", 8, "WARNING", "WKC expected=1 observed=0"),
            ("invalid", 5, "ERROR", "Return structure=invalid"),
            ("rejected", 9, "WARNING", "attribution=matched"),
        ):
            with self.subTest(scenario=scenario):
                rc, out, err = self.invoke(["-c", "simulate", "--scenario", scenario, "--debug"])
                self.assertEqual(rc, code)
                self.assertIn("mode=simulate source=synthetic", out.getvalue())
                self.assertIn("FPRD fixture delivery=accepted-by-transport", out.getvalue())
                self.assertIn(detail, out.getvalue())
                diagnostics = err.getvalue().splitlines()
                self.assertEqual(len(diagnostics), 2)
                self.assertTrue(diagnostics[0].startswith(level + " "))
                self.assertTrue(diagnostics[1].startswith("DEBUG phase="))
        rc, out, err = self.invoke(["-c", "simulate", "--scenario", "success"])
        self.assertEqual((rc, err.getvalue()), (0, ""))
        self.assertIn("OK (0)", out.getvalue())

    def test_public_modes_never_acquire_and_diagnose_has_no_enablement_switch(self):
        factory = Mock(side_effect=AssertionError("industrial resource requested"))
        backend = Mock(side_effect=AssertionError("native backend constructed"))
        for platform, has_api in (("linux", True), ("linux", False), ("win32", False), ("darwin", False), ("x", False)):
            with self.subTest(platform=platform, has_api=has_api):
                system = linux_symbols(factory)
                if platform == "linux" and not has_api:
                    system.socket = None
                with patch.object(ec.sys, "platform", platform), patch.object(ec, "socket", system), \
                        patch.object(ec, "_LinuxPacketTransport", backend):
                    status, out, _ = self.invoke(["-c", "capabilities"])
                    text = out.getvalue()
                    self.assertEqual(status, 0)
                    self.assertIn(f"Platform={platform} Python={sys.implementation.name}", text)
                    self.assertIn(".".join(map(str, sys.version_info[:3])), text)
                    self.assertIn("symbols present" if has_api else "symbols absent", text)
                    for phrase in ("Native backend: implemented", "Native diagnose: disabled", "Physical interoperability: pending"):
                        self.assertIn(phrase, text)
                    for args, reason in (([], "requires"), (["--interface", "fixture0"], "requires"),
                                         (["--confirm-bench"], "requires"),
                                         (["--interface", "bad/name", "--confirm-bench"], "Linux name")):
                        status, out, err = self.invoke(["-c", "diagnose", *args])
                        self.assertEqual((status, out.getvalue()), (2, ""))
                        self.assertIn(reason, err.getvalue())
                    valid = ["-c", "diagnose", "--interface", "fixture0", "--confirm-bench"]
                    status, out, err = self.invoke(valid)
                    self.assertEqual(status, 3)
                    self.assertIn("mode=diagnose source=local phase=precheck", out.getvalue())
                    self.assertIn("disabled pending physical interoperability validation", err.getvalue())
                    for flag in ("--enable", "--force", "--active", "--profile", "--confirm"):
                        status, out, err = self.invoke(valid + [flag])
                        self.assertEqual((status, out.getvalue()), (2, ""))
                        self.assertIn("unrecognized arguments", err.getvalue())
                    self.assertEqual(self.invoke(["-c", "inspect", "--hex", MIN_FRAME.hex()])[0], 0)
                    self.assertEqual(self.invoke(["-c", "simulate", "--scenario", "success"])[0], 0)
        factory.assert_not_called()
        backend.assert_not_called()

    def test_fifteen_rows_fit_and_utf8_budget_handles_partial_codepoints(self):
        rc, out, err = self.invoke(["-c", "inspect", "--hex", wrap_chain(nop_chain(15)).hex(), "--debug"])
        self.assertEqual(rc, 0)
        self.assertEqual(sum(line.startswith("  byte ") for line in out.getvalue().splitlines()), 15)
        self.assertLessEqual(len((out.getvalue() + err.getvalue()).encode("utf8")), 16 * 1024)
        for size in (16_383, 16_384, 16_385):
            with self.subTest(size=size):
                stream = io.StringIO()
                body = ("a" if size % 2 else "") + ("é" * (size // 2))
                ec._write_bounded(stream, body, 16 * 1024)
                rendered = stream.getvalue()
                self.assertLessEqual(len(rendered.encode("utf8")), 16 * 1024)
                if size <= 16_384:
                    self.assertEqual(rendered, body)
                else:
                    self.assertTrue(rendered.endswith("\n[output limited]\n"))
                    self.assertEqual(rendered.split("\n")[0], "a" + "é" * 8182)
                    self.assertNotIn("\ufffd", rendered)
        out, err = io.StringIO(), io.StringIO()
        reason = "é\n" + "A" * 5_000
        result = ec.OperationResult(ec.Status.PROTOCOL_ERROR, ec.Mode.INSPECT, ec.Origin.OFFLINE_INPUT,
                                    ec.Phase.INSPECT, reason, cleanup=ec.CleanupFailure(ec.Status.PROTOCOL_ERROR, reason))
        with redirect_stdout(out), redirect_stderr(err), patch.object(ec, "format_result", return_value="漢" * 8_000):
            ec._present(result, True, "é" * 2_000)
        self.assertLessEqual(len((out.getvalue() + err.getvalue()).encode("utf8")), 16 * 1024)
        self.assertTrue(out.getvalue().endswith("[output limited]\n"))
        self.assertEqual(err.getvalue().count("[output limited]"), 1)
        self.assertIn("ERROR cleanup after PROTOCOL_ERROR: ??", err.getvalue())
        self.assertNotIn("A" * 241, err.getvalue())

    def test_logging_uses_one_owned_handler_per_call_and_restores_process_state(self):
        root = logging.getLogger()
        root_state = (root.level, root.handlers[:], root.filters[:], root.disabled, root.propagate)
        handlers = []
        handler_type = ec._DiagnosticHandler

        def create(stream):
            handler = handler_type(stream)
            handler.close = Mock(wraps=handler.close)
            handlers.append(handler)
            return handler

        with patch.object(ec, "_DiagnosticHandler", side_effect=create) as factory:
            for _ in range(2):
                status, _, err = self.invoke(["-c", "simulate", "--scenario", "success", "--debug"])
                self.assertEqual(status, 0)
                self.assertEqual(err.getvalue().count("DEBUG phase="), 1)
                self.assertEqual(err.getvalue().count("INFO OK"), 1)
        self.assertEqual(factory.call_count, 2)
        self.assertIsNot(handlers[0], handlers[1])
        for handler in handlers:
            handler.close.assert_called_once_with()
        self.assertEqual((root.level, root.handlers, root.filters, root.disabled, root.propagate), root_state)

    def test_interruptions_report_130_with_phase_when_available(self):
        command = ["-c", "capabilities"]
        for name in ("_make_parser", "_present"):
            with self.subTest(name=name), patch.object(ec, name, side_effect=KeyboardInterrupt):
                rc, out, err = self.invoke(command)
                self.assertEqual((rc, out.getvalue(), err.getvalue()), (130, "", ""))
        with patch.object(ec._ArgumentParser, "parse_args", side_effect=KeyboardInterrupt):
            rc, out, _ = self.invoke(command)
        self.assertEqual(rc, 130)
        self.assertIn("mode=- source=local phase=validate", out.getvalue())
        with patch.object(ec, "_dispatch", side_effect=KeyboardInterrupt):
            rc, out, _ = self.invoke(command)
        self.assertEqual(rc, 130)
        self.assertIn("mode=capabilities source=local phase=dispatch", out.getvalue())
        bad_stdout = Mock(spec_set=io.StringIO)
        bad_stdout.write.side_effect = BrokenPipeError("output failed")
        bad_stderr = Mock(spec_set=io.StringIO)
        bad_stderr.write.side_effect = KeyboardInterrupt
        self.assertEqual(self.invoke(command, bad_stdout, bad_stderr)[0], 130)
        bad_stdout.write.side_effect = KeyboardInterrupt
        with redirect_stdout(bad_stdout), redirect_stderr(None):
            self.assertEqual(ec.main(command), 130)

    def test_broken_pipes_and_encoding_failures_map_to_local_error(self):
        command = ["-c", "capabilities"]
        for target, method, fault in (
            ("stdout", "write", BrokenPipeError("broken stdout")),
            ("stdout", "flush", BrokenPipeError("failed flush")),
            ("stdout", "write", UnicodeEncodeError("ascii", "é", 0, 1, "encoding fault")),
            ("stderr", "flush", BrokenPipeError("broken stderr")),
            ("stderr", "write", UnicodeEncodeError("ascii", "é", 0, 1, "encoding fault")),
        ):
            with self.subTest(target=target, method=method, fault=fault):
                stream = Mock(spec_set=io.StringIO)
                stream.write.side_effect = len
                getattr(stream, method).side_effect = fault
                rc, out, err = self.invoke(command + ["--debug"], **{target: stream})
                self.assertEqual(rc, 4)
                stream.close.assert_not_called()
                if target == "stdout":
                    self.assertIn("ERROR LOCAL_ERROR", err.getvalue())
                else:
                    self.assertIn("OK (0)", out.getvalue())
        bad_output = Mock(spec_set=io.StringIO)
        bad_output.write.side_effect = OSError("failure")
        bad_diagnostic = Mock(spec_set=io.StringIO)
        bad_diagnostic.write.side_effect = ValueError("closed diagnostic")
        self.assertEqual(self.invoke(command, bad_output, bad_diagnostic)[0], 4)

    def test_buffered_write_failure_preserves_cause_and_maps_to_local_error(self):
        for method in ("write", "flush"):
            with self.subTest(method=method):
                failure = BufferError("fixture buffer has an active view")
                stdout = Mock(spec_set=io.StringIO)
                stdout.write.side_effect = len
                getattr(stdout, method).side_effect = failure
                with self.assertRaises(OSError) as raised:
                    ec._write_text(stdout, "fixture")
                self.assertIs(raised.exception.__cause__, failure)
                stdout.reset_mock()

                code, _, stderr = self.invoke(["-c", "capabilities"], stdout=stdout)
                self.assertEqual(code, 4)
                self.assertEqual(stderr.getvalue(), "ERROR LOCAL_ERROR BufferError: fixture buffer has an active view\n")
                stdout.write.assert_called_once()
                stdout.close.assert_not_called()

        code, stdout, stderr = self.invoke(["-c", "capabilities"])
        self.assertEqual(code, 0)
        self.assertIn("OK (0) mode=capabilities", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

        failure = BufferError("fixture failure outside stream I/O")
        with patch.object(ec, "_dispatch", side_effect=failure), self.assertRaises(BufferError) as raised:
            self.invoke(["-c", "capabilities"])
        self.assertIs(raised.exception, failure)

    def test_buffered_failure_avoids_reusing_the_defective_diagnostic_stream(self):
        def blocked():
            stream = Mock(spec_set=io.StringIO)
            stream.write.side_effect = BufferError("fixture buffer has an active view")
            return stream

        diagnostic = blocked()
        shared = blocked()
        first, second = blocked(), blocked()
        stdout_only = blocked()
        for label, stdout, stderr, failing in (
            ("diagnostic", io.StringIO(), diagnostic, (diagnostic,)),
            ("shared stream", shared, shared, (shared,)),
            ("both streams", first, second, (first, second)),
            ("absent stderr", stdout_only, None, (stdout_only,)),
        ):
            with self.subTest(case=label), redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(ec.main(["-c", "capabilities", "--debug"]), 4)
                for stream in failing:
                    stream.write.assert_called_once()
                    stream.flush.assert_not_called()
                    stream.close.assert_not_called()

    def test_closed_standard_streams_return_local_error(self):
        for target, command in (
            ("stdout", ["-c", "capabilities"]),
            ("stdout", ["--help"]),
            ("stderr", []),
            ("stderr", ["-c", "capabilities", "--debug"]),
        ):
            with self.subTest(target=target, command=command):
                closed = io.StringIO()
                closed.close()
                rc, _, _ = self.invoke(command, **{target: closed})
                self.assertEqual(rc, 4)
        original = io.TextIOWrapper(io.BytesIO(), encoding="utf8")
        original.close()
        with patch.object(sys, "__stdout__", original):
            rc, _, err = self.invoke(["--help"], stdout=original)
        self.assertEqual(rc, 4)
        self.assertIn("ERROR LOCAL_ERROR", err.getvalue())

    def test_required_missing_standard_streams_return_local_error_once(self):
        command = ["-c", "capabilities"]
        debug = [*command, "--debug"]
        original_stdout, original_stderr = sys.stdout, sys.stderr
        for label, argv, stdout, stderr in (
            ("result", command, None, io.StringIO()),
            ("help", ["--help"], None, io.StringIO()),
            ("usage", [], io.StringIO(), None),
            ("debug", debug, io.StringIO(), None),
            ("both absent", debug, None, None),
        ):
            with self.subTest(case=label):
                with redirect_stdout(stdout), redirect_stderr(stderr), \
                        patch.object(ec, "_write_text", wraps=ec._write_text) as write:
                    self.assertEqual(ec.main(argv), 4)
                    self.assertIs(sys.stdout, stdout)
                    self.assertIs(sys.stderr, stderr)
                self.assertIs(sys.stdout, original_stdout)
                self.assertIs(sys.stderr, original_stderr)
                self.assertEqual(sum(call.args[0] is None for call in write.call_args_list), 1)
                if stderr is not None:
                    self.assertEqual(
                        stderr.getvalue(), "ERROR LOCAL_ERROR OSError: standard text stream is unavailable\n",
                    )
                    self.assertFalse(stderr.closed)
                if stdout is not None:
                    if argv == debug:
                        self.assertTrue(stdout.getvalue().startswith("OK (0) mode=capabilities"))
                    else:
                        self.assertEqual(stdout.getvalue(), "")
                    self.assertFalse(stdout.closed)

    def test_unused_missing_channels_and_healthy_effective_streams(self):
        command = ["-c", "capabilities"]
        for argv, prefix in ((command, "OK (0) mode=capabilities"), (["--help"], "usage: ethercat_master.py")):
            with self.subTest(argv=argv):
                stdout = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(None):
                    self.assertEqual(ec.main(argv), 0)
                self.assertTrue(stdout.getvalue().startswith(prefix))
        stderr = io.StringIO()
        with redirect_stdout(None), redirect_stderr(stderr):
            self.assertEqual(ec.main([]), 2)
        self.assertIn("ERROR USAGE_ERROR", stderr.getvalue())

        with patch.object(sys, "__stdout__", None), patch.object(sys, "__stderr__", None):
            code, stdout, stderr = self.invoke([*command, "--debug"])
            self.assertEqual(code, 0)
            self.assertIn("OK (0) mode=capabilities", stdout.getvalue())
            self.assertIn("DEBUG phase=report source=local", stderr.getvalue())
            self.assertIsNone(sys.__stdout__)
            self.assertIsNone(sys.__stderr__)
        code, stdout, stderr = self.invoke(command)
        self.assertEqual((code, stderr.getvalue()), (0, ""))
        self.assertIn("OK (0) mode=capabilities", stdout.getvalue())

    def test_unexpected_stream_attribute_error_is_not_swallowed(self):
        stdout = Mock(spec_set=io.StringIO)
        failure = AttributeError("fixture writer failed internally")
        stdout.write.side_effect = failure
        with self.assertRaises(AttributeError) as raised:
            self.invoke(["-c", "capabilities"], stdout=stdout)
        self.assertIs(raised.exception, failure)
        stdout.close.assert_not_called()

    def test_help_uses_effective_stdout_for_each_original_stream_state(self):
        closed = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        closed.close()
        detached = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with detached.detach(), io.TextIOWrapper(io.BytesIO(), encoding="utf-8") as available:
            for state, original in (("available", available), ("absent", None), ("closed", closed), ("detached", detached)):
                for option in ("-h", "--help"):
                    with self.subTest(state=state, option=option), patch.object(sys, "__stdout__", original):
                        code, stdout, stderr = self.invoke([option])
                        self.assertEqual(code, 0)
                        self.assertIs(sys.__stdout__, original)
                        self.assertFalse(stdout.isatty())
                        self.assertFalse(stdout.closed)
                        self.assertIn("usage: ethercat_master.py", stdout.getvalue())
                        self.assertIn("--command", stdout.getvalue())
                        self.assertNotIn("Traceback", stdout.getvalue())
                        self.assertEqual(stderr.getvalue(), "")
            self.assertFalse(available.closed)
            self.assertEqual(available.buffer.getvalue(), b"")

    def test_short_text_writes_do_not_report_success(self):
        class ShortStream(io.StringIO):
            def write(self, message):
                return super().write(message[:5])

        for target in ("stdout", "stderr"):
            with self.subTest(target=target):
                stream = ShortStream()
                rc, _, _ = self.invoke(["-c", "capabilities", "--debug"], **{target: stream})
                self.assertEqual(rc, 4)
                self.assertLessEqual(len(stream.getvalue()), 10)

    def test_native_result_format_labels_diagnostic_and_test_origin(self):
        assessment = ec.EventAssessment(ec.Status.OK, ec.Attribution.MATCHED, "synthetic system", True, 1, 0x12)
        evidence = ec.ExchangeEvidence(ec.ReadProfile.APRD, ec.Delivery.ACCEPTED, 25, 1, 1, assessment)
        result = ec.OperationResult(ec.Status.OK, ec.Mode.DIAGNOSE, ec.Origin.NATIVE_TEST,
                                    ec.Phase.CORRELATE, "controlled test", evidence)
        text = ec.format_result(result)
        self.assertIn("source=native-backend-test", text)
        self.assertIn("APRD diagnostic delivery=accepted-by-transport", text)
        self.assertIn("ESC Type observed=0x12", text)


class ImportIsolationTests(OfflineCase):
    def test_fresh_import_has_only_stdlib_dependencies_and_no_operational_effects(self):
        source = SOURCE.read_bytes()
        self.assertFalse(source.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", source)
        tree = ast.parse(source.decode("utf8"), filename=str(SOURCE), feature_version=(3, 12))
        module_names = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                        for alias in node.names}
        module_names.update(node.module.split(".")[0] for node in ast.walk(tree)
                            if isinstance(node, ast.ImportFrom) and node.module is not None)
        self.assertEqual(module_names - sys.stdlib_module_names, set())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0)
        out, err = io.StringIO(), io.StringIO()
        root = logging.getLogger()
        old_state = (root.level, tuple(root.handlers), tuple(root.filters), signal.getsignal(signal.SIGINT))
        old_modules = set(sys.modules)
        with redirect_stdout(out), redirect_stderr(err):
            fresh = load_client()
        self.assertIsNot(fresh, ec)
        self.assertIsNot(fresh.FrameEvent, ec.FrameEvent)
        self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))
        self.assertEqual((root.level, tuple(root.handlers), tuple(root.filters), signal.getsignal(signal.SIGINT)),
                         old_state)
        self.assertFalse((set(sys.modules) - old_modules) - sys.stdlib_module_names)

    def test_entry_point_uses_guarded_real_dispatch_and_propagates_exit_status(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", [str(SOURCE), "-c", "simulate", "--scenario", "rejected"]), \
                redirect_stdout(out), redirect_stderr(err), self.assertRaises(SystemExit) as raised:
            runpy.run_path(str(SOURCE), run_name="__main__")
        self.assertEqual(raised.exception.code, 9)
        self.assertIn("REJECTED (9) mode=simulate source=synthetic", out.getvalue())
        self.assertIn("explicit rejection", err.getvalue())

    def test_entry_point_closes_only_its_failed_standard_stream(self):
        class FailedPipe(io.StringIO):
            def write(self, message):
                raise BrokenPipeError("synthetic broken standard pipe")

        for descriptor in ("stdout", "stderr"):
            with self.subTest(descriptor=descriptor):
                out, err = io.StringIO(), io.StringIO()
                stream = FailedPipe()
                if descriptor == "stdout":
                    out = stream
                else:
                    err = stream
                with patch.object(sys, "argv", [str(SOURCE), "-c", "capabilities", "--debug"]), \
                        patch.object(stream, "close", side_effect=OSError("failed stream close")) as close, \
                        patch.object(sys, f"__{descriptor}__", stream), redirect_stdout(out), redirect_stderr(err), \
                        self.assertRaises(SystemExit) as raised:
                    runpy.run_path(str(SOURCE), run_name="__main__")
                self.assertEqual(raised.exception.code, 4)
                # A failed stderr may be tried again to report the primary output failure.
                self.assertEqual(close.call_count, 1 if descriptor == "stdout" else 2)
