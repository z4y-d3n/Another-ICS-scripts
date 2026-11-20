"""Public modes via the guarded entry point, with OS pipes and real exit codes."""

from pathlib import Path
import platform
import socket
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase

from integration_support import run_cli, vectors


class CliProcessTests(TestCase):
    def invoke(self, args, code, *, cwd=None, broken=None):
        options = {} if cwd is None else {"cwd": cwd}
        actual, stdout, stderr = run_cli(args, broken=broken, **options)
        self.assertLessEqual(len(stdout) + len(stderr), 16 * 1024)
        out = stdout.decode("utf-8").replace("\r\n", "\n")
        err = stderr.decode("utf-8").replace("\r\n", "\n")
        for marker in ("Traceback", "Exception ignored", "OFFLINE GUARD", "prohibited effects"):
            self.assertNotIn(marker, out + err)
        self.assertEqual(actual, code, (args, broken, out, err))
        return out, err

    def test_help_and_invalid_cli(self):
        out, err = self.invoke(["-h"], 0)
        for token in ("--command", "inspect", "simulate", "capabilities", "diagnose"):
            self.assertIn(token, out)
        self.assertEqual(err, "")

        for argv, reason in (
            ([], "select a mode"),
            (["--unrecognized"], "unrecognized arguments"),
            (["-c", "simulate", "--scenario", "unsupported"], "invalid choice"),
            (["-c", "simulate", "--scenario", "success", "--padding", "stripped"], "belongs to inspect"),
            (["-c", "inspect", "--hex", vectors.MIN_FRAME.hex(), "--timeout", "1"], "belongs to simulate"),
        ):
            with self.subTest(argv=argv):
                out, err = self.invoke(argv, 2)
                self.assertEqual(out, "")
                self.assertIn("usage:", err)
                self.assertIn("ERROR USAGE_ERROR", err)
                self.assertIn(reason, err)

    def test_inspect_decodes_fields_and_respects_frame_and_datagram_limits(self):
        for frame, padding, header, rows in (
            (vectors.APRD_RETURN, "stripped", "datagrams=1 padding=stripped (0 bytes)",
             ("byte 16: APRD (0x01) Idx=0x39 ADP=0x0001 ADO=0x0000 Len=1", "IRQ=0x0040 WKC=1")),
            (vectors.CHAINED, "stripped", "datagrams=2 padding=stripped (0 bytes)",
             ("byte 16: LRD (0x0a) Idx=0x7e logical=0x12345678 Len=1 C=1 M=1 IRQ=0xbeef WKC=4660",
              "byte 29: unknown (0xe1) Idx=0x7f address-bytes=11223344 Len=0 C=0 M=0 IRQ=0xa0b0 WKC=22136")),
            (vectors.CHAINED + bytes(19), "retained", "datagrams=2 padding=retained (19 bytes)",
             ("EtherCAT Type 1 chain=25 bytes", "Len=1", "Len=0")),
            (vectors.single_payload(bytes(1486)), "stripped", "EtherCAT Type 1 chain=1498 bytes datagrams=1",
             ("Len=1486", "WKC=22136")),
            (vectors.wrap_chain(vectors.nop_chain(15)), "stripped", "datagrams=15",
             ("byte 184: NOP",)),
        ):
            with self.subTest(length=len(frame), padding=padding, header=header):
                out, err = self.invoke(["-c", "inspect", "--hex", frame.hex(), "--padding", padding, "--debug"], 0)
                self.assertTrue(out.startswith("OK (0) mode=inspect source=offline-input phase=inspect\n"))
                self.assertIn(header, out)
                for fragment in rows:
                    self.assertIn(fragment, out)
                self.assertNotIn("attribution=", out)
                self.assertNotIn("delivery=", out)
                self.assertIn("structural inspection completed", err)
                self.assertIn("phase=inspect source=offline-input", err)
                if "datagrams=15" in header:
                    self.assertEqual(out.count(": NOP "), 15)

    def test_inspect_reports_usage_structure_and_format_separately(self):
        cases = (
            ("z1", 2, "hex input", ""),
            (vectors.MIN_FRAME.hex()[:-1], 2, "hex input", ""),
            (vectors.MIN_FRAME[:13].hex(), 5, "truncated Ethernet", "PROTOCOL_ERROR"),
            (vectors.CHAINED[:-1].hex(), 5, "truncated datagram chain", "PROTOCOL_ERROR"),
            (vectors.replace_field(vectors.MIN_FRAME, 12, b"\x08\x00").hex(),
             3, "outside untagged EtherCAT", "UNSUPPORTED"),
            (vectors.wrap_chain(vectors.nop_chain(16)).hex(), 3, "15 datagrams", "UNSUPPORTED"),
            ((vectors.single_payload(bytes(1486)) + b"\0").hex(), 2, "2..3028 ASCII", ""),
        )
        for value, code, reason, status in cases:
            with self.subTest(code=code, reason=reason, chars=len(value)):
                out, err = self.invoke(["-c", "inspect", "--hex", value], code)
                self.assertIn(reason, err)
                if status:
                    self.assertEqual(out.strip(), f"{status} ({code}) mode=inspect source=offline-input phase=inspect")
                else:
                    self.assertEqual(out, "")
                    self.assertIn("USAGE_ERROR", err)

    def test_all_scenarios_report_status_evidence_and_origin(self):
        for scenario, code, status, phase, events, attribution, observed, reason in (
            ("success", 0, "OK", "correlate", 1, "valid attribution=matched", 1, "synthetic return matches"),
            ("timeout", 6, "TIMEOUT", "receive", 0, None, "unavailable", "deadline reached"),
            ("uncorrelated", 7, "UNCORRELATED", "receive", 1, "unverified attribution=foreign",
             "unavailable", "identity fields differ"),
            ("wkc-mismatch", 8, "INDETERMINATE", "correlate", 1, "valid attribution=matched",
             0, "Working Counter differs"),
            ("invalid", 5, "PROTOCOL_ERROR", "correlate", 1, "invalid attribution=matched",
             "unavailable", "truncated datagram chain"),
            ("rejected", 9, "REJECTED", "correlate", 1, "unverified attribution=matched",
             "unavailable", "explicit rejection from the synthetic fixture"),
        ):
            with self.subTest(scenario=scenario):
                out, err = self.invoke(["-c", "simulate", "--scenario", scenario, "--debug"], code)
                lines = out.splitlines()
                self.assertEqual(lines[0], f"{status} ({code}) mode=simulate source=synthetic phase={phase}")
                self.assertEqual(lines[1], f"FPRD fixture delivery=accepted-by-transport events={events}")
                self.assertEqual(lines[-1], f"WKC expected=1 observed={observed}")
                if attribution is None:
                    self.assertEqual(len(lines), 3)
                else:
                    self.assertEqual(lines[2:-1], [f"Return structure={attribution}"])
                self.assertIn(f"{status} [simulate]", err)
                self.assertIn(reason, err)
                self.assertIn(f"phase={phase} elapsed_ns=", err)
                self.assertEqual(out.count("source=synthetic"), 1)

    def test_timeout_boundaries_are_logical_and_repeated_processes_are_independent(self):
        argv = ["-c", "simulate", "--scenario", "timeout", "--debug"]
        for extra, logical_ns in (([], 1_000_000_000), (["--timeout", "0.001"], 1_000_000),
                                  (["--timeout", "10"], 10_000_000_000), ([], 1_000_000_000)):
            with self.subTest(extra=extra, logical_ns=logical_ns):
                out, err = self.invoke(argv + extra, 6)
                self.assertIn("TIMEOUT (6) mode=simulate source=synthetic phase=receive", out)
                self.assertIn(f"elapsed_ns={logical_ns} events=0", err)

    def test_capabilities_report_actual_runtime_from_alternate_unicode_cwd(self):
        # Restrict this expectation to the actual platform and local API;
        # the simulated platform combinations are verified in-process.
        has_api = sys.platform == "linux" and all(
            isinstance(getattr(socket, name, None), int)
            for name in ("AF_PACKET", "SOCK_RAW", "SOL_SOCKET", "MSG_TRUNC",
                         "MSG_CTRUNC", "PACKET_OUTGOING", "MSG_ERRQUEUE")
        ) and callable(getattr(socket, "CMSG_SPACE", None)) and callable(socket.socket)
        with TemporaryDirectory(prefix="Gate 3 inspección ") as directory:
            out, err = self.invoke(["-c", "capabilities", "--debug"], 0, cwd=Path(directory))
        for token in (
            "OK (0) mode=capabilities source=local phase=report",
            f"Platform={sys.platform} Python=cpython {platform.python_version()}",
            "Offline modes: inspect, simulate (FPRD), capabilities",
            "Native backend: implemented for Linux",
            "Native backend validation: offline exercises with a substituted system boundary",
            "Physical interoperability: pending",
            "Native diagnose: disabled",
            "Linux packet API symbols " + ("present" if has_api else "absent on this runtime"),
        ):
            self.assertIn(token, out)
        self.assertIn("phase=report source=local", err)

    def test_diagnose_rejects_incomplete_and_valid_requests(self):
        base = ["-c", "diagnose"]
        for extra in ([], ["--interface", "fixture0"], ["--confirm-bench"]):
            with self.subTest(extra=extra):
                out, err = self.invoke(base + extra, 2)
                self.assertEqual(out, "")
                self.assertIn("diagnose requires --interface and --confirm-bench", err)
        out, err = self.invoke(base + ["--interface", "fixture0", "--confirm-bench"], 3)
        self.assertEqual(out.strip(), "UNSUPPORTED (3) mode=diagnose source=local phase=precheck")
        self.assertIn("disabled pending physical interoperability validation", err)

    def test_broken_stdout_exits_4_and_reports_to_stderr(self):
        for argv in (["-h"], ["-c", "simulate", "--scenario", "success"]):
            with self.subTest(argv=argv):
                out, err = self.invoke(argv, 4, broken="stdout")
                self.assertEqual(out, "")
                self.assertEqual(len(err.splitlines()), 1)
                self.assertIn("ERROR LOCAL_ERROR", err)
                self.assertRegex(err, r"ERROR LOCAL_ERROR (?:BrokenPipeError|OSError):")

    def test_broken_stderr_exits_4_after_result_or_usage(self):
        for argv, result in (
            (["-c", "simulate", "--scenario", "success", "--debug"], "OK (0) mode=simulate source=synthetic"),
            (["-c", "inspect", "--hex", vectors.MIN_FRAME[:13].hex()], "PROTOCOL_ERROR (5) mode=inspect"),
            ([], ""),
        ):
            with self.subTest(argv=argv):
                out, err = self.invoke(argv, 4, broken="stderr")
                self.assertEqual(err, "")
                if result:
                    self.assertTrue(out.startswith(result))
                else:
                    self.assertEqual(out, "")
