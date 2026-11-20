"""Platform visibility and the public precheck with acquisition spies."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import Mock, patch

from integration_support import OfflineCase, ec, packet


class LocalModesTests(OfflineCase):
    def test_capability_matrix_reports_symbols_without_acquisition(self):
        for platform, missing in (("linux", None), ("linux", "CMSG_SPACE"),
                                  ("linux", "SO_TIMESTAMPING_NEW"), ("win32", None), ("darwin", None)):
            with self.subTest(platform=platform, missing=missing):
                factory = Mock(side_effect=AssertionError("capabilities acquired a resource"))
                symbols = packet.linux_symbols(factory)
                if missing is not None:
                    setattr(symbols, missing, None)
                out, err = StringIO(), StringIO()
                with (
                    patch.object(ec.sys, "platform", platform),
                    patch.object(ec, "socket", symbols),
                    redirect_stdout(out),
                    redirect_stderr(err),
                ):
                    code = ec.main(["-c", "capabilities", "--debug"])
                self.assertEqual(code, 0)
                self.assertIn(f"Platform={platform} Python=cpython", out.getvalue())
                reported = "present" if platform == "linux" and missing is None else "absent on this runtime"
                self.assertIn(f"Linux packet API symbols {reported}", out.getvalue())
                self.assertIn("Physical interoperability: pending", out.getvalue())
                self.assertIn("Native diagnose: disabled", out.getvalue())
                self.assertIn("phase=report source=local", err.getvalue())
                factory.assert_not_called()
                if missing != "CMSG_SPACE":
                    symbols.CMSG_SPACE.assert_not_called()

    def test_diagnose_never_constructs_transport_or_falls_back(self):
        factory = Mock(side_effect=AssertionError("diagnose acquired a resource"))
        symbols = packet.linux_symbols(factory)
        for args, code, reason in (
            (["--interface", "fixture0"], 2, "requires --interface and --confirm-bench"),
            (["--interface", "not an interface", "--confirm-bench"], 2, "interface requires"),
            (["--interface", "fixture0", "--confirm-bench"], 3, "disabled pending physical interoperability validation"),
            (["--interface", "fixture0", "--confirm-bench", "--enable-native"], 2, "unrecognized arguments"),
        ):
            with self.subTest(args=args):
                out, err = StringIO(), StringIO()
                with (
                    patch.object(ec.sys, "platform", "linux"),
                    patch.object(ec, "socket", symbols),
                    patch.object(ec, "_LinuxPacketTransport", side_effect=AssertionError("constructed backend")) as backend,
                    patch.object(ec, "simulate", side_effect=AssertionError("synthetic fallback")) as fallback,
                    redirect_stdout(out),
                    redirect_stderr(err),
                ):
                    self.assertEqual(ec.main(["-c", "diagnose", *args]), code)
                self.assertIn(reason, err.getvalue())
                self.assertEqual(out.getvalue().strip(),
                                 "UNSUPPORTED (3) mode=diagnose source=local phase=precheck" if code == 3 else "")
                backend.assert_not_called()
                fallback.assert_not_called()
                factory.assert_not_called()
