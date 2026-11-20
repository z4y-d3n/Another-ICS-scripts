"""Literal and metamorphic checks of local conversion and presentation."""

from fractions import Fraction
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ethercat_unit"))
try:
    from support import OfflineCase, ec
    from vectors import CHAINED
finally:
    sys.path.pop(0)


class GenericInputTests(OfflineCase):
    def test_hex_conserves_bytes_under_case_and_concatenation(self):
        self.assertEqual(ec.parse_hex("0019aBfF"), b"\x00\x19\xab\xff")
        octets = bytes(range(256))
        for raw in (b"\x00", b"\xff", octets, (octets * 6)[:1513], (octets * 6)[:1514]):
            with self.subTest(size=len(raw), first=raw[0]):
                lower = raw.hex()
                middle = len(raw) // 2 * 2
                for text in (lower, lower.upper(), lower[:middle] + lower[middle:].upper()):
                    actual = ec.parse_hex(text)
                    self.assertIs(type(actual), bytes)
                    self.assertEqual(actual, raw)
                    self.assertEqual(len(actual) * 2, len(text))
                if middle:
                    self.assertEqual(ec.parse_hex(lower[:middle]) + ec.parse_hex(lower[middle:]), raw)

    def test_hex_rejects_outside_the_ascii_text_contract(self):
        class DerivedText(str):
            pass

        for label, value in (
            ("empty", ""), ("one digit", "a"), ("incomplete at limit", "1" * 3027),
            ("over limit", "01" * 1515), ("bytes", b"01"), ("bool", True),
            ("integer", 10), ("missing", None), ("subclass", DerivedText("01")),
            ("space", "01 23 "), ("newline", "01\n2"), ("tab", "01\t2"),
            ("zero width joiner", "0\u200d13"), ("nonbreaking space", "0\u00a013"),
            ("nul", "0\x0013"), ("full width", "０１"), ("arabic-Indic", "٠١"),
            ("prefix", "0x01"), ("one invalid nibble", "0g"),
        ):
            with self.subTest(case=label):
                with self.assertRaises(ec.UsageError) as caught:
                    ec.parse_hex(value)
                self.assertIs(type(caught.exception), ec.UsageError)
                self.assertIn("ASCII hexadecimal", str(caught.exception))

    def test_decimal_representations_agree_with_exact_rationals(self):
        for rational, spellings in (
            (Fraction(1, 1000), (".001", "+.0010", "1e-3", "001.0E-003")),
            (Fraction(1, 5), ("0.20", "2.e-1", "+002E-01")),
            (Fraction(3, 2), ("1.5", "15e-1", "+.15e+1")),
            (Fraction(1), ("1", "1.", "+001.0", "1E+00")),
            (Fraction(10), ("10", "10.000", "0.1e2", "100e-1")),
        ):
            for text in spellings:
                with self.subTest(text=text):
                    actual = ec._parse_timeout(text)
                    self.assertIs(type(actual), float)
                    self.assertEqual(actual, float(rational))

    def test_decimal_rejection_precedes_float_rounding(self):
        for text in (
            "", "+", ".", "1e", "1e+", " 1", "1 ", "1\n", "1,5", "1_0", "0x1",
            "１.０", "١", "−1", "NaN", "Infinity", "-inf", "-1", "-0.0", "-.001",
            "0.0009999999999999999999999", "10.000000000000000000001",
            "1e-300", "1e300", "1e" + "9" * 28, "11",
        ):
            with self.subTest(text=text):
                with self.assertRaises(ec.UsageError) as caught:
                    ec._parse_timeout(text)
                self.assertIs(type(caught.exception), ec.UsageError)
                self.assertIn("timeout", str(caught.exception))

    def test_numeric_timeout_retains_values_inside_inclusive_limits(self):
        for value in (0.001, math.nextafter(0.001, math.inf), 0.125, 1, math.nextafter(10, 0), 10):
            with self.subTest(value=value):
                actual = ec.validate_timeout(value)
                self.assertIs(type(actual), float)
                self.assertEqual(actual, float(value))

        class DerivedInt(int):
            pass

        for value in (
            math.nextafter(0.001, 0), math.nextafter(10, math.inf), -0.0,
            float("nan"), math.inf, -math.inf, 10**90, True, "1", None, Fraction(1), DerivedInt(1),
        ):
            with self.subTest(value=value, kind=type(value).__name__):
                with self.assertRaises(ec.UsageError) as caught:
                    ec.validate_timeout(value)
                self.assertIs(type(caught.exception), ec.UsageError)

    def test_diagnostic_normalization_and_truncation_have_stable_boundaries(self):
        self.assertEqual(ec._short_message(" a~\x7f\x00\t\nÉ🙂"), " a~??????")
        self.assertEqual(ec._short_message(""), "")
        self.assertEqual(ec._failure_text(OSError("a\nb🙂c")), "OSError: a?b?c")
        for limit in (60, 240):
            exact = "a" * (limit - 2) + "é~"
            expected = "a" * (limit - 2) + "?~"
            with self.subTest(limit=limit):
                self.assertEqual(ec._short_message(exact[:-1], limit), expected[:-1])
                self.assertEqual(ec._short_message(exact, limit), expected)
                self.assertEqual(ec._short_message(exact + "x", limit), "a" * (limit - 3) + "...")
        self.assertEqual(ec._short_message("a" * 241), "a" * 237 + "...")


class InspectionPresentationTests(OfflineCase):
    def test_approved_inspection_has_an_ordered_bounded_text_result(self):
        output = (
            "OK (0) mode=inspect source=offline-input phase=inspect\n"
            "Ethernet II dst=00:11:22:33:44:55 src=66:77:88:99:aa:bb EtherType=0x88a4\n"
            "EtherCAT Type 1 chain=25 bytes datagrams=2 padding=stripped (0 bytes)\n"
            "  byte 16: LRD (0x0a) Idx=0x7e logical=0x12345678 Len=1 C=1 M=1 IRQ=0xbeef WKC=4660\n"
            "  byte 29: unknown (0xe1) Idx=0x7f address-bytes=11223344 Len=0 C=0 M=0 IRQ=0xa0b0 WKC=22136\n"
        )
        original = ec.inspect_frame(CHAINED)
        self.assertIs(type(original), ec.OperationResult)
        self.assertIs(type(original.detail), ec.EtherCATFrame)
        self.assertIs(original.status, ec.Status.OK)
        self.assertIs(original.mode, ec.Mode.INSPECT)
        self.assertIs(original.origin, ec.Origin.OFFLINE_INPUT)
        self.assertIs(original.phase, ec.Phase.INSPECT)
        self.assertIsNone(original.cleanup)
        for text in (CHAINED.hex(), CHAINED.hex().upper()):
            with self.subTest(text=text):
                repeated = ec.inspect_frame(ec.parse_hex(text))
                self.assertEqual(repeated, original)
                actual = ec.format_result(repeated)
                self.assertIs(type(actual), str)
                self.assertEqual(actual, output)
                self.assertLessEqual(len(actual.encode("utf-8")), 12 * 1024)
