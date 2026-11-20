from dataclasses import FrozenInstanceError, astuple

from support import OfflineCase, ec
from vectors import (
    APRD_REQUEST, CHAINED, ETHERNET, FPRD_REQUEST, MIN_FRAME, nop_chain,
    replace_field, single_payload, wrap_chain,
)


class CodecTests(OfflineCase):
    def reject(self, raw, error, offset, reason, padding=ec.Padding.STRIPPED):
        with self.assertRaises(error) as caught:
            ec.decode_frame(raw, padding)
        self.assertIs(type(caught.exception), error)
        self.assertEqual(caught.exception.offset, offset)
        self.assertLessEqual(offset, len(raw))
        self.assertIn(reason, caught.exception.reason)
        self.assertTrue(str(caught.exception).startswith(f"byte {offset}: "))

    def test_ethernet_header_and_full_chained_literal(self):
        frame = ec.decode_frame(CHAINED)
        self.assertEqual(
            (frame.destination.hex(), frame.source.hex(), frame.chain_length, frame.padding, frame.padding_convention),
            ("001122334455", "66778899aabb", 25, b"", ec.Padding.STRIPPED),
        )
        self.assertEqual(tuple(astuple(d) for d in frame.datagrams), (
            (16, 10, 0x7E, b"\x78\x56\x34\x12", True, True, 0xBEEF, b"\xaa", 0x1234),
            (29, 0xE1, 0x7F, b"\x11\x22\x33\x44", False, False, 0xA0B0, b"", 0x5678),
        ))
        self.assertEqual([d.command_name for d in frame.datagrams], ["LRD", "unknown"])
        with self.assertRaises(FrozenInstanceError):
            frame.datagrams[0].wkc = 0

    def test_unrecognized_encapsulation_and_ethercat_type_are_unsupported(self):
        for ether_type in (b"\x08\x00", b"\x81\x00", b"\xa4\x88"):
            with self.subTest(ether_type=ether_type):
                self.reject(replace_field(MIN_FRAME, 12, ether_type), ec.UnsupportedFrame, 12, "EtherType")
        for frame_type in (0, 2, 15):
            with self.subTest(frame_type=frame_type):
                raw = replace_field(MIN_FRAME, 15, bytes([frame_type << 4]))
                self.reject(raw, ec.UnsupportedFrame, 15, f"type {frame_type}")

    def test_reserved_bits_and_contradictory_chain_lengths(self):
        for word, reason, offset in (
            (b"\x0c\x18", "reserved bit", 15),
            (b"\x00\x10", "outside 12..1498", 14),
            (b"\x0b\x10", "outside 12..1498", 14),
            (b"\xdb\x15", "outside 12..1498", 14),
            (b"\xff\x17", "outside 12..1498", 14),
            (b"\x0d\x10", "truncated datagram chain", 28),
        ):
            with self.subTest(word=word.hex()):
                self.reject(replace_field(MIN_FRAME, 14, word), ec.InvalidFrame, offset, reason)
        for bit in (0x08, 0x10, 0x20):
            with self.subTest(bit=bit):
                self.reject(replace_field(MIN_FRAME, 23, bytes([bit])), ec.InvalidFrame, 23, "reserved bits")

    def test_truncation_at_each_byte_of_a_chained_frame(self):
        for end in range(len(CHAINED)):
            with self.subTest(end=end):
                reason = ("Ethernet header" if end < 14 else
                          "EtherCAT header" if end < 16 else "datagram chain")
                self.reject(CHAINED[:end], ec.InvalidFrame, end, reason)

    def test_inner_truncation_with_consistent_outer_length(self):
        # The first 13 bytes form a continuing datagram with one payload byte.
        chain = CHAINED[16:]
        for second_bytes in range(12):
            with self.subTest(second_bytes=second_bytes):
                raw = wrap_chain(chain[:13 + second_bytes])
                offset, reason = (23, "M flag") if second_bytes == 0 else (29, "incomplete datagram")
                self.reject(raw, ec.InvalidFrame, offset, reason)
        for length in (1, 2, 3):
            with self.subTest(length=length):
                raw = replace_field(MIN_FRAME, 22, length.to_bytes(2, "little"))
                self.reject(raw, ec.InvalidFrame, 22, "payload and Working Counter overrun")

    def test_continuity_requires_more_if_and_only_if_another_datagram_follows(self):
        self.reject(replace_field(CHAINED, 23, b"\x40"), ec.InvalidFrame, 23, "M flag")
        self.reject(replace_field(CHAINED, 36, b"\x80"), ec.InvalidFrame, 36, "M flag")

    def test_minimum_padding_conventions_preserve_observed_padding(self):
        self.assertEqual((len(MIN_FRAME), len(ec.decode_frame(MIN_FRAME).datagrams[0].payload)), (28, 0))
        pad = bytes(range(32))
        frame = ec.decode_frame(MIN_FRAME + pad, ec.Padding.RETAINED)
        self.assertEqual((len(MIN_FRAME + pad), frame.padding, frame.datagrams[0].wkc), (60, pad, 0))
        self.assertIs(frame.padding_convention, ec.Padding.RETAINED)
        self.reject(MIN_FRAME, ec.InvalidFrame, 28, "expected 60", ec.Padding.RETAINED)
        for size, offset in ((31, 59), (33, 60), (36, 60)):
            with self.subTest(size=size):
                self.reject(MIN_FRAME + bytes(size), ec.InvalidFrame, offset, "expected 60", ec.Padding.RETAINED)
        for extra in (1, 4, 32):
            with self.subTest(extra=extra):
                self.reject(MIN_FRAME + bytes(extra), ec.InvalidFrame, 28, "expected 28")

    def test_payload_and_frame_boundaries(self):
        for size in (1, 31, 32, 33, 1485, 1486):
            with self.subTest(size=size):
                payload = b"\x93" * size
                raw = single_payload(payload)
                for padding in ec.Padding:
                    captured = raw.ljust(60, b"\xc7") if padding is ec.Padding.RETAINED else raw
                    result = ec.decode_frame(captured, padding)
                    self.assertEqual((len(raw), result.chain_length), (28 + size, 12 + size))
                    self.assertEqual((result.datagrams[0].payload, result.datagrams[0].wkc), (payload, 0x5678))
                    self.assertEqual(len(result.padding), len(captured) - len(raw))
        oversized = single_payload(bytes(1487))
        self.assertEqual(len(oversized), 1515)
        self.reject(oversized, ec.InvalidFrame, 1514, "1514-byte input limit")
        self.reject(oversized[:-1], ec.InvalidFrame, 14, "outside 12..1498")

    def test_datagram_limit_is_applied_after_structural_validation(self):
        for count in (1, 14, 15):
            with self.subTest(count=count):
                frame = ec.decode_frame(wrap_chain(nop_chain(count)))
                self.assertEqual([d.offset for d in frame.datagrams], list(range(16, 16 + 12 * count, 12)))
                self.assertEqual([d.more for d in frame.datagrams], [True] * (count - 1) + [False])
        self.reject(wrap_chain(nop_chain(16)), ec.UnsupportedFrame, 196, "15 datagrams")
        self.reject(wrap_chain(nop_chain(17)), ec.UnsupportedFrame, 196, "15 datagrams")
        broken = replace_field(wrap_chain(nop_chain(17)), 215, b"\x08")
        self.reject(broken, ec.InvalidFrame, 215, "reserved bits")

    def test_input_types_and_known_command_names(self):
        class DerivedBytes(bytes):
            pass

        for raw in (None, "", bytearray(MIN_FRAME), memoryview(MIN_FRAME), DerivedBytes(MIN_FRAME)):
            with self.subTest(raw=type(raw)):
                with self.assertRaisesRegex(TypeError, "requires bytes and a Padding"):
                    ec.decode_frame(raw)
        with self.assertRaisesRegex(TypeError, "requires bytes and a Padding"):
            ec.decode_frame(MIN_FRAME, "stripped")
        commands = (
            "NOP", "APRD", "APWR", "APRW", "FPRD", "FPWR", "FPRW", "BRD", "BWR", "BRW",
            "LRD", "LWR", "LRW", "ARMW", "FRMW", "unknown",
        )
        for command, name in (*enumerate(commands), (255, "unknown")):
            with self.subTest(command=command):
                frame = ec.decode_frame(replace_field(MIN_FRAME, 16, bytes([command])))
                self.assertEqual((frame.datagrams[0].command, frame.datagrams[0].command_name), (command, name))

    def test_encoder_golden_literals_and_closed_profiles(self):
        for profile, expected, size in ((ec.ReadProfile.FPRD, FPRD_REQUEST, 30),
                                        (ec.ReadProfile.APRD, APRD_REQUEST, 29)):
            with self.subTest(profile=profile):
                raw = ec.encode_request(profile)
                self.assertIs(type(raw), bytes)
                self.assertEqual((raw, len(raw)), (expected, size))
        for profile in ("FPRD", "FPWR", "AL", None, 4):
            with self.subTest(invalid=profile):
                with self.assertRaisesRegex(ec.UsageError, "unknown synthetic read profile"):
                    ec.encode_request(profile)

    def test_inspection_maps_errors_and_reports_context(self):
        cases = (
            (MIN_FRAME, ec.Status.OK, "structural inspection"),
            (MIN_FRAME[:-1], ec.Status.PROTOCOL_ERROR, "byte 27"),
            (ETHERNET[:12] + b"\x08\x00", ec.Status.UNSUPPORTED, "EtherType"),
        )
        for raw, status, reason in cases:
            with self.subTest(status=status):
                result = ec.inspect_frame(raw)
                self.assertEqual((result.status, result.mode, result.origin, result.phase),
                                 (status, ec.Mode.INSPECT, ec.Origin.OFFLINE_INPUT, ec.Phase.INSPECT))
                self.assertIn(reason, result.reason)
                if status is ec.Status.OK:
                    self.assertEqual(result.detail.chain_length, 12)
                else:
                    self.assertIsNone(result.detail)
