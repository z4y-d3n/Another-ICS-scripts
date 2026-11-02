"""Deterministic offline regression boundaries, not device interoperability.

Fixtures below are hand-built from reviewed wire layouts. Encoders are checked
against fixed bytes; decoders consume independent literals, never their encoder's
output. All product code executes inside a default-deny guard. The only children
are nine bounded real -h probes. No server, listener, broker, UA session or PKI.
"""

from contextlib import redirect_stdout
import hashlib
import importlib.metadata
import io
import logging
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

from check_sources import ROOT, SOURCES, check_bytes, check_root, parse_manifest
from ci_support import (FakeSocket, GuardViolation, OfflineGuard, child_environment,
                        client_module, socket_facade, temporary_workdir)


def checkout_snapshot():
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.relative_to(ROOT).parts}


def setUpModule():
    global _CHECKOUT_BEFORE
    _CHECKOUT_BEFORE = checkout_snapshot()
    unexpected = [p for p in _CHECKOUT_BEFORE if any(
        part in {"__pycache__", "pki", "ot_audit_logs"} for part in Path(p).parts)]
    if unexpected:
        raise AssertionError(f"Checkout already contains runtime artifacts: {unexpected}")


def tearDownModule():
    after = checkout_snapshot()
    if after != _CHECKOUT_BEFORE:
        changed = sorted(k for k in after.keys() | _CHECKOUT_BEFORE.keys()
                         if after.get(k) != _CHECKOUT_BEFORE.get(k))
        raise AssertionError(f"Tests changed checkout files: {changed}")


class IntegrityAndGuardTests(unittest.TestCase):
    def test_source_provenance_utf8_and_in_memory_compile(self):
        output = io.StringIO()
        with OfflineGuard(), redirect_stdout(output):
            check_root(ROOT)
        self.assertEqual(output.getvalue().count("UTF8/AST/compile PASS"), 9)

    def test_changed_in_memory_source_is_rejected(self):
        records = parse_manifest((ROOT / "SOURCE_SHA256.md").read_text(encoding="utf-8"))
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            check_bytes(SOURCES[0], (ROOT / SOURCES[0]).read_bytes() + b"\n", records[SOURCES[0]])

    def test_duplicate_provenance_row_is_rejected(self):
        text = (ROOT / "SOURCE_SHA256.md").read_text(encoding="utf-8")
        row = next(line for line in text.splitlines() if line.startswith("| `"))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            parse_manifest(text + "\n" + row)

    def test_missing_provenance_row_is_rejected(self):
        text = (ROOT / "SOURCE_SHA256.md").read_text(encoding="utf-8")
        text = "\n".join(line for line in text.splitlines() if not line.startswith("| `modbus"))
        with self.assertRaisesRegex(ValueError, "missing"):
            parse_manifest(text)

    def test_socket_constructor_denied_and_restored(self):
        original = socket.socket
        with self.assertRaisesRegex(GuardViolation, "socket.socket"):
            with OfflineGuard():
                socket.socket()
        self.assertIs(socket.socket, original)

    def test_cached_real_socket_constructor_denied_by_audit(self):
        cached_constructor = socket.socket
        with self.assertRaisesRegex(GuardViolation, "socket.__new__"):
            with OfflineGuard():
                cached_constructor()

    def test_dns_denied_even_if_product_catches_exception(self):
        with self.assertRaisesRegex(GuardViolation, "caught forbidden"):
            with OfflineGuard():
                try:
                    socket.getaddrinfo("fixture.invalid", 1)
                except GuardViolation:
                    caught = True
                self.assertTrue(caught)

    def test_file_write_denied_before_file_is_created(self):
        with temporary_workdir() as directory:
            path = directory / "forbidden.log"
            with self.assertRaisesRegex(GuardViolation, "file write"):
                with OfflineGuard():
                    path.write_text("must not be written", encoding="utf-8")
            self.assertFalse(path.exists())

    def test_process_spawn_denied_before_execution(self):
        with self.assertRaisesRegex(GuardViolation, "subprocess.Popen"):
            with OfflineGuard():
                subprocess.run([sys.executable, "-c", "raise AssertionError('must never execute')"],
                               timeout=1, check=True)

    def test_only_empty_shell_initialization_is_neutralized(self):
        original = os.system
        with OfflineGuard() as guard:
            self.assertEqual(os.system(""), 0)
            self.assertEqual(guard.import_events, ["Windows ANSI no-op"])
        with self.assertRaisesRegex(GuardViolation, "nonempty"):
            with OfflineGuard():
                os.system("forbidden-command")
        self.assertIs(os.system, original)

    def test_import_isolation_restored_after_exception(self):
        old_signal, old_system, old_stdout = signal.signal, os.system, sys.stdout
        handler = signal.getsignal(signal.SIGINT)
        alias = "_offline_modbus_master"
        old_module = sys.modules.get(alias)
        with self.assertRaisesRegex(RuntimeError, "intentional fixture failure"):
            with client_module("modbus_master.py"):
                self.assertIs(signal.getsignal(signal.SIGINT), handler)
                raise RuntimeError("intentional fixture failure")
        self.assertIs(signal.signal, old_signal)
        self.assertIs(os.system, old_system)
        self.assertIs(sys.stdout, old_stdout)
        self.assertIs(sys.modules.get(alias), old_module)


class CLIHelpTests(unittest.TestCase):
    """Nine isolated children; no target/credentials and at most eight seconds each."""


def _help_test(name):
    def test(self):
        with temporary_workdir() as directory:
            result = subprocess.run(
                [sys.executable, "-B", str(ROOT / "tests" / "cli_guard_probe.py"), name],
                timeout=8, capture_output=True, text=True, encoding="utf-8",
                cwd=directory, env=child_environment())
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertIn(f"CLI_HELP_PASS {name} flag=-h exit=0 forbidden=0", result.stdout)
            self.assertEqual(list(directory.iterdir()), [], "Help wrote runtime artifacts")
            print(result.stdout, end="")
    test.__doc__ = f"Real {name} -h menu, under network/process/write denial."
    return test


for _source in SOURCES:
    setattr(CLIHelpTests, f"test_{Path(_source).stem}_h_menu", _help_test(_source))


class ClientCase(unittest.TestCase):
    source = None

    def setUp(self):
        self.directory = self.enterContext(temporary_workdir())
        self.m = self.enterContext(client_module(self.source))
        self.m.logger.addHandler(logging.NullHandler())
        self.m.logger.propagate = False
        # Fixed clock only on this isolated module, never on the shared time module.
        if hasattr(self.m, "time"):
            self.m.time = SimpleNamespace(monotonic=lambda: 100.0, time=lambda: 0.0)


class ModbusTests(ClientCase):
    source = "modbus_master.py"

    def setUp(self):
        super().setUp()
        self.c = self.m.RawModbusClient("fixture.invalid", timeout=1, retries=0)
        self.addCleanup(self.c.close)

    def test_modbus_mbap_exact_request_and_correlated_register(self):
        fake = FakeSocket(bytes.fromhex("0001000000050103021234"), chunk_size=2)
        self.c.sock = fake
        self.assertEqual(self.c.read_holding_registers(0, 1).registers, [0x1234])
        self.assertIn(("sendall", bytes.fromhex("000100000006010300000001")), fake.events)
        self.assertEqual((self.c.tid, self.c.last_outcome), (2, "PROTOCOL_ACCEPTED"))

    def test_modbus_transaction_id_wraps_at_16_bits(self):
        self.c.tid = 65535
        fake = FakeSocket(bytes.fromhex("ffff000000050103020001"))
        self.c.sock = fake
        self.assertEqual(self.c.read_holding_registers(0, 1).registers, [1])
        self.assertEqual(self.c.tid, 0)
        self.assertEqual(next(e[1] for e in fake.events if e[0] == "sendall")[:2], b"\xff\xff")

    def test_modbus_mismatched_transaction_closes_and_is_indeterminate(self):
        fake = FakeSocket(bytes.fromhex("0002000000050103021234"))
        self.c.sock = fake
        self.assertIsNone(self.c.read_holding_registers(0, 1))
        self.assertTrue(fake.closed)
        self.assertIsNone(self.c.sock)
        self.assertEqual(self.c.last_outcome, "INDETERMINATE")

    def test_modbus_exception_is_rejected_with_code(self):
        self.c.sock = FakeSocket(bytes.fromhex("000100000003018302"))
        self.assertIs(self.c.read_holding_registers(0, 1), False)
        self.assertEqual((self.c.last_outcome, self.c.last_exception_code), ("REJECTED", 2))

    def test_modbus_eof_is_not_acceptance(self):
        fake = FakeSocket(b"\x00\x01")
        self.c.sock = fake
        self.assertIsNone(self.c.read_holding_registers(0, 1))
        self.assertEqual(self.c.last_outcome, "INDETERMINATE")
        self.assertTrue(fake.closed)

    def test_modbus_register_boundary_rejects_before_send(self):
        fake = FakeSocket()
        self.c.sock = fake
        self.assertIs(self.c.read_holding_registers(65535, 2), False)
        self.assertEqual(self.c.last_outcome, "NOT_SENT")
        self.assertEqual(fake.events, [])

    def test_modbus_nonzero_unused_coil_bits_rejected(self):
        self.c.sock = FakeSocket(bytes.fromhex("00010000000401010181"))
        self.assertIs(self.c.read_coils(0, 1), False)
        self.assertEqual(self.c.last_outcome, "FAILED")


class S7Tests(ClientCase):
    source = "s7comm_master.py"
    REQUEST = bytes.fromhex("32010000000100010000f0")
    RESPONSE = bytes.fromhex("0300001402f080320300000001000100000000f0")

    def setUp(self):
        super().setUp()
        self.c = self.m.RawS7Client("fixture.invalid", timeout=1, retries=0)
        self.addCleanup(self.c.close)

    def test_s7_s5time_fixed_encode_and_independent_decode(self):
        self.assertEqual(self.m.s5time_encode(9990), bytes.fromhex("0999"))
        self.assertEqual(self.m.s5time_decode(bytes.fromhex("3123")), 1230000)

    def test_s7_s5time_invalid_bcd_rejected(self):
        with self.assertRaisesRegex(ValueError, "BCD"):
            self.m.s5time_decode(bytes.fromhex("0a00"))

    def test_s7_s5time_out_of_range_rejected(self):
        with self.assertRaisesRegex(ValueError, "0..9990000"):
            self.m.s5time_encode(9990001)

    def test_s7_bcd_invalid_digit_rejected(self):
        self.assertEqual(self.m.bcd_decode(0x59), 59)
        with self.assertRaisesRegex(ValueError, "BCD"):
            self.m.bcd_decode(0xFA)

    def test_s7_tpkt_cotp_and_correlated_response(self):
        fake = FakeSocket(self.RESPONSE, chunk_size=3)
        self.c.sock = fake
        self.assertEqual(self.c._send_recv(self.REQUEST), bytes.fromhex("320300000001000100000000f0"))
        self.assertIn(("sendall", bytes.fromhex("0300001202f080") + self.REQUEST), fake.events)

    def test_s7_malformed_tpkt_rejected_and_closed(self):
        fake = FakeSocket(bytes.fromhex("0300ffff"))
        self.c.sock = fake
        self.assertIsNone(self.c._send_recv(self.REQUEST))
        self.assertTrue(fake.closed)
        self.assertIsNone(self.c.sock)

    def test_s7_mismatched_pdu_reference_rejected(self):
        frame = bytearray(self.RESPONSE)
        frame[12] = 2
        fake = FakeSocket(frame)
        self.c.sock = fake
        self.assertIsNone(self.c._send_recv(self.REQUEST))
        self.assertTrue(fake.closed)


class ENIPTests(ClientCase):
    source = "enip_master.py"
    REQUEST = bytes.fromhex("6f0002000700000000000000010000000000000000000000aabb")

    def setUp(self):
        super().setUp()
        self.c = self.m.RawENIPClient("fixture.invalid", timeout=1, retries=0)
        self.addCleanup(self.c._drop_transport)

    def test_enip_encapsulation_header_exact_byte_order(self):
        self.assertEqual(self.c._build_enip_header(0x6F, 2, session=0x11223344,
                                                 context=0x0102030405060708), bytes.fromhex(
            "6f0002004433221100000000080706050403020100000000"))

    def test_enip_encapsulation_correlated_response(self):
        fake = FakeSocket(self.REQUEST[:24] + b"\x11\x22", chunk_size=5)
        self.c.sock = fake
        self.assertEqual(self.c._send_recv(self.REQUEST), (0x6F, 7, 0, b"\x11\x22"))
        self.assertEqual(self.c.last_outcome, "PROTOCOL_ACCEPTED")
        self.assertIn(("sendall", self.REQUEST), fake.events)

    def test_enip_mismatched_session_context_and_length_rejected(self):
        for offset in (4, 12, 3):
            with self.subTest(header_byte=offset):
                frame = bytearray(self.REQUEST)
                frame[offset] = 255
                fake = FakeSocket(frame)
                self.c.sock = fake
                self.assertIsNone(self.c._send_recv(self.REQUEST))
                self.assertEqual(self.c.last_outcome, "INDETERMINATE")
                self.assertTrue(fake.closed)

    def test_enip_unconnected_cpf_fixed_fixture(self):
        cpf = bytes.fromhex("000000000000020000000000b20006008e0000001234")
        self.assertEqual(self.c._parse_cpf(cpf, False, 0), bytes.fromhex("8e0000001234"))
        self.assertEqual(self.c._parse_cip_response(bytes.fromhex("8e0000001234"), 14), b"\x12\x34")

    def test_enip_truncated_cpf_rejected(self):
        with self.assertRaisesRegex(ValueError, "Truncated"):
            self.c._parse_cpf(bytes.fromhex("00000000000002000000"), False, 0)

    def test_enip_cip_status_is_rejection(self):
        self.assertIsNone(self.c._parse_cip_response(bytes.fromhex("8e000500"), 14))
        self.assertEqual(self.c.last_outcome, "REJECTED")


class PROFINETTests(ClientCase):
    source = "profinet_master.py"

    def test_profinet_rpc_request_fixed_header_fields_and_sequence(self):
        with patch.object(self.m.uuid, "uuid4", return_value=self.m.uuid.UUID(int=0)):
            c = self.m.RawPNIORPCClient("fixture.invalid")
        frame = c._build_dcerpc_request(5, b"\xaa\xbb")
        self.assertEqual(len(frame), 82)
        self.assertEqual(frame[:8], bytes.fromhex("0400200000000000"))
        self.assertEqual(frame[8:24], bytes.fromhex("dea000006c9711d1827100a02442df7d"))
        self.assertEqual(frame[24:40], bytes.fromhex("dea000016c9711d1827100a02442df7d"))
        self.assertEqual(frame[40:56], bytes(16))
        self.assertEqual(frame[56:], bytes.fromhex("0000000000000001000000000005ffffffff000200000000aabb"))
        self.assertEqual((c.seq_num, c._build_dcerpc_request(5, b"")[64:68]), (1, b"\0\0\0\1"))

    def test_profinet_im1_exact_structure_and_truncation(self):
        fixture = bytes.fromhex("002100380100") + b"PUMP".ljust(32) + b"LAB".ljust(22)
        self.assertEqual(self.m.parse_im1(fixture), {
            "Tag Function (Plant Designation)": "PUMP", "Tag Location (Location ID)": "LAB"})
        self.assertIsNone(self.m.parse_im1(fixture[:-1]))

    def test_profinet_dcp_block_length_excludes_alignment_padding(self):
        self.assertEqual(self.m.RawPROFINETDCPClient._build_dcp_block(2, 2, b"abc"),
                         bytes.fromhex("0202000361626300"))

    def test_profinet_dcp_native_capability_detected_without_opening_socket(self):
        self.assertEqual(hasattr(socket, "AF_PACKET"), sys.platform.startswith("linux"))
        if not hasattr(socket, "AF_PACKET"):
            c = self.m.RawPROFINETDCPClient("fixture-iface")
            self.assertFalse(c.open())
            self.assertIsNone(c.sock)

    def test_profinet_dcp_missing_af_packet_rejected_on_every_os(self):
        facade = socket_facade()
        self.m.socket = facade
        c = self.m.RawPROFINETDCPClient("fixture-iface")
        self.assertFalse(c.open())
        self.assertEqual(facade.calls, [])

    def test_profinet_dcp_fake_open_failure_recovery_and_idempotence(self):
        failed, good = FakeSocket(fail="getsockname"), FakeSocket()
        facade = socket_facade(failed, good, af_packet=True)
        self.m.socket = facade
        c = self.m.RawPROFINETDCPClient("fixture-iface")
        self.addCleanup(c.close)
        self.assertFalse(c.open())
        self.assertTrue(failed.closed)
        self.assertIsNone(c.sock)
        self.assertEqual(c.src_mac, bytes(6))
        self.assertTrue(c.open())
        self.assertTrue(c.open())
        self.assertEqual(len(facade.calls), 2)
        self.assertIs(c.sock, good)
        self.assertEqual(c.src_mac, bytes.fromhex("020000000001"))
        self.assertEqual([e[0] for e in good.events], ["bind", "settimeout", "getsockname"])
        c.close()
        c.close()
        self.assertTrue(good.closed)

    def test_profinet_rpc_fake_setup_failure_recovery_and_idempotence(self):
        failed, good = FakeSocket(fail="settimeout"), FakeSocket()
        facade = socket_facade(failed, good)
        self.m.socket = facade
        c = self.m.RawPNIORPCClient("fixture.invalid")
        self.addCleanup(c.close)
        self.assertFalse(c.connect())
        self.assertTrue(failed.closed)
        self.assertIsNone(c.sock)
        self.assertTrue(c.connect())
        self.assertTrue(c.connect())
        self.assertEqual(len(facade.calls), 2)
        self.assertIs(c.sock, good)
        c.close()
        c.close()
        self.assertTrue(good.closed)


class IEC104Tests(ClientCase):
    source = "iec104_master.py"

    def setUp(self):
        super().setUp()
        self.c = self.m.RawIEC104Client("fixture.invalid", retries=0)
        self.addCleanup(self.c.close)

    def test_iec104_ioa_byte_order_and_upper_bound(self):
        self.assertEqual(self.m.pack_ioa(0x123456), b"\x56\x34\x12")
        with self.assertRaisesRegex(ValueError, "IOA"):
            self.m.pack_ioa(0x1000000)

    def test_iec104_asdu_negative_and_test_flags_exact_bytes(self):
        self.assertEqual(self.c._build_asdu(45, 1, 7, 0x1234, b"\xaa", True, True),
                         bytes.fromhex("2d01c7013412aa"))

    def test_iec104_single_point_object_independent_fixture(self):
        self.assertEqual(self.c._parse_information_objects(1, False, 1, bytes.fromhex("03020181")),
                         [{"ioa": 0x010203, "raw": b"\x81", "value": "ON (1)",
                           "quality": "IV(Invalid)", "timestamp": ""}])

    def test_iec104_truncated_object_is_not_decoded(self):
        self.assertIsNone(self.c._parse_information_objects(1, False, 1, b"\x01\x00\x00"))

    def test_iec104_ack_outside_sent_window_closes(self):
        self.c.vs = 1
        fake = FakeSocket()
        self.c.sock = fake
        self.assertIsNone(self.c._process_incoming_apdu(bytes.fromhex("680401000400")))
        self.assertEqual(self.c.va, 0)
        self.assertTrue(fake.closed)

    def test_iec104_sequence_wrap_ack_is_accepted(self):
        self.c.va, self.c.vs = 32767, 1
        self.assertEqual(self.c._process_incoming_apdu(bytes.fromhex("680401000000")),
                         {"format": "S", "rx_ack": 0})
        self.assertEqual(self.c.va, 0)

    def test_iec104_invalid_calendar_time_is_explicit(self):
        self.assertEqual(self.m.decode_cp56time2a(bytes.fromhex("000000001f0218")), "Invalid-Time")


class BACnetTests(ClientCase):
    source = "bacnet_master.py"

    def test_bacnet_application_value_fixed_encode(self):
        self.assertEqual(self.m.encode_application_value("1.5", "real"), bytes.fromhex("443fc00000"))
        self.assertEqual(self.m.encode_context_object_id(0, 8, 1), bytes.fromhex("0c02000001"))

    def test_bacnet_application_tags_independent_fixture(self):
        self.assertEqual(self.m.decode_application_tags(bytes.fromhex("11212a31ff443fc00000")),
                         [True, 42, -1, 1.5])

    def test_bacnet_wrong_real_length_rejected(self):
        with self.assertRaisesRegex(ValueError, "length"):
            self.m.decode_application_tags(bytes.fromhex("43000000"))

    def test_bacnet_truncated_extended_length_rejected(self):
        with self.assertRaisesRegex(ValueError, "Truncated extended length"):
            self.m.decode_application_tags(bytes.fromhex("75fe00"))

    def test_bacnet_bvlc_length_and_npdu_checked(self):
        c = self.m.RawBACnetClient("fixture.invalid")
        self.assertEqual(c._build_npdu(), b"\x01\x04")
        self.assertEqual(c._build_bvlc(bytes.fromhex("01001000")), bytes.fromhex("810a000801001000"))
        self.assertEqual(c._strip_bvlc_and_npdu(bytes.fromhex("810a000801001000")), (b"\x10\x00", None, None))
        self.assertEqual(c._strip_bvlc_and_npdu(bytes.fromhex("810a000901001000")), (None, None, None))

    def test_bacnet_udp_setup_failure_recovery_and_idempotence(self):
        failed, good = FakeSocket(fail="setsockopt"), FakeSocket()
        facade = socket_facade(failed, good)
        self.m.socket = facade
        c = self.m.RawBACnetClient("fixture.invalid")
        self.addCleanup(c.close)
        self.assertFalse(c.connect())
        self.assertTrue(failed.closed)
        self.assertIsNone(c.sock)
        self.assertTrue(c.connect())
        self.assertTrue(c.connect())
        self.assertIs(c.sock, good)
        self.assertEqual(len(facade.calls), 2)
        self.assertEqual([e[0] for e in good.events], ["setsockopt", "setsockopt", "settimeout"])
        c.close()
        c.close()
        self.assertTrue(good.closed)


class OPCUATests(ClientCase):
    source = "opcua_master.py"

    def test_opcua_required_real_dependency_version(self):
        self.assertEqual(importlib.metadata.version("asyncua"), "2.0.1")
        self.assertEqual(self.m.ua.NodeId(42, 2).to_string(), "ns=2;i=42")

    def test_opcua_nodeid_and_namespace_helpers(self):
        nodeid = self.m.ua.NodeId.from_string("ns=3;s=Lab.Tag")
        self.assertEqual(self.m.nodeid_to_str(nodeid), "ns=3;s=Lab.Tag")
        self.assertEqual(self.m.get_namespace(nodeid), 3)

    def test_opcua_uint16_variant_exact_type_and_value(self):
        variant = self.m.cast_value_to_variant("0xffff", self.m.ua.VariantType.UInt16)
        self.assertEqual(variant.Value, 65535)
        self.assertEqual(variant.VariantType, self.m.ua.VariantType.UInt16)

    def test_opcua_uint16_overflow_rejected(self):
        with self.assertRaisesRegex(ValueError, "range"):
            self.m.cast_value_to_variant("65536", self.m.ua.VariantType.UInt16)

    def test_opcua_invalid_boolean_rejected(self):
        with self.assertRaisesRegex(ValueError, "Boolean"):
            self.m.cast_value_to_variant("maybe", self.m.ua.VariantType.Boolean)

    def test_opcua_display_url_removes_userinfo(self):
        self.assertEqual(self.m.display_url("opc.tcp://example:placeholder@fixture.invalid:4840/path"),
                         "opc.tcp://fixture.invalid:4840/path")

    def test_opcua_safe_display_and_access_metadata(self):
        self.assertEqual(self.m.safe_str(b"\x00\xff"), "0x00FF")
        self.assertEqual(self.m.safe_str("ab\ncd", 3), "ab ...")
        self.assertEqual(self.m.format_access_level({self.m.ua.AccessLevel.CurrentRead}), ("R/-", False))
        # Access metadata is not user authorization or an actual device write.


class MQTTTests(ClientCase):
    source = "mqtt_spb_master.py"

    def test_mqtt_protobuf_varint_independent_encode_and_decode(self):
        self.assertEqual(self.m.encode_varint(300), b"\xac\x02")
        self.assertEqual(self.m.decode_varint(b"\x96\x01", 0), (150, 2))

    def test_mqtt_protobuf_uint64_overflow_rejected(self):
        with self.assertRaisesRegex(ValueError, "uint64"):
            self.m.decode_varint(b"\xff" * 9 + b"\x02", 0)

    def test_mqtt_protobuf_truncation_and_invalid_field_rejected(self):
        with self.assertRaisesRegex(ValueError, "Truncated"):
            self.m.decode_varint(b"\x80", 0)
        with self.assertRaisesRegex(ValueError, "field number"):
            list(self.m._pb_fields(b"\x00\x01"))

    def test_mqtt_sparkplug_metric_exact_fixed_timestamp(self):
        self.assertEqual(self.m.encode_spb_metric("x", 11, "true", timestamp_ms=0),
                         bytes.fromhex("0a01781800200b7001"))

    def test_mqtt_sparkplug_metric_independent_literal(self):
        metric = self.m.decode_spb_metric(bytes.fromhex("0a01781800200b7001"))
        self.assertEqual(metric, dict(name="x", alias=None, timestamp=0, datatype=11,
                                     datatype_name="Boolean", is_null=False, value=True))

    def test_mqtt_sparkplug_wrong_wire_type_reports_error_not_partial_values(self):
        # Payload.metrics contains Metric.datatype encoded as wire 2, not varint.
        result = self.m.decode_spb_payload(bytes.fromhex("12022200"))
        self.assertEqual(result["metrics"], [])
        self.assertIn("Wrong wire type", result["error"])

    def test_mqtt_partial_packet_timeout_preserves_buffer(self):
        c = self.m.RawMQTTClient("fixture.invalid", client_id="offline-fixture", keepalive=0)
        fake = FakeSocket(fail="timeout")
        fake.timeout = 4.0
        c.sock = fake
        self.addCleanup(c._abort_transport)
        c._rx_buffer.extend(bytes.fromhex("300500"))
        self.assertEqual(c._read_packet(), (None, None, None))
        self.assertEqual(c._rx_buffer, bytes.fromhex("300500"))
        self.assertFalse(fake.closed)
        self.assertEqual(fake.gettimeout(), 4.0)


class DNP3Tests(ClientCase):
    source = "dnp3_master.py"
    # Synthetic FT3 literals, independently checked with MSB-first polynomial
    # division (0x3d65) and boundary reflection, not copied from build_link().
    LINK_STATUS = bytes.fromhex("056405c901000004a657")
    DATA_FRAME = bytes.fromhex("056407c401000004468bc0c019ba")

    def test_dnp3_crc_catalogue_check_and_empty_complement(self):
        # CRC RevEng's CRC-16/DNP check value for ASCII 123456789:
        # https://reveng.sourceforge.io/crc-catalogue/16.htm#crc.cat.crc-16-dnp
        self.assertEqual(self.m.crc16(b"123456789"), 0xEA82)
        self.assertEqual(self.m.crc16(b""), 0xFFFF)

    def test_dnp3_fixed_link_status_frame_encode(self):
        self.assertEqual(self.m.build_link(b"", 1, 1024, control=0xC9), self.LINK_STATUS)

    def test_dnp3_independent_link_status_fixture_parse(self):
        self.assertEqual(self.m.parse_link(self.LINK_STATUS), (0xC9, 1, 1024, b""))

    def test_dnp3_header_crc_corruption_rejected(self):
        frame = bytearray(self.LINK_STATUS)
        frame[8] ^= 1
        with self.assertRaisesRegex(self.m.ProtocolError, "CRC mismatch"):
            self.m.parse_link(frame)

    def test_dnp3_data_block_crc_checked_on_independent_fixture(self):
        self.assertEqual(self.m.parse_link(self.DATA_FRAME), (0xC4, 1, 1024, b"\xc0\xc0"))
        frame = bytearray(self.DATA_FRAME)
        frame[10] ^= 1
        with self.assertRaisesRegex(self.m.ProtocolError, "data CRC mismatch"):
            self.m.parse_link(frame)

    def test_dnp3_length_truncation_rejected(self):
        with self.assertRaisesRegex(self.m.ProtocolError, "header/length"):
            self.m.parse_link(self.LINK_STATUS[:-1])

    def test_dnp3_binary_object_independent_fixture(self):
        points = self.m.parse_objects(bytes.fromhex("010200000081"))
        self.assertEqual(points, [dict(group=1, variation=2, index=0, flags=1, timestamp=None,
                                      raw=b"\x81", qualifier=0, value=1)])

    def test_dnp3_unsupported_object_rejected_and_subset_explicit(self):
        self.assertFalse(self.m.supported_read(99, 1))
        self.assertTrue(self.m.supported_read(1, 2))
        with self.assertRaisesRegex(self.m.ProtocolError, "Unsupported object G99V1"):
            self.m.parse_objects(bytes.fromhex("63010701"))


class LoggerTests(unittest.TestCase):
    """Temporary files only; verify handler ownership, not kernel FD release."""
    def test_modbus_console_setup_replaces_only_owned_handler(self):
        with temporary_workdir(), client_module("modbus_master.py") as m:
            external = logging.NullHandler()
            m.logger.addHandler(external)
            m.setup_logger(False)
            old = m.setup_logger._owned_handlers[0]
            m.setup_logger(True)
            self.assertEqual(len(m.logger.handlers), 2)
            self.assertIn(external, m.logger.handlers)
            self.assertNotIn(old, m.logger.handlers)
            self.assertEqual(m.logger.level, logging.DEBUG)

    def test_s7_console_audit_setup_replaces_and_closes_owned_file(self):
        with temporary_workdir() as directory:
            with client_module("s7comm_master.py", write_roots=(directory,)) as m:
                external = logging.NullHandler()
                m.logger.addHandler(external)
                m.setup_logger(False)
                old_file = next(h for h in m.setup_logger._owned_handlers if isinstance(h, logging.FileHandler))
                m.setup_logger(True)
                self.assertEqual(len(m.setup_logger._owned_handlers), 2)
                self.assertEqual(len(m.logger.handlers), 3)
                self.assertIn(external, m.logger.handlers)
                self.assertIsNone(old_file.stream)
                self.assertEqual(len(list((directory / "ot_audit_logs").glob("*.log"))), 1)

    def test_opcua_repeated_logging_has_one_authentication_filter(self):
        with temporary_workdir() as directory:
            with client_module("opcua_master.py", write_roots=(directory,)) as m:
                m.setup_logger(False)
                m.setup_logger(False)
                wire = logging.getLogger("asyncua.client.ua_client.UASocketProtocol")
                self.assertEqual(sum(isinstance(f, m.AuthenticationLogFilter) for f in wire.filters), 1)
                self.assertEqual(len(m.logger.handlers), 2)
                self.assertFalse((directory / "pki").exists())

    def test_dnp3_logger_replaces_all_handlers_including_external(self):
        # DNP3 intentionally owns the full logger, unlike the other clients.
        with temporary_workdir() as directory:
            with client_module("dnp3_master.py", write_roots=(directory,)) as m:
                external = logging.NullHandler()
                m.logger.addHandler(external)
                m.setup_logger(audit_file=str(directory / "audit.log"))
                first = m.logger.handlers[:]
                m.setup_logger(debug=True, audit_file=str(directory / "audit.log"))
                self.assertNotIn(external, m.logger.handlers)
                self.assertTrue(external._closed)
                self.assertEqual(len(m.logger.handlers), 2)
                self.assertIsNone(next(h for h in first if isinstance(h, logging.FileHandler)).stream)
                self.assertFalse(m.logger.propagate)


if __name__ == "__main__":
    unittest.main(verbosity=2)
