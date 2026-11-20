from dataclasses import astuple
import errno
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from linux_fakes import (
    ERRQUEUE, IFACE, MSG_CTRUNC, MSG_TRUNC, RX_ADDRESS, TX_SECONDS,
    auxdata, extended_error, linux_symbols, received, scheduled, timestamp,
)
from support import OfflineCase, ec
from vectors import NATIVE_RETURN, single_payload


class PacketPlanningTests(OfflineCase):
    def test_symbols_and_callable_matrix_has_no_acquisition(self):
        for platform, supported in (("linux", True), ("win32", False), ("darwin", False), ("other", False)):
            with self.subTest(platform=platform):
                system = linux_symbols(Mock(side_effect=AssertionError("socket factory called while planning")))
                self.assertIs(ec.supports_linux_packet(platform, system), supported)
                plan = ec.plan_linux_packet(platform, system, IFACE)
                caps = ec.report_capabilities(platform, system)
                self.assertEqual(caps.platform, platform)
                self.assertIs(caps.linux_packet_api, supported)
                if supported:
                    self.assertEqual((plan.constructor, plan.bind_address), ((17, 3, 0), (IFACE, 0x88A4)))
                else:
                    self.assertIsNone(plan)
                    system.CMSG_SPACE.assert_not_called()
                system.socket.assert_not_called()
        for name in ("AF_PACKET", "SOCK_RAW", "SOL_SOCKET", "MSG_TRUNC", "MSG_CTRUNC",
                     "MSG_ERRQUEUE", "PACKET_OUTGOING", "SO_TIMESTAMPING_NEW", "socket", "CMSG_SPACE"):
            for missing in (True, False):
                with self.subTest(name=name, missing=missing):
                    factory = Mock()
                    system = linux_symbols(factory)
                    if missing:
                        delattr(system, name)
                    else:
                        setattr(system, name, "wrong-type")
                    self.assertFalse(ec.supports_linux_packet("linux", system))
                    self.assertIsNone(ec.plan_linux_packet("linux", system, IFACE))
                    factory.assert_not_called()

    def test_interface_and_reference_validation_precede_platform_and_native_acquisition(self):
        system = linux_symbols(Mock())
        for name in ("", "x" * 16, ".", "..", "x/y", "x:y", "x y", "éth0", "x\n", 5, None):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ec.UsageError, "Linux name"):
                    ec.plan_linux_packet("win32", system, name)
        system.CMSG_SPACE.assert_not_called()
        system.socket.assert_not_called()
        for value in (0, 255):
            with self.subTest(value=value):
                context = ec._NativeDiagnosticContext("a-B.09_" + "x" * 8, value, ec.Padding.STRIPPED)
                self.assertEqual(context.expected_esc_type, value)
                self.assertEqual(len(context.interface), 15)
        for value in (-1, 256, True, "12", None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ec.UsageError, "single byte"):
                    ec._NativeDiagnosticContext(IFACE, value, ec.Padding.STRIPPED)
        with self.assertRaisesRegex(ec.UsageError, "padding convention"):
            ec._NativeDiagnosticContext(IFACE, 0x12, "stripped")

    def test_cmsg_plan_validates_lp64_and_ilp32_space_without_acquisition(self):
        for width, rx, tx in ((8, 104, 96), (4, 92, 88)):
            with self.subTest(width=width):
                system = linux_symbols(Mock(), width)
                plan = ec.plan_linux_packet("linux", system, IFACE)
                self.assertEqual((plan.receive_control_bytes, plan.transmit_control_bytes), (rx, tx))
                self.assertEqual((plan.socket_level, plan.timestamping_option, plan.outgoing_type), (1, 65, 4))
                self.assertEqual((plan.truncation_flag, plan.control_truncation_flag, plan.error_queue_flag),
                                 (0x20, 0x08, 0x2000))
                self.assertEqual(system.CMSG_SPACE.call_args_list, [call(48), call(20), call(16)])
                system.socket.assert_not_called()

    def test_timestamp_option_fallback_follows_architecture_only_for_native_symbol_identity(self):
        system = linux_symbols(Mock())
        del system.SO_TIMESTAMPING_NEW
        for machine, expected in (("x86_64", 65), ("aarch64", 65), ("SPARC64", 0x43),
                                  ("parisc64", 0x403A), ("hppa", 0x403A)):
            with self.subTest(machine=machine):
                uname = Mock(return_value=SimpleNamespace(machine=machine))
                with patch.object(ec, "_SYSTEM_SOCKET_MODULE", system), patch.object(ec.os, "uname", uname, create=True):
                    plan = ec.plan_linux_packet("linux", system, IFACE)
                self.assertEqual(plan.timestamping_option, expected)
                uname.assert_called_once_with()
        system.socket.assert_not_called()


class PacketMetadataTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.plan = ec.plan_linux_packet("linux", linux_symbols(Mock()), IFACE)
        self.tx_ns = 1_700_000_000_000_000_250

    def normalize(self, message):
        return ec._normalize_packet(message, self.plan, ec.Padding.RETAINED, 123, self.tx_ns)

    def test_tx_schedule_requires_error_queue_and_well_formed_software_timestamp(self):
        self.assertEqual(ec._scheduled_timestamp(scheduled(), self.plan), self.tx_ns)
        future = (2**31 + 1) * 1_000_000_000 + 999_999_999
        control = [extended_error(), timestamp(2**31 + 1, 999_999_999, clock_slots=(1, 2, 3, 4))]
        self.assertEqual(ec._scheduled_timestamp(scheduled(control=control), self.plan), future)
        for message in (None, (b"", [], ERRQUEUE), scheduled(data=b"x"), scheduled(data=bytearray()),
                        scheduled(flags=False), scheduled(flags=-1), scheduled(flags=0),
                        scheduled(flags=ERRQUEUE | MSG_CTRUNC), scheduled(flags=ERRQUEUE | MSG_TRUNC)):
            with self.subTest(message=message):
                self.assertIsNone(ec._scheduled_timestamp(message, self.plan))

    def test_tx_schedule_checks_extended_error_origin_info_and_record_shape(self):
        for control in (
            [], [timestamp()], [extended_error()], [extended_error(number=errno.EIO), timestamp()],
            [extended_error(origin=2), timestamp()], [extended_error(info=0), timestamp()],
            [(1, 16, extended_error()[2]), timestamp()], [(263, 16, bytes(15)), timestamp()],
            [(263, 16, bytes(17)), timestamp()], [extended_error(), extended_error()],
            [extended_error(), timestamp(), timestamp()], "wrong cmsg list",
        ):
            with self.subTest(control=control):
                self.assertIsNone(ec._scheduled_timestamp(scheduled(control=control), self.plan))

    def test_rx_software_timestamp_uses_only_the_valid_first_64_bit_slot(self):
        for cmsg in (
            timestamp(-1, 1), timestamp(0, 0, clock_slots=(1, 2, 3, 4)),
            timestamp(TX_SECONDS, -1), timestamp(TX_SECONDS, 1_000_000_000),
            (1, 65, bytes(24)), (1, 65, bytes(49)), (2, 65, timestamp()[2]),
            (1, 37, timestamp()[2]),
        ):
            with self.subTest(cmsg=cmsg):
                result = self.normalize(received(control=[cmsg, auxdata(29)]))
                self.assertIsNone(result.packet_metadata.rx_software_ns)
                self.assertIs(result.packet_metadata.vlan_tagged, False)
        for sec, nsec in ((0, 1), (TX_SECONDS, 0), (TX_SECONDS, 999_999_999)):
            with self.subTest(sec=sec, nsec=nsec):
                metadata = self.normalize(received(control=[timestamp(sec, nsec), auxdata(29)])).packet_metadata
                self.assertEqual(metadata.rx_software_ns, sec * 1_000_000_000 + nsec)

    def test_receive_preserves_observed_bytes_metadata_and_separate_clock_domains(self):
        event = self.normalize(received())
        self.assertEqual((event.data, event.timestamp_ns, event.interface, event.exchange_id),
                         (NATIVE_RETURN, 123, IFACE, None))
        self.assertIs(event.direction, ec.Direction.INBOUND)
        self.assertIs(event.padding, ec.Padding.RETAINED)
        self.assertIs(event.truncated, False)
        self.assertEqual(astuple(event.packet_metadata),
                         (0x88A4, 1, 1, False, 29, self.tx_ns, 1_700_000_000_000_000_251))

    def test_packet_direction_and_address_metadata_are_not_invented(self):
        for kind, direction in ((0, ec.Direction.INBOUND), (1, ec.Direction.INBOUND), (2, ec.Direction.INBOUND),
                                (3, ec.Direction.INBOUND), (4, ec.Direction.OUTBOUND), (5, ec.Direction.UNKNOWN),
                                (True, ec.Direction.UNKNOWN), ("0", ec.Direction.UNKNOWN)):
            with self.subTest(kind=kind):
                address = RX_ADDRESS[:2] + (kind,) + RX_ADDRESS[3:]
                result = self.normalize(received(address=address))
                self.assertIs(result.direction, direction)
                self.assertEqual(result.packet_metadata.packet_type, kind if type(kind) is int else None)
                if direction is ec.Direction.OUTBOUND:
                    self.assertIsNone(result.packet_metadata.rx_software_ns)
                    self.assertIsNone(result.packet_metadata.vlan_tagged)
        for address in (None, (IFACE, 0x88A4), ("", -1, 0, None), ("x" * 16, 65536, 0, True)):
            with self.subTest(address=address):
                event = self.normalize(received(address=address))
                self.assertEqual((event.interface, event.packet_metadata.protocol, event.packet_metadata.hardware_type),
                                 (None, None, None))

    def test_malformed_recvmsg_envelope_bytes_and_flags_are_transport_errors(self):
        for message, reason in (
            ([], "invalid packet result"), ((b"", [], 0), "invalid packet result"),
            (received(data=bytearray()), "invalid packet bytes or flags"),
            (received(data=bytes(1515)), "invalid packet bytes or flags"),
            (received(flags=-1), "invalid packet bytes or flags"),
            (received(flags=False), "invalid packet bytes or flags"),
            (received(flags=ERRQUEUE), "error-queue data on the receive path"),
        ):
            with self.subTest(reason=reason, size=len(message)):
                with self.assertRaisesRegex(ec.TransportError, reason):
                    self.normalize(message)

    def test_missing_invalid_and_duplicate_auxdata_deny_complete_link_evidence(self):
        for control in (
            [], None, [timestamp()], [(263, 9, auxdata(29)[2])],
            [(263, 8, bytes(19))], [(263, 8, bytes(21))], [auxdata(29), auxdata(29)],
            [auxdata(29), timestamp(), (1, 22, b"")], [auxdata(29), (1,)],
            [(263, 8, memoryview(auxdata(29)[2]))], [auxdata(29, 30)], [auxdata(30, 28)],
        ):
            with self.subTest(control=control):
                event = self.normalize((NATIVE_RETURN, control, 0, RX_ADDRESS))
                self.assertIsNone(event.packet_metadata.vlan_tagged)
                self.assertIsNone(event.packet_metadata.packet_length)
        event = self.normalize(received(control=(auxdata(29), (2, 99, b"other"))))
        self.assertEqual(event.packet_metadata.packet_length, 29)
        self.assertIs(event.packet_metadata.vlan_tagged, False)

    def test_truncated_data_and_truncated_control_are_distinct(self):
        flag_data = self.normalize(received(flags=MSG_TRUNC))
        self.assertTrue(flag_data.truncated)
        self.assertFalse(flag_data.packet_metadata.vlan_tagged)
        flag_control = self.normalize(received(flags=MSG_CTRUNC))
        self.assertFalse(flag_control.truncated)
        self.assertIsNone(flag_control.packet_metadata.rx_software_ns)
        self.assertIsNone(flag_control.packet_metadata.packet_length)
        self.assertIsNone(flag_control.packet_metadata.vlan_tagged)
        flags = self.normalize(received(flags=MSG_TRUNC | MSG_CTRUNC))
        self.assertTrue(flags.truncated)
        aux = self.normalize(received(control=[auxdata(30, 29), timestamp()]))
        self.assertTrue(aux.truncated)
        self.assertEqual(aux.packet_metadata.packet_length, 30)

    def test_auxdata_length_exceeding_the_capture_is_truncated_even_without_the_flag(self):
        full = single_payload(bytes(1486))
        result = self.normalize(received(full, control=[auxdata(1515, 1515)]))
        self.assertEqual((len(result.data), result.packet_metadata.packet_length), (1514, 1515))
        self.assertTrue(result.truncated)

    def test_vlan_tag_and_tpid_validity_do_not_turn_contradictory_metadata_into_untagged(self):
        for status, expected in ((0x01, False), (0x11, True), (0x51, True), (0x41, None)):
            with self.subTest(status=status):
                control = [timestamp(), auxdata(29, status=status, tpid=0x8100 if status & 0x40 else 0)]
                result = self.normalize(received(control=control))
                self.assertIs(result.packet_metadata.vlan_tagged, expected)
                self.assertEqual(result.packet_metadata.packet_length, 29)
