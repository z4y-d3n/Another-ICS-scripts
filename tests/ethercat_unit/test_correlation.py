from dataclasses import replace

from support import OfflineCase, ec
from vectors import APRD_RETURN, FPRD_RETURN, NATIVE_RETURN, nop_chain, replace_field, wrap_chain

MATCHED = ec.Attribution.MATCHED
FOREIGN = ec.Attribution.FOREIGN
INSUFFICIENT = ec.Attribution.INSUFFICIENT


class CorrelationTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.context = ec.ExchangeContext("memory")
        self.pending = ec.PendingExchange(ec.ReadProfile.APRD, self.context, 10, 21)
        self.event = ec.FrameEvent(15, "memory", self.context.exchange_id, ec.Direction.INBOUND, APRD_RETURN)
        native = ec._NativeDiagnosticContext("fixture0", 0x12, ec.Padding.STRIPPED)
        self.native_pending = ec.PendingExchange(ec.ReadProfile.APRD, native, 10, 21)
        tx = 1_700_000_000_000_010_000
        self.metadata = ec.PacketMetadata(0x88A4, 0, 1, False, 29, tx, tx + 1)
        self.native_event = ec.FrameEvent(15, "fixture0", None, ec.Direction.INBOUND, NATIVE_RETURN,
                                          packet_metadata=self.metadata)

    def assert_assessment(self, result, status, attribution, reason, structure=None, wkc=None, esc_type=None):
        self.assertIs(result.status, status)
        self.assertIs(result.attribution, attribution)
        self.assertIs(result.structurally_valid, structure)
        self.assertEqual((result.wkc, result.esc_type), (wkc, esc_type))
        self.assertIn(reason, result.reason)

    def test_stable_fields_vary_independently_in_both_profiles(self):
        cases = (
            ("destination", 0, b"\x02"), ("EtherType", 12, b"\x08\x00"),
            ("frame type", 15, b"\x20"), ("command", 16, b"\x03"), ("index", 17, b"\xa7"),
            ("register", 20, b"\x17"), ("length", 22, b"\x03"),
        )
        for profile, raw in ((ec.ReadProfile.FPRD, FPRD_RETURN), (ec.ReadProfile.APRD, APRD_RETURN)):
            pending = replace(self.pending, profile=profile)
            self.assert_assessment(ec.assess_event(replace(self.event, data=raw), pending, 15),
                                   ec.Status.OK, MATCHED, "synthetic return", True, 1)
            for field, offset, value in cases:
                with self.subTest(profile=profile, field=field):
                    candidate = replace(self.event, data=replace_field(raw, offset, value))
                    self.assert_assessment(ec.assess_event(candidate, pending, 15),
                                           ec.Status.UNCORRELATED, FOREIGN, "identity fields")
        event = replace(self.event, data=replace_field(FPRD_RETURN, 18, b"\x35\x12"))
        self.assert_assessment(ec.assess_event(event, replace(self.pending, profile=ec.ReadProfile.FPRD), 15),
                               ec.Status.UNCORRELATED, FOREIGN, "identity fields")

    def test_mutable_source_irq_and_c_do_not_override_a_matched_read(self):
        for offset, edited in ((6, b"\x02\x10\x10\x10\x10\x10"), (23, b"\x00"), (24, b"\xff\xfe")):
            with self.subTest(offset=offset):
                event = replace(self.event, data=replace_field(APRD_RETURN, offset, edited))
                self.assert_assessment(ec.assess_event(event, self.pending, 15), ec.Status.OK,
                                       MATCHED, "synthetic return", True, 1)

    def test_direction_interface_and_session_are_independent_conditions(self):
        cases = (
            ({"direction": ec.Direction.OUTBOUND, "data": b"", "interface": "other"},
             None, ec.Attribution.IGNORED, "outbound copy"),
            ({"interface": "other"}, ec.Status.UNCORRELATED, FOREIGN, "another interface"),
            ({"exchange_id": object()}, ec.Status.UNCORRELATED, FOREIGN, "another exchange"),
            ({"direction": ec.Direction.UNKNOWN}, ec.Status.INDETERMINATE, INSUFFICIENT, "incomplete direction"),
            ({"interface": None}, ec.Status.INDETERMINATE, INSUFFICIENT, "incomplete direction"),
            ({"exchange_id": None}, ec.Status.INDETERMINATE, INSUFFICIENT, "incomplete direction"),
            ({"packet_metadata": self.metadata}, ec.Status.INDETERMINATE, INSUFFICIENT, "incomplete direction"),
        )
        for changes, status, attribution, reason in cases:
            with self.subTest(changes=changes):
                self.assert_assessment(ec.assess_event(replace(self.event, **changes), self.pending, 15),
                                       status, attribution, reason)
        first, equal_but_distinct = [1], [1]
        pending = replace(self.pending, context=ec.ExchangeContext("memory", first))
        event = replace(self.event, exchange_id=equal_but_distinct)
        self.assertEqual(first, equal_but_distinct)
        self.assert_assessment(ec.assess_event(event, pending, 15),
                               ec.Status.UNCORRELATED, FOREIGN, "another exchange")

    def test_exchange_window_requires_send_at_or_before_event_and_exclusive_deadline(self):
        for stamped, observed, ok in (
            (9, 15, False), (10, 10, True), (14, 15, True), (16, 15, False),
            (20, 20, True), (20, 21, False), (21, 21, False), (22, 22, False),
        ):
            with self.subTest(stamped=stamped, observed=observed):
                result = ec.assess_event(replace(self.event, timestamp_ns=stamped), self.pending, observed)
                if ok:
                    self.assert_assessment(result, ec.Status.OK, MATCHED, "synthetic return", True, 1)
                else:
                    self.assert_assessment(result, ec.Status.INDETERMINATE, INSUFFICIENT, "outside the exchange window")

    def test_truncated_prefix_rules_require_complete_fields_before_attribution(self):
        for size in (0, 5, 6, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23):
            with self.subTest(size=size):
                result = ec.assess_event(replace(self.event, data=APRD_RETURN[:size]), self.pending, 15)
                self.assert_assessment(result, ec.Status.INDETERMINATE, INSUFFICIENT, "complete return identity")
        for offset, value in ((0, b"\x02\xff\xff\xff\xff\xff"), (12, b"\x08\x00"),
                              (16, b"\x04"), (17, b"\x37"), (20, b"\x22\x00")):
            with self.subTest(offset=offset):
                raw = replace_field(APRD_RETURN, offset, value)[:offset + len(value)]
                self.assert_assessment(ec.assess_event(replace(self.event, data=raw), self.pending, 15),
                                       ec.Status.UNCORRELATED, FOREIGN, "identity fields")
        # Bytes outside the declared chain cannot establish identity.
        bounded = replace_field(APRD_RETURN, 14, b"\x07\x10")
        self.assert_assessment(ec.assess_event(replace(self.event, data=bounded), self.pending, 15),
                               ec.Status.INDETERMINATE, INSUFFICIENT, "complete return identity")

    def test_structural_validity_and_position_take_precedence_over_payload_and_counter(self):
        for size in range(24, 29):
            with self.subTest(size=size):
                event = replace(self.event, data=APRD_RETURN[:size])
                self.assert_assessment(ec.assess_event(event, self.pending, 15),
                                       ec.Status.PROTOCOL_ERROR, MATCHED, f"byte {size}", False)
        contradicts = replace_field(APRD_RETURN, 18, b"\x03\x00")
        self.assert_assessment(ec.assess_event(replace(self.event, data=contradicts), self.pending, 15),
                               ec.Status.INDETERMINATE, INSUFFICIENT, "position 0x0003", True, 1)
        self.assert_assessment(ec.assess_event(replace(self.event, data=contradicts[:-1]), self.pending, 15),
                               ec.Status.INDETERMINATE, INSUFFICIENT, "position 0x0003", False)
        datagram = replace_field(APRD_RETURN, 23, b"\xc0")[16:]
        for extra, structure, reason in ((1, True, "unexpected datagram count"), (15, None, "15 datagrams")):
            with self.subTest(extra=extra):
                event = replace(self.event, data=wrap_chain(datagram + nop_chain(extra)))
                self.assert_assessment(ec.assess_event(event, self.pending, 15),
                                       ec.Status.INDETERMINATE, INSUFFICIENT, reason, structure)
        self.assert_assessment(ec.assess_event(replace(self.event, truncated=True), self.pending, 15),
                               ec.Status.PROTOCOL_ERROR, MATCHED, "reported truncation", False)

    def test_working_counter_and_value_have_distinct_roles(self):
        for profile, raw in ((ec.ReadProfile.FPRD, FPRD_RETURN), (ec.ReadProfile.APRD, APRD_RETURN)):
            pending = replace(self.pending, profile=profile)
            for wkc in (0, 1, 2, 32768, 65535):
                with self.subTest(profile=profile, wkc=wkc):
                    event = replace(self.event, data=raw[:-2] + wkc.to_bytes(2, "little"))
                    status, reason = (ec.Status.OK, "synthetic return") if wkc == 1 else (
                        ec.Status.INDETERMINATE, "Working Counter differs")
                    self.assert_assessment(ec.assess_event(event, pending, 15), status, MATCHED, reason, True, wkc)
            value_fault = replace_field(raw, 26, b"\x2a")
            self.assert_assessment(ec.assess_event(replace(self.event, data=value_fault), pending, 15),
                                   ec.Status.INDETERMINATE, MATCHED, "read value differs", True, 1)
            both_faults = value_fault[:-2] + b"\x02\x00"
            self.assert_assessment(ec.assess_event(replace(self.event, data=both_faults), pending, 15),
                                   ec.Status.INDETERMINATE, MATCHED, "Working Counter differs", True, 2)

    def test_explicit_rejection_is_exclusive_to_attributable_synthetic_events(self):
        negative = ec.RejectionEvent(15, "memory", self.context.exchange_id, ec.Direction.INBOUND, ec.ReadProfile.APRD)
        self.assert_assessment(ec.assess_event(negative, self.pending, 15),
                               ec.Status.REJECTED, MATCHED, "explicit rejection")
        self.assert_assessment(ec.assess_event(replace(negative, profile=ec.ReadProfile.FPRD), self.pending, 15),
                               ec.Status.UNCORRELATED, FOREIGN, "another profile")
        self.assert_assessment(ec.assess_event(replace(negative, exchange_id=None), self.pending, 15),
                               ec.Status.INDETERMINATE, INSUFFICIENT, "incomplete direction")
        self.assert_assessment(ec.assess_event(replace(negative, interface="fixture0"), self.native_pending, 15),
                               ec.Status.UNCORRELATED, FOREIGN, "synthetic event")

    def test_native_link_evidence_requires_protocol_link_type_vlan_and_no_token(self):
        result = ec.assess_event(self.native_event, self.native_pending, 15)
        self.assert_assessment(result, ec.Status.OK, MATCHED, "reference read", True, 1, 0x12)
        for field, foreign in (("protocol", 0x0800), ("hardware_type", 772), ("vlan_tagged", True)):
            for value in (foreign, None):
                with self.subTest(field=field, value=value):
                    metadata = replace(self.metadata, **{field: value})
                    result = ec.assess_event(replace(self.native_event, packet_metadata=metadata), self.native_pending, 15)
                    if value is None:
                        self.assert_assessment(result, ec.Status.INDETERMINATE, INSUFFICIENT, "incomplete direction")
                    else:
                        self.assert_assessment(result, ec.Status.UNCORRELATED, FOREIGN, "outside the link profile")
        for changes in ({"packet_metadata": None}, {"exchange_id": object()}):
            with self.subTest(changes=changes):
                result = ec.assess_event(replace(self.native_event, **changes), self.native_pending, 15)
                self.assert_assessment(result, ec.Status.INDETERMINATE, INSUFFICIENT, "incomplete direction")

    def test_native_order_is_compared_within_the_kernel_clock_domain(self):
        tx = self.metadata.tx_scheduled_ns
        for sent, received in ((None, tx + 1), (tx, None), (tx, tx - 1), (tx, tx)):
            with self.subTest(sent=sent, received=received):
                metadata = replace(self.metadata, tx_scheduled_ns=sent, rx_software_ns=received)
                result = ec.assess_event(replace(self.native_event, packet_metadata=metadata), self.native_pending, 15)
                self.assert_assessment(result, ec.Status.INDETERMINATE, INSUFFICIENT, "kernel timestamps")
        result = ec.assess_event(self.native_event, self.native_pending, 21)
        self.assert_assessment(result, ec.Status.INDETERMINATE, INSUFFICIENT, "outside the exchange window")
        for offset, value, reason, wkc, esc in (
            (18, b"\x00\x00", "position", 1, 0x12),
            (26, b"\x13", "read value differs", 1, 0x13),
            (27, b"\x00", "Working Counter", 0, 0x12),
        ):
            with self.subTest(offset=offset):
                event = replace(self.native_event, data=replace_field(NATIVE_RETURN, offset, value))
                attribution = INSUFFICIENT if offset == 18 else MATCHED
                self.assert_assessment(ec.assess_event(event, self.native_pending, 15),
                                       ec.Status.INDETERMINATE, attribution, reason, True, wkc, esc)
