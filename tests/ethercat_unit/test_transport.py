from dataclasses import replace

from support import OfflineCase, ec
from vectors import FPRD_REQUEST, FPRD_RETURN


class TypesAndMemoryTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.clock = ec.VirtualClock(10)
        self.context = ec.ExchangeContext("fixture")
        self.first = ec.FrameEvent(15, "fixture", self.context.exchange_id, ec.Direction.INBOUND, b"")
        self.second = ec.RejectionEvent(15, "fixture", self.context.exchange_id, ec.Direction.INBOUND, ec.ReadProfile.FPRD)

    def test_virtual_clock_is_an_explicit_nonnegative_monotonic_nanosecond_clock(self):
        self.assertEqual(ec.VirtualClock()(), 0)
        self.clock.advance_to(10)
        self.clock.advance_to(11)
        self.assertEqual(self.clock(), 11)
        for value in (-1, True, 10.0, None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "nonnegative integer"):
                    ec.VirtualClock(value)
        for value in (10, 11.0, True, None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "cannot move backwards"):
                    self.clock.advance_to(value)
                self.assertEqual(self.clock(), 11)

    def test_context_tokens_are_unique_and_labels_are_bounded(self):
        first, second = ec.ExchangeContext("x"), ec.ExchangeContext("x")
        self.assertIsNot(first.exchange_id, second.exchange_id)
        token = []
        self.assertIs(ec.ExchangeContext("x" * 15, token).exchange_id, token)
        for label in ("", "x" * 16, None, 2):
            with self.subTest(label=label):
                with self.assertRaisesRegex(ec.UsageError, "bounded interface label"):
                    ec.ExchangeContext(label)
        with self.assertRaisesRegex(ec.UsageError, "context token"):
            ec.ExchangeContext("x", None)

    def test_event_time_interface_data_and_flags_are_typed(self):
        self.assertEqual((self.first.padding, self.first.truncated, self.first.packet_metadata),
                         (ec.Padding.STRIPPED, False, None))
        self.assertEqual(len(replace(self.first, data=bytes(1514)).data), 1514)
        self.assertIsNone(replace(self.first, interface=None).interface)
        for changes, error, reason in (
            ({"timestamp_ns": -1}, ValueError, "nonnegative integer"),
            ({"timestamp_ns": True}, ValueError, "nonnegative integer"),
            ({"interface": ""}, ValueError, "interface label"),
            ({"interface": 12}, ValueError, "interface label"),
            ({"direction": "inbound"}, TypeError, "Direction"),
            ({"data": bytearray()}, ValueError, "1514"),
            ({"data": bytes(1515)}, ValueError, "1514"),
            ({"padding": "stripped"}, TypeError, "Padding"),
            ({"truncated": 1}, TypeError, "truncation flag"),
        ):
            with self.subTest(changes=list(changes)):
                with self.assertRaisesRegex(error, reason):
                    replace(self.first, **changes)
        with self.assertRaisesRegex(TypeError, "synthetic rejection requires a read profile"):
            replace(self.second, profile="FPRD")

    def test_queue_shape_type_limit_and_chronology_are_validated(self):
        for events, error, reason in (
            ([self.first], ec.UsageError, "tuple"),
            ((self.first,) * 65, ec.UsageError, "at most 64"),
            ((None,), TypeError, "typed frame or rejection"),
            ((self.first, replace(self.second, timestamp_ns=14)), ec.UsageError, "nondecreasing"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(error, reason):
                    ec.MemoryTransport(self.clock, events)
                self.assertEqual(self.clock(), 10)
        for count in (63, 64):
            with self.subTest(count=count):
                events = tuple(replace(self.first, data=bytes([i]).rjust(1514, b"\0")) for i in range(count))
                clock = ec.VirtualClock()
                transport = ec.MemoryTransport(clock, events)
                transport.open(20)
                outgoing = bytes(1514)
                transport.send(outgoing, 20)
                self.assertEqual(transport.sent_frame, outgoing)
                self.assertEqual([transport.receive(20).data[-1] for _ in events], list(range(count)))
                self.assertEqual(clock(), 15)
                self.assertIsNone(transport.receive(20))
                self.assertEqual(clock(), 20)
                transport.close()
                self.assertTrue(transport.closed)

    def test_lifecycle_delivery_bounds_no_reopen_and_close_discards_the_queue(self):
        transport = ec.MemoryTransport(self.clock, (self.first, self.second))
        self.assertIs(transport.origin, ec.Origin.SYNTHETIC)
        self.assertIsNone(transport.sent_frame)
        with self.assertRaisesRegex(ec.TransportError, "cannot accept"):
            transport.send(FPRD_REQUEST, 20)
        with self.assertRaisesRegex(ec.DeadlineExpired, "deadline"):
            transport.open(10)
        transport.open(20)
        with self.assertRaisesRegex(ec.TransportError, "single-use"):
            transport.open(20)
        with self.assertRaisesRegex(ec.TransportError, "no pending"):
            transport.receive(20)
        for data in (None, bytearray(b"x"), b"", bytes(1515)):
            with self.subTest(length=None if data is None else len(data)):
                with self.assertRaisesRegex(ec.TransportError, "bounded frame buffer"):
                    transport.send(data, 20)
                self.assertIsNone(transport.sent_frame)
        with self.assertRaisesRegex(ec.DeadlineExpired, "deadline"):
            transport.send(FPRD_REQUEST, 10)
        transport.send(FPRD_REQUEST, 20)
        self.assertEqual(transport.sent_frame, FPRD_REQUEST)
        with self.assertRaisesRegex(ec.TransportError, "cannot accept another"):
            transport.send(FPRD_RETURN, 20)
        self.assertEqual(transport.sent_frame, FPRD_REQUEST)
        transport.close()
        transport.close()
        self.assertTrue(transport.closed)
        self.assertEqual(len(transport._events), 0)
        with self.assertRaisesRegex(ec.TransportError, "no pending"):
            transport.receive(20)
        with self.assertRaisesRegex(ec.TransportError, "single-use"):
            transport.open(20)

    def test_receive_keeps_fifo_on_ties_and_pending_events_at_the_deadline(self):
        clock = ec.VirtualClock(16)
        edge = replace(self.first, timestamp_ns=20)
        transport = ec.MemoryTransport(clock, (self.first, self.second, edge))
        transport.open(20)
        transport.send(b"x", 20)
        self.assertIs(transport.receive(20), self.first)
        self.assertIs(transport.receive(20), self.second)
        self.assertEqual(clock(), 16)
        self.assertIsNone(transport.receive(20))
        self.assertEqual(clock(), 20)
        self.assertIsNone(transport.receive(20))
        self.assertIs(transport.receive(21), edge)
        transport.close()
