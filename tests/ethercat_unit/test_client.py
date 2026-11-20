from dataclasses import replace
import math
from unittest.mock import Mock, call

from support import OfflineCase, ec
from vectors import FPRD_REQUEST, FPRD_RETURN, replace_field


class ExchangeTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.clock = ec.VirtualClock(100)
        self.context = ec.ExchangeContext("fixture")
        self.event = ec.FrameEvent(500, "fixture", self.context.exchange_id, ec.Direction.INBOUND, FPRD_RETURN)
        self.deadline = 1_000_100

    def transport(self):
        transport = Mock(spec_set=["open", "send", "receive", "close", "origin"])
        transport.origin = ec.Origin.SYNTHETIC
        return transport

    def event_at(self, timestamp, result=None):
        def receive(deadline):
            self.assertEqual(deadline, self.deadline)
            self.clock.advance_to(timestamp)
            if isinstance(result, BaseException):
                raise result
            return result
        return receive

    def exchange(self, transport):
        result = ec.run_exchange(ec.ReadProfile.FPRD, self.context, transport, self.clock, 0.001)
        self.assertIs(result.mode, ec.Mode.SIMULATE)
        self.assertIs(result.origin, ec.Origin.SYNTHETIC)
        self.assertIs(result.detail.profile, ec.ReadProfile.FPRD)
        self.assertEqual(result.detail.expected_wkc, 1)
        return result

    def assert_outcome(self, result, status, phase, delivery, events, reason):
        self.assertIs(result.status, status)
        self.assertIs(result.phase, phase)
        self.assertIs(result.detail.delivery, delivery)
        self.assertEqual(result.detail.events, events)
        self.assertIn(reason, result.reason)

    def test_unrelated_and_outbound_events_do_not_end_exchange_or_trigger_retry(self):
        transport = self.transport()
        foreign = replace(self.event, data=replace_field(FPRD_RETURN, 20, b"\x01"))
        transport.receive.side_effect = (
            replace(self.event, direction=ec.Direction.OUTBOUND, timestamp_ns=100),
            replace(foreign, timestamp_ns=100),
            replace(self.event, timestamp_ns=100),
            AssertionError("a duplicate after the terminal return must not be read"),
        )
        result = self.exchange(transport)
        self.assert_outcome(result, ec.Status.OK, ec.Phase.CORRELATE, ec.Delivery.ACCEPTED, 3, "matches")
        self.assertEqual((result.detail.assessment.wkc, result.detail.elapsed_ns), (1, 0))
        self.assertEqual(transport.mock_calls, [
            call.open(self.deadline), call.send(FPRD_REQUEST, self.deadline),
            call.receive(self.deadline), call.receive(self.deadline), call.receive(self.deadline), call.close(),
        ])

    def test_byte_complete_return_at_deadline_is_not_success(self):
        for delta, status, reason in ((-1, ec.Status.OK, "matches"), (0, ec.Status.INDETERMINATE, "outside"),
                                      (1, ec.Status.INDETERMINATE, "outside")):
            with self.subTest(delta=delta):
                self.clock = ec.VirtualClock(100)
                observed = self.deadline + delta
                transport = self.transport()
                transport.receive.side_effect = self.event_at(observed, replace(self.event, timestamp_ns=observed))
                result = self.exchange(transport)
                self.assert_outcome(result, status, ec.Phase.CORRELATE, ec.Delivery.ACCEPTED, 1, reason)
                self.assertEqual(result.detail.elapsed_ns, 1_000_000 + delta)
                transport.close.assert_called_once_with()

    def test_expiry_precedence_with_and_without_foreign_candidate(self):
        for foreign in (False, True):
            for reported in (None, ec.DeadlineExpired("wait expired")):
                with self.subTest(foreign=foreign, reported=reported):
                    self.clock = ec.VirtualClock(100)
                    transport = self.transport()
                    first = replace(self.event, interface="foreign", timestamp_ns=100)

                    def receive(deadline):
                        if foreign and transport.receive.call_count == 1:
                            return first
                        return self.event_at(self.deadline, reported)(deadline)

                    transport.receive.side_effect = receive
                    result = self.exchange(transport)
                    status = ec.Status.UNCORRELATED if foreign else ec.Status.TIMEOUT
                    self.assert_outcome(result, status, ec.Phase.RECEIVE, ec.Delivery.ACCEPTED, int(foreign), "eadline")
                    self.assertEqual(result.detail.elapsed_ns, 1_000_000)
                    self.assertEqual(transport.receive.call_count, 1 + int(foreign))
                    transport.close.assert_called_once_with()

    def test_premature_expiry_and_event_budget_are_indeterminate(self):
        for reported in (None, ec.DeadlineExpired("too soon")):
            with self.subTest(reported=reported):
                transport = self.transport()
                transport.receive.side_effect = self.event_at(200, reported)
                self.clock = ec.VirtualClock(100)
                result = self.exchange(transport)
                self.assert_outcome(result, ec.Status.INDETERMINATE, ec.Phase.RECEIVE,
                                    ec.Delivery.ACCEPTED, 0, "before the deadline")
                self.assertIsNone(result.detail.assessment)
        matching = replace(self.event, timestamp_ns=100)
        echo = replace(matching, direction=ec.Direction.OUTBOUND)
        for skipped in (62, 63, 64):
            with self.subTest(skipped=skipped):
                self.clock = ec.VirtualClock(100)
                transport = self.transport()
                transport.receive.side_effect = [echo] * skipped + [matching]
                result = self.exchange(transport)
                if skipped < 64:
                    self.assert_outcome(result, ec.Status.OK, ec.Phase.CORRELATE,
                                        ec.Delivery.ACCEPTED, skipped + 1, "matches")
                else:
                    self.assert_outcome(result, ec.Status.INDETERMINATE, ec.Phase.RECEIVE,
                                        ec.Delivery.ACCEPTED, 64, "budget exhausted")
                    self.assertIsNone(result.detail.assessment)
                self.assertEqual(transport.receive.call_count, min(skipped + 1, 64))
                transport.send.assert_called_once_with(FPRD_REQUEST, self.deadline)
                transport.close.assert_called_once_with()

    def test_initialization_expiry_forbids_send(self):
        transport = self.transport()
        transport.open.side_effect = self.event_at(self.deadline)
        result = self.exchange(transport)
        self.assert_outcome(result, ec.Status.TIMEOUT, ec.Phase.INITIALIZE, ec.Delivery.NOT_SENT,
                            0, "during initialization")
        self.assertEqual(transport.mock_calls, [call.open(self.deadline), call.close()])

    def test_phase_and_delivery_control_error_classification(self):
        local, timeout = ec.Status.LOCAL_ERROR, ec.Status.TIMEOUT
        uncertain, interrupted = ec.Status.INDETERMINATE, ec.Status.INTERRUPTED
        opening, sending, receiving = ec.Phase.INITIALIZE, ec.Phase.SEND, ec.Phase.RECEIVE
        unsent, possible, accepted = ec.Delivery.NOT_SENT, ec.Delivery.UNCERTAIN, ec.Delivery.ACCEPTED
        cases = (
            ("open", ec.TransportError("open-fault"), local, opening, unsent),
            ("open", OSError("open-fault"), local, opening, unsent),
            ("open", ec._UnsupportedTransport("open-fault"), ec.Status.UNSUPPORTED, opening, unsent),
            ("open", ec.DeadlineExpired("open-fault"), timeout, opening, unsent),
            ("open", KeyboardInterrupt(), interrupted, opening, unsent),
            ("send", ec.DeadlineExpired("send-fault"), timeout, sending, unsent),
            ("send", ec.TransportError("send-fault"), local, sending, unsent),
            ("send", ec.DeliveryUncertain("send-fault"), uncertain, sending, possible),
            ("send", OSError("send-fault"), uncertain, sending, possible),
            ("send", KeyboardInterrupt(), interrupted, sending, possible),
            ("send", ec._InterruptedBeforeSend(), interrupted, sending, unsent),
            ("receive", ec.TransportError("receive-fault"), uncertain, receiving, accepted),
            ("receive", OSError("receive-fault"), uncertain, receiving, accepted),
            ("receive", KeyboardInterrupt(), interrupted, receiving, accepted),
        )
        expected_calls = {
            "open": [call.open(self.deadline), call.close()],
            "send": [call.open(self.deadline), call.send(FPRD_REQUEST, self.deadline), call.close()],
            "receive": [call.open(self.deadline), call.send(FPRD_REQUEST, self.deadline),
                        call.receive(self.deadline), call.close()],
        }
        for method, error, status, phase, delivery in cases:
            with self.subTest(method=method, error=type(error).__name__):
                transport = self.transport()
                getattr(transport, method).side_effect = error
                result = self.exchange(transport)
                reason = "interrupted by user" if status is interrupted else f"{method}-fault"
                self.assert_outcome(result, status, phase, delivery, 0, reason)
                self.assertEqual(transport.mock_calls, expected_calls[method])
                self.assertIsNone(result.cleanup)

    def test_cleanup_retains_primary_result_and_only_overrides_success(self):
        for primary in (None, OSError("primary bind"), KeyboardInterrupt()):
            for secondary in (RuntimeError("secondary close"), KeyboardInterrupt()):
                with self.subTest(primary=primary, secondary=secondary):
                    transport = self.transport()
                    transport.open.side_effect = primary
                    transport.receive.return_value = replace(self.event, timestamp_ns=100)
                    transport.close.side_effect = secondary
                    result = self.exchange(transport)
                    expected = ec.Status.OK if primary is None else (
                        ec.Status.INTERRUPTED if isinstance(primary, KeyboardInterrupt) else ec.Status.LOCAL_ERROR)
                    self.assertIs(result.cleanup.primary_status, expected)
                    self.assertEqual(result.cleanup.reason,
                                     "KeyboardInterrupt" if isinstance(secondary, KeyboardInterrupt) else
                                     "RuntimeError: secondary close")
                    if primary is None:
                        status = ec.Status.INTERRUPTED if isinstance(secondary, KeyboardInterrupt) else ec.Status.LOCAL_ERROR
                        self.assert_outcome(result, status, ec.Phase.CLOSE, ec.Delivery.ACCEPTED, 1, "after a matching return")
                        self.assertEqual(result.detail.assessment.wkc, 1)
                        transport.receive.assert_called_once_with(self.deadline)
                    else:
                        reason = "interrupted by user" if isinstance(primary, KeyboardInterrupt) else "primary bind"
                        self.assert_outcome(result, expected, ec.Phase.INITIALIZE, ec.Delivery.NOT_SENT, 0, reason)
                        transport.send.assert_not_called()
                    transport.close.assert_called_once_with()

    def test_unexpected_exception_keeps_identity_and_cleanup_note(self):
        for secondary in (None, RuntimeError("close failed")):
            with self.subTest(secondary=secondary):
                transport = self.transport()
                primary = AssertionError("broken transport invariant")
                transport.receive.side_effect = primary
                transport.close.side_effect = secondary
                with self.assertRaises(AssertionError) as raised:
                    self.exchange(transport)
                self.assertIs(raised.exception, primary)
                self.assertEqual(getattr(primary, "__notes__", []),
                                 ["Cleanup failed: RuntimeError: close failed"] if secondary else [])
                transport.close.assert_called_once_with()

    def test_unprintable_cleanup_error_preserves_the_primary_failure(self):
        class UnprintableCloseError(OSError):
            def __str__(self):
                raise ValueError("fixture close error text unavailable")

        cleanup_reason = "UnprintableCloseError: <message unavailable>"
        for error_type in (PermissionError, TypeError):
            with self.subTest(error=error_type.__name__):
                transport = self.transport()
                cause = OSError("underlying fixture failure")
                primary = error_type("fixture open failed")
                primary.add_note("original note")

                def fail_open(deadline):
                    raise primary from cause

                transport.open.side_effect = fail_open
                transport.close.side_effect = UnprintableCloseError()
                if error_type is PermissionError:
                    result = self.exchange(transport)
                    self.assert_outcome(result, ec.Status.LOCAL_ERROR, ec.Phase.INITIALIZE, ec.Delivery.NOT_SENT,
                                        0, "PermissionError: fixture open failed")
                    self.assertIs(type(result.cleanup), ec.CleanupFailure)
                    self.assertIs(result.cleanup.primary_status, ec.Status.LOCAL_ERROR)
                    self.assertEqual(result.cleanup.reason, cleanup_reason)
                else:
                    with self.assertRaises(TypeError) as raised:
                        self.exchange(transport)
                    self.assertIs(raised.exception, primary)
                    self.assertEqual(primary.__notes__, ["original note", "Cleanup failed: " + cleanup_reason])
                self.assertIs(primary.__cause__, cause)
                self.assertEqual(transport.mock_calls, [call.open(self.deadline), call.close()])

    def test_validation_precedes_transfer_of_resource_ownership(self):
        native = ec._NativeDiagnosticContext("fixture", 0x12, ec.Padding.STRIPPED)
        transport = self.transport()
        for profile, context, timeout, reason in (
            (ec.ReadProfile.FPRD, self.context, 0, "timeout"),
            ("FPRD", self.context, 1, "unknown synthetic read profile"),
            (ec.ReadProfile.APRD, native, 1, "requires the Linux packet transport"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ec.UsageError, reason):
                    ec.run_exchange(profile, context, transport, self.clock, timeout)
        self.assertEqual(transport.mock_calls, [])
        transport.origin = ec.Origin.NATIVE_TEST
        with self.assertRaisesRegex(ec.UsageError, "native diagnosis requires"):
            ec.run_exchange(ec.ReadProfile.APRD, native, transport, self.clock)
        self.assertEqual(transport.mock_calls, [])

    def test_invalid_synthetic_context_is_rejected_before_open(self):
        transport = self.transport()
        transport.receive.side_effect = self.event_at(self.deadline)
        with self.assertRaisesRegex(ec.UsageError, "synthetic exchange requires"):
            ec.run_exchange(ec.ReadProfile.FPRD, None, transport, self.clock, 0.001)
        self.assertEqual(transport.mock_calls, [])

    def test_memory_transport_uses_the_same_clock_as_its_client(self):
        other = ec.VirtualClock(self.clock())
        transport = ec.MemoryTransport(other, ())
        with self.assertRaisesRegex(ec.UsageError, "share the same clock"):
            self.exchange(transport)
        self.assertEqual((self.clock(), other()), (100, 100))
        self.assertFalse(transport.closed)
        self.assertIsNone(transport.sent_frame)

    def test_timeout_validation_is_finite_and_inclusive(self):
        for value in (0.001, math.nextafter(0.001, math.inf), 1, math.nextafter(10, 0), 10):
            with self.subTest(value=value):
                self.assertIs(type(ec.validate_timeout(value)), float)
                self.assertEqual(ec.validate_timeout(value), value)
        for value in (math.nextafter(0.001, 0), math.nextafter(10, math.inf), math.nan, math.inf,
                      -math.inf, "1", True, None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ec.UsageError, "finite and between"):
                    ec.validate_timeout(value)

    def test_simulation_scenarios_preserve_delivery_status_and_provenance_in_both_profiles(self):
        cases = (
            (ec.Scenario.SUCCESS, ec.Status.OK, ec.Phase.CORRELATE, 1, 1, 500_000),
            (ec.Scenario.TIMEOUT, ec.Status.TIMEOUT, ec.Phase.RECEIVE, 0, None, 1_000_000_000),
            (ec.Scenario.UNCORRELATED, ec.Status.UNCORRELATED, ec.Phase.RECEIVE, 1, None, 1_000_000_000),
            (ec.Scenario.WKC_MISMATCH, ec.Status.INDETERMINATE, ec.Phase.CORRELATE, 1, 0, 500_000),
            (ec.Scenario.INVALID, ec.Status.PROTOCOL_ERROR, ec.Phase.CORRELATE, 1, None, 500_000),
            (ec.Scenario.REJECTED, ec.Status.REJECTED, ec.Phase.CORRELATE, 1, None, 500_000),
        )
        for profile in (ec.ReadProfile.FPRD, ec.ReadProfile.APRD):
            for scenario, status, phase, events, wkc, elapsed in cases:
                with self.subTest(profile=profile, scenario=scenario):
                    result = ec.simulate(scenario, profile=profile)
                    self.assertEqual((result.status, result.phase, result.origin, result.mode),
                                     (status, phase, ec.Origin.SYNTHETIC, ec.Mode.SIMULATE))
                    detail = result.detail
                    self.assertEqual((detail.profile, detail.delivery, detail.events, detail.expected_wkc, detail.elapsed_ns),
                                     (profile, ec.Delivery.ACCEPTED, events, 1, elapsed))
                    self.assertEqual(detail.assessment.wkc if detail.assessment else None, wkc)
                    self.assertIsNone(result.cleanup)
        for timeout, nanoseconds in ((0.001, 1_000_000), (0.001000001, 1_000_001), (10, 10_000_000_000)):
            with self.subTest(timeout=timeout):
                self.assertEqual(ec.simulate(ec.Scenario.TIMEOUT, timeout).detail.elapsed_ns, nanoseconds)
        for scenario, profile in (("success", ec.ReadProfile.FPRD), (ec.Scenario.SUCCESS, "FPRD")):
            with self.subTest(scenario=scenario, profile=profile):
                with self.assertRaisesRegex(ec.UsageError, "known scenario and read profile"):
                    ec.simulate(scenario, profile=profile)
