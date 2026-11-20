"""Exercise ownership and cleanup through the existing in-memory transport."""

from dataclasses import replace
from pathlib import Path
import sys
from unittest.mock import DEFAULT, Mock, call, patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ethercat_unit"))
try:
    from support import OfflineCase, ec
    from vectors import FPRD_REQUEST, FPRD_RETURN
finally:
    sys.path.pop(0)


START_NS = 100
OBSERVED_NS = 200
DEADLINE_NS = 1_000_100


class ResourceLifecycleTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.context = ec.ExchangeContext("fixture")
        self.rejection = ec.RejectionEvent(
            OBSERVED_NS, self.context.interface, self.context.exchange_id, ec.Direction.INBOUND, ec.ReadProfile.FPRD,
        )
        self.foreign = replace(self.rejection, interface="other")

    def tracked_transport(self, *events):
        clock = ec.VirtualClock(START_NS)
        transport = ec.MemoryTransport(clock, events)
        operations = Mock()
        for name in ("open", "send", "receive", "close"):
            method = self.enterContext(patch.object(transport, name, wraps=getattr(transport, name)))
            operations.attach_mock(method, name)
        return clock, transport, operations

    def exchange(self, clock, transport):
        result = ec.run_exchange(ec.ReadProfile.FPRD, self.context, transport, clock, timeout=0.001)
        self.assertIs(type(result), ec.OperationResult)
        self.assertIs(type(result.detail), ec.ExchangeEvidence)
        self.assertIs(result.mode, ec.Mode.SIMULATE)
        self.assertIs(result.origin, ec.Origin.SYNTHETIC)
        self.assertIs(result.detail.profile, ec.ReadProfile.FPRD)
        self.assertIs(type(result.detail.expected_wkc), int)
        self.assertEqual(result.detail.expected_wkc, 1)
        return result

    def assert_progress(self, result, status, phase, delivery, events, elapsed_ns):
        self.assertIs(result.status, status)
        self.assertIs(result.phase, phase)
        self.assertIs(result.detail.delivery, delivery)
        self.assertIs(type(result.detail.events), int)
        self.assertIs(type(result.detail.elapsed_ns), int)
        self.assertEqual((result.detail.events, result.detail.elapsed_ns), (events, elapsed_ns))

    def assert_cleanup(self, cleanup, primary_status, reason):
        if reason is None:
            self.assertIsNone(cleanup)
            return
        self.assertIs(type(cleanup), ec.CleanupFailure)
        self.assertIs(cleanup.primary_status, primary_status)
        self.assertEqual(cleanup.reason, reason)

    def assert_assessment(self, assessment, status, attribution, structure, wkc):
        self.assertIs(type(assessment), ec.EventAssessment)
        self.assertIs(assessment.status, status)
        self.assertIs(assessment.attribution, attribution)
        self.assertIs(assessment.structurally_valid, structure)
        self.assertIs(type(assessment.wkc), type(wkc))
        self.assertEqual(assessment.wkc, wkc)
        self.assertIsNone(assessment.esc_type)

    def fail_after_release(self, transport, error):
        def close():
            ec.MemoryTransport.close(transport)
            raise error

        transport.close.side_effect = close

    def assert_released(self, transport, operations, expected_calls):
        self.assertEqual(operations.mock_calls, expected_calls)
        self.assertTrue(transport.closed)
        self.assertEqual(len(transport._events), 0)

    def test_ownership_transfers_after_clock_read_and_closed_transport_cannot_send_again(self):
        clock, transport, operations = self.tracked_transport(self.rejection, self.foreign)
        failure = ValueError("fixture clock unavailable before open")
        with patch.object(ec.VirtualClock, "__call__", side_effect=failure):
            with self.assertRaises(ValueError) as raised:
                self.exchange(clock, transport)
        self.assertIs(raised.exception, failure)
        self.assertEqual(operations.mock_calls, [])
        self.assertFalse(transport.closed)
        self.assertIsNone(transport.sent_frame)

        result = self.exchange(clock, transport)
        self.assert_progress(result, ec.Status.REJECTED, ec.Phase.CORRELATE, ec.Delivery.ACCEPTED, 1,
                             OBSERVED_NS - START_NS)
        self.assertIsNone(result.cleanup)
        self.assert_released(transport, operations, [
            call.open(DEADLINE_NS), call.send(FPRD_REQUEST, DEADLINE_NS), call.receive(DEADLINE_NS), call.close(),
        ])

        operations.reset_mock()
        repeat_deadline = DEADLINE_NS + OBSERVED_NS - START_NS
        repeated = self.exchange(clock, transport)
        self.assert_progress(repeated, ec.Status.LOCAL_ERROR, ec.Phase.INITIALIZE, ec.Delivery.NOT_SENT, 0, 0)
        self.assertIsNone(repeated.detail.assessment)
        self.assertIn("single-use", repeated.reason)
        self.assertIsNone(repeated.cleanup)
        self.assertEqual(transport.sent_frame, FPRD_REQUEST)
        self.assert_released(transport, operations, [call.open(repeat_deadline), call.close()])

    def test_partial_open_releases_queued_events_even_if_cleanup_reports_a_failure(self):
        for error_type in (PermissionError, TimeoutError):
            for close_fault in (False, True):
                with self.subTest(error=error_type.__name__, close_fault=close_fault):
                    clock, transport, operations = self.tracked_transport(self.rejection)
                    primary = error_type("fixture initialization stopped")

                    def incomplete_open(deadline):
                        ec.MemoryTransport.open(transport, deadline)
                        raise primary

                    transport.open.side_effect = incomplete_open
                    cleanup_reason = None
                    if close_fault:
                        self.fail_after_release(transport, OSError("close acknowledgement failed"))
                        cleanup_reason = "OSError: close acknowledgement failed"

                    result = self.exchange(clock, transport)
                    self.assert_progress(result, ec.Status.LOCAL_ERROR, ec.Phase.INITIALIZE, ec.Delivery.NOT_SENT, 0, 0)
                    self.assertIsNone(result.detail.assessment)
                    self.assertEqual(result.reason, f"{error_type.__name__}: fixture initialization stopped")
                    self.assert_cleanup(result.cleanup, ec.Status.LOCAL_ERROR, cleanup_reason)
                    self.assertEqual(clock(), START_NS)
                    self.assertIsNone(transport.sent_frame)
                    self.assert_released(transport, operations, [call.open(DEADLINE_NS), call.close()])

    def test_unclassified_errors_keep_their_explicit_cause_and_notes_when_cleanup_is_interrupted(self):
        for stage, error_type in (("send", ValueError), ("receive", TypeError)):
            for close_fault in (False, True):
                with self.subTest(stage=stage, error=error_type.__name__, close_fault=close_fault):
                    clock, transport, operations = self.tracked_transport(self.rejection)
                    cause = OSError("underlying fixture failure")
                    primary = error_type("dependency contract failure")
                    primary.add_note("dependency detail")

                    def fail(*args):
                        raise primary from cause

                    getattr(transport, stage).side_effect = fail
                    notes = ["dependency detail"]
                    if close_fault:
                        self.fail_after_release(transport, KeyboardInterrupt("cleanup interrupted"))
                        notes.append("Cleanup failed: KeyboardInterrupt: cleanup interrupted")

                    with self.assertRaises(error_type) as raised:
                        self.exchange(clock, transport)
                    self.assertIs(raised.exception, primary)
                    self.assertIs(primary.__cause__, cause)
                    self.assertEqual(primary.__notes__, notes)
                    expected_calls = [call.open(DEADLINE_NS), call.send(FPRD_REQUEST, DEADLINE_NS)]
                    if stage == "receive":
                        expected_calls.append(call.receive(DEADLINE_NS))
                    self.assert_released(transport, operations, [*expected_calls, call.close()])

    def test_receive_failure_preserves_previous_evidence_through_cleanup(self):
        cases = (
            ("premature expiry", None, ec.Status.INDETERMINATE,
             "transport indicated expiry before the deadline", OSError),
            ("dependency timeout", TimeoutError, ec.Status.INDETERMINATE,
             "TimeoutError: fixture receive stopped", OSError),
            ("interruption", KeyboardInterrupt, ec.Status.INTERRUPTED,
             "exchange interrupted by user", KeyboardInterrupt),
        )
        for scenario, receive_error, status, reason, close_error in cases:
            for close_fault in (False, True):
                with self.subTest(scenario=scenario, close_fault=close_fault):
                    clock, transport, operations = self.tracked_transport(self.foreign, self.rejection)
                    response = None if receive_error is None else receive_error("fixture receive stopped")
                    transport.receive.side_effect = (DEFAULT, response)
                    cleanup_reason = None
                    if close_fault:
                        self.fail_after_release(transport, close_error("secondary close failure"))
                        cleanup_reason = f"{close_error.__name__}: secondary close failure"

                    result = self.exchange(clock, transport)
                    self.assert_progress(result, status, ec.Phase.RECEIVE, ec.Delivery.ACCEPTED, 1,
                                         OBSERVED_NS - START_NS)
                    self.assertEqual(result.reason, reason)
                    assessment = result.detail.assessment
                    self.assert_assessment(assessment, ec.Status.UNCORRELATED, ec.Attribution.FOREIGN, None, None)
                    self.assertEqual(assessment.reason, "event belongs to another interface")
                    self.assert_cleanup(result.cleanup, status, cleanup_reason)
                    self.assert_released(transport, operations, [
                        call.open(DEADLINE_NS), call.send(FPRD_REQUEST, DEADLINE_NS),
                        call.receive(DEADLINE_NS), call.receive(DEADLINE_NS), call.close(),
                    ])

    def test_close_interrupt_preserves_terminal_rejection_and_invalidates_success(self):
        matching = ec.FrameEvent(
            OBSERVED_NS, self.context.interface, self.context.exchange_id, ec.Direction.INBOUND, FPRD_RETURN,
        )
        cases = (
            (self.rejection, ec.Status.REJECTED, ec.Status.REJECTED, ec.Phase.CORRELATE,
             "explicit rejection from the synthetic fixture", None, None),
            (matching, ec.Status.OK, ec.Status.INTERRUPTED, ec.Phase.CLOSE,
             "transport cleanup failed after a matching return", True, 1),
        )
        for event, primary_status, status, phase, reason, structure, wkc in cases:
            with self.subTest(primary=primary_status.name):
                clock, transport, operations = self.tracked_transport(event, self.foreign)
                self.fail_after_release(transport, KeyboardInterrupt("cleanup interrupted"))

                result = self.exchange(clock, transport)
                self.assert_progress(result, status, phase, ec.Delivery.ACCEPTED, 1, OBSERVED_NS - START_NS)
                self.assertEqual(result.reason, reason)
                self.assert_assessment(result.detail.assessment, primary_status, ec.Attribution.MATCHED, structure, wkc)
                self.assert_cleanup(result.cleanup, primary_status, "KeyboardInterrupt: cleanup interrupted")
                self.assert_released(transport, operations, [
                    call.open(DEADLINE_NS), call.send(FPRD_REQUEST, DEADLINE_NS), call.receive(DEADLINE_NS), call.close(),
                ])
