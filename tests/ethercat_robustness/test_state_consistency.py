"""State and time invariants of the approved offline EtherCAT flows."""

from dataclasses import replace
from functools import partial
from itertools import permutations
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ethercat_unit"))
try:
    from support import OfflineCase, ec
    from vectors import CHAINED
finally:
    sys.path.pop(0)


MILLISECOND_NS = 1_000_000


class StateConsistencyTests(OfflineCase):
    def assert_exchange(self, result, *, profile, status, phase, elapsed_ns, events):
        self.assertIs(type(result), ec.OperationResult)
        self.assertIs(result.status, status)
        self.assertIs(result.phase, phase)
        self.assertIs(result.mode, ec.Mode.SIMULATE)
        self.assertIs(result.origin, ec.Origin.SYNTHETIC)
        self.assertIsNone(result.cleanup)
        self.assertIs(type(result.reason), str)
        self.assertTrue(result.reason)
        detail = result.detail
        self.assertIs(type(detail), ec.ExchangeEvidence)
        self.assertIs(detail.profile, profile)
        self.assertIs(detail.delivery, ec.Delivery.ACCEPTED)
        for value, expected in ((detail.elapsed_ns, elapsed_ns), (detail.events, events), (detail.expected_wkc, 1)):
            self.assertIs(type(value), int)
            self.assertEqual(value, expected)

    def assert_assessment(self, assessment, status, attribution, structure=None, wkc=None):
        if attribution is None:
            self.assertIsNone(assessment)
            return
        self.assertIs(type(assessment), ec.EventAssessment)
        self.assertIs(assessment.status, status)
        self.assertIs(assessment.attribution, attribution)
        self.assertIs(assessment.structurally_valid, structure)
        self.assertIsNone(assessment.esc_type)
        if wkc is None:
            self.assertIsNone(assessment.wkc)
        else:
            self.assertIs(type(assessment.wkc), int)
            self.assertEqual(assessment.wkc, wkc)

    def exchange_in_memory(self, profile, start_ns, context, events):
        clock = ec.VirtualClock(start_ns)
        transport = ec.MemoryTransport(clock, events)
        result = ec.run_exchange(profile, context, transport, clock, timeout=0.001)
        self.assertIs(transport.closed, True)
        self.assertEqual(clock(), start_ns + result.detail.elapsed_ns)
        return result

    def test_timeout_extension_preserves_typed_scenario_outcomes(self):
        # Status and assessment expectations come from the Gate 3 scenario table.
        cases = (
            (ec.Scenario.SUCCESS, ec.Status.OK, ec.Attribution.MATCHED, True, 1),
            (ec.Scenario.TIMEOUT, ec.Status.TIMEOUT, None, None, None),
            (ec.Scenario.UNCORRELATED, ec.Status.UNCORRELATED, ec.Attribution.FOREIGN, None, None),
            (ec.Scenario.WKC_MISMATCH, ec.Status.INDETERMINATE, ec.Attribution.MATCHED, True, 0),
            (ec.Scenario.INVALID, ec.Status.PROTOCOL_ERROR, ec.Attribution.MATCHED, False, None),
            (ec.Scenario.REJECTED, ec.Status.REJECTED, ec.Attribution.MATCHED, None, None),
        )
        for profile in (ec.ReadProfile.FPRD, ec.ReadProfile.APRD):
            for scenario, status, attribution, structure, wkc in cases:
                with self.subTest(profile=profile, scenario=scenario):
                    short = ec.simulate(scenario, timeout=0.001, profile=profile)
                    long = ec.simulate(scenario, timeout=10, profile=profile)
                    waits = scenario in (ec.Scenario.TIMEOUT, ec.Scenario.UNCORRELATED)
                    phase = ec.Phase.RECEIVE if waits else ec.Phase.CORRELATE
                    events = 0 if scenario is ec.Scenario.TIMEOUT else 1
                    for result, budget_ns in ((short, MILLISECOND_NS), (long, 10_000_000_000)):
                        self.assert_exchange(
                            result, profile=profile, status=status, phase=phase,
                            elapsed_ns=budget_ns if waits else 500_000, events=events,
                        )
                        self.assert_assessment(result.detail.assessment, status, attribution, structure, wkc)
                    normalized_long = replace(long, detail=replace(long.detail, elapsed_ns=short.detail.elapsed_ns))
                    self.assertEqual(normalized_long, short)

    def test_translated_clock_preserves_local_window_boundaries(self):
        # An explicit rejection is a local typed event with no binary payload.
        cases = (
            (-1, ec.Status.INDETERMINATE, ec.Phase.CORRELATE, ec.Attribution.INSUFFICIENT, 0),
            (0, ec.Status.REJECTED, ec.Phase.CORRELATE, ec.Attribution.MATCHED, 0),
            (MILLISECOND_NS - 1, ec.Status.REJECTED, ec.Phase.CORRELATE, ec.Attribution.MATCHED, MILLISECOND_NS - 1),
            (MILLISECOND_NS, ec.Status.TIMEOUT, ec.Phase.RECEIVE, None, MILLISECOND_NS),
            (MILLISECOND_NS + 1, ec.Status.TIMEOUT, ec.Phase.RECEIVE, None, MILLISECOND_NS),
        )
        for profile in (ec.ReadProfile.FPRD, ec.ReadProfile.APRD):
            context = ec.ExchangeContext("memory")
            for delta, status, phase, attribution, elapsed in cases:
                with self.subTest(profile=profile, delta=delta):
                    results = []
                    # The second origin is beyond exact consecutive binary64 integers.
                    for start in (1, (1 << 53) + 1):
                        rejection = ec.RejectionEvent(
                            start + delta, context.interface, context.exchange_id, ec.Direction.INBOUND, profile,
                        )
                        result = self.exchange_in_memory(profile, start, context, (rejection,))
                        self.assert_exchange(
                            result, profile=profile, status=status, phase=phase, elapsed_ns=elapsed,
                            events=0 if attribution is None else 1,
                        )
                        self.assert_assessment(result.detail.assessment, status, attribution)
                        results.append(result)
                    self.assertEqual(results[0], results[1])

    def test_event_budget_and_queued_suffix_preserve_terminal_evidence(self):
        profile = ec.ReadProfile.FPRD
        context = ec.ExchangeContext("memory")
        rejection = ec.RejectionEvent(3, context.interface, context.exchange_id, ec.Direction.INBOUND, profile)
        foreign = replace(rejection, timestamp_ns=1, profile=ec.ReadProfile.APRD)
        ignored = replace(rejection, timestamp_ns=2, direction=ec.Direction.OUTBOUND)
        cases = (
            ("waits at 63", (foreign,) + (ignored,) * 62, ec.Status.UNCORRELATED, ec.Phase.RECEIVE, MILLISECOND_NS),
            ("exhausts at 64", (foreign,) + (ignored,) * 63, ec.Status.INDETERMINATE, ec.Phase.RECEIVE, 2),
            ("terminates at 64", (foreign,) + (ignored,) * 62 + (rejection,), ec.Status.REJECTED, ec.Phase.CORRELATE, 3),
        )
        for label, events, status, phase, elapsed in cases:
            with self.subTest(case=label):
                result = self.exchange_in_memory(profile, 0, context, events)
                self.assert_exchange(
                    result, profile=profile, status=status, phase=phase, elapsed_ns=elapsed, events=len(events),
                )
                if status is ec.Status.REJECTED:
                    self.assert_assessment(result.detail.assessment, ec.Status.REJECTED, ec.Attribution.MATCHED)
                else:
                    self.assert_assessment(result.detail.assessment, ec.Status.UNCORRELATED, ec.Attribution.FOREIGN)

        with self.subTest(case="pending event after rejection"):
            prefix = (foreign,) + (ignored,) * 61 + (rejection,)
            suffix = replace(rejection, timestamp_ns=4, direction=ec.Direction.UNKNOWN)
            first = self.exchange_in_memory(profile, 0, context, prefix)
            extended = self.exchange_in_memory(profile, 0, context, prefix + (suffix,))
            for result in (first, extended):
                self.assert_exchange(
                    result, profile=profile, status=ec.Status.REJECTED,
                    phase=ec.Phase.CORRELATE, elapsed_ns=3, events=63,
                )
                self.assert_assessment(result.detail.assessment, ec.Status.REJECTED, ec.Attribution.MATCHED)
            self.assertEqual(extended, first)

    def test_independent_local_operations_can_run_in_any_order(self):
        # Mix inspection with successful, timed-out and explicitly rejected simulations.
        cases = {
            "inspection": (partial(ec.inspect_frame, CHAINED), ec.Status.OK, ec.EtherCATFrame),
            "success": (partial(ec.simulate, ec.Scenario.SUCCESS, 0.001, ec.ReadProfile.APRD),
                        ec.Status.OK, ec.ExchangeEvidence),
            "timeout": (partial(ec.simulate, ec.Scenario.TIMEOUT, 0.001), ec.Status.TIMEOUT, ec.ExchangeEvidence),
            "rejection": (partial(ec.simulate, ec.Scenario.REJECTED, 0.001), ec.Status.REJECTED, ec.ExchangeEvidence),
        }
        baseline = {name: invoke() for name, (invoke, _, _) in cases.items()}
        for order in permutations(cases):
            with self.subTest(order=order):
                for name in order:
                    invoke, status, detail_type = cases[name]
                    result = invoke()
                    self.assertIs(type(result), ec.OperationResult, name)
                    self.assertIs(result.status, status, name)
                    self.assertIs(type(result.detail), detail_type, name)
                    origin = ec.Origin.OFFLINE_INPUT if name == "inspection" else ec.Origin.SYNTHETIC
                    self.assertIs(result.origin, origin, name)
                    self.assertEqual(result, baseline[name], name)
