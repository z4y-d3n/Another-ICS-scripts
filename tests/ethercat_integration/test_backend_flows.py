"""Production packet adapter, common client and audit in one guarded exchange."""

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import errno
from io import StringIO
from unittest.mock import call

from integration_support import OfflineCase, ec, packet, vectors


DEADLINE_NS = 1_000_000


def pending_exchange(*packets, initial_ns=0):
    return packet.PacketHarness(
        packet.quiet(), packet.tx_read(packet.scheduled()),
        *(packet.rx_read(message) for message in packets), initial_ns=initial_ns,
    )


def outgoing_copy():
    address = packet.RX_ADDRESS[:2] + (4,) + packet.RX_ADDRESS[3:]
    return packet.received(vectors.NATIVE_REQUEST, address=address)


def foreign_return():
    data = vectors.replace_field(vectors.NATIVE_RETURN, 20, b"\x01\x00")
    return packet.received(data)


class BackendFlowTests(OfflineCase):
    def assert_exchange(self, result, status, phase, delivery, events, reason, *,
                        attribution=None, structure=None, wkc=None, esc_type=None, cleanup=None):
        self.assertIsInstance(result, ec.OperationResult)
        self.assertIs(result.status, status)
        self.assertIs(result.mode, ec.Mode.DIAGNOSE)
        self.assertIs(result.origin, ec.Origin.NATIVE_TEST)
        self.assertIs(result.phase, phase)
        self.assertIn(reason, result.reason)
        evidence = result.detail
        self.assertIsInstance(evidence, ec.ExchangeEvidence)
        self.assertIs(evidence.profile, ec.ReadProfile.APRD)
        self.assertIs(evidence.delivery, delivery)
        self.assertEqual(evidence.events, events)
        self.assertEqual(evidence.expected_wkc, 1)
        if attribution is None:
            self.assertIsNone(evidence.assessment)
        else:
            assessment = evidence.assessment
            self.assertEqual((assessment.attribution, assessment.structurally_valid,
                              assessment.wkc, assessment.esc_type), (attribution, structure, wkc, esc_type))

        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            ec._present(result, debug=True)
        output, log = stdout.getvalue(), stderr.getvalue()
        self.assertLessEqual(len((output + log).encode("utf-8")), 16 * 1024)
        self.assertEqual(output.splitlines()[0],
                         f"{status.name} ({status.value}) mode=diagnose source=native-backend-test phase={phase}")
        self.assertIn(f"APRD diagnostic delivery={delivery} events={events}\n", output)
        self.assertIn(f"WKC expected=1 observed={wkc if wkc is not None else 'unavailable'}\n", output)
        self.assertNotIn("source=native-linux", output)
        if attribution is None:
            self.assertNotIn("Return structure=", output)
        else:
            label = {None: "unverified", True: "valid", False: "invalid"}[structure]
            self.assertIn(f"Return structure={label} attribution={attribution}\n", output)
        if esc_type is None:
            self.assertNotIn("ESC Type observed=", output)
        else:
            self.assertIn(f"ESC Type observed=0x{esc_type:02x}\n", output)
        self.assertIn(f"{status.name} [diagnose]", log)
        self.assertIn(reason, log)
        self.assertIn(f"phase={phase} elapsed_ns={evidence.elapsed_ns} events={events}", log)
        if cleanup is None:
            self.assertIsNone(result.cleanup)
            self.assertNotIn("cleanup after ", log)
        else:
            primary, secondary = cleanup
            self.assertIs(result.cleanup.primary_status, primary)
            self.assertIn(secondary, result.cleanup.reason)
            self.assertIn(f"cleanup after {primary.name}:", log)
            self.assertIn(secondary, log)
            self.assertLess(log.index(f"{status.name} [diagnose]"), log.index("cleanup after "))

    def assert_lifecycle(self, harness, *, sent=True, acquired=True):
        harness.trace.factory.assert_called_once_with(17, 3, 0)
        if sent:
            harness.resource.send.assert_called_once_with(vectors.NATIVE_REQUEST)
        else:
            harness.resource.send.assert_not_called()
        harness.transport.close()  # Even a cleanup failure leaves the wrapper single-owner.
        if acquired:
            harness.resource.close.assert_called_once_with()
            self.assertEqual(harness.trace.mock_calls[-1], call.fd.close())
        else:
            harness.resource.close.assert_not_called()
        self.assertIsNone(harness.transport._resource)

    def test_nominal_exchange_uses_one_deadline_through_audit_and_close(self):
        start = 900_000
        h = pending_exchange(initial_ns=start)
        h.resource.bind.side_effect = lambda _: h.clock.advance_to(start + 250_000)

        def send(request):
            h.clock.advance_to(start + 625_000)
            return len(request)

        def receive():
            h.clock.advance_to(start + 875_000)
            return packet.received()

        h.resource.send.side_effect = send
        h.pending.append(packet.rx_read(receive))
        result = h.exchange()
        self.assert_exchange(result, ec.Status.OK, ec.Phase.CORRELATE, ec.Delivery.ACCEPTED, 1,
                             "matches the reference", attribution=ec.Attribution.MATCHED,
                             structure=True, wkc=1, esc_type=0x12)
        self.assertEqual(result.detail.elapsed_ns, 875_000)
        self.assertEqual(h.trace.mock_calls, packet.OPEN_CALLS + [
            call.fd.recvmsg(1514, 0), call.fd.settimeout(0.00075), call.fd.send(vectors.NATIVE_REQUEST),
            call.fd.settimeout(0.0), call.fd.recvmsg(0, 96, packet.ERRQUEUE),
            call.fd.settimeout(0.000375), call.fd.recvmsg(1514, 104), call.fd.close(),
        ])
        self.assert_lifecycle(h)
        self.assertTrue(h.closed)
        self.assertFalse(h.pending)

    def test_nonterminal_evidence_is_superseded_by_matching_return(self):
        for prefix in ((outgoing_copy(),), (foreign_return(), outgoing_copy(), foreign_return())):
            with self.subTest(prefix_count=len(prefix)):
                h = pending_exchange(*prefix, packet.received(), foreign_return())
                result = h.exchange()
                self.assert_exchange(result, ec.Status.OK, ec.Phase.CORRELATE, ec.Delivery.ACCEPTED,
                                     len(prefix) + 1, "matches the reference", attribution=ec.Attribution.MATCHED,
                                     structure=True, wkc=1, esc_type=0x12)
                self.assertEqual(list(h.pending), [packet.rx_read(foreign_return())])
                self.assert_lifecycle(h)

    def test_foreign_events_preserve_evidence_at_expiry_and_budget(self):
        for expired, status, events, reason in (
            (True, ec.Status.UNCORRELATED, 3, "Deadline reached"),
            (False, ec.Status.INDETERMINATE, 64, "event budget exhausted"),
        ):
            with self.subTest(expired=expired):
                h = pending_exchange(foreign_return(), outgoing_copy(), foreign_return())

                def deadline():
                    h.clock.advance_to(DEADLINE_NS)
                    raise TimeoutError("capture expired")

                if expired:
                    h.pending.append(packet.rx_read(deadline))
                else:
                    h.pending.extend(packet.rx_read(outgoing_copy()) for _ in range(61))
                trailing = packet.rx_read(packet.received())
                h.pending.append(trailing)
                result = h.exchange()
                self.assert_exchange(result, status, ec.Phase.RECEIVE, ec.Delivery.ACCEPTED, events, reason,
                                     attribution=ec.Attribution.FOREIGN)
                self.assertIn("identity fields differ", result.detail.assessment.reason)
                self.assertEqual(result.detail.elapsed_ns, DEADLINE_NS if expired else 0)
                self.assertEqual(h.resource.recvmsg.call_count, 6 if expired else 66)
                self.assertEqual(list(h.pending), [trailing])
                self.assert_lifecycle(h)

    def test_terminal_evidence_keeps_precedence_and_stops_consumption(self):
        match = ec.Attribution.MATCHED
        insufficient = ec.Attribution.INSUFFICIENT
        for message, status, reason, attribution, structure, wkc, esc_type in (
            (packet.received(vectors.NATIVE_RETURN[:18]), ec.Status.INDETERMINATE,
             "capture lacks complete", insufficient, None, None, None),
            (packet.received(vectors.NATIVE_RETURN[:-1]), ec.Status.PROTOCOL_ERROR,
             "truncated datagram chain", match, False, None, None),
            (packet.received(control=[packet.timestamp(nsec=251), packet.auxdata(30, snaplen=30)]),
             ec.Status.INDETERMINATE, "incomplete direction or exchange context", insufficient, None, None, None),
            (packet.received(vectors.replace_field(vectors.NATIVE_RETURN, 26, b"\x13\x00\x00")),
             ec.Status.INDETERMINATE, "Working Counter differs", match, True, 0, 0x13),
        ):
            with self.subTest(reason=reason):
                h = pending_exchange(outgoing_copy(), foreign_return(), message, packet.received())
                result = h.exchange()
                self.assert_exchange(result, status, ec.Phase.CORRELATE, ec.Delivery.ACCEPTED, 3, reason,
                                     attribution=attribution, structure=structure, wkc=wkc, esc_type=esc_type)
                self.assertEqual(list(h.pending), [packet.rx_read(packet.received())])
                self.assert_lifecycle(h)

    def test_local_window_and_kernel_order_are_independent(self):
        for offset, rx_time, succeeds, reason in (
            (-1, 251, True, "matches the reference"),
            (0, 251, False, "outside the exchange window"),
            (1, 251, False, "outside the exchange window"),
            (-1, None, False, "kernel timestamps do not establish receive order"),
            (-1, 249, False, "kernel timestamps do not establish receive order"),
        ):
            with self.subTest(offset=offset, rx_time=rx_time):
                h = pending_exchange(foreign_return())
                control = [packet.auxdata(len(vectors.NATIVE_RETURN))]
                if rx_time is not None:
                    control.append(packet.timestamp(nsec=rx_time))

                def timed_return():
                    h.clock.advance_to(DEADLINE_NS + offset)
                    return packet.received(control=control)

                h.pending.append(packet.rx_read(timed_return))
                result = h.exchange()
                status = ec.Status.OK if succeeds else ec.Status.INDETERMINATE
                attribution = ec.Attribution.MATCHED if succeeds else ec.Attribution.INSUFFICIENT
                self.assert_exchange(result, status, ec.Phase.CORRELATE, ec.Delivery.ACCEPTED, 2, reason,
                                     attribution=attribution, structure=True if succeeds else None,
                                     wkc=1 if succeeds else None, esc_type=0x12 if succeeds else None)
                self.assertEqual(result.detail.elapsed_ns, DEADLINE_NS + offset)
                self.assert_lifecycle(h)

    def test_configuration_and_preparation_fail_before_acquisition(self):
        h = packet.PacketHarness()
        for overrides, message in (
            ({"clock": ec.VirtualClock()}, "share the reference context and clock"),
            ({"context": replace(h.context, expected_esc_type=0x13)}, "share the reference context and clock"),
            ({"profile": ec.ReadProfile.FPRD}, "requires the APRD profile"),
            ({"timeout": 0}, "timeout must be finite"),
        ):
            with self.subTest(overrides=tuple(overrides)):
                with self.assertRaisesRegex(ec.UsageError, message):
                    h.exchange(**overrides)
                self.assertEqual(h.trace.mock_calls, [])
                h.system.CMSG_SPACE.assert_not_called()

    def test_expiry_stops_acquisition_preflight_and_reception_at_the_same_deadline(self):
        for stage, phase, sent in (
            ("factory", ec.Phase.INITIALIZE, False),
            ("preflight", ec.Phase.SEND, False),
            ("receive", ec.Phase.RECEIVE, True),
        ):
            with self.subTest(stage=stage):
                h = pending_exchange()

                def expire(result=None):
                    h.clock.advance_to(DEADLINE_NS)
                    return result

                def quiet_but_expired():
                    expire()
                    raise BlockingIOError(errno.EAGAIN, "no queued data")

                def receive_expired():
                    expire()
                    raise TimeoutError("reader expired")

                if stage == "factory":
                    h.trace.factory.side_effect = lambda *_: expire(h.resource)
                elif stage == "preflight":
                    h.pending[0] = ((1514, 0), quiet_but_expired)
                else:
                    h.pending.append(packet.rx_read(receive_expired))
                result = h.exchange()
                delivery = ec.Delivery.ACCEPTED if sent else ec.Delivery.NOT_SENT
                self.assert_exchange(result, ec.Status.TIMEOUT, phase, delivery, 0, "deadline")
                self.assertEqual(result.detail.elapsed_ns, DEADLINE_NS)
                self.assertEqual(h.resource.recvmsg.call_count, {"factory": 0, "preflight": 1, "receive": 3}[stage])
                self.assert_lifecycle(h, sent=sent)

    def test_acquisition_failure_and_ambiguous_delivery_do_not_retry(self):
        for stage in ("acquire", "send"):
            with self.subTest(stage=stage):
                h = pending_exchange(packet.received())
                if stage == "acquire":
                    h.trace.factory.side_effect = PermissionError(errno.EACCES, "fixture denied")
                    status, phase, delivery = ec.Status.LOCAL_ERROR, ec.Phase.INITIALIZE, ec.Delivery.NOT_SENT
                    reason, reads = "fixture denied", 0
                else:
                    h.resource.send.side_effect = lambda request: len(request) - 1
                    status, phase, delivery = ec.Status.INDETERMINATE, ec.Phase.SEND, ec.Delivery.UNCERTAIN
                    reason, reads = "accepting the complete frame", 1
                self.assert_exchange(h.exchange(), status, phase, delivery, 0, reason)
                self.assertEqual(h.resource.recvmsg.call_count, reads)
                self.assert_lifecycle(h, sent=stage == "send", acquired=stage == "send")

    def test_cleanup_error_preserves_primary_evidence_and_promotes_prior_success(self):
        for stage, status, phase, delivery, events, primary, reason in (
            ("init", ec.Status.LOCAL_ERROR, ec.Phase.INITIALIZE, ec.Delivery.NOT_SENT, 0,
             ec.Status.LOCAL_ERROR, "bind denied"),
            ("timeout", ec.Status.TIMEOUT, ec.Phase.RECEIVE, ec.Delivery.ACCEPTED, 0,
             ec.Status.TIMEOUT, "deadline reached"),
            ("receive", ec.Status.INDETERMINATE, ec.Phase.RECEIVE, ec.Delivery.ACCEPTED, 1,
             ec.Status.INDETERMINATE, "receive failed"),
            ("normalize", ec.Status.INDETERMINATE, ec.Phase.RECEIVE, ec.Delivery.ACCEPTED, 0,
             ec.Status.INDETERMINATE, "invalid packet result"),
            ("interrupt", ec.Status.INTERRUPTED, ec.Phase.SEND, ec.Delivery.UNCERTAIN, 0,
             ec.Status.INTERRUPTED, "interrupted by user"),
            ("success", ec.Status.LOCAL_ERROR, ec.Phase.CLOSE, ec.Delivery.ACCEPTED, 1,
             ec.Status.OK, "cleanup failed after a matching return"),
        ):
            with self.subTest(stage=stage):
                h = pending_exchange()
                h.resource.close.side_effect = OSError(errno.EIO, "secondary cleanup")
                if stage == "init":
                    h.resource.bind.side_effect = PermissionError(errno.EPERM, "bind denied")
                elif stage == "interrupt":
                    h.resource.send.side_effect = KeyboardInterrupt()
                    h.resource.close.side_effect = KeyboardInterrupt("secondary cleanup")
                elif stage == "timeout":
                    def expire():
                        h.clock.advance_to(DEADLINE_NS)
                        raise TimeoutError("reader expired")

                    h.pending.append(packet.rx_read(expire))
                elif stage == "receive":
                    h.pending.extend((packet.rx_read(foreign_return()),
                                      packet.rx_read(OSError(errno.EIO, "receive failed"))))
                elif stage == "normalize":
                    h.pending.append(packet.rx_read((b"",)))
                else:
                    h.pending.append(packet.rx_read(packet.received()))
                result = h.exchange()
                evidence = {
                    "receive": dict(attribution=ec.Attribution.FOREIGN),
                    "success": dict(attribution=ec.Attribution.MATCHED, structure=True, wkc=1, esc_type=0x12),
                }.get(stage, {})
                self.assert_exchange(result, status, phase, delivery, events, reason,
                                     cleanup=(primary, "secondary cleanup"), **evidence)
                self.assert_lifecycle(h, sent=stage != "init")
