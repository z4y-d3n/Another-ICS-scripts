from dataclasses import replace
import errno
from unittest.mock import Mock, call, patch

from linux_fakes import (
    BOUND_ADDRESS, ERRQUEUE, IFACE, MSG_CTRUNC, MSG_TRUNC, OPEN_CALLS, RX_ADDRESS, TX_DEFAULT_NS,
    PacketHarness, auxdata, linux_symbols, quiet, received, rx_read, scheduled, timestamp, tx_read,
)
from support import OfflineCase, ec
from vectors import APRD_REQUEST, FPRD_REQUEST, NATIVE_REQUEST, NATIVE_RETURN, replace_field


class LinuxBackendTests(OfflineCase):
    def assert_result(self, result, status, phase, delivery, events, reason):
        self.assertIs(result.status, status)
        self.assertIs(result.phase, phase)
        self.assertIs(result.mode, ec.Mode.DIAGNOSE)
        self.assertIs(result.origin, ec.Origin.NATIVE_TEST)
        self.assertIs(result.detail.delivery, delivery)
        self.assertEqual(result.detail.events, events)
        self.assertIn(reason, result.reason)

    def test_production_backend_opens_sends_and_receives_exactly_one_fixed_request(self):
        h = PacketHarness(quiet(), tx_read(scheduled()), rx_read(received()))
        result = h.exchange()
        self.assert_result(result, ec.Status.OK, ec.Phase.CORRELATE, ec.Delivery.ACCEPTED, 1, "reference read")
        self.assertEqual((result.detail.expected_wkc, result.detail.assessment.wkc, result.detail.assessment.esc_type),
                         (1, 1, 0x12))
        self.assertIs(result.detail.assessment.attribution, ec.Attribution.MATCHED)
        self.assertEqual(h.trace.mock_calls, OPEN_CALLS + [
            call.fd.recvmsg(1514, 0), call.fd.settimeout(0.001), call.fd.send(NATIVE_REQUEST),
            call.fd.settimeout(0.0), call.fd.recvmsg(0, 96, ERRQUEUE),
            call.fd.settimeout(0.001), call.fd.recvmsg(1514, 104), call.fd.close(),
        ])
        self.assertFalse(h.pending)
        self.assertTrue(h.closed)
        self.assertIsNone(h.transport._resource)
        self.assertIsNone(result.cleanup)

    def test_reference_profile_clock_and_origin_are_checked_before_factory(self):
        for override in (
            {"context": ec.ExchangeContext(IFACE)}, {"profile": ec.ReadProfile.FPRD},
            {"context": ec._NativeDiagnosticContext("other", 0x12, ec.Padding.STRIPPED)},
            {"context": ec._NativeDiagnosticContext(IFACE, 0x13, ec.Padding.STRIPPED)},
            {"context": ec._NativeDiagnosticContext(IFACE, 0x12, ec.Padding.RETAINED)},
            {"clock": ec.VirtualClock(20_000_000_000)},
        ):
            with self.subTest(override=list(override)):
                h = PacketHarness()
                with self.assertRaisesRegex(ec.UsageError, "APRD profile|share the reference context and clock"):
                    h.exchange(**override)
                self.assertEqual(h.trace.mock_calls, [])
                self.assertFalse(h.closed)
        system = linux_symbols(Mock())
        context = ec._NativeDiagnosticContext(IFACE, 0x12, ec.Padding.STRIPPED)
        with patch.object(ec, "socket", system):
            self.assertIs(ec._LinuxPacketTransport(context, platform="linux").origin, ec.Origin.NATIVE_TEST)
        self.assertIs(ec._LinuxPacketTransport(context).origin, ec.Origin.NATIVE_LINUX)
        system.socket.assert_not_called()

    def test_platform_or_incomplete_api_returns_unsupported_without_acquisition(self):
        for platform, remove in (("win32", None), ("darwin", None), ("other", None), ("linux", "CMSG_SPACE")):
            with self.subTest(platform=platform, remove=remove):
                h = PacketHarness()
                if remove:
                    delattr(h.system, remove)
                h.transport = ec._LinuxPacketTransport(h.context, h.clock, system=h.system, platform=platform)
                result = h.exchange()
                self.assert_result(result, ec.Status.UNSUPPORTED, ec.Phase.INITIALIZE, ec.Delivery.NOT_SENT, 0,
                                   "API is unavailable")
                self.assertEqual(h.trace.mock_calls, [])

    def test_factory_failure_has_no_resource_to_close(self):
        for code, status, reason in ((errno.EPERM, ec.Status.LOCAL_ERROR, "factory fault"),
                                     (errno.EAFNOSUPPORT, ec.Status.UNSUPPORTED, "factory fault"),
                                     (errno.ENOSYS, ec.Status.UNSUPPORTED, "factory fault"),
                                     (None, ec.Status.INTERRUPTED, "interrupted")):
            with self.subTest(code=code):
                h = PacketHarness()
                h.trace.factory.side_effect = KeyboardInterrupt() if code is None else OSError(code, "factory fault")
                result = h.exchange()
                self.assert_result(result, status, ec.Phase.INITIALIZE, ec.Delivery.NOT_SENT, 0, reason)
                self.assertEqual(h.trace.mock_calls, OPEN_CALLS[:1])
                self.assertIsNone(h.transport._resource)

    def test_partial_initialization_closes_owned_resource_and_does_not_send(self):
        for method, index, error, status, reason in (
            ("settimeout", 1, OSError(errno.EIO, "nonblocking fault"), ec.Status.LOCAL_ERROR, "nonblocking fault"),
            ("setsockopt", 2, OSError(errno.ENOPROTOOPT, "aux unavailable"), ec.Status.UNSUPPORTED, "aux unavailable"),
            ("setsockopt", 3, OSError(errno.EPERM, "timestamp fault"), ec.Status.LOCAL_ERROR, "timestamp fault"),
            ("bind", 4, OSError(errno.ENODEV, "bind fault"), ec.Status.LOCAL_ERROR, "bind fault"),
            ("bind", 4, KeyboardInterrupt(), ec.Status.INTERRUPTED, "interrupted"),
            ("getsockname", 5, OSError(errno.EIO, "name fault"), ec.Status.LOCAL_ERROR, "name fault"),
        ):
            with self.subTest(method=method, index=index, error=error):
                h = PacketHarness()
                getattr(h.resource, method).side_effect = error if index != 3 else [None, error]
                result = h.exchange()
                self.assert_result(result, status, ec.Phase.INITIALIZE, ec.Delivery.NOT_SENT, 0, reason)
                self.assertEqual(h.trace.mock_calls, OPEN_CALLS[:index + 1] + [call.fd.close()])
                self.assertTrue(h.closed)
                self.assertIsNone(h.transport._resource)
        h = PacketHarness()
        h.resource.recvmsg = None
        result = h.exchange()
        self.assert_result(result, ec.Status.UNSUPPORTED, ec.Phase.INITIALIZE, ec.Delivery.NOT_SENT, 0, "recvmsg")
        self.assertEqual(h.trace.mock_calls, OPEN_CALLS[:1] + [call.fd.close()])

    def test_invalid_bound_link_metadata_prevents_send(self):
        for address, status, reason in (
            (list(BOUND_ADDRESS), ec.Status.LOCAL_ERROR, "identity differs"),
            (BOUND_ADDRESS[:-1], ec.Status.LOCAL_ERROR, "identity differs"),
            (("other", *BOUND_ADDRESS[1:]), ec.Status.LOCAL_ERROR, "identity differs"),
            ((IFACE, 0, *BOUND_ADDRESS[2:]), ec.Status.LOCAL_ERROR, "identity differs"),
            ((*BOUND_ADDRESS[:3], 772, BOUND_ADDRESS[4]), ec.Status.UNSUPPORTED, "Ethernet link type"),
        ) + tuple(((*BOUND_ADDRESS[:4], mac), ec.Status.LOCAL_ERROR, "valid local Ethernet MAC")
                  for mac in (None, bytes(5), bytes(6), b"\x01\x12\x34\x56\x78\x9a", bytearray(6))):
            with self.subTest(address=address):
                h = PacketHarness()
                h.resource.getsockname.return_value = address
                result = h.exchange()
                self.assert_result(result, status, ec.Phase.INITIALIZE, ec.Delivery.NOT_SENT, 0, reason)
                self.assertEqual(h.trace.mock_calls, OPEN_CALLS + [call.fd.close()])
                self.assertTrue(h.closed)

    def test_preflight_refuses_queued_data_and_faults_before_send(self):
        for result, status, reason in (
            (received(), ec.Status.LOCAL_ERROR, "queued before the request"),
            (BlockingIOError(errno.EIO, "preflight not would-block"), ec.Status.LOCAL_ERROR, "preflight"),
            (PermissionError(errno.EPERM, "preflight permission"), ec.Status.LOCAL_ERROR, "permission"),
            (KeyboardInterrupt(), ec.Status.INTERRUPTED, "interrupted"),
        ):
            with self.subTest(result=type(result).__name__):
                h = PacketHarness(((1514, 0), result))
                answer = h.exchange()
                self.assert_result(answer, status, ec.Phase.SEND, ec.Delivery.NOT_SENT, 0, reason)
                self.assertEqual(h.trace.mock_calls, OPEN_CALLS + [call.fd.recvmsg(1514, 0), call.fd.close()])
                self.assertTrue(h.closed)

    def test_send_attempt_maps_count_errno_and_interruption_without_retry(self):
        cases = (
            (0, ec.Status.INDETERMINATE, ec.Delivery.UNCERTAIN, "complete frame"),
            (59, ec.Status.INDETERMINATE, ec.Delivery.UNCERTAIN, "complete frame"),
            (61, ec.Status.INDETERMINATE, ec.Delivery.UNCERTAIN, "complete frame"),
            (True, ec.Status.INDETERMINATE, ec.Delivery.UNCERTAIN, "complete frame"),
            (OSError(errno.EAGAIN, "would block"), ec.Status.LOCAL_ERROR, ec.Delivery.NOT_SENT, "would block"),
            (OSError(errno.EMSGSIZE, "message too big"), ec.Status.LOCAL_ERROR, ec.Delivery.NOT_SENT, "message too big"),
            (TimeoutError("wait timed out"), ec.Status.INDETERMINATE, ec.Delivery.UNCERTAIN, "wait timed out"),
            (OSError(errno.EIO, "send failed"), ec.Status.INDETERMINATE, ec.Delivery.UNCERTAIN, "send failed"),
            (KeyboardInterrupt(), ec.Status.INTERRUPTED, ec.Delivery.UNCERTAIN, "interrupted"),
        )
        for report, status, delivery, reason in cases:
            with self.subTest(report=report):
                h = PacketHarness(quiet())
                h.resource.send.side_effect = [report]
                result = h.exchange()
                self.assert_result(result, status, ec.Phase.SEND, delivery, 0, reason)
                self.assertEqual(h.trace.mock_calls, OPEN_CALLS + [
                    call.fd.recvmsg(1514, 0), call.fd.settimeout(0.001), call.fd.send(NATIVE_REQUEST), call.fd.close(),
                ])
                self.assertTrue(h.closed)

    def test_single_use_state_rejects_wrong_frames_reentrancy_and_use_after_close(self):
        h = PacketHarness(quiet())
        with self.assertRaisesRegex(ec.TransportError, "cannot accept"):
            h.transport.send(APRD_REQUEST, 1_000_000)
        with self.assertRaisesRegex(ec.TransportError, "no pending request"):
            h.transport.receive(1_000_000)
        self.assertEqual(h.trace.mock_calls, [])
        h.transport.open(1_000_000)
        for frame in (FPRD_REQUEST, bytearray(APRD_REQUEST), b"", APRD_REQUEST + b"\0"):
            with self.subTest(frame=type(frame)):
                with self.assertRaisesRegex(ec.TransportError, "only the fixed ESC Type APRD"):
                    h.transport.send(frame, 1_000_000)
        self.assertEqual(h.trace.mock_calls, OPEN_CALLS)
        h.transport.send(APRD_REQUEST, 1_000_000)
        with self.assertRaisesRegex(ec.TransportError, "another request"):
            h.transport.send(APRD_REQUEST, 1_000_000)

        def reentrant_close():
            self.assertIs(h.transport._resource, h.resource)
            h.transport.close()
            h.closed = True

        h.resource.close.side_effect = reentrant_close
        h.transport.close()
        h.transport.close()
        h.resource.send.assert_called_once_with(NATIVE_REQUEST)
        h.resource.close.assert_called_once_with()
        self.assertTrue(h.closed)
        self.assertIsNone(h.transport._resource)
        with self.assertRaisesRegex(ec.TransportError, "single-use"):
            h.transport.open(1_000_000)
        with self.assertRaisesRegex(ec.TransportError, "no pending"):
            h.transport.receive(1_000_000)
        with self.assertRaisesRegex(ec.TransportError, "cannot accept"):
            h.transport.send(APRD_REQUEST, 1_000_000)

    def test_receive_faults_keep_known_delivery_and_close_once(self):
        for fault, status, reason in (
            (OSError(errno.EIO, "rx failed"), ec.Status.INDETERMINATE, "rx failed"),
            (TimeoutError(errno.ETIMEDOUT, "kernel timed out"), ec.Status.INDETERMINATE, "kernel timed out"),
            (TimeoutError("python wait timed out"), ec.Status.INDETERMINATE, "before the deadline"),
            (KeyboardInterrupt(), ec.Status.INTERRUPTED, "interrupted"),
            ((NATIVE_RETURN, [], 0), ec.Status.INDETERMINATE, "invalid packet result"),
        ):
            with self.subTest(fault=fault):
                h = PacketHarness(quiet(), tx_read(scheduled()), rx_read(fault))
                result = h.exchange()
                self.assert_result(result, status, ec.Phase.RECEIVE, ec.Delivery.ACCEPTED, 0, reason)
                h.resource.recvmsg.assert_has_calls([call(1514, 0), call(0, 96, ERRQUEUE), call(1514, 104)])
                h.resource.send.assert_called_once_with(NATIVE_REQUEST)
                h.resource.close.assert_called_once_with()
                self.assertFalse(h.pending)

    def test_tx_schedule_queue_is_polled_only_once_and_never_synthesizes_evidence(self):
        h = PacketHarness(quiet(), tx_read(BlockingIOError(errno.EAGAIN, "not yet queued")),
                          rx_read(received(address=RX_ADDRESS[:2] + (4,) + RX_ADDRESS[3:])), rx_read(received()))
        result = h.exchange()
        self.assert_result(result, ec.Status.INDETERMINATE, ec.Phase.CORRELATE, ec.Delivery.ACCEPTED, 2,
                           "kernel timestamps")
        self.assertEqual(h.resource.recvmsg.call_args_list,
                         [call(1514, 0), call(0, 96, ERRQUEUE), call(1514, 104), call(1514, 104)])
        h.resource.send.assert_called_once_with(NATIVE_REQUEST)
        h.resource.close.assert_called_once_with()
        h = PacketHarness(quiet(), tx_read(BlockingIOError(errno.EIO, "unexpected error queue fault")))
        result = h.exchange()
        self.assert_result(result, ec.Status.INDETERMINATE, ec.Phase.RECEIVE, ec.Delivery.ACCEPTED, 0,
                           "error queue fault")
        self.assertEqual(h.resource.recvmsg.call_args_list, [call(1514, 0), call(0, 96, ERRQUEUE)])

    def test_one_deadline_applies_before_and_during_acquisition_send_and_receive(self):
        h = PacketHarness()
        with self.assertRaisesRegex(ec.DeadlineExpired, "deadline"):
            h.transport.open(0)
        h.transport.close()
        self.assertEqual(h.trace.mock_calls, [])

        for stage in ("plan", "factory", "bind", "preflight", "arm", "submitted", "tx-arm", "errqueue"):
            with self.subTest(stage=stage):
                h = PacketHarness(quiet())

                def expire(result=None):
                    h.clock.advance_to(1_000_000)
                    return result

                if stage == "plan":
                    h.system.CMSG_SPACE.side_effect = lambda size: expire(size + 16)
                elif stage == "factory":
                    h.trace.factory.side_effect = lambda *address: expire(h.resource)
                elif stage == "bind":
                    h.resource.bind.side_effect = lambda address: expire()
                elif stage == "preflight":
                    def blocked_at_edge():
                        expire()
                        raise BlockingIOError(errno.EAGAIN, "quiet at edge")

                    h.pending[0] = ((1514, 0), blocked_at_edge)
                elif stage == "arm":
                    h.resource.settimeout.side_effect = lambda timeout: expire() if timeout > 0 else None
                elif stage == "submitted":
                    h.resource.send.side_effect = lambda request: expire(len(request))
                elif stage == "tx-arm":
                    h.resource.settimeout.side_effect = lambda timeout: expire() if h.resource.settimeout.call_count == 3 else None
                else:
                    h.pending.append(tx_read(lambda: expire(scheduled())))

                result = h.exchange()
                phase = ec.Phase.INITIALIZE if stage in ("plan", "factory", "bind") else (
                    ec.Phase.SEND if stage in ("preflight", "arm") else ec.Phase.RECEIVE)
                accepted = phase is ec.Phase.RECEIVE
                status = ec.Status.TIMEOUT
                self.assert_result(result, status, phase,
                                   ec.Delivery.ACCEPTED if accepted else ec.Delivery.NOT_SENT, 0, "deadline")
                self.assertEqual(result.detail.elapsed_ns, 1_000_000)
                self.assertEqual(h.resource.send.call_count, int(accepted))
                self.assertEqual(h.resource.close.call_count, int(stage != "plan"))
                self.assertIsNone(h.transport._resource)
                if stage == "bind":
                    h.resource.getsockname.assert_not_called()
                if stage == "errqueue":
                    self.assertEqual(h.resource.recvmsg.call_args_list, [call(1514, 0), call(0, 96, ERRQUEUE)])
                if stage == "tx-arm":
                    self.assertEqual(h.resource.recvmsg.call_args_list, [call(1514, 0)])

    def test_remaining_timeout_accounts_for_time_already_spent(self):
        h = PacketHarness(quiet(), tx_read(scheduled()), rx_read(received()))
        h.resource.bind.side_effect = lambda address: h.clock.advance_to(250_000)

        def send(request):
            h.clock.advance_to(625_000)
            return len(request)

        h.resource.send.side_effect = send
        result = h.exchange()
        self.assert_result(result, ec.Status.OK, ec.Phase.CORRELATE, ec.Delivery.ACCEPTED, 1, "reference read")
        self.assertEqual(h.resource.settimeout.call_args_list, [call(0.0), call(0.00075), call(0.0), call(0.000375)])
        self.assertEqual(result.detail.elapsed_ns, 625_000)

    def test_output_padding_policy_comes_from_the_native_reference(self):
        context = ec._NativeDiagnosticContext(IFACE, 0x12, ec.Padding.RETAINED)
        for padding, status, reason in ((b"", ec.Status.PROTOCOL_ERROR, "expected 60"),
                                        (bytes(range(31)), ec.Status.OK, "reference read")):
            with self.subTest(padding_len=len(padding)):
                h = PacketHarness(quiet(), tx_read(scheduled()), rx_read(received(NATIVE_RETURN + padding)),
                                  context=context)
                result = h.exchange(context=replace(context))
                self.assert_result(result, status, ec.Phase.CORRELATE, ec.Delivery.ACCEPTED, 1, reason)
                h.resource.send.assert_called_once_with(NATIVE_REQUEST)
                h.resource.close.assert_called_once_with()

    def test_native_received_evidence_changes_classification_without_changing_delivery(self):
        fresh = timestamp(nsec=TX_DEFAULT_NS + 1)
        for flags, control, ns, status, reason in (
            (MSG_TRUNC, None, None, ec.Status.PROTOCOL_ERROR, "reported truncation"),
            (MSG_CTRUNC, None, None, ec.Status.INDETERMINATE, "incomplete direction"),
            (0, [], None, ec.Status.INDETERMINATE, "incomplete direction"),
            (0, [fresh, auxdata(29, status=0x51, tpid=0x8100)], None,
             ec.Status.UNCORRELATED, "outside the link profile"),
            (0, [fresh, auxdata(29, status=0x41, tpid=0x8100)], None,
             ec.Status.INDETERMINATE, "incomplete direction"),
            (0, None, TX_DEFAULT_NS - 1, ec.Status.INDETERMINATE, "kernel timestamps"),
            (0, None, TX_DEFAULT_NS, ec.Status.INDETERMINATE, "kernel timestamps"),
            (0, [timestamp()], None, ec.Status.INDETERMINATE, "incomplete direction"),
        ):
            with self.subTest(flags=flags, control=control, ns=ns):
                if ns is not None:
                    control = [timestamp(nsec=ns), auxdata(29)]
                message = received(control=control, flags=flags)
                h = PacketHarness(quiet(), tx_read(scheduled()))
                h.pending.append(rx_read(message))
                if status is ec.Status.UNCORRELATED:
                    def reach_deadline():
                        h.clock.advance_to(1_000_000)
                        raise TimeoutError("input poll expired")

                    h.pending.append(rx_read(reach_deadline))
                result = h.exchange()
                phase = ec.Phase.RECEIVE if status is ec.Status.UNCORRELATED else ec.Phase.CORRELATE
                self.assert_result(result, status, phase, ec.Delivery.ACCEPTED, 1, reason)
                self.assertIsNone(result.detail.assessment.wkc)
                h.resource.close.assert_called_once_with()

    def test_release_failure_retains_primary_status_delivery_and_cause(self):
        for phase, primary, status, reason in (
            (ec.Phase.INITIALIZE, OSError(errno.EPERM, "binding denied"), ec.Status.LOCAL_ERROR, "binding denied"),
            (ec.Phase.RECEIVE, OSError(errno.EIO, "receive lost"), ec.Status.INDETERMINATE, "receive lost"),
            (ec.Phase.CLOSE, None, ec.Status.LOCAL_ERROR, "cleanup failed after a matching return"),
        ):
            with self.subTest(phase=phase):
                h = PacketHarness(quiet(), tx_read(scheduled()), rx_read(
                    primary if phase is ec.Phase.RECEIVE else received()))
                if phase is ec.Phase.INITIALIZE:
                    h.resource.bind.side_effect = primary
                h.resource.close.side_effect = OSError(errno.EIO, "secondary close")
                result = h.exchange()
                delivery = ec.Delivery.NOT_SENT if phase is ec.Phase.INITIALIZE else ec.Delivery.ACCEPTED
                self.assert_result(result, status, phase, delivery, int(phase is ec.Phase.CLOSE), reason)
                self.assertIs(result.cleanup.primary_status, ec.Status.OK if primary is None else status)
                self.assertIn("secondary close", result.cleanup.reason)
                self.assertIsNone(h.transport._resource)
                h.transport.close()
                h.resource.close.assert_called_once_with()

    def test_second_interrupt_preserves_primary_and_allows_at_most_one_close_invocation(self):
        for before_call in (True, False):
            with self.subTest(before_call=before_call):
                h = PacketHarness()
                h.resource.bind.side_effect = KeyboardInterrupt("primary")
                close_lookup = Mock()
                if before_call:
                    class InterruptedLookup:
                        def __getattr__(self, name):
                            if name == "close":
                                close_lookup()
                                raise KeyboardInterrupt("secondary before close")
                            return getattr(h.resource, name)

                    h.trace.factory.return_value = InterruptedLookup()
                else:
                    h.resource.close.side_effect = KeyboardInterrupt("secondary inside close")
                result = h.exchange()
                self.assert_result(result, ec.Status.INTERRUPTED, ec.Phase.INITIALIZE,
                                   ec.Delivery.NOT_SENT, 0, "interrupted by user")
                self.assertIs(result.cleanup.primary_status, ec.Status.INTERRUPTED)
                appended = "before" if before_call else "inside"
                self.assertEqual(result.cleanup.reason, f"KeyboardInterrupt: secondary {appended} close")
                self.assertIsNone(h.transport._resource)
                h.transport.close()
                self.assertEqual(close_lookup.call_count, int(before_call))
                self.assertEqual(h.resource.close.call_count, int(not before_call))
                h.resource.send.assert_not_called()

    def test_native_echo_is_ignored_until_fresh_return_or_expiry(self):
        outgoing = received(address=RX_ADDRESS[:2] + (4,) + RX_ADDRESS[3:])
        for include_return in (False, True):
            with self.subTest(include_return=include_return):
                h = PacketHarness(quiet(), tx_read(scheduled()), rx_read(outgoing))

                def expire():
                    h.clock.advance_to(1_000_000)
                    raise TimeoutError("capture wait elapsed")

                h.pending.append(rx_read(received() if include_return else expire))
                result = h.exchange()
                if include_return:
                    self.assert_result(result, ec.Status.OK, ec.Phase.CORRELATE, ec.Delivery.ACCEPTED, 2, "reference")
                else:
                    self.assert_result(result, ec.Status.TIMEOUT, ec.Phase.RECEIVE, ec.Delivery.ACCEPTED, 1, "deadline")
                    self.assertIsNone(result.detail.assessment)
                h.resource.send.assert_called_once_with(NATIVE_REQUEST)
                h.resource.close.assert_called_once_with()

    def test_native_observation_deadline_excludes_an_otherwise_fresh_return(self):
        for offset, status in ((-1, ec.Status.OK), (0, ec.Status.INDETERMINATE), (1, ec.Status.INDETERMINATE)):
            with self.subTest(offset=offset):
                h = PacketHarness(quiet(), tx_read(scheduled()))

                def return_at_edge():
                    h.clock.advance_to(1_000_000 + offset)
                    return received()

                h.pending.append(rx_read(return_at_edge))
                result = h.exchange()
                reason = "reference read" if status is ec.Status.OK else "outside the exchange window"
                self.assert_result(result, status, ec.Phase.CORRELATE, ec.Delivery.ACCEPTED, 1, reason)
                self.assertEqual(result.detail.elapsed_ns, 1_000_000 + offset)
                h.resource.close.assert_called_once_with()

    def test_native_receive_never_consumes_the_65th_event(self):
        outgoing = received(address=RX_ADDRESS[:2] + (4,) + RX_ADDRESS[3:])
        h = PacketHarness(quiet(), tx_read(scheduled()), *([rx_read(outgoing)] * 64), rx_read(received()))
        result = h.exchange()
        self.assert_result(result, ec.Status.INDETERMINATE, ec.Phase.RECEIVE, ec.Delivery.ACCEPTED, 64, "event budget")
        self.assertEqual(h.resource.recvmsg.call_count, 2 + 64)
        self.assertEqual(list(h.pending), [rx_read(received())])
        h.resource.send.assert_called_once_with(NATIVE_REQUEST)
        h.resource.close.assert_called_once_with()
