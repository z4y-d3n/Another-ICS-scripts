"""Scripted register of the Linux API boundary and its documented C layouts."""

from collections import deque
import errno
from struct import pack
from types import SimpleNamespace
from unittest.mock import Mock, call

from support import ec
from vectors import BOUND_MAC, NATIVE_RETURN

IFACE = "fixture0"
BOUND_ADDRESS = (IFACE, 0x88A4, 0, 1, BOUND_MAC)
RX_ADDRESS = (IFACE, 0x88A4, 1, 1, bytes.fromhex("020000000003"))
CMSG_TIMESTAMPING = (1, 65)
CMSG_AUXDATA = (263, 8)
CMSG_TX_TIMESTAMP = (263, 16)
ERRQUEUE = 0x2000
MSG_TRUNC = 0x20
MSG_CTRUNC = 0x08
TX_SECONDS = 1_700_000_000
TX_DEFAULT_NS = 250


def timestamp(sec=TX_SECONDS, nsec=TX_DEFAULT_NS, *, clock_slots=(0, 0, 0, 0)):
    """Three __kernel_timespec entries with signed 64-bit seconds and nsec."""
    return (*CMSG_TIMESTAMPING, pack("=qqqqqq", sec, nsec, *clock_slots))


def auxdata(length, snaplen=None, *, status=0x01, tci=0, tpid=0):
    if snaplen is None:
        snaplen = length
    return (*CMSG_AUXDATA, pack("=IIIHHHH", status, length, snaplen, 0, 14, tci, tpid))


def extended_error(number=errno.ENOMSG, origin=4, info=1):
    # ENOMSG is symbolic in the runtime. Windows and Linux ABIs can differ.
    return (*CMSG_TX_TIMESTAMP, pack("=IBBBBII", number, origin, 0, 0, 0, info, 0))


def scheduled(*, control=None, flags=ERRQUEUE, data=b""):
    if control is None:
        control = [extended_error(), timestamp()]
    return data, control, flags, None


def received(data=NATIVE_RETURN, *, control=None, flags=0, address=RX_ADDRESS):
    if control is None:
        control = [timestamp(nsec=TX_DEFAULT_NS + 1), auxdata(len(data))]
    return data, control, flags, address


def linux_symbols(factory, width=8):
    # CMSG_SPACE accounts for the aligned header and padded data. Both LP64
    # and ILP32 have two C ints after the size_t length.
    def space(size):
        header = width + 8
        return ((header + width - 1) // width + (size + width - 1) // width) * width

    return SimpleNamespace(
        AF_PACKET=17, SOCK_RAW=3, SOL_SOCKET=1, MSG_TRUNC=MSG_TRUNC, MSG_CTRUNC=MSG_CTRUNC,
        MSG_ERRQUEUE=ERRQUEUE, PACKET_OUTGOING=4, SO_TIMESTAMPING_NEW=65,
        CMSG_SPACE=Mock(side_effect=space), socket=factory,
    )


class PacketHarness:
    """Single scripted resource with strict operation names and a bounded read script."""

    def __init__(self, *reads, context=None, initial_ns=0):
        self.clock = ec.VirtualClock(initial_ns)
        self.context = context or ec._NativeDiagnosticContext(IFACE, 0x12, ec.Padding.STRIPPED)
        self.closed = False
        self.trace = Mock()
        self.resource = Mock(spec_set=["settimeout", "setsockopt", "bind", "getsockname", "send", "recvmsg", "close"])
        self.resource.getsockname.return_value = BOUND_ADDRESS
        self.resource.send.side_effect = len
        self.resource.close.side_effect = self._close
        self.trace.attach_mock(self.resource, "fd")
        self.trace.attach_mock(Mock(return_value=self.resource), "factory")
        self.system = linux_symbols(self.trace.factory)
        self.transport = ec._LinuxPacketTransport(self.context, self.clock, system=self.system, platform="linux")
        self.pending = deque(reads)
        self.resource.recvmsg.side_effect = self._recvmsg

    def _recvmsg(self, *args):
        if not self.pending:
            raise AssertionError(f"unexpected recvmsg call: {args!r}")
        expected, result = self.pending.popleft()
        if args != expected:
            raise AssertionError(f"recvmsg{args!r} != recvmsg{expected!r}")
        if isinstance(result, BaseException):
            raise result
        if callable(result):
            return result()
        return result

    def _close(self):
        if self.closed:
            raise AssertionError("attempted to close a released fake resource")
        self.closed = True

    def exchange(self, **overrides):
        options = dict(profile=ec.ReadProfile.APRD, context=self.context, transport=self.transport,
                       clock=self.clock, timeout=0.001)
        options.update(overrides)
        return ec.run_exchange(**options)


OPEN_CALLS = [
    call.factory(17, 3, 0), call.fd.settimeout(0.0), call.fd.setsockopt(263, 8, 1),
    call.fd.setsockopt(1, 65, 0x918), call.fd.bind((IFACE, 0x88A4)), call.fd.getsockname(),
]


def quiet():
    return (1514, 0), BlockingIOError(errno.EAGAIN, "no queued packet")


def tx_read(result):
    return (0, 96, ERRQUEUE), result


def rx_read(result):
    return (1514, 104), result
