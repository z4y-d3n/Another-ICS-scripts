#!/usr/bin/env python3
"""Offline EtherCAT Type 1 client with an internal Linux diagnostic backend."""

from __future__ import annotations

import argparse
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from decimal import Decimal, InvalidOperation
import errno
from enum import IntEnum, StrEnum
from itertools import pairwise
import logging
import os
import re
import socket
from struct import Struct
import sys
from time import monotonic_ns
from typing import Protocol, TextIO


# Protocol constants and data types
ETHERCAT_ETHERTYPE = 0x88A4
ETHERCAT_TYPE = 1
MIN_ETHERNET_NO_FCS = 60
MAX_FRAME_BYTES = 1514  # Untagged Ethernet II, no FCS.
MAX_DATAGRAMS = 15  # Product support limit, independent of the wire format.
MAX_EVENTS = 64  # At most 96,896 captured frame bytes per in-memory queue.
MAX_OUTPUT_BYTES = 16 * 1024
MIN_TIMEOUT = 0.001
MAX_TIMEOUT = 10.0
DEFAULT_TIMEOUT = 1.0
NS_PER_SECOND = 1_000_000_000

_ETHERNET = Struct("!6s6sH")
_WORD = Struct("<H")
_PHYSICAL_ADDRESS = Struct("<HH")
_DATAGRAM = Struct("<BB4sHH")
_CHAIN_START = _ETHERNET.size + _WORD.size
_DATAGRAM_OVERHEAD = _DATAGRAM.size + _WORD.size
MAX_CHAIN_BYTES = MAX_FRAME_BYTES - _CHAIN_START
MAX_SINGLE_PAYLOAD_BYTES = MAX_CHAIN_BYTES - _DATAGRAM_OVERHEAD

_LENGTH_MASK = 0x07FF
_FRAME_RESERVED = 0x0800
_DATAGRAM_RESERVED = 0x3800
_CIRCULATING = 0x4000
_MORE = 0x8000
_COMMAND_NAMES = (
    "NOP", "APRD", "APWR", "APRW", "FPRD", "FPWR", "FPRW", "BRD",
    "BWR", "BRW", "LRD", "LWR", "LRW", "ARMW", "FRMW",
)


class Status(IntEnum):
    OK = 0
    USAGE_ERROR = 2
    UNSUPPORTED = 3
    LOCAL_ERROR = 4
    PROTOCOL_ERROR = 5
    TIMEOUT = 6
    UNCORRELATED = 7
    INDETERMINATE = 8
    REJECTED = 9
    INTERRUPTED = 130


class Mode(StrEnum):
    INSPECT = "inspect"
    SIMULATE = "simulate"
    CAPABILITIES = "capabilities"
    DIAGNOSE = "diagnose"


class Origin(StrEnum):
    LOCAL = "local"
    OFFLINE_INPUT = "offline-input"
    SYNTHETIC = "synthetic"
    NATIVE_LINUX = "native-linux"
    NATIVE_TEST = "native-backend-test"


class Phase(StrEnum):
    VALIDATE = "validate"
    DISPATCH = "dispatch"
    INSPECT = "inspect"
    REPORT = "report"
    PRECHECK = "precheck"
    INITIALIZE = "initialize"
    SEND = "send"
    RECEIVE = "receive"
    CORRELATE = "correlate"
    CLOSE = "close"


class Padding(StrEnum):
    STRIPPED = "stripped"
    RETAINED = "retained"


class ReadProfile(StrEnum):
    FPRD = "FPRD"
    APRD = "APRD"


class Scenario(StrEnum):
    SUCCESS = "success"
    TIMEOUT = "timeout"
    UNCORRELATED = "uncorrelated"
    WKC_MISMATCH = "wkc-mismatch"
    INVALID = "invalid"
    REJECTED = "rejected"


class Direction(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    UNKNOWN = "unknown"


class Attribution(StrEnum):
    IGNORED = "ignored"
    FOREIGN = "foreign"
    INSUFFICIENT = "insufficient"
    MATCHED = "matched"


class Delivery(StrEnum):
    NOT_SENT = "not-sent"
    ACCEPTED = "accepted-by-transport"
    UNCERTAIN = "uncertain"


class UsageError(ValueError):
    """An invalid CLI argument or exchange configuration."""


class FrameError(ValueError):
    def __init__(self, offset: int, reason: str) -> None:
        self.offset = offset
        self.reason = reason
        super().__init__(f"byte {offset}: {reason}")


class InvalidFrame(FrameError):
    """A structural error in the input bytes."""


class UnsupportedFrame(FrameError):
    """A format or datagram count outside the supported profile."""


# Binary frame inspection
@dataclass(frozen=True, slots=True)
class Datagram:
    offset: int
    command: int
    index: int
    address: bytes
    circulating: bool
    more: bool
    irq: int
    payload: bytes
    wkc: int

    @property
    def command_name(self) -> str:
        if self.command < len(_COMMAND_NAMES):
            return _COMMAND_NAMES[self.command]
        return "unknown"


@dataclass(frozen=True, slots=True)
class EtherCATFrame:
    destination: bytes
    source: bytes
    chain_length: int
    datagrams: tuple[Datagram, ...]
    padding: bytes
    padding_convention: Padding


def decode_frame(data: bytes, padding: Padding = Padding.STRIPPED) -> EtherCATFrame:
    """Decode an untagged Type 1 capture without FCS under the selected padding convention.

    FrameError subclasses distinguish malformed input from unsupported representations.
    """
    if type(data) is not bytes or not isinstance(padding, Padding):
        raise TypeError("decode_frame requires bytes and a Padding value")
    if len(data) > MAX_FRAME_BYTES:
        raise InvalidFrame(MAX_FRAME_BYTES, "frame exceeds the 1514-byte input limit")
    if len(data) < _ETHERNET.size:
        raise InvalidFrame(len(data), "truncated Ethernet header")
    destination, source, ether_type = _ETHERNET.unpack_from(data)
    if ether_type != ETHERCAT_ETHERTYPE:
        raise UnsupportedFrame(12, f"EtherType 0x{ether_type:04x} outside untagged EtherCAT")
    if len(data) < _CHAIN_START:
        raise InvalidFrame(len(data), "truncated EtherCAT header")

    (header,) = _WORD.unpack_from(data, _ETHERNET.size)
    frame_type = header >> 12
    if frame_type != ETHERCAT_TYPE:
        raise UnsupportedFrame(_ETHERNET.size + 1, f"EtherCAT type {frame_type} outside Type 1")
    if header & _FRAME_RESERVED:
        raise InvalidFrame(_ETHERNET.size + 1, "EtherCAT header reserved bit is set")
    chain_length = header & _LENGTH_MASK
    if not _DATAGRAM_OVERHEAD <= chain_length <= MAX_CHAIN_BYTES:
        raise InvalidFrame(_ETHERNET.size, "datagram chain length outside 12..1498 bytes")
    chain_end = _CHAIN_START + chain_length
    if len(data) < chain_end:
        raise InvalidFrame(len(data), "truncated datagram chain")

    expected_size = chain_end
    if padding is Padding.RETAINED:
        expected_size = max(MIN_ETHERNET_NO_FCS, chain_end)
    if len(data) != expected_size:
        raise InvalidFrame(min(len(data), expected_size), f"expected {expected_size} bytes with {padding} padding")

    datagrams = []
    overflow_offset = None
    cursor = _CHAIN_START
    while cursor < chain_end:
        if chain_end - cursor < _DATAGRAM_OVERHEAD:
            raise InvalidFrame(cursor, "incomplete datagram in declared chain")
        command, index, address, length_flags, irq = _DATAGRAM.unpack_from(data, cursor)
        if length_flags & _DATAGRAM_RESERVED:
            raise InvalidFrame(cursor + 7, "datagram reserved bits are set")
        payload_start = cursor + _DATAGRAM.size
        payload_end = payload_start + (length_flags & _LENGTH_MASK)
        next_cursor = payload_end + _WORD.size
        if next_cursor > chain_end:
            raise InvalidFrame(cursor + 6, "payload and Working Counter overrun the declared chain")
        more = bool(length_flags & _MORE)
        if more != (next_cursor < chain_end):
            raise InvalidFrame(cursor + 7, "M flag disagrees with datagram chain continuity")

        if len(datagrams) < MAX_DATAGRAMS:
            (wkc,) = _WORD.unpack_from(data, payload_end)
            datagrams.append(Datagram(
                cursor, command, index, address, bool(length_flags & _CIRCULATING),
                more, irq, data[payload_start:payload_end], wkc,
            ))
        elif overflow_offset is None:
            # Validate the remaining structure before declaring it outside the support profile.
            overflow_offset = cursor
        cursor = next_cursor

    if overflow_offset is not None:
        raise UnsupportedFrame(overflow_offset, f"chain exceeds the supported {MAX_DATAGRAMS} datagrams")
    return EtherCATFrame(destination, source, chain_length, tuple(datagrams), data[chain_end:], padding)


# Exchange fixtures and return correlation
@dataclass(frozen=True, slots=True)
class _ReadSpec:
    command: int
    index: int
    request_adp: int
    return_adp: int
    ado: int
    expected_payload: bytes
    expected_wkc: int = 1


_BROADCAST_DESTINATION = b"\xff" * 6
_FIXTURE_SOURCE = bytes.fromhex("020000000001")
_READ_SPECS = {
    ReadProfile.FPRD: _ReadSpec(0x04, 0x27, 0x1234, 0x1234, 0x0100, b"\xa5\x5a"),
    ReadProfile.APRD: _ReadSpec(0x01, 0x39, 0, 1, 0x0000, b"\x11"),
}


def encode_request(profile: ReadProfile) -> bytes:
    """Construct the fixed, stripped capture fixture for a supported read profile."""
    if not isinstance(profile, ReadProfile):
        raise UsageError("unknown synthetic read profile")
    spec = _READ_SPECS[profile]
    length = len(spec.expected_payload)
    chain_length = _DATAGRAM_OVERHEAD + length
    address = _PHYSICAL_ADDRESS.pack(spec.request_adp, spec.ado)
    return (
        _ETHERNET.pack(_BROADCAST_DESTINATION, _FIXTURE_SOURCE, ETHERCAT_ETHERTYPE)
        + _WORD.pack((ETHERCAT_TYPE << 12) | chain_length)
        + _DATAGRAM.pack(spec.command, spec.index, address, length, 0)
        + bytes(length)
        + _WORD.pack(0)
    )


# Return literals assembled from the published layout and fixture values.
# Both returns change Src MAC, IRQ, C, payload and WKC. APRD also changes ADP.
_RETURN_FIXTURES = {
    ReadProfile.FPRD: bytes.fromhex(
        "ffffffffffff 020000000003 88a4 0e10 0427 3412 0001 0240 3402 a55a 0100"
    ),
    ReadProfile.APRD: bytes.fromhex(
        "ffffffffffff 020000000003 88a4 0d10 0139 0100 0000 0140 4000 11 0100"
    ),
}


@dataclass(frozen=True, slots=True)
class ExchangeContext:
    interface: str
    exchange_id: object = field(default_factory=object)

    def __post_init__(self) -> None:
        if type(self.interface) is not str or not 1 <= len(self.interface) <= 15:
            raise UsageError("exchange requires a bounded interface label")
        if self.exchange_id is None:
            raise UsageError("exchange requires a context token")


@dataclass(frozen=True, slots=True)
class _NativeDiagnosticContext:
    """Reference values for an authorized, dedicated single-ESC bench."""

    interface: str
    expected_esc_type: int
    padding: Padding

    def __post_init__(self) -> None:
        _validate_interface(self.interface)
        if type(self.expected_esc_type) is not int or not 0 <= self.expected_esc_type <= 0xFF:
            raise UsageError("the reference ESC Type must be a single byte")
        if not isinstance(self.padding, Padding):
            raise UsageError("the receive padding convention must be selected explicitly")


@dataclass(frozen=True, slots=True)
class LinkEvent:
    timestamp_ns: int
    interface: str | None
    exchange_id: object | None
    direction: Direction

    def __post_init__(self) -> None:
        if type(self.timestamp_ns) is not int or self.timestamp_ns < 0:
            raise ValueError("event timestamp must be a nonnegative integer in nanoseconds")
        if self.interface is not None and (type(self.interface) is not str or not 1 <= len(self.interface) <= 15):
            raise ValueError("invalid event interface label")
        if not isinstance(self.direction, Direction):
            raise TypeError("event requires a Direction value")


@dataclass(frozen=True, slots=True)
class PacketMetadata:
    protocol: int | None
    packet_type: int | None
    hardware_type: int | None
    vlan_tagged: bool | None
    packet_length: int | None  # Kernel-reported length in the packet socket, not a wire measurement.
    tx_scheduled_ns: int | None = None  # Linux software timestamps use the system clock.
    rx_software_ns: int | None = None


@dataclass(frozen=True, slots=True)
class FrameEvent(LinkEvent):
    data: bytes
    padding: Padding = Padding.STRIPPED
    truncated: bool = False
    packet_metadata: PacketMetadata | None = None

    def __post_init__(self) -> None:
        LinkEvent.__post_init__(self)
        if type(self.data) is not bytes or len(self.data) > MAX_FRAME_BYTES:
            raise ValueError("frame event requires at most 1514 bytes of captured data")
        if not isinstance(self.padding, Padding) or type(self.truncated) is not bool:
            raise TypeError("frame event requires Padding and a truncation flag")


@dataclass(frozen=True, slots=True)
class RejectionEvent(LinkEvent):
    profile: ReadProfile

    def __post_init__(self) -> None:
        LinkEvent.__post_init__(self)
        if not isinstance(self.profile, ReadProfile):
            raise TypeError("synthetic rejection requires a read profile")


@dataclass(frozen=True, slots=True)
class PendingExchange:
    profile: ReadProfile
    context: ExchangeContext | _NativeDiagnosticContext
    sent_at_ns: int
    deadline_ns: int


@dataclass(frozen=True, slots=True)
class EventAssessment:
    status: Status | None
    attribution: Attribution
    reason: str
    structurally_valid: bool | None = None
    wkc: int | None = None
    esc_type: int | None = None


def _stable_fields(data: bytes, spec: _ReadSpec) -> tuple[Attribution, int | None]:
    """Use only complete identity fields inside the declared chain, even on a bad capture."""
    if len(data) >= 6 and data[:6] != _BROADCAST_DESTINATION:
        return Attribution.FOREIGN, None
    if len(data) < _ETHERNET.size:
        return Attribution.INSUFFICIENT, None
    if _ETHERNET.unpack_from(data)[2] != ETHERCAT_ETHERTYPE:
        return Attribution.FOREIGN, None
    if len(data) < _CHAIN_START:
        return Attribution.INSUFFICIENT, None
    (header,) = _WORD.unpack_from(data, _ETHERNET.size)
    if header >> 12 != ETHERCAT_TYPE:
        return Attribution.FOREIGN, None

    # Through Len/flags. A short prefix can rule out identity before it can establish it.
    identity = data[_CHAIN_START:_CHAIN_START + min(8, header & _LENGTH_MASK)]
    if not bytes((spec.command, spec.index)).startswith(identity[:2]):
        return Attribution.FOREIGN, None
    adp = _WORD.unpack_from(identity, 2)[0] if len(identity) >= 4 else None
    if spec.command == 0x04 and adp is not None and adp != spec.return_adp:
        return Attribution.FOREIGN, None
    if len(identity) >= 6 and _WORD.unpack_from(identity, 4)[0] != spec.ado:
        return Attribution.FOREIGN, None
    if len(identity) < 8:
        return Attribution.INSUFFICIENT, adp
    (length_flags,) = _WORD.unpack_from(identity, 6)
    if (length_flags & _LENGTH_MASK) != len(spec.expected_payload):
        return Attribution.FOREIGN, None
    return Attribution.MATCHED, adp


def assess_event(
    event: FrameEvent | RejectionEvent, pending: PendingExchange, observed_at_ns: int,
) -> EventAssessment:
    """Check identity, context and timing before interpreting a candidate return.

    Synthetic events use exchange identity. Native candidates also require link
    metadata and kernel timestamps that establish receive order.
    """
    if event.direction is Direction.OUTBOUND:
        return EventAssessment(None, Attribution.IGNORED, "outbound copy")
    context = pending.context
    if event.interface is not None and event.interface != context.interface:
        return EventAssessment(Status.UNCORRELATED, Attribution.FOREIGN, "event belongs to another interface")
    if isinstance(context, ExchangeContext) and (
        event.exchange_id is not None and event.exchange_id is not context.exchange_id
    ):
        return EventAssessment(Status.UNCORRELATED, Attribution.FOREIGN, "event belongs to another exchange context")

    metadata = event.packet_metadata if isinstance(event, FrameEvent) else None
    if isinstance(context, _NativeDiagnosticContext):
        if isinstance(event, RejectionEvent):
            return EventAssessment(Status.UNCORRELATED, Attribution.FOREIGN, "rejection is a synthetic event")
        if metadata is not None and (
            metadata.protocol not in (None, ETHERCAT_ETHERTYPE)
            or metadata.hardware_type not in (None, _ARPHRD_ETHER)
            or metadata.vlan_tagged is True
        ):
            return EventAssessment(Status.UNCORRELATED, Attribution.FOREIGN, "packet metadata is outside the link profile")
        complete_context = metadata is not None and (
            metadata.protocol == ETHERCAT_ETHERTYPE and metadata.hardware_type == _ARPHRD_ETHER
            and metadata.vlan_tagged is False and event.exchange_id is None
        )
        expected_payload = bytes((context.expected_esc_type,))
    else:
        complete_context = event.exchange_id is not None and metadata is None
        expected_payload = _READ_SPECS[pending.profile].expected_payload

    spec = _READ_SPECS[pending.profile]
    adp = None
    if isinstance(event, FrameEvent):
        evidence, adp = _stable_fields(event.data, spec)
        if evidence is Attribution.FOREIGN:
            return EventAssessment(Status.UNCORRELATED, evidence, "return identity fields differ from the request")
        if evidence is Attribution.INSUFFICIENT:
            return EventAssessment(Status.INDETERMINATE, evidence, "capture lacks complete return identity fields")
    elif event.profile is not pending.profile:
        return EventAssessment(Status.UNCORRELATED, Attribution.FOREIGN, "rejection belongs to another profile")

    if event.direction is not Direction.INBOUND or event.interface is None or not complete_context:
        return EventAssessment(Status.INDETERMINATE, Attribution.INSUFFICIENT, "incomplete direction or exchange context")
    if not pending.sent_at_ns <= event.timestamp_ns <= observed_at_ns < pending.deadline_ns:
        return EventAssessment(Status.INDETERMINATE, Attribution.INSUFFICIENT, "candidate is outside the exchange window")
    if isinstance(context, _NativeDiagnosticContext) and (
        metadata is None or metadata.tx_scheduled_ns is None or metadata.rx_software_ns is None
        or metadata.rx_software_ns <= metadata.tx_scheduled_ns
    ):
        return EventAssessment(
            Status.INDETERMINATE, Attribution.INSUFFICIENT, "kernel timestamps do not establish receive order",
        )
    if isinstance(event, RejectionEvent):
        return EventAssessment(Status.REJECTED, Attribution.MATCHED, "explicit rejection from the synthetic fixture")

    assert adp is not None  # Complete stable fields include the two-byte ADP.
    position_issue = None
    if adp != spec.return_adp:
        position_issue = f"return position 0x{adp:04x} differs from expected 0x{spec.return_adp:04x}"
    try:
        if event.truncated:
            raise InvalidFrame(len(event.data), "transport reported truncation")
        frame = decode_frame(event.data, event.padding)
    except InvalidFrame as exc:
        if position_issue:
            return EventAssessment(Status.INDETERMINATE, Attribution.INSUFFICIENT, f"{position_issue}. {exc}", False)
        return EventAssessment(Status.PROTOCOL_ERROR, Attribution.MATCHED, str(exc), False)
    except UnsupportedFrame as exc:
        return EventAssessment(Status.INDETERMINATE, Attribution.INSUFFICIENT, str(exc))

    if len(frame.datagrams) != 1:
        return EventAssessment(
            Status.INDETERMINATE, Attribution.INSUFFICIENT, "return has an unexpected datagram count", True,
        )
    datagram = frame.datagrams[0]
    esc_type = datagram.payload[0] if isinstance(context, _NativeDiagnosticContext) else None
    if position_issue:
        return EventAssessment(
            Status.INDETERMINATE, Attribution.INSUFFICIENT, position_issue, True, datagram.wkc, esc_type,
        )
    if datagram.wkc != spec.expected_wkc:
        return EventAssessment(
            Status.INDETERMINATE, Attribution.MATCHED, "Working Counter differs from the read profile expectation",
            True, datagram.wkc, esc_type,
        )
    if datagram.payload != expected_payload:
        return EventAssessment(
            Status.INDETERMINATE, Attribution.MATCHED, "read value differs from the expected value",
            True, datagram.wkc, esc_type,
        )
    reason = "return matches the reference read profile" if esc_type is not None else "synthetic return matches the read profile"
    return EventAssessment(
        Status.OK, Attribution.MATCHED, reason, True, datagram.wkc, esc_type,
    )


# Transport abstractions
class TransportError(Exception):
    """A transport failure, with definite non-delivery if raised by send()."""


class DeadlineExpired(TransportError):
    """The budget expired before starting a transport operation."""


class DeliveryUncertain(TransportError):
    """A send attempt may have delivered data. The client may never retry it."""


class _UnsupportedTransport(TransportError):
    """The selected platform, API, or link type is outside the transport profile."""


class _InterruptedBeforeSend(KeyboardInterrupt):
    """An interruption while preparing the socket, before the send call."""


class Transport(Protocol):
    origin: Origin

    # receive() returns None at expiry. A DeadlineExpired at that stage has the same meaning.
    # close() must be safe after a failed open() and release any partial resource.
    def open(self, deadline_ns: int) -> None: ...
    def send(self, frame: bytes, deadline_ns: int) -> None: ...
    def receive(self, deadline_ns: int) -> FrameEvent | RejectionEvent | None: ...
    def close(self) -> None: ...


class VirtualClock:
    """Monotonic nanoseconds with explicit advancement by the simulated transport."""

    def __init__(self, start_ns: int = 0) -> None:
        if type(start_ns) is not int or start_ns < 0:
            raise ValueError("clock must start at a nonnegative integer nanosecond")
        self._now_ns = start_ns

    def __call__(self) -> int:
        return self._now_ns

    def advance_to(self, instant_ns: int) -> None:
        if type(instant_ns) is not int or instant_ns < self._now_ns:
            raise ValueError("virtual clock cannot move backwards")
        self._now_ns = instant_ns


def _check_budget(clock: Callable[[], int], deadline_ns: int) -> None:
    if clock() >= deadline_ns:
        raise DeadlineExpired("exchange deadline reached before transport operation")


class MemoryTransport:
    origin = Origin.SYNTHETIC

    def __init__(self, clock: VirtualClock, events: tuple[FrameEvent | RejectionEvent, ...]) -> None:
        if type(events) is not tuple or len(events) > MAX_EVENTS:
            raise UsageError("simulation requires a tuple of at most 64 events")
        if any(not isinstance(event, (FrameEvent, RejectionEvent)) for event in events):
            raise TypeError("simulation requires typed frame or rejection events")
        if any(first.timestamp_ns > second.timestamp_ns for first, second in pairwise(events)):
            raise UsageError("fixture events must be ordered by nondecreasing timestamp")
        self._clock = clock
        self._events = deque(events)
        self._opened = False
        self.sent_frame: bytes | None = None
        self.closed = False

    def open(self, deadline_ns: int) -> None:
        _check_budget(self._clock, deadline_ns)
        if self._opened or self.closed:
            raise TransportError("simulated transport is single-use")
        self._opened = True

    def send(self, frame: bytes, deadline_ns: int) -> None:
        _check_budget(self._clock, deadline_ns)
        if not self._opened or self.closed or self.sent_frame is not None:
            raise TransportError("simulated transport cannot accept another request")
        if type(frame) is not bytes or not 1 <= len(frame) <= MAX_FRAME_BYTES:
            raise TransportError("send requires a complete bounded frame buffer")
        self.sent_frame = frame

    def receive(self, deadline_ns: int) -> FrameEvent | RejectionEvent | None:
        if self.closed or self.sent_frame is None:
            raise TransportError("simulated transport has no pending request")
        now = self._clock()
        if self._events and now < deadline_ns and self._events[0].timestamp_ns < deadline_ns:
            event = self._events.popleft()
            self._clock.advance_to(max(now, event.timestamp_ns))
            return event
        self._clock.advance_to(max(now, deadline_ns))
        return None

    def close(self) -> None:
        self.closed = True
        self._events.clear()


# Internal Linux backend. Public dispatch rejects diagnose before constructing a transport.
_SYSTEM_SOCKET_MODULE = socket
_PACKET_SYMBOLS = (
    "AF_PACKET", "SOCK_RAW", "SOL_SOCKET", "MSG_TRUNC", "MSG_CTRUNC", "MSG_ERRQUEUE", "PACKET_OUTGOING",
)
_INTERFACE_RE = re.compile(r"[a-zA-Z0-9_.-]{1,15}")
# Linux socket.h, if_arp.h and if_packet.h. CPython need not export these constants.
_SOL_PACKET = 263
_PACKET_AUXDATA = 8
_PACKET_TX_TIMESTAMP = 16
_ARPHRD_ETHER = 1
_PACKET_INBOUND_TYPES = (0, 1, 2, 3)  # HOST, BROADCAST, MULTICAST, OTHERHOST.
_TP_STATUS_VLAN_VALID = 1 << 4
_TP_STATUS_VLAN_TPID_VALID = 1 << 6
_SO_EE_ORIGIN_TIMESTAMPING = 4
_SCM_TSTAMP_SCHED = 1
_SOF_TIMESTAMPING_RX_SOFTWARE = 1 << 3
_SOF_TIMESTAMPING_SOFTWARE = 1 << 4
_SOF_TIMESTAMPING_TX_SCHED = 1 << 8
_SOF_TIMESTAMPING_OPT_TSONLY = 1 << 11
_TIMESTAMPING_FLAGS = (
    _SOF_TIMESTAMPING_RX_SOFTWARE | _SOF_TIMESTAMPING_SOFTWARE
    | _SOF_TIMESTAMPING_TX_SCHED | _SOF_TIMESTAMPING_OPT_TSONLY
)
_AUXDATA = Struct("=IIIHHHH")
_SCM_TIMESTAMPING64 = Struct("=6q")
_SOCK_EXTENDED_ERR = Struct("=IBBBBII")
_WOULD_BLOCK = (errno.EAGAIN, errno.EWOULDBLOCK)
_API_UNSUPPORTED = (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.ENOPROTOOPT, errno.ENOSYS)


def supports_linux_packet(platform: str, symbols: object) -> bool:
    return (
        platform == "linux"
        and all(isinstance(getattr(symbols, name, None), int) for name in _PACKET_SYMBOLS)
        and callable(getattr(symbols, "socket", None))
        and callable(getattr(symbols, "CMSG_SPACE", None))
        and (symbols is _SYSTEM_SOCKET_MODULE or isinstance(getattr(symbols, "SO_TIMESTAMPING_NEW", None), int))
    )


def _validate_interface(interface: str) -> None:
    if type(interface) is not str or interface in (".", "..") or _INTERFACE_RE.fullmatch(interface) is None:
        raise UsageError("interface requires a 1..15 character Linux name in [A-Za-z0-9_.-]")


@dataclass(frozen=True, slots=True)
class PacketSocketPlan:
    constructor: tuple[int, int, int]
    bind_address: tuple[str, int]
    outgoing_type: int
    truncation_flag: int
    control_truncation_flag: int
    error_queue_flag: int
    socket_level: int
    timestamping_option: int
    receive_control_bytes: int
    transmit_control_bytes: int


def _timestamping_option(symbols: object) -> int:
    option = getattr(symbols, "SO_TIMESTAMPING_NEW", None)
    if isinstance(option, int):
        return option
    # Linux UAPI socket.h uses the asm-generic value except on SPARC and PA-RISC.
    machine = os.uname().machine.lower()
    if machine.startswith("sparc"):
        return 0x0043
    if machine.startswith(("parisc", "hppa")):
        return 0x403A
    return 65


def plan_linux_packet(platform: str, symbols: object, interface: str) -> PacketSocketPlan | None:
    _validate_interface(interface)
    if not supports_linux_packet(platform, symbols):
        return None
    cmsg_space = getattr(symbols, "CMSG_SPACE")
    timestamp_space = cmsg_space(_SCM_TIMESTAMPING64.size)
    # Protocol zero receives nothing before bind. CPython converts bind's host-order EtherType.
    return PacketSocketPlan(
        (getattr(symbols, "AF_PACKET"), getattr(symbols, "SOCK_RAW"), 0),
        (interface, ETHERCAT_ETHERTYPE),
        getattr(symbols, "PACKET_OUTGOING"), getattr(symbols, "MSG_TRUNC"),
        getattr(symbols, "MSG_CTRUNC"), getattr(symbols, "MSG_ERRQUEUE"),
        getattr(symbols, "SOL_SOCKET"), _timestamping_option(symbols),
        timestamp_space + cmsg_space(_AUXDATA.size), timestamp_space + cmsg_space(_SOCK_EXTENDED_ERR.size),
    )


_PacketMessage = tuple[bytes, list[tuple[int, int, bytes]], int, object]


class _PacketSocket(Protocol):
    def settimeout(self, seconds: float) -> None: ...
    def setsockopt(self, level: int, option: int, value: int) -> None: ...
    def bind(self, address: tuple[str, int]) -> None: ...
    def getsockname(self) -> object: ...
    def send(self, frame: bytes) -> int: ...
    def recvmsg(self, bufsize: int, ancbufsize: int, flags: int = 0) -> _PacketMessage: ...
    def close(self) -> None: ...


def _bound_mac(address: object, wanted: tuple[str, int]) -> bytes:
    if not isinstance(address, tuple) or len(address) != 5 or address[:2] != wanted:
        raise TransportError("packet socket identity differs from the requested bind")
    if address[3] != _ARPHRD_ETHER:
        raise _UnsupportedTransport("packet socket needs an Ethernet link type")
    mac = address[4]
    if type(mac) is not bytes or len(mac) != 6 or not any(mac) or mac[0] & 1:
        raise TransportError("packet socket did not report a valid local Ethernet MAC")
    return mac


def _control_value(control: object, level: int, kind: int) -> bytes | None:
    if not isinstance(control, (list, tuple)) or len(control) > 2:
        return None
    value = None
    for record in control:
        if not isinstance(record, tuple) or len(record) != 3 or type(record[2]) is not bytes:
            return None
        if record[:2] == (level, kind):
            if value is not None:
                return None
            value = record[2]
    return value


def _software_timestamp(control: object, plan: PacketSocketPlan) -> int | None:
    value = _control_value(control, plan.socket_level, plan.timestamping_option)
    if value is None or len(value) != _SCM_TIMESTAMPING64.size:
        return None
    seconds, nanoseconds, *_ = _SCM_TIMESTAMPING64.unpack(value)
    if seconds < 0 or not 0 <= nanoseconds < NS_PER_SECOND or not (seconds or nanoseconds):
        return None
    return seconds * NS_PER_SECOND + nanoseconds


def _scheduled_timestamp(message: _PacketMessage, plan: PacketSocketPlan) -> int | None:
    """Extract the software timestamp from a valid transmit-scheduling notification."""
    if not isinstance(message, tuple) or len(message) != 4:
        return None
    data, control, flags, _ = message
    if type(data) is not bytes or data or type(flags) is not int or flags < 0 or not flags & plan.error_queue_flag:
        return None
    if flags & (plan.control_truncation_flag | plan.truncation_flag):
        return None
    value = _control_value(control, _SOL_PACKET, _PACKET_TX_TIMESTAMP)
    if value is None or len(value) != _SOCK_EXTENDED_ERR.size:
        return None
    error, origin, _, _, _, info, _ = _SOCK_EXTENDED_ERR.unpack(value)
    if (error, origin, info) != (errno.ENOMSG, _SO_EE_ORIGIN_TIMESTAMPING, _SCM_TSTAMP_SCHED):
        return None
    return _software_timestamp(control, plan)


def _normalize_packet(
    message: _PacketMessage, plan: PacketSocketPlan, padding: Padding, observed_at_ns: int,
    tx_scheduled_ns: int | None,
) -> FrameEvent:
    """Convert a receive-path recvmsg result into an event with optional link metadata.

    The caller supplies the monotonic observation time. Kernel timestamps remain
    in their original clock domain as evidence for receive ordering.
    """
    if not isinstance(message, tuple) or len(message) != 4:
        raise TransportError("recvmsg returned an invalid packet result")
    data, control, flags, address = message
    if type(data) is not bytes or len(data) > MAX_FRAME_BYTES or type(flags) is not int or flags < 0:
        raise TransportError("recvmsg returned invalid packet bytes or flags")
    if flags & plan.error_queue_flag:
        raise TransportError("recvmsg returned error-queue data on the receive path")

    interface = protocol = packet_type = hardware_type = None
    if isinstance(address, tuple) and len(address) >= 4:
        name, proto, kind, link_type = address[:4]
        interface = name if type(name) is str and 1 <= len(name) <= 15 else None
        protocol = proto if type(proto) is int and 0 <= proto <= 0xFFFF else None
        packet_type = kind if type(kind) is int else None
        hardware_type = link_type if type(link_type) is int else None

    if packet_type == plan.outgoing_type:
        direction = Direction.OUTBOUND
    elif packet_type in _PACKET_INBOUND_TYPES:
        direction = Direction.INBOUND
    else:
        direction = Direction.UNKNOWN

    truncated = bool(flags & plan.truncation_flag)
    vlan_tagged = packet_length = rx_software_ns = None
    if direction is not Direction.OUTBOUND and not flags & plan.control_truncation_flag:
        rx_software_ns = _software_timestamp(control, plan)
        value = _control_value(control, _SOL_PACKET, _PACKET_AUXDATA)
        if value is not None and len(value) == _AUXDATA.size:
            status, length, snaplen, _, _, _, _ = _AUXDATA.unpack(value)
            if len(data) == min(snaplen, MAX_FRAME_BYTES) and snaplen <= length:
                packet_length = length
                truncated = truncated or len(data) < length
                # This bit describes the skb delivered by Linux, after possible offload or demux.
                if status & _TP_STATUS_VLAN_VALID:
                    vlan_tagged = True
                elif not status & _TP_STATUS_VLAN_TPID_VALID:
                    vlan_tagged = False

    return FrameEvent(
        observed_at_ns, interface, None, direction, data, padding, truncated,
        PacketMetadata(
            protocol, packet_type, hardware_type, vlan_tagged, packet_length, tx_scheduled_ns, rx_software_ns,
        ),
    )


class _PacketState(StrEnum):
    NEW = "new"
    OPENING = "opening"
    READY = "ready"
    SEND_ATTEMPTED = "send-attempted"
    AWAITING = "awaiting"
    CLOSING = "closing"
    CLOSED = "closed"


class _LinuxPacketTransport:
    """Single-owner Linux APRD backend, exercised with a substituted socket API in tests."""

    def __init__(
        self, context: _NativeDiagnosticContext, clock: Callable[[], int] = monotonic_ns,
        *, system: object | None = None, platform: str | None = None,
    ) -> None:
        self._context = context
        self._clock = clock
        self._system = socket if system is None else system
        self._platform = sys.platform if platform is None else platform
        self.origin = Origin.NATIVE_LINUX if self._system is _SYSTEM_SOCKET_MODULE else Origin.NATIVE_TEST
        self._state = _PacketState.NEW
        self._resource: _PacketSocket | None = None
        self._plan: PacketSocketPlan | None = None
        self._mac: bytes | None = None
        self._tx_timestamp_read = False
        self._tx_scheduled_ns: int | None = None

    def _check_reference(self, context: _NativeDiagnosticContext, clock: Callable[[], int]) -> None:
        if context != self._context or clock is not self._clock:
            raise UsageError("client and packet transport must share the reference context and clock")

    def open(self, deadline_ns: int) -> None:
        if self._state is not _PacketState.NEW:
            raise TransportError("Linux packet transport is single-use")
        self._state = _PacketState.OPENING
        _check_budget(self._clock, deadline_ns)
        plan = plan_linux_packet(self._platform, self._system, self._context.interface)
        if plan is None:
            raise _UnsupportedTransport("Linux packet socket API is unavailable")
        _check_budget(self._clock, deadline_ns)
        try:
            self._resource = resource = getattr(self._system, "socket")(*plan.constructor)
            _check_budget(self._clock, deadline_ns)
            if not callable(getattr(resource, "recvmsg", None)):
                raise _UnsupportedTransport("packet socket does not support recvmsg")
            resource.settimeout(0.0)
            _check_budget(self._clock, deadline_ns)
            resource.setsockopt(_SOL_PACKET, _PACKET_AUXDATA, 1)
            _check_budget(self._clock, deadline_ns)
            resource.setsockopt(plan.socket_level, plan.timestamping_option, _TIMESTAMPING_FLAGS)
            _check_budget(self._clock, deadline_ns)
            resource.bind(plan.bind_address)
            _check_budget(self._clock, deadline_ns)
            mac = _bound_mac(resource.getsockname(), plan.bind_address)
            _check_budget(self._clock, deadline_ns)
        except OSError as exc:
            if exc.errno in _API_UNSUPPORTED:
                raise _UnsupportedTransport(_failure_text(exc)) from exc
            raise
        self._mac = mac
        self._plan = plan
        self._state = _PacketState.READY

    def _arm_timeout(self, resource: _PacketSocket, deadline_ns: int) -> None:
        remaining_ns = deadline_ns - self._clock()
        if remaining_ns <= 0:
            raise DeadlineExpired("exchange deadline reached before transport operation")
        resource.settimeout(remaining_ns / NS_PER_SECOND)
        _check_budget(self._clock, deadline_ns)

    def send(self, frame: bytes, deadline_ns: int) -> None:
        try:
            resource, mac = self._resource, self._mac
            if self._state is not _PacketState.READY or resource is None or mac is None:
                raise TransportError("packet transport cannot accept another request")
            if type(frame) is not bytes or frame != encode_request(ReadProfile.APRD):
                raise TransportError("packet transport accepts only the fixed ESC Type APRD request")
            self._state = _PacketState.SEND_ATTEMPTED
            # Use the interface MAC and explicitly pad the single Ethernet message without an FCS.
            wire_bytes = (_ETHERNET.pack(_BROADCAST_DESTINATION, mac, ETHERCAT_ETHERTYPE)
                          + frame[_ETHERNET.size:]).ljust(MIN_ETHERNET_NO_FCS, b"\0")
            _check_budget(self._clock, deadline_ns)
            # Still nonblocking. Pending EtherCAT traffic defeats the quiet-bench assumption.
            try:
                resource.recvmsg(MAX_FRAME_BYTES, 0)
            except BlockingIOError as exc:
                if exc.errno not in _WOULD_BLOCK:
                    raise
            else:
                raise TransportError("EtherCAT traffic was queued before the request")
            self._arm_timeout(resource, deadline_ns)
        except KeyboardInterrupt as exc:
            raise _InterruptedBeforeSend() from exc
        except OSError as exc:
            raise TransportError(_failure_text(exc)) from exc

        try:
            delivered = resource.send(wire_bytes)
        except OSError as exc:
            if exc.errno in (*_WOULD_BLOCK, errno.EMSGSIZE):
                raise TransportError(_failure_text(exc)) from exc
            raise
        if type(delivered) is not int or delivered != len(wire_bytes):
            raise DeliveryUncertain("packet socket did not report accepting the complete frame")
        self._state = _PacketState.AWAITING

    def _read_tx_schedule(self, resource: _PacketSocket, plan: PacketSocketPlan, deadline_ns: int) -> int | None:
        _check_budget(self._clock, deadline_ns)
        resource.settimeout(0.0)
        _check_budget(self._clock, deadline_ns)
        try:
            message = resource.recvmsg(0, plan.transmit_control_bytes, plan.error_queue_flag)
        except BlockingIOError as exc:
            if exc.errno not in _WOULD_BLOCK:
                raise
            return None
        return _scheduled_timestamp(message, plan)

    def receive(self, deadline_ns: int) -> FrameEvent | None:
        resource, plan = self._resource, self._plan
        if self._state is not _PacketState.AWAITING or resource is None or plan is None:
            raise TransportError("packet transport has no pending request")
        if not self._tx_timestamp_read:
            self._tx_timestamp_read = True
            self._tx_scheduled_ns = self._read_tx_schedule(resource, plan, deadline_ns)
        self._arm_timeout(resource, deadline_ns)
        try:
            message = resource.recvmsg(MAX_FRAME_BYTES, plan.receive_control_bytes)
        except TimeoutError as exc:
            if exc.errno is not None:
                raise
            return None
        # This is local observation time. The socket did not supply a session token.
        return _normalize_packet(message, plan, self._context.padding, self._clock(), self._tx_scheduled_ns)

    def close(self) -> None:
        if self._state in (_PacketState.CLOSING, _PacketState.CLOSED):
            return
        self._state = _PacketState.CLOSING
        try:
            if self._resource is not None:
                self._resource.close()
        finally:
            self._resource = None
            self._state = _PacketState.CLOSED


# Operation results and lifecycle
@dataclass(frozen=True, slots=True)
class ExchangeEvidence:
    profile: ReadProfile
    delivery: Delivery
    elapsed_ns: int
    events: int
    expected_wkc: int
    assessment: EventAssessment | None


@dataclass(frozen=True, slots=True)
class Capabilities:
    platform: str
    implementation: str
    python_version: str
    linux_packet_api: bool


@dataclass(frozen=True, slots=True)
class CleanupFailure:
    primary_status: Status
    reason: str


@dataclass(frozen=True, slots=True)
class OperationResult:
    status: Status
    mode: Mode | None
    origin: Origin
    phase: Phase
    reason: str
    detail: EtherCATFrame | ExchangeEvidence | Capabilities | None = None
    cleanup: CleanupFailure | None = None


@dataclass(slots=True)
class _Progress:
    phase: Phase = Phase.INITIALIZE
    delivery: Delivery = Delivery.NOT_SENT
    events: int = 0
    last_assessment: EventAssessment | None = None


def validate_timeout(seconds: float) -> float:
    if type(seconds) not in (float, int) or not MIN_TIMEOUT <= seconds <= MAX_TIMEOUT:
        raise UsageError("timeout must be finite and between 0.001 and 10 seconds")
    return float(seconds)


def _receive_exchange(
    pending: PendingExchange, transport: Transport, clock: Callable[[], int], progress: _Progress,
) -> tuple[Status, str]:
    """Update progress while classifying events within the shared deadline and event budget."""
    while clock() < pending.deadline_ns and progress.events < MAX_EVENTS:
        try:
            event = transport.receive(pending.deadline_ns)
        except DeadlineExpired:
            event = None
        observed_at = clock()
        if event is None:
            if observed_at < pending.deadline_ns:
                return Status.INDETERMINATE, "transport indicated expiry before the deadline"
            break
        progress.events += 1
        assessment = assess_event(event, pending, observed_at)
        if assessment.status is None:
            continue
        progress.last_assessment = assessment
        if assessment.status is not Status.UNCORRELATED:
            progress.phase = Phase.CORRELATE
            return assessment.status, assessment.reason

    if clock() < pending.deadline_ns:
        return Status.INDETERMINATE, "event budget exhausted before the deadline"
    if progress.last_assessment is not None:
        return Status.UNCORRELATED, progress.last_assessment.reason + ". Deadline reached."
    return Status.TIMEOUT, "deadline reached without a candidate return"


def _short_message(message: str, limit: int = 240) -> str:
    text = "".join(c if " " <= c <= "~" else "?" for c in message[:limit])
    return text if len(message) <= limit else text[:-3] + "..."


def _failure_text(exc: BaseException) -> str:
    """Render a bounded diagnostic even if the exception's message fails to render."""
    try:
        message = str(exc)
    except Exception:
        # A diagnostic must not replace the failure it describes.
        message = "<message unavailable>"
    return _short_message(f"{type(exc).__name__}: {message}").rstrip(": ")


def run_exchange(
    profile: ReadProfile, context: ExchangeContext | _NativeDiagnosticContext,
    transport: Transport, clock: Callable[[], int],
    timeout: float = DEFAULT_TIMEOUT,
) -> OperationResult:
    """Own one transport attempt and use a single monotonic deadline through receipt.

    Validate the context before taking ownership. Close the transport after the
    attempt and retain cleanup evidence alongside the primary result.
    """
    budget_ns = round(validate_timeout(timeout) * NS_PER_SECOND)
    origin = transport.origin
    native = origin in (Origin.NATIVE_LINUX, Origin.NATIVE_TEST)
    if native:
        if (not isinstance(transport, _LinuxPacketTransport) or not isinstance(context, _NativeDiagnosticContext)
                or profile is not ReadProfile.APRD):
            raise UsageError("native diagnosis requires the APRD profile and a reference context")
        transport._check_reference(context, clock)
    elif isinstance(context, _NativeDiagnosticContext):
        raise UsageError("native reference context requires the Linux packet transport")
    elif not isinstance(context, ExchangeContext):
        raise UsageError("synthetic exchange requires an ExchangeContext")
    elif isinstance(transport, MemoryTransport) and clock is not transport._clock:
        raise UsageError("client and memory transport must share the same clock")
    mode = Mode.DIAGNOSE if native else Mode.SIMULATE
    request = encode_request(profile)
    started_at = clock()
    deadline = started_at + budget_ns
    progress = _Progress()
    cleanup_error = None
    unexpected = None
    try:
        transport.open(deadline)
        sent_at = clock()
        if sent_at >= deadline:
            raise DeadlineExpired("deadline reached during initialization")
        progress.phase = Phase.SEND
        progress.delivery = Delivery.UNCERTAIN
        transport.send(request, deadline)
        progress.delivery = Delivery.ACCEPTED
        progress.phase = Phase.RECEIVE
        pending = PendingExchange(profile, context, sent_at, deadline)
        status, reason = _receive_exchange(pending, transport, clock, progress)
    except KeyboardInterrupt as exc:
        if isinstance(exc, _InterruptedBeforeSend):
            progress.delivery = Delivery.NOT_SENT
        status, reason = Status.INTERRUPTED, "exchange interrupted by user"
    except DeadlineExpired as exc:
        if progress.phase is Phase.SEND:
            progress.delivery = Delivery.NOT_SENT
        status, reason = Status.TIMEOUT, str(exc)
    except DeliveryUncertain as exc:
        status, reason = Status.INDETERMINATE, _failure_text(exc)
    except _UnsupportedTransport as exc:
        status, reason = Status.UNSUPPORTED, str(exc)
    except TransportError as exc:
        if progress.phase is Phase.SEND:
            progress.delivery = Delivery.NOT_SENT
        status = Status.INDETERMINATE if progress.delivery is Delivery.ACCEPTED else Status.LOCAL_ERROR
        reason = _failure_text(exc)
    except OSError as exc:
        status = Status.LOCAL_ERROR if progress.delivery is Delivery.NOT_SENT else Status.INDETERMINATE
        reason = _failure_text(exc)
    except BaseException as exc:
        unexpected = exc
        raise
    finally:
        try:
            transport.close()
        except (Exception, KeyboardInterrupt) as exc:
            cleanup_error = exc
            if unexpected is not None:
                unexpected.add_note("Cleanup failed: " + _failure_text(exc))

    evidence = ExchangeEvidence(
        profile, progress.delivery, clock() - started_at, progress.events,
        _READ_SPECS[profile].expected_wkc, progress.last_assessment,
    )
    result = OperationResult(status, mode, origin, progress.phase, reason, evidence)
    if cleanup_error is not None:
        cleanup = CleanupFailure(status, _failure_text(cleanup_error))
        if status is Status.OK:
            status = Status.INTERRUPTED if isinstance(cleanup_error, KeyboardInterrupt) else Status.LOCAL_ERROR
            return replace(
                result, status=status, phase=Phase.CLOSE, reason="transport cleanup failed after a matching return",
                cleanup=cleanup,
            )
        return replace(result, cleanup=cleanup)
    return result


# Offline operations
def simulate(
    scenario: Scenario, timeout: float = DEFAULT_TIMEOUT, profile: ReadProfile = ReadProfile.FPRD,
) -> OperationResult:
    if not isinstance(scenario, Scenario) or not isinstance(profile, ReadProfile):
        raise UsageError("simulation requires a known scenario and read profile")
    timeout = validate_timeout(timeout)
    clock = VirtualClock()
    context = ExchangeContext("memory")
    meta = (500_000, context.interface, context.exchange_id, Direction.INBOUND)
    if scenario is Scenario.TIMEOUT:
        events = ()
    elif scenario is Scenario.REJECTED:
        events = (RejectionEvent(*meta, profile),)
    else:
        response = _RETURN_FIXTURES[profile]
        if scenario is Scenario.UNCORRELATED:
            # Same Idx and exchange context, with a different register offset.
            response = response[:20] + bytes([response[20] ^ 1]) + response[21:]
        elif scenario is Scenario.WKC_MISMATCH:
            response = response[:-2] + b"\x00\x00"
        elif scenario is Scenario.INVALID:
            response = response[:-1]
        events = (FrameEvent(*meta, response),)
    return run_exchange(profile, context, MemoryTransport(clock, events), clock, timeout)


_HEX_RE = re.compile(r"[0-9A-Fa-f]+")
_SECONDS_RE = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
_RESULT_OUTPUT_BUDGET = 12 * 1024
_USAGE_OUTPUT_BUDGET = MAX_OUTPUT_BYTES - _RESULT_OUTPUT_BUDGET - 2 * 1024
_MAX_CLI_ARGUMENTS = 16
_MAX_CLI_TOKEN = 2 * MAX_FRAME_BYTES + len("--hex=")


def parse_hex(text: str) -> bytes:
    if type(text) is not str or not 1 <= len(text) <= 2 * MAX_FRAME_BYTES:
        raise UsageError("hex input must contain 2..3028 ASCII hexadecimal characters")
    if len(text) % 2 or _HEX_RE.fullmatch(text) is None:
        raise UsageError("hex input must contain an even number of ASCII hexadecimal characters without separators")
    return bytes.fromhex(text)


def _parse_timeout(text: str) -> float:
    if _SECONDS_RE.fullmatch(text) is None:
        raise UsageError("timeout requires decimal seconds")
    try:
        seconds = Decimal(text)
    except InvalidOperation:
        raise UsageError("timeout must be finite and between 0.001 and 10 seconds") from None
    if not Decimal(str(MIN_TIMEOUT)) <= seconds <= Decimal(str(MAX_TIMEOUT)):
        raise UsageError("timeout must be finite and between 0.001 and 10 seconds")
    return float(seconds)


def inspect_frame(data: bytes, padding: Padding = Padding.STRIPPED) -> OperationResult:
    try:
        frame = decode_frame(data, padding)
    except InvalidFrame as exc:
        return OperationResult(Status.PROTOCOL_ERROR, Mode.INSPECT, Origin.OFFLINE_INPUT, Phase.INSPECT, str(exc))
    except UnsupportedFrame as exc:
        return OperationResult(Status.UNSUPPORTED, Mode.INSPECT, Origin.OFFLINE_INPUT, Phase.INSPECT, str(exc))
    return OperationResult(
        Status.OK, Mode.INSPECT, Origin.OFFLINE_INPUT, Phase.INSPECT, "structural inspection completed", frame,
    )


def report_capabilities(platform: str, symbols: object) -> Capabilities:
    version = ".".join(str(part) for part in sys.version_info[:3])
    return Capabilities(platform, sys.implementation.name, version, supports_linux_packet(platform, symbols))


# CLI and presentation
class _BufferedWriteError(OSError):
    def __init__(self, stream: TextIO, failure: BufferError) -> None:
        super().__init__(_failure_text(failure))
        self.stream = stream


def _close_failed_stream(stream: TextIO) -> None:
    # Avoid a second flush when the executable exits with a failed pipe or console.
    if __name__ == "__main__" and (stream is sys.__stdout__ or stream is sys.__stderr__):
        try:
            stream.close()
        except (OSError, ValueError, BufferError):
            pass


def _write_text(stream: TextIO | None, message: str) -> None:
    """Write and flush text through the active stream, if available."""
    if stream is None:
        raise OSError("standard text stream is unavailable")
    try:
        if stream.write(message) != len(message):
            raise OSError("text stream accepted only part of the output")
        stream.flush()
    except (OSError, ValueError, BufferError) as exc:
        _close_failed_stream(stream)
        if isinstance(exc, BufferError):
            raise _BufferedWriteError(stream, exc) from exc
        if isinstance(exc, ValueError) and not isinstance(exc, UnicodeError):
            # TextIOBase raises ValueError for operations on a closed stream.
            raise OSError(str(exc)) from exc
        raise


def _write_bounded(stream: TextIO | None, message: str, budget: int) -> None:
    encoded = message.encode("utf-8", errors="replace")
    if len(encoded) > budget:
        marker = b"\n[output limited]\n"
        message = (encoded[:budget - len(marker)] + marker).decode("utf-8", errors="ignore")
    _write_text(stream, message)


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise UsageError(_short_message(message))

    def print_help(self, file: TextIO | None = None) -> None:
        _write_bounded(sys.stdout if file is None else file, self.format_help(), _RESULT_OUTPUT_BUDGET)


class _StoreOnce(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None) -> None:
        if getattr(namespace, self.dest) is not None:
            raise UsageError(f"{self.option_strings[-1]} may be specified only once")
        setattr(namespace, self.dest, values)


def _make_parser() -> _ArgumentParser:
    # CPython 3.14's formatter needs its own color option because it probes
    # stdout during construction, before argparse applies the parser setting.
    color_options = {"color": False} if sys.version_info >= (3, 14) else {}

    def formatter(prog: str) -> argparse.HelpFormatter:
        # Preserve terminal wrapping when the original stdout can be queried.
        try:
            if not getattr(getattr(sys, "__stdout__", None), "closed", False):
                return argparse.RawDescriptionHelpFormatter(prog, **color_options)
        except (OSError, ValueError):
            pass
        return argparse.RawDescriptionHelpFormatter(prog, width=78, **color_options)

    parser = _ArgumentParser(
        prog="ethercat_master.py", allow_abbrev=False, formatter_class=formatter,
        description="Inspect untagged EtherCAT Type 1 frames offline or run a deterministic in-memory exchange.",
        epilog=(
            "Examples\n"
            "  python ethercat_master.py -c inspect --hex ffffffffffff02000000000188a40e100427341200010200000000000000\n"
            "  python ethercat_master.py -c simulate --scenario success --debug\n"
            "  python ethercat_master.py -c capabilities\n\n"
            "Exit codes\n"
            "  0 OK, 2 usage, 3 unsupported, 4 local error, 5 protocol error,\n"
            "            6 timeout, 7 uncorrelated, 8 indeterminate, 9 rejected, 130 interrupted.\n"
            "Diagnose is disabled pending physical interoperability validation. The internal\n"
            "backend is Linux-only. Future use requires a dedicated interface, an authorized\n"
            "isolated single-ESC bench and existing packet socket permissions.\n"
            "Diagnose validates --interface and --confirm-bench before checking availability."
        ),
        **color_options,
    )
    parser.add_argument("-c", "--command", action=_StoreOnce, choices=tuple(Mode), help="Select a mode.")
    parser.add_argument("--hex", dest="frame_hex", action=_StoreOnce, help="Inspect continuous ASCII hex, without FCS.")
    parser.add_argument(
        "--padding", action=_StoreOnce, choices=tuple(Padding), help="Inspect padding convention, default stripped.",
    )
    parser.add_argument(
        "--scenario", action=_StoreOnce, choices=tuple(Scenario), help="Select the synthetic FPRD fixture for simulation.",
    )
    parser.add_argument(
        "--timeout", action=_StoreOnce, metavar="SECONDS", help="Simulation timeout from 0.001 to 10 seconds, default 1.",
    )
    parser.add_argument("--interface", action=_StoreOnce, help="Dedicated interface for the diagnose candidate.")
    parser.add_argument("--confirm-bench", action="store_true", help="Confirm the authorized bench for diagnose.")
    parser.add_argument("--debug", action="store_true", help="Print classification and logical timing details to stderr.")
    return parser


_MODE_ARGUMENTS = {
    Mode.INSPECT: ("frame_hex", "padding"),
    Mode.SIMULATE: ("scenario", "timeout"),
    Mode.CAPABILITIES: (),
    Mode.DIAGNOSE: ("interface", "confirm_bench"),
}


def _dispatch(args: argparse.Namespace, mode: Mode) -> OperationResult:
    for owner, fields in _MODE_ARGUMENTS.items():
        if owner is mode:
            continue
        for name in fields:
            value = getattr(args, name)
            if value is not None and value is not False:
                option = "hex" if name == "frame_hex" else name.replace("_", "-")
                raise UsageError(f"--{option} belongs to {owner}")

    if mode is Mode.INSPECT:
        if args.frame_hex is None:
            raise UsageError("inspect requires --hex")
        return inspect_frame(parse_hex(args.frame_hex), Padding(args.padding or Padding.STRIPPED))
    if mode is Mode.SIMULATE:
        if args.scenario is None:
            raise UsageError("simulate requires --scenario")
        timeout = DEFAULT_TIMEOUT if args.timeout is None else _parse_timeout(args.timeout)
        return simulate(Scenario(args.scenario), timeout)
    if mode is Mode.CAPABILITIES:
        return OperationResult(
            Status.OK, mode, Origin.LOCAL, Phase.REPORT, "local capability report",
            report_capabilities(sys.platform, socket),
        )
    if args.interface is None or not args.confirm_bench:
        raise UsageError(
            "diagnose requires --interface and --confirm-bench. "
            "Native diagnostics are disabled pending physical interoperability validation."
        )
    _validate_interface(args.interface)
    # Public dispatch stops before constructing a native transport.
    return OperationResult(
        Status.UNSUPPORTED, mode, Origin.LOCAL, Phase.PRECHECK,
        "native diagnostics are disabled pending physical interoperability validation",
    )


def _format_datagram(datagram: Datagram) -> str:
    if 0x0A <= datagram.command <= 0x0C:
        address = f"logical=0x{int.from_bytes(datagram.address, 'little'):08x}"
    elif 0 < datagram.command < len(_COMMAND_NAMES):
        adp, ado = _PHYSICAL_ADDRESS.unpack(datagram.address)
        address = f"ADP=0x{adp:04x} ADO=0x{ado:04x}"
    else:
        address = f"address-bytes={datagram.address.hex()}"
    return (
        f"  byte {datagram.offset}: {datagram.command_name} (0x{datagram.command:02x}) "
        f"Idx=0x{datagram.index:02x} {address} Len={len(datagram.payload)} "
        f"C={int(datagram.circulating)} M={int(datagram.more)} IRQ=0x{datagram.irq:04x} WKC={datagram.wkc}"
    )


def format_result(result: OperationResult) -> str:
    lines = [
        f"{result.status.name} ({result.status.value}) mode={result.mode or '-'} source={result.origin} phase={result.phase}",
    ]
    detail = result.detail
    if isinstance(detail, EtherCATFrame):
        lines += [
            f"Ethernet II dst={detail.destination.hex(':')} src={detail.source.hex(':')} EtherType=0x{ETHERCAT_ETHERTYPE:04x}",
            f"EtherCAT Type 1 chain={detail.chain_length} bytes datagrams={len(detail.datagrams)} "
            f"padding={detail.padding_convention} ({len(detail.padding)} bytes)",
        ]
        lines.extend(_format_datagram(datagram) for datagram in detail.datagrams)
    elif isinstance(detail, ExchangeEvidence):
        label = "fixture" if result.mode is Mode.SIMULATE else "diagnostic"
        lines.append(f"{detail.profile} {label} delivery={detail.delivery} events={detail.events}")
        assessment = detail.assessment
        if assessment is not None:
            structure = {True: "valid", False: "invalid", None: "unverified"}[assessment.structurally_valid]
            lines.append(f"Return structure={structure} attribution={assessment.attribution}")
        observed = assessment.wkc if assessment is not None else None
        lines.append(f"WKC expected={detail.expected_wkc} observed={observed if observed is not None else 'unavailable'}")
        if assessment is not None and assessment.esc_type is not None:
            lines.append(f"ESC Type observed=0x{assessment.esc_type:02x}")
    elif isinstance(detail, Capabilities):
        symbols = "present" if detail.linux_packet_api else "absent on this runtime"
        lines += [
            f"Platform={_short_message(detail.platform, 60)} Python={detail.implementation} {detail.python_version}",
            "Offline modes: inspect, simulate (FPRD), capabilities",
            "Input profile: untagged Ethernet II Type 1, no FCS, stripped or retained padding",
            f"Limits: {MAX_FRAME_BYTES} bytes, {MAX_DATAGRAMS} datagrams, {MAX_EVENTS} events, {MAX_OUTPUT_BYTES} UTF-8 output bytes",
            "Native backend: implemented for Linux with documented AF_PACKET/SOCK_RAW",
            f"Linux packet API symbols {symbols}",
            "Native backend validation: offline exercises with a substituted system boundary",
            "Native diagnose: disabled pending physical interoperability validation.",
            "Physical interoperability: pending",
        ]
    return "\n".join(lines) + "\n"


class _DiagnosticHandler(logging.StreamHandler):
    def emit(self, record: logging.LogRecord) -> None:
        _write_text(self.stream, self.format(record) + self.terminator)


def _present(result: OperationResult, debug: bool, usage: str = "") -> None:
    """Emit bounded CLI output and use a private handler for stderr diagnostics."""
    if usage:
        _write_bounded(sys.stderr, usage, _USAGE_OUTPUT_BUDGET)
    if result.status is not Status.USAGE_ERROR:
        _write_bounded(sys.stdout, format_result(result), _RESULT_OUTPUT_BUDGET)

    # At most three bounded log lines fit the stderr allowance left after usage.
    handler = _DiagnosticHandler(sys.stderr)

    def log(level: int, message: str, *args: object) -> None:
        # CLI diagnostics have their own verbosity and do not use the host's logger.
        handler.handle(logging.LogRecord("ethercat_master", level, "", 0, message, args, None))

    try:
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        if result.status in (Status.USAGE_ERROR, Status.LOCAL_ERROR, Status.PROTOCOL_ERROR):
            level = logging.ERROR
        else:
            level = logging.INFO if result.status is Status.OK else logging.WARNING
        if debug or level != logging.INFO:
            log(level, "%s [%s] %s", result.status.name, result.mode or "-", _short_message(result.reason))
        if result.cleanup is not None:
            log(logging.ERROR, "cleanup after %s: %s", result.cleanup.primary_status.name, _short_message(result.cleanup.reason))
        if debug:
            if isinstance(result.detail, ExchangeEvidence):
                log(logging.DEBUG, "phase=%s elapsed_ns=%d events=%d", result.phase, result.detail.elapsed_ns, result.detail.events)
            else:
                log(logging.DEBUG, "phase=%s source=%s", result.phase, result.origin)
    finally:
        handler.close()


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI against the host's current streams and return a public exit code."""
    try:
        parser = _make_parser()
        mode = None
        debug = False
        try:
            arguments = sys.argv[1:] if argv is None else argv
            if len(arguments) > _MAX_CLI_ARGUMENTS or any(
                type(arg) is not str or len(arg) > _MAX_CLI_TOKEN for arg in arguments
            ):
                raise UsageError("argument count or length exceeds the CLI limits")
            try:
                args = parser.parse_args(arguments)
            except SystemExit as exc:
                # argparse's help action has already printed the bounded help text.
                return int(exc.code)
            debug = args.debug
            if args.command is None:
                raise UsageError("select a mode with -c or --command")
            mode = Mode(args.command)
            result = _dispatch(args, mode)
        except UsageError as exc:
            result = OperationResult(Status.USAGE_ERROR, mode, Origin.LOCAL, Phase.VALIDATE, str(exc))
        except KeyboardInterrupt:
            phase = Phase.VALIDATE if mode is None else Phase.DISPATCH
            result = OperationResult(Status.INTERRUPTED, mode, Origin.LOCAL, phase, "interrupted by user")
        _present(result, debug, parser.format_usage() if result.status is Status.USAGE_ERROR else "")
        return result.status.value
    except KeyboardInterrupt:
        return Status.INTERRUPTED.value
    except (OSError, UnicodeError) as exc:
        stream = sys.stderr
        if stream is None:
            return Status.LOCAL_ERROR.value
        try:
            if isinstance(exc, _BufferedWriteError):
                if exc.stream is stream:
                    return Status.LOCAL_ERROR.value
                reason = str(exc)
            else:
                reason = _failure_text(exc)
            _write_bounded(stream, f"ERROR LOCAL_ERROR {reason}\n", 512)
        except (OSError, UnicodeError, ValueError):
            # The diagnostic stream can also be unavailable.
            pass
        except KeyboardInterrupt:
            return Status.INTERRUPTED.value
        return Status.LOCAL_ERROR.value


if __name__ == "__main__":
    raise SystemExit(main())
