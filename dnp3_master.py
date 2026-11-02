#!/usr/bin/env python3
"""Independent standard-library DNP3/TCP master for an explicit protocol subset.

Reference-validated FT3, transport, application and object formats; no claim of
complete IEEE 1815 coverage. See --help for the implemented operations.
"""
import argparse
from datetime import datetime, timezone
import logging
import math
import os
import socket
import struct
import sys
import time


logger = logging.getLogger('DNP3MasterCLI')
MAX_APPLICATION = 65535
MAX_FRAGMENTS = 256
MAX_POINTS = 10000
IIN1 = {1: 'ALL_STATIONS', 2: 'CLASS1_EVENTS', 4: 'CLASS2_EVENTS', 8: 'CLASS3_EVENTS',
        16: 'NEED_TIME', 32: 'LOCAL_CONTROL', 64: 'DEVICE_TROUBLE', 128: 'DEVICE_RESTART'}
IIN2 = {1: 'FUNCTION_NOT_SUPPORTED', 2: 'OBJECT_UNKNOWN', 4: 'PARAMETER_ERROR',
        8: 'EVENT_BUFFER_OVERFLOW', 16: 'ALREADY_EXECUTING', 32: 'CONFIG_CORRUPT'}
COMMAND_STATUS = {0: 'SUCCESS', 1: 'TIMEOUT', 2: 'NO_SELECT', 3: 'FORMAT_ERROR',
                  4: 'NOT_SUPPORTED', 5: 'ALREADY_ACTIVE', 6: 'HARDWARE_ERROR',
                  7: 'LOCAL', 8: 'TOO_MANY_OPS', 9: 'NOT_AUTHORIZED'}


class ProtocolError(Exception):
    pass


class RejectedError(ProtocolError):
    pass


class IndeterminateError(ProtocolError):
    pass


def crc16(data):
    """CRC-16/DNP, reflected 0x3d65, init 0, final complement."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA6BC if crc & 1 else 0)
    return crc ^ 0xFFFF


def build_link(data, destination, source, control=0xC4):
    if not 0 <= destination <= 65519 or not 0 <= source <= 65519:
        raise ValueError('Unicast link addresses must be in 0..65519')
    if len(data) > 250:
        raise ValueError('FT3 user data exceeds 250 bytes')
    header = struct.pack('<2sBBHH', b'\x05\x64', len(data) + 5, control, destination, source)
    frame = header + struct.pack('<H', crc16(header))
    for offset in range(0, len(data), 16):
        block = data[offset:offset+16]
        frame += block + struct.pack('<H', crc16(block))
    return frame


def parse_link(frame):
    if len(frame) < 10 or frame[:2] != b'\x05\x64' or frame[2] < 5:
        raise ProtocolError('Invalid FT3 header/length')
    amount = frame[2] - 5
    total = 10 + amount + 2 * ((amount + 15) // 16)
    if len(frame) != total or crc16(frame[:8]) != int.from_bytes(frame[8:10], 'little'):
        raise ProtocolError('FT3 length or header CRC mismatch')
    control, destination, source = struct.unpack('<BHH', frame[3:8])
    function = control & 15
    primary = bool(control & 0x40)
    if primary:
        if function not in (0, 2, 3, 4, 9) or bool(control & 0x10) != (function in (2, 3)):
            raise ProtocolError('Invalid primary function/FCV')
    elif function not in (0, 1, 11, 15) or control & 0x20:
        raise ProtocolError('Invalid secondary function/reserved bit')
    if bool(amount) != (primary and function in (3, 4)):
        raise ProtocolError('Link function and user data disagree')
    result, offset = bytearray(), 10
    while len(result) < amount:
        count = min(16, amount - len(result))
        block = frame[offset:offset+count]
        if crc16(block) != int.from_bytes(frame[offset+count:offset+count+2], 'little'):
            raise ProtocolError('FT3 data CRC mismatch')
        result.extend(block)
        offset += count + 2
    return control, destination, source, bytes(result)


def iin_names(iin):
    result = [name for mask, name in IIN1.items() if iin[0] & mask]
    result += [name for mask, name in IIN2.items() if iin[1] & mask]
    return '|'.join(result) if result else 'CLEAR'


# Each numeric layout is flags-present, struct format, absolute-time-present.
NUMERIC = {
    (20, 1): (True, 'I', False), (20, 2): (True, 'H', False),
    (20, 5): (False, 'I', False), (20, 6): (False, 'H', False),
    (22, 1): (True, 'I', False), (22, 2): (True, 'H', False),
    (22, 5): (True, 'I', True), (22, 6): (True, 'H', True),
    (30, 1): (True, 'i', False), (30, 2): (True, 'h', False),
    (30, 3): (False, 'i', False), (30, 4): (False, 'h', False),
    (30, 5): (True, 'f', False), (30, 6): (True, 'd', False),
    (40, 1): (True, 'i', False), (40, 2): (True, 'h', False),
    (40, 3): (True, 'f', False), (40, 4): (True, 'd', False),
}
for _group in (32, 42):
    for _variation, _format, _time in ((1, 'i', False), (2, 'h', False), (3, 'i', True),
                                      (4, 'h', True), (5, 'f', False), (6, 'd', False),
                                      (7, 'f', True), (8, 'd', True)):
        NUMERIC[_group, _variation] = (True, _format, _time)
BINARY = {(1, 2): (False, False), (2, 1): (False, False), (2, 2): (False, True),
          (3, 2): (True, False), (4, 1): (True, False), (4, 2): (True, True),
          (10, 2): (False, False), (11, 1): (False, False), (11, 2): (False, True)}
PACKED = {(1, 1): 1, (3, 1): 2, (10, 1): 1}
ANALOG_FORMATS = {1: 'i', 2: 'h', 3: 'f', 4: 'd'}


def supported_read(group, variation):
    return ((group, variation) in NUMERIC or (group, variation) in BINARY
            or (group, variation) in PACKED
            or (group in {g for g, _ in NUMERIC} | {g for g, _ in BINARY} and variation == 0))


def parse_objects(data):
    """Decode bounded, known object variations; unknown formats never guessed."""
    offset, objects, headers = 0, [], 0

    def take(count):
        nonlocal offset
        if count < 0 or offset + count > len(data):
            raise ProtocolError('Truncated DNP3 object/header')
        part = data[offset:offset+count]
        offset += count
        return part

    while offset < len(data):
        headers += 1
        if headers > 256:
            raise ProtocolError('Object header limit exceeded')
        group, variation, qualifier = take(3)
        prefix, range_code = qualifier >> 4, qualifier & 15
        if qualifier & 0x80 or prefix not in (0, 1, 2):
            raise ProtocolError(f'Unsupported qualifier 0x{qualifier:02x}')
        if range_code in (0, 1) and prefix == 0:
            width = range_code + 1
            start = int.from_bytes(take(width), 'little')
            stop = int.from_bytes(take(width), 'little')
            if stop < start:
                raise ProtocolError('Descending object range')
            count, indexes = stop - start + 1, range(start, stop + 1)
        elif range_code in (7, 8):
            width = range_code - 6
            count = int.from_bytes(take(width), 'little')
            indexes = [None] * min(count, MAX_POINTS + 1)
        else:
            raise ProtocolError(f'Unsupported response qualifier 0x{qualifier:02x}')
        if count + len(objects) > MAX_POINTS:
            raise ProtocolError('Point count limit exceeded')
        key = group, variation
        if key in PACKED:
            if prefix or range_code not in (0, 1):
                raise ProtocolError('Packed data requires an unprefixed index range')
            bits = PACKED[key]
            packed = take((count * bits + 7) // 8)
            for i, index in enumerate(indexes):
                value = (packed[(i * bits) // 8] >> ((i * bits) % 8)) & ((1 << bits) - 1)
                objects.append(dict(group=group, variation=variation, index=index, value=value,
                                    flags=None, timestamp=None, raw=b'', qualifier=qualifier))
            continue
        if key in BINARY:
            size = 1 + (6 if BINARY[key][1] else 0)
        elif key in NUMERIC:
            flags, fmt, timestamp = NUMERIC[key]
            size = int(flags) + struct.calcsize('<' + fmt) + (6 if timestamp else 0)
        elif key == (12, 1):
            size = 11
        elif group == 41 and variation in ANALOG_FORMATS:
            size = struct.calcsize('<' + ANALOG_FORMATS[variation]) + 1
        elif group == 50 and variation in (1, 3):
            size = 6
        elif group == 52 and variation in (1, 2):
            size = 2
        else:
            raise ProtocolError(f'Unsupported object G{group}V{variation}; no values decoded')
        for default_index in indexes:
            index = int.from_bytes(take(prefix), 'little') if prefix else default_index
            raw = take(size)
            point = dict(group=group, variation=variation, index=index, flags=None,
                         timestamp=None, raw=raw, qualifier=qualifier)
            if key in BINARY:
                double, has_time = BINARY[key]
                point['flags'] = raw[0] & (0x3f if double else 0x7f)
                point['value'] = raw[0] >> (6 if double else 7)
                if has_time: point['timestamp'] = int.from_bytes(raw[-6:], 'little')
            elif key in NUMERIC:
                flags, fmt, has_time = NUMERIC[key]
                start = int(flags)
                point['flags'] = raw[0] if flags else None
                point['value'] = struct.unpack_from('<' + fmt, raw, start)[0]
                if has_time: point['timestamp'] = int.from_bytes(raw[-6:], 'little')
            elif key == (12, 1):
                code, count_value, on, off, status = struct.unpack('<BBIIB', raw)
                point.update(value=code, count=count_value, on_time=on, off_time=off, status=status)
            elif group == 41:
                point.update(value=struct.unpack('<' + ANALOG_FORMATS[variation], raw[:-1])[0], status=raw[-1])
            else:
                point['value'] = int.from_bytes(raw, 'little')
            objects.append(point)
    return objects


def class_headers(classes):
    return b''.join(bytes((60, item + 1, 6)) for item in classes)


class DNP3Client:
    def __init__(self, host, port=20000, master_address=1, outstation_address=1024,
                 timeout=3.0, retries=2):
        self.host, self.port = host, port
        self.master, self.outstation = master_address, outstation_address
        self.timeout, self.retries, self.sock = timeout, retries, None
        self._reset_state()

    def _reset_state(self):
        self.buffer = bytearray()
        self.transport_tx, self.application_seq = 0, 0
        self.transport_rx = None
        self.last_transport = None
        self.rx_link_ready, self.rx_fcb = False, True
        self.last_unsolicited = None
        self.unsolicited_pending = None
        self.events = []
        self.last_response_fragments = 0
        self._source_states = {}

    def connect(self):
        for attempt in range(self.retries + 1):
            try:
                self.sock = socket.create_connection((self.host, self.port), self.timeout)
                self._reset_state()
                logger.info(f'[TCP_CONNECTED] {self.host}:{self.port}')
                return True
            except OSError as error:
                self.close()
                if attempt == self.retries:
                    logger.error(f'[NOT_SENT] TCP connection failed: {error}')
                    return False
                time.sleep(min(.25 * (attempt + 1), 1))
        return False

    def close(self):
        if self.sock:
            try: self.sock.close()
            finally: self.sock = None

    def _send_link(self, data=b'', control=0xC4, destination=None):
        if not self.sock: raise ConnectionError('No TCP session')
        frame = build_link(data, self.outstation if destination is None else destination, self.master, control)
        logger.debug('TX: %s', frame.hex().upper())
        self.sock.sendall(frame)

    def _send_application(self, application):
        if not 2 <= len(application) <= MAX_APPLICATION:
            raise ValueError('Application payload size outside supported range')
        for offset in range(0, len(application), 249):
            chunk = application[offset:offset+249]
            header = self.transport_tx | (0x40 if offset == 0 else 0) | (0x80 if offset + len(chunk) == len(application) else 0)
            self._send_link(bytes([header]) + chunk)
            self.transport_tx = (self.transport_tx + 1) & 63

    def _recv_link(self, deadline):
        while True:
            if len(self.buffer) >= 3:
                if self.buffer[:2] != b'\x05\x64' or self.buffer[2] < 5:
                    raise ProtocolError('Invalid FT3 stream start/length')
                count = self.buffer[2] - 5
                length = 10 + count + 2 * ((count + 15) // 16)
                if len(self.buffer) >= length:
                    frame = bytes(self.buffer[:length])
                    del self.buffer[:length]
                    logger.debug('RX: %s', frame.hex().upper())
                    return parse_link(frame)
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError('DNP3 receive deadline expired')
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(4096)
            if not chunk: raise ConnectionError('EOF in DNP3 stream')
            self.buffer.extend(chunk)
            if len(self.buffer) > 8192:
                raise ProtocolError('TCP accumulation limit exceeded')

    def _handle_link(self, frame, expected_source=None):
        control, destination, source, data = frame
        if destination != self.master or source != (self.outstation if expected_source is None else expected_source):
            logger.debug('Ignoring unrelated link addresses %s -> %s', source, destination)
            return None
        if control & 0x80:
            raise ProtocolError('Received master-direction frame from outstation')
        function = control & 15
        if not control & 0x40:
            if function in (1, 15) or control & 0x10:
                raise RejectedError('Link NACK/not-supported/busy')
            return ('status' if function == 11 else 'ack'), b''
        if function == 9:
            self._send_link(control=0x8b, destination=source)
        elif function == 0:
            self.rx_link_ready, self.rx_fcb = True, True
            self._send_link(control=0x80, destination=source)
        elif function in (2, 3):
            if not self.rx_link_ready:
                self._send_link(control=0x81, destination=source)
                raise ProtocolError('Confirmed link data before RESET_LINK_STATES')
            self._send_link(control=0x80, destination=source)
            if bool(control & 0x20) != self.rx_fcb:
                return None  # Duplicate: re-ACK, never re-deliver application data.
            self.rx_fcb = not self.rx_fcb
            if function == 3: return 'data', data
        elif function == 4:
            return 'data', data
        return None

    def _switch_source(self, address):
        # Transport, link FCB and unsolicited/application sequences belong to a
        # link association, even when one TCP peer serves multiple addresses.
        if address == self.outstation:
            return
        defaults = dict(transport_tx=0, application_seq=0, transport_rx=None,
                        last_transport=None, rx_link_ready=False, rx_fcb=True,
                        last_unsolicited=None, unsolicited_pending=None,
                        last_response_fragments=0)
        self._source_states[self.outstation] = {name: getattr(self, name) for name in defaults}
        state = self._source_states.pop(address, defaults)
        for name, value in state.items():
            setattr(self, name, value)
        self.outstation = address

    def link_status(self, address=None):
        address = self.outstation if address is None else address
        previous = self.outstation
        self._switch_source(address)
        try:
            self._send_link(control=0xC9, destination=address)
            deadline = time.monotonic() + self.timeout
            for _ in range(1024):
                result = self._handle_link(self._recv_link(deadline), expected_source=address)
                if result and result[0] == 'status':
                    return True
                if result and result[0] == 'data':
                    fragment = self._transport_data(result[1])
                    if fragment is not None and fragment['unsolicited']:
                        self.events.extend(self._unsolicited(fragment))
                        if len(self.events) > MAX_POINTS:
                            raise ProtocolError('Link-diagnostic event limit exceeded')
            raise ProtocolError('Link response frame limit exceeded')
        finally:
            self._switch_source(previous)

    def _recv_fragment(self, deadline):
        for _ in range(1024):
            handled = self._handle_link(self._recv_link(deadline))
            if not handled or handled[0] != 'data': continue
            fragment = self._transport_data(handled[1])
            if fragment is not None:
                return fragment
        raise ProtocolError('Transport frame limit exceeded')

    def _transport_data(self, payload):
        header, piece = payload[0], payload[1:]
        seq, first, final = header & 63, bool(header & 0x40), bool(header & 0x80)
        if self.last_transport == (header, piece):
            return None
        if first:
            if self.transport_rx is not None:
                self.transport_rx = None
                raise ProtocolError('Overlapping transport FIR')
            self.transport_rx = [bytearray(), seq, 0]
        if self.transport_rx is None or self.transport_rx[1] != seq:
            self.transport_rx = None
            raise ProtocolError('Missing/out-of-order transport segment')
        state = self.transport_rx
        state[0].extend(piece)
        state[1], state[2] = (seq + 1) & 63, state[2] + 1
        self.last_transport = header, piece
        if len(state[0]) > MAX_APPLICATION or state[2] > MAX_FRAGMENTS:
            self.transport_rx = None
            raise ProtocolError('Transport reassembly limit exceeded')
        if not final: return None
        application = bytes(state[0])
        self.transport_rx = None
        if len(application) < 4:
            raise ProtocolError('Truncated application response')
        control, function, first_iin, second_iin = application[:4]
        if function not in (129, 130) or bool(control & 0x10) != (function == 130):
            raise ProtocolError('Response function/UNS mismatch')
        return dict(seq=control & 15, first=bool(control & 0x80), final=bool(control & 0x40),
                    confirm=bool(control & 0x20), unsolicited=bool(control & 0x10),
                    iin=(first_iin, second_iin), data=application[4:], raw=application)

    def _confirm(self, fragment):
        control = 0xC0 | (0x10 if fragment['unsolicited'] else 0) | fragment['seq']
        self._send_application(bytes([control, 0]))

    def _unsolicited(self, fragment):
        if self.last_unsolicited == fragment['raw']:
            if fragment['confirm']: self._confirm(fragment)
            return []
        pending = self.unsolicited_pending
        if fragment['first']:
            if pending is not None: raise ProtocolError('Overlapping unsolicited FIR')
            pending = [fragment['seq'], [], 0]
            self.unsolicited_pending = pending
        if pending is None or pending[0] != fragment['seq']:
            self.unsolicited_pending = None
            raise ProtocolError('Unsolicited application fragment sequence mismatch')
        points = parse_objects(fragment['data'])
        for point in points:
            point['source'] = self.outstation
        pending[1].extend(points)
        pending[2] += 1
        if len(pending[1]) > MAX_POINTS or pending[2] > MAX_FRAGMENTS:
            raise ProtocolError('Unsolicited reassembly limit exceeded')
        if fragment['confirm']: self._confirm(fragment)
        self.last_unsolicited = fragment['raw']
        pending[0] = (fragment['seq'] + 1) & 15
        logger.info('[UNSOLICITED] IIN=%s', iin_names(fragment['iin']))
        if fragment['final']:
            self.unsolicited_pending = None
            return pending[1]
        return []

    def exchange(self, function, objects=b''):
        seq = self.application_seq
        # Advance even on ambiguous timeout; never reuse the old sequence immediately.
        self.application_seq = (seq + 1) & 15
        try:
            self._send_application(bytes([0xC0 | seq, function]) + objects)
            deadline = time.monotonic() + self.timeout
            expected, points, iin, last, count = seq, [], (0, 0), None, 0
            for _ in range(1024):
                fragment = self._recv_fragment(deadline)
                if fragment['unsolicited']:
                    self.events.extend(self._unsolicited(fragment))
                    if len(self.events) > MAX_POINTS: raise ProtocolError('Interleaved event limit exceeded')
                    continue
                if last == fragment['raw']:
                    if fragment['confirm']: self._confirm(fragment)
                    continue
                if fragment['seq'] != expected:
                    logger.debug('Ignoring unrelated application sequence %s', fragment['seq'])
                    continue
                if fragment['first'] != (count == 0):
                    raise ProtocolError('Invalid solicited application FIR')
                decoded = parse_objects(fragment['data'])
                if fragment['iin'][1] & 0x17:
                    if fragment['confirm']: self._confirm(fragment)
                    raise RejectedError('Application IIN: ' + iin_names(fragment['iin']))
                points.extend(decoded)
                count += 1
                if count > MAX_FRAGMENTS or len(points) > MAX_POINTS:
                    raise ProtocolError('Application reassembly limit exceeded')
                iin = (iin[0] | fragment['iin'][0], iin[1] | fragment['iin'][1])
                expected = (expected + 1) & 15
                self.application_seq = expected
                last = fragment['raw']
                if fragment['confirm']: self._confirm(fragment)
                if fragment['final']:
                    self.last_response_fragments = count
                    logger.info('[APPLICATION_RESPONSE] IIN=%s', iin_names(iin))
                    return points, iin
            raise ProtocolError('Application response frame limit exceeded')
        except (TimeoutError, socket.timeout, ConnectionError, OSError) as error:
            raise IndeterminateError(f'Request sent or attempted; response unknown: {error}') from error

    def read(self, group, variation, start=None, stop=None):
        if not supported_read(group, variation):
            raise ValueError(f'Unsupported read G{group}V{variation}')
        header = bytes([group, variation, 6]) if start is None else bytes([group, variation, 1]) + struct.pack('<HH', start, stop)
        points, iin = self.exchange(1, header)
        for point in points:
            if (point['group'] != group or (variation and point['variation'] != variation)
                    or (start is not None and (point['index'] is None or not start <= point['index'] <= stop))):
                raise ProtocolError('Read response object/range mismatch')
        return points, iin

    def integrity(self, classes=(0, 1, 2, 3)):
        points, iin = self.exchange(1, class_headers(classes))
        static_groups, event_groups = {1, 3, 10, 20, 30, 40}, {2, 4, 11, 22, 32, 42}
        if (0 not in classes and any(p['group'] in static_groups for p in points)) or (
                not any(c in classes for c in (1, 2, 3)) and any(p['group'] in event_groups for p in points)):
            raise ProtocolError('Class response does not match static/event class selection')
        if any(p['group'] in (12, 41, 50, 52) for p in points):
            raise ProtocolError('Non-measurement object in class response')
        return points, iin

    def command(self, group, variation, index, value, sbo=False):
        request = bytes([group, variation, 0x28]) + struct.pack('<HH', 1, index) + value
        for function in ((3, 4) if sbo else (5,)):
            points, iin = self._consequential_exchange(function, request)
            if self.last_response_fragments != 1 or len(points) != 1:
                raise IndeterminateError('Command reply did not contain one complete matching command')
            point = points[0]
            if (point['group'], point['variation'], point['index'], point['raw'][:-1]) != (group, variation, index, value[:-1]):
                raise IndeterminateError('Command reply type/index/value mismatch; command outcome unknown')
            if point['status'] != 0:
                raise RejectedError('Command status ' + COMMAND_STATUS.get(point['status'], str(point['status'])))
            if function == 3:
                logger.info('[SELECT_ACCEPTED] Exact command selected; sending OPERATE')
        logger.info('[PROTOCOL_ACCEPTED] Command status SUCCESS; physical state unverified')
        return True

    def _consequential_exchange(self, function, objects=b''):
        try:
            return self.exchange(function, objects)
        except (RejectedError, IndeterminateError):
            raise
        except ProtocolError as error:
            raise IndeterminateError(f'Invalid reply after command send; outcome unknown: {error}') from error

    def sync_clock(self, timestamp=None):
        recorded = int(time.time() * 1000) if timestamp is None else timestamp
        points, _ = self._consequential_exchange(24)
        if self.last_response_fragments != 1 or points:
            raise IndeterminateError('RECORD_CURRENT_TIME reply is not one empty response fragment')
        points, iin = self._consequential_exchange(2, bytes([50, 3, 7, 1]) + recorded.to_bytes(6, 'little'))
        if self.last_response_fragments != 1 or points or iin[0] & 16:
            raise IndeterminateError('Time WRITE response has objects or NEED_TIME remains set; clock state unknown')
        logger.info('[PROTOCOL_ACCEPTED] LAN time synchronization acknowledged; clock readback unverified')
        return True

    def restart(self, kind='warm'):
        points, _ = self._consequential_exchange(13 if kind == 'cold' else 14)
        if self.last_response_fragments != 1 or len(points) != 1 or points[0]['group'] != 52 or points[0]['variation'] not in (1, 2) or points[0]['qualifier'] not in (7, 8):
            raise IndeterminateError('Restart response is not one counted G52V1/V2 delay; restart state unknown')
        point = points[0]
        delay = point['value'] * (1000 if point['variation'] == 1 else 1)
        logger.info('[PROTOCOL_ACCEPTED] %s restart accepted; reported delay=%sms; reboot unverified', kind, delay)
        return delay

    def watch(self, duration=10, max_events=100):
        deadline, received = time.monotonic() + duration, 0
        if self.events:
            print_points(self.events)
            received += len(self.events)
            self.events.clear()
        while time.monotonic() < deadline and received < max_events:
            try:
                fragment = self._recv_fragment(deadline)
            except (TimeoutError, socket.timeout):
                if self.transport_rx is not None or self.unsolicited_pending is not None:
                    raise ProtocolError('Incomplete event fragment at monitoring deadline')
                break
            if not fragment['unsolicited']:
                logger.debug('Ignoring solicited response without pending request')
                continue
            points = self._unsolicited(fragment)
            print_points(points)
            received += len(points)
        logger.info('[WATCH_COMPLETED] %s event points observed', received)
        return received


def print_points(points):
    for point in points:
        timestamp = point['timestamp']
        suffix = ''
        if timestamp is not None:
            suffix = ' timestamp_ms=' + str(timestamp)
        print(f" G{point['group']}V{point['variation']} index={point['index']} value={point['value']} flags={point['flags']}{suffix}")


def setup_logger(debug=False, audit_file=None):
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.propagate = False
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(stream)
    if audit_file is None:
        audit_file = os.path.join('ot_audit_logs', 'dnp3_master_LAB_' + datetime.now().strftime('%Y%m%d') + '.log')
    os.makedirs(os.path.dirname(os.path.abspath(audit_file)), exist_ok=True)
    file_handler = logging.FileHandler(audit_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)


def build_parser():
    parser = argparse.ArgumentParser(description='Independent DNP3/TCP Master CLI (reference-validated subset)')
    parser.add_argument('-H', '--host', required=True)
    parser.add_argument('-p', '--port', type=int, default=20000)
    parser.add_argument('-c', '--command', required=True, choices=['ping', 'integrity', 'read', 'watch', 'scan', 'control', 'analog', 'sync-clock', 'restart'])
    parser.add_argument('--master-address', type=int, default=1)
    parser.add_argument('--outstation-address', type=int, default=1024)
    parser.add_argument('--timeout', type=float, default=3)
    parser.add_argument('--retries', type=int, default=2, help='TCP connect retries only; commands are never replayed')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--audit-file', help='Local audit path; default daily file in ot_audit_logs')
    parser.add_argument('--classes', default='0,1,2,3', help='Comma-separated class numbers for integrity; event classes for explicit unsolicited change')
    parser.add_argument('--group', type=int)
    parser.add_argument('--variation', type=int)
    parser.add_argument('--start', type=int)
    parser.add_argument('--stop', type=int)
    parser.add_argument('--duration', type=float, default=10, help='Bounded watch duration in seconds')
    parser.add_argument('--max-events', type=int, default=100)
    unsol = parser.add_mutually_exclusive_group()
    unsol.add_argument('--enable-unsolicited', action='store_true', help='Explicitly enable selected event classes before watch')
    unsol.add_argument('--disable-unsolicited', action='store_true', help='Explicitly disable selected event classes before watch')
    parser.add_argument('--scan-start', type=int, default=1)
    parser.add_argument('--scan-end', type=int, default=10)
    parser.add_argument('--index', type=int)
    parser.add_argument('--operation', choices=['pulse-on', 'pulse-off', 'latch-on', 'latch-off'], default='latch-on')
    parser.add_argument('--count', type=int, default=1)
    parser.add_argument('--on-time', type=int, default=100, help='CROB on-time in milliseconds')
    parser.add_argument('--off-time', type=int, default=100, help='CROB off-time in milliseconds')
    parser.add_argument('--sbo', action='store_true')
    parser.add_argument('--analog-type', choices=['int32', 'int16', 'float32', 'float64'], default='float32')
    parser.add_argument('-v', '--value')
    parser.add_argument('--time-ms', type=int, help='UTC milliseconds since epoch for LAN synchronization; defaults to current time')
    parser.add_argument('--restart-type', choices=['cold', 'warm'], default='warm')
    return parser


def validate_args(parser, args):
    if not 1 <= args.port <= 65535 or not all(0 <= x <= 65519 for x in (args.master_address, args.outstation_address)):
        parser.error('Port/link address outside supported unicast range')
    if args.master_address == args.outstation_address:
        parser.error('Master and outstation addresses must differ')
    if not all(math.isfinite(x) and x > 0 for x in (args.timeout, args.duration)) or not 0 <= args.retries <= 10 or not 1 <= args.max_events <= MAX_POINTS:
        parser.error('Timeout/duration/retries/event bound invalid')
    try:
        args.classes = tuple(dict.fromkeys(int(x) for x in args.classes.split(',')))
        if not args.classes or any(x not in (0, 1, 2, 3) for x in args.classes): raise ValueError()
    except ValueError:
        parser.error('Classes must be comma-separated numbers in 0..3')
    if args.command == 'read':
        if args.group is None or args.variation is None or not supported_read(args.group, args.variation):
            parser.error('Read requires a supported --group and --variation')
        if ((args.start is None) != (args.stop is None) or
                (args.start is not None and not 0 <= args.start <= args.stop <= 65535)):
            parser.error('Read range requires 0 <= --start <= --stop <= 65535')
    if args.command in ('control', 'analog') and (args.index is None or not 0 <= args.index <= 65535):
        parser.error('Control/analog requires --index in 0..65535')
    if not 1 <= args.count <= 255 or not all(0 <= x <= 0xffffffff for x in (args.on_time, args.off_time)):
        parser.error('CROB count/timing outside wire range')
    if args.command == 'analog':
        if args.value is None: parser.error('Analog requires --value')
        try:
            if args.analog_type.startswith('int'): value = int(args.value, 0)
            else:
                value = float(args.value)
                if not math.isfinite(value): raise ValueError('Nonfinite value')
            args.analog_variation = ['int32', 'int16', 'float32', 'float64'].index(args.analog_type) + 1
            args.analog_bytes = struct.pack('<' + ANALOG_FORMATS[args.analog_variation] + 'B', value, 0)
        except (ValueError, OverflowError, struct.error) as error:
            parser.error('Invalid analog value: ' + str(error))
    if args.time_ms is not None and not 0 <= args.time_ms < (1 << 48):
        parser.error('Time must fit unsigned 48-bit milliseconds')
    if not 0 <= args.scan_start <= args.scan_end <= 65519 or args.scan_end - args.scan_start > 1023:
        parser.error('Scan must contain at most 1024 valid unicast addresses')
    if (args.enable_unsolicited or args.disable_unsolicited) and args.command != 'watch':
        parser.error('Unsolicited configuration flags apply only to watch')
    if (args.enable_unsolicited or args.disable_unsolicited) and not any(args.classes):
        parser.error('Unsolicited configuration requires at least one event class (1..3)')


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    setup_logger(args.debug, args.audit_file)
    client = DNP3Client(args.host, args.port, args.master_address, args.outstation_address, args.timeout, args.retries)
    if not client.connect(): return 1
    try:
        if args.command == 'ping':
            client.link_status()
            logger.info('[LINK_STATUS_VALID] Correlated outstation link reply')
            points, iin = client.integrity((0,))
            print_points(points)
            logger.info('[APPLICATION_RESPONSIVE] Class0 response received; IIN=%s', iin_names(iin))
        elif args.command == 'integrity':
            points, _ = client.integrity(args.classes)
            print_points(points)
        elif args.command == 'read':
            points, _ = client.read(args.group, args.variation, args.start, args.stop)
            print_points(points)
        elif args.command == 'watch':
            if args.enable_unsolicited or args.disable_unsolicited:
                classes = tuple(x for x in args.classes if x)
                if not classes: raise ValueError('Unsolicited change requires at least one event class')
                points, _ = client._consequential_exchange(20 if args.enable_unsolicited else 21, class_headers(classes))
                if client.last_response_fragments != 1 or points:
                    raise IndeterminateError('Unsolicited configuration reply is not one empty response')
                logger.info('[PROTOCOL_ACCEPTED] Explicit unsolicited configuration accepted')
            client.watch(args.duration, args.max_events)
        elif args.command == 'scan':
            found = []
            for address in range(args.scan_start, args.scan_end + 1):
                try:
                    client.link_status(address)
                    found.append(address)
                    logger.info('[LINK_ADDRESS_FOUND] %s', address)
                except (TimeoutError, socket.timeout):
                    continue
            if not found:
                logger.warning('[NO_RESPONSE] No correlated link addresses in selected range')
                return 1
        elif args.command == 'control':
            code = ['pulse-on', 'pulse-off', 'latch-on', 'latch-off'].index(args.operation) + 1
            value = struct.pack('<BBIIB', code, args.count, args.on_time, args.off_time, 0)
            client.command(12, 1, args.index, value, args.sbo)
        elif args.command == 'analog':
            client.command(41, args.analog_variation, args.index, args.analog_bytes, args.sbo)
        elif args.command == 'sync-clock':
            client.sync_clock(args.time_ms)
        elif args.command == 'restart':
            client.restart(args.restart_type)
        return 0
    except IndeterminateError as error:
        logger.error('[INDETERMINATE] %s', error)
        return 1
    except RejectedError as error:
        logger.error('[REJECTED] %s', error)
        return 1
    except (ProtocolError, ValueError, OSError) as error:
        logger.error('[FAILED] %s', error)
        return 1
    except KeyboardInterrupt:
        logger.warning('[INTERRUPTED] Monitoring/request interrupted; pending outcome may be unknown')
        return 130
    finally:
        client.close()


if __name__ == '__main__':
    sys.exit(main())
