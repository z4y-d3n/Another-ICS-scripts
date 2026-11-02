#!/usr/bin/env python3
import sys
import signal
import argparse
import logging
import os
import struct
import socket
import ssl
import json
import time
from datetime import datetime

# --- 1. Signal Handling, Terminal Setup & Audit Logging ---
def signal_handler(sig, frame):
    print("\n\033[93m[WARNING] Execution cancelled by user (Ctrl+C). Exiting cleanly...\033[0m")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if os.name == 'nt':
    os.system("")

class Color:
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    GREY = '\033[90m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

logger = logging.getLogger("MQTTSpBMasterCLI")

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        log_color = Color.RESET
        if record.levelno == logging.DEBUG: log_color = Color.GREY
        elif record.levelno == logging.INFO: log_color = Color.RESET
        elif record.levelno == logging.WARNING: log_color = Color.YELLOW
        elif record.levelno == logging.ERROR: log_color = Color.RED
        elif record.levelno == logging.CRITICAL: log_color = Color.RED + Color.BOLD

        format_str = f"{Color.GREY}%(asctime)s{Color.RESET} - {log_color}%(levelname)s{Color.RESET} - {log_color}%(message)s{Color.RESET}"
        formatter = logging.Formatter(format_str, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)

def setup_logger(debug_mode):
    # Prepare both destinations before replacing a working configuration.
    prepared_handlers = []
    try:
        console_handler = logging.StreamHandler(sys.stdout)
        prepared_handlers.append(console_handler)
        console_handler.setFormatter(ColoredFormatter())

        audit_dir = "ot_audit_logs"
        os.makedirs(audit_dir, exist_ok=True)
        log_file = os.path.join(audit_dir, f"mqtt_spb_master_LAB_{datetime.now().strftime('%Y%m%d')}.log")

        file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        prepared_handlers.append(file_handler)
        file_handler.setFormatter(file_formatter)
    except Exception:
        for handler in prepared_handlers:
            handler.close()
        raise

    # Replace only handlers created by this setup function.
    for owned_handler in getattr(setup_logger, "_owned_handlers", ()):
        logger.removeHandler(owned_handler)
        owned_handler.close()
    logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
    logger.propagate = False
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    setup_logger._owned_handlers = (console_handler, file_handler)

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        formatted_message = message[0].upper() + message[1:] if message else message
        print(f"\n{Color.RED}{Color.BOLD}[SYNTAX ERROR]{Color.RESET}")
        print(f"{Color.RED}Detail: {formatted_message}{Color.RESET}")
        print(f"{Color.YELLOW}Hint: Review syntax. Use '-h' or '--help' for detailed required arguments.{Color.RESET}\n")
        self.exit(2)

class ColoredHelpFormatter(argparse.HelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = f"{Color.CYAN}{Color.BOLD}Usage:{Color.RESET} "
        super().add_usage(usage, actions, groups, prefix)


# --- 2. SPARKPLUG B & MQTT CONSTANTS ---
CONNACK_CODES = {
    0x00: "Connection Accepted",
    0x01: "Connection Refused: Unacceptable Protocol Version",
    0x02: "Connection Refused: Identifier Rejected",
    0x03: "Connection Refused: Server Unavailable",
    0x04: "Connection Refused: Bad Username or Password",
    0x05: "Connection Refused: Not Authorized",
}

SPB_DATATYPES = {
    1:  "Int8",
    2:  "Int16",
    3:  "Int32",
    4:  "Int64",
    5:  "UInt8",
    6:  "UInt16",
    7:  "UInt32",
    8:  "UInt64",
    9:  "Float",
    10: "Double",
    11: "Boolean",
    12: "String",
    13: "DateTime",
    14: "Text",
    15: "UUID",
    16: "DataSet",
    17: "Bytes",
    18: "File",
    19: "Template",
}

SPB_NAME_TO_TYPE = {
    "int8":     1,
    "int16":    2,
    "int32":    3,
    "int64":    4,
    "uint8":    5,
    "uint16":   6,
    "uint32":   7,
    "uint64":   8,
    "float":    9,
    "double":   10,
    "bool":     11,
    "string":   12,
    "datetime": 13,
    "text":     14,
}


# --- 3. ZERO-DEPENDENCY PROTOBUF ENGINE FOR SPARKPLUG B ---
def encode_varint(value):
    """Encodes an unsigned 64-bit integer into Google Protobuf Base-128 Varint bytes."""
    value &= 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)

def decode_varint(buf, idx):
    """Decodes a Protobuf Base-128 Varint starting at buf[idx]. Returns (value, new_idx)."""
    result = 0
    shift = 0
    while idx < len(buf) and shift < 70:
        b = buf[idx]
        idx += 1
        if shift == 63 and b > 1:
            raise ValueError("Protobuf Varint exceeds uint64")
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, idx
        shift += 7
    raise ValueError("Truncated Protobuf Varint")

def _pb_fields(buf):
    """Iterate complete protobuf fields, rejecting truncated or invalid wire data."""
    idx = 0
    while idx < len(buf):
        tag, idx = decode_varint(buf, idx)
        field, wire = tag >> 3, tag & 7
        if not 1 <= field < (1 << 29):
            raise ValueError("Invalid Protobuf field number")
        if wire == 0:
            value, idx = decode_varint(buf, idx)
        elif wire in (1, 2, 5):
            if wire == 2:
                size, idx = decode_varint(buf, idx)
            else:
                size = 8 if wire == 1 else 4
            if size > len(buf) - idx:
                raise ValueError("Truncated Protobuf field")
            value = buf[idx:idx + size]
            idx += size
        else:
            raise ValueError("Unsupported Protobuf wire type")
        yield field, wire, value

def pb_tag(field_number, wire_type):
    return encode_varint((field_number << 3) | wire_type)

def pb_encode_string_or_bytes(field_number, data_bytes):
    if isinstance(data_bytes, str):
        data_bytes = data_bytes.encode('utf-8')
    return pb_tag(field_number, 2) + encode_varint(len(data_bytes)) + data_bytes

def encode_spb_metric(name, dtype_code, value, timestamp_ms=None, alias=None):
    """Encodes a single Sparkplug B Metric message into binary Protobuf wire format."""
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)

    if dtype_code not in SPB_NAME_TO_TYPE.values() and dtype_code != 15:
        raise ValueError("Unsupported Sparkplug command datatype")
    if alias is not None and not 0 <= int(alias) <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Sparkplug alias must be uint64")
    if dtype_code in (1, 2, 3, 4, 5, 6, 7, 8, 13) and value is not None and str(value).lower() != "null":
        bits = {1:8, 2:16, 3:32, 4:64, 5:8, 6:16, 7:32, 8:64, 13:64}[dtype_code]
        signed = dtype_code in (1, 2, 3, 4)
        lower = -(1 << (bits - 1)) if signed else 0
        upper = (1 << (bits - (1 if signed else 0))) - 1
        if not lower <= int(str(value), 0) <= upper:
            raise ValueError(f"Value outside {SPB_DATATYPES[dtype_code]} range")
    m_buf = bytearray()
    if name:
        m_buf.extend(pb_encode_string_or_bytes(1, name))
    if alias is not None:
        m_buf.extend(pb_tag(2, 0) + encode_varint(int(alias)))
    m_buf.extend(pb_tag(3, 0) + encode_varint(timestamp_ms))
    m_buf.extend(pb_tag(4, 0) + encode_varint(dtype_code))

    # Encode value into corresponding Metric oneof field (10..16)
    if value is None or str(value).strip().lower() == "null":
        m_buf.extend(pb_tag(7, 0) + encode_varint(1))  # is_null = True
    elif dtype_code in (1, 2, 3, 5, 6, 7):  # Int8, Int16, Int32, UInt8, UInt16, UInt32 -> int_value (Field 10, uint32)
        iv = int(str(value), 0) & 0xFFFFFFFF
        m_buf.extend(pb_tag(10, 0) + encode_varint(iv))
    elif dtype_code in (4, 8, 13):  # Int64, UInt64, DateTime -> long_value (Field 11, uint64)
        lv = int(str(value), 0) & 0xFFFFFFFFFFFFFFFF
        m_buf.extend(pb_tag(11, 0) + encode_varint(lv))
    elif dtype_code == 9:  # Float -> float_value (Field 12, wire_type 5 = 32-bit little-endian)
        m_buf.extend(pb_tag(12, 5) + struct.pack('<f', float(value)))
    elif dtype_code == 10:  # Double -> double_value (Field 13, wire_type 1 = 64-bit little-endian)
        m_buf.extend(pb_tag(13, 1) + struct.pack('<d', float(value)))
    elif dtype_code == 11:  # Boolean -> boolean_value (Field 14, wire_type 0)
        literal = str(value).strip().lower()
        if literal not in ("1", "true", "on", "yes", "t", "0", "false", "off", "no", "f"):
            raise ValueError("Invalid Boolean value")
        bval = 1 if literal in ("1", "true", "on", "yes", "t") else 0
        m_buf.extend(pb_tag(14, 0) + encode_varint(bval))
    elif dtype_code in (12, 14, 15):  # String / Text / UUID -> string_value (Field 15, wire_type 2)
        m_buf.extend(pb_encode_string_or_bytes(15, str(value)))
    else:
        m_buf.extend(pb_encode_string_or_bytes(15, str(value)))

    return bytes(m_buf)

def encode_spb_payload(metrics_bytes_list, seq=0, timestamp_ms=None):
    """Encodes a complete Sparkplug B Payload (Timestamp, Metrics, Sequence)."""
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)

    p_buf = bytearray()
    p_buf.extend(pb_tag(1, 0) + encode_varint(timestamp_ms))
    for mb in metrics_bytes_list:
        p_buf.extend(pb_tag(2, 2) + encode_varint(len(mb)) + mb)
    p_buf.extend(pb_tag(3, 0) + encode_varint(seq & 0xFF))
    return bytes(p_buf)

def _sign_extend(val, bits):
    sign_bit = 1 << (bits - 1)
    return (val & (sign_bit - 1)) - (val & sign_bit)

def decode_spb_metric(buf):
    """Decodes a binary Sparkplug B Metric message into a dictionary."""
    idx = 0
    metric = {
        "name": "",
        "alias": None,
        "timestamp": None,
        "datatype": 0,
        "datatype_name": "Unknown",
        "is_null": False,
        "value": None,
    }
    raw_int = None
    raw_long = None
    value_field = None

    expected_wire = {1:2, 2:0, 3:0, 4:0, 5:0, 6:0, 7:0, 8:2, 9:2,
                     10:0, 11:0, 12:5, 13:1, 14:0, 15:2, 16:2, 17:2, 18:2, 19:2}
    for field_num, wire_type, val in _pb_fields(buf):
        if field_num in expected_wire and wire_type != expected_wire[field_num]:
            raise ValueError("Wrong wire type for Sparkplug Metric field")
        if 10 <= field_num <= 19:
            value_field = field_num
            raw_int = raw_long = None  # Protobuf oneof: last value wins.
            metric["value"] = None
        if field_num == 1: metric["name"] = val.decode('utf-8')
        elif field_num == 2: metric["alias"] = val
        elif field_num == 3: metric["timestamp"] = val
        elif field_num == 4:
            metric["datatype"] = val
            metric["datatype_name"] = SPB_DATATYPES.get(val, f"Type-{val}")
        elif field_num == 7: metric["is_null"] = bool(val)
        elif field_num == 10:
            if val > 0xFFFFFFFF: raise ValueError("Metric int_value exceeds uint32")
            raw_int = val
        elif field_num == 11: raw_long = val
        elif field_num == 12: metric["value"] = struct.unpack('<f', val)[0]
        elif field_num == 13: metric["value"] = struct.unpack('<d', val)[0]
        elif field_num == 14: metric["value"] = bool(val)
        elif field_num == 15: metric["value"] = val.decode('utf-8')
        elif field_num == 16: metric["value"] = f"0x{val.hex().upper()}"
        elif field_num in (17, 18, 19): metric["value"] = f"<Complex field {field_num} ({len(val)}B)>"

    # Apply sign-extension rules for signed integer types
    dt = metric["datatype"]
    type_fields = {1:10, 2:10, 3:10, 4:11, 5:10, 6:10, 7:10, 8:11, 9:12,
                   10:13, 11:14, 12:15, 13:11, 14:15, 15:15, 16:17, 17:16, 18:16, 19:18}
    if not metric["is_null"] and dt in type_fields and value_field is not None and value_field != type_fields[dt]:
        raise ValueError("Sparkplug datatype does not match value field")
    if metric["is_null"]:
        metric["value"] = "NULL"
    elif raw_int is not None:
        if dt == 1:   metric["value"] = _sign_extend(raw_int & 0xFF, 8)
        elif dt == 2: metric["value"] = _sign_extend(raw_int & 0xFFFF, 16)
        elif dt == 3: metric["value"] = _sign_extend(raw_int & 0xFFFFFFFF, 32)
        else:         metric["value"] = raw_int & 0xFFFFFFFF
    elif raw_long is not None:
        if dt == 4:   metric["value"] = _sign_extend(raw_long & 0xFFFFFFFFFFFFFFFF, 64)
        elif dt == 13:
            ts_str = datetime.fromtimestamp(raw_long / 1000.0).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            metric["value"] = f"{ts_str} ({raw_long})"
        else:         metric["value"] = raw_long

    return metric

def decode_spb_payload(buf):
    """Decodes a binary Sparkplug B Payload message."""
    idx = 0
    payload = {
        "timestamp": None,
        "seq": None,
        "uuid": None,
        "metrics": []
    }
    try:
        expected_wire = {1:0, 2:2, 3:0, 4:2, 5:2}
        for field_num, wire_type, val in _pb_fields(buf):
            if field_num in expected_wire and wire_type != expected_wire[field_num]:
                raise ValueError("Wrong wire type for Sparkplug Payload field")
            if field_num == 1: payload["timestamp"] = val
            elif field_num == 2: payload["metrics"].append(decode_spb_metric(val))
            elif field_num == 3: payload["seq"] = val
            elif field_num == 4: payload["uuid"] = val.decode('utf-8')
    except (ValueError, OverflowError, OSError) as e:
        payload["metrics"] = []
        payload["error"] = str(e)
        logger.warning(f"Invalid Sparkplug payload: {e}")

    return payload


# --- 4. NATIVE RAW SOCKET MQTT v3.1.1 CLIENT ---
class RawMQTTClient:
    def __init__(
        self, host, port=1883, client_id=None, username=None, password=None,
        keepalive=30, timeout=4.0, retries=2, use_tls=False, insecure=False,
        cafile=None, certfile=None, keyfile=None
    ):
        self.host = host
        self.port = port
        self.client_id = client_id or f"ot-maint-cli-{os.getpid()}"
        self.username = username
        self.password = password
        self.keepalive = keepalive
        self.timeout = timeout
        self.retries = retries
        self.use_tls = use_tls
        self.insecure = insecure
        self.cafile = cafile
        self.certfile = certfile
        self.keyfile = keyfile

        self.sock = None
        self.packet_id = 1
        self.spb_seq = 0
        self._rx_buffer = bytearray()
        self._pending_packets = []
        self._pending_bytes = 0
        self._last_tx = time.monotonic()
        self._ping_sent = None
        self.max_packet_size = 16 * 1024 * 1024

    @staticmethod
    def _encode_length(length):
        if not 0 <= length <= 268435455:
            raise ValueError("MQTT Remaining Length out of range")
        out = bytearray()
        while True:
            digit = length % 128
            length //= 128
            if length > 0:
                digit |= 0x80
            out.append(digit)
            if length <= 0:
                break
        return bytes(out)

    @staticmethod
    def _pack_utf8(text):
        b = str(text).encode('utf-8')
        if b'\x00' in b or len(b) > 65535:
            raise ValueError("Invalid MQTT UTF-8 string")
        return struct.pack('>H', len(b)) + b

    def connect(self, suppress_logs=False):
        if self.password is not None and self.username is None:
            logger.error("Password requires username in MQTT 3.1.1")
            return False
        for attempt in range(self.retries + 1):
            raw_sock = None
            try:
                self._rx_buffer.clear()
                self._pending_packets.clear()
                self._pending_bytes = 0
                self._ping_sent = None
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock = raw_sock
                raw_sock.settimeout(self.timeout)
                raw_sock.connect((self.host, self.port))

                if self.use_tls:
                    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.cafile)
                    if self.insecure:
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    if self.certfile and self.keyfile:
                        ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
                    self.sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
                else:
                    self.sock = raw_sock

                # Build MQTT v3.1.1 CONNECT Packet (0x10)
                conn_flags = 0x02  # Clean Session = 1
                payload = self._pack_utf8(self.client_id)
                if self.username is not None:
                    conn_flags |= 0x80
                    payload += self._pack_utf8(self.username)
                    if self.password is not None:
                        conn_flags |= 0x40
                        payload += self._pack_utf8(self.password)

                var_hdr = self._pack_utf8("MQTT") + struct.pack('>BBH', 4, conn_flags, self.keepalive)
                rem_bytes = var_hdr + payload
                pkt = b'\x10' + self._encode_length(len(rem_bytes)) + rem_bytes

                logger.debug(f"TX MQTT CONNECT: {len(pkt)} bytes (credentials redacted)")
                self._send_packet(pkt)

                ptype, flags, body = self.recv_packet()
                if ptype != 0x20 or flags != 0 or len(body) != 2 or body[0] != 0 or body[1] not in CONNACK_CODES:
                    raise ConnectionError("Invalid CONNACK received from broker.")

                ret_code = body[1]
                ret_desc = CONNACK_CODES.get(ret_code, f"Unknown Return Code (0x{ret_code:02X})")
                if ret_code != 0x00:
                    logger.error(f"[MQTT AUTH/CONN ERROR] {ret_desc}")
                    self.close()
                    return False

                if not suppress_logs:
                    logger.info(f"MQTT Session established ({ret_desc} | ClientID: {self.client_id})")
                return True

            except Exception as e:
                self.close()
                if attempt < self.retries and not suppress_logs:
                    logger.warning(f"[RETRY] Attempt {attempt + 1} failed ({e}). Retrying...")
                    time.sleep(1.0)
                elif attempt == self.retries and not suppress_logs:
                    logger.error(f"[CONNECTION ERROR] Could not connect to {self.host}:{self.port} - {e}")
                    return False
        return False

    def close(self):
        if self.sock:
            try:
                # Send MQTT DISCONNECT (0xE0 0x00)
                self.sock.sendall(b'\xE0\x00')
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            finally:
                self.sock = None

    def _send_packet(self, packet):
        self.sock.sendall(packet)
        self._last_tx = time.monotonic()

    def _abort_transport(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        self._rx_buffer.clear()
        self._pending_packets.clear()
        self._pending_bytes = 0

    @staticmethod
    def _validate_packet(ptype, flags, body):
        if ptype == 0x30:
            qos = (flags >> 1) & 3
            if qos > 1 or (qos == 0 and flags & 8):
                raise ValueError("Unsupported or invalid PUBLISH QoS/flags")
        elif ptype in (0x20, 0x40, 0x90, 0xD0):
            if flags != 0:
                raise ValueError("Invalid MQTT fixed-header flags")
            size = {0x20:2, 0x40:2, 0xD0:0}.get(ptype)
            if size is not None and len(body) != size:
                raise ValueError("Invalid MQTT control-packet length")
            if ptype == 0x90 and len(body) != 3:
                raise ValueError("Expected one SUBACK return code")
            if ptype in (0x40, 0x90) and body[:2] == b'\x00\x00':
                raise ValueError("Zero packet identifier")
        else:
            raise ValueError("Unexpected MQTT server control packet")

    def _read_packet(self, custom_timeout=None):
        if not self.sock:
            return None, None, None
        prev_to = self.sock.gettimeout()
        deadline = time.monotonic() + (self.timeout if custom_timeout is None else custom_timeout)
        try:
            now = time.monotonic()
            if self._ping_sent is not None and now - self._ping_sent >= self.timeout:
                raise ConnectionError("Keepalive PINGRESP timeout")
            if self.keepalive and self._ping_sent is None and now - self._last_tx >= self.keepalive / 2:
                self._send_packet(b'\xc0\x00')
                self._ping_sent = now
            while True:
                if len(self._rx_buffer) >= 2:
                    rem_len = 0
                    header_len = None
                    for i in range(1, min(len(self._rx_buffer), 5)):
                        byte = self._rx_buffer[i]
                        rem_len |= (byte & 127) << (7 * (i - 1))
                        if not byte & 128:
                            header_len = i + 1
                            break
                        if i == 4:
                            raise ValueError("Malformed MQTT Remaining Length")
                    if rem_len > self.max_packet_size:
                        raise ValueError("MQTT packet exceeds local 16 MiB limit")
                    if header_len is not None and len(self._rx_buffer) >= header_len + rem_len:
                        first = self._rx_buffer[0]
                        body = bytes(self._rx_buffer[header_len:header_len + rem_len])
                        del self._rx_buffer[:header_len + rem_len]
                        ptype, flags = first & 0xF0, first & 15
                        self._validate_packet(ptype, flags, body)
                        if ptype == 0xD0: self._ping_sent = None
                        logger.debug(f"RX MQTT [0x{first:02X} Len:{rem_len}]: {body[:64].hex().upper()}")
                        return ptype, flags, body
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None, None, None
                self.sock.settimeout(remaining)
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise ConnectionError("MQTT broker closed connection")
                self._rx_buffer.extend(chunk)
                if len(self._rx_buffer) > self.max_packet_size + 5:
                    raise ValueError("MQTT receive buffer exceeds local limit")
        except socket.timeout:
            # Preserve the complete partial frame for the next receive call.
            return None, None, None
        except (OSError, ValueError, ConnectionError) as e:
            logger.debug(f"[SOCKET READ] {e}")
            self._abort_transport()
            return None, None, None
        finally:
            if self.sock:
                self.sock.settimeout(prev_to)

    def recv_packet(self, custom_timeout=None):
        if self._pending_packets:
            packet = self._pending_packets.pop(0)
            self._pending_bytes -= len(packet[2])
            return packet
        return self._read_packet(custom_timeout)

    def _wait_for(self, expected_type, packet_id=None):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            packet = self._read_packet(max(0.001, deadline - time.monotonic()))
            ptype, flags, body = packet
            if ptype is None:
                return None
            if ptype == expected_type and (packet_id is None or struct.unpack('>H', body[:2])[0] == packet_id):
                return body
            if ptype == 0x30:
                self._pending_bytes += len(body)
                if len(self._pending_packets) >= 1024 or self._pending_bytes > self.max_packet_size:
                    self._abort_transport()
                    return None
                self._pending_packets.append(packet)
        return None

    def ping(self):
        """Wait for an exact PINGRESP while preserving interleaved telemetry."""
        self._send_packet(b'\xc0\x00')
        self._ping_sent = time.monotonic()
        return self._wait_for(0xD0) is not None

    def subscribe(self, topic_filter, qos=0):
        if qos not in (0, 1) or not topic_filter:
            raise ValueError("Invalid subscription QoS or empty topic filter")
        for i, level in enumerate(topic_filter.split('/')):
            if ('+' in level and level != '+') or ('#' in level and (level != '#' or i != len(topic_filter.split('/')) - 1)):
                raise ValueError("Invalid MQTT topic filter")
        pid = self.packet_id
        self.packet_id = (self.packet_id % 65535) + 1
        rem = struct.pack('>H', pid) + self._pack_utf8(topic_filter) + bytes([qos])
        self._send_packet(b'\x82' + self._encode_length(len(rem)) + rem)
        body = self._wait_for(0x90, pid)
        return body is not None and body[2] in (0, 1) and body[2] <= qos

    def publish(self, topic, payload_bytes, qos=0, retain=False):
        if not topic or '+' in topic or '#' in topic or qos not in (0, 1):
            raise ValueError("Invalid publish topic or unsupported QoS")
        if isinstance(payload_bytes, str): payload_bytes = payload_bytes.encode('utf-8')
        var_hdr = self._pack_utf8(topic)
        pid = self.packet_id
        if qos:
            self.packet_id = (self.packet_id % 65535) + 1
            var_hdr += struct.pack('>H', pid)
        rem = var_hdr + payload_bytes
        if len(rem) > self.max_packet_size:
            raise ValueError("MQTT packet exceeds local 16 MiB limit")
        packet = bytes([0x30 | (qos << 1) | bool(retain)]) + self._encode_length(len(rem)) + rem
        logger.debug(f"TX MQTT PUBLISH ({topic}): {len(packet)} bytes")
        self._send_packet(packet)
        # No retry after an ambiguous command timeout.
        return self._wait_for(0x40, pid) is not None if qos == 1 else True

    def parse_publish_body(self, flags, body):
        """Validate complete topic/identifier before delivering or acknowledging."""
        try:
            self._validate_packet(0x30, flags, body)
            if len(body) < 2: raise ValueError("Truncated PUBLISH topic length")
            tlen = struct.unpack('>H', body[:2])[0]
            idx = 2 + tlen
            if not tlen or idx > len(body): raise ValueError("Truncated/empty PUBLISH topic")
            topic = body[2:idx].decode('utf-8')
            if any(c in topic for c in ('\x00', '+', '#')): raise ValueError("Invalid PUBLISH topic")
            if (flags >> 1) & 3:
                if idx + 2 > len(body): raise ValueError("Truncated PUBLISH identifier")
                pid = struct.unpack('>H', body[idx:idx+2])[0]
                if not pid: raise ValueError("Zero PUBLISH identifier")
                idx += 2
                self._send_packet(b'\x40\x02' + struct.pack('>H', pid))
            return topic, body[idx:]
        except (ValueError, UnicodeError) as e:
            logger.warning(f"Invalid MQTT PUBLISH: {e}")
            self._abort_transport()
            return None, None


# --- 5. COMMAND EXECUTION LOGIC ---
def print_spb_metrics_table(topic, spb_data):
    if "error" in spb_data:
        logger.error(f"Cannot display malformed Sparkplug payload on {topic}: {spb_data['error']}")
        return
    ts_val = spb_data.get("timestamp")
    ts_str = datetime.fromtimestamp(ts_val / 1000.0).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if ts_val else "N/A"
    seq_val = spb_data.get("seq", "N/A")

    print(
        f"{Color.CYAN}{Color.BOLD}[SPARKPLUG B]{Color.RESET} Topic: {Color.YELLOW}{topic}{Color.RESET} | "
        f"Seq: {Color.BLUE}{seq_val}{Color.RESET} | Payload Time: {Color.GREY}{ts_str}{Color.RESET}"
    )

    metrics = spb_data.get("metrics", [])
    if not metrics:
        print(f"  {Color.GREY}(No metrics in Sparkplug B payload){Color.RESET}\n")
        return

    print(f"  {'METRIC NAME':<34} | {'ALIAS':<7} | {'DATATYPE':<10} | {'VALUE':<28} | {'METRIC TIMESTAMP'}")
    print(f"  {'-'*34}-+-{'-'*7}-+-{'-'*10}-+-{'-'*28}-+-{'-'*23}")
    for m in metrics:
        m_name = m["name"] if m["name"] else f"<Alias:{m['alias']}>"
        alias_s = str(m["alias"]) if m["alias"] is not None else "-"
        m_ts = datetime.fromtimestamp(m["timestamp"] / 1000.0).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if m["timestamp"] else "-"
        print(
            f"  {Color.BLUE}{m_name[:34]:<34}{Color.RESET} | "
            f"{alias_s:<7} | "
            f"{Color.CYAN}{m['datatype_name']:<10}{Color.RESET} | "
            f"{Color.GREEN}{Color.BOLD}{str(m['value'])[:28]:<28}{Color.RESET} | "
            f"{Color.GREY}{m_ts}{Color.RESET}"
        )
    print()

def do_ping(client):
    print(f"\n{Color.CYAN}{Color.BOLD}--- MQTT / SPARKPLUG B BROKER DIAGNOSTIC ---{Color.RESET}")
    ping_ok = client.ping()
    print(f" {Color.BOLD}MQTT v3.1.1 CONNECT / CONNACK:{Color.RESET} {Color.GREEN}VALIDATED (0x00){Color.RESET}")
    print(f" {Color.BOLD}Keep-Alive PINGREQ / PINGRESP:{Color.RESET} {Color.GREEN if ping_ok else Color.RED}{'ONLINE (0xD0)' if ping_ok else 'NO RESPONSE'}{Color.RESET}\n")
    return ping_ok

def do_broker_info(client, args):
    logger.info("Subscribing to '$SYS/broker/#' to fingerprint MQTT Broker...")
    if not client.subscribe("$SYS/broker/#", qos=0):
        logger.error("Broker subscription rejected or unconfirmed")
        return False

    sys_info = {}
    deadline = time.time() + max(args.listen_time, 3.0)
    while time.time() < deadline:
        ptype, flags, body = client.recv_packet(custom_timeout=0.5)
        if ptype == 0x30:
            topic, payload = client.parse_publish_body(flags, body)
            if topic:
                sys_info[topic] = payload.decode('utf-8', errors='replace')

    print(f"\n{Color.CYAN}{Color.BOLD}--- MQTT BROKER $SYS FINGERPRINT ---{Color.RESET}")
    if not sys_info:
        print(f" {Color.YELLOW}Broker restricts access to '$SYS/#' or published no system metrics.{Color.RESET}\n")
        return

    for k in sorted(sys_info.keys()):
        print(f"  {Color.BLUE}{k:<44}:{Color.RESET} {Color.GREEN}{sys_info[k]}{Color.RESET}")
    print()

def do_discover(client, args):
    sub_topic = args.topic or "#"
    logger.info(f"Listening on '{sub_topic}' for {args.listen_time}s to map Sparkplug B & MQTT topology...")
    if not client.subscribe(sub_topic, qos=0):
        logger.error("Discovery subscription rejected or unconfirmed")
        return False

    spb_nodes = {}
    std_topics = {}
    last_ping = time.time()
    deadline = time.time() + args.listen_time

    while time.time() < deadline:
        ptype, flags, body = client.recv_packet(custom_timeout=0.5)
        if ptype == 0x30:
            topic, payload = client.parse_publish_body(flags, body)
            if not topic:
                continue
            if topic.startswith("spBv1.0/"):
                parts = topic.split("/")
                if len(parts) >= 4:
                    grp, mtype, edge = parts[1], parts[2], parts[3]
                    dev = parts[4] if len(parts) >= 5 else "(Edge Node)"
                    key = (grp, edge, dev)
                    if key not in spb_nodes:
                        spb_nodes[key] = {"msg_types": set(), "metric_count": 0}
                    spb_nodes[key]["msg_types"].add(mtype)
                    if mtype != "STATE":
                        decoded = decode_spb_payload(payload)
                        spb_nodes[key]["metric_count"] = max(
                            spb_nodes[key]["metric_count"], len(decoded.get("metrics", []))
                        )
            else:
                std_topics[topic] = len(payload)

        if time.time() - last_ping >= 10.0:
            client.ping()
            last_ping = time.time()

    print(f"\n{Color.CYAN}{Color.BOLD}--- SPARKPLUG B TOPOLOGY DISCOVERED ({len(spb_nodes)} Entities) ---{Color.RESET}")
    if spb_nodes:
        print(f" {'GROUP ID':<18} | {'EDGE NODE ID':<22} | {'DEVICE ID':<20} | {'MSG TYPES SEEN':<22} | {'MAX METRICS'}")
        print(f" {'-'*18}-+-{'-'*22}-+-{'-'*20}-+-{'-'*22}-+-{'-'*11}")
        for (grp, edge, dev), info in sorted(spb_nodes.items()):
            mtypes = ",".join(sorted(info["msg_types"]))
            print(
                f" {Color.YELLOW}{grp:<18}{Color.RESET} | "
                f"{Color.GREEN}{edge:<22}{Color.RESET} | "
                f"{Color.BLUE}{dev:<20}{Color.RESET} | "
                f"{mtypes:<22} | "
                f"{info['metric_count']}"
            )
    else:
        print(f" {Color.YELLOW}No active Sparkplug B ('spBv1.0/#') traffic captured during window.{Color.RESET}")

    print(f"\n{Color.CYAN}{Color.BOLD}--- STANDARD MQTT TOPICS DISCOVERED ({len(std_topics)}) ---{Color.RESET}")
    for t, blen in list(sorted(std_topics.items()))[:40]:
        print(f"  - {Color.YELLOW}{t}{Color.RESET} ({blen} bytes)")
    print()

def do_watch(client, args):
    if args.topic:
        sub_topic = args.topic
    elif args.group_id:
        edge_part = args.edge_node_id if args.edge_node_id else "+"
        if args.device_id:
            sub_topic = f"spBv1.0/{args.group_id}/+/{edge_part}/{args.device_id}"
        elif args.edge_node_id:
            sub_topic = f"spBv1.0/{args.group_id}/+/{edge_part}/#"
        else:
            sub_topic = f"spBv1.0/{args.group_id}/#"
    else:
        sub_topic = "spBv1.0/#"

    logger.info(f"Subscribing to '{sub_topic}' for real-time telemetry decoding...")
    print(f"{Color.GREY}Auto-detecting Sparkplug B Protobuf, JSON & Raw Payloads | Press Ctrl+C to stop.{Color.RESET}\n")
    if not client.subscribe(sub_topic, qos=args.qos):
        logger.error("Watch subscription rejected or unconfirmed")
        return False

    last_ping = time.time()
    while True:
        ptype, flags, body = client.recv_packet(custom_timeout=1.0)
        if ptype is None and client.sock is None:
            logger.error("Watch stopped: broker connection lost")
            return False
        if ptype == 0x30:
            topic, payload = client.parse_publish_body(flags, body)
            if not topic:
                continue

            if topic.startswith("spBv1.0/") and not topic.startswith("spBv1.0/STATE/"):
                spb_data = decode_spb_payload(payload)
                if args.metric:
                    spb_data["metrics"] = [m for m in spb_data["metrics"] if m["name"] == args.metric]
                if spb_data["metrics"] or not args.metric:
                    print_spb_metrics_table(topic, spb_data)
            else:
                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                txt = payload.decode('utf-8', errors='replace')
                try:
                    parsed_json = json.loads(txt)
                    pretty = json.dumps(parsed_json)
                    print(f"{Color.CYAN}[{ts}] [MQTT JSON]{Color.RESET} {Color.YELLOW}{topic}{Color.RESET} -> {Color.GREEN}{pretty}{Color.RESET}")
                except Exception:
                    print(f"{Color.CYAN}[{ts}] [MQTT RAW]{Color.RESET}  {Color.YELLOW}{topic}{Color.RESET} -> {Color.GREEN}{txt}{Color.RESET}")

        if time.time() - last_ping >= 15.0:
            client.ping()
            last_ping = time.time()

def do_rebirth(client, args):
    if args.device_id:
        cmd_topic = f"spBv1.0/{args.group_id}/DCMD/{args.edge_node_id}/{args.device_id}"
        rebirth_metric_name = "Device Control/Rebirth"
        birth_sub = f"spBv1.0/{args.group_id}/DBIRTH/{args.edge_node_id}/{args.device_id}"
    else:
        cmd_topic = f"spBv1.0/{args.group_id}/NCMD/{args.edge_node_id}"
        rebirth_metric_name = "Node Control/Rebirth"
        birth_sub = f"spBv1.0/{args.group_id}/+/+"

    logger.warning(f"EXECUTING OT SPARKPLUG B REBIRTH REQUEST -> Topic: {cmd_topic} ({rebirth_metric_name} = True)")

    # Subscribe first so we capture the resulting NBIRTH / DBIRTH immediately
    if not client.subscribe(f"spBv1.0/{args.group_id}/#"):
        logger.error("Rebirth subscription rejected or unconfirmed; command not sent")
        return False

    m_bytes = encode_spb_metric(rebirth_metric_name, 11, True)  # DataType 11 = Boolean
    p_bytes = encode_spb_payload([m_bytes], seq=0)

    if client.publish(cmd_topic, p_bytes, qos=args.qos, retain=False):
        logger.info(f"{Color.GREEN}[REBIRTH SENT]{Color.RESET} Waiting {args.listen_time}s for NBIRTH / DBIRTH inventory response...")
        deadline = time.time() + args.listen_time
        while time.time() < deadline:
            ptype, flags, body = client.recv_packet(custom_timeout=0.5)
            if ptype == 0x30:
                topic, payload = client.parse_publish_body(flags, body)
                expected_birth = birth_sub if args.device_id else f"spBv1.0/{args.group_id}/NBIRTH/{args.edge_node_id}"
                if topic == expected_birth:
                    spb_data = decode_spb_payload(payload)
                    print_spb_metrics_table(topic, spb_data)
        return True
    logger.error("[INDETERMINATE] Rebirth command has no broker acknowledgement")
    return False

def do_write_spb(client, args):
    if args.device_id:
        cmd_topic = f"spBv1.0/{args.group_id}/DCMD/{args.edge_node_id}/{args.device_id}"
    else:
        cmd_topic = f"spBv1.0/{args.group_id}/NCMD/{args.edge_node_id}"

    dtype_code = SPB_NAME_TO_TYPE[args.type.lower()]
    dtype_label = SPB_DATATYPES.get(dtype_code, args.type)

    logger.warning(
        f"EXECUTING OT SPARKPLUG B COMMAND WRITE - Topic: {cmd_topic}, "
        f"Metric: '{args.metric}', Alias: {args.alias}, Type: {dtype_label}, Value: {args.value}"
    )

    m_bytes = encode_spb_metric(args.metric, dtype_code, args.value, alias=args.alias)
    p_bytes = encode_spb_payload([m_bytes], seq=0)

    if client.publish(cmd_topic, p_bytes, qos=args.qos, retain=False):
        print(
            f"\n{Color.GREEN}{Color.BOLD}[{'BROKER_ACKNOWLEDGED' if args.qos == 1 else 'SENT_UNCONFIRMED'}]{Color.RESET} Sparkplug B command published to {Color.YELLOW}{cmd_topic}{Color.RESET}\n"
            f"  {Color.BLUE}Metric:{Color.RESET}   {args.metric or f'Alias:{args.alias}'}\n"
            f"  {Color.BLUE}DataType:{Color.RESET} {dtype_label}\n"
            f"  {Color.BLUE}Value:{Color.RESET}    {Color.GREEN}{args.value}{Color.RESET}\n"
        )
        logger.info("Downstream command execution is unverified")
        return True
    else:
        logger.error("[INDETERMINATE] Sparkplug command has no broker acknowledgement")
        return False

def do_write_mqtt(client, args):
    logger.warning(
        f"EXECUTING OT STANDARD MQTT PUBLISH - Topic: {args.topic}, "
        f"QoS: {args.qos}, Retain: {args.retain}, Value: {args.value}"
    )

    if args.type == "hex":
        payload_bytes = bytes.fromhex(args.value.replace(" ", ""))
    else:
        payload_bytes = args.value.encode('utf-8')

    if client.publish(args.topic, payload_bytes, qos=args.qos, retain=args.retain):
        print(f"\n{Color.GREEN}{Color.BOLD}[{'BROKER_ACKNOWLEDGED' if args.qos == 1 else 'SENT_UNCONFIRMED'}]{Color.RESET} Published {len(payload_bytes)} bytes to topic '{Color.YELLOW}{args.topic}{Color.RESET}'. Downstream execution unverified.\n")
        return True
    else:
        logger.error("[INDETERMINATE] MQTT message has no broker acknowledgement")
        return False


# --- 6. MAIN ENTRY POINT ---
def main():
    desc_text = f"{Color.BOLD}MQTT v3.1.1 & Sparkplug B Master CLI (by z4y_d3n){Color.RESET}\n"
    custom_usage = (
        f"{Color.GREEN}mqtt_spb_master.py{Color.RESET} "
        f"{Color.YELLOW}[-H HOST] [-c COMMAND] [-p PORT] [-G GROUP] [-E EDGE_NODE] [-D DEVICE] "
        f"[-m METRIC] [-v VALUE] [-t TYPE] [-T TOPIC] [-u USER] [-P PASS] [--tls]{Color.RESET}"
    )

    parser = CustomArgumentParser(description=desc_text, usage=custom_usage, formatter_class=ColoredHelpFormatter)

    parser.add_argument("-H", "--host", required=True, type=str, help="Target IP/Hostname of the MQTT / IIoT Broker.")
    parser.add_argument("-c", "--command", required=True, choices=[
        "ping", "broker-info", "discover", "watch", "rebirth", "write-spb", "write-mqtt"
    ], help="MQTT / Sparkplug B action to execute.")
    parser.add_argument("-p", "--port", type=int, default=None, help="Broker TCP/TLS Port (Default: 1883, or 8883 with --tls).")
    parser.add_argument("--timeout", type=float, default=4.0, help="Socket timeout in seconds (Default: 4.0).")
    parser.add_argument("--debug", action="store_true", help="Enable raw Hex MQTT & Protobuf trace logs.")

    auth_group = parser.add_argument_group(f"{Color.CYAN}Authentication & TLS Security Options{Color.RESET}")
    auth_group.add_argument("-u", "--user", type=str, default=None, help="MQTT Broker Username.")
    auth_group.add_argument("-P", "--password", type=str, default=None, help="MQTT Broker Password.")
    auth_group.add_argument("--client-id", type=str, default=None, help="Custom MQTT Client ID.")
    auth_group.add_argument("--tls", action="store_true", help="Enable native SSL/TLS encryption.")
    auth_group.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification (Self-signed broker certs).")
    auth_group.add_argument("--cafile", type=str, default=None, help="Path to CA certificate PEM file.")
    auth_group.add_argument("--cert", type=str, default=None, help="Path to Client certificate PEM file (mTLS).")
    auth_group.add_argument("--key", type=str, default=None, help="Path to Client private key PEM file (mTLS).")

    spb_group = parser.add_argument_group(f"{Color.CYAN}Sparkplug B Namespace & Metric Options (spBv1.0){Color.RESET}")
    spb_group.add_argument("-G", "--group-id", type=str, help="Sparkplug B Group ID (e.g., 'PlantaAgua', 'Subestacion1').")
    spb_group.add_argument("-E", "--edge-node-id", type=str, help="Sparkplug B Edge Node ID (e.g., 'Gateway_OT_01').")
    spb_group.add_argument("-D", "--device-id", type=str, default=None, help="Optional Sparkplug B Device ID (e.g., 'PLC_Legacy_01').")
    spb_group.add_argument("-m", "--metric", type=str, default=None, help="Sparkplug B Metric Name (e.g., 'Outputs/Valvula_1').")
    spb_group.add_argument("--alias", type=int, default=None, help="Optional Sparkplug B Metric numeric Alias.")

    mqtt_group = parser.add_argument_group(f"{Color.CYAN}Data Formatting & Standard MQTT Options{Color.RESET}")
    mqtt_group.add_argument("-T", "--topic", type=str, default=None, help="Explicit MQTT Topic or Filter (e.g., 'planta/celda1/#').")
    mqtt_group.add_argument("-v", "--value", type=str, default=None, help="Value to publish for 'write-spb' or 'write-mqtt'.")
    mqtt_group.add_argument("-t", "--type", choices=list(SPB_NAME_TO_TYPE.keys()) + ["hex"], default="float", help="Metric DataType for 'write-spb' or 'hex'/'string' for 'write-mqtt' (Default: float).")
    mqtt_group.add_argument("-q", "--qos", type=int, choices=[0, 1], default=0, help="MQTT Quality of Service (0 or 1, Default: 0).")
    mqtt_group.add_argument("--retain", action="store_true", help="Set MQTT Retain flag on 'write-mqtt'.")
    mqtt_group.add_argument("-w", "--listen-time", type=float, default=5.0, help="Collection window in seconds for 'discover', 'broker-info', or 'rebirth' (Default: 5.0).")

    if len(sys.argv) == 1:
        parser.print_usage()
        sys.exit(1)

    parser.usage = argparse.SUPPRESS
    args = parser.parse_args()

    if args.port is None:
        args.port = 8883 if args.tls else 1883

    if not 1 <= args.port <= 65535 or not 0 < args.timeout < float('inf') or not 0 <= args.listen_time < float('inf'):
        parser.error("Port, timeout, or listen-time outside valid range.")
    if args.password is not None and args.user is None:
        parser.error("Password requires a username in MQTT 3.1.1.")
    if bool(args.cert) != bool(args.key):
        parser.error("Client certificate and key must be specified together.")

    # --- Logical Validations ---
    if args.command == "rebirth" and (not args.group_id or not args.edge_node_id):
        parser.error("Arguments -G / --group-id and -E / --edge-node-id are strictly required for 'rebirth'.")
    if args.command == "write-spb":
        if args.type == "hex":
            parser.error("Type 'hex' is supported only by write-mqtt.")
        if not args.group_id or not args.edge_node_id:
            parser.error("Arguments -G / --group-id and -E / --edge-node-id are required for 'write-spb'.")
        if (not args.metric and args.alias is None) or args.value is None:
            parser.error("Arguments -m / --metric (or --alias) and -v / --value are required for 'write-spb'.")
    if args.command == "write-mqtt" and (not args.topic or args.value is None):
        parser.error("Arguments -T / --topic and -v / --value are strictly required for 'write-mqtt'.")
    if args.command in ("write-spb", "rebirth"):
        for value in (args.group_id, args.edge_node_id, args.device_id):
            if value is not None and (not value or any(c in value for c in ('/', '+', '#', '\x00'))):
                parser.error("Sparkplug topic identifiers must be single non-wildcard levels.")

    setup_logger(args.debug)

    client = RawMQTTClient(
        host=args.host,
        port=args.port,
        client_id=args.client_id,
        username=args.user,
        password=args.password,
        timeout=args.timeout,
        use_tls=args.tls,
        insecure=args.insecure,
        cafile=args.cafile,
        certfile=args.cert,
        keyfile=args.key,
    )

    if not client.connect():
        sys.exit(1)

    sec_mode = "TLS" if args.tls else "PLAINTEXT"
    print(
        f"{Color.GREEN}{Color.BOLD}[CONNECTED]{Color.RESET} {Color.CYAN}{args.host}:{args.port}{Color.RESET} ({sec_mode}) | "
        f"Command: {Color.YELLOW}{args.command.upper()}{Color.RESET}\n"
    )

    try:
        if args.command == "ping":
            result = do_ping(client)
        elif args.command == "broker-info":
            result = do_broker_info(client, args)
        elif args.command == "discover":
            result = do_discover(client, args)
        elif args.command == "watch":
            result = do_watch(client, args)
        elif args.command == "rebirth":
            result = do_rebirth(client, args)
        elif args.command == "write-spb":
            result = do_write_spb(client, args)
        elif args.command == "write-mqtt":
            result = do_write_mqtt(client, args)
        if result is False:
            sys.exit(1)
    except (ValueError, OSError, ConnectionError) as e:
        logger.error(f"[FAILED/INDETERMINATE] {e}")
        sys.exit(1)
    finally:
        client.close()

if __name__ == "__main__":
    main()
