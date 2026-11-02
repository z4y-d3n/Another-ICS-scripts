#!/usr/bin/env python3
import sys
import signal
import argparse
import logging
import os
import struct
import socket
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

logger = logging.getLogger("BACnetMasterCLI")

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
        log_file = os.path.join(audit_dir, f"bacnet_master_LAB_{datetime.now().strftime('%Y%m-%d').replace('-', '')}.log")

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


# --- 2. BACNET ASHRAE 135 CONSTANTS & DICTIONARIES ---
OBJECT_TYPES = {
    "ai":  0,  "analog-input":        0,
    "ao":  1,  "analog-output":       1,
    "av":  2,  "analog-value":        2,
    "bi":  3,  "binary-input":        3,
    "bo":  4,  "binary-output":       4,
    "bv":  5,  "binary-value":        5,
    "cal": 6,  "calendar":            6,
    "cmd": 7,  "command":             7,
    "dev": 8,  "device":              8,
    "ev":  9,  "event-enrollment":    9,
    "fil": 10, "file":                10,
    "grp": 11, "group":               11,
    "lp":  12, "loop":                12,
    "msi": 13, "multi-state-input":   13,
    "mso": 14, "multi-state-output":  14,
    "nc":  15, "notification-class":  15,
    "prg": 16, "program":             16,
    "sch": 17, "schedule":            17,
    "msv": 19, "multi-state-value":   19,
    "tl":  20, "trend-log":           20,
}

OBJECT_TYPE_NAMES = {
    0: "Analog-Input (AI)",
    1: "Analog-Output (AO)",
    2: "Analog-Value (AV)",
    3: "Binary-Input (BI)",
    4: "Binary-Output (BO)",
    5: "Binary-Value (BV)",
    6: "Calendar",
    7: "Command",
    8: "Device (DEV)",
    9: "Event-Enrollment",
    10: "File",
    11: "Group",
    12: "Loop",
    13: "Multi-State-Input (MSI)",
    14: "Multi-State-Output (MSO)",
    15: "Notification-Class",
    16: "Program",
    17: "Schedule",
    19: "Multi-State-Value (MSV)",
    20: "Trend-Log",
}

PROPERTY_IDS = {
    "ack-required":                 1,
    "application-software-version": 12,
    "archive":                      13,
    "cov-increment":                22,
    "description":                  28,
    "device-type":                  31,
    "event-state":                  36,
    "firmware-revision":            44,
    "high-limit":                   45,
    "inactive-text":                46,
    "active-text":                  4,
    "location":                     58,
    "low-limit":                    59,
    "max-apdu-length-accepted":     62,
    "model-name":                   70,
    "number-of-states":             74,
    "object-identifier":            75,
    "object-list":                  76,
    "object-name":                  77,
    "object-type":                  79,
    "out-of-service":               81,
    "polarity":                     84,
    "present-value":                85,
    "priority-array":               87,
    "protocol-revision":            139,
    "protocol-version":             98,
    "reliability":                  103,
    "relinquish-default":           104,
    "segmentation-supported":       107,
    "state-text":                   110,
    "status-flags":                 111,
    "system-status":                112,
    "units":                        117,
    "vendor-identifier":            120,
    "vendor-name":                  121,
}

PROPERTY_NAMES = {v: k for k, v in PROPERTY_IDS.items()}

ENGINEERING_UNITS = {
    2: "m²", 3: "A", 4: "mA", 5: "V", 6: "kV", 7: "MV",
    18: "W", 19: "kW", 20: "MW", 27: "Hz", 31: "J", 47: "Wh", 48: "kWh",
    53: "Pa", 54: "kPa", 55: "bar", 56: "psi", 62: "°C", 63: "°K", 64: "°F",
    67: "Years", 70: "Days", 71: "Hours", 72: "Minutes", 73: "Seconds",
    80: "m", 85: "L/s", 87: "L/min", 95: "no-units", 98: "%", 104: "rpm",
    134: "m³/h", 135: "m³/min", 142: "ppm", 166: "m/s", 190: "Ω"
}

PRIORITY_LEVEL_NAMES = {
    1:  "1 - Manual-Life-Safety",
    2:  "2 - Automatic-Life-Safety",
    3:  "3 - Available",
    4:  "4 - Available",
    5:  "5 - Critical-Equipment-Control",
    6:  "6 - Minimum-On-Off",
    7:  "7 - Available",
    8:  "8 - Manual-Operator (Maintenance)",
    9:  "9 - Available",
    10: "10 - Available",
    11: "11 - Available",
    12: "12 - Available",
    13: "13 - Available",
    14: "14 - Available",
    15: "15 - Available",
    16: "16 - Lowest / Schedule"
}

ERROR_CLASSES = {
    0: "Device", 1: "Object", 2: "Property", 3: "Resources",
    4: "Security", 5: "Services", 6: "VT", 7: "Communication"
}

ERROR_CODES = {
    0: "Other", 2: "Configuration-In-Progress", 3: "Device-Busy",
    4: "Dynamic-Creation-Not-Supported", 9: "Invalid-Array-Index",
    19: "Invalid-Data-Type", 25: "Operational-Problem", 27: "Password-Failure",
    31: "Unknown-Object", 32: "Unknown-Property", 37: "Value-Out-Of-Range",
    40: "Write-Access-Denied", 41: "Character-Set-Not-Supported",
    42: "Invalid-Array-Index"
}


# --- 3. ASN.1 / BACNET TAG ENCODING & DECODING HELPERS ---
def pack_unsigned(val):
    """Packs an unsigned integer into minimum required big-endian bytes (1..4)."""
    val = int(val)
    if val < 0x100: return struct.pack('>B', val)
    elif val < 0x10000: return struct.pack('>H', val)
    elif val < 0x1000000: return struct.pack('>I', val)[1:]
    else: return struct.pack('>I', val)

def pack_signed(val):
    """Packs a signed integer into minimum required 2's complement big-endian bytes (1..4)."""
    val = int(val)
    if -128 <= val <= 127: return struct.pack('>b', val)
    elif -32768 <= val <= 32767: return struct.pack('>h', val)
    elif -8388608 <= val <= 8388607: return struct.pack('>i', val)[1:]
    else: return struct.pack('>i', val)

def build_tag_header(tag_num, is_context, length):
    """Builds a standard BACnet ASN.1 Tag Header."""
    cls_bit = 0x08 if is_context else 0x00
    if tag_num < 15:
        first_byte = (tag_num << 4) | cls_bit
        ext_tag = b''
    else:
        first_byte = 0xF0 | cls_bit
        ext_tag = struct.pack('>B', tag_num)

    if length < 5:
        return struct.pack('>B', first_byte | length) + ext_tag
    elif length < 254:
        return struct.pack('>B', first_byte | 5) + ext_tag + struct.pack('>B', length)
    elif length < 65536:
        return struct.pack('>B', first_byte | 5) + ext_tag + struct.pack('>BH', 254, length)
    else:
        return struct.pack('>B', first_byte | 5) + ext_tag + struct.pack('>BI', 255, length)

def encode_context_unsigned(tag_num, val):
    payload = pack_unsigned(val)
    return build_tag_header(tag_num, True, len(payload)) + payload

def encode_context_enumerated(tag_num, val):
    return encode_context_unsigned(tag_num, val)

def encode_context_string(tag_num, text):
    str_bytes = b'\x00' + str(text).encode('utf-8')  # 0x00 = ANSI X3.4 / UTF-8
    return build_tag_header(tag_num, True, len(str_bytes)) + str_bytes

def encode_context_object_id(tag_num, obj_type, instance):
    if not 0 <= int(obj_type) <= 1023 or not 0 <= int(instance) <= 4194303:
        raise ValueError('BACnet object type or instance out of range')
    raw_id = (int(obj_type) << 22) | int(instance)
    payload = struct.pack('>I', raw_id)
    return build_tag_header(tag_num, True, 4) + payload

def encode_opening_tag(tag_num):
    if tag_num < 15:
        return struct.pack('>B', (tag_num << 4) | 0x0E)
    return struct.pack('>BB', 0xFE, tag_num)

def encode_closing_tag(tag_num):
    if tag_num < 15:
        return struct.pack('>B', (tag_num << 4) | 0x0F)
    return struct.pack('>BB', 0xFF, tag_num)

def encode_application_value(val_str, val_type="auto", obj_type=0):
    """Encodes an Application-Tagged BACnet value for WriteProperty."""
    if val_type == "null" or str(val_str).strip().lower() == "null":
        return b'\x00'  # Application Tag 0 (Null) -> Relinquish command!

    # Auto-detect appropriate BACnet Application Tag based on Object Type if set to 'auto'
    if val_type == "auto":
        if obj_type in (0, 1, 2):    val_type = "real"      # AI, AO, AV -> Real (Float32)
        elif obj_type in (3, 4, 5):  val_type = "enum"      # BI, BO, BV -> Enumerated (0=Inactive, 1=Active)
        elif obj_type in (13, 14, 19): val_type = "uint"    # MSI, MSO, MSV -> Unsigned Int (1..N)
        else:                        val_type = "real"

    if val_type == "bool":
        text = str(val_str).strip().lower()
        if text not in ('1', 'true', 'on', 'active', 'yes', '0', 'false', 'off', 'inactive', 'no'):
            raise ValueError('Invalid BACnet boolean')
        b_val = int(text in ('1', 'true', 'on', 'active', 'yes'))
        return struct.pack('>B', 0x10 | b_val)  # Application Tag 1 (Boolean)
    elif val_type == "uint":
        payload = pack_unsigned(int(str(val_str), 0))
        return build_tag_header(2, False, len(payload)) + payload
    elif val_type == "int":
        payload = pack_signed(int(str(val_str), 0))
        return build_tag_header(3, False, len(payload)) + payload
    elif val_type == "real":
        payload = struct.pack('>f', float(val_str))
        return build_tag_header(4, False, 4) + payload
    elif val_type == "double":
        payload = struct.pack('>d', float(val_str))
        return build_tag_header(5, False, 8) + payload
    elif val_type == "string":
        payload = b'\x00' + str(val_str).encode('utf-8')
        return build_tag_header(7, False, len(payload)) + payload
    elif val_type == "enum":
        s_low = str(val_str).strip().lower()
        if s_low in ("active", "on", "true", "1"): e_val = 1
        elif s_low in ("inactive", "off", "false", "0"): e_val = 0
        else: e_val = int(s_low, 0)
        payload = pack_unsigned(e_val)
        return build_tag_header(9, False, len(payload)) + payload
    else:
        payload = struct.pack('>f', float(val_str))
        return build_tag_header(4, False, 4) + payload

def decode_application_tags(buf):
    """Decodes a sequence of BACnet ASN.1 Application Tags into Python objects."""
    results = []
    idx = 0
    while idx < len(buf):
        first = buf[idx]
        idx += 1
        tag_num = (first >> 4) & 0x0F
        is_context = bool(first & 0x08)
        lvt = first & 0x07

        if tag_num == 15:
            if idx >= len(buf): raise ValueError('Truncated extended tag')
            tag_num = buf[idx]
            idx += 1

        # Handle Context Opening/Closing tags gracefully
        if is_context and lvt == 6:
            continue
        if is_context and lvt == 7:
            break

        # Application Boolean stores its value in LVT directly
        if not is_context and tag_num == 1:
            if lvt not in (0, 1): raise ValueError('Invalid Boolean LVT')
            results.append(bool(lvt & 0x01))
            continue

        # Determine length
        if lvt < 5:
            length = lvt
        else:
            if idx >= len(buf): raise ValueError('Truncated extended length')
            len_ext = buf[idx]
            idx += 1
            if len_ext < 254:
                length = len_ext
            elif len_ext == 254:
                if idx + 2 > len(buf): raise ValueError('Truncated extended length')
                length = struct.unpack('>H', buf[idx:idx+2])[0]
                idx += 2
            else:
                if idx + 4 > len(buf): raise ValueError('Truncated extended length')
                length = struct.unpack('>I', buf[idx:idx+4])[0]
                idx += 4

        if idx + length > len(buf): raise ValueError('Truncated tag value')
        if not is_context and (tag_num in (4, 10, 11, 12) and length != 4 or tag_num == 5 and length != 8):
            raise ValueError('Invalid application value length')
        if not is_context and tag_num in (2, 3, 9) and length == 0:
            raise ValueError('Empty application numeric value')
        val_bytes = buf[idx : idx + length]
        idx += length

        if is_context:
            # Context-tagged primitive inside a constructed value
            results.append(f"CTX[{tag_num}]:0x{val_bytes.hex().upper()}")
            continue

        # Decode standard BACnet Application Tags (0..12)
        if tag_num == 0:    # Null
            results.append("NULL")
        elif tag_num == 2:  # Unsigned Int
            u_val = int.from_bytes(val_bytes, byteorder='big', signed=False)
            results.append(u_val)
        elif tag_num == 3:  # Signed Int
            s_val = int.from_bytes(val_bytes, byteorder='big', signed=True)
            results.append(s_val)
        elif tag_num == 4 and len(val_bytes) == 4:  # Real (Float32)
            f_val = struct.unpack('>f', val_bytes)[0]
            results.append(f_val)
        elif tag_num == 5 and len(val_bytes) == 8:  # Double (Float64)
            d_val = struct.unpack('>d', val_bytes)[0]
            results.append(d_val)
        elif tag_num == 6:  # Octet String
            results.append(f"0x{val_bytes.hex().upper()}")
        elif tag_num == 7:  # Character String
            if len(val_bytes) > 0:
                charset = val_bytes[0]
                raw_txt = val_bytes[1:]
                if charset == 0:
                    results.append(raw_txt.decode('utf-8', errors='replace'))
                elif charset == 4:
                    results.append(raw_txt.decode('utf-16-be', errors='replace'))
                else:
                    results.append(raw_txt.decode('latin-1', errors='replace'))
            else:
                results.append("")
        elif tag_num == 8:  # Bit String (e.g., Status_Flags)
            if len(val_bytes) >= 2:
                unused_bits = val_bytes[0]
                if unused_bits > 7: raise ValueError('Invalid unused bit count')
                total_bits = (len(val_bytes) - 1) * 8 - unused_bits
                bits = [bool((val_bytes[1 + i // 8] >> (7 - i % 8)) & 1) for i in range(total_bits)]
                results.append(("BITSTRING", bits))
            else:
                results.append(("BITSTRING", []))
        elif tag_num == 9:  # Enumerated
            e_val = int.from_bytes(val_bytes, byteorder='big', signed=False)
            results.append(("ENUM", e_val))
        elif tag_num == 10 and len(val_bytes) == 4:  # Date
            yr = 1900 + val_bytes[0]
            mo, dy, dow = val_bytes[1], val_bytes[2], val_bytes[3]
            results.append(f"{yr:04d}-{mo:02d}-{dy:02d} (DOW:{dow})")
        elif tag_num == 11 and len(val_bytes) == 4:  # Time
            hr, mn, sc, hd = val_bytes[0], val_bytes[1], val_bytes[2], val_bytes[3]
            results.append(f"{hr:02d}:{mn:02d}:{sc:02d}.{hd:02d}")
        elif tag_num == 12 and len(val_bytes) == 4:  # BACnetObjectIdentifier
            raw_id = struct.unpack('>I', val_bytes)[0]
            otype = (raw_id >> 22) & 0x3FF
            oinst = raw_id & 0x3FFFFF
            results.append(("OBJ_ID", otype, oinst))
        else:
            results.append(f"TAG_{tag_num}[{val_bytes.hex().upper()}]")

    return results

def extract_context_block(apdu_body, target_tag_num):
    """Extracts the byte slice enclosed between Opening Tag [target_tag_num] and Closing Tag [target_tag_num]."""
    idx, stack, start = 0, [], None
    while idx < len(apdu_body):
        first = apdu_body[idx]; pos = idx; idx += 1
        tag, context, lvt = first >> 4, bool(first & 8), first & 7
        if tag == 15:
            if idx >= len(apdu_body): return None
            tag = apdu_body[idx]; idx += 1
        if context and lvt == 6:
            stack.append(tag)
            if tag == target_tag_num and start is None: start = idx
            continue
        if context and lvt == 7:
            if not stack or stack.pop() != tag: return None
            if tag == target_tag_num and not stack and start is not None:
                return apdu_body[start:pos] if idx == len(apdu_body) else None
            continue
        length = 0 if not context and tag == 1 else lvt
        if lvt == 5:
            if idx >= len(apdu_body): return None
            length = apdu_body[idx]; idx += 1
            if length >= 254:
                width = 2 if length == 254 else 4
                if idx + width > len(apdu_body): return None
                length = int.from_bytes(apdu_body[idx:idx+width], 'big'); idx += width
        if lvt in (6, 7) or idx + length > len(apdu_body): return None
        idx += length
    return None


def resolve_identifier(text, names, maximum):
    """Resolve known names or explicit numbers; never fall back to a different target."""
    text = str(text).strip().lower()
    if text in names:
        return names[text]
    try:
        value = int(text, 0) if text.startswith(('0x', '0o', '0b')) else int(text, 10)
    except ValueError:
        raise ValueError(f'Unknown BACnet identifier: {text!r}') from None
    if not 0 <= value <= maximum:
        raise ValueError('BACnet identifier out of range')
    return value

def format_decoded_value(decoded_list, prop_id=None, obj_type=None):
    """Formats decoded ASN.1 values into human-readable industrial engineering strings."""
    if not decoded_list:
        return "Empty"

    formatted_items = []
    for item in decoded_list:
        if isinstance(item, tuple):
            kind = item[0]
            if kind == "OBJ_ID":
                _, otype, oinst = item
                tname = OBJECT_TYPE_NAMES.get(otype, f"Type-{otype}")
                formatted_items.append(f"{tname}:{oinst}")
            elif kind == "ENUM":
                eval_num = item[1]
                if prop_id == 117:  # Engineering Units
                    formatted_items.append(f"{ENGINEERING_UNITS.get(eval_num, f'Unit-{eval_num}')} ({eval_num})")
                elif prop_id == 85 and obj_type in (3, 4, 5):  # Binary Present_Value
                    formatted_items.append("ACTIVE (1)" if eval_num == 1 else "INACTIVE (0)")
                elif prop_id == 112:  # System_Status
                    st_map = {0: "OPERATIONAL (0)", 1: "OPERATIONAL-READ-ONLY (1)", 2: "DOWNLOAD-REQUIRED (2)", 3: "DOWNLOAD-IN-PROGRESS (3)", 4: "NON-OPERATIONAL (4)", 5: "BACKUP-IN-PROGRESS (5)"}
                    formatted_items.append(st_map.get(eval_num, f"Status-{eval_num}"))
                else:
                    formatted_items.append(f"{eval_num}")
            elif kind == "BITSTRING":
                bits = item[1]
                if prop_id == 111 and len(bits) >= 4:  # Status_Flags
                    flags = []
                    if bits[0]: flags.append("IN_ALARM")
                    if bits[1]: flags.append("FAULT")
                    if bits[2]: flags.append("OVERRIDDEN")
                    if bits[3]: flags.append("OUT_OF_SERVICE")
                    formatted_items.append("NORMAL (0000)" if not flags else " | ".join(flags))
                else:
                    formatted_items.append("".join("1" if b else "0" for b in bits))
        else:
            formatted_items.append(str(item))

    return formatted_items[0] if len(formatted_items) == 1 else ", ".join(formatted_items)


# --- 4. NATIVE RAW SOCKET BACNET/IP CLIENT ---
class RawBACnetClient:
    BVLC_TYPE = 0x81
    BVLC_UNICAST = 0x0A
    BVLC_BROADCAST = 0x0B

    def __init__(self, host, port=47808, timeout=3.0, retries=2, dnet=None, dadr=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.dnet = dnet
        self.dadr = dadr
        self.sock = None
        self.invoke_id = 1
        self.last_outcome = 'NOT_SENT'

    def connect(self):
        if self.sock is not None:
            return True
        candidate = None
        try:
            candidate = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            candidate.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            candidate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            candidate.settimeout(self.timeout)
            self.sock = candidate
            return True
        except OSError as e:
            logger.error(f"[SOCKET ERROR] Could not initialize UDP socket: {e}")
            return False
        finally:
            if candidate is not None and self.sock is not candidate:
                try:
                    candidate.close()
                except Exception as cleanup_error:
                    logger.error(f"[SOCKET CLEANUP ERROR] Could not close initialization candidate: {cleanup_error}")

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            finally:
                self.sock = None

    def _build_npdu(self, expecting_reply=True):
        """Builds the BACnet NPDU header, optionally inserting DNET/DADR routing fields."""
        version = 0x01
        control = 0x04 if expecting_reply else 0x00

        if self.dnet is not None:
            control |= 0x20  # Destination Specifier present
            dnet_bytes = struct.pack('>H', int(self.dnet))
            if self.dadr is not None:
                clean_hex = str(self.dadr).replace(":", "").replace("-", "").replace("0x", "")
                if len(clean_hex) % 2 != 0:
                    clean_hex = "0" + clean_hex
                dadr_bytes = bytes.fromhex(clean_hex)
            else:
                dadr_bytes = b''
            dlen_byte = struct.pack('>B', len(dadr_bytes))
            hop_count = b'\xFF'
            return struct.pack('>BB', version, control) + dnet_bytes + dlen_byte + dadr_bytes + hop_count

        return struct.pack('>BB', version, control)

    def _build_bvlc(self, npdu_and_apdu, is_broadcast=False):
        func = self.BVLC_BROADCAST if is_broadcast else self.BVLC_UNICAST
        total_len = 4 + len(npdu_and_apdu)
        return struct.pack('>BBH', self.BVLC_TYPE, func, total_len) + npdu_and_apdu

    def _strip_bvlc_and_npdu(self, packet):
        """Parses BVLL and NPDU headers, returning (apdu_bytes, snet, sadr_hex)."""
        if (len(packet) < 6 or packet[0] != 0x81 or packet[1] not in (4, 10, 11)
                or int.from_bytes(packet[2:4], 'big') != len(packet)):
            return None, None, None

        bvlc_func = packet[1]
        # Forwarded-NPDU (0x04) has a 6-byte originating IP:Port after the 4-byte BVLC header
        idx = 10 if bvlc_func == 0x04 else 4
        if idx + 2 > len(packet):
            return None, None, None

        npdu_ver = packet[idx]
        npdu_ctrl = packet[idx + 1]
        idx += 2

        if npdu_ver != 0x01 or (npdu_ctrl & 0xD0):
            # Ignore pure Network Layer control messages
            return None, None, None

        snet, sadr_hex = None, None
        # Destination specifier present (Bit 5 = 0x20)
        if npdu_ctrl & 0x20:
            if idx + 3 > len(packet): return None, None, None
            dlen = packet[idx + 2]
            idx += 3 + dlen
            if idx >= len(packet): return None, None, None

        # Source specifier present (Bit 3 = 0x08)
        if npdu_ctrl & 0x08:
            if idx + 3 > len(packet): return None, None, None
            snet = struct.unpack('>H', packet[idx:idx+2])[0]
            slen = packet[idx + 2]
            if slen == 0 or idx + 3 + slen > len(packet): return None, None, None
            sadr_bytes = packet[idx + 3 : idx + 3 + slen]
            sadr_hex = sadr_bytes.hex().upper()
            idx += 3 + slen

        # If Destination specifier was present, 1 byte Hop Count follows Source Specifier
        if npdu_ctrl & 0x20:
            idx += 1

        return (packet[idx:], snet, sadr_hex) if idx < len(packet) else (None, None, None)

    def send_Confirmed_Request(self, service_choice, service_data, suppress_logs=False):
        """Bounded confirmed transaction; consequential requests are never replayed."""
        self.last_outcome = 'NOT_SENT'
        inv_id = self.invoke_id
        self.invoke_id = (inv_id + 1) % 256
        apdu_hdr = struct.pack('>BBBB', 0x02, 0x05, inv_id, service_choice)
        frame = self._build_bvlc(self._build_npdu(True) + apdu_hdr + service_data)
        peer = (socket.gethostbyname(self.host), self.port)
        attempts = self.retries + 1 if service_choice == 12 else 1
        for attempt in range(attempts):
            assembled = bytearray()
            next_seq, previous, segments = 0, None, 0
            deadline = time.monotonic() + self.timeout
            try:
                # Password-bearing DeviceCommunicationControl/Reinitialize packets are redacted.
                if service_choice not in (17, 20): logger.debug('TX BACnet: %s', frame.hex())
                self.last_outcome = 'INDETERMINATE'
                self.sock.sendto(frame, (self.host, self.port))
                while time.monotonic() < deadline:
                    self.sock.settimeout(max(.001, deadline - time.monotonic()))
                    raw, addr = self.sock.recvfrom(65535)
                    if addr != peer: continue
                    if len(raw) >= 10 and raw[1] == 4:
                        origin = (socket.inet_ntoa(raw[4:8]), int.from_bytes(raw[8:10], 'big'))
                        if origin != peer: continue
                    apdu, snet, sadr = self._strip_bvlc_and_npdu(raw)
                    if self.dnet is not None:
                        expected = bytes.fromhex(str(self.dadr).replace(':', '').replace('-', '').replace('0x', '')) if self.dadr else None
                        if snet != self.dnet or expected is not None and sadr != expected.hex().upper(): continue
                    if not apdu or len(apdu) < 3 or apdu[1] != inv_id: continue
                    kind, flags = apdu[0] & 0xF0, apdu[0] & 15
                    if kind in (0x20, 0x30, 0x50):
                        service_pos = 4 if kind == 0x30 and flags & 8 else 2
                        if len(apdu) <= service_pos or apdu[service_pos] != service_choice: continue
                    if kind == 0x20:
                        if flags or len(apdu) != 3 or service_choice == 12: continue
                        self.last_outcome = 'PROTOCOL_ACCEPTED'
                        return b'SIMPLE_ACK'
                    if kind == 0x30:
                        if service_choice != 12 or flags & 3 or flags & 4 and not flags & 8: continue
                        if not flags & 8:
                            if segments: return None
                            self.last_outcome = 'PROTOCOL_ACCEPTED'
                            return apdu[3:]
                        seq, window = apdu[2], apdu[3]
                        if not 1 <= window <= 127: return None
                        if previous is not None and seq == ((next_seq - 1) & 255):
                            if apdu != previous: return None
                        else:
                            if seq != next_seq: return None
                            assembled.extend(apdu[5:]); segments += 1
                            if len(assembled) > 1048576 or segments > 4096: return None
                            next_seq = (next_seq + 1) & 255
                            previous = apdu
                        ack = struct.pack('>BBBB', 0x40, inv_id, seq, window)
                        self.sock.sendto(self._build_bvlc(self._build_npdu(False) + ack), (self.host, self.port))
                        if not flags & 4:
                            self.last_outcome = 'PROTOCOL_ACCEPTED'
                            return bytes(assembled)
                    elif kind in (0x50, 0x60, 0x70):
                        self.last_outcome = 'REJECTED'
                        if not suppress_logs: logger.error('BACnet rejected request: %s', apdu.hex())
                        return None
            except socket.timeout:
                pass
            except (OSError, ValueError) as exc:
                if not suppress_logs: logger.error('BACnet transaction failed: %s', exc)
                return None
            finally:
                self.sock.settimeout(self.timeout)
        if not suppress_logs: logger.error('INDETERMINATE: no correlated BACnet response')
        return None

    # --- Standard BACnet Services ---
    def who_is(self, low_limit=None, high_limit=None, broadcast=True, listen_time=2.5):
        """Sends Unconfirmed Who-Is (Service 0x08) and collects I-Am (Service 0x00) responses."""
        payload = b''
        if low_limit is not None and high_limit is not None:
            payload = encode_context_unsigned(0, low_limit) + encode_context_unsigned(1, high_limit)

        apdu = struct.pack('>BB', 0x10, 0x08) + payload
        npdu = self._build_npdu(expecting_reply=False)
        frame = self._build_bvlc(npdu + apdu, is_broadcast=broadcast)

        logger.debug(f"TX Who-Is ({self.host}:{self.port}): {frame.hex().upper()}")
        self.sock.sendto(frame, (self.host, self.port))

        discovered = []
        seen = set()
        deadline = time.time() + listen_time

        peer = (socket.gethostbyname(self.host), self.port) if not broadcast else None
        while time.time() < deadline:
            try:
                self.sock.settimeout(max(0.2, deadline - time.time()))
                raw_pkt, addr = self.sock.recvfrom(4096)
                if peer is not None and addr != peer: continue
                if peer is not None and len(raw_pkt) >= 10 and raw_pkt[1] == 4:
                    origin = (socket.inet_ntoa(raw_pkt[4:8]), int.from_bytes(raw_pkt[8:10], 'big'))
                    if origin != peer: continue
                rx_apdu, snet, sadr = self._strip_bvlc_and_npdu(raw_pkt)
                if self.dnet is not None and snet != self.dnet: continue
                if self.dadr is not None:
                    expected = bytes.fromhex(self.dadr.replace(':', '').replace('-', '').replace('0x', '')).hex().upper()
                    if sadr != expected: continue
                if not rx_apdu or len(rx_apdu) < 2:
                    continue
                # Check for Unconfirmed-Request (0x10) + I-Am (0x00)
                if rx_apdu[0] == 0x10 and rx_apdu[1] == 0x00:
                    tags = decode_application_tags(rx_apdu[2:])
                    if len(tags) == 4 and isinstance(tags[0], tuple) and tags[0][:2] == ("OBJ_ID", 8):
                        dev_inst = tags[0][2]
                        max_apdu = tags[1]
                        seg_supp = tags[2][1] if isinstance(tags[2], tuple) else tags[2]
                        vendor_id = tags[3]
                        key = (addr[0], dev_inst, snet, sadr)
                        if key not in seen:
                            seen.add(key)
                            discovered.append({
                                "ip": addr[0],
                                "port": addr[1],
                                "device_id": dev_inst,
                                "max_apdu": max_apdu,
                                "segmentation": seg_supp,
                                "vendor_id": vendor_id,
                                "snet": snet,
                                "sadr": sadr
                            })
            except socket.timeout:
                break
            except Exception:
                continue

        self.sock.settimeout(self.timeout)
        return discovered

    def read_property(self, obj_type, instance, prop_id, array_index=None, suppress_logs=False):
        """Executes ReadProperty (Service Choice 12 / 0x0C) and returns decoded ASN.1 values."""
        req = encode_context_object_id(0, obj_type, instance)
        req += encode_context_unsigned(1, prop_id)
        if array_index is not None:
            req += encode_context_unsigned(2, array_index)

        ack_body = self.send_Confirmed_Request(0x0C, req, suppress_logs=suppress_logs)
        if not ack_body:
            return None

        if not ack_body.startswith(req + encode_opening_tag(3)):
            self.last_outcome = 'FAILED'
            return None
        val_block = extract_context_block(ack_body, 3)
        if val_block is None:
            self.last_outcome = 'FAILED'
            return None

        try:
            return decode_application_tags(val_block)
        except ValueError as exc:
            self.last_outcome = 'FAILED'
            logger.error('Malformed ReadProperty ACK: %s', exc)
            return None

    def write_property(self, obj_type, instance, prop_id, value_str, val_type="auto", priority=8, array_index=None):
        """Executes WriteProperty (Service Choice 15 / 0x0F) with Command Priority (1..16)."""
        if priority is not None and not 1 <= int(priority) <= 16: raise ValueError('Priority out of range')
        req = encode_context_object_id(0, obj_type, instance)
        req += encode_context_unsigned(1, prop_id)
        if array_index is not None:
            req += encode_context_unsigned(2, array_index)

        encoded_val = encode_application_value(value_str, val_type=val_type, obj_type=obj_type)
        req += encode_opening_tag(3) + encoded_val + encode_closing_tag(3)

        if priority is not None and 1 <= int(priority) <= 16:
            req += encode_context_unsigned(4, int(priority))

        ack = self.send_Confirmed_Request(0x0F, req)
        return ack == b'SIMPLE_ACK'

    def device_communication_control(self, state_Action, duration_min=None, password=None):
        """Executes DeviceCommunicationControl (Service Choice 17 / 0x11)."""
        state_map = {"enable": 0, "disable": 1, "disable-initiation": 2}
        req = b''
        if duration_min is not None:
            req += encode_context_unsigned(0, int(duration_min))
        if state_Action not in state_map: raise ValueError('Unknown communication control action')
        req += encode_context_enumerated(1, state_map[state_Action])
        if password:
            req += encode_context_string(2, password)

        ack = self.send_Confirmed_Request(0x11, req)
        return ack == b'SIMPLE_ACK'

    def reinitialize_device(self, reinit_state="warmstart", password=None):
        """Executes ReinitializeDevice (Service Choice 20 / 0x14)."""
        state_map = {"coldstart": 0, "warmstart": 1}
        if reinit_state not in state_map: raise ValueError('Unknown reinitialization action')
        req = encode_context_enumerated(0, state_map[reinit_state])
        if password:
            req += encode_context_string(1, password)

        ack = self.send_Confirmed_Request(0x14, req)
        return ack == b'SIMPLE_ACK'


# --- 5. COMMAND EXECUTION LOGIC ---
def resolve_device_instance(client, args):
    """Auto-discovers target Device Instance via Unicast Who-Is if not explicitly passed via -d."""
    if args.device_id is not None:
        return args.device_id
    logger.info(f"Auto-discovering BACnet Device Instance on {args.host}:{args.port}...")
    devs = client.who_is(broadcast=False, listen_time=1.8)
    if devs:
        found_id = devs[0]["device_id"]
        logger.info(f"{Color.GREEN}[AUTO-DISCOVERED]{Color.RESET} Device Instance ID: {found_id} (Vendor ID: {devs[0]['vendor_id']})")
        return found_id
    logger.error("Could not auto-discover Device Instance ID. Please specify it explicitly using '-d / --device-id'.")
    return None

def do_whois(client, args):
    is_bcast = args.host.endswith(".255") or args.host == "255.255.255.255" or args.broadcast
    mode_lbl = "BROADCAST" if is_bcast else "UNICAST"
    logger.info(f"Sending BACnet Who-Is ({mode_lbl}) to {args.host}:{args.port}...")

    devices = client.who_is(low_limit=args.low_limit, high_limit=args.high_limit, broadcast=is_bcast, listen_time=args.timeout)
    print(f"\n{Color.CYAN}{Color.BOLD}--- BACNET/IP WHO-IS DISCOVERY RESULTS ({len(devices)}) ---{Color.RESET}")
    if not devices:
        print(f" {Color.YELLOW}No BACnet I-Am responses received.{Color.RESET}\n")
        return False

    print(f" {'IP:PORT':<21} | {'DEVICE ID':<10} | {'VENDOR ID':<10} | {'MAX APDU':<9} | {'ROUTING (SNET / SADR)'}")
    print(f" {'-'*21}-+-{'-'*10}-+-{'-'*10}-+-{'-'*9}-+-{'-'*24}")
    for d in devices:
        route_str = f"DNET={d['snet']} DADR={d['sadr']}" if d['snet'] is not None else "Direct BACnet/IP"
        print(
            f" {Color.CYAN}{d['ip'] + ':' + str(d['port']):<21}{Color.RESET} | "
            f"{Color.GREEN}{d['device_id']:<10}{Color.RESET} | "
            f"{Color.YELLOW}{d['vendor_id']:<10}{Color.RESET} | "
            f"{d['max_apdu']:<9} | "
            f"{Color.GREY}{route_str}{Color.RESET}"
        )
    print()
    return True

def do_fingerprint(client, args):
    dev_id = resolve_device_instance(client, args)
    if dev_id is None:
        return False

    logger.info(f"Querying BACnet Device Object (Device:{dev_id}) Identity & Diagnostic Properties...")
    props_to_query = [
        ("Object Name",                  77),
        ("Vendor Name",                  121),
        ("Vendor Identifier",            120),
        ("Model Name",                   70),
        ("Firmware Revision",            44),
        ("Application Software Version", 12),
        ("System Status",                112),
        ("Location",                     58),
        ("Description",                  28),
        ("Protocol Version",             98),
        ("Protocol Revision",            139),
        ("Max APDU Length Accepted",     62),
    ]

    print(f"\n{Color.CYAN}{Color.BOLD}--- BACNET CONTROLLER FINGERPRINT (Device:{dev_id}) ---{Color.RESET}")
    observed = 0
    for label, pid in props_to_query:
        res = client.read_property(8, dev_id, pid, suppress_logs=True)
        if res is not None:
            observed += 1
            val_str = format_decoded_value(res, prop_id=pid, obj_type=8)
            print(f"  {Color.BLUE}{label:<30}:{Color.RESET} {Color.GREEN}{val_str}{Color.RESET}")
    print()
    return observed > 0

def do_objects(client, args):
    dev_id = resolve_device_instance(client, args)
    if dev_id is None:
        return False

    logger.info(f"Retrieving Object_List (Property 76) from Device:{dev_id}...")
    obj_list = client.read_property(8, dev_id, 76, suppress_logs=True)

    # Fallback: If Object_List is too large for a single APDU and segmentation is unsupported, read index 0 (count) then 1..N
    if not obj_list:
        logger.info("Bulk Object_List read failed or segmented. Falling back to indexed array reading (Index 0..N)...")
        cnt_res = client.read_property(8, dev_id, 76, array_index=0, suppress_logs=True)
        if cnt_res and isinstance(cnt_res[0], int):
            total_objs = cnt_res[0]
            if not 0 <= total_objs <= 65536:
                logger.error('Object_List exceeds bounded inventory limit (65536)')
                return False
            logger.info(f"Device reports {total_objs} objects. Reading entries individually...")
            obj_list = []
            for idx in range(1, total_objs + 1):
                entry = client.read_property(8, dev_id, 76, array_index=idx, suppress_logs=True)
                if entry:
                    obj_list.extend(entry)

    if not obj_list:
        logger.error("Failed to retrieve Object_List from target controller.")
        return False

    print(f"\n{Color.CYAN}{Color.BOLD}--- BACNET OBJECT INVENTORY (Device:{dev_id} | Total: {len(obj_list)}) ---{Color.RESET}")
    print(f" {'OBJECT IDENTIFIER':<28} | {'OBJECT NAME':<26} | {'PRESENT VALUE':<20} | {'UNITS / STATUS'}")
    print(f" {'-'*28}-+-{'-'*26}-+-{'-'*20}-+-{'-'*24}")

    for item in obj_list:
        if not (isinstance(item, tuple) and item[0] == "OBJ_ID"):
            continue
        _, otype, oinst = item
        type_str = OBJECT_TYPE_NAMES.get(otype, f"Type-{otype}")
        obj_id_str = f"{type_str}:{oinst}"

        name_res = client.read_property(otype, oinst, 77, suppress_logs=True)
        name_str = format_decoded_value(name_res) if name_res else "N/A"

        if otype == 8:
            pv_str = "DEVICE_ROOT"
            unit_str = "ONLINE"
        else:
            pv_res = client.read_property(otype, oinst, 85, suppress_logs=True)
            pv_str = format_decoded_value(pv_res, prop_id=85, obj_type=otype) if pv_res else "N/A"

            unit_res = client.read_property(otype, oinst, 117, suppress_logs=True)
            unit_str = format_decoded_value(unit_res, prop_id=117) if unit_res else ""
            if not unit_str:
                sf_res = client.read_property(otype, oinst, 111, suppress_logs=True)
                unit_str = format_decoded_value(sf_res, prop_id=111) if sf_res else "N/A"

        print(
            f" {Color.YELLOW}{obj_id_str:<28}{Color.RESET} | "
            f"{Color.BLUE}{name_str[:26]:<26}{Color.RESET} | "
            f"{Color.GREEN}{str(pv_str)[:20]:<20}{Color.RESET} | "
            f"{Color.GREY}{unit_str}{Color.RESET}"
        )
    print()
    return True

def do_read(client, args):
    otype = resolve_identifier(args.obj_type, OBJECT_TYPES, 1023)
    pid = resolve_identifier(args.prop, PROPERTY_IDS, 4194303)
    tname = OBJECT_TYPE_NAMES.get(otype, f"Type-{otype}")
    pname = PROPERTY_NAMES.get(pid, f"Property-{pid}")

    logger.info(f"Reading BACnet [{tname}, Instance: {args.instance}, Property: {pname} ({pid})]...")
    decoded = client.read_property(otype, args.instance, pid, array_index=args.index)
    if decoded is None:
        logger.error("Failed to read property from BACnet controller.")
        return False

    val_str = format_decoded_value(decoded, prop_id=pid, obj_type=otype)
    print(f"\n{Color.CYAN}{Color.BOLD}--- BACNET READ PROPERTY RESPONSE ---{Color.RESET}")
    print(f"  {Color.BLUE}Object:{Color.RESET}         {Color.YELLOW}{tname} (Instance {args.instance}){Color.RESET}")
    print(f"  {Color.BLUE}Property:{Color.RESET}       {pname} (ID: {pid})")
    if args.index is not None:
        print(f"  {Color.BLUE}Array Index:{Color.RESET}    {args.index}")
    print(f"  {Color.BLUE}Decoded Value:{Color.RESET}  {Color.GREEN}{Color.BOLD}{val_str}{Color.RESET}\n")
    return True

def do_priority_array(client, args):
    otype = resolve_identifier(args.obj_type, OBJECT_TYPES, 1023)
    tname = OBJECT_TYPE_NAMES.get(otype, f"Type-{otype}")

    logger.info(f"Reading 16-Level Priority_Array (Property 87) for {tname}:{args.instance}...")
    pa_list = client.read_property(otype, args.instance, 87)
    rel_def = client.read_property(otype, args.instance, 104, suppress_logs=True)
    pv_list = client.read_property(otype, args.instance, 85, suppress_logs=True)

    if pa_list is None:
        logger.error("Object does not support Priority_Array (Property 87) or is not commandable.")
        return False

    print(f"\n{Color.CYAN}{Color.BOLD}--- BACNET COMMAND PRIORITY ARRAY ({tname}:{args.instance}) ---{Color.RESET}")
    if pv_list:
        print(f" {Color.BOLD}Active Present_Value (85):{Color.RESET}  {Color.GREEN}{format_decoded_value(pv_list, 85, otype)}{Color.RESET}")
    if rel_def:
        print(f" {Color.BOLD}Relinquish_Default (104):{Color.RESET}   {Color.BLUE}{format_decoded_value(rel_def, 85, otype)}{Color.RESET}\n")

    print(f" {'PRIORITY LEVEL':<36} | {'COMMAND VALUE'}")
    print(f" {'-'*36}-+-{'-'*28}")
    for lvl in range(1, 17):
        lvl_name = PRIORITY_LEVEL_NAMES.get(lvl, f"Level {lvl}")
        raw_item = pa_list[lvl - 1] if (lvl - 1) < len(pa_list) else "UNKNOWN (entry not observed)"
        val_s = format_decoded_value([raw_item], prop_id=85, obj_type=otype)
        if val_s == "NULL":
            print(f" {Color.GREY}{lvl_name:<36} | NULL (Relinquished){Color.RESET}")
        elif str(raw_item).startswith('UNKNOWN'):
            print(f" {Color.YELLOW}{lvl_name:<36} | {val_s}{Color.RESET}")
        else:
            print(f" {Color.YELLOW}{Color.BOLD}{lvl_name:<36}{Color.RESET} | {Color.GREEN}{Color.BOLD}{val_s} [VALUE PRESENT]{Color.RESET}")
    print()
    return True

def do_write(client, args):
    otype = resolve_identifier(args.obj_type, OBJECT_TYPES, 1023)
    pid = resolve_identifier(args.prop, PROPERTY_IDS, 4194303)
    tname = OBJECT_TYPE_NAMES.get(otype, f"Type-{otype}")
    pname = PROPERTY_NAMES.get(pid, f"Property-{pid}")

    val_to_write = "null" if args.relinquish else args.value
    vtype_to_use = "null" if args.relinquish else args.type

    action_desc = "RELINQUISH (NULL)" if args.relinquish else f"WRITE VALUE '{val_to_write}'"
    logger.warning(
        f"EXECUTING OT BACNET {action_desc} - "
        f"Object: {tname}:{args.instance}, Property: {pname} ({pid}), Priority: {args.priority}"
    )

    if client.write_property(otype, args.instance, pid, val_to_write, val_type=vtype_to_use, priority=args.priority, array_index=args.index):
        print(f"\n{Color.GREEN}{Color.BOLD}[SUCCESS]{Color.RESET} WriteProperty accepted (Simple-ACK) on {tname}:{args.instance} (Priority {args.priority}).")
        verify = client.read_property(otype, args.instance, pid, array_index=args.index, suppress_logs=True)
        if verify is not None:
            print(f" {Color.BOLD}READBACK_OBSERVED:{Color.RESET} {Color.GREEN}{format_decoded_value(verify, pid, otype)}{Color.RESET}\n")
    else:
        logger.error("BACnet WriteProperty failed or was rejected by the controller.")
        return False
    return True

def do_watch(client, args):
    otype = resolve_identifier(args.obj_type, OBJECT_TYPES, 1023)
    tname = OBJECT_TYPE_NAMES.get(otype, f"Type-{otype}")
    logger.info(f"Starting WATCH mode for {tname}:{args.instance} (Polling interval: {args.wait}s)...")
    print(f"{Color.GREY}Monitoring Present_Value (85) & Status_Flags (111) | Press Ctrl+C to stop.{Color.RESET}\n")

    prev_tuple = None
    while True:
        pv_res = client.read_property(otype, args.instance, 85, suppress_logs=True)
        sf_res = client.read_property(otype, args.instance, 111, suppress_logs=True)
        if pv_res is not None:
            pv_str = format_decoded_value(pv_res, prop_id=85, obj_type=otype)
            sf_str = format_decoded_value(sf_res, prop_id=111) if sf_res else "UNKNOWN"
            cur_tuple = (pv_str, sf_str)
            if cur_tuple != prev_tuple:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                sf_color = Color.GREEN if "NORMAL" in sf_str else Color.YELLOW
                print(
                    f"{Color.CYAN}[{ts}]{Color.RESET} {Color.YELLOW}{tname}:{args.instance}{Color.RESET} -> "
                    f"Present_Value: {Color.GREEN}{Color.BOLD}{pv_str}{Color.RESET} | "
                    f"Status_Flags: {sf_color}{sf_str}{Color.RESET}"
                )
                prev_tuple = cur_tuple
        time.sleep(args.wait)

def do_control(client, args):
    logger.warning(f"EXECUTING OT BACNET DEVICE CONTROL - Action: {args.action.upper()}, Target: {args.host}:{args.port}")
    if args.action in ("enable", "disable", "disable-initiation"):
        ok = client.device_communication_control(args.action, duration_min=args.duration, password=args.password)
    else:
        ok = client.reinitialize_device(args.action, password=args.password)

    if ok:
        print(f"\n{Color.GREEN}{Color.BOLD}[SUCCESS]{Color.RESET} Controller accepted '{args.action.upper()}' command (Simple-ACK).\n")
    else:
        logger.error(f"Controller did not confirm acceptance of '{args.action.upper()}' command.")
    return ok


# --- 6. MAIN ENTRY POINT ---
def main():
    desc_text = f"{Color.BOLD}BACnet/IP (ASHRAE 135) Master CLI (by z4y_d3n){Color.RESET}\n"
    custom_usage = (
        f"{Color.GREEN}bacnet_master.py{Color.RESET} "
        f"{Color.YELLOW}[-H HOST] [-c COMMAND] [-p PORT] [-d DEVICE_ID] "
        f"[-o OBJ_TYPE] [-i INSTANCE] [-P PROPERTY] [-v VALUE] [--priority PRIO] [--relinquish]{Color.RESET}"
    )

    parser = CustomArgumentParser(description=desc_text, usage=custom_usage, formatter_class=ColoredHelpFormatter)

    parser.add_argument("-H", "--host", required=True, type=str, help="Target IP or Broadcast IP (e.g., 192.168.1.50 or 192.168.1.255).")
    parser.add_argument("-c", "--command", required=True, choices=[
        "whois", "fingerprint", "objects", "read", "write", "priority-array", "watch", "control"
    ], help="BACnet protocol action to execute.")
    parser.add_argument("-p", "--port", type=int, default=47808, help="UDP BACnet/IP Port (Default: 47808 / 0xBAC0).")
    parser.add_argument("--timeout", type=float, default=3.0, help="UDP response timeout in seconds (Default: 3.0).")
    parser.add_argument("--debug", action="store_true", help="Enable raw Hex BVLL/NPDU/APDU trace logs.")

    obj_group = parser.add_argument_group(f"{Color.CYAN}BACnet Object & Property Addressing Options{Color.RESET}")
    obj_group.add_argument("-d", "--device-id", type=int, default=None, help="Target Device Instance ID (Auto-discovered if omitted).")
    obj_group.add_argument("-o", "--obj-type", type=str, default="av", help="Object Type: ai, ao, av, bi, bo, bv, msi, mso, msv, dev (Default: av).")
    obj_group.add_argument("-i", "--instance", type=int, default=None, help="Object Instance number (e.g., 0, 1, 100).")
    obj_group.add_argument("-P", "--prop", type=str, default="present-value", help="Property name or numeric ID (Default: present-value / 85).")
    obj_group.add_argument("--index", type=int, default=None, help="Optional BACnet Property Array Index.")

    write_group = parser.add_argument_group(f"{Color.CYAN}Write, Priority Array & Relinquish Options (-c write){Color.RESET}")
    write_group.add_argument("-v", "--value", type=str, help="Value to write (or 'null' to relinquish).")
    write_group.add_argument("-t", "--type", choices=["auto", "real", "double", "uint", "int", "enum", "bool", "string", "null"], default="auto", help="ASN.1 Application Tag data type (Default: auto).")
    write_group.add_argument("--priority", type=int, choices=range(1, 17), default=8, metavar="[1-16]", help="BACnet Command Priority Level 1..16 (Default: 8 = Manual Operator).")
    write_group.add_argument("--relinquish", action="store_true", help="Send Application Tag NULL to release manual override at selected --priority.")

    route_group = parser.add_argument_group(f"{Color.CYAN}Discovery, Routing & Device Control Options{Color.RESET}")
    route_group.add_argument("--broadcast", action="store_true", help="Force BVLC Original-Broadcast-NPDU (0x0B) during 'whois'.")
    route_group.add_argument("--low-limit", type=int, default=None, help="Who-Is Low Device Instance limit.")
    route_group.add_argument("--high-limit", type=int, default=None, help="Who-Is High Device Instance limit.")
    route_group.add_argument("--dnet", type=int, default=None, help="Destination BACnet Network Number (DNET) for routing behind BACnet routers.")
    route_group.add_argument("--dadr", type=str, default=None, help="Destination MAC Address in Hex (DADR, e.g., '05' for MS/TP node 5).")
    route_group.add_argument("-a", "--action", choices=["enable", "disable", "disable-initiation", "warmstart", "coldstart"], help="Control action for '-c control'.")
    route_group.add_argument("--password", type=str, default=None, help="Optional BACnet password for '-c control' (max 20 chars).")
    route_group.add_argument("--duration", type=int, default=None, help="Optional duration in minutes for 'disable' communication control.")
    route_group.add_argument("-w", "--wait", type=float, default=2.0, help="Polling interval in seconds for '-c watch' (Default: 2.0).")

    if len(sys.argv) == 1:
        parser.print_usage()
        sys.exit(1)

    parser.usage = argparse.SUPPRESS
    args = parser.parse_args()

    # --- Logical Validations ---
    try:
        resolve_identifier(args.obj_type, OBJECT_TYPES, 1023)
        resolve_identifier(args.prop, PROPERTY_IDS, 4194303)
        if not 1 <= args.port <= 65535 or not 0 < args.timeout < float('inf') or not 0 < args.wait < float('inf'):
            raise ValueError('Port, timeout or polling interval out of range')
        for value in (args.instance, args.device_id, args.low_limit, args.high_limit):
            if value is not None and not 0 <= value <= 4194303: raise ValueError('Instance out of range')
        if args.index is not None and not 0 <= args.index <= 4294967295: raise ValueError('Array index out of range')
        if (args.low_limit is None) != (args.high_limit is None): raise ValueError('Who-Is requires both bounds')
        if args.low_limit is not None and args.low_limit > args.high_limit: raise ValueError('Who-Is bounds reversed')
        if args.dnet is not None and not 1 <= args.dnet <= 65534: raise ValueError('DNET out of range')
        if args.dadr is not None:
            if args.dnet is None: raise ValueError('DADR requires DNET')
            raw = bytes.fromhex(args.dadr.replace(':', '').replace('-', '').replace('0x', ''))
            if not 1 <= len(raw) <= 255: raise ValueError('DADR length out of range')
        if args.duration is not None and not 0 <= args.duration <= 65535: raise ValueError('Duration out of range')
        if args.password and len(args.password.encode('utf-8')) > 20: raise ValueError('Password exceeds 20 octets')
    except ValueError as exc:
        parser.error(str(exc))
    if args.command in ("read", "write", "priority-array", "watch") and args.instance is None:
        parser.error(f"Argument -i / --instance is strictly required for the '{args.command}' command.")
    if args.command == "write" and not args.relinquish and args.value is None:
        parser.error("Argument -v / --value (or --relinquish) is strictly required for 'write'.")
    if args.command == "control" and not args.action:
        parser.error("Argument -a / --action is strictly required for 'control'.")

    setup_logger(args.debug)
    client = RawBACnetClient(
        args.host, port=args.port,
        timeout=args.timeout, retries=2,
        dnet=args.dnet, dadr=args.dadr
    )

    if not client.connect():
        sys.exit(1)

    route_info = f" | Route DNET:{args.dnet}/DADR:{args.dadr}" if args.dnet is not None else ""
    print(f"{Color.GREEN}{Color.BOLD}[UDP READY]{Color.RESET} {Color.CYAN}{args.host}:{args.port}{Color.RESET}{route_info} | Command: {Color.YELLOW}{args.command.upper()}{Color.RESET}\n")

    try:
        if args.command == "whois":
            result = do_whois(client, args)
        elif args.command == "fingerprint":
            result = do_fingerprint(client, args)
        elif args.command == "objects":
            result = do_objects(client, args)
        elif args.command == "read":
            result = do_read(client, args)
        elif args.command == "priority-array":
            result = do_priority_array(client, args)
        elif args.command == "write":
            result = do_write(client, args)
        elif args.command == "watch":
            result = do_watch(client, args)
        elif args.command == "control":
            result = do_control(client, args)
    finally:
        client.close()
    if result is False:
        sys.exit(1)

if __name__ == "__main__":
    main()
