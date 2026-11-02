#!/usr/bin/env python3
import sys
import signal
import argparse
import logging
import os
import struct
import socket
import time
import math
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

logger = logging.getLogger("IEC104MasterCLI")

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
        log_file = os.path.join(audit_dir, f"iec104_master_LAB_{datetime.now().strftime('%Y%m%d')}.log")

        file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler = logging.FileHandler(log_file)
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

# --- 2. IEC 60870-5-104 PROTOCOL CONSTANTS & HELPERS ---
ASDU_TYPES = {
    1:  ("M_SP_NA_1", "Single-point information"),
    3:  ("M_DP_NA_1", "Double-point information"),
    5:  ("M_ST_NA_1", "Step position information"),
    7:  ("M_BO_NA_1", "Bitstring of 32 bits"),
    9:  ("M_ME_NA_1", "Measured value, normalized"),
    11: ("M_ME_NB_1", "Measured value, scaled"),
    13: ("M_ME_NC_1", "Measured value, short float"),
    15: ("M_IT_NA_1", "Integrated totals"),
    30: ("M_SP_TB_1", "Single-point with CP56Time2a"),
    31: ("M_DP_TB_1", "Double-point with CP56Time2a"),
    32: ("M_ST_TB_1", "Step position with CP56Time2a"),
    33: ("M_BO_TB_1", "Bitstring of 32 bits with CP56Time2a"),
    34: ("M_ME_TD_1", "Measured value, normalized with CP56Time2a"),
    35: ("M_ME_TE_1", "Measured value, scaled with CP56Time2a"),
    36: ("M_ME_TF_1", "Measured value, short float with CP56Time2a"),
    37: ("M_IT_TB_1", "Integrated totals with CP56Time2a"),
    45: ("C_SC_NA_1", "Single command"),
    46: ("C_DC_NA_1", "Double command"),
    47: ("C_RC_NA_1", "Regulating step command"),
    48: ("C_SE_NA_1", "Set-point command, normalized"),
    49: ("C_SE_NB_1", "Set-point command, scaled"),
    50: ("C_SE_NC_1", "Set-point command, short float"),
    51: ("C_BO_NA_1", "Bitstring of 32 bits command"),
    70: ("M_EI_NA_1", "End of initialization"),
    100: ("C_IC_NA_1", "Interrogation command"),
    101: ("C_CI_NA_1", "Counter interrogation command"),
    102: ("C_RD_NA_1", "Read command"),
    103: ("C_CS_NA_1", "Clock synchronization command"),
    105: ("C_RP_NA_1", "Reset process command")
}

COT_NAMES = {
    1: "Periodic/Cyclic",
    2: "Background scan",
    3: "Spontaneous",
    4: "Initialized",
    5: "Requested",
    6: "Activation (act)",
    7: "Activation Confirmation (actcon)",
    8: "Deactivation (deact)",
    9: "Deactivation Confirmation (deactcon)",
    10: "Activation Termination (actterm)",
    20: "Interrogated by Station GI",
    37: "Interrogated by Counter GI",
    44: "Unknown Type ID",
    45: "Unknown Cause of Transmission (COT)",
    46: "Unknown Common Address of ASDU (CA)",
    47: "Unknown Information Object Address (IOA)"
}

def pack_ioa(ioa):
    """Packs a 24-bit Information Object Address (Little Endian)."""
    if not isinstance(ioa, int) or not 0 <= ioa <= 0xffffff:
        raise ValueError('IOA must be in 0..16777215')
    return ioa.to_bytes(3, 'little')

def unpack_ioa(data_3bytes):
    """Unpacks a 24-bit Information Object Address (Little Endian)."""
    return struct.unpack('<I', data_3bytes + b'\x00')[0]

def decode_qds(qds_byte):
    """Decodes IEC-104 Quality Descriptor (QDS) flags."""
    flags = []
    if qds_byte & 0x80: flags.append("IV(Invalid)")
    if qds_byte & 0x40: flags.append("NT(NotTopical)")
    if qds_byte & 0x20: flags.append("SB(Substituted)")
    if qds_byte & 0x10: flags.append("BL(Blocked)")
    if qds_byte & 0x01: flags.append("OV(Overflow)")
    return "GOOD" if not flags else "|".join(flags)

def encode_cp56time2a(dt=None):
    """Encodes a datetime object into a 7-byte IEC CP56Time2a structure."""
    if dt is None:
        dt = datetime.now()
    if not 2000 <= dt.year <= 2099:
        raise ValueError('CP56Time2a year must be in 2000..2099')
    ms = (dt.second * 1000) + (dt.microsecond // 1000)
    minute = dt.minute & 0x3F
    hour = dt.hour & 0x1F
    dow = dt.isoweekday() & 0x07
    day = (dow << 5) | (dt.day & 0x1F)
    month = dt.month & 0x0F
    year = (dt.year % 100) & 0x7F
    return struct.pack('<HBBBBB', ms, minute, hour, day, month, year)

def decode_cp56time2a(data_7bytes):
    """Decodes a 7-byte IEC CP56Time2a structure into an ISO string."""
    if len(data_7bytes) < 7:
        return "Invalid-Time"
    ms, minute, hour, day_dow, month, year = struct.unpack('<HBBBBB', data_7bytes[:7])
    sec = ms // 1000
    msec = ms % 1000
    invalid = bool(minute & 0x80)
    summer = bool(hour & 0x80)
    minute &= 0x3F
    hour &= 0x1F
    day = day_dow & 0x1F
    month &= 0x0F
    year = 2000 + (year & 0x7F)
    try:
        datetime(year, month, day, hour, minute, sec)
    except ValueError:
        return 'Invalid-Time'
    suffix = (' [IV]' if invalid else '') + (' [SU]' if summer else '')
    return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}.{msec:03d}{suffix}"


# --- 3. NATIVE RAW SOCKET IEC 60870-5-104 CLIENT ---
class RawIEC104Client:
    # U-Frame Control Constants
    STARTDT_ACT = b'\x68\x04\x07\x00\x00\x00'
    STARTDT_CON = b'\x68\x04\x0b\x00\x00\x00'
    STOPDT_ACT  = b'\x68\x04\x13\x00\x00\x00'
    STOPDT_CON  = b'\x68\x04\x23\x00\x00\x00'
    TESTFR_ACT  = b'\x68\x04\x43\x00\x00\x00'
    TESTFR_CON  = b'\x68\x04\x83\x00\x00\x00'

    def __init__(self, host, port=2404, timeout=3.0, retries=2, oa=1):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.oa = oa
        self.sock = None
        
        # Sequence numbers V(S) and V(R)
        self.vs = 0
        self.vr = 0
        self.unacked_rx = 0
        self.data_transfer_active = False
        self.va = 0
        self._rx_buffer = bytearray()
        self._last_request_asdu = None
        self._ack_pending_since = None

    def connect(self, suppress_logs=False):
        for attempt in range(self.retries + 1):
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.sock.connect((self.host, self.port))
                self.vs = 0
                self.va = 0
                self._rx_buffer.clear()
                self.data_transfer_active = False
                self.vr = 0
                self.unacked_rx = 0
                self._ack_pending_since = None
                if not suppress_logs:
                    logger.info(f"TCP Socket connected to {self.host}:{self.port}")
                return True
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                self.close()
                if attempt < self.retries and not suppress_logs:
                    logger.warning(f"[RETRY] Connection attempt {attempt + 1} failed ({e}). Retrying...")
                    time.sleep(1.0)
                elif attempt == self.retries and not suppress_logs:
                    logger.error(f"[CONNECTION ERROR] Failed to connect to {self.host}:{self.port} - {e}")
                    return False
        return False

    def close(self):
        if self.sock:
            if self.data_transfer_active:
                try:
                    self._send_raw(self.STOPDT_ACT)
                except Exception:
                    pass
                self.data_transfer_active = False
            try:
                self.sock.close()
            except Exception:
                pass
            finally:
                self.sock = None

    def _send_raw(self, frame):
        if not self.sock:
            raise ConnectionError("Socket is not connected.")
        logger.debug(f"TX: {frame.hex().upper()}")
        self.sock.sendall(frame)

    def _recv_exact(self, length):
        data = b''
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Remote controller closed the TCP connection.")
            data += chunk
        return data

    def recv_apdu(self, custom_timeout=None):
        """Collect one APDU; preserve partially received bytes across idle timeouts."""
        if not self.sock:
            return None
        prev_timeout = self.sock.gettimeout()
        timeout = self.timeout if custom_timeout is None else custom_timeout
        deadline = time.monotonic() + timeout
        try:
            while True:
                if len(self._rx_buffer) >= 2:
                    if self._rx_buffer[0] != 0x68 or not 4 <= self._rx_buffer[1] <= 253:
                        raise ValueError('Invalid IEC-104 start/length')
                    total = self._rx_buffer[1] + 2
                    if len(self._rx_buffer) >= total:
                        result = bytes(self._rx_buffer[:total])
                        del self._rx_buffer[:total]
                        logger.debug(f'RX: {result.hex().upper()}')
                        return result
                else:
                    total = 2
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self.sock.settimeout(remaining)
                chunk = self.sock.recv(total - len(self._rx_buffer))
                if not chunk:
                    raise ConnectionError('Remote controller closed TCP connection')
                self._rx_buffer.extend(chunk)
        except socket.timeout:
            return None
        except (ConnectionError, OSError, ValueError) as error:
            logger.error(f'[NETWORK/PROTOCOL ERROR] {error}')
            self.data_transfer_active = False
            self.close()
            self._rx_buffer.clear()
            return None
        finally:
            if self.sock:
                self.sock.settimeout(prev_timeout)

    def send_s_frame(self):
        """Sends a Supervisory frame (S-Format) acknowledging received I-frames."""
        ctrl = struct.pack('<BBH', 0x01, 0x00, (self.vr << 1))
        apdu = b'\x68\x04' + ctrl
        self._send_raw(apdu)
        self.unacked_rx = 0
        self._ack_pending_since = None

    def send_i_frame(self, asdu):
        """Wraps an ASDU into an Information frame (I-Format) and increments V(S)."""
        if not self.data_transfer_active:
            raise ConnectionError('STARTDT is required before sending an ASDU')
        if not 6 <= len(asdu) <= 249 or (self.vs - self.va) % 32768 >= 12:
            raise ValueError('ASDU size or unacknowledged send window exceeded')
        self._last_request_asdu = asdu
        ctrl = struct.pack('<HH', (self.vs << 1), (self.vr << 1))
        apdu_len = 4 + len(asdu)
        apdu = struct.pack('<BB', 0x68, apdu_len) + ctrl + asdu
        self._send_raw(apdu)
        self.vs = (self.vs + 1) % 32768
        self.unacked_rx = 0
        self._ack_pending_since = None

    def start_data_transfer(self, suppress_logs=False):
        """Initiates IEC-104 data transfer (STARTDT act -> STARTDT con)."""
        if not suppress_logs:
            logger.info("Sending STARTDT act (0x07)...")
        try:
            self._send_raw(self.STARTDT_ACT)
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                apdu = self.recv_apdu(custom_timeout=max(0.2, deadline - time.time()))
                if not apdu:
                    break
                if apdu == self.STARTDT_CON:
                    self.data_transfer_active = True
                    if not suppress_logs:
                        logger.info(f"{Color.GREEN}[SUCCESS]{Color.RESET} Received STARTDT con (0x0B). Link active.")
                    return True
                # Handle unexpected initial frames (e.g. M_EI_NA_1 End of Init)
                self._process_incoming_apdu(apdu)
            if not suppress_logs:
                logger.error("[TIMEOUT] Did not receive STARTDT con from target.")
            return False
        except Exception as e:
            if not suppress_logs:
                logger.error(f"[ERROR] Failed during STARTDT handshake: {e}")
            return False

    def test_frame(self, on_asdu=None):
        """Wait for TESTFR con while processing interleaved session traffic."""
        logger.info('Sending TESTFR act (0x43)...')
        self._send_raw(self.TESTFR_ACT)
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            apdu = self.recv_apdu(custom_timeout=max(.001, deadline - time.monotonic()))
            if apdu is None:
                break
            if apdu == self.TESTFR_CON:
                logger.info('[PROTOCOL_ACCEPTED] Received TESTFR con')
                return True
            parsed = self._process_incoming_apdu(apdu)
            if parsed and parsed['format'] == 'I' and on_asdu is not None:
                on_asdu(parsed)
        return False

    def _build_asdu(self, type_id, vsq, cot, ca, info_obj_bytes, is_negative=False, is_test=False):
        if not 0 <= ca <= 65535 or not 0 <= self.oa <= 255:
            raise ValueError('CA/OA address outside wire range')
        cot_byte = (cot & 0x3F) | (0x40 if is_negative else 0x00) | (0x80 if is_test else 0x00)
        header = struct.pack('<BBBBH', type_id, vsq, cot_byte, self.oa, ca)
        return header + info_obj_bytes

    def _process_incoming_apdu(self, apdu):
        """Parses APCI & ASDU. Automatically replies to TESTFR act and tracks V(R)."""
        if (not apdu or len(apdu) < 6 or apdu[0] != 0x68
                or apdu[1] != len(apdu) - 2 or not 4 <= apdu[1] <= 253):
            return self._protocol_error('Invalid APDU framing')

        ctrl1 = apdu[2]
        # U-Format Frame (bits 0 and 1 are 11 -> 0x03)
        if (ctrl1 & 0x03) == 0x03:
            if len(apdu) != 6 or apdu[3:] != b'\x00\x00\x00' or ctrl1 not in (7, 11, 19, 35, 67, 131):
                return self._protocol_error('Invalid U-format control')
            if ctrl1 == 0x43:  # TESTFR act from RTU
                logger.debug("Received TESTFR act from RTU -> Replying TESTFR con.")
                self._send_raw(self.TESTFR_CON)
            elif ctrl1 == 0x07:  # STARTDT act
                self._send_raw(self.STARTDT_CON)
                self.data_transfer_active = True
            elif ctrl1 == 0x13:
                self._send_raw(self.STOPDT_CON)
                self.data_transfer_active = False
            elif ctrl1 == 0x23:
                self.data_transfer_active = False
            return {"format": "U", "control": ctrl1}

        # S-Format Frame (bits 0 and 1 are 01 -> 0x01)
        elif (ctrl1 & 0x03) == 0x01:
            if len(apdu) != 6 or apdu[2:4] != b'\x01\x00' or apdu[4] & 1:
                return self._protocol_error('Invalid S-format control')
            rx_ack = struct.unpack('<H', apdu[4:6])[0] >> 1
            if not self._accept_ack(rx_ack):
                return None
            return {"format": "S", "rx_ack": rx_ack}

        # I-Format Frame (bit 0 is 0)
        else:
            tx_seq = struct.unpack('<H', apdu[2:4])[0] >> 1
            rx_ack = struct.unpack('<H', apdu[4:6])[0] >> 1
            if apdu[4] & 1 or tx_seq != self.vr or not self._accept_ack(rx_ack):
                return self._protocol_error('Invalid I-format sequence/acknowledgment')
            self.vr = (tx_seq + 1) % 32768
            if not self.unacked_rx:
                self._ack_pending_since = time.monotonic()
            self.unacked_rx += 1
            
            # Send S-Frame immediately if unacknowledged frames reach threshold (w=8)
            if self.unacked_rx >= 8:
                self.send_s_frame()

            asdu = apdu[6:]
            if len(asdu) < 6:
                return None

            type_id, vsq, cot_raw, oa, ca = struct.unpack('<BBBBH', asdu[:6])
            sq = bool(vsq & 0x80)
            num_ix = vsq & 0x7F
            is_negative = bool(cot_raw & 0x40)
            cot = cot_raw & 0x3F
            payload = asdu[6:]

            objects = self._parse_information_objects(type_id, sq, num_ix, payload)
            if objects is None:
                return self._protocol_error('Truncated/invalid information objects')
            return {
                "format": "I",
                "tx_seq": tx_seq,
                "rx_ack": rx_ack,
                "type_id": type_id,
                "type_name": ASDU_TYPES.get(type_id, (f"TYPE_{type_id}", "Unknown ASDU"))[0],
                "sq": sq,
                "count": num_ix,
                "cot": cot,
                "cot_name": COT_NAMES.get(cot, f"COT_{cot}"),
                "is_negative": is_negative,
                "is_test": bool(cot_raw & 0x80),
                "raw_asdu": asdu,
                "oa": oa,
                "ca": ca,
                "objects": objects
            }

    def _protocol_error(self, message):
        logger.error(f'[PROTOCOL ERROR] {message}')
        self.data_transfer_active = False
        self.close()
        return None

    def _accept_ack(self, ack):
        if (ack - self.va) % 32768 > (self.vs - self.va) % 32768:
            self._protocol_error('Acknowledgment outside sent sequence range')
            return False
        self.va = ack
        return True

    def _parse_information_objects(self, type_id, sq, count, payload):
        """Decodes Information Objects inside an ASDU payload."""
        objects = []
        sizes = {1:1, 3:1, 5:2, 7:5, 9:3, 11:3, 13:5, 15:5,
                 30:8, 31:8, 32:9, 33:12, 34:10, 35:10, 36:12, 37:12,
                 45:1, 46:1, 47:1, 48:3, 49:3, 50:5, 51:4,
                 70:1, 100:1, 101:1, 102:0, 103:7, 105:1}
        if count == 0:
            return [] if not payload else None
        size = sizes.get(type_id)
        if size is not None:
            expected = (3 if sq else count * 3) + count * size
            if len(payload) != expected:
                return None
            if sq and unpack_ioa(payload[:3]) + count - 1 > 0xffffff:
                return None
        elif count != 1 or len(payload) < 3:
            return None
        idx = 0
        base_ioa = 0

        for i in range(count):
            if not sq or i == 0:
                if idx + 3 > len(payload):
                    break
                base_ioa = unpack_ioa(payload[idx:idx+3])
                idx += 3
                current_ioa = base_ioa
            else:
                current_ioa = base_ioa + i

            data_start = idx
            val_str = ""
            qds_str = "N/A"
            ts_str = ""

            try:
                # 1. Single-point information (M_SP_NA_1 / M_SP_TB_1)
                if type_id in (1, 30):
                    siq = payload[idx]; idx += 1
                    spi = bool(siq & 0x01)
                    val_str = "ON (1)" if spi else "OFF (0)"
                    qds_str = decode_qds(siq & 0xF0)
                    if type_id == 30:
                        ts_str = decode_cp56time2a(payload[idx:idx+7]); idx += 7

                # 2. Double-point information (M_DP_NA_1 / M_DP_TB_1)
                elif type_id in (3, 31):
                    diq = payload[idx]; idx += 1
                    dpi = diq & 0x03
                    dp_map = {0: "INTERMEDIATE (0)", 1: "OFF (1)", 2: "ON (2)", 3: "INDETERMINATE (3)"}
                    val_str = dp_map.get(dpi, str(dpi))
                    qds_str = decode_qds(diq & 0xF0)
                    if type_id == 31:
                        ts_str = decode_cp56time2a(payload[idx:idx+7]); idx += 7

                # 3. Step position information (M_ST_NA_1 / M_ST_TB_1)
                elif type_id in (5, 32):
                    vti = payload[idx]; qds = payload[idx+1]; idx += 2
                    transient = " (Transient)" if (vti & 0x80) else ""
                    step_val = vti & 0x7F
                    if step_val >= 64: step_val -= 128
                    val_str = f"{step_val}{transient}"
                    qds_str = decode_qds(qds)
                    if type_id == 32:
                        ts_str = decode_cp56time2a(payload[idx:idx+7]); idx += 7

                # 4. Bitstring of 32 bits (M_BO_NA_1 / M_BO_TB_1)
                elif type_id in (7, 33):
                    bsi = struct.unpack('<I', payload[idx:idx+4])[0]
                    qds = payload[idx+4]; idx += 5
                    val_str = f"0x{bsi:08X}"
                    qds_str = decode_qds(qds)
                    if type_id == 33:
                        ts_str = decode_cp56time2a(payload[idx:idx+7]); idx += 7

                # 5. Measured value, normalized (M_ME_NA_1 / M_ME_TD_1)
                elif type_id in (9, 34):
                    raw_nva = struct.unpack('<h', payload[idx:idx+2])[0]
                    qds = payload[idx+2]; idx += 3
                    norm_val = round(raw_nva / 32768.0, 5)
                    val_str = f"{norm_val} (Raw: {raw_nva})"
                    qds_str = decode_qds(qds)
                    if type_id == 34:
                        ts_str = decode_cp56time2a(payload[idx:idx+7]); idx += 7

                # 6. Measured value, scaled (M_ME_NB_1 / M_ME_TE_1)
                elif type_id in (11, 35):
                    sva = struct.unpack('<h', payload[idx:idx+2])[0]
                    qds = payload[idx+2]; idx += 3
                    val_str = f"{sva}"
                    qds_str = decode_qds(qds)
                    if type_id == 35:
                        ts_str = decode_cp56time2a(payload[idx:idx+7]); idx += 7

                # 7. Measured value, short float (M_ME_NC_1 / M_ME_TF_1)
                elif type_id in (13, 36):
                    fval = struct.unpack('<f', payload[idx:idx+4])[0]
                    qds = payload[idx+4]; idx += 5
                    val_str = f"{fval:.9g}"
                    qds_str = decode_qds(qds)
                    if type_id == 36:
                        ts_str = decode_cp56time2a(payload[idx:idx+7]); idx += 7

                # 8. Integrated totals / Counters (M_IT_NA_1 / M_IT_TB_1)
                elif type_id in (15, 37):
                    bcr = struct.unpack('<i', payload[idx:idx+4])[0]
                    seq_flags = payload[idx+4]; idx += 5
                    val_str = f"{bcr} (SQ:{seq_flags & 0x1F})"
                    flags = [name for mask, name in ((0x20, 'CY'), (0x40, 'CA'), (0x80, 'IV')) if seq_flags & mask]
                    qds_str = '|'.join(flags) if flags else 'GOOD'
                    if type_id == 37:
                        ts_str = decode_cp56time2a(payload[idx:idx+7]); idx += 7

                # 9. Control Echoes & System Commands (45..51, 70, 100..105)
                else:
                    end = len(payload) if size is None else idx + size
                    rem = payload[idx:end]
                    val_str = f"RAW[{rem.hex().upper()}]"
                    idx = end

            except (struct.error, IndexError):
                val_str = "PARSE_ERR"
                break

            objects.append({
                "ioa": current_ioa,
                "raw": payload[data_start:idx],
                "value": val_str,
                "quality": qds_str,
                "timestamp": ts_str
            })

        return objects


# --- 4. COMMAND EXECUTION LOGIC ---
def print_asdu_table(parsed_list):
    if not parsed_list:
        print(f" {Color.YELLOW}No Information Objects received.{Color.RESET}\n")
        return

    print(f" {'CA':<6} | {'IOA':<8} | {'ASDU TYPE':<12} | {'VALUE':<24} | {'QUALITY':<14} | {'TIMESTAMP / COT'}")
    print(f" {'-'*6}-+-{'-'*8}-+-{'-'*12}-+-{'-'*24}-+-{'-'*14}-+-{'-'*24}")
    for item in parsed_list:
        ca = item["ca"]
        tname = item["type_name"]
        cot_str = item["cot_name"]
        for obj in item["objects"]:
            q_color = Color.GREEN if obj["quality"] in ("GOOD", "N/A") else Color.YELLOW
            ts_or_cot = obj["timestamp"] if obj["timestamp"] else cot_str
            print(
                f" {ca:<6} | {Color.YELLOW}{obj['ioa']:<8}{Color.RESET} | "
                f"{Color.BLUE}{tname:<12}{Color.RESET} | "
                f"{Color.GREEN}{obj['value']:<24}{Color.RESET} | "
                f"{q_color}{obj['quality']:<14}{Color.RESET} | {Color.GREY}{ts_or_cot}{Color.RESET}"
            )
    print()

def do_ping(client):
    print(f"\n{Color.CYAN}{Color.BOLD}--- IEC 60870-5-104 LINK DIAGNOSTIC ---{Color.RESET}")
    if client.start_data_transfer():
        test_ok = client.test_frame()
        print(f" {Color.BOLD}STARTDT Handshake (0x07 -> 0x0B):{Color.RESET} {Color.GREEN}VALIDATED{Color.RESET}")
        print(f" {Color.BOLD}TESTFR Keep-Alive (0x43 -> 0x83):{Color.RESET} {Color.GREEN if test_ok else Color.YELLOW}{'VALIDATED' if test_ok else 'NO RESPONSE'}{Color.RESET}\n")
        return test_ok
    else:
        logger.error("Target did not complete IEC-104 STARTDT activation.")
    return False

def do_interrogate(client, args):
    if not client.start_data_transfer():
        return False

    if args.counter_gi:
        logger.info(f"Sending Counter Interrogation Command (C_CI_NA_1, Type 101) to CA={args.ca}...")
        info_obj = pack_ioa(0) + struct.pack('<B', 0x05)  # QCC = 5 (General request counter)
        asdu = client._build_asdu(101, 0x01, 6, args.ca, info_obj)
    else:
        qoi = 20 if args.group == 0 else (20 + args.group)
        grp_desc = "Station General (QOI=20)" if args.group == 0 else f"Group {args.group} (QOI={qoi})"
        logger.info(f"Sending Interrogation Command (C_IC_NA_1, Type 100) [{grp_desc}] to CA={args.ca}...")
        info_obj = pack_ioa(0) + struct.pack('<B', qoi)
        asdu = client._build_asdu(100, 0x01, 6, args.ca, info_obj)

    client.send_i_frame(asdu)

    collected_asdus = []
    completed = False
    accepted = False
    deadline = time.time() + max(args.timeout, 6.0)

    while time.time() < deadline:
        apdu = client.recv_apdu(custom_timeout=1.5)
        if not apdu:
            break
        parsed = client._process_incoming_apdu(apdu)
        if not parsed or parsed["format"] != "I":
            continue

        if parsed['ca'] != args.ca or parsed['oa'] != client.oa or parsed['is_test']:
            continue
        if parsed["type_id"] in (100, 101):
            if not _matches_echo(parsed, asdu):
                continue
            if parsed["cot"] == 7:
                if parsed["is_negative"]:
                    logger.error(f"[REJECTED] Target rejected Interrogation (Negative actcon, CA={parsed['ca']}).")
                    break
                accepted = True
                logger.info(f"{Color.GREEN}[ACTCON]{Color.RESET} Interrogation confirmed by controller (CA={parsed['ca']}). Receiving points...")
            elif parsed["cot"] == 10 and not parsed["is_negative"] and accepted:
                completed = True
                logger.info(f"{Color.GREEN}[ACTTERM]{Color.RESET} Interrogation completed (COT=10).")
                break
            elif parsed["cot"] in (44, 45, 46, 47):
                logger.error(f"[ASDU ERROR] Controller returned: {parsed['cot_name']}")
                break
        elif not parsed['is_negative'] and (parsed['cot'] in range(37, 42) if args.counter_gi else parsed['cot'] == 20 + args.group):
            collected_asdus.append(parsed)

    if client.unacked_rx > 0:
        client.send_s_frame()

    print(f"\n{Color.CYAN}{Color.BOLD}--- INTERROGATION RESULTS (CA: {args.ca}) ---{Color.RESET}")
    print_asdu_table(collected_asdus)
    if not completed:
        logger.warning('[INDETERMINATE] Interrogation has no correlated activation termination')
    return completed

def do_read(client, args):
    if not client.start_data_transfer():
        return

    logger.info(f"Sending Read Command (C_RD_NA_1, Type 102) for CA={args.ca}, IOA={args.ioa}...")
    info_obj = pack_ioa(args.ioa)
    asdu = client._build_asdu(102, 0x01, 5, args.ca, info_obj)  # COT = 5 (Request)
    client.send_i_frame(asdu)

    collected = []
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        apdu = client.recv_apdu(custom_timeout=1.5)
        if not apdu:
            break
        parsed = client._process_incoming_apdu(apdu)
        if not parsed or parsed["format"] != "I":
            continue

        if parsed['ca'] != args.ca or parsed['oa'] != client.oa or parsed['is_test']:
            continue
        if parsed["cot"] in (44, 45, 46, 47):
            logger.error(f"[READ ERROR] Controller replied with {parsed['cot_name']} (COT={parsed['cot']}).")
            return False

        if parsed['cot'] != 5 or parsed['is_negative'] or parsed['type_id'] not in (1, 3, 5, 7, 9, 11, 13, 15, 30, 31, 32, 33, 34, 35, 36, 37):
            continue
        for obj in parsed["objects"]:
            if obj["ioa"] == args.ioa:
                collected.append(parsed)
                break
        if collected:
            break

    if client.unacked_rx > 0:
        client.send_s_frame()

    print(f"\n{Color.CYAN}{Color.BOLD}--- READ IOA {args.ioa} RESPONSE ---{Color.RESET}")
    print_asdu_table(collected)
    return bool(collected)

def _build_command_asdu(client, args, select_flag=False):
    if not 0 <= args.qu <= 31:
        raise ValueError('Command qualifier must be in 0..31')
    val = str(args.value).lower()
    allowed = {
        'single': ('0', '1', 'true', 'false', 'on', 'off'),
        'double': ('0', '1', '2', 'true', 'false', 'on', 'off'),
        'step': ('1', '2', 'up', 'higher', '+', 'down', 'lower', '-'),
    }
    if args.type in allowed and val not in allowed[args.type]:
        raise ValueError('Unrecognized control state')
    se_bit = 0x80 if select_flag else 0x00
    qu_bits = (args.qu & 0x1F) << 2
    ioa_bytes = pack_ioa(args.ioa)

    if args.type == "single":
        # C_SC_NA_1 (Type 45): SCS bit 0 (0=OFF, 1=ON)
        scs = 1 if str(args.value).lower() in ("1", "true", "on") else 0
        sco = se_bit | qu_bits | scs
        return client._build_asdu(45, 0x01, 6, args.ca, ioa_bytes + struct.pack('<B', sco))

    elif args.type == "double":
        # C_DC_NA_1 (Type 46): DCS bits 0-1 (1=OFF, 2=ON)
        val_str = str(args.value).lower()
        if val_str in ("0", "off", "false"): dcs = 1
        elif val_str in ("1", "2", "on", "true"): dcs = 2
        else: dcs = int(args.value) & 0x03
        dco = se_bit | qu_bits | dcs
        return client._build_asdu(46, 0x01, 6, args.ca, ioa_bytes + struct.pack('<B', dco))

    elif args.type == "step":
        # C_RC_NA_1 (Type 47): RCS bits 0-1 (1=LOWER/DOWN, 2=HIGHER/UP)
        val_str = str(args.value).lower()
        rcs = 2 if val_str in ("2", "up", "higher", "+") else 1
        rco = se_bit | qu_bits | rcs
        return client._build_asdu(47, 0x01, 6, args.ca, ioa_bytes + struct.pack('<B', rco))

    elif args.type == "norm":
        # C_SE_NA_1 (Type 48): Normalized value (-1.0 to +1.0) + QOS
        source_value = float(args.value)
        if not math.isfinite(source_value): raise ValueError('Setpoint must be finite')
        fval = max(-1.0, min(32767 / 32768, source_value))
        nva = int(fval * 32768)
        qos = se_bit | 0x00
        return client._build_asdu(48, 0x01, 6, args.ca, ioa_bytes + struct.pack('<hB', nva, qos))

    elif args.type == "scaled":
        # C_SE_NB_1 (Type 49): Scaled 16-bit integer + QOS
        sva = int(args.value)
        qos = se_bit | 0x00
        return client._build_asdu(49, 0x01, 6, args.ca, ioa_bytes + struct.pack('<hB', sva, qos))

    elif args.type == "float":
        # C_SE_NC_1 (Type 50): IEEE 754 float32 + QOS
        fval = float(args.value)
        if not math.isfinite(fval): raise ValueError('Setpoint must be finite')
        qos = se_bit | 0x00
        return client._build_asdu(50, 0x01, 6, args.ca, ioa_bytes + struct.pack('<fB', fval, qos))

    elif args.type == "bitstring":
        # C_BO_NA_1 (Type 51): 32-bit unsigned integer
        bval = int(str(args.value), 0)
        return client._build_asdu(51, 0x01, 6, args.ca, ioa_bytes + struct.pack('<I', bval))

def _matches_echo(parsed, expected_asdu):
    raw = parsed.get('raw_asdu', b'')
    return (parsed.get('format') == 'I' and not parsed.get('is_test')
            and len(raw) == len(expected_asdu) and raw[:2] == expected_asdu[:2]
            and raw[3:] == expected_asdu[3:])


def _wait_command_confirmation(client, timeout, expected_asdu=None):
    expected_asdu = expected_asdu or client._last_request_asdu
    if expected_asdu is None:
        logger.error('[LOCAL_ERROR] Missing expected command for response correlation')
        return False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        apdu = client.recv_apdu(custom_timeout=max(.001, deadline - time.monotonic()))
        if not apdu:
            break
        parsed = client._process_incoming_apdu(apdu)
        if not parsed or not _matches_echo(parsed, expected_asdu):
            continue
        if parsed['cot'] == 7:
            if parsed['is_negative']:
                logger.error('[REJECTED] Correlated negative activation confirmation')
                return False
            return True
        if parsed['cot'] in (44, 45, 46, 47):
            logger.error(f"[REJECTED] {parsed['cot_name']}")
            return False
    logger.error('[INDETERMINATE] No correlated activation confirmation received')
    return False


def do_write(client, args):
    if not client.start_data_transfer():
        return

    mode_str = "SELECT-BEFORE-OPERATE (SBO)" if args.sbo else "DIRECT EXECUTE"
    logger.warning(
        f"EXECUTING OT CONTROL COMMAND [{mode_str}] - "
        f"CA: {args.ca}, IOA: {args.ioa}, Type: {args.type.upper()}, Value: {args.value}"
    )

    if args.sbo:
        logger.info(f"[SBO STEP 1/2] Sending SELECT (S/E=1) to IOA={args.ioa}...")
        select_asdu = _build_command_asdu(client, args, select_flag=True)
        client.send_i_frame(select_asdu)
        if not _wait_command_confirmation(client, args.timeout, select_asdu):
            logger.error("[SBO ABORTED] SELECT was not confirmed; EXECUTE will not be sent.")
            return False
        logger.info(f"{Color.GREEN}[SELECT CONFIRMED]{Color.RESET} Target accepted selection (Positive actcon).")

    logger.info(f"Sending EXECUTE (S/E=0) to IOA={args.ioa}...")
    exec_asdu = _build_command_asdu(client, args, select_flag=False)
    client.send_i_frame(exec_asdu)

    if _wait_command_confirmation(client, args.timeout, exec_asdu):
        if client.unacked_rx > 0:
            client.send_s_frame()
        print(f"\n{Color.GREEN}{Color.BOLD}[PROTOCOL_ACCEPTED]{Color.RESET} Positive ACTCON on CA={args.ca}, IOA={args.ioa}; completion and field state unverified.\n")
        return True
    return False

def do_sync_clock(client, args):
    if not client.start_data_transfer():
        return

    target_dt = datetime.now() if not args.time_str else datetime.strptime(args.time_str, "%Y-%m-%d %H:%M:%S")
    logger.warning(f"EXECUTING OT CLOCK SYNCHRONIZATION (C_CS_NA_1, Type 103) - CA: {args.ca}, Time: {target_dt}")
    
    info_obj = pack_ioa(0) + encode_cp56time2a(target_dt)
    asdu = client._build_asdu(103, 0x01, 6, args.ca, info_obj)
    client.send_i_frame(asdu)

    accepted = _wait_command_confirmation(client, args.timeout, asdu)
    if accepted:
        print(f"\n{Color.GREEN}[PROTOCOL_ACCEPTED]{Color.RESET} Clock synchronization accepted by CA={args.ca}; clock readback unverified.\n")
    return accepted


def do_watch(client, args):
    if not client.start_data_transfer():
        return

    logger.info(f"Starting WATCH mode on {args.host}:{args.port} (CA={args.ca}). Listening for spontaneous/cyclic events...")
    print(f"{Color.GREY}Keep-Alive TESTFR interval: {args.wait}s | Press Ctrl+C to stop.{Color.RESET}\n")

    def show_event(parsed):
        if parsed and parsed['format'] == 'I' and parsed['objects'] and parsed['ca'] == args.ca:
            if args.ioa is not None:
                parsed['objects'] = [o for o in parsed['objects'] if o['ioa'] == args.ioa]
            if parsed['objects']:
                now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"{Color.CYAN}[{now_str}] Event Received (COT: {parsed['cot_name']}):{Color.RESET}")
                print_asdu_table([parsed])

    last_keepalive = time.time()
    while True:
        apdu = client.recv_apdu(custom_timeout=1.0)
        if apdu:
            show_event(client._process_incoming_apdu(apdu))

        if not client.sock:
            return False
        if (client.unacked_rx > 0 and client._ack_pending_since is not None
                and time.monotonic() - client._ack_pending_since >= 10.0):
            client.send_s_frame()
        if time.time() - last_keepalive >= args.wait:
            if client.unacked_rx > 0:
                client.send_s_frame()
            if not client.test_frame(on_asdu=show_event):
                logger.error('[FAILED] TESTFR confirmation timed out')
                return False
            last_keepalive = time.time()

def do_scan(args):
    logger.info(f"Scanning Common Addresses (CA {args.scan_start}..{args.scan_end}) on {args.host}:{args.port}...")
    client = RawIEC104Client(args.host, args.port, timeout=1.5, retries=0, oa=args.oa)
    if not client.connect(suppress_logs=True) or not client.start_data_transfer(suppress_logs=True):
        logger.error("Could not establish base IEC-104 session for scanning.")
        client.close()
        return False

    found_cas = []
    try:
        for ca in range(args.scan_start, args.scan_end + 1):
            if (client.vs - client.va) % 32768 >= 12:
                # A silent peer has not acknowledged our send window. Start a
                # fresh session before the next address; never bypass k.
                logger.warning('Unacknowledged scan window full; reconnecting before CA %s', ca)
                client.close()
                if not client.connect(suppress_logs=True) or not client.start_data_transfer(suppress_logs=True):
                    logger.error('Scan incomplete: could not renew the IEC-104 session')
                    break
                if (client.vs - client.va) % 32768 >= 12:
                    logger.error('Scan incomplete: fresh session counters were not reset')
                    break
            info_obj = pack_ioa(0) + struct.pack('<B', 20)
            asdu = client._build_asdu(100, 0x01, 6, ca, info_obj)
            client.send_i_frame(asdu)

            deadline = time.time() + 0.6
            while time.time() < deadline:
                apdu = client.recv_apdu(custom_timeout=0.3)
                if not apdu:
                    break
                parsed = client._process_incoming_apdu(apdu)
                if parsed and _matches_echo(parsed, asdu):
                    if parsed["cot"] == 7 and not parsed["is_negative"]:
                        logger.info(f"{Color.GREEN}[+] Common Address (CA) {ca} responded positively.{Color.RESET}")
                        found_cas.append(ca)
                    elif parsed["cot"] == 46:  # Unknown CA
                        break
            if client.unacked_rx > 0:
                client.send_s_frame()
    finally:
        client.close()

    print(f"\n{Color.CYAN}{Color.BOLD}--- COMMON ADDRESS (CA) SCAN RESULTS ---{Color.RESET}")
    if found_cas:
        print(f" Responsive CAs: {Color.GREEN}{found_cas}{Color.RESET}\n")
    else:
        print(f" {Color.YELLOW}No Common Addresses responded in range {args.scan_start}..{args.scan_end}.{Color.RESET}\n")
    return bool(found_cas)


# --- 5. MAIN ENTRY POINT ---
def main():
    desc_text = f"{Color.BOLD}IEC 60870-5-104 Master CLI (by z4y_d3n){Color.RESET}\n"
    custom_usage = (
        f"{Color.GREEN}iec104_master.py{Color.RESET} "
        f"{Color.YELLOW}[-H HOST] [-c COMMAND] [-p PORT] [-C CA] [-I IOA] "
        f"[-t TYPE] [-v VALUE] [--sbo] [-g GROUP] [-w WAIT]{Color.RESET}"
    )

    parser = CustomArgumentParser(description=desc_text, usage=custom_usage, formatter_class=ColoredHelpFormatter)

    parser.add_argument("-H", "--host", required=True, type=str, help="Target IP of the RTU/PLC/IED.")
    parser.add_argument("-c", "--command", required=True, choices=["ping", "interrogate", "read", "write", "watch", "sync-clock", "scan"], help="Protocol action to execute.")
    parser.add_argument("-p", "--port", type=int, default=2404, help="TCP Port (Default: 2404).")
    parser.add_argument("--timeout", type=float, default=3.0, help="Socket timeout in seconds (Default: 3.0).")
    parser.add_argument("--debug", action="store_true", help="Enable raw Hex APDU TX/RX trace logs.")

    addr_group = parser.add_argument_group(f"{Color.CYAN}ASDU & Object Addressing Options{Color.RESET}")
    addr_group.add_argument("-C", "--ca", type=int, default=1, help="Common Address of ASDU / Station ID (Default: 1).")
    addr_group.add_argument("-I", "--ioa", type=lambda x: int(x, 0), help="Information Object Address (24-bit integer or Hex, e.g., 100 or 0x100).")
    addr_group.add_argument("-O", "--oa", type=int, default=1, help="Originator Address (Default: 1).")

    gi_group = parser.add_argument_group(f"{Color.CYAN}Interrogation & Scan Options{Color.RESET}")
    gi_group.add_argument("-g", "--group", type=int, choices=range(0, 17), default=0, metavar="[0-16]", help="Interrogation group: 0=Station GI (QOI=20), 1..16=Group GI.")
    gi_group.add_argument("--counter-gi", action="store_true", help="Execute Counter Interrogation (C_CI_NA_1, Type 101) instead of Station GI.")
    gi_group.add_argument("--scan-start", type=int, default=1, help="Start Common Address for 'scan' (Default: 1).")
    gi_group.add_argument("--scan-end", type=int, default=50, help="End Common Address for 'scan' (Default: 50).")

    ctrl_group = parser.add_argument_group(f"{Color.CYAN}Control & Set-Point Options (-c write / sync-clock){Color.RESET}")
    ctrl_group.add_argument("-t", "--type", choices=["single", "double", "step", "norm", "scaled", "float", "bitstring"], default="single", help="Command ASDU type (45..51).")
    ctrl_group.add_argument("-v", "--value", type=str, help="Command value (e.g., 1/0, on/off, up/down, or numeric setpoint).")
    ctrl_group.add_argument("--sbo", action="store_true", help="Enforce Two-Step Select-Before-Operate (S/E=1 then S/E=0).")
    ctrl_group.add_argument("--qu", type=int, default=0, help="Command Qualifier QU (0=Unspecified, 1=Short pulse, 2=Long pulse, 3=Persistent).")
    ctrl_group.add_argument("--time-str", type=str, help="Custom timestamp for 'sync-clock' ('YYYY-MM-DD HH:MM:SS'). Defaults to local system clock.")

    mon_group = parser.add_argument_group(f"{Color.CYAN}Monitoring Options (-c watch){Color.RESET}")
    mon_group.add_argument("-w", "--wait", type=float, default=10.0, help="Keep-Alive TESTFR interval in seconds during 'watch' mode (Default: 10.0).")

    if len(sys.argv) == 1:
        parser.print_usage()
        sys.exit(1)

    parser.usage = argparse.SUPPRESS
    args = parser.parse_args()

    # --- Logical Validations ---
    if args.command == "read" and args.ioa is None:
        parser.error("Argument -I / --ioa is strictly required for the 'read' command.")
    if args.command == "write":
        if args.ioa is None or args.value is None:
            parser.error("Arguments -I / --ioa and -v / --value are strictly required for the 'write' command.")

    if (not 1 <= args.port <= 65535 or not math.isfinite(args.timeout) or args.timeout <= 0
            or not math.isfinite(args.wait) or args.wait <= 0):
        parser.error('Port and positive timeouts must be valid.')
    if not 0 <= args.ca <= 65535 or not 0 <= args.oa <= 255 or (args.ioa is not None and not 0 <= args.ioa <= 0xffffff):
        parser.error('CA/OA/IOA outside wire range.')
    if not 0 <= args.scan_start <= args.scan_end <= 65535 or not 0 <= args.qu <= 31:
        parser.error('Invalid scan range or command qualifier.')
    if args.command == 'write':
        try:
            _build_command_asdu(RawIEC104Client(args.host, oa=args.oa), args)
        except (ValueError, OverflowError, struct.error) as error:
            parser.error(str(error))
    if args.command == 'sync-clock' and args.time_str:
        try:
            datetime.strptime(args.time_str, '%Y-%m-%d %H:%M:%S')
        except ValueError as error:
            parser.error(str(error))
    setup_logger(args.debug)

    if args.command == "scan":
        return 0 if do_scan(args) else 1

    client = RawIEC104Client(args.host, port=args.port, timeout=args.timeout, retries=2, oa=args.oa)
    if not client.connect():
        sys.exit(1)

    print(f"{Color.GREEN}{Color.BOLD}[CONNECTED]{Color.RESET} {Color.CYAN}{args.host}:{args.port}{Color.RESET} | CA: {Color.BLUE}{args.ca}{Color.RESET} | Command: {Color.YELLOW}{args.command.upper()}{Color.RESET}\n")

    try:
        handlers = {'ping': lambda c, a: do_ping(c), 'interrogate': do_interrogate,
                    'read': do_read, 'write': do_write, 'sync-clock': do_sync_clock, 'watch': do_watch}
        return 0 if handlers[args.command](client, args) else 1
    except (ValueError, struct.error, OSError) as error:
        logger.error(f'[FAILED/LOCAL_ERROR] {error}')
        return 1
    finally:
        client.close()

if __name__ == "__main__":
    sys.exit(main())
