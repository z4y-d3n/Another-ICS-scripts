#!/usr/bin/env python3
import sys
import signal
import argparse
import logging
import os
import struct
import socket
import time
from datetime import datetime, timedelta

# --- 1. Terminal Setup & Audit Logging ---
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

logger = logging.getLogger("S7MasterCLI")

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
        log_file = os.path.join(audit_dir, f"s7_master_LAB_{datetime.now().strftime('%Y%m%d')}.log")

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
        print(f"{Color.YELLOW}Hint: Review your syntax. Use '-h' or '--help' to see required arguments.{Color.RESET}\n")
        self.exit(2)

class ColoredHelpFormatter(argparse.HelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = f"{Color.CYAN}{Color.BOLD}Usage:{Color.RESET} "
        super().add_usage(usage, actions, groups, prefix)

# --- 2. DATA TYPE HELPERS ---
def bcd_encode(val): return ((val // 10) << 4) | (val % 10)
def bcd_decode(val):
    if not 0 <= val <= 255 or val >> 4 > 9 or val & 15 > 9:
        raise ValueError('Invalid BCD digit')
    return ((val >> 4) * 10) + (val & 0x0F)

def s5time_encode(ms):
    if not 0 <= ms <= 9990000:
        raise ValueError('S5TIME milliseconds must be in 0..9990000')
    if ms <= 9990: base = 0; val = ms // 10
    elif ms <= 99900: base = 1; val = ms // 100
    elif ms <= 999000: base = 2; val = ms // 1000
    else: base = 3; val = ms // 10000
    bcd_val = ((val // 100) << 8) | (((val // 10) % 10) << 4) | (val % 10)
    return struct.pack('>H', (base << 12) | bcd_val)

def s5time_decode(data):
    w = struct.unpack('>H', data)[0]
    base = (w >> 12) & 0x03
    mult = [10, 100, 1000, 10000][base]
    bcd = w & 0x0FFF
    if any(((bcd >> shift) & 0x0F) > 9 for shift in (0, 4, 8)):
        raise ValueError('Invalid S5TIME BCD digit')
    val = ((bcd >> 8) * 100) + (((bcd >> 4) & 0x0F) * 10) + (bcd & 0x0F)
    return val * mult 

# --- 3. NATIVE S7COMM CLIENT SECURED ---
class RawS7Client:
    def __init__(self, host, port=102, rack=0, slot=2, timeout=3.0, retries=2):
        self.host = host
        self.port = port
        self.rack = rack
        self.slot = slot
        self.timeout = timeout
        self.retries = retries
        self.sock = None
        self.pdu_ref = 1
        self.negotiated_pdu = 240 

    def connect(self):
        for attempt in range(self.retries + 1):
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.sock.connect((self.host, self.port))
                
                if not self._send_cotp_cr():
                    raise ConnectionError("COTP Connection Request failed.")
                if not self._send_s7_setup():
                    raise ConnectionError("S7 Setup Communication failed.")
                    
                logger.info(f"Connection established with {self.host}:{self.port} (Negotiated PDU: {self.negotiated_pdu} bytes)")
                return True
            except socket.timeout:
                self.close()
                if attempt < self.retries:
                    logger.warning(f"[RETRY] Connection timed out. Retrying in 1.5s...")
                    time.sleep(1.5)
                else:
                    logger.error(f"[NETWORK ERROR] Timeout. Retries exhausted for {self.host}:{self.port}.")
            except (ConnectionError, OSError) as e:
                self.close()
                if attempt < self.retries:
                    backoff = 1.5 * (attempt + 1)
                    logger.warning(f"[RETRY] Connection failed ({e}). Retrying in {backoff}s...")
                    time.sleep(backoff)
                else:
                    logger.error(f"[NETWORK ERROR] Retries exhausted for {self.host}:{self.port}.")
        return False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            finally:
                self.sock = None

    def _recv_exact(self, length):
        data = b''
        deadline = time.monotonic() + self.timeout
        while len(data) < length:
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ConnectionError('Total socket read deadline exceeded')
                self.sock.settimeout(remaining)
                chunk = self.sock.recv(length - len(data))
                if not chunk: raise ConnectionError("Socket closed remotely.")
                data += chunk
            except socket.timeout:
                raise ConnectionError("Timeout reading from socket.")
            except Exception as e:
                raise ConnectionError(f"Socket read failure: {e}")
        self.sock.settimeout(self.timeout)
        return data

    def _send_recv(self, payload):
        if not self.sock: return None

        cotp_dt = b'\x02\xf0\x80'
        tpkt = struct.pack('>BBH', 3, 0, 4 + len(cotp_dt) + len(payload))
        request_frame = tpkt + cotp_dt + payload

        try:
            logger.debug(f"TX: {request_frame.hex().upper()}")
            self.sock.sendall(request_frame)
            
            tpkt_resp = self._recv_exact(4)
            if tpkt_resp[:2] != b'\x03\x00':
                raise ValueError('Invalid TPKT header')
                
            resp_len = struct.unpack('>H', tpkt_resp[2:4])[0]
            limit = 960 if payload[10:11] == b'\xf0' else self.negotiated_pdu
            if not 17 <= resp_len <= limit + 7:
                raise ValueError('Invalid TPKT/PDU length')
            resp_data = self._recv_exact(resp_len - 4)
            logger.debug(f"RX: {(tpkt_resp + resp_data).hex().upper()}")
            
            if resp_data[:3] != b'\x02\xf0\x80':
                raise ValueError('Expected complete COTP Data TPDU')
            response = resp_data[3:]
            header_len = 10 if payload[1] == 7 else 12
            if len(response) < header_len or response[0] != 0x32 or response[1] != (7 if payload[1] == 7 else 3):
                raise ValueError('Invalid S7 response header')
            if response[4:6] != payload[4:6]:
                raise ValueError('Mismatched S7 PDU reference')
            plen, dlen = struct.unpack('>HH', response[6:10])
            if header_len + plen + dlen != len(response):
                raise ValueError('S7 parameter/data lengths do not match frame')
            if header_len == 12:
                if response[10:12] != b'\x00\x00':
                    logger.error(f'[REJECTED] S7 header error {response[10:12].hex()}')
                    return None
                expected = payload[10:12] if payload[10] in (4, 5) else payload[10:11]
                if response[12:12+len(expected)] != expected:
                    raise ValueError('Mismatched S7 response function/item count')
            return response
        except Exception as e:
            logger.error(f"[INDETERMINATE/PROTOCOL ERROR] Transaction failed: {e}")
            self.close()
            return None

    def _send_cotp_cr(self):
        dst_tsap_byte1 = 0x01
        dst_tsap_byte2 = (self.rack * 0x20) + self.slot
        
        cotp_cr = struct.pack(
            '>18B',
            0x11, 0xE0,             
            0x00, 0x00,             
            0x00, 0x01,             
            0x00,                   
            0xC1, 0x02, 0x01, 0x00, 
            0xC2, 0x02, dst_tsap_byte1, dst_tsap_byte2, 
            0xC0, 0x01, 0x0A        
        )
        
        tpkt = struct.pack('>BBH', 3, 0, 4 + len(cotp_cr))
        
        try:
            self.sock.sendall(tpkt + cotp_cr)
            resp = self._recv_exact(4)
            if resp[:2] != b'\x03\x00':
                return False
                
            resp_len = struct.unpack('>H', resp[2:4])[0]
            if not 11 <= resp_len <= 128:
                return False
            cotp_resp = self._recv_exact(resp_len - 4)

            return (len(cotp_resp) >= 7 and cotp_resp[0] + 1 == len(cotp_resp)
                    and cotp_resp[1] == 0xD0 and cotp_resp[2:4] == b'\x00\x01'
                    and cotp_resp[6] == 0)
        except Exception:
            return False

    def _send_s7_setup(self):
        s7_header = struct.pack('>BBHHHH', 0x32, 0x01, 0x0000, self.pdu_ref, 8, 0)
        s7_param = struct.pack('>BBHHH', 0xF0, 0x00, 0x0001, 0x0001, 960)
        self.pdu_ref = (self.pdu_ref + 1) & 0xFFFF
        resp = self._send_recv(s7_header + s7_param)
        
        if resp and len(resp) >= 20 and resp[0] == 0x32 and resp[1] == 0x03:
            offered = struct.unpack('>H', resp[18:20])[0]
            if resp[6:10] == b'\x00\x08\x00\x00' and 240 <= offered <= 960:
                self.negotiated_pdu = offered
                return True
        return False

    def _get_area_and_addr(self, area, byte_offset, bit_offset, is_bool):
        S7_AREAS = {'I': 0x81, 'Q': 0x82, 'M': 0x83, 'DB': 0x84, 'C': 0x1C, 'T': 0x1D, 'PI': 0x80, 'PQ': 0x80}
        if area.upper() not in S7_AREAS:
            raise ValueError('Unknown S7 memory area')
        if byte_offset < 0 or not 0 <= bit_offset <= 7 or (not is_bool and bit_offset != 0):
            raise ValueError('Invalid S7 byte/bit address or non-byte-aligned access')
        area_code = S7_AREAS[area.upper()]
        
        if area_code in [0x1C, 0x1D]:
            if is_bool or bit_offset:
                raise ValueError('Timers/counters require word elements')
            any_type = area_code
            bit_address = byte_offset
        else:
            any_type = 0x01 if is_bool else 0x02
            bit_address = (byte_offset * 8) + bit_offset
            
        if bit_address > 0xFFFFFF:
            raise ValueError('S7 address exceeds 24 bits')
        addr_bytes = bit_address.to_bytes(3, 'big')
        return area_code, any_type, addr_bytes

    def read_variable(self, area, db_number, byte_offset, bit_offset, size, is_bool=False):
        max_read = self.negotiated_pdu - 18
        if size > max_read:
            logger.error(f"[PROTOCOL ERROR] Requested size exceeds negotiated PDU ({max_read} bytes).")
            return None

        area_code, any_type, addr_bytes = self._get_area_and_addr(area, byte_offset, bit_offset, is_bool)
        if size < 1 or not 0 <= db_number <= 65535 or (is_bool and size != 1):
            raise ValueError('Invalid S7 size/DB number')
        elements = size
        if area_code in (0x1C, 0x1D):
            if size % 2: raise ValueError('Timer/counter size must be an even number of bytes')
            elements = size // 2
        if area_code != 0x84: db_number = 0
        
        item = struct.pack('>BBBBHHB3s', 0x12, 0x0A, 0x10, any_type, elements, db_number, area_code, addr_bytes)
        s7_param = struct.pack('>BB', 0x04, 0x01) + item
        s7_header = struct.pack('>BBHHHH', 0x32, 0x01, 0x0000, self.pdu_ref, len(s7_param), 0)
        self.pdu_ref = (self.pdu_ref + 1) & 0xFFFF
        
        resp = self._send_recv(s7_header + s7_param)
        if not resp or len(resp) < 14: return None
        if resp[10] != 0x00 or resp[11] != 0x00:
            logger.error(f"[S7 ERROR] Header Error Class: 0x{resp[10]:02X}, Code: 0x{resp[11]:02X}")
            return None

        param_len = struct.unpack('>H', resp[6:8])[0]
        data_base = 12 + param_len
        
        if len(resp) < data_base + 4: return None
            
        if resp[data_base] != 0xFF:
            logger.error(f"[S7 ERROR] Access Refused/CPU Error. Code: 0x{resp[data_base]:02X}")
            return None
            
        data_len = struct.unpack('>H', resp[data_base+2:data_base+4])[0]
        ts = resp[data_base+1]
        if ts not in (3, 4, 9): return None
        byte_len = (data_len + 7) // 8 if ts in (3, 4) else data_len
        if byte_len != size or data_base + 4 + byte_len != len(resp):
            logger.error('[PROTOCOL ERROR] Read item size differs from requested/declared size')
            return None
        return resp[data_base+4:data_base+4+byte_len]

    def write_variable(self, area, db_number, byte_offset, bit_offset, data_bytes, is_bool=False):
        size = len(data_bytes)
        max_write = self.negotiated_pdu - 28 
        if size > max_write:
            logger.error(f"[PROTOCOL ERROR] Write size exceeds negotiated PDU ({max_write} bytes).")
            return False

        area_code, any_type, addr_bytes = self._get_area_and_addr(area, byte_offset, bit_offset, is_bool)
        if size < 1 or not 0 <= db_number <= 65535 or (is_bool and (size != 1 or data_bytes[0] not in (0, 1))):
            raise ValueError('Invalid S7 write size/DB/BOOL')
        elements = size
        if area_code in (0x1C, 0x1D):
            if size % 2: raise ValueError('Timer/counter size must be even')
            elements = size // 2
        if area_code != 0x84: db_number = 0
        
        item = struct.pack('>BBBBHHB3s', 0x12, 0x0A, 0x10, any_type, elements, db_number, area_code, addr_bytes)
        s7_param = struct.pack('>BB', 0x05, 0x01) + item
        
        transport_size = 0x03 if is_bool else 0x04
        length_bits = size if is_bool else (size * 8)
        if area_code in (0x1C, 0x1D):
            transport_size, length_bits = 9, size
        s7_data = struct.pack('>BBH', 0x00, transport_size, length_bits) + data_bytes
        
        s7_header = struct.pack('>BBHHHH', 0x32, 0x01, 0x0000, self.pdu_ref, len(s7_param), len(s7_data))
        self.pdu_ref = (self.pdu_ref + 1) & 0xFFFF
        
        logger.warning(f"EXECUTING OT MEMORY WRITE - Area: {area.upper()}, DB: {db_number}, Offset: {byte_offset}.{bit_offset}")
        resp = self._send_recv(s7_header + s7_param + s7_data)
        
        if not resp or len(resp) < 14: return False
        
        param_len = struct.unpack('>H', resp[6:8])[0]
        data_base = 12 + param_len
        
        if len(resp) != data_base + 1: return False
            
        if resp[data_base] != 0xFF:
            logger.error(f"[S7 ERROR] Write denied. Return Code: 0x{resp[data_base]:02X}")
            return False
        return True

    def pi_service(self, pi_name, pi_data=b''):
        if not 1 <= len(pi_name) <= 255 or len(pi_data) > 65535:
            raise ValueError('PI service name/data length invalid')
        if pi_name == b'_STOP':
            param = b'\x29' + b'\x00' * 5 + b'\x09P_PROGRAM'
        else:
            param = b'\x28' + b'\x00' * 6 + b'\xfd' + struct.pack('>H', len(pi_data)) + pi_data
            param += bytes([len(pi_name)]) + pi_name
        pi_data = b''
        
        s7_header = struct.pack('>BBHHHH', 0x32, 0x01, 0x0000, self.pdu_ref, len(param), len(pi_data))
        self.pdu_ref = (self.pdu_ref + 1) & 0xFFFF
        
        resp = self._send_recv(s7_header + param + pi_data)
        if not resp or len(resp) < 12:
            return False
            
        if len(resp) >= 12 and resp[10] == 0x00 and resp[11] == 0x00:
            return True
        return False

    def _send_recv_userdata_fragmented(self, func_group, subfunc, data):
        seq = 0
        fragments = []
        total = 0
        # S7 userdata last-unit flag is parameter byte 9, not an S7 header byte.
        for fragment in range(256):
            if fragment:
                param = bytes([0, 1, 0x12, 8, 0x12, func_group, subfunc, seq, 0, 0, 0, 0])
                data = b'\x0a\x00\x00\x00'
            else:
                param = bytes([0, 1, 0x12, 4, 0x11, func_group, subfunc, seq])
            header = struct.pack('>BBHHHH', 0x32, 7, 0, self.pdu_ref, len(param), len(data))
            self.pdu_ref = (self.pdu_ref + 1) & 0xffff
            resp = self._send_recv(header + param + data)
            if not resp:
                return None, b''
            plen, dlen = struct.unpack('>HH', resp[6:10])
            rp = resp[10:10+plen]
            rd = resp[10+plen:]
            if (plen != 12 or rp[:4] != b'\x00\x01\x12\x08'
                    or rp[4] != 0x12 or rp[5] != (0x80 | (func_group & 0x0f))
                    or rp[6] != subfunc or rp[10:12] != b'\x00\x00'
                    or rp[9] not in (0, 1) or dlen < 4):
                logger.error('[PROTOCOL ERROR] Invalid userdata response parameters')
                return None, b''
            if fragment and rp[7] != seq:
                return None, b''
            seq = rp[7]
            ret, ts, count = struct.unpack('>BBH', rd[:4])
            if ret != 255:
                return ret, b''
            if ts not in (4, 9) or (ts == 4 and count % 8):
                return None, b''
            size = count // 8 if ts == 4 else count
            if size != len(rd) - 4:
                return None, b''
            total += size
            if total > 1024 * 1024 or (rp[9] and size == 0):
                return None, b''
            fragments.append(rd[4:])
            if rp[9] == 0:
                return 255, b''.join(fragments)
        logger.error('[PROTOCOL ERROR] Userdata fragment limit exceeded')
        return None, b''

    def read_szl(self, szl_id, index=0x0000):
        data = struct.pack('>BBHHH', 0xFF, 0x09, 0x0004, szl_id, index)
        ret_code, payload = self._send_recv_userdata_fragmented(0x44, 0x01, data)
        if ret_code != 0xFF or len(payload) < 8:
            return None
        if payload[:4] != struct.pack('>HH', szl_id, index):
            logger.error('[PROTOCOL ERROR] Mismatched SZL ID/index')
            return None
        payload = payload[4:]
        record_len, count = struct.unpack('>HH', payload[:4])
        if len(payload) != 4 + record_len * count:
            logger.error('[PROTOCOL ERROR] Truncated SZL records')
            return None
        return payload

    def list_blocks_functions(self, subfunc, data):
        return self._send_recv_userdata_fragmented(0x43, subfunc, data)

# --- 4. Command Execution Logic ---
def do_read(client, args):
    TYPE_SIZES = {
        'bool': 1, 'byte': 1, 'char': 1,
        'int16': 2, 'word': 2, 's5time': 2, 'date': 2,
        'dint': 4, 'udint': 4, 'dword': 4, 'float32': 4, 'time': 4, 'tod': 4,
        'dt': 8
    }
    
    is_bool = (args.type == 'bool')
    size = TYPE_SIZES.get(args.type, args.size)
    
    logger.info(f"Reading S7 [Area: {args.area.upper()}, DB: {args.db}, Offset: {args.offset}.{args.bit_offset}, Size: {size}, Type: {args.type.upper()}]")
    raw_data = client.read_variable(args.area, args.db, args.offset, args.bit_offset, size, is_bool)
    
    if not raw_data:
        logger.error("Failed to read variable from S7 CPU.")
        return False

    print(f"\n{Color.CYAN}{Color.BOLD}--- S7 READ RESPONSE ---{Color.RESET}")
    print(f" {Color.BOLD}Hex Payload:{Color.RESET} {Color.GREY}{raw_data.hex().upper()}{Color.RESET}")

    try:
        if args.type == 'bool': print(f" {Color.BOLD}Decoded BOOL:{Color.RESET} {Color.GREEN}{bool(raw_data[0])}{Color.RESET}")
        elif args.type == 'byte': print(f" {Color.BOLD}Decoded BYTE:{Color.RESET} {Color.GREEN}{struct.unpack('>B', raw_data)[0]}{Color.RESET}")
        elif args.type == 'char': print(f" {Color.BOLD}Decoded CHAR:{Color.RESET} {Color.GREEN}{chr(raw_data[0]) if 32 <= raw_data[0] <= 126 else '.'}{Color.RESET}")
        elif args.type == 'int16': print(f" {Color.BOLD}Decoded INT16:{Color.RESET} {Color.GREEN}{struct.unpack('>h', raw_data)[0]}{Color.RESET}")
        elif args.type == 'word': print(f" {Color.BOLD}Decoded WORD:{Color.RESET} {Color.GREEN}{struct.unpack('>H', raw_data)[0]}{Color.RESET}")
        elif args.type == 'dint': print(f" {Color.BOLD}Decoded DINT:{Color.RESET} {Color.GREEN}{struct.unpack('>i', raw_data)[0]}{Color.RESET}")
        elif args.type == 'udint': print(f" {Color.BOLD}Decoded UDINT:{Color.RESET} {Color.GREEN}{struct.unpack('>I', raw_data)[0]}{Color.RESET}")
        elif args.type == 'dword': print(f" {Color.BOLD}Decoded DWORD:{Color.RESET} {Color.GREEN}{struct.unpack('>I', raw_data)[0]}{Color.RESET}")
        elif args.type == 'float32': print(f" {Color.BOLD}Decoded REAL:{Color.RESET} {Color.GREEN}{struct.unpack('>f', raw_data)[0]:.9g}{Color.RESET}")
        elif args.type == 'time': print(f" {Color.BOLD}Decoded TIME (ms):{Color.RESET} {Color.GREEN}{struct.unpack('>i', raw_data)[0]} ms{Color.RESET}")
        elif args.type == 's5time': print(f" {Color.BOLD}Decoded S5TIME (ms):{Color.RESET} {Color.GREEN}{s5time_decode(raw_data)} ms{Color.RESET}")
        elif args.type == 'tod':
            ms_midnight = struct.unpack('>I', raw_data)[0]
            if ms_midnight >= 86400000: raise ValueError('TOD exceeds one day')
            h = ms_midnight // 3600000
            m = (ms_midnight % 3600000) // 60000
            s = (ms_midnight % 60000) // 1000
            ms = ms_midnight % 1000
            print(f" {Color.BOLD}Decoded TOD:{Color.RESET} {Color.GREEN}{h:02d}:{m:02d}:{s:02d}.{ms:03d}{Color.RESET}")
        elif args.type == 'date':
            days = struct.unpack('>H', raw_data)[0]
            dt_obj = datetime(1990, 1, 1) + timedelta(days=days)
            print(f" {Color.BOLD}Decoded DATE:{Color.RESET} {Color.GREEN}{dt_obj.strftime('%Y-%m-%d')}{Color.RESET}")
        elif args.type == 's7string':
            if len(raw_data) < 2 or raw_data[1] > raw_data[0] or len(raw_data) < 2 + raw_data[1]:
                raise ValueError('Invalid S7 STRING header/length')
            text = raw_data[2:2+raw_data[1]].decode('ascii', errors='replace')
            print(f' Decoded S7STRING: {text}')
        elif args.type == 'dt':
            if len(raw_data) != 8: raise ValueError('DATE_AND_TIME requires eight bytes')
            year = bcd_decode(raw_data[0]); year = 1900 + year if year > 89 else 2000 + year
            mon = bcd_decode(raw_data[1]); day = bcd_decode(raw_data[2])
            hr = bcd_decode(raw_data[3]); mn = bcd_decode(raw_data[4]); sec = bcd_decode(raw_data[5])
            ms = (bcd_decode(raw_data[6]) * 10) + (raw_data[7] >> 4)
            if raw_data[7] >> 4 > 9 or not 1 <= (raw_data[7] & 15) <= 7:
                raise ValueError('Invalid millisecond/day-of-week field')
            datetime(year, mon, day, hr, mn, sec, ms * 1000)
            print(f" {Color.BOLD}Decoded Date/Time:{Color.RESET} {Color.GREEN}{year}-{mon:02d}-{day:02d} {hr:02d}:{mn:02d}:{sec:02d}.{ms:03d}{Color.RESET}")
        else:
            ascii_str = raw_data.decode('ascii', errors='replace').replace('\x00', '.')
            print(f" {Color.BOLD}Decoded ASCII:{Color.RESET} {Color.YELLOW}{ascii_str}{Color.RESET}")
    except (struct.error, ValueError):
        logger.error(f"Invalid typed value. The raw data length was {len(raw_data)} bytes.")
        return False
    print()
    return True

def do_write(client, args):
    logger.info(f"Preparing S7 Write [Area: {args.area.upper()}, DB: {args.db}, Offset: {args.offset}.{args.bit_offset}, Type: {args.type.upper()}]")
    
    try:
        if args.type == 'bool': 
            if args.value.lower() not in ('true', '1', 't', 'y', 'yes', 'false', '0', 'f', 'n', 'no'):
                raise ValueError('Unrecognized BOOL value')
            val_bool = args.value.lower() in ['true', '1', 't', 'y', 'yes']
            data_bytes = b'\x01' if val_bool else b'\x00'
        elif args.type == 'byte': data_bytes = struct.pack('>B', int(args.value))
        elif args.type == 'word': data_bytes = struct.pack('>H', int(args.value))
        elif args.type == 'dword': data_bytes = struct.pack('>I', int(args.value))
        elif args.type == 'char': data_bytes = args.value[0].encode('ascii', errors='replace')
        elif args.type == 'int16': data_bytes = struct.pack('>h', int(args.value))
        elif args.type == 'dint': data_bytes = struct.pack('>i', int(args.value))
        elif args.type == 'udint': data_bytes = struct.pack('>I', int(args.value))
        elif args.type == 'float32': data_bytes = struct.pack('>f', float(args.value))
        elif args.type == 'time': data_bytes = struct.pack('>i', int(args.value))
        elif args.type == 's5time': data_bytes = s5time_encode(int(args.value))
        elif args.type == 'tod':
            time_str = args.value
            ms_val = 0
            if '.' in time_str:
                time_str, ms_str = time_str.split('.')
                if not ms_str or any(c < '0' or c > '9' for c in ms_str):
                    raise ValueError('Time-of-day fraction must contain ASCII decimal digits')
                ms_val = int(ms_str.ljust(3, '0')[:3])
            parts = time_str.split(':')
            if not 1 <= len(parts) <= 3: raise ValueError('Invalid time-of-day format')
            h = int(parts[0]) if len(parts) > 0 else 0
            m = int(parts[1]) if len(parts) > 1 else 0
            s = int(parts[2]) if len(parts) > 2 else 0
            if not (0 <= h < 24 and 0 <= m < 60 and 0 <= s < 60):
                raise ValueError('Time of day must be within 00:00:00..23:59:59.999')
            total_ms = (h * 3600000) + (m * 60000) + (s * 1000) + ms_val
            data_bytes = struct.pack('>I', total_ms)
        elif args.type == 'date':
            target_dt = datetime.strptime(args.value, "%Y-%m-%d")
            delta = target_dt - datetime(1990, 1, 1)
            data_bytes = struct.pack('>H', delta.days)
        elif args.type == 's7string':
            max_len = 254
            safe_str = args.value[:254]
            data_bytes = struct.pack(f'>BB{len(safe_str)}s', max_len, len(safe_str), safe_str.encode('ascii'))
        elif args.type == 'dt':
            if args.value.lower() == 'now': dt = datetime.now()
            else: dt = datetime.strptime(args.value, "%Y-%m-%d %H:%M:%S")
            if not 1990 <= dt.year <= 2089:
                raise ValueError('S7 DATE_AND_TIME year must be in 1990..2089')
            year_bcd = bcd_encode(dt.year % 100)
            ms_high = bcd_encode(dt.microsecond // 10000)
            ms_low_dow = ((dt.microsecond // 1000 % 10) << 4) | (dt.isoweekday() % 7 + 1)
            data_bytes = struct.pack('>BBBBBBBB', year_bcd, bcd_encode(dt.month), bcd_encode(dt.day), bcd_encode(dt.hour), bcd_encode(dt.minute), bcd_encode(dt.second), ms_high, ms_low_dow)
        elif args.type == 'hex': data_bytes = bytes.fromhex(args.value.replace(" ", ""))
        else: data_bytes = args.value.encode('ascii')
    except Exception as e:
        logger.error(f"Input format error: {e}")
        return False

    is_bool = (args.type == 'bool')
    if client.write_variable(args.area, args.db, args.offset, args.bit_offset, data_bytes, is_bool):
        logger.info(f"{Color.GREEN}[PROTOCOL_ACCEPTED] PLC acknowledged memory write; readback unverified.{Color.RESET}")
        return True
    return False

def do_diag(client, args):
    aliases = {
        "identity": [0x0011], "characteristics": [0x0012], "components": [0x001C],
        "network": [0x014A], "protection": [0x0232], "connections": [0x0132],
        "rack": [0x0111], "system": [0x0014], "blocks": [0x0015],
        "full": [0x0011, 0x0012, 0x001C, 0x014A, 0x0232, 0x0132, 0x0111, 0x0014, 0x0015]
    }

    user_szl = args.szl_id.lower()
    if user_szl in aliases:
        szl_list = aliases[user_szl]
    else:
        try:
            szl_list = [int(user_szl, 16)]
        except ValueError:
            logger.error(f"Invalid SZL ID or Alias '{args.szl_id}'.")
            return False

    print(f"\n{Color.CYAN}{Color.BOLD}--- S7 DEVICE FINGERPRINT ---{Color.RESET}")
    
    successful = True
    for szl_id in szl_list:
        logger.info(f"Querying SZL ID: 0x{szl_id:04X}...")
        szl_data = client.read_szl(szl_id)
        
        if not szl_data:
            logger.warning(f"[-] SZL 0x{szl_id:04X} not supported by this CPU or returned empty.")
            successful = False
            continue

        if args.debug:
            print(f" {Color.BOLD}Raw SZL Data (0x{szl_id:04X}):{Color.RESET} {Color.GREY}{szl_data.hex().upper()}{Color.RESET}")

        if len(szl_data) < 8: continue

        record_len = struct.unpack('>H', szl_data[0:2])[0]
        num_records = struct.unpack('>H', szl_data[2:4])[0]
        base_offset = 4
        
        if record_len == 0: continue

        if szl_id == 0x0011:
            print(f"\n {Color.BOLD}Decoded Identity (0x0011):{Color.RESET}")
            offset = base_offset
            for _ in range(num_records):
                if offset + record_len > len(szl_data): break
                record_data = szl_data[offset : offset + record_len]
                if len(record_data) >= 2:
                    idx = struct.unpack('>H', record_data[0:2])[0]
                    if idx == 0x0001:
                        mlfb_bytes = record_data[2:22] if len(record_data) >= 22 else b''
                        if mlfb_bytes:
                            mlfb = mlfb_bytes.decode('ascii', errors='ignore').strip('\x00 ')
                            if mlfb: print(f"  - {Color.BLUE}Basic Hardware:{Color.RESET} {mlfb}")
                    elif idx == 0x0007:
                        if len(record_data) >= 28:
                            if record_data[24] == 0x56:
                                print(f"  - {Color.BLUE}Version:{Color.RESET} V{record_data[25]}.{record_data[26]}.{record_data[27]}")
                            else:
                                print(f"  - {Color.BLUE}Version:{Color.RESET} {record_data[24]}.{record_data[25]}.{record_data[26]}.{record_data[27]}")
                    elif args.debug:
                        if idx == 0x0006:
                            mlfb_bytes = record_data[2:22] if len(record_data) >= 22 else b''
                            if mlfb_bytes:
                                mlfb = mlfb_bytes.decode('ascii', errors='ignore').strip('\x00 ')
                                if mlfb: print(f"  - {Color.GREY}[DEBUG] Firmware Base:{Color.RESET} {mlfb}")
                        elif idx == 0x0081:
                            text = record_data[2:].decode('ascii', errors='ignore').strip('\x00 ')
                            if text: print(f"  - {Color.GREY}[DEBUG] Extra Info:{Color.RESET} {text}")
                        else:
                            print(f"  - {Color.GREY}[DEBUG] Unknown Index (0x{idx:04X}):{Color.RESET} {record_data[2:].hex().upper()}")
                offset += record_len

        elif szl_id == 0x0012:
            print(f"\n {Color.BOLD}Decoded CPU Characteristics (0x0012):{Color.RESET}")
            offset = base_offset
            char_map = {
                0x0001: "MC7 processing generating code", 0x0002: "MC7 interpreter",
                0x0101: "1 ms time resolution", 0x0102: "10 ms time resolution",
                0x0103: "No real-time clock", 0x0104: "BCD time-of-day format",
                0x0105: "All time-of-day functions supported", 0x0106: "OB_RT is available",
                0x0201: "Multiprocessor capability", 0x0202: "Cold, warm and hot restart possible",
                0x0203: "Cold and hot restart possible", 0x0204: "Warm and hot restart possible",
                0x0205: "Only warm restart possible", 0x0206: "New distributed I/O config possible during RUN",
                0x0208: "Motion control functionality", 0x0302: "All 32-bit fixed-point instructions",
                0x0303: "All floating-point instructions", 0x0304: "sin, asin, cos, acos, tan, atan, sqr, sqrt, ln, exp",
                0x0305: "Accumulator 3/4 with ENT, PUSH, POP, LEAVE", 0x0306: "Master control relay instructions",
                0x0307: "Address register 1 exists", 0x0308: "Address register 2 exists",
                0x0309: "Area-overlapping addressing", 0x030A: "Area-internal addressing",
                0x030B: "Memory-indirect addressing for bit memory (M)", 0x030C: "Memory-indirect addressing for data blocks (DB)",
                0x030D: "Memory-indirect addressing for DI", 0x030E: "Memory-indirect addressing for local data",
                0x030F: "Parameter transfer instructions", 0x0310: "Memory bit edge instructions for I",
                0x0311: "Memory bit edge instructions for Q", 0x0312: "Memory bit edge instructions for bit memory",
                0x0313: "Memory bit edge instructions for data blocks (DB)", 0x0314: "Memory bit edge instructions for DI",
                0x0315: "Memory bit edge instructions for local data (LD)", 0x0316: "Dynamic evaluation of the ERAB bit",
                0x0317: "Dynamic local data area", 0x0403: "C_DIAG instruction available"
            }
            for _ in range(num_records):
                if offset + record_len > len(szl_data): break
                record_data = szl_data[offset : offset + record_len]
                if len(record_data) >= 2:
                    char_id = struct.unpack('>H', record_data[0:2])[0]
                    desc = char_map.get(char_id, "Unknown Characteristic")
                    print(f"  - {Color.BLUE}ID 0x{char_id:04X}:{Color.RESET} {desc}")
                offset += record_len

        elif szl_id == 0x001C:
            print(f"\n {Color.BOLD}Decoded Components (0x001C):{Color.RESET}")
            offset = base_offset
            labels = {
                1: "System Name", 2: "Module", 3: "Plant Identification",
                4: "Copyright", 5: "Serial Number", 7: "Module Type", 
                8: "Memory Card SN", 9: "Manufacturer ID", 10: "OEM ID",
                11: "Location Designation", 12: "Sync Module 1", 13: "Sync Module 2"
            }
            for _ in range(num_records):
                if offset + record_len > len(szl_data): break
                record_data = szl_data[offset : offset + record_len]
                if len(record_data) >= 2:
                    idx = struct.unpack('>H', record_data[0:2])[0]
                    text = record_data[2:].decode('ascii', errors='ignore').strip('\x00 ')
                    if text:
                        label = labels.get(idx, f"Unknown ({idx})")
                        print(f"  - {Color.BLUE}{label}:{Color.RESET} {text}")
                offset += record_len

        elif szl_id == 0x014A:
            print(f"\n {Color.BOLD}Decoded Network Info (0x014A):{Color.RESET}")
            offset = base_offset
            for _ in range(num_records):
                if offset + record_len > len(szl_data): break
                record_data = szl_data[offset : offset + record_len]
                if len(record_data) >= 20:
                    mac = ":".join(f"{b:02X}" for b in record_data[2:8])
                    ip = ".".join(str(b) for b in record_data[8:12])
                    subnet = ".".join(str(b) for b in record_data[12:16])
                    gw = ".".join(str(b) for b in record_data[16:20])
                    print(f"  - {Color.BLUE}MAC Address:{Color.RESET} {mac}")
                    print(f"  - {Color.BLUE}IP Address:{Color.RESET} {ip}")
                    print(f"  - {Color.BLUE}Subnet Mask:{Color.RESET} {subnet}")
                    print(f"  - {Color.BLUE}Gateway:{Color.RESET} {gw}")
                offset += record_len

        elif szl_id in [0x0232, 0x0131]:
            print(f"\n {Color.BOLD}Decoded Protection State (0x{szl_id:04X}):{Color.RESET}")
            offset = base_offset
            for _ in range(num_records):
                if offset + record_len > len(szl_data): break
                record_data = szl_data[offset : offset + record_len]
                if len(record_data) >= 4:
                    prot_level, mode_switch = record_data[2], record_data[3]
                    modes = {1: "RUN", 2: "RUN-P", 3: "STOP", 4: "MRES", 0: "UNKNOWN"}
                    levels = {1: "1 (No Password)", 2: "2 (Read-Only)", 3: "3 (Read/Write Protected)", 0: "0 (Not Set)"}
                    print(f"  - {Color.BLUE}Protection Level:{Color.RESET} {levels.get(prot_level, f'Unknown ({prot_level})')}")
                    print(f"  - {Color.BLUE}Mode Switch:{Color.RESET} {modes.get(mode_switch, f'Unknown ({mode_switch})')}")
                offset += record_len

        elif szl_id == 0x0132:
            print(f"\n {Color.BOLD}Decoded Connections (0x0132):{Color.RESET}")
            print(f"  - {Color.BLUE}Total Active Connections:{Color.RESET} {num_records}")
            offset = base_offset
            for i in range(num_records):
                if offset + record_len > len(szl_data): break
                record_data = szl_data[offset : offset + record_len]
                print(f"    {Color.GREY}[Conn {i+1}]{Color.RESET} Data: {record_data.hex().upper()}")
                offset += record_len

        elif szl_id == 0x0014:
            print(f"\n {Color.BOLD}Decoded System Areas (0x0014):{Color.RESET}")
            offset = base_offset
            sys_areas = {
                1: ("PII (Inputs)", "bytes"), 2: ("PIQ (Outputs)", "bytes"),
                3: ("Memory (M)", "bytes/flags"), 4: ("Timers (T)", "units"),
                5: ("Counters (C)", "units"), 6: ("Logical Address Space", "bytes"),
                7: ("Local Data Area", "bytes"), 8: ("Memory (M)", "bytes"),
                9: ("Local Data Area", "KB")
            }
            for _ in range(num_records):
                if offset + record_len > len(szl_data): break
                record_data = szl_data[offset : offset + record_len]
                if len(record_data) >= 8:
                    idx = struct.unpack('>H', record_data[0:2])[0]
                    anzahl = struct.unpack('>H', record_data[4:6])[0]
                    reman = struct.unpack('>H', record_data[6:8])[0]
                    area_name, unit = sys_areas.get(idx, (f"Area 0x{idx:04X}", "units"))
                    print(f"  - {Color.BLUE}{area_name}:{Color.RESET} Quantity: {anzahl} {unit} | Retentive: {reman}")
                offset += record_len

        elif szl_id == 0x0015:
            print(f"\n {Color.BOLD}Decoded Block Types (0x0015):{Color.RESET}")
            offset = base_offset
            block_names = {0x0800: "OB", 0x0A00: "DB", 0x0B00: "SDB", 0x0C00: "FC", 0x0E00: "FB"}
            for _ in range(num_records):
                if offset + record_len > len(szl_data): break
                record_data = szl_data[offset : offset + record_len]
                if len(record_data) >= 10:
                    idx = struct.unpack('>H', record_data[0:2])[0]
                    max_anz = struct.unpack('>H', record_data[2:4])[0]
                    max_lng = struct.unpack('>H', record_data[4:6])[0]
                    max_abl = struct.unpack('>I', record_data[6:10])[0]
                    b_name = block_names.get(idx, f"Type 0x{idx:04X}")
                    print(f"  - {Color.BLUE}{b_name}s:{Color.RESET} Max Blocks: {max_anz} | Max Size: {max_lng} KB | Work Mem: {max_abl} bytes")
                offset += record_len

        elif szl_id == 0x0111:
            print(f"\n {Color.BOLD}Decoded Rack Status (0x0111):{Color.RESET}")
            offset = base_offset
            for i in range(num_records):
                if offset + record_len > len(szl_data): break
                record_data = szl_data[offset : offset + record_len]
                print(f"    {Color.GREY}[Slot {i}]{Color.RESET} Status: {record_data.hex().upper()}")
                offset += record_len

        else:
            print(f"\n {Color.BOLD}Decoded Unknown SZL (0x{szl_id:04X}):{Color.RESET}")
            offset = base_offset
            for i in range(num_records):
                if offset + record_len > len(szl_data): break
                record_data = szl_data[offset : offset + record_len]
                print(f"    {Color.GREY}[Record {i+1}]{Color.RESET} Data: {record_data.hex().upper()}")
                offset += record_len
    print()
    return successful

def do_control(client, args):
    logger.info(f"Preparing S7 CPU Control Action: {args.action.upper()}")
    
    if args.action == 'stop':
        res = client.pi_service(b'_STOP')
    elif args.action == 'start':
        res = client.pi_service(b'P_PROGRAM')
    elif args.action == 'compress':
        res = client.pi_service(b'_GARB')
    elif args.action == 'custom':
        if not args.pi_name:
            logger.error("Custom control requires --pi-name argument (e.g., '_STOP')")
            return False
        res = client.pi_service(args.pi_name.encode('ascii'))
    
    if res:
        logger.info(f"{Color.GREEN}[SUCCESS] CPU accepted the control command '{args.action.upper()}'.{Color.RESET}")
    else:
        logger.error(f"[ERROR] CPU rejected or failed to process the control command '{args.action.upper()}'.")
    return bool(res)

def do_inventory(client, args):
    BLOCK_TYPES_HEX = {'OB': 0x38, 'DB': 0x41, 'SDB': 0x42, 'FC': 0x43, 'SFC': 0x44, 'FB': 0x45, 'SFB': 0x46}
    RETURN_CODES = {
        0xFF: "Success", 0x01: "Hardware error", 0x03: "Access denied", 
        0x0A: "Object does not exist", 0x11: "Block not found", 0x1A: "Insufficient working memory",
        0x1B: "Insufficient load memory"
    }
    LANGUAGES = {0x01: "AWL / STL", 0x02: "KOP / LAD", 0x03: "FUP / FBD", 0x04: "SCL", 0x05: "DB", 0x06: "GRAPH"}

    if args.block_type:
        # --- 2. LIST BLOCKS OF TYPE (0x02) ---
        logger.info(f"Querying Block List for type {args.block_type}...")
        type_hex = BLOCK_TYPES_HEX[args.block_type]
        data = struct.pack('>BBHBB', 0xFF, 0x09, 2, 0x30, type_hex)
        
        ret_code, payload = client.list_blocks_functions(0x02, data)
        
        if ret_code is None:
            logger.error("CPU did not respond or connection failed during request.")
            return False
        if ret_code != 0xFF:
            logger.error(f"CPU rejected List Blocks of Type request. Return Code: 0x{ret_code:02X} ({RETURN_CODES.get(ret_code, 'Unknown')})")
            return False
            
        if len(payload) % 4:
            logger.error('[PROTOCOL ERROR] Truncated block inventory entry')
            return False
        print(f"\n{Color.CYAN}{Color.BOLD}--- S7 BLOCK NUMBERS FOUND ({args.block_type}) ---{Color.RESET}")
        if payload:
            block_numbers = []
            for i in range(0, len(payload), 4):
                if i + 2 <= len(payload):
                    block_numbers.append(struct.unpack('>H', payload[i:i+2])[0])
            print(f"  - {Color.BLUE}Blocks IDs:{Color.RESET} {', '.join(map(str, block_numbers))}")
        else:
            print(f"  - {Color.YELLOW}No blocks of this type returned.{Color.RESET}")

    else:
        # --- 1. LIST BLOCKS (0x01) ---
        logger.info("Executing Master Block Inventory (Function Group 0x03)...")
        data = struct.pack('>BBH', 0x0A, 0x00, 0)
        ret_code, payload = client.list_blocks_functions(0x01, data)
        
        if ret_code is None:
            logger.error("CPU did not respond or connection failed during request.")
            return False
        if ret_code != 0xFF:
            logger.error(f"CPU rejected List Blocks request. Return Code: 0x{ret_code:02X} ({RETURN_CODES.get(ret_code, 'Unknown')})")
            return False

        if len(payload) % 4:
            logger.error('[PROTOCOL ERROR] Truncated inventory entry')
            return False
        print(f"\n{Color.CYAN}{Color.BOLD}--- S7 CURRENT BLOCK INVENTORY ---{Color.RESET}")
        if payload:
            offset = 0
            while offset + 4 <= len(payload):
                block_bytes = payload[offset:offset+4]
                if block_bytes[0] == 0x30:
                    b_type = block_bytes[1]
                    count = struct.unpack('>H', block_bytes[2:4])[0]
                    name = {v: k for k, v in BLOCK_TYPES_HEX.items()}.get(b_type, f"Type 0x{b_type:02X}")
                    if count > 0:
                        print(f"  - {Color.BLUE}{name}s:{Color.RESET} {count} blocks present")
                offset += 4
        else:
            print(f"  - {Color.YELLOW}Inventory empty or unreadable.{Color.RESET}")
    print()
    return True

def main():
    custom_usage = (
        f"{Color.GREEN}s7comm_master.py{Color.RESET} "
        f"{Color.YELLOW}[-H HOST] [-c COMMAND] [-p PORT] [-r RACK] [-s SLOT] "
        f"[-A AREA] [-D DB] [-O OFFSET] [-B BIT] [-S SIZE] [-v VALUE] [-t TYPE] [-a ACTION]{Color.RESET}"
    )

    parser = CustomArgumentParser(
        description=f"{Color.BOLD}S7comm Master CLI (by z4y_d3n){Color.RESET}",
        usage=custom_usage,
        formatter_class=ColoredHelpFormatter
    )
    
    parser.add_argument("-H", "--host", required=True, type=str, help="Target PLC IP Address.")
    parser.add_argument("-c", "--command", required=True, choices=["read", "write", "diag", "control", "inventory"], help="Action to execute.")
    parser.add_argument("-p", "--port", type=int, default=102, help="TCP ISO Port (Default: 102).")
    parser.add_argument("--debug", action="store_true", help="Enable Hex network trace logs.")
    
    parser.add_argument("-r", "--rack", type=int, default=0, help="PLC Rack Number (Default: 0)")
    parser.add_argument("-s", "--slot", type=int, default=2, help="PLC Slot Number (Default: 2)")
    
    parser.add_argument("-A", "--area", choices=["db", "m", "i", "q", "c", "t", "pi", "pq"], default="db", help="Memory Area")
    parser.add_argument("-D", "--db", type=int, default=1, help="Data Block Number (if area is db)")
    parser.add_argument("-O", "--offset", type=int, default=0, help="Byte Offset")
    parser.add_argument("-B", "--bit-offset", type=int, default=0, help="Bit Offset (0-7). Required for BOOL operations.")
    parser.add_argument("-S", "--size", type=int, default=1, help="Number of bytes to read (ignored for specific types)")
    
    parser.add_argument("--szl-id", type=str, default="identity", help="Alias: identity, characteristics, components, network, protection, connections, rack, system, blocks, full. Or Hex ID.")
    
    parser.add_argument("-v", "--value", type=str, help="Value to write (-c write)")
    parser.add_argument("-t", "--type", choices=["hex", "bool", "byte", "char", "int16", "word", "dint", "udint", "dword", "float32", "string", "s7string", "time", "s5time", "tod", "date", "dt"], default="hex", help="Data format conversion type.")
    
    parser.add_argument("-a", "--action", choices=["start", "stop", "compress", "custom"], help="CPU Control action (-c control).")
    parser.add_argument("--pi-name", type=str, help="Custom PI Service name (e.g. '_STOP').")
    
    parser.add_argument("--block-type", type=str, choices=["OB", "DB", "SDB", "FC", "SFC", "FB", "SFB"], help="Specific Block Type to enumerate (-c inventory).")

    if len(sys.argv) == 1:
        parser.print_usage()
        sys.exit(1)
        
    parser.usage = argparse.SUPPRESS
    args = parser.parse_args()
    
    if args.command == "write" and args.value is None:
        parser.error("The '-v' (Value) argument is required with 'write'.")
    if args.command == "control" and args.action is None:
        parser.error("The '-a' (Action) argument is required with 'control'.")

    if not 1 <= args.port <= 65535 or not 0 <= args.rack <= 7 or not 0 <= args.slot <= 31:
        parser.error('Port/rack/slot outside wire range.')
    if not 0 <= args.db <= 65535 or args.offset < 0 or not 0 <= args.bit_offset <= 7 or args.size < 1:
        parser.error('DB/offset/bit/size outside valid range.')
    if args.command == 'control' and args.action == 'custom' and not args.pi_name:
        parser.error('Custom control requires --pi-name.')
    setup_logger(args.debug)
    client = RawS7Client(args.host, port=args.port, rack=args.rack, slot=args.slot)

    if not client.connect():
        sys.exit(1)

    try:
        handlers = {"read": do_read, "write": do_write, "diag": do_diag, "control": do_control, "inventory": do_inventory}
        return 0 if handlers[args.command](client, args) else 1
    except (ValueError, struct.error, OSError) as error:
        logger.error(f"[FAILED/LOCAL_ERROR] {error}")
        return 1
    finally:
        client.close()

if __name__ == "__main__":
    sys.exit(main())
