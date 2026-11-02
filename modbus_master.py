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

# 1. Silence KeyboardInterrupt (Ctrl+C) globally
def signal_handler(sig, frame):
    print("\n\033[93m[WARNING] Execution cancelled by user (Ctrl+C). Exiting cleanly...\033[0m")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Enable ANSI support for older Windows terminals (CMD)
if os.name == 'nt':
    os.system("")

# Universal ANSI color palette
class Color:
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    GREY = '\033[90m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# Custom log formatter to maintain terminal colors
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

# Setup central logger
logger = logging.getLogger("ModbusMasterCLI")
def setup_logger(debug_mode):
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColoredFormatter())
    # Replace only handlers created by this setup function.
    for owned_handler in getattr(setup_logger, "_owned_handlers", ()):
        logger.removeHandler(owned_handler)
        owned_handler.close()
    logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
    logger.addHandler(handler)
    setup_logger._owned_handlers = (handler,)

# Custom Argument Parser for clearer syntax error handling
class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        formatted_message = message[0].upper() + message[1:] if message else message
        print(f"\n{Color.RED}{Color.BOLD}[SYNTAX ERROR]{Color.RESET}")
        print(f"{Color.RED}Detail: {formatted_message}{Color.RESET}")
        print(f"{Color.YELLOW}Hint: Review your syntax. You can add '-h' or '--help' to see required and allowed arguments.{Color.RESET}\n")
        self.exit(2)

# Custom Help Formatter to colorize the "usage: " prefix
class ColoredHelpFormatter(argparse.HelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = f"{Color.CYAN}{Color.BOLD}Usage:{Color.RESET} "
        super().add_usage(usage, actions, groups, prefix)

    def _format_args(self, action, default_metavar):
        if action.nargs == argparse.ONE_OR_MORE:
            get_metavar = self._metavar_formatter(action, default_metavar)
            return '%s' % get_metavar(1)
        return super()._format_args(action, default_metavar)

# Modbus Exception Code Mapping
MODBUS_EXCEPTIONS = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Server Device Failure",
    5: "Acknowledge",
    6: "Server Device Busy",
    8: "Memory Parity Error",
    10: "Gateway Path Unavailable",
    11: "Gateway Target Device Failed to Respond"
}

def get_type_name(type_code, count):
    types = {
        'di': ('Discrete Input', 'Discrete Inputs'),
        'co': ('Coil', 'Coils'),
        'ir': ('Input Register', 'Input Registers'),
        'hr': ('Holding Register', 'Holding Registers')
    }
    name_singular, name_plural = types.get(type_code, (type_code.upper(), type_code.upper() + 's'))
    return name_singular if count == 1 else name_plural

def get_endian(order_str):
    return '>' if order_str.lower() == 'big' else '<'


# --- RAW SOCKET MODBUS CLIENT ---
class RawModbusClient:
    def __init__(self, host, port=502, timeout=3.0, retries=2):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.sock = None
        self.tid = 1 
        self.last_outcome = 'NOT_SENT'
        self.last_exception_code = None

    def connect(self, suppress_logs=False):
        self.last_exception_code = None
        for attempt in range(self.retries + 1):
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                self.sock.connect((self.host, self.port))
                return True
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                if self.sock: 
                    self.sock.close()
                    self.sock = None
                if attempt == self.retries and not suppress_logs:
                    logger.error(f"[CONNECTION ERROR] Failed to connect to {self.host}:{self.port} - {e}")
                    return False
        return False

    def close(self):
        if self.sock: 
            self.sock.close()
            self.sock = None

    def _fail(self, message, suppress_logs=False, outcome='FAILED'):
        self.last_outcome = outcome
        if outcome != 'REJECTED':
            self.last_exception_code = None
        if not suppress_logs:
            logger.error(f"[{outcome}] {message}")
        return False

    def _valid_range(self, address, count, maximum, suppress_logs=False):
        if not (isinstance(address, int) and isinstance(count, int) and
                0 <= address <= 65535 and 1 <= count <= maximum and address + count <= 65536):
            return self._fail(f"Invalid address/count: {address}/{count} (maximum {maximum}).", suppress_logs, 'NOT_SENT')
        return True

    def _recv_exact(self, size, deadline):
        data = bytearray()
        while len(data) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("transaction deadline expired")
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("EOF before complete Modbus frame")
            data.extend(chunk)
        return bytes(data)

    def _send_recv(self, unit_id, fc, payload, address=0, suppress_logs=False):
        self.last_exception_code = None
        self.last_outcome = 'NOT_SENT'
        if not self.sock:
            self._fail("Socket not connected.", suppress_logs, 'NOT_SENT')
            return None
        if not (0 <= unit_id <= 255 and 1 <= fc <= 127 and len(payload) <= 252):
            return self._fail("Invalid Unit ID, function or PDU length.", suppress_logs, 'NOT_SENT')
        tid = self.tid
        self.tid = (self.tid + 1) & 0xFFFF
        request_frame = struct.pack('>HHHBB', tid, 0, 2 + len(payload), unit_id, fc) + payload
        try:
            deadline = time.monotonic() + self.timeout
            # A sendall failure may follow a partial send; do not retry writes.
            self.last_outcome = 'INDETERMINATE'
            self.sock.settimeout(self.timeout)
            self.sock.sendall(request_frame)
            r_tid, r_pid, r_len, r_uid = struct.unpack('>HHHB', self._recv_exact(7, deadline))
            if r_tid != tid or r_pid != 0 or r_uid != unit_id or not 2 <= r_len <= 254:
                raise ValueError("Mismatched MBAP transaction/protocol/unit or invalid length")
            resp_pdu = self._recv_exact(r_len - 1, deadline)
            if resp_pdu[0] == (fc | 0x80):
                if len(resp_pdu) != 2:
                    raise ValueError("Malformed Modbus exception PDU")
                code = resp_pdu[1]
                self.last_exception_code = code
                return self._fail(f"Modbus exception {code}: {MODBUS_EXCEPTIONS.get(code, 'Unknown Exception')} at address {address}.", suppress_logs, 'REJECTED')
            if resp_pdu[0] != fc:
                raise ValueError("Mismatched response function code")
            self.last_outcome = 'PROTOCOL_ACCEPTED'
            return resp_pdu[1:]
        except ValueError as e:
            self.close()
            self._fail(f"{e}; acceptance is unconfirmed at address {address}.", suppress_logs, 'INDETERMINATE')
            return None
        except (OSError, ConnectionError) as e:
            self.close()  # Never consume a late reply as a later request's answer.
            self._fail(f"{e}; response unknown at address {address}.", suppress_logs, 'INDETERMINATE')
            return None

    # --- Standard Modbus Functions ---
    def read_discrete_inputs(self, address, count, device_id=1, suppress_logs=False):
        return self._read_bits(2, address, count, device_id, suppress_logs)

    def read_coils(self, address, count, device_id=1, suppress_logs=False):
        return self._read_bits(1, address, count, device_id, suppress_logs)

    def read_input_registers(self, address, count, device_id=1, suppress_logs=False):
        return self._read_regs(4, address, count, device_id, suppress_logs)

    def read_holding_registers(self, address, count, device_id=1, suppress_logs=False):
        return self._read_regs(3, address, count, device_id, suppress_logs)

    def write_coil(self, address, value, device_id=1):
        if not self._valid_range(address, 1, 1): return False
        val = 0xFF00 if value else 0x0000
        payload = struct.pack('>HH', address, val)
        return self._write_echo(device_id, 5, payload, payload, address)

    def write_coils(self, address, values, device_id=1):
        if not self._valid_range(address, len(values), 1968): return False
        byte_count = (len(values) + 7) // 8
        payload = struct.pack('>HHB', address, len(values), byte_count)
        byte_array = bytearray(byte_count)
        for i, v in enumerate(values):
            if v: byte_array[i//8] |= (1 << (i%8))
        return self._write_echo(device_id, 15, payload + byte_array, payload[:4], address)

    def write_register(self, address, value, device_id=1):
        if not self._valid_range(address, 1, 1): return False
        if not isinstance(value, int) or not 0 <= value <= 65535:
            return self._fail("Register value must be an unsigned 16-bit integer.", outcome='NOT_SENT')
        payload = struct.pack('>HH', address, value)
        return self._write_echo(device_id, 6, payload, payload, address)

    def write_registers(self, address, values, device_id=1):
        if not self._valid_range(address, len(values), 123): return False
        if any(not isinstance(v, int) or not 0 <= v <= 65535 for v in values):
            return self._fail("Register values must be unsigned 16-bit integers.", outcome='NOT_SENT')
        byte_count = len(values) * 2
        payload = struct.pack('>HHB', address, len(values), byte_count)
        for v in values:
            payload += struct.pack('>H', v)
        return self._write_echo(device_id, 16, payload, payload[:4], address)

    def _write_echo(self, device_id, fc, payload, expected, address):
        response = self._send_recv(device_id, fc, payload, address)
        if response is None or response is False: return False
        if response != expected:
            return self._fail("Write echo does not match requested address/value/count; acceptance unconfirmed.", outcome='INDETERMINATE')
        return True

    def read_device_information(self, read_code, object_id, device_id=1):
        info = {}
        if read_code not in (1, 2, 3, 4) or not 0 <= object_id <= 255:
            self._fail("Invalid device identification request.", outcome='NOT_SENT')
            return None
        for _ in range(256):
            resp_pdu = self._send_recv(device_id, 43, struct.pack('>BBB', 14, read_code, object_id))
            if resp_pdu is None or resp_pdu is False: return None
            try:
                if (len(resp_pdu) < 6 or resp_pdu[0] != 14 or resp_pdu[1] != read_code or
                        resp_pdu[2] not in (1, 2, 3, 0x81, 0x82, 0x83) or resp_pdu[3] not in (0, 255)):
                    raise ValueError("Malformed device identification header")
                idx = 6
                for _ in range(resp_pdu[5]):
                    if idx + 2 > len(resp_pdu): raise ValueError("Truncated identity object header")
                    obj_id, obj_len = resp_pdu[idx:idx+2]
                    idx += 2
                    if obj_id < object_id or obj_id in info or idx + obj_len > len(resp_pdu):
                        raise ValueError("Truncated, repeated or out-of-range identity object")
                    info[obj_id] = resp_pdu[idx:idx+obj_len]
                    idx += obj_len
                if idx != len(resp_pdu): raise ValueError("Unexpected trailing identity data")
                if resp_pdu[3] == 0: break
                next_id = resp_pdu[4]
                if read_code == 4 or not info or next_id <= max(info):
                    raise ValueError("Non-progressing identity continuation")
                object_id = next_id
            except ValueError as e:
                self._fail(str(e))
                return None
        else:
            self._fail("Identity continuation limit exceeded.")
            return None
        class Result: pass
        res = Result()
        res.information = info
        res.isError = lambda: False
        return res

    # --- Internal parsers ---
    def _read_bits(self, fc, address, count, device_id, suppress_logs=False):
        if not self._valid_range(address, count, 2000, suppress_logs): return False
        payload = struct.pack('>HH', address, count)
        resp = self._send_recv(device_id, fc, payload, address, suppress_logs)
        if resp is None or resp is False: return resp
        expected = (count + 7) // 8
        if len(resp) != expected + 1 or resp[0] != expected:
            return self._fail("Bit response byte count/length does not match request.", suppress_logs)
        if count % 8 and resp[-1] >> (count % 8):
            return self._fail("Nonzero unused bits in bit response.", suppress_logs)
        
        bits = []
        for b in resp[1:]:
            for i in range(8):
                bits.append(bool((b >> i) & 1))
        
        class Result: pass
        res = Result()
        res.bits = bits[:count]
        return res

    def _read_regs(self, fc, address, count, device_id, suppress_logs=False):
        if not self._valid_range(address, count, 125, suppress_logs): return False
        payload = struct.pack('>HH', address, count)
        resp = self._send_recv(device_id, fc, payload, address, suppress_logs)
        if resp is None or resp is False: return resp
        if len(resp) != count * 2 + 1 or resp[0] != count * 2:
            return self._fail("Register response byte count/length does not match request.", suppress_logs)
        
        regs = []
        for i in range(1, len(resp), 2):
            if i + 1 < len(resp):
                regs.append(struct.unpack('>H', resp[i:i+2])[0])
                
        class Result: pass
        res = Result()
        res.registers = regs[:count]
        return res

def check_modbus_error(rr):
    if rr is None or rr is False:
        return True
    return False

# --- Data Formatting Functions ---
def encode_payload(values, fmt_type, byteorder, wordorder):
    registers = []
    for v in values:
        if fmt_type == 'float32': packed = struct.pack('>f', float(v))
        elif fmt_type == 'int32': packed = struct.pack('>i', int(v))
        elif fmt_type == 'uint32': packed = struct.pack('>I', int(v))
        elif fmt_type == 'int16': packed = struct.pack('>h', int(v))
        elif fmt_type == 'uint16': packed = struct.pack('>H', int(v))
        else: raise ValueError(f"Format {fmt_type} not supported")
        words = [packed[i:i+2] for i in range(0, len(packed), 2)]
        if byteorder == '<': words = [word[::-1] for word in words]
        regs = [struct.unpack('>H', word)[0] for word in words]
        
        if wordorder == '<' and len(regs) > 1: regs.reverse()
        registers.extend(regs)
    return registers

def decode_payload(registers, fmt_type, number, byteorder, wordorder):
    values = []
    regs_per_value = 2 if '32' in fmt_type else 1
    
    for i in range(number):
        chunk = registers[i * regs_per_value : (i + 1) * regs_per_value]
        if wordorder == '<' and len(chunk) > 1: chunk = chunk[::-1]
            
        words = [struct.pack('>H', reg) for reg in chunk]
        if byteorder == '<': words = [word[::-1] for word in words]
        packed = b''.join(words)
        
        if fmt_type == 'float32': val = struct.unpack('>f', packed)[0]
        elif fmt_type == 'int32': val = struct.unpack('>i', packed)[0]
        elif fmt_type == 'uint32': val = struct.unpack('>I', packed)[0]
        elif fmt_type == 'int16': val = struct.unpack('>h', packed)[0]
        elif fmt_type == 'uint16': val = struct.unpack('>H', packed)[0]
        
        values.append(val)
    return values

def print_read_results(results, start_address, is_bool, format_type=''):
    addr_step = 2 if not is_bool and '32' in format_type else 1
    for i, val in enumerate(results):
        current_address = start_address + (i * addr_step)
        val_str = f"{Color.GREEN}True{Color.RESET}" if is_bool and val else (f"{Color.RED}False{Color.RESET}" if is_bool else f"{Color.GREEN}{val}{Color.RESET}")
        print(f" Address [{Color.YELLOW}{current_address:04d}{Color.RESET}] -> {val_str}")
    print()

# --- Command Execution Logic ---
def do_read(client, args, fmt_type, byteorder, wordorder):
    type_name = get_type_name(args.type, args.number)
    logger.info(f"Reading {args.number} {type_name} starting at address {args.address}...")
    
    multiplier = 2 if args.bits == 32 and args.type in ['ir', 'hr'] else 1
    total_registers_to_read = args.number * multiplier
    MAX_READ = 100 if args.type in ['ir', 'hr'] else 800
    
    raw_results = []

    for offset in range(0, total_registers_to_read, MAX_READ):
        chunk_size = min(MAX_READ, total_registers_to_read - offset)
        current_address = args.address + offset
        
        if args.type == 'di': rr = client.read_discrete_inputs(current_address, chunk_size, device_id=args.device_id)
        elif args.type == 'co': rr = client.read_coils(current_address, chunk_size, device_id=args.device_id)
        elif args.type == 'ir': rr = client.read_input_registers(current_address, chunk_size, device_id=args.device_id)
        elif args.type == 'hr': rr = client.read_holding_registers(current_address, chunk_size, device_id=args.device_id)

        if check_modbus_error(rr): return False

        if args.type in ['di', 'co']: raw_results.extend(rr.bits[:chunk_size])
        else: raw_results.extend(rr.registers[:chunk_size])

    print(f"\n{Color.CYAN}{Color.BOLD}--- Read Results ---{Color.RESET}")
    if args.type in ['di', 'co']:
        print_read_results(raw_results[:args.number], args.address, is_bool=True)
    else:
        decoded_values = decode_payload(raw_results, fmt_type, args.number, byteorder, wordorder)
        print_read_results(decoded_values[:args.number], args.address, is_bool=False, format_type=fmt_type)
    return True

def do_watch(client, args, fmt_type, byteorder, wordorder):
    type_name = get_type_name(args.type, args.number)
    logger.info(f"Starting WATCH mode for {args.number} {type_name} at address {args.address}...")
    print(f"{Color.GREY}Polling interval: {args.wait}s | Press Ctrl+C to stop.{Color.RESET}\n")
    
    multiplier = 2 if args.bits == 32 and args.type in ['ir', 'hr'] else 1
    total_registers_to_read = args.number * multiplier
    MAX_READ = 100 if args.type in ['ir', 'hr'] else 800
    
    previous_values = None
    
    try:
        while True:
            raw_results = []
            error_occurred = False
            
            for offset in range(0, total_registers_to_read, MAX_READ):
                chunk_size = min(MAX_READ, total_registers_to_read - offset)
                current_address = args.address + offset
                
                # Logs are suppressed to avoid spamming the console every second
                if args.type == 'di': rr = client.read_discrete_inputs(current_address, chunk_size, device_id=args.device_id, suppress_logs=True)
                elif args.type == 'co': rr = client.read_coils(current_address, chunk_size, device_id=args.device_id, suppress_logs=True)
                elif args.type == 'ir': rr = client.read_input_registers(current_address, chunk_size, device_id=args.device_id, suppress_logs=True)
                elif args.type == 'hr': rr = client.read_holding_registers(current_address, chunk_size, device_id=args.device_id, suppress_logs=True)

                if check_modbus_error(rr): 
                    error_occurred = True
                    break

                if args.type in ['di', 'co']: raw_results.extend(rr.bits[:chunk_size])
                else: raw_results.extend(rr.registers[:chunk_size])
                
            if not error_occurred:
                if args.type in ['di', 'co']:
                    current_values = raw_results[:args.number]
                    is_bool = True
                else:
                    is_bool = False
                    current_values = decode_payload(raw_results, fmt_type, args.number, byteorder, wordorder)[:args.number]
                        
                # Compare current vs previous and print only when a change is detected
                if current_values != previous_values:
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                    print(f"{Color.CYAN}[{timestamp}] Values Updated:{Color.RESET}")
                    
                    addr_step = 2 if not is_bool and '32' in fmt_type else 1
                    for i, val in enumerate(current_values):
                        current_address = args.address + (i * addr_step)
                        # Print only the specific registers that changed within the block
                        if previous_values is None or previous_values[i] != val:
                            val_str = f"{Color.GREEN}True{Color.RESET}" if is_bool and val else (f"{Color.RED}False{Color.RESET}" if is_bool else f"{Color.GREEN}{val}{Color.RESET}")
                            print(f" Address [{Color.YELLOW}{current_address:04d}{Color.RESET}] -> {val_str}")
                    print()
                    previous_values = current_values
                    
            elif client.sock is None:
                logger.warning("Read response unavailable; reconnecting before the next watch poll.")
                client.connect(suppress_logs=True)
            time.sleep(args.wait)
    except KeyboardInterrupt:
        pass # The global signal handler will catch this and exit cleanly
    return True

def do_write(client, args, fmt_type, byteorder, wordorder):
    type_name = get_type_name(args.type, len(args.values))
    logger.info(f"Writing {len(args.values)} {type_name} starting at address {args.address}...")
    
    if args.bits == 32 and args.address % 2 != 0:
        logger.warning(f"Address {args.address} is odd. Writing 32-bit values to unaligned addresses may cause memory overlapping.")

    try:
        if args.type == 'co':
            values = [bool(int(v)) for v in args.values]
            MAX_WRITE_CO = 800 
            
            for offset in range(0, len(values), MAX_WRITE_CO):
                chunk = values[offset : offset + MAX_WRITE_CO]
                current_address = args.address + offset
                
                if len(chunk) == 1: rr = client.write_coil(current_address, chunk[0], device_id=args.device_id)
                else: rr = client.write_coils(current_address, chunk, device_id=args.device_id)
                
                if check_modbus_error(rr): return False
                
        elif args.type == 'hr':
            MAX_WRITE_HR = 100
            payload = encode_payload(args.values, fmt_type, byteorder, wordorder)
            
            for offset in range(0, len(payload), MAX_WRITE_HR):
                chunk = payload[offset : offset + MAX_WRITE_HR]
                current_address = args.address + offset
                
                if len(chunk) == 1: rr = client.write_register(current_address, chunk[0], device_id=args.device_id)
                else: rr = client.write_registers(current_address, chunk, device_id=args.device_id)
                
                if check_modbus_error(rr): return False

        logger.info(f"{Color.GREEN}[PROTOCOL_ACCEPTED] All Modbus write echoes matched the requested address/value/count.{Color.RESET}")
        return True

    except (ValueError, struct.error, OverflowError) as e:
        logger.warning(f"Verify that the input value matches the expected format: {e}")
        return False

def do_fingerprint(client, args):
    logger.info(f"Starting Modbus TCP Identity Fingerprinting for Unit ID {args.device_id}...")
    
    fingerprint_data = {
        "device_info": {}, 
        "supported_functions": []
    }
    
    logger.info("Level 1: Querying Basic Device ID (Read Code 1)...")
    rr_basic = client.read_device_information(read_code=0x01, object_id=0x00, device_id=args.device_id)
    if rr_basic is not None and not rr_basic.isError():
        fingerprint_data["supported_functions"].append("FC43 Basic Identity (0x01)")
        info = getattr(rr_basic, 'information', {})
        if 0 in info: fingerprint_data["device_info"]["Vendor Name"] = info[0].decode('utf-8', errors='ignore')
        if 1 in info: fingerprint_data["device_info"]["Product Code"] = info[1].decode('utf-8', errors='ignore')
        if 2 in info: fingerprint_data["device_info"]["Revision"] = info[2].decode('utf-8', errors='ignore')
    else: logger.warning(" [-] Basic query returned no valid identity response.")

    logger.info("Level 2: Querying Regular Device ID (Read Code 2)...")
    rr_reg = client.read_device_information(read_code=0x02, object_id=0x00, device_id=args.device_id)
    if rr_reg is not None and not rr_reg.isError():
        fingerprint_data["supported_functions"].append("FC43 Regular Identity (0x02)")
        info = getattr(rr_reg, 'information', {})
        if 3 in info: fingerprint_data["device_info"]["Vendor URL"] = info[3].decode('utf-8', errors='ignore')
        if 4 in info: fingerprint_data["device_info"]["Product Name"] = info[4].decode('utf-8', errors='ignore')
        if 5 in info: fingerprint_data["device_info"]["Model Name"] = info[5].decode('utf-8', errors='ignore')
        if 6 in info: fingerprint_data["device_info"]["User Application"] = info[6].decode('utf-8', errors='ignore')
    else: logger.warning(" [-] Regular query returned no valid identity response.")

    logger.info("Level 3: Querying Extended Device ID (Read Code 3)...")
    rr_ext = client.read_device_information(read_code=0x03, object_id=0x80, device_id=args.device_id)
    if rr_ext is not None and not rr_ext.isError():
        fingerprint_data["supported_functions"].append("FC43 Extended Identity (0x03)")
        info = getattr(rr_ext, 'information', {})
        for key, value in info.items():
            if key >= 0x80:
                fingerprint_data["device_info"][f"Vendor Ext {key}"] = value.decode('utf-8', errors='ignore')
    else: logger.warning(" [-] Extended query returned no valid identity response.")

    # Terminal formatted output instead of JSON
    print(f"\n{Color.CYAN}{Color.BOLD}--- FINGERPRINT RESULTS ---{Color.RESET}")
    print(f" {Color.BOLD}Target:{Color.RESET} {args.host}:{args.port} (Unit ID: {args.device_id})")
    
    if fingerprint_data["supported_functions"]:
        print(f"\n {Color.BOLD}Supported Identity Functions:{Color.RESET}")
        for sf in fingerprint_data["supported_functions"]:
            print(f"  - {Color.GREEN}{sf}{Color.RESET}")
            
    if fingerprint_data["device_info"]:
        print(f"\n {Color.BOLD}Device Information:{Color.RESET}")
        for key, val in fingerprint_data["device_info"].items():
            print(f"  {Color.BLUE}{key}:{Color.RESET} {val}")
    else:
        print(f"\n {Color.YELLOW}No device information could be extracted.{Color.RESET}")
    print()
    return bool(fingerprint_data['supported_functions'])

def do_scan(args):
    logger.info(f"Starting Unit ID scan on {args.host}:{args.port} (Timeout: 0.5s) ...")
    
    # We use a short timeout specifically for scanning to speed up the 256 iterations
    scan_client = RawModbusClient(args.host, args.port, timeout=0.5, retries=0)
    if not scan_client.connect(suppress_logs=True):
        logger.error(f"Failed to establish base connection to {args.host}:{args.port} for scanning.")
        return False
        
    found_ids = []
    try:
        for uid in range(256):
            if scan_client.sock is None and not scan_client.connect(suppress_logs=True):
                continue
            rr = scan_client.read_holding_registers(address=0, count=1, device_id=uid, suppress_logs=True)
            
            if rr is not None and (rr is not False or (scan_client.last_outcome == 'REJECTED' and scan_client.last_exception_code == 0x02)):
                logger.info(f"{Color.GREEN}[+] Unit ID {uid} responded.{Color.RESET}")
                found_ids.append(uid)
    finally:
        scan_client.close()

    print(f"\n{Color.CYAN}{Color.BOLD}--- SCAN RESULTS ---{Color.RESET}")
    if found_ids:
        print(f"Responsive Unit IDs: {Color.GREEN}{found_ids}{Color.RESET}\n")
    else:
        print(f"{Color.YELLOW}No responsive downstream Unit IDs established.{Color.RESET}\n")
    return bool(found_ids)

# --- Main Entry Point ---
def main():
    custom_usage = (
        f"{Color.GREEN}modbus_master.py{Color.RESET} "
        f"{Color.YELLOW}[-H HOST] [-c COMMAND] [-p PORT] [-d DEVICE_ID] [-t TYPE] "
        f"[-a ADDRESS] [-n NUMBER] [-v VALUE(S)] [-f FORMAT] [-b BITS] [-w WAIT]{Color.RESET}"
    )
    
    parser = CustomArgumentParser(
        description=f"{Color.BOLD}Modbus TCP Master CLI (by z4y_d3n){Color.RESET}",
        usage=custom_usage,
        formatter_class=ColoredHelpFormatter
    )
    
    parser.add_argument("-H", "--host", required=True, type=str, help="Server IP (e.g., 192.168.1.100)")
    parser.add_argument("-c", "--command", required=True, choices=["read", "write", "fingerprint", "scan", "watch"], help="Action to execute")
    parser.add_argument("-p", "--port", type=int, default=502, help="TCP Port (default: 502)")
    parser.add_argument("-d", "--device-id", type=int, default=1, help="Slave/Unit ID (default: 1)")
    parser.add_argument("--debug", action="store_true", help="Enable DEBUG logs")
    
    # Required only for Read/Write/Watch commands
    parser.add_argument("-t", "--type", choices=["di", "co", "ir", "hr"], help="Memory type: di (Discrete Input), co (Coil), ir (Input Register), hr (Holding Register). Required for read/write/watch")
    parser.add_argument("-a", "--address", type=int, help="Starting address (Required for read/write/watch)")
    parser.add_argument("-n", "--number", type=int, default=1, help="Amount of values to read (-c read/watch)")
    parser.add_argument("-v", "--values", nargs='+', metavar="VALUE(S)", help="Values to write, separated by spaces (-c write)")
    parser.add_argument("-w", "--wait", type=float, default=1.0, help="Polling interval in seconds for continuous monitoring (-c watch). Default: 1.0")
    
    parser.add_argument("-f", "--format", choices=["uint", "int", "float"], default="uint", help="Data format (ir/hr only). Default: uint")
    parser.add_argument("-b", "--bits", type=int, choices=[16, 32], default=16, help="Register size in bits (16 or 32). Default: 16")
    parser.add_argument("--byteorder", choices=["big", "little"], default="big", help="Byte Order (Endianness)")
    parser.add_argument("--wordorder", choices=["big", "little"], default="big", help="Word Order")

    if len(sys.argv) == 1:
        parser.print_usage()
        sys.exit(1)
        
    parser.usage = argparse.SUPPRESS
    args = parser.parse_args()

    # --- Argument Logic Validations ---
    if args.command in ["read", "write", "watch"]:
        if args.type is None or args.address is None:
            parser.error(f"Arguments -t/--type and -a/--address are strictly required for the '{args.command}' command.")
            
    if args.command == "write":
        if not args.values:
            parser.error("The '--values' / '-v' argument is required with '-c write'.")
        if args.type in ["di", "ir"]:
            parser.error(f"Memory type '{args.type}' is read-only.")
            
    if args.format == "float" and args.bits == 16:
        parser.error("The 'float' format requires setting the size to 32 bits (-b 32).")
    if not 1 <= args.port <= 65535 or not 0 <= args.device_id <= 255:
        parser.error("Port must be 1..65535 and Unit ID must be 0..255.")
    if not math.isfinite(args.wait) or args.wait <= 0:
        parser.error("Polling interval must be a finite positive number.")
    if args.command in ['read', 'watch'] and args.number <= 0:
        parser.error("Number of values must be positive.")
    if args.command in ['read', 'write', 'watch']:
        count = len(args.values) if args.command == 'write' else args.number
        if args.type in ['ir', 'hr'] and args.bits == 32: count *= 2
        if not 0 <= args.address <= 65535 or args.address + count > 65536:
            parser.error("Requested address range must fit 0..65535.")
    if args.command == 'write':
        try:
            if args.type == 'co':
                if any(int(v) not in (0, 1) for v in args.values):
                    raise ValueError("Coil values must be 0 or 1")
            else:
                encode_payload(args.values, f'{args.format}{args.bits}', get_endian(args.byteorder), get_endian(args.wordorder))
        except (ValueError, struct.error, OverflowError) as e:
            parser.error(str(e))

    fmt_type = f"{args.format}{args.bits}"
    b_order = get_endian(args.byteorder)
    w_order = get_endian(args.wordorder)

    setup_logger(args.debug)
    
    if args.command == "scan":
        return 0 if do_scan(args) else 1

    client = RawModbusClient(args.host, port=args.port, timeout=3.0, retries=2)

    if not client.connect():
        sys.exit(1)

    print(f"{Color.GREEN}{Color.BOLD}[CONNECTED]{Color.RESET} {Color.CYAN}{args.host}:{args.port}{Color.RESET} | Command: {Color.YELLOW}{args.command.upper()}{Color.RESET}\n")

    try:
        if args.command == "read": result = do_read(client, args, fmt_type, b_order, w_order)
        elif args.command == "watch": result = do_watch(client, args, fmt_type, b_order, w_order)
        elif args.command == "write": result = do_write(client, args, fmt_type, b_order, w_order)
        elif args.command == "fingerprint": result = do_fingerprint(client, args)
        return 0 if result else 1
    finally:
        client.close()

if __name__ == "__main__":
    sys.exit(main())
