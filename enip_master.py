#!/usr/bin/env python3
import sys
import signal
import argparse
import logging
import os
import struct
import socket
import time
import re

# --- 1. Signal Handling & Terminal Setup ---
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

logger = logging.getLogger("ENIPMasterCLI")
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

# --- 2. NATIVE ETHERNET/IP CLIENT ---
class RawENIPClient:
    def __init__(self, host, port=44818, timeout=3.0, retries=2):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.sock = None
        self.session_handle = 0
        
        self.ot_conn_id = 0
        self.to_conn_id = 0
        self.conn_serial = 0x1234
        self.sequence_num = 0
        self.context_num = 0
        self.connected_slot = None
        self.last_outcome = 'NOT_SENT'

    def connect(self, suppress_logs=False):
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
        try:
            if self.ot_conn_id != 0 and self.sock:
                self.forward_close()
            self.unregister_session()
        finally:
            self._drop_transport()

    def _drop_transport(self):
        if self.sock:
            self.sock.close()
        self.sock = None
        self.session_handle = self.ot_conn_id = self.to_conn_id = 0
        self.connected_slot = None

    def _fail(self, message, outcome='FAILED', suppress_logs=False):
        self.last_outcome = outcome
        if not suppress_logs: logger.error(f"[{outcome}] {message}")
        return None

    def _build_enip_header(self, command, length, session=0, status=0, context=None, options=0):
        if context is None:
            self.context_num = (self.context_num + 1) & 0xFFFFFFFFFFFFFFFF
            # SendUnitData uses the connected ID and sequence, not sender context.
            context = 0 if command == 0x70 else self.context_num
        return struct.pack('<HHIIQI', command, length, session, status, context, options)

    def _recv_exact(self, size, deadline):
        data = bytearray()
        while len(data) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise socket.timeout("transaction deadline expired")
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(size - len(data))
            if not chunk: raise ConnectionError("EOF before complete encapsulation packet")
            data.extend(chunk)
        return bytes(data)

    def _send_recv(self, payload, suppress_logs=False):
        self.last_outcome = 'NOT_SENT'
        if not self.sock:
            return self._fail("Socket not connected.", 'NOT_SENT', suppress_logs)
        if len(payload) < 24:
            return self._fail("Missing encapsulation header.", 'NOT_SENT', suppress_logs)
        command, length, session, _, context, _ = struct.unpack('<HHIIQI', payload[:24])
        if length != len(payload) - 24 or length > 65511:
            return self._fail("Invalid request length.", 'NOT_SENT', suppress_logs)
        try:
            deadline = time.monotonic() + self.timeout
            self.last_outcome = 'INDETERMINATE'
            self.sock.settimeout(self.timeout)
            self.sock.sendall(payload)
            fields = struct.unpack('<HHIIQI', self._recv_exact(24, deadline))
            r_cmd, r_len, r_session, r_status, r_ctx, r_opt = fields
            if (r_cmd != command or r_opt != 0 or r_len > 65511 or
                    (command != 0x70 and r_ctx != context) or
                    (command != 0x65 and r_session != session)):
                raise ValueError("Mismatched command/session/context/options or invalid encapsulation length")
            resp_data = self._recv_exact(r_len, deadline)
            if r_status != 0:
                self._fail(f"Encapsulation status 0x{r_status:08X}.", 'REJECTED', suppress_logs)
            else:
                self.last_outcome = 'PROTOCOL_ACCEPTED'
            return (r_cmd, r_session, r_status, resp_data)
        except (ValueError, OSError, ConnectionError) as e:
            self._drop_transport()
            return self._fail(f"{e}; request response is unknown. No retry.", 'INDETERMINATE', suppress_logs)

    def _wrap_unconnected_send(self, cip_msg, slot):
        if not isinstance(slot, int) or not 0 <= slot <= 255:
            raise ValueError("Slot must be 0..255")
        route_path = struct.pack('<BB', 0x01, slot)
        if len(route_path) % 2 != 0: route_path += b'\x00'
        route_path_words = len(route_path) // 2
        
        msg_len = len(cip_msg)
        padded_msg = cip_msg + b'\x00' if msg_len % 2 != 0 else cip_msg
        
        payload = struct.pack('<BBH', 0x0A, 0x0E, msg_len) + padded_msg
        payload += struct.pack('<BB', route_path_words, 0) + route_path
        
        cm_path = struct.pack('<BBBB', 0x20, 0x06, 0x24, 0x01)
        return struct.pack('<BB', 0x52, len(cm_path) // 2) + cm_path + payload

    # --- Data Type Packing/Unpacking ---
    def encode_data(self, value, data_type):
        try:
            if data_type == 'bool':
                number = int(value)
                if number not in (0, 1): raise ValueError('BOOL requires 0 or 1')
                return struct.pack('<?', bool(number))
            elif data_type == 'int8': return struct.pack('<b', int(value))
            elif data_type == 'int16': return struct.pack('<h', int(value))
            elif data_type == 'int32': return struct.pack('<i', int(value))
            elif data_type == 'float32': return struct.pack('<f', float(value))
            elif data_type == 'string': return str(value).encode('ascii')
            else: raise ValueError(f"Unsupported data type: {data_type}")
        except (ValueError, struct.error, OverflowError, UnicodeError) as e:
            logger.error(f"Failed to pack data. Ensure value matches the selected type: {e}")
            return None

    def decode_data(self, data, data_type):
        try:
            if data_type == 'bool': return struct.unpack('<?', data[:1])[0]
            elif data_type == 'int8': return struct.unpack('<b', data[:1])[0]
            elif data_type == 'int16': return struct.unpack('<h', data[:2])[0]
            elif data_type == 'int32': return struct.unpack('<i', data[:4])[0]
            elif data_type == 'float32': return struct.unpack('<f', data[:4])[0]
            elif data_type == 'string': return data.decode('ascii', errors='ignore')
            else: return data.hex()
        except struct.error:
            return data.hex()
            
    # --- System & Topology Discovery ---
    def list_identity(self):
        logger.info("Sending List Identity command (0x63)...")
        header = self._build_enip_header(0x63, 0)
        
        response = self._send_recv(header)
        if not response: return None
        
        r_cmd, r_session, r_status, data = response
        if r_status != 0 or len(data) < 2: return None
        
        item_count = struct.unpack('<H', data[0:2])[0]
        items, offset = [], 2
        for _ in range(item_count):
            if offset + 4 > len(data): return self._fail("Truncated ListIdentity item header.")
            item_type, item_length = struct.unpack_from('<HH', data, offset)
            offset += 4
            if offset + item_length > len(data): return self._fail("Truncated ListIdentity item.")
            if item_type == 0x0C: items.append(data[offset:offset+item_length])
            offset += item_length
        if offset != len(data) or len(items) != 1:
            return self._fail("Expected one complete identity item for this TCP peer.")
        id_data = items[0]
        if len(id_data) < 34 or struct.unpack_from('<H', id_data)[0] != 1:
            return self._fail("Invalid identity version or length.")
        
        vendor_id = struct.unpack('<H', id_data[18:20])[0]
        device_type = struct.unpack('<H', id_data[20:22])[0]
        product_code = struct.unpack('<H', id_data[22:24])[0]
        revision = f"{id_data[24]}.{id_data[25]}"
        status = struct.unpack('<H', id_data[26:28])[0]
        serial_num = struct.unpack('<I', id_data[28:32])[0]
        name_len = id_data[32]
        if len(id_data) != 34 + name_len:
            return self._fail("Truncated identity product name/state.")
        
        name = id_data[33:33+name_len].decode('utf-8', errors='ignore')
        
        return {
            "Vendor ID": vendor_id,
            "Device Type": f"0x{device_type:02X}",
            "Product Code": product_code,
            "Revision": revision,
            "Status": f"0x{status:04X}",
            "Serial Number": f"0x{serial_num:08X}",
            "Product Name": name
        }

    def get_tcp_config(self, use_connected=False, slot=None):
        logger.info("Requesting TCP/IP Interface Configuration (Class 0xF5, Inst 1, Attr 5)...")
        raw_data = self.read_cip_attribute(0xF5, 1, 5, use_connected, slot)
        
        config = {}
        if raw_data and len(raw_data) >= 22:
            config["IP Address"] = socket.inet_ntop(socket.AF_INET, raw_data[0:4][::-1])
            config["Subnet Mask"] = socket.inet_ntop(socket.AF_INET, raw_data[4:8][::-1])
            config["Gateway"] = socket.inet_ntop(socket.AF_INET, raw_data[8:12][::-1])
            config["Primary DNS"] = socket.inet_ntop(socket.AF_INET, raw_data[12:16][::-1])
            config["Secondary DNS"] = socket.inet_ntop(socket.AF_INET, raw_data[16:20][::-1])
            
            domain = ""
            if len(raw_data) >= 22:
                domain_len = struct.unpack('<H', raw_data[20:22])[0]
                if len(raw_data) not in (22 + domain_len, 22 + domain_len + (domain_len % 2)):
                    return self._fail("Invalid TCP/IP domain string length.")
                if domain_len > 0 and len(raw_data) >= 22 + domain_len:
                    domain = raw_data[22:22+domain_len].decode('ascii', errors='ignore')
            config["Domain Name"] = domain
        else:
            return None
            
        logger.info("Requesting Hostname (Class 0xF5, Inst 1, Attr 6)...")
        host_data = self.read_cip_attribute(0xF5, 1, 6, use_connected, slot)
        if host_data is not None and len(host_data) >= 2:
            host_len = struct.unpack('<H', host_data[0:2])[0]
            if len(host_data) not in (2 + host_len, 2 + host_len + (host_len % 2)):
                return self._fail("Invalid hostname string length.")
            config["Hostname"] = ""
            if host_len > 0 and len(host_data) >= 2 + host_len:
                config["Hostname"] = host_data[2:2+host_len].decode('ascii', errors='ignore')
        else:
            config["Hostname"] = "UNAVAILABLE"
            
        return config

    # --- CIP Session & Connection Management ---
    def register_session(self):
        logger.info("Registering session (0x65)...")
        req_data = struct.pack('<HH', 1, 0)
        header = self._build_enip_header(0x65, len(req_data))
        response = self._send_recv(header + req_data)
        if response and response[2] == 0 and response[1] != 0 and response[3] == req_data:
            self.session_handle = response[1]
            logger.info(f"{Color.GREEN}[SUCCESS]{Color.RESET} Session registered. Handle: 0x{self.session_handle:08X}")
            return True
        if response and response[2] == 0:
            self._fail("Invalid RegisterSession handle/version/options response.")
        return False

    def unregister_session(self):
        if self.session_handle != 0 and self.sock:
            logger.info("Unregistering session to free PLC resources (0x66)...")
            header = self._build_enip_header(0x66, 0, session=self.session_handle)
            try: self.sock.sendall(header)
            except Exception: pass
            self.session_handle = 0

    def forward_open(self, slot=None):
        logger.info("Establishing Class 3 Connection (Forward_Open 0x54)...")
        if self.session_handle == 0: return False
        if slot is not None and not 0 <= slot <= 255:
            self._fail("Slot must be 0..255.", 'NOT_SENT')
            return False
        route_path = (bytes([1, slot]) if slot is not None else b'') + bytes.fromhex('2002 2401')
        fw_payload = struct.pack('<BBIIHHIB3sIHIHBB',
            0x0A, 0x0E, 0x11223344, 0x55667788,
            self.conn_serial, 0x00FF, 0x12345678, 3, bytes(3),
            0x0007A120, 0x43F4, 0x0007A120, 0x43F4, 0xA3, len(route_path)//2
        ) + route_path
        result = self._execute_cip_transaction(bytes.fromhex('5402 2006 2401') + fw_payload, False, None)
        if result is None: return False
        if len(result) < 26:
            self._fail("Truncated Forward_Open response.", 'INDETERMINATE')
            return False
        ot, to, serial, vendor, origin = struct.unpack_from('<IIHHI', result)
        if ((serial, vendor, origin) != (self.conn_serial, 0x00FF, 0x12345678) or
                not ot or not to or result[25] != 0 or len(result) != 26 + 2 * result[24]):
            self._fail("Mismatched or malformed Forward_Open identity/reply.", 'INDETERMINATE')
            return False
        self.ot_conn_id, self.to_conn_id = ot, to
        self.connected_slot = slot
        self.sequence_num = 0
        logger.info(f"[PROTOCOL_ACCEPTED] Class 3 connection established. O->T ID: 0x{ot:08X}")
        return True

    def forward_close(self, slot=None):
        logger.info("Closing Class 3 Connection (Forward_Close 0x4E)...")
        if not self.session_handle or not self.ot_conn_id: return False
        if slot is None: slot = self.connected_slot
        route_path = (bytes([1, slot]) if slot is not None else b'') + bytes.fromhex('2002 2401')
        payload = struct.pack('<BBHHIBB', 0x0A, 0x0E, self.conn_serial, 0x00FF,
                              0x12345678, len(route_path)//2, 0) + route_path
        result = self._execute_cip_transaction(bytes.fromhex('4e02 2006 2401') + payload, False, None)
        if result is None: return False
        if (len(result) < 10 or struct.unpack_from('<HHI', result) != (self.conn_serial, 0x00FF, 0x12345678)
                or result[9] != 0 or len(result) != 10 + result[8] * 2):
            self._fail("Mismatched or malformed Forward_Close response.", 'INDETERMINATE')
            return False
        self.ot_conn_id = self.to_conn_id = 0
        self.connected_slot = None
        return True

    def _parse_cpf(self, data, use_connected, sequence):
        if len(data) < 8 or struct.unpack_from('<I', data)[0] != 0:
            raise ValueError("Invalid/truncated CPF interface header")
        count = struct.unpack_from('<H', data, 6)[0]
        if count != 2: raise ValueError("Expected two CPF items")
        items, offset = [], 8
        for _ in range(count):
            if offset + 4 > len(data): raise ValueError("Truncated CPF item header")
            kind, length = struct.unpack_from('<HH', data, offset)
            offset += 4
            if offset + length > len(data): raise ValueError("Truncated CPF item data")
            items.append((kind, data[offset:offset+length]))
            offset += length
        if offset != len(data): raise ValueError("Unexpected trailing CPF data")
        address_type, address = items[0]
        data_type, cip = items[1]
        if use_connected:
            if (address_type != 0xA1 or len(address) != 4 or
                    struct.unpack('<I', address)[0] != self.to_conn_id or data_type != 0xB1 or len(cip) < 2 or
                    struct.unpack_from('<H', cip)[0] != sequence):
                raise ValueError("Mismatched connected address, data type or sequence")
            cip = cip[2:]
        elif address_type != 0 or address or data_type != 0xB2:
            raise ValueError("Invalid unconnected CPF address/data items")
        return cip

    def _parse_cip_response(self, cip, service):
        if len(cip) < 4 or cip[0] != (service | 0x80) or cip[1] != 0:
            raise ValueError("Mismatched/truncated CIP response service/header")
        offset = 4 + 2 * cip[3]
        if offset > len(cip): raise ValueError("Truncated CIP additional status")
        if cip[2] != 0:
            extra = cip[4:offset].hex(' ')
            return self._fail(f"CIP service 0x{service:02X} status 0x{cip[2]:02X}; additional status: {extra or 'none'}.", 'REJECTED')
        return cip[offset:]

    def _execute_cip_transaction(self, cip_msg, use_connected, slot):
        self.last_outcome = 'NOT_SENT'
        if not self.session_handle:
            return self._fail("No active session.", 'NOT_SENT')
        service = cip_msg[0]
        sequence = None
        try:
            if use_connected:
                if not self.ot_conn_id or not self.to_conn_id:
                    return self._fail("No active Class 3 connection.", 'NOT_SENT')
                self.sequence_num = (self.sequence_num + 1) & 0xFFFF
                sequence = self.sequence_num
                data = (struct.pack('<IHHHHIHHH', 0, 0, 2, 0xA1, 4, self.ot_conn_id,
                                    0xB1, len(cip_msg)+2, sequence) + cip_msg)
                command = 0x70
            else:
                if slot is not None: cip_msg = self._wrap_unconnected_send(cip_msg, slot)
                data = struct.pack('<IHHHHHH', 0, 0, 2, 0, 0, 0xB2, len(cip_msg)) + cip_msg
                command = 0x6F
            response = self._send_recv(self._build_enip_header(command, len(data), session=self.session_handle) + data)
            if not response or response[2] != 0: return None
            cip = self._parse_cpf(response[3], use_connected, sequence)
            # A routed reply commonly carries the embedded service directly. Some
            # bridges return a successful Unconnected_Send wrapper first.
            if not use_connected and slot is not None and cip[:1] == b'\xd2':
                cip = self._parse_cip_response(cip, 0x52)
                if cip is None: return None
            result = self._parse_cip_response(cip, service)
            if result is not None: self.last_outcome = 'PROTOCOL_ACCEPTED'
            return result
        except (ValueError, struct.error, OverflowError) as e:
            outcome = 'INDETERMINATE' if self.last_outcome != 'NOT_SENT' else 'NOT_SENT'
            return self._fail(str(e), outcome)

    @staticmethod
    def _attribute_path(class_id, instance_id, attr_id):
        values = (class_id, instance_id, attr_id)
        if any(not isinstance(v, int) or not 0 <= v <= 255 for v in values):
            raise ValueError("This CLI uses 8-bit class/instance/attribute IDs (0..255)")
        return bytes([0x20, class_id, 0x24, instance_id, 0x30, attr_id])

    # --- Standard CIP Services ---
    def read_cip_attribute(self, class_id, instance_id, attr_id, use_connected=False, slot=None):
        try:
            path = self._attribute_path(class_id, instance_id, attr_id)
        except ValueError as e:
            return self._fail(str(e), 'NOT_SENT')
        return self._execute_cip_transaction(bytes([0x0E, len(path)//2]) + path, use_connected, slot)

    def write_cip_attribute(self, class_id, instance_id, attr_id, data_bytes, use_connected=False, slot=None):
        try:
            path = self._attribute_path(class_id, instance_id, attr_id)
        except ValueError as e:
            self._fail(str(e), 'NOT_SENT')
            return False
        result = self._execute_cip_transaction(bytes([0x10, len(path)//2]) + path + data_bytes, use_connected, slot)
        if result is None: return False
        if result:
            self._fail("Unexpected Set_Attribute_Single response data.", 'INDETERMINATE')
            return False
        return True

    @staticmethod
    def _tag_path(tag_name):
        path = bytearray()
        for part in tag_name.split('.'):
            match = re.fullmatch(r'([A-Za-z_:][A-Za-z0-9_:]*)(\[\d+(?:,\d+)*\])*', part)
            if not match: raise ValueError("Invalid symbolic tag/member/index syntax")
            name = match[1].encode('ascii')
            if len(name) > 255: raise ValueError("Symbol segment exceeds 255 bytes")
            path.extend(bytes([0x91, len(name)]) + name)
            if len(name) % 2: path.append(0)
            for index_text in re.findall(r'\d+', part[len(match[1]):]):
                index = int(index_text)
                if index <= 255: path.extend(struct.pack('<BB', 0x28, index))
                elif index <= 65535: path.extend(struct.pack('<BBH', 0x29, 0, index))
                elif index <= 0xFFFFFFFF: path.extend(struct.pack('<BBI', 0x2A, 0, index))
                else: raise ValueError("Tag array index exceeds 32 bits")
        if not path or len(path) > 510: raise ValueError("Symbolic path exceeds 255 words")
        return bytes(path)

    # --- Symbolic Logix Services ---
    def read_tag(self, tag_name, elements=1, use_connected=False, slot=None):
        try:
            if not 1 <= elements <= 65535: raise ValueError("Elements must be 1..65535")
            path = self._tag_path(tag_name)
        except ValueError as e:
            return self._fail(str(e), 'NOT_SENT')
        result = self._execute_cip_transaction(bytes([0x4C, len(path)//2]) + path + struct.pack('<H', elements), use_connected, slot)
        if result is None: return None
        if len(result) < 2: return self._fail("Truncated Read Tag type.")
        type_code = struct.unpack_from('<H', result)[0]
        raw = result[2:]
        size = {0xC1: 1, 0xC2: 1, 0xC3: 2, 0xC4: 4, 0xCA: 4}.get(type_code)
        if size is not None and len(raw) != elements * size:
            return self._fail("Read Tag value length does not match type and element count.")
        return type_code, raw

    def write_tag(self, tag_name, data_type_code, data_bytes, elements=1, use_connected=False, slot=None):
        try:
            size = {0xC1: 1, 0xC2: 1, 0xC3: 2, 0xC4: 4, 0xCA: 4}.get(data_type_code)
            if size is None: raise ValueError("Supported tag writes: BOOL/SINT/INT/DINT/REAL; STRING requires its structure type handle")
            if not 1 <= elements <= 65535 or len(data_bytes) != elements * size:
                raise ValueError("Write Tag data length must match type and element count")
            path = self._tag_path(tag_name)
            message = bytes([0x4D, len(path)//2]) + path + struct.pack('<HH', data_type_code, elements) + data_bytes
        except (ValueError, struct.error) as e:
            self._fail(str(e), 'NOT_SENT')
            return False
        result = self._execute_cip_transaction(message, use_connected, slot)
        if result is None: return False
        if result:
            self._fail("Unexpected Write Tag response data.", 'INDETERMINATE')
            return False
        return True

# --- 3. Command Execution ---
def process_connection(client, args):
    if not client.register_session(): return False
    if args.connected:
        if not client.forward_open(args.slot): return False
    return True

def do_read_attribute(client, args):
    if not process_connection(client, args): return False
    logger.info(f"Requesting CIP attribute [Class: 0x{args.class_id:02X}, Inst: 0x{args.instance_id:02X}, Attr: 0x{args.attribute_id:02X}]...")
    
    raw_data = client.read_cip_attribute(args.class_id, args.instance_id, args.attribute_id, args.connected, args.slot)
    if raw_data is not None:
        print(f"\n{Color.CYAN}{Color.BOLD}--- CIP READ RESPONSE ---{Color.RESET}")
        hex_data = " ".join([f"{b:02X}" for b in raw_data])
        print(f" {Color.BOLD}Hex Payload:{Color.RESET} {Color.GREEN}{hex_data}{Color.RESET}")
        
        decoded_val = client.decode_data(raw_data, args.type)
        print(f" {Color.BOLD}Decoded ({args.type}):{Color.RESET} {Color.YELLOW}{decoded_val}{Color.RESET}\n")
        return True
    else:
        logger.error("Failed to read CIP attribute.")
        return False

def do_write_attribute(client, args):
    if not process_connection(client, args): return False
    logger.info(f"Writing CIP attribute [Class: 0x{args.class_id:02X}, Inst: 0x{args.instance_id:02X}, Attr: 0x{args.attribute_id:02X}]...")
    
    data_bytes = client.encode_data(args.value, args.type)
    if data_bytes is None: return False

    if client.write_cip_attribute(args.class_id, args.instance_id, args.attribute_id, data_bytes, args.connected, args.slot):
        print(f"\n{Color.GREEN}{Color.BOLD}[PROTOCOL_ACCEPTED]{Color.RESET} CIP Set_Attribute_Single accepted.\n")
        return True
    return False

def do_read_tag(client, args):
    if not process_connection(client, args): return False
    logger.info(f"Requesting Tag [{args.tag}] (Elements: {args.elements})...")

    result = client.read_tag(args.tag, args.elements, args.connected, args.slot)
    if result is not None:
        data_type, raw_data = result
        print(f"\n{Color.CYAN}{Color.BOLD}--- READ TAG RESPONSE ---{Color.RESET}")
        print(f" {Color.BOLD}Data Type Code:{Color.RESET} {Color.BLUE}0x{data_type:04X}{Color.RESET}")
        
        hex_data = " ".join([f"{b:02X}" for b in raw_data])
        print(f" {Color.BOLD}Hex Payload:{Color.RESET} {Color.GREEN}{hex_data}{Color.RESET}")
        
        types = {0xC1: ('bool', 1), 0xC2: ('int8', 1), 0xC3: ('int16', 2), 0xC4: ('int32', 4), 0xCA: ('float32', 4)}
        if data_type not in types:
            logger.warning(f"Unsupported tag type 0x{data_type:04X}; raw payload shown without typed decoding.")
            return True
        actual_type, width = types[data_type]
        if args.type != actual_type:
            logger.warning(f"Requested display type {args.type} differs from returned {actual_type}; decoding returned type.")
        values = [client.decode_data(raw_data[i:i+width], actual_type) for i in range(0, len(raw_data), width)]
        decoded_val = values[0] if len(values) == 1 else values
        print(f" {Color.BOLD}Decoded ({actual_type}):{Color.RESET} {Color.YELLOW}{decoded_val}{Color.RESET}\n")
        return True
    else:
        logger.error("Failed to read tag.")
        return False

def do_write_tag(client, args):
    if not process_connection(client, args): return False
    logger.info(f"Writing Tag [{args.tag}] with value '{args.value}' (Type: {args.type})...")
    
    # Standard CIP Type Mapping for Logix
    CIP_TYPES = {'bool': 0x00C1, 'int8': 0x00C2, 'int16': 0x00C3, 'int32': 0x00C4, 'float32': 0x00CA, 'string': 0x00D0}
    data_type_code = CIP_TYPES[args.type]
    
    data_bytes = client.encode_data(args.value, args.type)
    if data_bytes is None: return False

    if client.write_tag(args.tag, data_type_code, data_bytes, args.elements, args.connected, args.slot):
        print(f"\n{Color.GREEN}{Color.BOLD}[PROTOCOL_ACCEPTED]{Color.RESET} CIP Write Tag accepted.\n")
        return True
    return False

def do_tcp_info(client, args):
    if not process_connection(client, args): return False
    info = client.get_tcp_config(args.connected, args.slot)
    if info:
        print(f"\n{Color.CYAN}{Color.BOLD}--- TCP/IP INTERFACE CONFIGURATION ---{Color.RESET}")
        for key, val in info.items():
            print(f"  {Color.BLUE}{key}:{Color.RESET} {val}")
        print()
        return True
    else:
        logger.error("Failed to retrieve TCP/IP configuration.")
        return False

# --- Main Entry Point ---
def main():
    desc_text = f"{Color.BOLD}EtherNet/IP Master CLI (by z4y_d3n){Color.RESET}\n"
    custom_usage = (
        f"{Color.GREEN}enip_master.py{Color.RESET} "
        f"{Color.YELLOW}[-H HOST] [-c COMMAND] [-p PORT] [-C CLASS] [-I INSTANCE] [-A ATTRIBUTE] "
        f"[-v VALUE] [-t TYPE] [-T TAG] [-E ELEMENTS] [-S SLOT] [-O]{Color.RESET}"
    )
    
    parser = CustomArgumentParser(description=desc_text, usage=custom_usage, formatter_class=ColoredHelpFormatter)
    
    parser.add_argument("-H", "--host", required=True, type=str, help="Target IP of the PLC/Device.")
    parser.add_argument("-c", "--command", required=True, choices=["list-identity", "read", "write", "read-tag", "write-tag", "tcp-info"], help="Protocol action to execute.")
    parser.add_argument("-p", "--port", type=int, default=44818, help="TCP Encapsulation Port (Default: 44818).")
    parser.add_argument("--debug", action="store_true", help="Enable DEBUG trace logs.")
    
    cip_group = parser.add_argument_group(f"{Color.CYAN}CIP Addressing Options{Color.RESET}")
    cip_group.add_argument("-C", "--class-id", type=lambda x: int(x, 0), help="CIP Class ID (Required for read/write).")
    cip_group.add_argument("-I", "--instance-id", type=lambda x: int(x, 0), help="CIP Instance ID.")
    cip_group.add_argument("-A", "--attribute-id", type=lambda x: int(x, 0), help="CIP Attribute ID.")
    
    tag_group = parser.add_argument_group(f"{Color.CYAN}Symbolic Tag Options (Logix 0x4C/0x4D){Color.RESET}")
    tag_group.add_argument("-T", "--tag", type=str, help="Tag name to read/write.")
    tag_group.add_argument("-E", "--elements", type=int, default=1, help="Number of elements to read (Default: 1); CLI tag writes require 1.")

    data_group = parser.add_argument_group(f"{Color.CYAN}Data Formatting Options{Color.RESET}")
    data_group.add_argument("-v", "--value", type=str, help="Value to write. Used with 'write' and 'write-tag'.")
    data_group.add_argument("-t", "--type", choices=["bool", "int8", "int16", "int32", "float32", "string"], default="int16", help="Attribute display/packing type; string is raw ASCII. Tag writes support atomic numeric/BOOL types.")
    
    topo_group = parser.add_argument_group(f"{Color.CYAN}Advanced Industrial Network Options{Color.RESET}")
    topo_group.add_argument("-S", "--slot", type=int, default=None, help="CPU Slot number. Injects 'Unconnected Send' (0x52) layer for Backplane Routing.")
    topo_group.add_argument("-O", "--connected", action="store_true", help="Enforces Connected Messaging via 'Forward_Open' (0x54).")

    if len(sys.argv) == 1:
        parser.print_usage()
        sys.exit(1)
        
    parser.usage = argparse.SUPPRESS
    args = parser.parse_args()

    # --- Logical Validations ---
    if args.command in ["read", "write"]:
        if args.class_id is None or args.instance_id is None or args.attribute_id is None:
            parser.error("Arguments -C (Class), -I (Instance), and -A (Attribute) are strictly required for 'read' and 'write'.")
            
    if args.command in ["write", "write-tag"]:
        if args.value is None:
            parser.error(f"Argument -v (Value) is required when executing '{args.command}'.")
            
    if args.command in ["read-tag", "write-tag"]:
        if args.tag is None:
            parser.error(f"Argument -T (Tag) is strictly required for '{args.command}'.")
    if not 1 <= args.port <= 65535:
        parser.error("TCP port must be 1..65535.")
    if args.slot is not None and not 0 <= args.slot <= 255:
        parser.error("Slot must be 0..255.")
    if not 1 <= args.elements <= 65535:
        parser.error("Elements must be 1..65535.")
    if args.command in ['read', 'write']:
        try:
            RawENIPClient._attribute_path(args.class_id, args.instance_id, args.attribute_id)
        except ValueError as e:
            parser.error(str(e))
    if args.command in ['read-tag', 'write-tag']:
        try:
            RawENIPClient._tag_path(args.tag)
        except ValueError as e:
            parser.error(str(e))
    if args.command == 'write-tag' and (args.elements != 1 or args.type == 'string'):
        parser.error("CLI tag writes accept one atomic value; STRING requires a structure type handle and is unsupported.")
    if args.command in ['write', 'write-tag']:
        if RawENIPClient(args.host).encode_data(args.value, args.type) is None:
            parser.error("Value does not fit the selected data type.")

    setup_logger(args.debug)
    client = RawENIPClient(args.host, port=args.port, timeout=3.0, retries=2)

    if not client.connect():
        sys.exit(1)

    print(f"{Color.GREEN}{Color.BOLD}[CONNECTED]{Color.RESET} {Color.CYAN}{args.host}:{args.port}{Color.RESET} | Command: {Color.YELLOW}{args.command.upper()}{Color.RESET}\n")

    try:
        if args.command == "list-identity":
            info = client.list_identity()
            if info:
                print(f"\n{Color.CYAN}{Color.BOLD}--- ETHERNET/IP FINGERPRINT ---{Color.RESET}")
                for key, val in info.items():
                    print(f"  {Color.BLUE}{key}:{Color.RESET} {val}")
                print()
            result = bool(info)
        elif args.command == "tcp-info":
            result = do_tcp_info(client, args)
        elif args.command == "read":
            result = do_read_attribute(client, args)
        elif args.command == "write":
            result = do_write_attribute(client, args)
        elif args.command == "read-tag":
            result = do_read_tag(client, args)
        elif args.command == "write-tag":
            result = do_write_tag(client, args)
        return 0 if result else 1
    finally:
        client.close()

if __name__ == "__main__":
    sys.exit(main())
