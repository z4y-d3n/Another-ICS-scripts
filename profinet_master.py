#!/usr/bin/env python3
import sys
import signal
import argparse
import logging
import os
import struct
import socket
import uuid
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

logger = logging.getLogger("PROFINETMasterCLI")

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
        log_file = os.path.join(audit_dir, f"profinet_master_LAB_{datetime.now().strftime('%Y%m%d')}.log")

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


# --- 2. PROFINET CONSTANTS, VENDOR IDS & BLOCK HELPERS ---
PROFINET_VENDORS = {
    0x002A: "Siemens AG",
    0x00B0: "Phoenix Contact GmbH",
    0x011E: "WAGO Kontakttechnik GmbH",
    0x012D: "Turck GmbH & Co. KG",
    0x001A: "ABB Automation",
    0x014D: "Festo SE & Co. KG",
    0x007E: "Balluff GmbH",
    0x0107: "SEW-EURODRIVE GmbH",
    0x0049: "Pilz GmbH & Co. KG",
    0x010C: "ifm electronic gmbh",
    0x0054: "Endress+Hauser",
    0x0121: "Pepperl+Fuchs SE",
    0x0083: "Beckhoff Automation",
    0x0133: "Rockwell Automation",
    0x00A6: "Schneider Electric",
    0x015B: "HMS Industrial Networks (Anybus)",
    0x011D: "Murrelektronik GmbH",
    0x002E: "Danfoss Drives",
    0x010E: "Sick AG",
    0x003B: "Weidmüller Interface",
}

CHANNEL_ERROR_TYPES = {
    0x0001: "Short circuit",
    0x0002: "Undervoltage",
    0x0003: "Overvoltage",
    0x0004: "Overload",
    0x0005: "Overtemperature",
    0x0006: "Line break / Wire break",
    0x0007: "Upper limit value exceeded",
    0x0008: "Lower limit value exceeded",
    0x0009: "Error",
    0x0010: "Parameterization fault",
    0x0011: "Power supply fault",
    0x0012: "Fuse blown / open",
    0x0013: "Communication fault",
    0x0014: "Ground fault",
    0x0015: "Reference point lost",
    0x0016: "Process event lost / sampling error",
    0x0017: "Threshold warning",
    0x0018: "Output disabled / shut off",
    0x0019: "Safety-related fault",
    0x001A: "External fault",
    0x0100: "PNIO Submodule mismatch / wrong module",
    0x8000: "Data transmission impossible (Link down)",
    0x8001: "Remote mismatch (LLDP peer error)",
    0x8002: "Media redundancy mismatch",
    0x8003: "Sync mismatch",
}

PNIO_ERROR_CODE1 = {
    0xB0: "Invalid Index (Record Index not supported by Subslot)",
    0xB1: "Write Length Error",
    0xB2: "Invalid Slot / Subslot (Module not plugged)",
    0xB3: "Type Conflict",
    0xB4: "Invalid Area / API",
    0xB5: "State Conflict (Not in valid state)",
    0xB6: "Access Denied (Read-only or protected record)",
    0xB7: "Invalid Range",
    0xB8: "Invalid Parameter",
    0xB9: "Invalid Type",
    0xBA: "Backup / Restore conflict",
    0xC0: "Resource Busy / Read constraint",
}

def mac_to_bytes(mac_str):
    clean = mac_str.replace(":", "").replace("-", "").replace(".", "").strip()
    if len(clean) != 12:
        raise ValueError(f"Invalid MAC address format: '{mac_str}'")
    return bytes.fromhex(clean)

def bytes_to_mac(b):
    return ":".join(f"{x:02X}" for x in b[:6])

def decode_device_role(role_byte):
    roles = []
    if role_byte & 0x01: roles.append("IO-Device")
    if role_byte & 0x02: roles.append("IO-Controller")
    if role_byte & 0x04: roles.append("IO-Multidevice")
    if role_byte & 0x08: roles.append("PN-Supervisor")
    return " | ".join(roles) if roles else f"0x{role_byte:02X}"


# --- 3. LAYER 3 CLIENT: PROFINET IO DCE/RPC (UDP PORT 34964) ---
class RawPNIORPCClient:
    """Implements Connectionless DCE/RPC (UDP 34964) for PROFINET IO ReadImplicit & Record Access."""
    UUID_NULL        = uuid.UUID("00000000-0000-0000-0000-000000000000")
    UUID_PNIO_OBJECT = uuid.UUID("dea00000-6c97-11d1-8271-00a02442df7d")
    UUID_PNIO_DEVICE = uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d")

    OPNUM_CONNECT       = 0
    OPNUM_RELEASE       = 1
    OPNUM_READ          = 2
    OPNUM_WRITE         = 3
    OPNUM_CONTROL       = 4
    OPNUM_READ_IMPLICIT = 5

    def __init__(self, host, port=34964, timeout=3.0, retries=2):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.sock = None
        self.activity_uuid = uuid.uuid4()
        self.seq_num = 0
        self.pnio_seq = 1
        self.last_outcome = 'NOT_SENT'

    def connect(self):
        if self.sock is not None:
            return True
        candidate = None
        try:
            candidate = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            candidate.settimeout(self.timeout)
            self.sock = candidate
            return True
        except OSError as e:
            logger.error(f"[SOCKET ERROR] Failed to create UDP socket: {e}")
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

    def _build_dcerpc_request(self, opnum, stub_data):
        """Builds an 80-byte Connectionless DCE/RPC v4 Request Header (Big-Endian DREP=0x00)."""
        rpc_vers = 4
        ptype = 0x00      # Request
        flags1 = 0x20     # Idempotent
        flags2 = 0x00
        drep = b'\x00\x00\x00'  # Big-Endian, ASCII, IEEE Float
        serial_hi = 0x00

        obj_bytes = self.UUID_PNIO_OBJECT.bytes
        if_bytes = self.UUID_PNIO_DEVICE.bytes
        act_bytes = self.activity_uuid.bytes

        server_boot = 0
        if_vers = 1
        seq = self.seq_num
        self.seq_num = (self.seq_num + 1) & 0xffffffff

        ihint = 0xFFFF
        ahint = 0xFFFF
        body_len = len(stub_data)
        fragnum = 0
        auth_proto = 0
        serial_lo = 0

        header = struct.pack(
            '>BBBB3sB16s16s16sIIIHHHHHBB',
            rpc_vers, ptype, flags1, flags2, drep, serial_hi,
            obj_bytes, if_bytes, act_bytes,
            server_boot, if_vers, seq,
            opnum, ihint, ahint, body_len, fragnum,
            auth_proto, serial_lo
        )
        return header + stub_data

    def _build_fack(self, rx_hdr, fragnum, drep_little):
        """Builds a DCE/RPC Fragment ACK (ptype=0x09) when receiving multi-fragment records."""
        endian = '<' if drep_little else '>'
        drep = b'\x10\x00\x00' if drep_little else b'\x00\x00\x00'
        seq = struct.unpack(f'{endian}I', rx_hdr[64:68])[0]
        opnum = struct.unpack(f'{endian}H', rx_hdr[68:70])[0]

        hdr = struct.pack(
            f'{endian}BBBB3sB16s16s16sIIIHHHHHBB',
            4, 0x09, 0x00, 0x00, drep, 0,
            rx_hdr[8:24], rx_hdr[24:40], rx_hdr[40:56],
            0, 1, seq, opnum, 0xFFFF, 0xFFFF, 0, fragnum, 0, 0
        )
        return hdr

    def _send_recv_rpc(self, opnum, stub_data, suppress_logs=False):
        if not self.sock:
            return None

        req_pkt = self._build_dcerpc_request(opnum, stub_data)

        peer = socket.gethostbyname(self.host)
        self.last_outcome = 'INDETERMINATE'
        for attempt in range(self.retries + 1):
            try:
                logger.debug(f"TX DCE/RPC ({self.host}:{self.port}): {req_pkt.hex().upper()}")
                self.sock.sendto(req_pkt, (self.host, self.port))

                fragments = {}
                last_fragment = None
                fragment_endian = None
                deadline = time.monotonic() + self.timeout

                while time.monotonic() < deadline:
                    self.sock.settimeout(max(.001, deadline - time.monotonic()))
                    raw_pkt, addr = self.sock.recvfrom(65535)
                    if addr != (peer, self.port): continue
                    logger.debug(f"RX DCE/RPC ({addr[0]}:{addr[1]}): {raw_pkt.hex().upper()}")
                    if len(raw_pkt) < 80 or raw_pkt[0] != 4:
                        continue

                    ptype = raw_pkt[1]
                    flags1 = raw_pkt[2]
                    drep_little = bool(raw_pkt[4] & 0x10)
                    endian = '<' if drep_little else '>'
                    if raw_pkt[4:7] not in (b'\x00\x00\x00', b'\x10\x00\x00') or raw_pkt[78] != 0: continue
                    rx_activity = uuid.UUID(bytes_le=raw_pkt[40:56]) if drep_little else uuid.UUID(bytes=raw_pkt[40:56])
                    if rx_activity != self.activity_uuid: continue
                    if struct.unpack(f'{endian}I', raw_pkt[64:68])[0] != struct.unpack('>I', req_pkt[64:68])[0]: continue
                    if struct.unpack(f'{endian}H', raw_pkt[68:70])[0] != opnum: continue

                    frag_len, frag_num = struct.unpack(f'{endian}HH', raw_pkt[74:78])
                    if len(raw_pkt) != 80 + frag_len: continue
                    stub_chunk = raw_pkt[80 : 80 + frag_len]

                    # Fault (0x03) or Reject (0x06)
                    if ptype in (0x03, 0x06):
                        self.last_outcome = 'REJECTED'
                        status_code = struct.unpack(f'{endian}I', stub_chunk[:4])[0] if len(stub_chunk) >= 4 else 0
                        if not suppress_logs:
                            logger.error(f"[DCE/RPC FAULT] Server returned PDU Type {ptype} (Status: 0x{status_code:08X})")
                        return None

                    if ptype != 0x02:  # Must be Response (0x02)
                        continue

                    is_frag = bool(flags1 & 0x04)
                    is_last_frag = bool(flags1 & 0x02)
                    no_fack = bool(flags1 & 0x08)

                    if not is_frag:
                        if frag_num or fragments: return None
                        self.last_outcome = 'PROTOCOL_ACCEPTED'
                        return (stub_chunk, endian)

                    if fragment_endian is not None and endian != fragment_endian: return None
                    fragment_endian = endian
                    if frag_num in fragments and fragments[frag_num] != stub_chunk: return None
                    fragments[frag_num] = stub_chunk
                    if len(fragments) > 4096 or sum(map(len, fragments.values())) > 1048576: return None
                    if is_last_frag:
                        if last_fragment is not None and last_fragment != frag_num: return None
                        last_fragment = frag_num
                    if not no_fack and not is_last_frag:
                        fack_pkt = self._build_fack(raw_pkt[:80], frag_num, drep_little)
                        self.sock.sendto(fack_pkt, (self.host, self.port))

                    if last_fragment is not None and set(fragments) == set(range(last_fragment + 1)):
                        self.last_outcome = 'PROTOCOL_ACCEPTED'
                        combined = b''.join(fragments[k] for k in sorted(fragments.keys()))
                        return (combined, endian)

            except socket.timeout:
                if attempt == self.retries and not suppress_logs:
                    logger.error(f"[TIMEOUT] No DCE/RPC response from {self.host}:{self.port} (UDP 34964).")
            except Exception as e:
                if not suppress_logs:
                    logger.error(f"[NETWORK ERROR] DCE/RPC transaction failed: {e}")
                return None

        return None

    def read_implicit_record(self, api, slot, subslot, index, max_len=4096, suppress_logs=False):
        """
        Executes PNIO ReadImplicit (Opnum 5) to read a PROFINET Record over UDP 34964
        without establishing an Application Relationship (AR).
        """
        self.last_outcome = 'FAILED'
        if not (0 <= api <= 0xffffffff and all(0 <= x <= 65535 for x in (slot, subslot, index)) and 0 < max_len <= 1048512):
            raise ValueError('PNIO address or record length out of range')
        # Build 64-byte IODReadReqHeader (BlockType = 0x0009, BlockLength = 60 / 0x003C)
        iod_read_req = struct.pack(
            '>HHBBH16sIHHHH I 16s8s',
            0x0009,                 # BlockType: IODReadReqHeader
            60,                     # BlockLength: 60 bytes
            1, 0,                   # BlockVersion 1.0
            self.pnio_seq,          # SeqNumber
            self.UUID_NULL.bytes,   # ARUUID (Null for ReadImplicit)
            api,                    # API (0 = standard)
            slot,                   # SlotNumber
            subslot,                # SubslotNumber
            0,                      # Padding
            index,                  # Record Data Object Index
            max_len,                # RecordDataLength to read
            self.UUID_NULL.bytes,   # TargetARUUID (Null)
            b'\x00' * 8             # Padding (8 bytes)
        )
        request_seq = self.pnio_seq
        self.pnio_seq = (self.pnio_seq + 1) & 65535

        # NDR Prefix (20 bytes): ArgsMaximum, ArgsLength, MaximumCount, Offset, ActualCount
        ndr_prefix = struct.pack('>IIIII', max_len, len(iod_read_req), max_len, 0, len(iod_read_req))
        res = self._send_recv_rpc(self.OPNUM_READ_IMPLICIT, ndr_prefix + iod_read_req, suppress_logs=suppress_logs)
        if not res:
            return None

        stub_resp, endian = res
        self.last_outcome = 'FAILED'
        if len(stub_resp) < 20:
            return None

        # First 4 bytes of PNIO Response Stub contain the PNIOStatus (ErrorCode, ErrorDecode, ErrorCode1, ErrorCode2)
        err_code, err_decode, err_code1, err_code2 = struct.unpack('>BBBB', stub_resp[:4])
        if any(stub_resp[:4]):
            self.last_outcome = 'REJECTED'
            if not suppress_logs:
                desc = PNIO_ERROR_CODE1.get(err_code1, f"ErrorCode1=0x{err_code1:02X}")
                logger.warning(
                    f"[PNIO STATUS] Slot {slot}/{subslot} Index 0x{index:04X} rejected: "
                    f"{desc} (0x{err_code:02X}{err_decode:02X}{err_code1:02X}{err_code2:02X})"
                )
            return None

        # NDR response: PNIOStatus + ArgsLength + conformant/varying array.
        args_length, maximum, offset, actual = struct.unpack(f'{endian}IIII', stub_resp[4:20])
        if offset != 0 or actual > maximum or actual != args_length or actual < 64 or actual > max_len + 64:
            self.last_outcome = 'FAILED'
            return None
        if len(stub_resp) < 20 + actual: return None
        block = stub_resp[20:20 + actual]
        btype, blen, vhi, vlo = struct.unpack('>HHBB', block[:6])
        if (btype, blen, vhi, vlo) != (0x8009, 60, 1, 0): return None
        if struct.unpack('>H', block[6:8])[0] != request_seq or block[8:24] != self.UUID_NULL.bytes: return None
        if struct.unpack('>IHH', block[24:32]) != (api, slot, subslot): return None
        if struct.unpack('>H', block[34:36])[0] != index: return None
        rec_len = struct.unpack('>I', block[36:40])[0]
        if rec_len > max_len or 64 + rec_len != actual: return None
        self.last_outcome = 'PROTOCOL_ACCEPTED'
        return block[64:]


# --- 4. PROFINET RECORD PARSERS (I&M, TOPOLOGY, DIAGNOSIS) ---
def parse_im0(data):
    """Decodes PROFINET I&M0 (0xAFF0) Identification & Maintenance Record (60 bytes)."""
    if not data or len(data) < 60:
        return None
    btype, blen, vhi, vlo = struct.unpack('>HHBB', data[:6])
    if (btype, blen, vhi, vlo) != (0x0020, 56, 1, 0) or len(data) != 60:
        return None

    vendor_id = struct.unpack('>H', data[6:8])[0]
    order_id = data[8:28].decode('ascii', errors='replace').strip()
    serial_num = data[28:44].decode('ascii', errors='replace').strip()
    hw_rev = struct.unpack('>H', data[44:46])[0]
    sw_prefix = chr(data[46]) if 32 <= data[46] <= 126 else 'V'
    sw_x, sw_y, sw_z = data[47], data[48], data[49]
    rev_cnt = struct.unpack('>H', data[50:52])[0]
    prof_id = struct.unpack('>H', data[52:54])[0]
    prof_type = struct.unpack('>H', data[54:56])[0]
    im_ver_maj, im_ver_min = data[56], data[57]
    im_supp = struct.unpack('>H', data[58:60])[0]

    supp_list = ["I&M0"]
    if im_supp & 0x0002: supp_list.append("I&M1")
    if im_supp & 0x0004: supp_list.append("I&M2")
    if im_supp & 0x0008: supp_list.append("I&M3")
    if im_supp & 0x0010: supp_list.append("I&M4")

    vendor_name = PROFINET_VENDORS.get(vendor_id, "Unknown Vendor")
    return {
        "Vendor": f"{vendor_name} (0x{vendor_id:04X})",
        "Order ID (MLFB)": order_id,
        "Serial Number": serial_num,
        "Hardware Revision": f"{hw_rev}",
        "Firmware / SW Revision": f"{sw_prefix}{sw_x}.{sw_y}.{sw_z}",
        "Revision Counter": f"{rev_cnt}",
        "Profile ID / Type": f"0x{prof_id:04X} / 0x{prof_type:04X}",
        "I&M Version": f"{im_ver_maj}.{im_ver_min}",
        "Supported I&M Records": ", ".join(supp_list),
        "raw_supported": im_supp
    }

def parse_im1(data):
    """Decodes PROFINET I&M1 (0xAFF1) Tag Function & Tag Location."""
    if not data or len(data) < 60:
        return None
    if data[:6] != bytes.fromhex('002100380100') or len(data) != 60: return None
    return {
        "Tag Function (Plant Designation)": data[6:38].decode('ascii', errors='replace').strip(),
        "Tag Location (Location ID)": data[38:60].decode('ascii', errors='replace').strip()
    }

def parse_im2(data):
    """Decodes PROFINET I&M2 (0xAFF2) Installation Date."""
    if not data or len(data) < 22:
        return None
    if data[:6] != bytes.fromhex('002200120100') or len(data) != 22: return None
    return {
        "Installation Date": data[6:22].decode('ascii', errors='replace').strip()
    }

def parse_im3(data):
    """Decodes PROFINET I&M3 (0xAFF3) General Descriptor."""
    if not data or len(data) < 60:
        return None
    if data[:6] != bytes.fromhex('002300380100') or len(data) != 60: return None
    return {
        "Descriptor (Maintenance Notes)": data[6:60].decode('ascii', errors='replace').strip()
    }

def parse_real_identification_data(data):
    """Decodes RealIdentificationData (0xE001 / 0xF000, BlockType 0x0013) into Slots & Subslots."""
    if not data or len(data) < 8:
        return []
    btype, blen, vhi, vlo = struct.unpack('>HHBB', data[:6])
    idx = 6
    slots_found = []
    if btype != 0x0013 or blen + 4 != len(data): return []

    try:
        if vhi == 1 and vlo == 0:
            num_slots = struct.unpack('>H', data[idx:idx+2])[0]; idx += 2
            for _ in range(num_slots):
                slot_num, mod_ident, num_subslots = struct.unpack('>HIH', data[idx:idx+8]); idx += 8
                for _ in range(num_subslots):
                    sub_num, sub_ident = struct.unpack('>HI', data[idx:idx+6]); idx += 6
                    slots_found.append({
                        "api": 0, "slot": slot_num, "subslot": sub_num,
                        "mod_ident": f"0x{mod_ident:08X}", "sub_ident": f"0x{sub_ident:08X}"
                    })
        elif vhi == 1 and vlo == 1:
            num_apis = struct.unpack('>H', data[idx:idx+2])[0]; idx += 2
            for _ in range(num_apis):
                api_val, num_slots = struct.unpack('>IH', data[idx:idx+6]); idx += 6
                for _ in range(num_slots):
                    slot_num, mod_ident, num_subslots = struct.unpack('>HIH', data[idx:idx+8]); idx += 8
                    for _ in range(num_subslots):
                        sub_num, sub_ident = struct.unpack('>HI', data[idx:idx+6]); idx += 6
                        slots_found.append({
                            "api": api_val, "slot": slot_num, "subslot": sub_num,
                            "mod_ident": f"0x{mod_ident:08X}", "sub_ident": f"0x{sub_ident:08X}"
                        })
    except struct.error:
        return []

    return slots_found

def parse_diagnosis_blocks(data):
    """Scans a PNIO DiagnosisData record (0xF80C / 0x800C) for DiagnosisData blocks (BlockType 0x0010)."""
    diags = []
    if not data or len(data) < 6:
        return diags

    idx = 0
    while idx + 6 <= len(data):
        btype, blen, vhi, vlo = struct.unpack('>HHBB', data[idx:idx+6])
        block_end = idx + 4 + blen
        if block_end > len(data) or blen < 2:
            break

        if btype == 0x0010 and vhi == 1 and vlo in (0, 1):
            # Parse DiagnosisBlock header
            header_len = 20 if vlo == 1 else 16
            if block_end < idx + header_len: return []
            start = idx + (10 if vlo == 1 else 6)
            slot, subslot, ch_num, ch_prop, usr_struct = struct.unpack('>HHHHH', data[start : start+10])
            sub_idx = idx + header_len
            if usr_struct == 0x8000:  # ChannelDiagnosisData
                if (block_end - sub_idx) % 6: return []
                while sub_idx + 6 <= block_end:
                    c_num, c_prop, c_err = struct.unpack('>HHH', data[sub_idx:sub_idx+6])
                    sub_idx += 6
                    err_desc = CHANNEL_ERROR_TYPES.get(c_err, f"Unknown Error (0x{c_err:04X})")
                    diags.append({
                        "slot": slot, "subslot": subslot, "channel": f"0x{c_num:04X}",
                        "type": "ChannelDiagnosis", "error": f"{err_desc} (0x{c_err:04X})"
                    })
            elif usr_struct == 0x8002:  # ExtChannelDiagnosisData
                if (block_end - sub_idx) % 12: return []
                while sub_idx + 12 <= block_end:
                    c_num, c_prop, c_err, ext_err, add_val = struct.unpack('>HHHHI', data[sub_idx:sub_idx+12])
                    sub_idx += 12
                    err_desc = CHANNEL_ERROR_TYPES.get(c_err, f"Error 0x{c_err:04X}")
                    diags.append({
                        "slot": slot, "subslot": subslot, "channel": f"0x{c_num:04X}",
                        "type": "ExtChannelDiag",
                        "error": f"{err_desc} | Ext:0x{ext_err:04X} Val:0x{add_val:08X}"
                    })
            else:
                diags.append({
                    "slot": slot, "subslot": subslot, "channel": f"0x{ch_num:04X}",
                    "type": f"Struct 0x{usr_struct:04X}",
                    "error": f"Raw[{data[sub_idx:block_end].hex().upper()}]"
                })

        idx = block_end
    return diags


# --- 5. LAYER 2 CLIENT: PROFINET DCP (ETHERTYPE 0x8892) ---
class RawPROFINETDCPClient:
    """Implements Layer 2 PROFINET DCP (Discovery & Basic Configuration Protocol) over AF_PACKET."""
    ETH_P_PROFINET = 0x8892
    ETH_P_ALL      = 0x0003
    MULTICAST_DCP  = b'\x01\x0e\xcf\x00\x00\x00'

    def __init__(self, iface, timeout=3.0):
        self.iface = iface
        self.timeout = timeout
        self.sock = None
        self.src_mac = b'\x00' * 6
        self.xid = int(time.time()) & 0xFFFFFFFF
        self.last_outcome = 'NOT_SENT'

    def open(self):
        if self.sock is not None:
            return True
        if not hasattr(socket, "AF_PACKET"):
            logger.error("[OS ERROR] Layer 2 Raw Ethernet (AF_PACKET) requires a Linux host with root/CAP_NET_RAW privileges.")
            return False
        candidate = None
        try:
            candidate = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(self.ETH_P_ALL))
            candidate.bind((self.iface, 0))
            candidate.settimeout(self.timeout)
            src_mac = candidate.getsockname()[4][:6]
            self.src_mac = src_mac
            self.sock = candidate
            return True
        except PermissionError:
            logger.error("[PERMISSION ERROR] Root privileges (sudo) are required to open Layer 2 AF_PACKET sockets for DCP.")
            return False
        except OSError as e:
            logger.error(f"[INTERFACE ERROR] Could not bind to network interface '{self.iface}': {e}")
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

    def _build_eth_dcp(self, dst_mac, frame_id, service_id, service_type, xid, resp_delay, blocks_bytes):
        eth_hdr = dst_mac + self.src_mac + struct.pack('>H', self.ETH_P_PROFINET)
        dcp_hdr = struct.pack('>HBBIBH', frame_id, service_id, service_type, xid, resp_delay >> 8, len(blocks_bytes))
        # Fix exact 10-byte DCP header after 2-byte FrameID: ServiceID(1), ServiceType(1), Xid(4), RespDelay(2), Length(2)
        dcp_hdr = struct.pack('>HBB I HH', frame_id, service_id, service_type, xid, resp_delay, len(blocks_bytes))
        frame = eth_hdr + dcp_hdr + blocks_bytes
        if len(frame) < 60:
            frame += b'\x00' * (60 - len(frame))
        return frame

    @staticmethod
    def _build_dcp_block(option, suboption, payload):
        hdr = struct.pack('>BBH', option, suboption, len(payload))
        pad = b'\x00' if (len(payload) % 2 == 1) else b''
        return hdr + payload + pad

    def _extract_dcp_payload(self, raw_eth):
        """Strips Ethernet (and optional 802.1Q VLAN tag) to return (src_mac, frame_id, dcp_bytes)."""
        if len(raw_eth) < 26:
            return None, None, None
        src_mac = raw_eth[6:12]
        eth_type = struct.unpack('>H', raw_eth[12:14])[0]
        offset = 14
        if eth_type == 0x8100:  # 802.1Q VLAN Tagged frame
            eth_type = struct.unpack('>H', raw_eth[16:18])[0]
            offset = 18
        if eth_type != self.ETH_P_PROFINET:
            return None, None, None
        frame_id = struct.unpack('>H', raw_eth[offset:offset+2])[0]
        if offset + 12 > len(raw_eth): return None, None, None
        return src_mac, frame_id, raw_eth[offset+2:]

    def identify_all(self):
        """Broadcasts DCP Identify Request (0xFEFE) and parses all DCP Identify Responses (0xFEFF)."""
        self.xid = (self.xid + 1) & 0xFFFFFFFF
        all_selector = self._build_dcp_block(0xFF, 0xFF, b'')
        pkt = self._build_eth_dcp(self.MULTICAST_DCP, 0xFEFE, 0x05, 0x00, self.xid, 0x0001, all_selector)

        logger.debug(f"TX DCP Identify ({self.iface}): {pkt.hex().upper()}")
        self.sock.send(pkt)

        devices = {}
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                self.sock.settimeout(max(0.2, deadline - time.monotonic()))
                raw_eth = self.sock.recv(2048)
                if raw_eth[:6] != self.src_mac: continue
                src_mac, frame_id, dcp_body = self._extract_dcp_payload(raw_eth)
                if frame_id != 0xFEFF or not dcp_body or len(dcp_body) < 10:
                    continue

                srv_id, srv_type, rx_xid, _, dcp_len = struct.unpack('>BBIHH', dcp_body[:10])
                if srv_id != 0x05 or srv_type != 0x01 or rx_xid != self.xid or 10 + dcp_len > len(dcp_body):
                    continue

                mac_str = bytes_to_mac(src_mac)
                dev_info = {
                    "mac": mac_str,
                    "station_name": "",
                    "vendor_type": "",
                    "vendor_id": "",
                    "device_id": "",
                    "role": "",
                    "ip": "0.0.0.0",
                    "netmask": "0.0.0.0",
                    "gateway": "0.0.0.0"
                }

                blocks = dcp_body[10 : 10 + dcp_len]
                idx = 0
                valid_blocks = True
                while idx + 4 <= len(blocks):
                    opt, sub, blen = struct.unpack('>BBH', blocks[idx:idx+4])
                    if idx + 4 + blen + (blen & 1) > len(blocks):
                        valid_blocks = False
                        break
                    bdata = blocks[idx+4 : idx+4+blen]
                    idx += 4 + blen + (1 if (blen % 2 == 1) else 0)

                    # Option 1, Suboption 2: IP Parameter (BlockInfo 2B + IP 4B + Netmask 4B + GW 4B)
                    if opt == 0x01 and sub == 0x02 and len(bdata) >= 14:
                        dev_info["ip"] = socket.inet_ntoa(bdata[2:6])
                        dev_info["netmask"] = socket.inet_ntoa(bdata[6:10])
                        dev_info["gateway"] = socket.inet_ntoa(bdata[10:14])
                    # Option 2, Suboption 1: Device Vendor / Family
                    elif opt == 0x02 and sub == 0x01 and len(bdata) >= 2:
                        dev_info["vendor_type"] = bdata[2:].decode('ascii', errors='replace').strip('\x00 ')
                    # Option 2, Suboption 2: NameOfStation
                    elif opt == 0x02 and sub == 0x02 and len(bdata) >= 2:
                        dev_info["station_name"] = bdata[2:].decode('ascii', errors='replace').strip('\x00 ')
                    # Option 2, Suboption 3: Device ID (VendorID 2B + DeviceID 2B)
                    elif opt == 0x02 and sub == 0x03 and len(bdata) >= 6:
                        vid, did = struct.unpack('>HH', bdata[2:6])
                        dev_info["vendor_id"] = f"0x{vid:04X}"
                        dev_info["device_id"] = f"0x{did:04X}"
                    # Option 2, Suboption 4: Device Role
                    elif opt == 0x02 and sub == 0x04 and len(bdata) >= 3:
                        dev_info["role"] = decode_device_role(bdata[2])

                if valid_blocks and idx == len(blocks): devices[mac_str] = dev_info
            except socket.timeout:
                break
            except Exception:
                continue

        return list(devices.values())

    def send_dcp_set(self, target_mac_str, option, suboption, block_payload):
        """Sends a Unicast DCP Set Request (FrameID 0xFEFD, ServiceID 0x04) and checks Response Error Code."""
        dst_mac = mac_to_bytes(target_mac_str)
        self.xid = (self.xid + 1) & 0xFFFFFFFF
        block = self._build_dcp_block(option, suboption, block_payload)
        pkt = self._build_eth_dcp(dst_mac, 0xFEFD, 0x04, 0x00, self.xid, 0x0000, block)

        logger.debug(f"TX DCP Set ({target_mac_str}): {pkt.hex().upper()}")
        self.last_outcome = 'INDETERMINATE'
        self.sock.send(pkt)

        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                self.sock.settimeout(max(0.2, deadline - time.monotonic()))
                raw_eth = self.sock.recv(2048)
                if raw_eth[:6] != self.src_mac: continue
                src_mac, frame_id, dcp_body = self._extract_dcp_payload(raw_eth)
                if frame_id != 0xFEFD or src_mac != dst_mac or not dcp_body or len(dcp_body) < 10:
                    continue

                srv_id, srv_type, rx_xid, _, dcp_len = struct.unpack('>BBIHH', dcp_body[:10])
                if srv_id == 4 and srv_type == 5 and rx_xid == self.xid:
                    self.last_outcome = 'REJECTED'
                    return False, 'DCP service unsupported'
                if srv_id == 0x04 and srv_type == 0x01 and rx_xid == self.xid:
                    if 10 + dcp_len > len(dcp_body):
                        return False, 'Malformed DCP length'
                    blocks = dcp_body[10:10+dcp_len]
                    pos, result = 0, None
                    while pos < len(blocks):
                        if pos + 4 > len(blocks): return False, 'Truncated DCP block'
                        opt, sub, size = struct.unpack('>BBH', blocks[pos:pos+4])
                        end = pos + 4 + size
                        if end + (size & 1) > len(blocks): return False, 'Truncated DCP block'
                        value = blocks[pos+4:end]
                        if (opt, sub) == (5, 4):
                            if size != 3 or value[:2] != bytes([option, suboption]) or result is not None:
                                return False, 'Mismatched DCP Control Response'
                            result = value[2]
                        pos = end + (size & 1)
                    if result is None: return False, 'INDETERMINATE: missing expected Control Response'
                    self.last_outcome = 'PROTOCOL_ACCEPTED' if result == 0 else 'REJECTED'
                    return result == 0, f'DCP BlockError 0x{result:02X}'
            except socket.timeout:
                break
        return False, "INDETERMINATE: timeout waiting for DCP Set Response"


# --- 6. COMMAND EXECUTION LOGIC ---
def do_im_fingerprint(rpc_client, args):
    logger.info(f"Querying PROFINET I&M0..I&M3 Records on {args.host} [API:{args.api}, Slot:{args.slot}, Subslot:{args.subslot}]...")
    raw_im0 = rpc_client.read_implicit_record(args.api, args.slot, args.subslot, 0xAFF0)

    # If Slot 0 Subslot 1 did not return I&M0, auto-discover first valid subslot via RealIdentificationData (0xE001)
    target_api, target_slot, target_subslot = args.api, args.slot, args.subslot
    if not raw_im0:
        raw_real = rpc_client.read_implicit_record(args.api, 0, 1, 0xE001, suppress_logs=True)
        slots = parse_real_identification_data(raw_real)
        for s in slots:
            raw_im0 = rpc_client.read_implicit_record(s["api"], s["slot"], s["subslot"], 0xAFF0, suppress_logs=True)
            if raw_im0:
                target_api, target_slot, target_subslot = s["api"], s["slot"], s["subslot"]
                break

    if not raw_im0:
        logger.error("Failed to retrieve I&M0 (0xAFF0) record from target PROFINET device.")
        return False

    im0 = parse_im0(raw_im0)
    if im0 is None:
        logger.error('Unsupported or malformed I&M0 record')
        return False
    print(f"\n{Color.CYAN}{Color.BOLD}--- PROFINET I&M0 DEVICE FINGERPRINT (Slot {target_slot} / Subslot {target_subslot}) ---{Color.RESET}")
    if im0:
        for k, v in im0.items():
            if k != "raw_supported":
                print(f"  {Color.BLUE}{k:<26}:{Color.RESET} {Color.GREEN}{v}{Color.RESET}")

    # Query I&M1, I&M2, I&M3 if supported or available
    raw_im1 = rpc_client.read_implicit_record(target_api, target_slot, target_subslot, 0xAFF1, suppress_logs=True)
    if raw_im1:
        im1 = parse_im1(raw_im1)
        if im1:
            for k, v in im1.items():
                print(f"  {Color.BLUE}{k:<26}:{Color.RESET} {Color.YELLOW}{v or '(empty)'}{Color.RESET}")

    raw_im2 = rpc_client.read_implicit_record(target_api, target_slot, target_subslot, 0xAFF2, suppress_logs=True)
    if raw_im2:
        im2 = parse_im2(raw_im2)
        if im2:
            for k, v in im2.items():
                print(f"  {Color.BLUE}{k:<26}:{Color.RESET} {Color.YELLOW}{v or '(empty)'}{Color.RESET}")

    raw_im3 = rpc_client.read_implicit_record(target_api, target_slot, target_subslot, 0xAFF3, suppress_logs=True)
    if raw_im3:
        im3 = parse_im3(raw_im3)
        if im3:
            for k, v in im3.items():
                print(f"  {Color.BLUE}{k:<26}:{Color.RESET} {Color.YELLOW}{v or '(empty)'}{Color.RESET}")
    print()
    return True

def do_topology(rpc_client, args):
    logger.info(f"Reading RealIdentificationData (0xE001 / 0xF000) from {args.host}...")
    raw_real = rpc_client.read_implicit_record(args.api, 0, 1, 0xE001, suppress_logs=True)
    if not raw_real:
        raw_real = rpc_client.read_implicit_record(args.api, 0, 1, 0xF000, suppress_logs=True)

    slots = parse_real_identification_data(raw_real)
    print(f"\n{Color.CYAN}{Color.BOLD}--- PROFINET PHYSICAL RACK & SUBSLOT TOPOLOGY ({args.host}) ---{Color.RESET}")
    if not slots:
        print(f" {Color.YELLOW}No RealIdentificationData entries returned.{Color.RESET}\n")
        return False

    print(f" {'API':<5} | {'SLOT':<6} | {'SUBSLOT':<9} | {'MODULE IDENT':<14} | {'SUBMODULE IDENT':<16} | {'ORDER ID / MLFB'}")
    print(f" {'-'*5}-+-{'-'*6}-+-{'-'*9}-+-{'-'*14}-+-{'-'*16}-+-{'-'*24}")
    for s in slots:
        # Attempt quick I&M0 read on subslot to show OrderID if available
        im0_raw = rpc_client.read_implicit_record(s["api"], s["slot"], s["subslot"], 0xAFF0, suppress_logs=True)
        im0_info = parse_im0(im0_raw) if im0_raw else None
        mlfb = im0_info["Order ID (MLFB)"] if im0_info else "-"
        print(
            f" {s['api']:<5} | "
            f"{Color.YELLOW}{s['slot']:<6}{Color.RESET} | "
            f"{Color.YELLOW}{'0x' + format(s['subslot'], '04X') if s['subslot'] >= 0x8000 else str(s['subslot']):<9}{Color.RESET} | "
            f"{Color.BLUE}{s['mod_ident']:<14}{Color.RESET} | "
            f"{Color.GREEN}{s['sub_ident']:<16}{Color.RESET} | "
            f"{Color.GREY}{mlfb}{Color.RESET}"
        )
    print()
    return True

def do_diag(rpc_client, args):
    logger.info(f"Querying Device DiagnosisData (0xF80C / 0x800C) on {args.host}...")
    raw_diag = rpc_client.read_implicit_record(args.api, args.slot, args.subslot, 0xF80C, suppress_logs=True)
    if not raw_diag:
        raw_diag = rpc_client.read_implicit_record(args.api, args.slot, args.subslot, 0x800C, suppress_logs=True)

    print(f"\n{Color.CYAN}{Color.BOLD}--- PROFINET ACTIVE CHANNEL & MODULE DIAGNOSIS ({args.host}) ---{Color.RESET}")
    if not raw_diag:
        print(f" {Color.GREEN}No diagnostic record obtained; device health is UNKNOWN.{Color.RESET}\n")
        return False

    diags = parse_diagnosis_blocks(raw_diag)
    if not diags:
        print(f" {Color.GREEN}No supported diagnostic entries decoded; device health is UNKNOWN.{Color.RESET}\n")
        return False

    print(f" {'SLOT':<6} | {'SUBSLOT':<9} | {'CHANNEL':<9} | {'DIAGNOSIS TYPE':<18} | {'FAULT DESCRIPTION'}")
    print(f" {'-'*6}-+-{'-'*9}-+-{'-'*9}-+-{'-'*18}-+-{'-'*36}")
    for d in diags:
        print(
            f" {Color.YELLOW}{d['slot']:<6}{Color.RESET} | "
            f"{Color.YELLOW}{d['subslot']:<9}{Color.RESET} | "
            f"{d['channel']:<9} | "
            f"{Color.BLUE}{d['type']:<18}{Color.RESET} | "
            f"{Color.RED}{Color.BOLD}{d['error']}{Color.RESET}"
        )
    print()
    return True

def do_read_record(rpc_client, args):
    logger.info(
        f"Executing PNIO ReadImplicit [API:{args.api}, Slot:{args.slot}, "
        f"Subslot:{args.subslot}, Index:0x{args.index:04X}]..."
    )
    data = rpc_client.read_implicit_record(args.api, args.slot, args.subslot, args.index)
    if data is None:
        logger.error(f"Failed to read Record Index 0x{args.index:04X}.")
        return False

    print(f"\n{Color.CYAN}{Color.BOLD}--- PROFINET RECORD READ (Index: 0x{args.index:04X} | Length: {len(data)} bytes) ---{Color.RESET}")
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset+16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        print(f"  {Color.GREY}{offset:04X}:{Color.RESET}  {Color.GREEN}{hex_part:<48}{Color.RESET}  {Color.YELLOW}{ascii_part}{Color.RESET}")
    print()
    return True

def do_dcp_scan(dcp_client):
    logger.info(f"Broadcasting PROFINET DCP Identify Request (0xFEFE) on interface '{dcp_client.iface}'...")
    devs = dcp_client.identify_all()
    print(f"\n{Color.CYAN}{Color.BOLD}--- PROFINET LAYER 2 DCP DISCOVERY RESULTS ({len(devs)}) ---{Color.RESET}")
    if not devs:
        print(f" {Color.YELLOW}No PROFINET devices responded on interface '{dcp_client.iface}'.{Color.RESET}\n")
        return False

    print(f" {'MAC ADDRESS':<18} | {'STATION NAME':<22} | {'IP ADDRESS':<15} | {'NETMASK':<15} | {'VENDOR:DEV ID':<13} | {'ROLE / FAMILY'}")
    print(f" {'-'*18}-+-{'-'*22}-+-{'-'*15}-+-{'-'*15}-+-{'-'*13}-+-{'-'*24}")
    for d in devs:
        vid_did = f"{d['vendor_id']}:{d['device_id']}" if d["vendor_id"] else "N/A"
        role_fam = f"{d['vendor_type']} ({d['role']})" if d["vendor_type"] else d["role"]
        print(
            f" {Color.YELLOW}{d['mac']:<18}{Color.RESET} | "
            f"{Color.GREEN}{Color.BOLD}{(d['station_name'] or '(unassigned)')[:22]:<22}{Color.RESET} | "
            f"{Color.CYAN}{d['ip']:<15}{Color.RESET} | "
            f"{d['netmask']:<15} | "
            f"{Color.BLUE}{vid_did:<13}{Color.RESET} | "
            f"{Color.GREY}{role_fam}{Color.RESET}"
        )
    print()
    return True

def do_dcp_action(dcp_client, args):
    qual = 0x0001 if args.permanent else 0x0000
    qual_str = "PERMANENT" if args.permanent else "TEMPORARY"

    if args.command == "dcp-blink":
        logger.warning(f"EXECUTING OT PROFINET DCP SIGNAL/LED FLASH on MAC {args.mac} (Interface: {dcp_client.iface})")
        # Option 5 (Control), Suboption 3 (Signal), BlockQualifier=0x0000, SignalValue=0x0100 (Flash Once)
        payload = struct.pack('>HH', 0x0000, 0x0100)
        ok, msg = dcp_client.send_dcp_set(args.mac, 0x05, 0x03, payload)

    elif args.command == "dcp-set-name":
        station_clean = args.station_name.strip().lower()
        logger.warning(f"EXECUTING OT PROFINET DCP SET STATION NAME [{qual_str}] -> '{station_clean}' on MAC {args.mac}")
        payload = struct.pack('>H', qual) + station_clean.encode('ascii')
        ok, msg = dcp_client.send_dcp_set(args.mac, 0x02, 0x02, payload)

    elif args.command == "dcp-set-ip":
        logger.warning(
            f"EXECUTING OT PROFINET DCP SET IP SUITE [{qual_str}] -> "
            f"IP:{args.new_ip}, Mask:{args.netmask}, GW:{args.gateway} on MAC {args.mac}"
        )
        ip_b = socket.inet_aton(args.new_ip)
        nm_b = socket.inet_aton(args.netmask)
        gw_b = socket.inet_aton(args.gateway)
        payload = struct.pack('>H', qual) + ip_b + nm_b + gw_b
        ok, msg = dcp_client.send_dcp_set(args.mac, 0x01, 0x02, payload)

    elif args.command == "dcp-reset":
        logger.warning(f"EXECUTING OT PROFINET DCP RESET TO FACTORY on MAC {args.mac}")
        # Option 5 (Control), Suboption 6 (Reset to Factory), Qualifier 0x0002 (Reset application/comm data)
        payload = struct.pack('>H', 0x0002)
        ok, msg = dcp_client.send_dcp_set(args.mac, 0x05, 0x06, payload)

    if ok:
        print(f"\n{Color.GREEN}{Color.BOLD}[SUCCESS]{Color.RESET} DCP command '{args.command}' accepted by {args.mac} ({msg}).\n")
    else:
        logger.error(f"DCP command '{args.command}' was not accepted on {args.mac}: {msg}")
    return ok


# --- 7. MAIN ENTRY POINT ---
def main():
    desc_text = f"{Color.BOLD}PROFINET IO (DCE/RPC & DCP) Master CLI (by z4y_d3n){Color.RESET}\n"
    custom_usage = (
        f"{Color.GREEN}profinet_master.py{Color.RESET} "
        f"{Color.YELLOW}[-c COMMAND] [-H HOST] [-p PORT] [-S SLOT] [-s SUBSLOT] [-I INDEX] "
        f"[-i IFACE] [-m MAC] [--station-name NAME] [--new-ip IP]{Color.RESET}"
    )

    parser = CustomArgumentParser(description=desc_text, usage=custom_usage, formatter_class=ColoredHelpFormatter)

    parser.add_argument("-c", "--command", required=True, choices=[
        "im", "topology", "diag", "read-record",
        "dcp-scan", "dcp-blink", "dcp-set-name", "dcp-set-ip", "dcp-reset"
    ], help="PROFINET action to execute (Layer 3 RPC or Layer 2 DCP).")
    parser.add_argument("--timeout", type=float, default=3.0, help="Socket timeout in seconds (Default: 3.0).")
    parser.add_argument("--debug", action="store_true", help="Enable raw Hex DCE/RPC & Ethernet DCP trace logs.")

    l3_group = parser.add_argument_group(f"{Color.CYAN}Layer 3 PROFINET IO DCE/RPC Options (-c im / topology / diag / read-record){Color.RESET}")
    l3_group.add_argument("-H", "--host", type=str, help="Target IP of the PROFINET IO-Device/Controller.")
    l3_group.add_argument("-p", "--port", type=int, default=34964, help="UDP PNIO Context Manager Port (Default: 34964).")
    l3_group.add_argument("-A", "--api", type=lambda x: int(x, 0), default=0, help="PROFINET API number (Default: 0).")
    l3_group.add_argument("-S", "--slot", type=lambda x: int(x, 0), default=0, help="Physical Slot number (Default: 0).")
    l3_group.add_argument("-s", "--subslot", type=lambda x: int(x, 0), default=1, help="Subslot number (Default: 1).")
    l3_group.add_argument("-I", "--index", type=lambda x: int(x, 0), default=0xAFF0, help="Record Index in Hex/Int for 'read-record' (e.g., 0xAFF0, 0xF841, 0x802A).")

    l2_group = parser.add_argument_group(f"{Color.CYAN}Layer 2 PROFINET DCP Options (-c dcp-*){Color.RESET}")
    l2_group.add_argument("-i", "--iface", type=str, help="Network Interface for Layer 2 DCP (e.g., eth0, ens33).")
    l2_group.add_argument("-m", "--mac", type=str, help="Target Device MAC Address (e.g., 00:0E:8C:AA:BB:CC).")
    l2_group.add_argument("--station-name", type=str, help="New PROFINET NameOfStation for 'dcp-set-name'.")
    l2_group.add_argument("--new-ip", type=str, help="New IPv4 Address for 'dcp-set-ip'.")
    l2_group.add_argument("--netmask", type=str, default="255.255.255.0", help="Subnet Mask for 'dcp-set-ip' (Default: 255.255.255.0).")
    l2_group.add_argument("--gateway", type=str, default="0.0.0.0", help="Default Gateway for 'dcp-set-ip' (Default: 0.0.0.0).")
    l2_group.add_argument("--permanent", action="store_true", help="Store DCP Name/IP configuration permanently in NVRAM.")

    if len(sys.argv) == 1:
        parser.print_usage()
        sys.exit(1)

    parser.usage = argparse.SUPPRESS
    args = parser.parse_args()

    # --- Logical Validations ---
    try:
        if not 1 <= args.port <= 65535 or not 0 < args.timeout < float('inf'):
            raise ValueError('Port or timeout out of range')
        if not 0 <= args.api <= 0xffffffff or any(not 0 <= x <= 65535 for x in (args.slot, args.subslot, args.index)):
            raise ValueError('PNIO address out of range')
        if args.mac and len(mac_to_bytes(args.mac)) != 6: raise ValueError('MAC must contain six octets')
        if args.command == 'dcp-set-ip':
            import ipaddress
            for value in (args.new_ip, args.netmask, args.gateway): ipaddress.IPv4Address(value)
        if args.station_name:
            raw = args.station_name.strip().lower().encode('ascii')
            if not 1 <= len(raw) <= 240: raise ValueError('Station name length out of range')
    except (ValueError, UnicodeError) as exc:
        parser.error(str(exc))
    l3_cmds = ("im", "topology", "diag", "read-record")
    l2_cmds = ("dcp-scan", "dcp-blink", "dcp-set-name", "dcp-set-ip", "dcp-reset")

    if args.command in l3_cmds and not args.host:
        parser.error(f"Argument -H / --host is strictly required for Layer 3 command '{args.command}'.")
    if args.command in l2_cmds and not args.iface:
        parser.error(f"Argument -i / --iface is strictly required for Layer 2 DCP command '{args.command}'.")
    if args.command in ("dcp-blink", "dcp-set-name", "dcp-set-ip", "dcp-reset") and not args.mac:
        parser.error(f"Argument -m / --mac is strictly required for '{args.command}'.")
    if args.command == "dcp-set-name" and not args.station_name:
        parser.error("Argument --station-name is strictly required for 'dcp-set-name'.")
    if args.command == "dcp-set-ip" and not args.new_ip:
        parser.error("Argument --new-ip is strictly required for 'dcp-set-ip'.")

    setup_logger(args.debug)

    # Execute Layer 3 (UDP 34964 DCE/RPC) Commands
    if args.command in l3_cmds:
        rpc_client = RawPNIORPCClient(args.host, port=args.port, timeout=args.timeout, retries=2)
        if not rpc_client.connect():
            sys.exit(1)
        print(
            f"{Color.GREEN}{Color.BOLD}[PNIO RPC READY]{Color.RESET} {Color.CYAN}{args.host}:{args.port}{Color.RESET} | "
            f"Slot:{Color.BLUE}{args.slot}.{args.subslot}{Color.RESET} | "
            f"Command: {Color.YELLOW}{args.command.upper()}{Color.RESET}\n"
        )
        try:
            if args.command == "im":
                result = do_im_fingerprint(rpc_client, args)
            elif args.command == "topology":
                result = do_topology(rpc_client, args)
            elif args.command == "diag":
                result = do_diag(rpc_client, args)
            elif args.command == "read-record":
                result = do_read_record(rpc_client, args)
        finally:
            rpc_client.close()
        if result is False:
            sys.exit(1)

    # Execute Layer 2 (Raw Ethernet 0x8892 DCP) Commands
    else:
        dcp_client = RawPROFINETDCPClient(args.iface, timeout=args.timeout)
        if not dcp_client.open():
            sys.exit(1)
        print(
            f"{Color.GREEN}{Color.BOLD}[DCP L2 READY]{Color.RESET} Interface: {Color.CYAN}{args.iface}{Color.RESET} "
            f"({bytes_to_mac(dcp_client.src_mac)}) | Command: {Color.YELLOW}{args.command.upper()}{Color.RESET}\n"
        )
        try:
            if args.command == "dcp-scan":
                do_dcp_scan(dcp_client)
            else:
                if not do_dcp_action(dcp_client, args): sys.exit(1)
        finally:
            dcp_client.close()

if __name__ == "__main__":
    main()
