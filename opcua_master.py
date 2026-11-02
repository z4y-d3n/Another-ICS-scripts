#!/usr/bin/env python3
import asyncio
import argparse
import logging
import os
import signal
import socket
import sys
import time
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit, urlunsplit

try:
    from asyncua import Client, Node, ua
except ImportError:
    print("\n\033[91m\033[1m[DEPENDENCY ERROR]\033[0m Library 'asyncua' is not installed.")
    print("\033[93mInstall it via: pip install asyncua cryptography\033[0m\n")
    sys.exit(1)

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

logger = logging.getLogger("OPCUAMasterCLI")

class AuthenticationLogFilter(logging.Filter):
    """asyncua 2.0.1 debug request repr contains the identity-token password."""
    def filter(self, record):
        args = record.args if isinstance(record.args, tuple) else ()
        if any(isinstance(arg, ua.ActivateSessionRequest) for arg in args):
            record.msg = "Sending ActivateSessionRequest (credentials redacted)"
            record.args = ()
        return True

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

def setup_logger(debug_mode: bool):
    # Prepare both destinations before replacing a working configuration.
    prepared_handlers = []
    try:
        console_handler = logging.StreamHandler(sys.stdout)
        prepared_handlers.append(console_handler)
        console_handler.setFormatter(ColoredFormatter())

        audit_dir = "ot_audit_logs"
        os.makedirs(audit_dir, exist_ok=True)
        log_file = os.path.join(audit_dir, f"opcua_master_LAB_{datetime.now().strftime('%Y%m%d')}.log")

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
    # Silence noisy third-party loggers unless debug mode is explicitly enabled
    logging.getLogger("asyncua").setLevel(logging.DEBUG if debug_mode else logging.CRITICAL)
    wire_logger = logging.getLogger("asyncua.client.ua_client.UASocketProtocol")
    if not any(isinstance(f, AuthenticationLogFilter) for f in wire_logger.filters):
        wire_logger.addFilter(AuthenticationLogFilter())
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


# --- 2. CONFIGURATION, PKI CERTIFICATES & DATA HELPERS ---
DEFAULT_APP_URI = f"urn:{socket.gethostname()}:ot:opcua-master"
CERT_DIR = Path("pki")
CLIENT_CERT = CERT_DIR / "client_cert.der"
CLIENT_KEY = CERT_DIR / "client_key.pem"

VARIANT_TYPE_MAP: Dict[str, ua.VariantType] = {
    "bool":       ua.VariantType.Boolean,
    "sbyte":      ua.VariantType.SByte,
    "byte":       ua.VariantType.Byte,
    "int16":      ua.VariantType.Int16,
    "uint16":     ua.VariantType.UInt16,
    "int32":      ua.VariantType.Int32,
    "uint32":     ua.VariantType.UInt32,
    "int64":      ua.VariantType.Int64,
    "uint64":     ua.VariantType.UInt64,
    "float":      ua.VariantType.Float,
    "double":     ua.VariantType.Double,
    "string":     ua.VariantType.String,
    "bytestring": ua.VariantType.ByteString,
    "datetime":   ua.VariantType.DateTime,
}

NODE_CLASS_NAMES = {
    ua.NodeClass.Object:        "Object",
    ua.NodeClass.Variable:      "Variable",
    ua.NodeClass.Method:        "Method",
    ua.NodeClass.ObjectType:    "ObjectType",
    ua.NodeClass.VariableType:  "VariableType",
    ua.NodeClass.ReferenceType: "ReferenceType",
    ua.NodeClass.DataType:      "DataType",
    ua.NodeClass.View:          "View",
}

def safe_str(value: Any, max_len: int = 80) -> str:
    try:
        if isinstance(value, (bytes, bytearray)):
            s = f"0x{value.hex().upper()}"
        else:
            s = str(value)
    except Exception:
        s = repr(value)
    s = s.replace("\n", " ").replace("\r", "")
    return s[:max_len] + ("..." if len(s) > max_len else "")

def display_url(url: str) -> str:
    """Remove URL userinfo only for output; asyncua still receives original URL."""
    parts = urlsplit(url)
    return urlunsplit(parts._replace(netloc=parts.netloc.rsplit('@', 1)[-1]))

def nodeid_to_str(nodeid: ua.NodeId) -> str:
    try:
        return nodeid.to_string()
    except Exception:
        return str(nodeid)

def get_namespace(nodeid: ua.NodeId) -> int:
    try:
        return int(nodeid.NamespaceIndex)
    except Exception:
        return 0

def format_access_level(access_set: Any) -> Tuple[str, bool]:
    if not access_set:
        return "-/-", False
    s = str(access_set)
    can_read = ("CurrentRead" in s) or (ua.AccessLevel.CurrentRead in access_set if isinstance(access_set, (set, list)) else False)
    can_write = ("CurrentWrite" in s) or (ua.AccessLevel.CurrentWrite in access_set if isinstance(access_set, (set, list)) else False)
    hist = ("HistoryRead" in s)
    r_str = "R" if can_read else "-"
    w_str = "W" if can_write else "-"
    h_str = "/H" if hist else ""
    return f"{r_str}/{w_str}{h_str}", can_write

def cast_value_to_variant(raw_val: str, vtype: ua.VariantType) -> ua.Variant:
    """Casts a CLI string value into a strictly typed OPC UA Variant."""
    if vtype == ua.VariantType.Boolean:
        literal = str(raw_val).strip().lower()
        if literal not in ("1", "true", "t", "yes", "y", "on", "0", "false", "f", "no", "n", "off"):
            raise ValueError("Invalid Boolean literal")
        val = literal in ("1", "true", "t", "yes", "y", "on")
    elif vtype in (
        ua.VariantType.SByte, ua.VariantType.Byte,
        ua.VariantType.Int16, ua.VariantType.UInt16,
        ua.VariantType.Int32, ua.VariantType.UInt32,
        ua.VariantType.Int64, ua.VariantType.UInt64
    ):
        val = int(str(raw_val).strip(), 0)
        bits = {ua.VariantType.SByte:8, ua.VariantType.Byte:8, ua.VariantType.Int16:16,
                ua.VariantType.UInt16:16, ua.VariantType.Int32:32, ua.VariantType.UInt32:32,
                ua.VariantType.Int64:64, ua.VariantType.UInt64:64}[vtype]
        signed = vtype in (ua.VariantType.SByte, ua.VariantType.Int16, ua.VariantType.Int32, ua.VariantType.Int64)
        if not (-(1 << (bits - 1)) if signed else 0) <= val <= (1 << (bits - int(signed))) - 1:
            raise ValueError(f"Value outside {vtype.name} range")
    elif vtype in (ua.VariantType.Float, ua.VariantType.Double):
        val = float(str(raw_val).strip())
        if vtype == ua.VariantType.Float:
            val = struct.unpack('<f', struct.pack('<f', val))[0]
    elif vtype == ua.VariantType.ByteString:
        clean_hex = str(raw_val).strip().replace(" ", "").replace("0x", "")
        val = bytes.fromhex(clean_hex)
    elif vtype == ua.VariantType.DateTime:
        if str(raw_val).strip().lower() == "now":
            val = datetime.now(timezone.utc)
        else:
            val = datetime.fromisoformat(str(raw_val).strip())
            if val.tzinfo is None:
                val = val.replace(tzinfo=timezone.utc)
    else:
        val = str(raw_val)
    return ua.Variant(val, vtype)

async def ensure_pki_certificates(cert_path: Path, key_path: Path, app_uri: str) -> bool:
    """Ensures valid OPC UA X.509v3 DER certificate and PEM private key exist with matching SAN URI."""
    if cert_path.exists() and key_path.exists():
        return True

    logger.info(f"Generating OPC UA X.509v3 Self-Signed Certificate in '{cert_path.parent}/'...")
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    hostname = socket.gethostname()

    # Primary method: Use cryptography directly to guarantee OPC UA compliant X.509v3 extensions
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OT Maintenance Engineering"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"OPCUAMasterCLI@{hostname}"),
        ])
        now_utc = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now_utc - timedelta(days=1))
            .not_valid_after(now_utc + timedelta(days=3650))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(app_uri),
                    x509.DNSName(hostname),
                    x509.DNSName("localhost"),
                ]),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
        logger.info(f"{Color.GREEN}[PKI READY]{Color.RESET} Created Certificate: {cert_path} | Key: {key_path}")
        return True
    except Exception as e:
        logger.error(f"[PKI ERROR] Failed to generate X.509 certificates: {e}")
        return False


# --- 3. CORE OPC UA CLIENT WRAPPER ---
class VariableRecord:
    def __init__(self, node_id: str, ns: int, name: str, vtype: str, value: Any, status: str, access: str, writable: bool):
        self.node_id = node_id
        self.ns = ns
        self.name = name
        self.vtype = vtype
        self.value = value
        self.status = status
        self.access = access
        self.writable = writable

class SubscriptionHandler:
    """Handles real-time OPC UA Pub/Sub DataChange notifications (UAExpert Data Access View)."""
    def datachange_notification(self, node: Node, val: Any, data: Any):
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        nid_str = nodeid_to_str(node.nodeid)
        status_str = "Good"
        src_ts = ""
        try:
            if hasattr(data, "monitored_item") and data.monitored_item.Value:
                dv = data.monitored_item.Value
                if dv.StatusCode:
                    status_str = dv.StatusCode.name
                if dv.SourceTimestamp:
                    src_ts = f" | SrcTime: {dv.SourceTimestamp.strftime('%H:%M:%S.%f')[:-3]}"
        except Exception:
            pass

        st_color = Color.GREEN if "Good" in status_str else Color.YELLOW
        print(
            f"{Color.CYAN}[{ts}]{Color.RESET} "
            f"Node [{Color.YELLOW}{nid_str:<22}{Color.RESET}] -> "
            f"{Color.GREEN}{Color.BOLD}{safe_str(val, 45)}{Color.RESET} "
            f"({st_color}{status_str}{Color.RESET}{Color.GREY}{src_ts}{Color.RESET})"
        )

    def status_change_notification(self, status: ua.StatusChangeNotification):
        logger.warning(f"[SUBSCRIPTION STATUS CHANGE] {status}")


class IndustrialOPCUAClient:
    def __init__(
        self,
        url: str,
        timeout: float = 10.0,
        op_timeout: float = 8.0,
        sec_policy: str = "auto",
        sec_mode: str = "auto",
        username: Optional[str] = None,
        password: Optional[str] = None,
        cert_path: Path = CLIENT_CERT,
        key_path: Path = CLIENT_KEY,
        app_uri: str = DEFAULT_APP_URI,
    ):
        self.url = url
        self.timeout = timeout
        self.op_timeout = op_timeout
        self.sec_policy = sec_policy
        self.sec_mode = sec_mode
        self.username = username
        self.password = password
        self.cert_path = cert_path
        self.key_path = key_path
        self.app_uri = app_uri

        self.client: Optional[Client] = None
        self.active_policy: str = "None"
        self.active_mode: str = "None"

    async def with_timeout(self, coro, desc: str = "operation", *, strict: bool = False):
        try:
            return await asyncio.wait_for(coro, timeout=self.op_timeout)
        except asyncio.TimeoutError:
            if strict:
                logger.error(f"[REQUIRED OP ERROR] {desc}: TimeoutError")
                raise
            logger.debug(f"[TIMEOUT] Timed out during {desc} ({self.op_timeout}s)")
            return None
        except Exception as e:
            if strict:
                logger.error(f"[REQUIRED OP ERROR] {desc}: {type(e).__name__}")
                raise
            logger.debug(f"[OP ERROR] {desc}: {e}")
            return None

    async def discover_endpoints(self, suppress_logs: bool = False) -> List[Any]:
        if not suppress_logs:
            logger.info(f"Querying OPC UA Server Endpoints on {display_url(self.url)}...")
        discovery_client = Client(self.url, timeout=self.timeout)
        try:
            endpoints = await discovery_client.connect_and_get_server_endpoints()
            return endpoints or []
        except Exception as e:
            if not suppress_logs:
                logger.error(f"[DISCOVERY ERROR] Could not fetch endpoints from {display_url(self.url)}: {e}")
            raise
        finally:
            try:
                await discovery_client.disconnect()
            except Exception:
                pass

    @staticmethod
    def parse_endpoint_security(ep) -> Tuple[str, str, int, List[str]]:
        policy_uri = getattr(ep, "SecurityPolicyUri", "") or ""
        policy_name = policy_uri.split("#")[-1] if "#" in policy_uri else (policy_uri or "None")

        mode_val = getattr(ep, "SecurityMode", 1)
        mode_map = {
            1: "None", "1": "None", "MessageSecurityMode.None_": "None",
            2: "Sign", "2": "Sign", "MessageSecurityMode.Sign": "Sign",
            3: "SignAndEncrypt", "3": "SignAndEncrypt", "MessageSecurityMode.SignAndEncrypt": "SignAndEncrypt",
        }
        mode_str = mode_map.get(mode_val, mode_map.get(str(mode_val), str(mode_val).split(".")[-1].rstrip("_")))
        level = getattr(ep, "SecurityLevel", 0)

        tokens = []
        for tk in getattr(ep, "UserIdentityTokens", []) or []:
            ttype = str(getattr(tk, "TokenType", "")).split(".")[-1]
            tokens.append(ttype)
        return policy_name, mode_str, level, tokens

    async def resolve_security(self) -> Tuple[str, str]:
        if self.sec_policy != "auto" and self.sec_mode != "auto":
            if (self.sec_policy == "None") != (self.sec_mode == "None"):
                raise ValueError("Security policy and mode must both be None or both secure")
            return self.sec_policy, self.sec_mode

        endpoints = await self.discover_endpoints(suppress_logs=True)
        if not endpoints:
            if self.sec_policy == "auto" and self.sec_mode == "auto":
                return "None", "None"
            raise ValueError("Cannot resolve explicitly requested security without endpoints")

        # Prefer "None" first if available for frictionless maintenance, else pick first supported endpoint
        parsed_eps = [self.parse_endpoint_security(ep) for ep in endpoints]
        supported = {"None", "Basic256Sha256", "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss", "Basic256", "Basic128Rsa15"}
        parsed_eps = [ep for ep in parsed_eps
                      if ep[0] in supported
                      and (ep[0] == "None") == (ep[1] == "None")
                      and (self.sec_policy == "auto" or ep[0] == self.sec_policy)
                      and (self.sec_mode == "auto" or ep[1] == self.sec_mode)]
        if not parsed_eps:
            raise ValueError("No endpoint matches requested security policy/mode")
        for pol, mod, _, _ in parsed_eps:
            if pol == "None" and mod == "None" and self.sec_policy == "auto":
                return "None", "None"

        pol, mod, _, _ = parsed_eps[0]
        final_pol = pol if self.sec_policy == "auto" else self.sec_policy
        final_mod = mod if self.sec_mode == "auto" else self.sec_mode
        return final_pol, final_mod

    async def connect(self, suppress_logs: bool = False) -> bool:
        try:
            self.active_policy, self.active_mode = await self.resolve_security()

            self.client = Client(self.url, timeout=self.timeout)
            self.client.application_uri = self.app_uri

            if self.active_policy != "None" and self.active_mode != "None":
                if not await ensure_pki_certificates(self.cert_path, self.key_path, self.app_uri):
                    return False
                sec_str = f"{self.active_policy},{self.active_mode},{self.cert_path},{self.key_path}"
                if not suppress_logs:
                    logger.info(f"Applying Security Policy: {self.active_policy} | Mode: {self.active_mode}")
                await self.client.set_security_string(sec_str)

            if self.username:
                self.client.set_user(self.username)
                if self.password is not None:
                    self.client.set_password(self.password)

            await self.client.connect()
            auth_mode = f"User '{self.username}'" if self.username else "Anonymous"
            if not suppress_logs:
                logger.info(
                    f"Session established ({auth_mode} | "
                    f"Security: {self.active_policy}/{self.active_mode})"
                )
            return True
        except Exception as e:
            if not suppress_logs:
                logger.error(f"[CONNECTION ERROR] Failed to connect to {display_url(self.url)}: {e}")
            return False

    async def disconnect(self):
        if self.client:
            try:
                await self.client.disconnect()
            except Exception:
                pass
            finally:
                self.client = None

    async def ensure_connected(self) -> bool:
        if not self.client:
            return await self.connect(suppress_logs=True)
        try:
            srv_node = self.client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server))
            await asyncio.wait_for(srv_node.read_node_class(), timeout=2.5)
            return True
        except Exception:
            logger.warning("[RECONNECT] Connection lost with OPC UA Server. Reconnecting...")
            await self.disconnect()
            return await self.connect(suppress_logs=True)

    async def safe_get_children(self, node: Node) -> List[Node]:
        children = await self.with_timeout(node.get_children(), "get_children")
        if children is not None:
            return list(children)
        # Fallback to raw browse if get_children fails
        try:
            if hasattr(node, "browse"):
                refs = await self.with_timeout(node.browse(), "browse")
                if refs:
                    return [self.client.get_node(r.NodeId) for r in refs]
        except Exception:
            pass
        return []

    async def read_variable_details(self, node: Node) -> Optional[VariableRecord]:
        try:
            bname = await self.with_timeout(node.read_browse_name(), "read_browse_name")
            dname = await self.with_timeout(node.read_display_name(), "read_display_name")
            name = dname.Text if (dname and dname.Text) else (bname.Name if bname else "?")

            dv = await self.with_timeout(node.read_data_value(raise_on_bad_status=False), "read_data_value")
            if dv and dv.Value is not None:
                val = dv.Value.Value
                vtype = dv.Value.VariantType.name
                status = dv.StatusCode.name if dv.StatusCode else "Good"
            else:
                val = await self.with_timeout(node.read_value(), "read_value")
                vtype_enum = await self.with_timeout(node.read_data_type_as_variant_type(), "read_vtype")
                vtype = vtype_enum.name if vtype_enum else type(val).__name__
                status = "Good" if val is not None else "Uncertain"

            acc_set = await self.with_timeout(node.get_user_access_level(), "get_user_access_level")
            if acc_set is None:
                acc_set = await self.with_timeout(node.get_access_level(), "get_access_level")
            acc_str, writable = format_access_level(acc_set)

            return VariableRecord(
                node_id=nodeid_to_str(node.nodeid),
                ns=get_namespace(node.nodeid),
                name=name,
                vtype=vtype,
                value=val,
                status=status,
                access=acc_str,
                writable=writable,
            )
        except Exception as e:
            logger.debug(f"Failed reading variable details for {node}: {e}")
            return None

    async def write_smart_value(self, node_id_str: str, raw_value: str, explicit_type: str = "auto") -> Tuple[bool, Any]:
        """Single typed write, then good-status and equal typed readback observation."""
        if not await self.ensure_connected():
            raise ConnectionError("No OPC UA session; write not sent")
        node = self.client.get_node(node_id_str)
        if explicit_type != "auto":
            if explicit_type not in VARIANT_TYPE_MAP:
                raise ValueError("Unsupported explicit VariantType")
            vtype = VARIANT_TYPE_MAP[explicit_type]
        else:
            vtype = await self.with_timeout(node.read_data_type_as_variant_type(), "read_variant_type")
            if vtype is None or vtype == ua.VariantType.Null:
                raise ValueError("Cannot resolve node VariantType; write not sent")
            if vtype not in VARIANT_TYPE_MAP.values():
                raise ValueError("CLI writes support scalar built-in datatypes only")
        variant = cast_value_to_variant(raw_value, vtype)
        logger.warning(f"EXECUTING OT OPC UA WRITE - Node: {node_id_str}, VariantType: {vtype.name}, Value: {variant.Value}")
        # asyncua 2.0.1 checks the per-node StatusCode inside write_attribute.
        # A lost response is ambiguous: never issue a second write automatically.
        await asyncio.wait_for(node.write_attribute(ua.AttributeIds.Value, ua.DataValue(variant)), self.op_timeout)
        logger.info("[PROTOCOL_ACCEPTED] Write service returned Good; reading value")
        dv = await self.with_timeout(node.read_data_value(raise_on_bad_status=False), "verify_write")
        if dv is None or dv.Value is None or dv.StatusCode is None or not dv.StatusCode.is_good():
            logger.warning("[PROTOCOL_ACCEPTED] Readback unavailable or non-Good; match unverified")
            return False, None if dv is None or dv.Value is None else dv.Value.Value
        new_val = dv.Value.Value
        matched = dv.Value.VariantType == vtype and new_val == variant.Value
        if matched:
            logger.info("[READBACK_MATCHED] Good typed readback equals written value; physical effect unverified")
        else:
            logger.warning(f"[READBACK_OBSERVED] Value/type differs from write: {new_val!r}; match unverified")
        return matched, new_val


# --- 4. COMMAND EXECUTION FUNCTIONS ---
def print_variable_table(records: List[VariableRecord], title: str):
    print(f"\n{Color.CYAN}{Color.BOLD}--- {title} ({len(records)}) ---{Color.RESET}")
    if not records:
        print(f" {Color.YELLOW}No matching variables found.{Color.RESET}\n")
        return

    print(
        f" {'NODE ID':<24} | {'NS':<3} | {'NAME':<26} | "
        f"{'TYPE':<10} | {'VALUE':<26} | {'PERM':<6} | {'STATUS'}"
    )
    print(f" {'-'*24}-+-{'-'*3}-+-{'-'*26}-+-{'-'*10}-+-{'-'*26}-+-{'-'*6}-+-{'-'*12}")
    for r in records:
        perm_color = Color.GREEN if r.writable else Color.GREY
        st_color = Color.GREEN if "Good" in r.status else Color.YELLOW
        print(
            f" {Color.YELLOW}{r.node_id:<24}{Color.RESET} | "
            f"{r.ns:<3} | "
            f"{Color.BLUE}{r.name[:26]:<26}{Color.RESET} | "
            f"{r.vtype[:10]:<10} | "
            f"{Color.GREEN}{safe_str(r.value, 26):<26}{Color.RESET} | "
            f"{perm_color}{r.access:<6}{Color.RESET} | "
            f"{st_color}{r.status}{Color.RESET}"
        )
    print()

async def do_endpoints(uaclient: IndustrialOPCUAClient):
    try:
        endpoints = await uaclient.discover_endpoints()
    except Exception:
        return False
    print(f"\n{Color.CYAN}{Color.BOLD}--- OPC UA SERVER ENDPOINTS DISCOVERY ---{Color.RESET}")
    if not endpoints:
        print(f" {Color.YELLOW}No endpoints returned by server.{Color.RESET}\n")
        return

    for idx, ep in enumerate(endpoints, 1):
        pol, mod, lvl, tokens = uaclient.parse_endpoint_security(ep)
        ep_url = display_url(getattr(ep, "EndpointUrl", uaclient.url))
        app_uri = getattr(ep.Server, "ApplicationUri", "N/A") if getattr(ep, "Server", None) else "N/A"
        pol_color = Color.GREEN if pol != "None" else Color.YELLOW
        print(f" {Color.BOLD}[Endpoint #{idx}]{Color.RESET} {Color.CYAN}{ep_url}{Color.RESET}")
        print(f"   - {Color.BLUE}Application URI:{Color.RESET} {app_uri}")
        print(f"   - {Color.BLUE}Security Policy:{Color.RESET} {pol_color}{pol}{Color.RESET}")
        print(f"   - {Color.BLUE}Security Mode:{Color.RESET}   {pol_color}{mod}{Color.RESET} (Level: {lvl})")
        print(f"   - {Color.BLUE}Identity Tokens:{Color.RESET} {', '.join(tokens) if tokens else 'Anonymous'}\n")

async def do_info(uaclient: IndustrialOPCUAClient):
    print(f"\n{Color.CYAN}{Color.BOLD}--- OPC UA SERVER STATUS & FINGERPRINT ---{Color.RESET}")
    ns_ok = status_ok = False
    try:
        ns_array = await asyncio.wait_for(uaclient.client.get_namespace_array(), timeout=uaclient.op_timeout)
        ns_ok = True
    except Exception as e:
        logger.warning(f"[INFO PARTIAL] Namespace information unavailable: {type(e).__name__}")
        ns_array = []

    # Read ServerStatus independently; a successful empty namespace array is valid.
    try:
        status_node = uaclient.client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerStatus))
        srv_status = await asyncio.wait_for(status_node.read_value(), timeout=uaclient.op_timeout)
        status_ok = True
    except Exception as e:
        logger.warning(f"[INFO PARTIAL] ServerStatus unavailable: {type(e).__name__}")
        srv_status = None

    if srv_status:
        build = getattr(srv_status, "BuildInfo", None)
        if build:
            print(f"  {Color.BLUE}Product Name:{Color.RESET}      {getattr(build, 'ProductName', 'N/A')}")
            print(f"  {Color.BLUE}Manufacturer:{Color.RESET}      {getattr(build, 'ManufacturerName', 'N/A')}")
            print(f"  {Color.BLUE}Software Version:{Color.RESET}  {getattr(build, 'SoftwareVersion', 'N/A')}")
            print(f"  {Color.BLUE}Build Number:{Color.RESET}      {getattr(build, 'BuildNumber', 'N/A')}")
            print(f"  {Color.BLUE}Product URI:{Color.RESET}       {getattr(build, 'ProductUri', 'N/A')}")
        state_val = getattr(srv_status, "State", "N/A")
        print(f"  {Color.BLUE}Server State:{Color.RESET}      {Color.GREEN}{state_val}{Color.RESET}")
        print(f"  {Color.BLUE}Start Time (UTC):{Color.RESET}  {getattr(srv_status, 'StartTime', 'N/A')}")
        print(f"  {Color.BLUE}Current Time (UTC):{Color.RESET}{getattr(srv_status, 'CurrentTime', 'N/A')}")

    if ns_array:
        print(f"\n {Color.BOLD}Registered Namespaces ({len(ns_array)}):{Color.RESET}")
        for idx, ns_uri in enumerate(ns_array):
            print(f"   [{Color.YELLOW}ns={idx}{Color.RESET}] {ns_uri}")
    print()
    if not (ns_ok or status_ok):
        logger.error("[INFO ERROR] Both namespace information and ServerStatus operations failed.")
        return False
    return True

async def do_browse(uaclient: IndustrialOPCUAClient, args):
    start_nid = args.node_id or "i=85"  # Default: Objects folder (i=85)
    print(f"\n{Color.CYAN}{Color.BOLD}--- OPC UA ADDRESS SPACE BROWSER (Root: {start_nid}, Max Depth: {args.max_depth}) ---{Color.RESET}")
    visited: Set[str] = set()

    async def _tree_walk(node: Node, depth: int, prefix: str):
        if depth > args.max_depth:
            return
        nid_str = nodeid_to_str(node.nodeid)
        if nid_str in visited:
            return
        visited.add(nid_str)

        nclass = await uaclient.with_timeout(node.read_node_class(), "read_node_class", strict=(depth == 0))
        dname = await uaclient.with_timeout(node.read_display_name(), "read_display_name")
        bname = await uaclient.with_timeout(node.read_browse_name(), "read_browse_name")
        label = dname.Text if (dname and dname.Text) else (bname.Name if bname else nid_str)
        cname = NODE_CLASS_NAMES.get(nclass, str(nclass))

        extra = ""
        if nclass == ua.NodeClass.Variable:
            rec = await uaclient.read_variable_details(node)
            if rec:
                extra = f" = {Color.GREEN}{safe_str(rec.value, 35)}{Color.RESET} [{rec.vtype} | {rec.access}]"

        c_color = Color.BLUE if nclass == ua.NodeClass.Object else (Color.YELLOW if nclass == ua.NodeClass.Variable else Color.CYAN)
        print(f"{prefix}├── {c_color}[{cname}]{Color.RESET} {Color.BOLD}{label}{Color.RESET} ({Color.GREY}{nid_str}{Color.RESET}){extra}")

        if depth < args.max_depth:
            children = await uaclient.safe_get_children(node)
            for child in children:
                await _tree_walk(child, depth + 1, prefix + "│   ")

    root_node = uaclient.client.get_node(start_nid)
    await _tree_walk(root_node, 0, " ")
    print()

async def do_enum(uaclient: IndustrialOPCUAClient, args) -> List[VariableRecord]:
    start_nid = args.node_id or "i=85"
    ns_desc = f"ns={args.ns}" if args.ns is not None else "ALL Namespaces"
    logger.info(
        f"Enumerating variables from '{start_nid}' (Filter: {ns_desc}, "
        f"Max Depth: {args.max_depth}, Max Nodes: {args.max_nodes})..."
    )

    variables: List[VariableRecord] = []
    visited: Set[str] = set()
    nodes_processed = 0

    async def _walk(node: Node, depth: int):
        nonlocal nodes_processed
        if nodes_processed >= args.max_nodes or depth > args.max_depth:
            return

        await uaclient.ensure_connected()
        nid_str = nodeid_to_str(node.nodeid)
        if nid_str in visited:
            return
        visited.add(nid_str)
        nodes_processed += 1

        nclass = await uaclient.with_timeout(node.read_node_class(), "read_node_class", strict=(depth == 0))
        if nclass == ua.NodeClass.Variable:
            node_ns = get_namespace(node.nodeid)
            if args.ns is None or node_ns == args.ns:
                rec = await uaclient.read_variable_details(node)
                if rec and (not args.writable_only or rec.writable):
                    variables.append(rec)
                    logger.debug(f"Found Variable: {rec.node_id} ({rec.name}) = {rec.value} [{rec.access}]")

        children = await uaclient.safe_get_children(node)
        for child in children:
            if nodes_processed >= args.max_nodes:
                break
            await _walk(child, depth + 1)

    root = uaclient.client.get_node(start_nid)
    await _walk(root, 0)

    title = "WRITABLE OPC UA VARIABLES" if args.writable_only else "DISCOVERED OPC UA VARIABLES"
    print_variable_table(variables, title)
    return variables

async def do_inspect(uaclient: IndustrialOPCUAClient, args):
    node = uaclient.client.get_node(args.node_id)
    print(f"\n{Color.CYAN}{Color.BOLD}--- UAEXPERT ATTRIBUTE INSPECTOR ({args.node_id}) ---{Color.RESET}")

    nclass = await uaclient.with_timeout(node.read_node_class(), "NodeClass", strict=True)
    bname = await uaclient.with_timeout(node.read_browse_name(), "BrowseName")
    dname = await uaclient.with_timeout(node.read_display_name(), "DisplayName")
    desc = await uaclient.with_timeout(node.read_description(), "Description")

    print(f"  {Color.BLUE}NodeId:{Color.RESET}                  {Color.YELLOW}{nodeid_to_str(node.nodeid)}{Color.RESET}")
    print(f"  {Color.BLUE}Namespace Index:{Color.RESET}         {get_namespace(node.nodeid)}")
    print(f"  {Color.BLUE}NodeClass:{Color.RESET}               {NODE_CLASS_NAMES.get(nclass, str(nclass))}")
    print(f"  {Color.BLUE}BrowseName:{Color.RESET}              {bname.to_string() if bname else 'N/A'}")
    print(f"  {Color.BLUE}DisplayName:{Color.RESET}             {dname.Text if dname else 'N/A'}")
    print(f"  {Color.BLUE}Description:{Color.RESET}             {desc.Text if (desc and desc.Text) else 'N/A'}")

    if nclass == ua.NodeClass.Variable:
        dv = await uaclient.with_timeout(node.read_data_value(raise_on_bad_status=False), "DataValue")
        vtype = await uaclient.with_timeout(node.read_data_type_as_variant_type(), "VariantType")
        vrank = await uaclient.with_timeout(node.read_value_rank(), "ValueRank")
        acc = await uaclient.with_timeout(node.get_access_level(), "AccessLevel")
        uacc = await uaclient.with_timeout(node.get_user_access_level(), "UserAccessLevel")
        hist = await uaclient.with_timeout(node.read_attribute(ua.AttributeIds.Historizing), "Historizing")
        min_samp = await uaclient.with_timeout(node.read_attribute(ua.AttributeIds.MinimumSamplingInterval), "MinSampling")

        acc_str, _ = format_access_level(acc)
        uacc_str, _ = format_access_level(uacc)
        hist_val = hist.Value.Value if (hist and hist.Value) else False
        ms_val = min_samp.Value.Value if (min_samp and min_samp.Value) else "N/A"

        print(f"  {Color.BLUE}Variant Type:{Color.RESET}            {Color.CYAN}{vtype.name if vtype else 'Unknown'}{Color.RESET}")
        print(f"  {Color.BLUE}ValueRank:{Color.RESET}               {vrank} ({'Scalar' if vrank == -1 else 'Array'})")
        print(f"  {Color.BLUE}AccessLevel:{Color.RESET}             {acc_str} ({acc})")
        print(f"  {Color.BLUE}UserAccessLevel:{Color.RESET}         {uacc_str} ({uacc})")
        print(f"  {Color.BLUE}MinimumSamplingInterval:{Color.RESET} {ms_val} ms")
        print(f"  {Color.BLUE}Historizing:{Color.RESET}             {hist_val}")
        if dv:
            print(f"  {Color.BLUE}Current Value:{Color.RESET}           {Color.GREEN}{Color.BOLD}{safe_str(dv.Value.Value if dv.Value else None, 100)}{Color.RESET}")
            print(f"  {Color.BLUE}StatusCode:{Color.RESET}              {Color.GREEN if dv.StatusCode.is_good() else Color.YELLOW}{dv.StatusCode.name} (0x{dv.StatusCode.value:08X}){Color.RESET}")
            print(f"  {Color.BLUE}SourceTimestamp:{Color.RESET}         {dv.SourceTimestamp}")
            print(f"  {Color.BLUE}ServerTimestamp:{Color.RESET}         {dv.ServerTimestamp}")

    elif nclass == ua.NodeClass.Method:
        children = await uaclient.safe_get_children(node)
        for ch in children:
            ch_bname = await uaclient.with_timeout(ch.read_browse_name(), "MethodArgBrowse")
            if ch_bname and ch_bname.Name in ("InputArguments", "OutputArguments"):
                arg_list = await uaclient.with_timeout(ch.read_value(), "MethodArgVal") or []
                print(f"  {Color.BLUE}{ch_bname.Name}:{Color.RESET}")
                for a in arg_list:
                    print(f"    - {Color.YELLOW}{getattr(a, 'Name', '?')}{Color.RESET} (DataType: {getattr(a, 'DataType', '?')})")
    print()

async def do_read(uaclient: IndustrialOPCUAClient, args):
    target_ids = args.nodes if args.nodes else ([args.node_id] if args.node_id else [])
    records: List[VariableRecord] = []
    for nid in target_ids:
        node = uaclient.client.get_node(nid)
        rec = await uaclient.read_variable_details(node)
        if rec:
            records.append(rec)
        else:
            logger.error(f"Could not read NodeId '{nid}'.")
    print_variable_table(records, "OPC UA READ RESULTS")
    return len(records) == len(target_ids) and all(rec.status.startswith("Good") for rec in records)

async def do_write(uaclient: IndustrialOPCUAClient, args):
    try:
        ok, new_val = await uaclient.write_smart_value(args.node_id, args.value, args.type)
        if ok:
            print(f"\n{Color.GREEN}{Color.BOLD}[SUCCESS]{Color.RESET} Value written to {Color.YELLOW}{args.node_id}{Color.RESET}")
            print(f" {Color.BOLD}Verified Readback Value:{Color.RESET} {Color.GREEN}{new_val}{Color.RESET} (Python type: {type(new_val).__name__})\n")
        return ok
    except (asyncio.TimeoutError, ConnectionError, OSError) as e:
        logger.error(f"[INDETERMINATE] Write response unavailable for {args.node_id}; no retry: {e}")
        return False
    except ValueError as e:
        logger.error(f"[LOCAL_ERROR] Write not sent to {args.node_id}: {e}")
        return False
    except Exception as e:
        logger.error(f"[WRITE FAILED] Server rejected write to {args.node_id}: {e}")
        return False

async def do_watch(uaclient: IndustrialOPCUAClient, args):
    target_ids = args.nodes if args.nodes else ([args.node_id] if args.node_id else [])
    logger.info(f"Creating OPC UA DataChange Subscription (Publishing Interval: {args.wait} ms)...")
    print(f"{Color.GREY}Subscribed to {len(target_ids)} node(s) | Press Ctrl+C to stop.{Color.RESET}\n")

    handler = SubscriptionHandler()
    sub = None
    handles = []
    subscribed_client = None

    try:
        while True:
            if subscribed_client is not uaclient.client:
                if sub is not None:
                    try:
                        await sub.delete()
                    except Exception:
                        pass
                sub = await uaclient.client.create_subscription(args.wait, handler)
                nodes_to_sub = [uaclient.client.get_node(nid) for nid in target_ids]
                handles = await sub.subscribe_data_change(nodes_to_sub)
                for handle in handles:
                    if isinstance(handle, ua.StatusCode):
                        handle.check()
                subscribed_client = uaclient.client
            await asyncio.sleep(1.0)
            if not await uaclient.ensure_connected():
                logger.error("Subscription session lost; reconnect failed")
                return False
    except asyncio.CancelledError:
        pass
    finally:
        if sub is not None:
            try:
                await sub.unsubscribe(handles)
            except (OSError, ua.UaStatusCodeError):
                logger.warning("Subscription unsubscribe cleanup failed", exc_info=True)
            try:
                await sub.delete()
            except (OSError, ua.UaStatusCodeError):
                logger.warning("Subscription delete cleanup failed", exc_info=True)

async def do_call(uaclient: IndustrialOPCUAClient, args):
    parent_id = args.node_id or "i=85"
    parent_node = uaclient.client.get_node(parent_id)
    method_node = uaclient.client.get_node(args.method_id)

    # Inspect InputArguments on the Method node if present to auto-cast CLI arguments
    typed_args: List[ua.Variant] = []
    input_arg_defs = []
    for ch in await uaclient.safe_get_children(method_node):
        bname = await uaclient.with_timeout(ch.read_browse_name(), "read_browse_name")
        if bname and bname.Name == "InputArguments":
            input_arg_defs = await uaclient.with_timeout(ch.read_value(), "read_input_args") or []
            break

    raw_call_args = args.call_args or []
    for idx, raw_a in enumerate(raw_call_args):
        if idx < len(input_arg_defs):
            dt_node_id = getattr(input_arg_defs[idx], "DataType", None)
            if dt_node_id and hasattr(dt_node_id, "Identifier") and isinstance(dt_node_id.Identifier, int):
                if getattr(dt_node_id, "NamespaceIndex", 0) != 0:
                    logger.error("[LOCAL_ERROR] Method custom DataType requires explicit encoding; call not sent")
                    return False
                try:
                    vtype = ua.VariantType(dt_node_id.Identifier)
                    typed_args.append(cast_value_to_variant(raw_a, vtype))
                    continue
                except (ValueError, OverflowError) as e:
                    logger.error(f"[LOCAL_ERROR] Invalid method argument {idx}: {e}; call not sent")
                    return False
        # Fallback heuristic parsing
        if raw_a.lower() in ("true", "false"):
            typed_args.append(ua.Variant(raw_a.lower() == "true", ua.VariantType.Boolean))
        else:
            try:
                typed_args.append(ua.Variant(int(raw_a, 0), ua.VariantType.Int32))
            except ValueError:
                try:
                    typed_args.append(ua.Variant(float(raw_a), ua.VariantType.Double))
                except ValueError:
                    typed_args.append(ua.Variant(raw_a, ua.VariantType.String))

    logger.warning(f"EXECUTING OT OPC UA METHOD CALL - Object: {parent_id}, Method: {args.method_id}, Args: {raw_call_args}")
    try:
        res = await parent_node.call_method(method_node.nodeid, *typed_args)
        print(f"\n{Color.GREEN}{Color.BOLD}[PROTOCOL_COMPLETED]{Color.RESET} Method {Color.YELLOW}{args.method_id}{Color.RESET} returned Good; physical effect unverified.")
        print(f" {Color.BOLD}Return Output:{Color.RESET} {Color.CYAN}{res}{Color.RESET}\n")
        return True
    except (asyncio.TimeoutError, ConnectionError, OSError) as e:
        logger.error(f"[INDETERMINATE] Method result unavailable; no retry: {e}")
        return False
    except Exception as e:
        logger.error(f"[METHOD CALL ERROR] Failed executing {args.method_id}: {e}")
        return False

async def do_history(uaclient: IndustrialOPCUAClient, args):
    node = uaclient.client.get_node(args.node_id)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=args.minutes)
    logger.info(f"Reading Historical Data for {args.node_id} (Last {args.minutes} minutes)...")

    try:
        dv_list = await node.read_raw_history(starttime=start_time, endtime=end_time, numvalues=args.max_nodes)
        print(f"\n{Color.CYAN}{Color.BOLD}--- HISTORICAL DATA ({args.node_id}) ---{Color.RESET}")
        if not dv_list:
            print(f" {Color.YELLOW}No historical records returned.{Color.RESET}\n")
            return True
        for dv in dv_list:
            ts_str = dv.SourceTimestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if dv.SourceTimestamp else "N/A"
            val = dv.Value.Value if dv.Value else None
            st = dv.StatusCode.name if dv.StatusCode else "Good"
            print(f" [{Color.GREY}{ts_str}{Color.RESET}] -> {Color.GREEN}{val}{Color.RESET} ({st})")
        print()
        return all(dv.StatusCode is not None and dv.StatusCode.is_good() for dv in dv_list)
    except Exception as e:
        logger.error(f"[HISTORY ERROR] Server does not support HistoryRead on {args.node_id} or failed: {e}")
        return False

async def do_interactive_shell(uaclient: IndustrialOPCUAClient, args):
    """Interactive UAExpert-style console preserving the active OPC UA Session."""
    print(f"\n{Color.CYAN}{Color.BOLD}=== OPC UA INTERACTIVE MAINTENANCE SHELL ==={Color.RESET}")
    print(f"Type {Color.YELLOW}help{Color.RESET} to list available commands, or {Color.YELLOW}exit{Color.RESET} to disconnect.\n")

    cached_vars: List[VariableRecord] = []

    while True:
        try:
            cmd_line = await asyncio.to_thread(input, f"{Color.GREEN}opcua>{Color.RESET} ")
        except EOFError:
            break
        cmd_line = cmd_line.strip()
        if not cmd_line:
            continue

        parts = cmd_line.split()
        action = parts[0].lower()

        if action in ("exit", "quit", "q"):
            break
        elif action == "help":
            print(f"  {Color.YELLOW}info{Color.RESET}                         - Show Server Status & Namespaces")
            print(f"  {Color.YELLOW}enum [ns]{Color.RESET}                    - Enumerate all variables (optional namespace index)")
            print(f"  {Color.YELLOW}writable{Color.RESET}                     - List writable variables from last enumeration")
            print(f"  {Color.YELLOW}browse [NodeId] [depth]{Color.RESET}      - Browse Address Space tree (default i=85, depth 2)")
            print(f"  {Color.YELLOW}inspect <NodeId>{Color.RESET}             - Inspect all attributes of a NodeId")
            print(f"  {Color.YELLOW}read <NodeId>{Color.RESET}                - Read current value of a NodeId")
            print(f"  {Color.YELLOW}write <NodeId> <Val> [type]{Color.RESET}  - Smart-write value to NodeId")
            print(f"  {Color.YELLOW}call <ObjId> <MethId> [args]{Color.RESET} - Execute a Method on an Object Node")
            print(f"  {Color.YELLOW}exit{Color.RESET}                         - Close session and exit")
        elif action == "info":
            await do_info(uaclient)
        elif action == "enum":
            try:
                ns = int(parts[1]) if len(parts) > 1 else args.ns
                if ns is not None and not 0 <= ns <= 65535:
                    raise ValueError
            except ValueError:
                print(f"{Color.RED}[INPUT ERROR] enum namespace must be an integer in 0..65535.{Color.RESET}")
                continue
            args.ns = ns
            args.writable_only = False
            cached_vars = await do_enum(uaclient, args)
        elif action == "writable":
            if not cached_vars:
                args.writable_only = True
                cached_vars = await do_enum(uaclient, args)
            else:
                w_list = [v for v in cached_vars if v.writable]
                print_variable_table(w_list, "WRITABLE OPC UA VARIABLES")
        elif action == "browse":
            try:
                max_depth = int(parts[2]) if len(parts) > 2 else 2
                if max_depth < 0:
                    raise ValueError
            except ValueError:
                print(f"{Color.RED}[INPUT ERROR] browse depth must be an integer >= 0.{Color.RESET}")
                continue
            args.node_id = parts[1] if len(parts) > 1 else "i=85"
            args.max_depth = max_depth
            await do_browse(uaclient, args)
        elif action == "inspect" and len(parts) >= 2:
            args.node_id = parts[1]
            await do_inspect(uaclient, args)
        elif action == "read" and len(parts) >= 2:
            args.nodes = parts[1:]
            await do_read(uaclient, args)
        elif action == "write" and len(parts) >= 3:
            args.node_id = parts[1]
            args.value = parts[2]
            args.type = parts[3].lower() if len(parts) > 3 else "auto"
            await do_write(uaclient, args)
        elif action == "call" and len(parts) >= 3:
            args.node_id = parts[1]
            args.method_id = parts[2]
            args.call_args = parts[3:]
            await do_call(uaclient, args)
        else:
            print(f"{Color.RED}[!] Unknown command or missing arguments. Type 'help' for syntax.{Color.RESET}")


# --- 5. MAIN ENTRY POINT ---
def parse_args():
    desc_text = f"{Color.BOLD}OPC UA Master CLI - UAExpert Lightweight Alternative (by z4y_d3n){Color.RESET}\n"
    custom_usage = (
        f"{Color.GREEN}opcua_master.py{Color.RESET} "
        f"{Color.YELLOW}[-U URL | -H HOST] [-c COMMAND] [--ns NS] [-n NODE_ID] "
        f"[-v VALUE] [-t TYPE] [--policy POLICY] [--mode MODE] [-u USER] [-P PASS]{Color.RESET}"
    )

    parser = CustomArgumentParser(description=desc_text, usage=custom_usage, formatter_class=ColoredHelpFormatter)

    conn_group = parser.add_argument_group(f"{Color.CYAN}Target & Connection Options{Color.RESET}")
    conn_group.add_argument("-U", "--url", type=str, help="Full OPC UA Server URL (e.g., opc.tcp://192.168.1.50:4840).")
    conn_group.add_argument("-H", "--host", type=str, help="Target IP/Hostname (Alternative to -U; builds opc.tcp://HOST:PORT).")
    conn_group.add_argument("-p", "--port", type=int, default=4840, help="TCP Port when using -H (Default: 4840).")
    conn_group.add_argument("-c", "--command", required=True, choices=[
        "endpoints", "info", "browse", "enum", "inspect", "read", "write", "watch", "call", "history", "shell"
    ], help="OPC UA action to execute.")
    conn_group.add_argument("--timeout", type=float, default=15.0, help="Session timeout in seconds (Default: 15.0).")
    conn_group.add_argument("--op-timeout", type=float, default=8.0, help="Individual node operation timeout (Default: 8.0).")
    conn_group.add_argument("--debug", action="store_true", help="Enable DEBUG logs.")

    sec_group = parser.add_argument_group(f"{Color.CYAN}Security, PKI & Authentication Options{Color.RESET}")
    sec_group.add_argument("--policy", choices=[
        "auto", "None", "Basic256Sha256", "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss", "Basic256", "Basic128Rsa15"
    ], default="auto", help="OPC UA Security Policy (Default: auto).")
    sec_group.add_argument("--mode", choices=["auto", "None", "Sign", "SignAndEncrypt"], default="auto", help="Message Security Mode (Default: auto).")
    sec_group.add_argument("-u", "--user", type=str, help="Username for UserNameIdentityToken authentication.")
    sec_group.add_argument("-P", "--password", type=str, help="Password for UserNameIdentityToken authentication.")
    sec_group.add_argument("--cert", type=Path, default=CLIENT_CERT, help=f"Client DER certificate path (Default: {CLIENT_CERT}).")
    sec_group.add_argument("--key", type=Path, default=CLIENT_KEY, help=f"Client PEM private key path (Default: {CLIENT_KEY}).")
    sec_group.add_argument("--app-uri", type=str, default=DEFAULT_APP_URI, help=f"Client Application URI (Default: {DEFAULT_APP_URI}).")

    node_group = parser.add_argument_group(f"{Color.CYAN}Address Space & Node Options{Color.RESET}")
    node_group.add_argument("-n", "--node-id", type=str, help="Target NodeId (e.g., 'ns=2;s=Channel1.Device1.Tag1' or 'ns=2;i=1001').")
    node_group.add_argument("--nodes", nargs='+', metavar="NODE_ID", help="Multiple NodeIds separated by space (for 'read' or 'watch').")
    node_group.add_argument("--ns", type=int, default=None, help="Namespace Index filter for 'enum' (Default: All namespaces).")
    node_group.add_argument("--writable-only", action="store_true", help="Filter only writable variables during 'enum'.")
    node_group.add_argument("--max-depth", type=int, default=4, help="Maximum recursion depth for 'browse' and 'enum' (Default: 4).")
    node_group.add_argument("--max-nodes", type=int, default=2000, help="Maximum nodes to inspect during 'enum' or 'history' (Default: 2000).")

    data_group = parser.add_argument_group(f"{Color.CYAN}Write, Method Call, Watch & History Options{Color.RESET}")
    data_group.add_argument("-v", "--value", type=str, help="Value to write (-c write).")
    data_group.add_argument("-t", "--type", choices=["auto"] + list(VARIANT_TYPE_MAP.keys()), default="auto", help="Explicit VariantType for 'write' (Default: auto-detect from PLC).")
    data_group.add_argument("-M", "--method-id", type=str, help="Method NodeId to execute (-c call).")
    data_group.add_argument("-a", "--call-args", nargs='*', metavar="ARG", help="Arguments for Method execution (-c call).")
    data_group.add_argument("-w", "--wait", type=float, default=500.0, help="Subscription publishing interval in ms for 'watch' (Default: 500.0).")
    data_group.add_argument("--minutes", type=int, default=60, help="Lookback window in minutes for 'history' (Default: 60).")

    if len(sys.argv) == 1:
        parser.print_usage()
        sys.exit(1)

    parser.usage = argparse.SUPPRESS
    args = parser.parse_args()

    # Build Target URL
    if not args.url and not args.host:
        parser.error("Either -U / --url or -H / --host is required.")
    target_url = args.url if args.url else f"opc.tcp://{args.host}:{args.port}"

    # Command-specific validations
    if args.command == "inspect" and not args.node_id:
        parser.error("Argument -n / --node-id is required for 'inspect'.")
    if args.command in ("read", "watch") and not (args.node_id or args.nodes):
        parser.error(f"Argument -n / --node-id or --nodes is required for '{args.command}'.")
    if args.command == "write" and (not args.node_id or args.value is None):
        parser.error("Arguments -n / --node-id and -v / --value are strictly required for 'write'.")
    if args.command == "call" and not args.method_id:
        parser.error("Argument -M / --method-id is required for 'call'.")
    if args.command == "history" and not args.node_id:
        parser.error("Argument -n / --node-id is required for 'history'.")

    if not 1 <= args.port <= 65535 or not 0 < args.timeout < float('inf') or not 0 < args.op_timeout < float('inf'):
        parser.error("Port and timeouts must be within valid positive ranges.")
    if args.max_depth < 0 or args.max_nodes < 1 or not 0 < args.wait < float('inf') or args.minutes < 0:
        parser.error("Invalid depth, node limit, subscription interval, or history window.")
    if args.ns is not None and not 0 <= args.ns <= 65535:
        parser.error("Namespace index must be 0..65535.")
    if args.password is not None and not args.user:
        parser.error("Password requires a username.")
    return args, target_url


async def async_main(args=None, target_url=None):
    if args is None:
        args, target_url = parse_args()
    setup_logger(args.debug)

    uaclient = IndustrialOPCUAClient(
        url=target_url,
        timeout=args.timeout,
        op_timeout=args.op_timeout,
        sec_policy=args.policy,
        sec_mode=args.mode,
        username=args.user,
        password=args.password,
        cert_path=args.cert,
        key_path=args.key,
        app_uri=args.app_uri,
    )

    if args.command == "endpoints":
        if await do_endpoints(uaclient) is False:
            sys.exit(1)
        return

    if not await uaclient.connect():
        sys.exit(1)

    print(
        f"{Color.GREEN}{Color.BOLD}[CONNECTED]{Color.RESET} {Color.CYAN}{display_url(target_url)}{Color.RESET} | "
        f"Security: {Color.BLUE}{uaclient.active_policy}/{uaclient.active_mode}{Color.RESET} | "
        f"Command: {Color.YELLOW}{args.command.upper()}{Color.RESET}\n"
    )

    result = None
    try:
        if args.command == "info":
            result = await do_info(uaclient)
        elif args.command in ("browse", "enum", "inspect"):
            try:
                if args.command == "browse":
                    await do_browse(uaclient, args)
                elif args.command == "enum":
                    await do_enum(uaclient, args)
                else:
                    await do_inspect(uaclient, args)
            except Exception:
                result = False
        elif args.command == "read":
            result = await do_read(uaclient, args)
        elif args.command == "write":
            result = await do_write(uaclient, args)
        elif args.command == "watch":
            result = await do_watch(uaclient, args)
        elif args.command == "call":
            result = await do_call(uaclient, args)
        elif args.command == "history":
            result = await do_history(uaclient, args)
        elif args.command == "shell":
            await do_interactive_shell(uaclient, args)
        if result is False:
            sys.exit(1)
    finally:
        await uaclient.disconnect()

if __name__ == "__main__":
    try:
        cli_args, cli_url = parse_args()
        asyncio.run(async_main(cli_args, cli_url))
    except KeyboardInterrupt:
        print("\n\033[93m[WARNING] Execution cancelled by user (Ctrl+C). Exiting cleanly...\033[0m")
        sys.exit(0)
