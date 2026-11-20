"""Independent binary oracles used only with buffers and offline doubles.

The named read literals come from the approved Gate 1 and 1.1 handoffs.
See ORACLES.md for field offsets, provenance and limits of the evidence.
"""

ETHERNET = bytes.fromhex("ffffffffffff 020000000003 88a4")
FPRD_REQUEST = bytes.fromhex(
    "ffffffffffff 020000000001 88a4 0e10 0427 3412 0001 0200 0000 0000 0000"
)
APRD_REQUEST = bytes.fromhex(
    "ffffffffffff 020000000001 88a4 0d10 0139 0000 0000 0100 0000 00 0000"
)
FPRD_RETURN = bytes.fromhex(
    "ffffffffffff 020000000003 88a4 0e10 0427 3412 0001 0240 3402 a55a 0100"
)
APRD_RETURN = bytes.fromhex(
    "ffffffffffff 020000000003 88a4 0d10 0139 0100 0000 0140 4000 11 0100"
)
BOUND_MAC = bytes.fromhex("02123456789a")
NATIVE_REQUEST = bytes.fromhex(
    "ffffffffffff 02123456789a 88a4 0d10 0139 0000 0000 0100 0000 00 0000"
) + bytes(31)
NATIVE_RETURN = bytes.fromhex(
    "ffffffffffff 020000000003 88a4 0d10 0139 0100 0000 0140 4000 12 0100"
)
MIN_FRAME = ETHERNET + bytes.fromhex("0c10 002a 0000 0000 0000 0000 0000")
# Gate 1 SM-02 included a known logical command and an unknown command.
CHAINED = bytes.fromhex(
    "001122334455 66778899aabb 88a4 1910 0a7e 78563412 01c0 efbe aa 3412"
    " e17f 11223344 0000 b0a0 7856"
)


def replace_field(data, offset, value):
    return data[:offset] + value + data[offset + len(value):]


def wrap_chain(chain):
    """Enclose a test chain in Ethernet II and a little-endian Type 1 header."""
    return ETHERNET + (0x1000 + len(chain)).to_bytes(2, "little") + chain


def nop_chain(count):
    continued = bytes.fromhex("0000 0000 0000 0080 0000 0000")
    last = bytes.fromhex("0000 0000 0000 0000 0000 0000")
    return continued * (count - 1) + last


def single_payload(payload):
    return wrap_chain(bytes.fromhex("0408 3412 0001") + len(payload).to_bytes(2, "little")
                      + bytes.fromhex("3412") + payload + bytes.fromhex("7856"))
