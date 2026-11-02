#!/usr/bin/env python3
"""Read-only byte provenance, UTF-8 and syntax checks; no client imports."""

import argparse
import ast
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "modbus_master.py", "s7comm_master.py", "enip_master.py",
    "profinet_master.py", "iec104_master.py", "bacnet_master.py",
    "opcua_master.py", "mqtt_spb_master.py", "dnp3_master.py",
)
ROW = re.compile(r"\| `([a-z0-9_]+\.py)` \| ([0-9a-f]{64}) \| ([1-9][0-9]*) \| (CRLF|LF) \|")


def parse_manifest(text):
    """Reject missing, extra, malformed and duplicate provenance rows."""
    records = {}
    for line in text.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        if line in ("| Script | SHA-256 | Bytes | EOL |", "| --- | --- | --- | --- |"):
            continue
        match = ROW.fullmatch(line)
        if not match:
            raise ValueError(f"Malformed provenance row: {line!r}")
        name, digest, size, eol = match.groups()
        if name.casefold() in {key.casefold() for key in records}:
            raise ValueError(f"Duplicate provenance path: {name}")
        records[name] = (digest, int(size), eol)
    if set(records) != set(SOURCES):
        raise ValueError(f"Provenance paths differ: missing={sorted(set(SOURCES) - records.keys())}, "
                         f"extra={sorted(records.keys() - set(SOURCES))}")
    return records


def line_endings(raw):
    crlf = raw.count(b"\r\n")
    lf = raw.count(b"\n") - crlf
    cr = raw.count(b"\r") - crlf
    return crlf, lf, cr


def check_bytes(name, raw, expected):
    digest, size, eol = expected
    actual = hashlib.sha256(raw).hexdigest()
    crlf, lf, cr = line_endings(raw)
    detail = f"{name}: SHA256={actual} bytes={len(raw)} CRLF={crlf} LF={lf} CR={cr}"
    if actual != digest or len(raw) != size:
        raise ValueError(f"{detail}; identity mismatch (expected SHA256={digest}, bytes={size}). "
                         "Investigate source edits; update provenance only after review.")
    if cr or (eol == "LF" and crlf) or (eol == "CRLF" and lf):
        raise ValueError(f"{detail}; expected {eol} line endings")
    source = raw.decode("utf-8", errors="strict")
    tree = ast.parse(source, filename=name)
    compile(tree, name, "exec", dont_inherit=True)
    return detail + "; UTF8/AST/compile PASS"


def check_root(root):
    records = parse_manifest((root / "SOURCE_SHA256.md").read_text(encoding="utf-8"))
    # Inspect actual directory entries: Path.exists alone hides case aliases on Windows.
    entries = list(root.iterdir())
    for name in SOURCES:
        aliases = [p.name for p in entries if p.name.casefold() == name.casefold()]
        if aliases != [name]:
            raise ValueError(f"Missing, noncanonical or case-colliding path {name}: {aliases}")
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Expected a regular root source file: {name}")
        print(check_bytes(name, path.read_bytes(), records[name]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="Source/provenance root (default: checkout)")
    args = parser.parse_args()
    try:
        check_root(args.root.resolve())
    except (OSError, UnicodeError, SyntaxError, ValueError) as exc:
        print(f"SOURCE CHECK FAILED: {exc}", file=sys.stderr)
        return 1
    print("SOURCE CHECK PASS: nine immutable snapshots; no files written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
