# Another-ICS-scripts

[![Portability CI on main](https://github.com/z4y-d3n/Another-ICS-scripts/actions/workflows/portability.yml/badge.svg?branch=main)](https://github.com/z4y-d3n/Another-ICS-scripts/actions/workflows/portability.yml)
[![CPython CI-tested versions: 3.12, 3.13, 3.14](https://img.shields.io/badge/CPython%20CI--tested-3.12%20%7C%203.13%20%7C%203.14-3776AB)](#testing-and-evidence)

Another set of ICS scripts, intentionally simple: nine independent, self-contained,
monolithic Python master clients for exploring, interacting with and testing
industrial protocols in explicitly authorized environments. Each file is its own
CLI application; download the script you need and run it directly. This is a
collection of scripts, not an installable framework or OT-ArchGuard.

| Script | Protocol |
| --- | --- |
| `modbus_master.py` | Modbus TCP |
| `s7comm_master.py` | S7comm / ISO-on-TCP |
| `enip_master.py` | EtherNet/IP / CIP |
| `profinet_master.py` | PROFINET DCP and PNIO DCE/RPC |
| `iec104_master.py` | IEC 60870-5-104 |
| `bacnet_master.py` | BACnet/IP |
| `opcua_master.py` | OPC UA |
| `mqtt_spb_master.py` | MQTT / Sparkplug B (implemented subset) |
| `dnp3_master.py` | DNP3/TCP (implemented subset) |

## Quick start

Use **CPython 3.12, 3.13 or 3.14**, covered by the offline CI matrix on Ubuntu,
Windows and macOS. This verifies the tested Python behavior, not every native
network capability. There is no package build or `pip install .` step.

```sh
python modbus_master.py -h
python profinet_master.py -h
```

**Every script has its own `-h` / `--help` menu** for supported commands, required
arguments, types, options and inline examples. Command sets and preconditions
differ, so consult the individual menu. **`-H` / `--host` selects a target; it is
not help.** OPC UA can instead use `-U` / `--url`; PROFINET DCP uses an interface.

Eight clients use Python's standard library for their protocol logic;
`asyncio` is part of Python. **OPC UA alone requires `asyncua==2.0.1`** and its
third-party transitive dependencies, including `cryptography`. Install it before
requesting OPC UA help:

```sh
python -m pip install asyncua==2.0.1
python opcua_master.py -h
```

That installation is optional for users of the other eight scripts.
[requirements-ci.txt](requirements-ci.txt) pins the same direct dependency for
the full CI suite; it is not a complete transitive lockfile.

## Testing and evidence

The [portability workflow](.github/workflows/portability.yml) runs nine OS/Python
combinations. In the [2026-11-02 run](https://github.com/z4y-d3n/Another-ICS-scripts/actions/runs/41457800317)
at commit [`c581dd7`](https://github.com/z4y-d3n/Another-ICS-scripts/commit/c581dd7ec7b91277d86cd922a37c5ef9ce62a41d),
**all nine jobs passed 86 offline tests each: 774 executions of 86 test cases**.
This records one successful run at that commit; the dynamic badge reports the
workflow's current status on `main`.

The [selective regression suite](tests/test_portability.py) checks source hashes,
UTF-8 and in-memory syntax compilation; real CLI help entry points under guards;
fixed binary encoding/parsing fixtures; protocol state and malformed inputs;
selected socket cleanup/recovery paths; and mandatory `asyncua` import/version
checks. Selected fixtures distinguish correlated replies, rejection and
indeterminate outcomes; none establishes operational authorization.
[SOURCE_SHA256.md](SOURCE_SHA256.md) records byte identity, not code correctness.

Historical development also included bounded regression, fuzz-style decoder and
fixture tests, adversarial/malformed-frame scenarios and follow-up corrections,
including BACnet/PROFINET socket-initialization cleanup. These are historical
engineering evidence; the smaller published CI suite does not rerun those entire
campaigns or provide an independent hardware audit.

To run the repository checks locally, install the CI dependency first, then:

```sh
python -B tests/check_sources.py
python -B tests/ci_support.py --run-tests
```

CI setup may contact package indexes. The protocol tests themselves use controlled
fixtures and fake sockets, without contacting ICS equipment; their cooperative
Python guards are **not a security sandbox**.

## Scope and safety

These checks validate no real industrial devices, plant networks or independent
third-party protocol stacks. They provide no formal protocol-conformance
certification or guarantee of defect-free behavior. The scripts are active
**master clients**: even reads contact devices, and some operations alter or
control industrial state. Use only in owned or explicitly authorized controlled
environments.

Native PROFINET DCP raw Ethernet requires Linux `AF_PACKET` and appropriate
socket privileges. Fake DCP tests on Windows/macOS do not prove native Ethernet
support there; PNIO-RPC is a separate UDP path.

No license is currently supplied; public visibility alone grants no unrestricted reuse.
