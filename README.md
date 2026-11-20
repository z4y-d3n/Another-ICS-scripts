# Another-ICS-scripts

[![Portability CI on main](https://github.com/z4y-d3n/Another-ICS-scripts/actions/workflows/portability.yml/badge.svg?branch=main)](https://github.com/z4y-d3n/Another-ICS-scripts/actions/workflows/portability.yml)
[![CPython CI targets 3.12, 3.13 and 3.14](https://img.shields.io/badge/CPython%20CI%20targets-3.12%20%7C%203.13%20%7C%203.14-3776AB)](#testing-and-quality-assurance)

## Introduction

Another-ICS-scripts is a collection of ten standalone Python clients for
exploring and testing industrial protocols in controlled, authorized environments.
Each client runs directly from its own script and provides a command-line interface.

## Supported Protocols

| Protocol | Script | Scope |
| --- | --- | --- |
| Modbus TCP | [`modbus_master.py`](modbus_master.py) | Coil and register access, polling, and device identification. |
| S7comm | [`s7comm_master.py`](s7comm_master.py) | PLC memory access, diagnostics, and block inventory over ISO-on-TCP. |
| EtherNet/IP | [`enip_master.py`](enip_master.py) | Device identification, explicit CIP attribute access, and tag reads and writes. |
| PROFINET | [`profinet_master.py`](profinet_master.py) | DCP discovery and configuration, plus PNIO DCE/RPC record reads and diagnostics. |
| IEC 60870-5-104 | [`iec104_master.py`](iec104_master.py) | Station interrogation, point reads, monitoring, and control commands. |
| BACnet/IP | [`bacnet_master.py`](bacnet_master.py) | Device discovery, object enumeration, and property reads, writes, and monitoring. |
| OPC UA | [`opcua_master.py`](opcua_master.py) | Endpoint discovery, node browsing, data access, subscriptions, and method calls. |
| MQTT / Sparkplug B | [`mqtt_spb_master.py`](mqtt_spb_master.py) | MQTT 3.1.1 publishing and subscribing, with support for a subset of Sparkplug B metrics. |
| DNP3/TCP | [`dnp3_master.py`](dnp3_master.py) | A subset covering link status, integrity polls, point reads, and selected controls. |
| EtherCAT | [`ethercat_master.py`](ethercat_master.py) | Offline inspection of Type 1 frames and deterministic simulation. |

## Quick Start

From the repository root, run the chosen script with Python. Use `--help` or `-h`
to see its supported commands, required arguments, and options.

```sh
python modbus_master.py --help
python profinet_master.py --help
```

Target arguments vary by command. Where supported, use `-H` or `--host` for a
network host. OPC UA also accepts `-U` or `--url` for an endpoint. PROFINET DCP
uses a network interface.

## Requirements and Dependencies

The CI targets are CPython **3.12, 3.13, and 3.14**. Nine clients use only the
Python standard library. OPC UA requires `asyncua`, including for `--help`.
Install the CI-pinned version, which also installs dependencies such as
`cryptography` for certificate handling.

```sh
python -m pip install asyncua==2.0.1
```

[`requirements-ci.txt`](requirements-ci.txt) pins the same version. Pip resolves
the transitive dependencies at installation time.

## Platform Compatibility

Offline checks target Ubuntu, Windows, and macOS. Networked operations primarily
use TCP or UDP, with platform-specific requirements for raw Ethernet.

- **PROFINET.** Native DCP uses raw Ethernet and requires Linux `AF_PACKET` and
  permission to open raw sockets. PNIO DCE/RPC uses UDP and does not require
  `AF_PACKET`.
- **EtherCAT.** The internal native backend uses Linux `AF_PACKET` raw sockets.
  Physical diagnostics in the public CLI remain disabled pending hardware
  interoperability validation.

## Testing and Quality Assurance

The [GitHub Actions workflow](.github/workflows/portability.yml) is configured
for nine combinations, pairing each of the three operating systems with each
of the three CPython versions listed above. It verifies the SHA-256 hashes of
all ten clients against [`SOURCE_SHA256.md`](SOURCE_SHA256.md), checks UTF-8
encoding, and compiles the sources in memory.

The [portability suite](tests/test_portability.py) exercises the CLI help menus,
selected protocol encoders and parsers, reply handling, and socket recovery. It
also verifies the installed OPC UA dependency. Additional unit, integration,
and robustness suites cover EtherCAT. The suites use fixed fixtures, test
doubles such as fake sockets, and cooperative Python guards. Dependency
installation may access package indexes.

Run the permanent checks from the repository root.

```sh
python -m pip install -r requirements-ci.txt
python -B tests/check_sources.py
python -B tests/ci_support.py --run-tests
python -B -m unittest discover -s tests/ethercat_unit -p "test_*.py" -v
python -B -m unittest discover -s tests/ethercat_integration -p "test_*.py" -v
python -B tests/ethercat_robustness/run_suite.py
```

Use the workflow run for the revision you are evaluating to confirm its CI
results. The tests exercise selected behavior without contacting industrial
equipment or sending native Ethernet traffic. They do not establish
interoperability with physical devices, plant networks, or independent protocol
stacks. The cooperative Python guards are intended for test isolation and do not constitute a security sandbox.

## Scope and Safety

Use networked clients only in controlled environments you own or are explicitly
authorized to test. Even reads send traffic to their targets. Writes, control
commands, and configuration changes can alter device or process state.

The project carries no formal protocol-conformance certification. Real-time
EtherCAT master operation and cyclic process control are outside its scope.

## License

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.

You may use, study, modify, and redistribute these scripts for noncommercial purposes, subject to the license terms.

Commercial use requires separate authorization from the copyright holder.

See [LICENSE](LICENSE) for the complete terms.
