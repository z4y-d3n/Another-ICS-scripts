# Another ICS scripts

[![Portability CI on main](https://github.com/z4y-d3n/Another-ICS-scripts/actions/workflows/portability.yml/badge.svg?branch=main)](https://github.com/z4y-d3n/Another-ICS-scripts/actions/workflows/portability.yml)
[![CPython CI targets 3.12, 3.13 and 3.14](https://img.shields.io/badge/CPython%20CI%20targets-3.12%20%7C%203.13%20%7C%203.14-3776AB)](#testing-and-evidence)

Another set of ICS scripts with ten independent, standalone Python clients for
exploring and testing industrial protocols in explicitly authorized environments.
Each file provides its own CLI and can run directly. EtherCAT provides offline
frame inspection and deterministic simulation.

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
| `ethercat_master.py` | EtherCAT Type 1 (offline inspection and simulation) |

## Quick start

The offline CI matrix targets **CPython 3.12, 3.13 and 3.14** on Ubuntu, Windows
and macOS. Run each script directly with Python.

```sh
python modbus_master.py -h
python profinet_master.py -h
```

**Every script has its own `-h` / `--help` menu** for supported commands, required
arguments, types, options and inline examples. Command sets and preconditions
differ, so consult the individual menu. Where supported, **`-H` / `--host` selects
a target**. OPC UA also accepts `-U` / `--url`. PROFINET DCP uses an interface.

Nine clients, including EtherCAT, use only Python's standard library.
**OPC UA alone requires `asyncua==2.0.1`** and its
third-party transitive dependencies, including `cryptography`. Install it before
requesting OPC UA help:

```sh
python -m pip install asyncua==2.0.1
python opcua_master.py -h
```

[requirements-ci.txt](requirements-ci.txt) pins the same direct dependency for
the full CI suite; it is not a complete transitive lockfile.

## EtherCAT offline usage

```sh
python ethercat_master.py --help
python ethercat_master.py -c capabilities
python ethercat_master.py -c inspect --hex ffffffffffff02000000000188a40e100427341200010200000000000000
python ethercat_master.py -c simulate --scenario success
python ethercat_master.py -c simulate --scenario timeout
```

| Mode | Supported behavior |
| --- | --- |
| `inspect` | Reads local ASCII hex for untagged Ethernet II EtherCAT Type 1 frames without FCS. Accepts stripped (default) or retained padding and up to 1,514 bytes and 15 datagrams per frame. |
| `simulate` | Uses synthetic FPRD fixtures, an in-memory transport and deterministic logical timing. The timeout is 0.001–10 seconds (default 1), with up to 64 events per exchange. |
| `capabilities` | Reports the local runtime, input profile, limits, Linux packet API symbols and public diagnostic status. |

All three modes run offline. Results identify offline input, synthetic fixtures
or the local runtime as their source. The CLI has a combined 16 KiB UTF-8 output
budget. Help lists the exit codes, including `0` for success, `4` for local
failures and `6` for the simulated timeout above.

The internal backend is implemented for Linux `AF_PACKET` / `SOCK_RAW` and has
offline test evidence from substituted system dependencies. Public `diagnose`
is disabled pending physical interoperability validation. Real-time master
operation and cyclic process control are outside this client's scope.

## Testing and evidence

The [portability workflow](.github/workflows/portability.yml) is configured for
nine OS/Python combinations. In the historical
[2026-11-02 run](https://github.com/z4y-d3n/Another-ICS-scripts/actions/runs/41457800317)
at commit [`c581dd7`](https://github.com/z4y-d3n/Another-ICS-scripts/commit/c581dd7ec7b91277d86cd922a37c5ef9ce62a41d),
**all nine jobs passed 86 offline tests each: 774 executions of 86 test cases**.
That run covered the original nine clients. The EtherCAT suites have local
Windows evidence on CPython 3.12, 3.13 and 3.14. Check the workflow run for the
commit in question for remote results, including Ubuntu and macOS.

The [selective regression suite](tests/test_portability.py) checks source hashes,
UTF-8 and in-memory syntax compilation; real CLI help entry points under guards;
fixed binary encoding/parsing fixtures; protocol state and malformed inputs;
selected socket cleanup/recovery paths; and mandatory `asyncua` import/version
checks. Selected fixtures distinguish correlated replies, rejection and
indeterminate outcomes; none establishes operational authorization.
[SOURCE_SHA256.md](SOURCE_SHA256.md) records the byte identity of all ten clients.

Historical development also included bounded regression, fuzz-style decoder and
fixture tests, adversarial/malformed-frame scenarios and follow-up corrections,
including BACnet/PROFINET socket-initialization cleanup. These are historical
engineering evidence; the smaller published CI suite does not rerun those entire
campaigns or provide an independent hardware audit.

To run the repository checks locally, install the CI dependency first, then:

```sh
python -B tests/check_sources.py
python -B tests/ci_support.py --run-tests
python -B -m unittest discover -s tests/ethercat_unit -p "test_*.py" -v
python -B -m unittest discover -s tests/ethercat_integration -p "test_*.py" -v
python -B tests/ethercat_robustness/run_suite.py
```

The EtherCAT suites cover unit contracts, integration with guarded local
processes and permanent robustness regressions. The extended input and
test-sensitivity campaigns under `tests/ethercat_robustness/` run on demand.

CI setup may contact package indexes. The protocol tests themselves use controlled
fixtures and fake sockets, without contacting ICS equipment; their cooperative
Python guards are **not a security sandbox**.

## Scope and safety

These checks validate no real industrial devices, plant networks or independent
third-party protocol stacks. They provide no formal protocol-conformance
certification or guarantee of defect-free behavior. The original nine scripts
provide active master-client operations. Even reads contact devices, and some
operations alter or control industrial state. Use them only in owned or
explicitly authorized controlled environments.

Native PROFINET DCP raw Ethernet requires Linux `AF_PACKET` and appropriate
socket privileges. Fake DCP tests on Windows/macOS do not prove native Ethernet
support there; PNIO-RPC is a separate UDP path.

## License

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.

You may use, study, modify, and redistribute these scripts for noncommercial purposes, subject to the license terms.

Commercial use requires separate authorization from the copyright holder.

See [LICENSE](LICENSE) for the complete terms.
