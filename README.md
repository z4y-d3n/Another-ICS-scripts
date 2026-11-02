# Nine OT/ICS Python clients

Nine independent, stand-alone, monolithic Python master clients for authorized
laboratory and protocol work. Each script runs separately; this repository is
not OT-ArchGuard, a unified package or a commercial scanner.

| Script | Protocol |
| --- | --- |
| `modbus_master.py` | Modbus TCP |
| `s7comm_master.py` | Siemens S7comm / ISO-on-TCP |
| `enip_master.py` | EtherNet/IP / CIP |
| `profinet_master.py` | PROFINET DCP and PNIO DCE/RPC |
| `iec104_master.py` | IEC 60870-5-104 |
| `bacnet_master.py` | BACnet/IP |
| `opcua_master.py` | OPC UA |
| `mqtt_spb_master.py` | MQTT / Sparkplug B subset |
| `dnp3_master.py` | DNP3/TCP subset |

## Quick start

Use a modern CPython interpreter. The proposed verification matrix targets
3.12–3.14; support across all platforms remains unconfirmed until Actions runs.
Downloaded scripts generally run directly without a project-wide installation.

```sh
python modbus_master.py -h
python dnp3_master.py -h
python opcua_master.py -h
```

**Each script has its own complete `-h` / `--help` menu** describing supported
commands, required flags, types and options. Consult that script's menu and its
embedded examples for usage; command sets differ. **`-H` / `--host` selects the
target where defined; it is not help.** OPC UA also accepts a URL, and PROFINET
DCP uses an interface. Install OPC UA's dependency before requesting its help.

## Dependencies

Eight clients use standard Python libraries without extra protocol packages;
`asyncio` is already part of Python. OPC UA requires third-party `asyncua` and
its transitive dependencies, including `cryptography`:

```sh
python -m pip install asyncua==2.0.1
```

`requirements-ci.txt` pins that direct dependency for CI; it is not a complete
transitive lockfile. No extra protocol libraries are needed for the other clients.

## Checks and limits

Historical bounded regression, fuzz-style and adversarial/malformed-input
campaigns led to corrections, including later BACnet/PROFINET socket cleanup;
these are historical evidence, not proof of zero defects. The supplied workflow
configures independent offline checks on Ubuntu, Windows and macOS × CPython
3.12, 3.13 and 3.14; those nine jobs have not yet run, and this smaller suite does
not rerun the entire historical fuzz campaign. Package installation may access
the network; tests use deterministic fixtures, fake transports and guarded help
subprocesses, with mandatory OPC UA checks and no silent dependency skips.

```sh
python -B tests/check_sources.py
python -B tests/ci_support.py --run-tests
```

Python guards are cooperative, not an OS sandbox. No live industrial equipment
or independent real-device interoperability is validated here, and there is no
formal conformance certification. Some commands change process state; even reads
contact devices, so use only explicitly authorized controlled environments.
PROFINET raw DCP requires Linux `AF_PACKET`; synthetic DCP checks on other OSes
do not establish native Ethernet support. PNIO-RPC UDP is a separate path.

No license has been selected; public visibility alone grants no redistribution rights.
