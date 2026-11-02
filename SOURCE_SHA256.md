# Source byte provenance

These are the accepted post-Phase-3 and post-socket-cleanup handoff snapshots.
SHA-256 proves byte identity, not correctness, conformance, interoperability or
field readiness. Intentional source edits require a reviewed table update and
matching verification in the same change; never regenerate expectations to hide
an unexplained mismatch.

Machine-readable format: exactly nine rows, in the table below, with a backtick
filename, lowercase 64-digit SHA-256, decimal byte count and `CRLF` or `LF` label.
`tests/check_sources.py` validates this format and compares raw bytes independently.

| Script | SHA-256 | Bytes | EOL |
| --- | --- | --- | --- |
| `modbus_master.py` | 145bc9f21bd8e95254a702cf7c0e038423250e0ffa8f34b9aeec5ecd4d085366 | 35956 | CRLF |
| `s7comm_master.py` | 9dedf2769aafbea18e9446c25da7eae5f00ebc50b2a49ff4922d3bc9ff1ed96e | 51571 | CRLF |
| `enip_master.py` | 75c0f7d6b623434f1bcfb7c970ca65c69eb9dc2fc5b64fd517c4a1a4fa17c9cd | 36028 | LF |
| `profinet_master.py` | 07c934c19f0b369e78eaaf9d27eaec2aa72a3fa9b5298a9eb9dfdde06491cc5a | 53166 | CRLF |
| `iec104_master.py` | dd44ea508f01a6bc44e408ae4d0028f8e81ef188c69cd5a774d522b6ea34cce9 | 49315 | CRLF |
| `bacnet_master.py` | 38f21c6f71a51fdfb1ccb35a3927de878f5356b7b8485558e1dc185c1dea7485 | 59056 | CRLF |
| `opcua_master.py` | d867838264e96417aee7bfc1a2b98999dd8d8b987460d480ffd8a13d25a2a617 | 60341 | CRLF |
| `mqtt_spb_master.py` | fe3ef34b2954dedfb183d07f9b8404fd585db22e6a45a3669412fb257aed82a8 | 48601 | CRLF |
| `dnp3_master.py` | 95131397ef854024d3424c8f892b8ee2f1d6b12edb54b2a147639220090a64db | 38554 | CRLF |

Run `python -B tests/check_sources.py` from the repository root. To calculate one
raw digest independently on any supported OS:

```sh
python -B -c "from pathlib import Path; import hashlib; b=Path('modbus_master.py').read_bytes(); print(len(b), hashlib.sha256(b).hexdigest())"
```

`.gitattributes` disables text conversion for production Python files, preserving
their historical CRLF/LF bytes even with `core.autocrlf`. Support files use LF.
The checker never imports clients, writes bytecode or updates this document.
