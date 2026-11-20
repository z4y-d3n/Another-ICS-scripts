"""Run the actual EtherCAT entry point in an isolated Python child."""

import os
from pathlib import Path
import runpy
import socket
import sys
from unittest.mock import patch


TESTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TESTS))
from ci_support import OfflineGuard


def main():
    if os.environ.get("COVERAGE_PROCESS_START"):
        import coverage

        # Some coverage installations start from a site hook before this script.
        if coverage.Coverage.current() is None and coverage.process_startup() is None:
            raise RuntimeError("child coverage did not start")

    # The parent writes the token only after closing the selected pipe reader.
    if sys.stdin.buffer.read(1) != b"\x01":
        raise RuntimeError("missing parent release token")
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if stream.isatty() or stream.encoding.lower() != "utf-8":
            raise RuntimeError("expected noninteractive UTF-8 pipes")

    target = TESTS.parent / "ethercat_master.py"
    sys.argv[0] = str(target)
    with OfflineGuard() as guard:
        for name in ("if_nameindex", "if_nametoindex", "if_indextoname"):
            if hasattr(socket, name):
                guard.stack.enter_context(patch.object(
                    socket, name, lambda *args, _name=name, **kwargs: guard.deny(f"socket.{_name}")
                ))
        try:
            runpy.run_path(str(target), run_name="__main__")
        finally:
            # Check even on SystemExit or if the client caught a guard error.
            if guard.violations or guard.import_events:
                raise RuntimeError(
                    f"prohibited effects: {guard.violations + guard.import_events}"
                )
    raise RuntimeError("entry point returned without SystemExit")


if __name__ == "__main__":
    main()
