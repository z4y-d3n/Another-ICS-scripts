#!/usr/bin/env python3
"""Execute one real client -h route with network/process/write guards installed."""

import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import runpy
import sys
from unittest.mock import patch

from check_sources import ROOT, SOURCES
from ci_support import OfflineGuard, preserve_logging, require_asyncua


class BoundedOutput(io.StringIO):
    def write(self, value):
        if self.tell() + len(value) > 65536:
            raise RuntimeError("CLI output exceeded 64 KiB")
        return super().write(value)


def probe(name):
    output = BoundedOutput()
    with preserve_logging(), OfflineGuard() as guard:
        if name == "opcua_master.py":
            require_asyncua()
        with redirect_stdout(output), redirect_stderr(output), patch.object(
                sys, "argv", [name, "-h"]):
            try:
                runpy.run_path(str(ROOT / name), run_name="__main__")
            except SystemExit as exc:
                if type(exc.code) is not int or exc.code != 0:
                    raise RuntimeError(f"Client help exited with {exc.code!r}") from exc
            else:
                raise RuntimeError("Client help did not take argparse's exit route")
        text = output.getvalue()
        # Eight clients deliberately use usage=argparse.SUPPRESS. Their real
        # top-level menu supplies a title, options and per-command examples.
        if not all(flag in text for flag in ("-h", "--help", "-H", "--host", "--command")):
            raise RuntimeError("Missing real help/host/command menu")
        if len(text) < 200 or not any(label in text.lower() for label in ("options:", "usage:")):
            raise RuntimeError("Help did not provide a useful argparse menu")
    print(f"CLI_HELP_PASS {name} flag=-h exit=0 forbidden=0 chars={len(text)} "
          f"neutralized={len(guard.import_events)}")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("script", choices=SOURCES)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    try:
        return probe(args.script)
    except Exception as exc:
        print(f"CLI_HELP_FAILED {args.script}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
