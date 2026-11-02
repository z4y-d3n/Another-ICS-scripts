#!/usr/bin/env python3
"""Small offline test helpers. Cooperative Python guards, not an OS sandbox.

Only explicit FakeSocket objects may model transport. Audit hooks also catch
cached real socket constructors; a caught violation still fails the guard scope.
Hooks remain dormant after exit, and monkeypatches/logging state are restored.
"""

import argparse
import asyncio  # Load socket/SSL class definitions before patching constructors.
from contextlib import contextmanager, ExitStack
import importlib.metadata
import importlib.util
import io
import logging
import os
from pathlib import Path
import platform
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

from check_sources import ROOT, SOURCES

_GUARDS = []
_HOOK_INSTALLED = False


class GuardViolation(RuntimeError):
    """A forbidden operation was attempted, even if product code caught it."""


class DependencyUnavailable(RuntimeError):
    """Required OPC UA environment is blocked, not a successful test."""


def require_asyncua():
    if importlib.util.find_spec("asyncua") is None:
        raise DependencyUnavailable(
            "BLOCKED: asyncua unavailable; install requirements-ci.txt. OPC UA checks are mandatory.")


def _audit(event, args):
    if not _GUARDS:
        return
    guard = _GUARDS[-1]
    # gethostname reads the local OS name (OPC UA's default app URI); it does
    # not resolve DNS, create a socket or transmit. Never print that URI.
    if (event.startswith("socket.") and event != "socket.gethostname") or event in {
        "os.system", "subprocess.Popen", "os.fork", "os.forkpty",
        "os.posix_spawn", "os.spawn", "os.exec", "os.startfile", "os.startfile/2",
    }:
        guard.deny(event)
    if event == "open":
        path, mode, flags = args
        writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
            isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        if writing and not guard.writable(path):
            guard.deny("file write")
    paths = {
        "os.mkdir": (0,), "os.remove": (0,), "os.rmdir": (0,),
        "os.rename": (0, 1), "os.link": (0, 1), "os.symlink": (0, 1),
        "os.truncate": (0,), "os.chmod": (0,), "os.chown": (0,),
        "os.utime": (0,),
    }
    if event in paths and any(not guard.writable(args[i]) for i in paths[event]):
        guard.deny(event)
    if event == "os.chdir":
        guard.deny(event)


class OfflineGuard:
    def __init__(self, write_roots=()):
        self.write_roots = tuple(Path(p).resolve() for p in write_roots)
        self.violations = []
        self.import_events = []
        self.stack = ExitStack()

    def writable(self, path):
        if isinstance(path, int) or path is None:
            return False
        resolved = Path(os.fsdecode(path)).resolve()
        return any(resolved.is_relative_to(root) for root in self.write_roots)

    def deny(self, operation):
        if len(self.violations) < 128:
            self.violations.append(operation)
        raise GuardViolation(f"OFFLINE GUARD: forbidden {operation}")

    def _system(self, command):
        if command == "":  # Exact Windows ANSI initialization, never a shell.
            self.import_events.append("Windows ANSI no-op")
            return 0
        return self.deny("os.system(nonempty)")

    def _signal(self, sig, handler):
        if sig == signal.SIGINT and callable(handler) and handler.__name__ == "signal_handler":
            self.import_events.append("SIGINT registration neutralized")
            return signal.getsignal(sig)
        return self.deny("unexpected signal registration")

    def __enter__(self):
        global _HOOK_INSTALLED
        if not _HOOK_INSTALLED:
            sys.addaudithook(_audit)
            _HOOK_INSTALLED = True
        _GUARDS.append(self)
        try:
            for name in ("socket", "create_connection", "socketpair", "fromfd", "fromshare",
                         "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr",
                         "getnameinfo", "getfqdn"):
                if hasattr(socket, name):
                    self.stack.enter_context(patch.object(
                        socket, name, lambda *a, _name=name, **kw: self.deny(f"socket.{_name}")))
            self.stack.enter_context(patch.object(os, "system", self._system))
            self.stack.enter_context(patch.object(signal, "signal", self._signal))
        except BaseException:
            self.stack.close()
            _GUARDS.pop()
            raise
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.stack.close()
        finally:
            assert _GUARDS.pop() is self
        if self.violations and exc_type is None:
            raise GuardViolation(f"OFFLINE GUARD: caught forbidden attempts: {self.violations}")
        return False


class FakeSocket:
    """Bounded byte stream and setup events; never owns a kernel socket."""
    def __init__(self, incoming=b"", *, fail=None, chunk_size=4096):
        if len(incoming) > 65536 or chunk_size < 1:
            raise ValueError("FakeSocket fixture exceeds bounds")
        self.incoming = bytearray(incoming)
        self.fail = fail
        self.chunk_size = chunk_size
        self.events = []
        self.timeout = None
        self.closed = False

    def _event(self, name, *args):
        if len(self.events) >= 128:
            raise AssertionError("FakeSocket event limit exceeded")
        if self.closed:
            raise AssertionError("FakeSocket used after close")
        self.events.append((name, *args))
        if self.fail == name:
            raise OSError(f"injected {name} failure")

    def settimeout(self, value):
        self._event("settimeout", value)
        self.timeout = value

    def gettimeout(self):
        return self.timeout

    def setsockopt(self, *args):
        self._event("setsockopt", *args)

    def bind(self, address):
        self._event("bind", address)

    def connect(self, address):
        self._event("connect", address)

    def getsockname(self):
        self._event("getsockname")
        return ("fixture-iface", 0, 0, 0, bytes.fromhex("020000000001"))

    def sendall(self, data):
        if len(data) > 65536:
            raise AssertionError("FakeSocket send limit exceeded")
        self._event("sendall", bytes(data))

    def recv(self, size):
        self._event("recv", size)
        if self.fail == "timeout":
            raise socket.timeout("injected timeout")
        size = min(size, self.chunk_size)
        result = bytes(self.incoming[:size])
        del self.incoming[:size]
        return result  # Exhaustion is deterministic EOF, never an infinite wait.

    def close(self):
        self._event("close")
        self.closed = True


def socket_facade(*candidates, af_packet=False):
    """A module-local injectable socket API; AF_PACKET is synthetic, never native."""
    pending = iter(candidates)
    calls = []

    def constructor(*args):
        calls.append(args)
        if len(calls) > len(candidates):
            raise AssertionError("Unexpected extra socket candidate")
        candidate = next(pending)
        if isinstance(candidate, BaseException):
            raise candidate
        return candidate

    facade = SimpleNamespace(socket=constructor, calls=calls, timeout=socket.timeout,
                             AF_INET=socket.AF_INET, SOCK_DGRAM=socket.SOCK_DGRAM,
                             SOCK_RAW=socket.SOCK_RAW, SOCK_STREAM=socket.SOCK_STREAM,
                             SOL_SOCKET=socket.SOL_SOCKET, SO_BROADCAST=socket.SO_BROADCAST,
                             SO_REUSEADDR=socket.SO_REUSEADDR, htons=socket.htons)
    if af_packet:
        facade.AF_PACKET = 17  # Linux address-family value, simulated on every OS.
    return facade


@contextmanager
def temporary_workdir():
    original = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="otics-offline-") as directory:
        os.chdir(directory)
        try:
            yield Path(directory)
        finally:
            os.chdir(original)


@contextmanager
def preserve_logging():
    def loggers():
        return [logging.getLogger()] + [v for v in logging.Logger.manager.loggerDict.values()
                                      if isinstance(v, logging.Logger)]
    states = {log: (log.level, log.propagate, log.disabled, log.handlers[:], log.filters[:])
              for log in loggers()}
    try:
        yield
    finally:
        for log in loggers():
            level, propagate, disabled, handlers, filters = states.get(log, (0, True, False, [], []))
            for handler in log.handlers[:]:
                if handler not in handlers:
                    handler.close()
            log.handlers[:] = handlers
            log.filters[:] = filters
            log.setLevel(level)
            log.propagate, log.disabled = propagate, disabled


@contextmanager
def client_module(name, *, write_roots=()):
    """Fresh module per test; guard stays active for the entire product boundary."""
    if name not in SOURCES:
        raise ValueError("Only canonical clients may be imported")
    if name == "opcua_master.py":
        require_asyncua()
    module_name = "_offline_" + Path(name).stem
    previous = sys.modules.get(module_name)
    with preserve_logging(), OfflineGuard(write_roots):
        spec = importlib.util.spec_from_file_location(module_name, ROOT / name)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            # Direct compile/exec avoids loader bytecode regardless of caller flags.
            exec(compile((ROOT / name).read_bytes(), str(ROOT / name), "exec"), module.__dict__)
            yield module
        finally:
            if previous is None:
                del sys.modules[module_name]
            else:
                sys.modules[module_name] = previous


def child_environment():
    env = os.environ.copy()
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", OTICS_OFFLINE_TESTS="1")
    return env


def environment_summary():
    print(f"OS={platform.system()} {platform.release()} CPU={platform.machine()}")
    print(f"Python={sys.executable} {platform.python_version()} {platform.python_implementation()}")
    require_asyncua()
    with OfflineGuard():
        import asyncua  # Mandatory import including real cryptographic dependencies.
    print(f"asyncua import PASS: {asyncua.__version__}")
    # Resolved versions are evidence; requirements-ci.txt pins only the direct dependency.
    for dist in sorted(importlib.metadata.distributions(), key=lambda d: d.metadata['Name'].lower()):
        print(f"dependency {dist.metadata['Name']}=={dist.version}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", action="store_true")
    parser.add_argument("--run-tests", action="store_true", help="Fresh temp cwd, 120 second suite timeout")
    args = parser.parse_args()
    if args.environment:
        environment_summary()
    if args.run_tests:
        with temporary_workdir() as directory:
            command = [sys.executable, "-B", "-m", "unittest", "discover", "-s", str(ROOT / "tests"),
                       "-p", "test_*.py", "-v"]
            try:
                result = subprocess.run(command, cwd=directory, env=child_environment(),
                                        timeout=120, capture_output=True, text=True, encoding="utf-8")
            except subprocess.TimeoutExpired as exc:
                print("LOCAL_TESTS_FAILED: suite exceeded 120 seconds", file=sys.stderr)
                for output in (exc.stdout, exc.stderr):
                    if output:
                        print(output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output)
                return 1
            print(result.stdout, end="")
            print(result.stderr, end="", file=sys.stderr)
            print(f"OFFLINE SUITE EXIT={result.returncode}")
            return result.returncode
    if not (args.environment or args.run_tests):
        parser.error("choose --environment and/or --run-tests")
    return 0


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    sys.exit(main())
