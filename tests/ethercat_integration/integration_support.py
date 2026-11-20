"""Imports of shared fixtures and the parent-side subprocess boundary."""

from pathlib import Path
import subprocess
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / "ethercat_unit"))
try:
    import linux_fakes as packet
    from support import OfflineCase, ec
    import vectors
finally:
    sys.path.pop(0)

from ci_support import child_environment


def run_cli(args, *, cwd=ROOT, broken=None):
    """Start one known local child, enforce a wall timeout and reap it."""
    if broken not in (None, "stdout", "stderr"):
        raise ValueError(f"invalid pipe selection: {broken!r}")
    env = child_environment()
    for variable in ("COLUMNS", "LINES", "PYTHONPATH", "PYTHONHOME"):
        env.pop(variable, None)
    command = [sys.executable, "-I", "-B", "-X", "utf8", str(HERE / "guarded_entry.py"), *args]
    with subprocess.Popen(
        command, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) as child:
        try:
            if broken is not None:
                getattr(child, broken).close()
                setattr(child, broken, None)
            stdout, stderr = child.communicate(input=b"\x01", timeout=8)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=8)
    return child.returncode, stdout or b"", stderr or b""
