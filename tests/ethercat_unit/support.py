"""Offline fixture support shared by the EtherCAT unit tests."""

import importlib.util
from pathlib import Path
import sys
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "ethercat_master.py"

# Reuse the repository guard for a fresh, standalone client import.
sys.path.insert(0, str(ROOT / "tests"))
try:
    from ci_support import OfflineGuard
finally:
    sys.path.pop(0)


def load_client():
    """Execute a fresh module, without the import cache or bytecode writes."""
    name = "_ethercat_unit_product"
    spec = importlib.util.spec_from_file_location(name, SOURCE)
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), vars(module))
    finally:
        if previous is None:
            del sys.modules[name]
        else:
            sys.modules[name] = previous
    return module


with OfflineGuard():
    ec = load_client()


class OfflineCase(TestCase):
    def setUp(self):
        self.guard = self.enterContext(OfflineGuard())
        self.addCleanup(self.assertEqual, self.guard.violations, [])
        self.addCleanup(self.assertEqual, self.guard.import_events, [])
