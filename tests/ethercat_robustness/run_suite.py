"""Count R1 methods and subtests and allow deterministic reverse discovery order."""

import argparse
from collections import Counter
import json
from pathlib import Path
import platform
from time import perf_counter
import unittest


class Results(unittest.TextTestResult):
    def __init__(self, *args):
        super().__init__(*args)
        self.passed = 0
        self.subtests = Counter()

    def addSuccess(self, test):
        self.passed += 1
        super().addSuccess(test)

    def addSubTest(self, test, subtest, error):
        if error is None:
            key = "passed"
        elif issubclass(error[0], test.failureException):
            key = "failed"
        else:
            key = "errors"
        self.subtests[key] += 1
        super().addSubTest(test, subtest, error)


def methods(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from methods(test)
        else:
            yield test


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reverse", action="store_true")
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    tests = list(methods(unittest.defaultTestLoader.discover(str(directory), pattern="test_*.py")))
    if args.reverse:
        tests.reverse()
    order = [test.id() for test in tests]
    start = perf_counter()
    result = unittest.TextTestRunner(verbosity=2, resultclass=Results).run(unittest.TestSuite(tests))
    print(json.dumps(dict(
        python=platform.python_version(), platform=platform.platform(), order=order,
        methods=result.testsRun, passed=result.passed, fail_records=len(result.failures),
        error_records=len(result.errors), skips=len(result.skipped),
        expected_failures=len(result.expectedFailures), unexpected_successes=len(result.unexpectedSuccesses),
        subtests={key: result.subtests[key] for key in ("passed", "failed", "errors")},
        seconds=perf_counter() - start,
        failure_ids=sorted(str(test) for test, _ in result.failures),
        error_ids=sorted(str(test) for test, _ in result.errors),
    )))
    return int(not result.wasSuccessful())


if __name__ == "__main__":
    raise SystemExit(main())
