"""Measure selected pure-function oracles using a fresh, guarded child per copy."""

import argparse
import ast
from contextlib import nullcontext
import json
from pathlib import Path
import subprocess
import sys
from time import perf_counter
from typing import NamedTuple
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
R1 = "test_input_quality.GenericInputTests."
OLD_CLI = "test_cli.CommandLineTests."
ORACLES = {
    "parse_hex": (
        (OLD_CLI + "test_hex_parser_continuous_ascii_and_size_boundaries",),
        (R1 + "test_hex_conserves_bytes_under_case_and_concatenation",
         R1 + "test_hex_rejects_outside_the_ascii_text_contract"),
    ),
    "_parse_timeout": (
        (OLD_CLI + "test_decimal_parser_resolves_exact_boundaries_before_float_conversion",),
        (R1 + "test_decimal_representations_agree_with_exact_rationals",
         R1 + "test_decimal_rejection_precedes_float_rounding"),
    ),
    "validate_timeout": (
        ("test_client.ExchangeTests.test_timeout_validation_is_finite_and_inclusive",),
        (R1 + "test_numeric_timeout_retains_values_inside_inclusive_limits",),
    ),
    "_short_message": ((), (R1 + "test_diagnostic_normalization_and_truncation_have_stable_boundaries",)),
}


class Change(NamedTuple):
    description: str
    before: str
    after: str
    args: tuple
    equivalent: bool = False


CHANGES = {
    "parse_hex": (
        Change("Reject the exact upper length", "<= 2 * MAX_FRAME_BYTES", "< 2 * MAX_FRAME_BYTES", ("01" * 1514,)),
        Change("Accept one more byte", "2 * MAX_FRAME_BYTES", "2 * MAX_FRAME_BYTES + 2", ("01" * 1515,)),
        Change("Accept subclasses of str", "type(text) is not str", "not isinstance(text, str)", ()),
        Change("Check only a prefix", "_HEX_RE.fullmatch(text)", "_HEX_RE.match(text)", ("0g",)),
        Change("Drop the parity check", "len(text) % 2 or ", "", ("abc",)),
        Change("Reverse decoded bytes", "return bytes.fromhex(text)", "return bytes.fromhex(text)[::-1]", ("0102",)),
        Change("Discard leading zeros", "return bytes.fromhex(text)", "return bytes.fromhex(text).lstrip(b'\\0')", ("0001",)),
        Change("Discard the final byte", "return bytes.fromhex(text)", "return bytes.fromhex(text)[:-1]", ("0102",)),
        Change("Move empty text into the syntax error branch", "1 <= len(text)", "0 <= len(text)", ("",)),
    ),
    "_parse_timeout": (
        Change("Reject the exact upper endpoint", "<= Decimal(str(MAX_TIMEOUT))", "< Decimal(str(MAX_TIMEOUT))", ("10",)),
        Change("Reject the exact lower endpoint", "Decimal(str(MIN_TIMEOUT)) <= seconds",
               "Decimal(str(MIN_TIMEOUT)) < seconds", (".001",)),
        Change("Validate after binary rounding", "Decimal(str(MIN_TIMEOUT)) <= seconds <= Decimal(str(MAX_TIMEOUT))",
               "MIN_TIMEOUT <= float(seconds) <= MAX_TIMEOUT", (".0009999999999999999999999",)),
        Change("Trim whitespace for grammar validation", "_SECONDS_RE.fullmatch(text)",
               "_SECONDS_RE.fullmatch(text.strip())", (" 1",)),
        Change("Accept a syntactically valid prefix", "_SECONDS_RE.fullmatch(text)", "_SECONDS_RE.match(text)", ("1_0",)),
        Change("Return Decimal instead of float", "return float(seconds)", "return seconds", ("1",)),
        Change("Round converted seconds to tenths", "return float(seconds)", "return round(float(seconds), 1)", (".001",)),
        Change("Discard decimal exponent", "Decimal(text)", "Decimal(text.lower().split('e', 1)[0])", ("1e-3",)),
        Change("Catch the wrong conversion error", "except InvalidOperation:", "except ValueError:", ("1e" + "9" * 28,)),
        Change("Lower the decimal minimum", "Decimal(str(MIN_TIMEOUT))", 'Decimal("0.0001")', (".0005",)),
    ),
    "validate_timeout": (
        Change("Accept bool and numeric subclasses", "type(seconds) not in (float, int)",
               "not isinstance(seconds, (float, int))", (True,)),
        Change("Reject integer seconds", "(float, int)", "(float,)", (1,)),
        Change("Reject the exact lower endpoint", "MIN_TIMEOUT <= seconds", "MIN_TIMEOUT < seconds", (0.001,)),
        Change("Reject the exact upper endpoint", "seconds <= MAX_TIMEOUT", "seconds < MAX_TIMEOUT", (10.0,)),
        Change("Preserve the input type on return", "return float(seconds)", "return seconds", (1,)),
        Change("Use two out-of-bounds tests", "not MIN_TIMEOUT <= seconds <= MAX_TIMEOUT",
               "seconds < MIN_TIMEOUT or seconds > MAX_TIMEOUT", (float("nan"),)),
        Change("Round valid seconds to milliseconds", "return float(seconds)", "return float(round(seconds, 3))", (0.00125,)),
    ),
    "_short_message": (
        Change("Truncate at the exact limit", "len(message) <= limit", "len(message) < limit", ("a" * 60, 60)),
        Change("Reject ASCII space", '" " <= c', '" " < c', (" ",)),
        Change("Accept DEL", 'c <= "~"', 'c <= "\\x7f"', ("\x7f",)),
        Change("Make the truncation one character longer", "text[:-3]", "text[:-2]", ("a" * 61, 60)),
        Change("Substitute underscore for unsupported characters", 'else "?"', 'else "_"', ("é",)),
        Change("Replace the ellipsis marker", '+ "..."', '+ "==="', ("a" * 61, 60)),
        Change("Drop the last character of an exact prefix", "message[:limit]", "message[:limit - 1]", ("a" * 60, 60)),
        Change("Change the default message limit", "limit: int = 240", "limit: int = 241", ("a" * 241,)),
        Change("Compare code points instead of characters", '" " <= c <= "~"', "32 <= ord(c) <= 126",
               (" ~é\x7f",), True),
    ),
}

CASES = {f"M{number:02}": pair for number, pair in enumerate(
    ((function, change) for function, changes in CHANGES.items() for change in changes), 1,
)}


def test_selection(names):
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(names)
    if loader.errors:
        raise RuntimeError("could not load selected oracles: " + "\n".join(loader.errors))

    class Result(unittest.TestResult):
        def stopTest(self, test):
            guard = getattr(test, "guard", None)
            if guard and (guard.violations or guard.import_events):
                raise RuntimeError("unexpected effects inside selected oracle")
            super().stopTest(test)

    result = suite.run(Result())
    return dict(
        tests=result.testsRun, failed=sorted({test.id() for test, _ in result.failures}),
        errors=sorted({test.id() for test, _ in result.errors}), skips=len(result.skipped),
    )


def observation(function, args, guard_error):
    try:
        value = function(*args)
    except guard_error:
        raise
    except Exception as exc:
        return "raises", type(exc).__name__, str(exc)
    return "returns", type(value).__name__, repr(value)


def worker(key):
    sys.path[:0] = [str(HERE), str(HERE.parent / "ethercat_unit")]
    from support import OfflineGuard, SOURCE, ec
    from ci_support import GuardViolation

    selection = list(ORACLES.values())
    boundary = nullcontext()
    evidence = {}
    with OfflineGuard() as guard:
        if key != "baseline":
            name, change = CASES[key]
            original = SOURCE.read_text(encoding="utf-8")
            function, = (node for node in ast.parse(original).body
                         if isinstance(node, ast.FunctionDef) and node.name == name)
            source = ast.get_source_segment(original, function)
            if source.count(change.before) != 1:
                return {"invalid": "copy did not contain exactly one occurrence"}
            try:
                code = compile(source.replace(change.before, change.after, 1), f"<{key}:{name}>", "exec")
            except SyntaxError as exc:
                return {"invalid": str(exc)}
            names = ("MAX_FRAME_BYTES", "MIN_TIMEOUT", "MAX_TIMEOUT", "UsageError",
                     "_HEX_RE", "_SECONDS_RE", "Decimal", "InvalidOperation")
            namespace = {name: getattr(ec, name) for name in names}
            exec(code, namespace)
            copied = namespace[name]
            args = change.args or (type("DerivedText", (str,), {})("01"),)
            before = observation(getattr(ec, name), args, GuardViolation)
            after = observation(copied, args, GuardViolation)
            evidence = dict(
                distinct_observation=before != after,
                baseline_observation=str(before)[:180], mutant_observation=str(after)[:180],
            )
            boundary = patch.object(ec, name, copied)
            selection = [ORACLES[name]]

        with boundary:
            for index, suite in enumerate(("prior_unit", "r1")):
                names = list(dict.fromkeys(name for group in selection for name in group[index]))
                evidence[suite] = test_selection(names)
    if guard.import_events:
        raise RuntimeError(f"unexpected import events: {guard.import_events}")
    return evidence


def run_worker(key, env):
    command = [sys.executable, "-I", "-B", "-X", "utf8", str(HERE / "mutation_sensitivity.py"), "--worker", key]
    start = perf_counter()
    try:
        child = subprocess.run(command, cwd=HERE.parents[1], env=env, shell=False,
                               capture_output=True, encoding="utf-8", timeout=8)
    except subprocess.TimeoutExpired:
        return {"classification": "TIMEOUT", "seconds": perf_counter() - start}
    if child.returncode:
        raise RuntimeError(f"guarded worker {key} failed (exit {child.returncode}): {child.stderr}")
    return {"seconds": perf_counter() - start, **json.loads(child.stdout)}


def failures(record):
    return any(record[suite]["failed"] or record[suite]["errors"] for suite in ("prior_unit", "r1"))


def campaign():
    import os

    env = os.environ.copy()
    for name in ("PYTHONHOME", "PYTHONPATH", "COVERAGE_PROCESS_START", "COVERAGE_FILE"):
        env.pop(name, None)
    baseline = run_worker("baseline", env)
    if "classification" in baseline or failures(baseline):
        raise RuntimeError(f"unmodified oracle control failed: {baseline}")
    rows = []
    for key, (function, change) in CASES.items():
        row = run_worker(key, env)
        if "classification" not in row:
            if "invalid" in row:
                row["classification"] = "INVALID"
            elif change.equivalent and not row["distinct_observation"] and not failures(row):
                row["classification"] = "EQUIVALENT"
            elif change.equivalent or not row["distinct_observation"]:
                row["classification"] = "INCONCLUSIVE"
            else:
                row["classification"] = "KILLED" if failures(row) else "SURVIVED"
        rows.append(dict(id=key, function=function, description=change.description, **row))
    killed = sum(row["classification"] == "KILLED" for row in rows)
    survived = sum(row["classification"] == "SURVIVED" for row in rows)
    print(json.dumps(dict(
        baseline=baseline, mutations=rows, killed=killed, survived=survived,
        score=killed / (killed + survived) if killed + survived else None,
    ), indent=2))
    return int(any(row["classification"] not in ("KILLED", "SURVIVED", "EQUIVALENT") for row in rows))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", choices=("baseline", *CASES), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker is None:
        return campaign()
    print(json.dumps(worker(args.worker)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
