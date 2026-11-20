"""Run the bounded Gate 4 campaign explicitly. Generated data stays in pure conversions."""

from collections import Counter
from fractions import Fraction
from functools import partial
import gc
import hashlib
import json
from pathlib import Path
import platform
import random
from statistics import median
import sys
from time import perf_counter_ns
import tracemalloc

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ethercat_unit"))
try:
    from support import OfflineGuard, ec
    from vectors import CHAINED, single_payload
finally:
    sys.path.pop(0)
from ci_support import GuardViolation


SEEDS = (0x18C17, 0x2BFD, 0x4A5E, 0x9E37)
TRIALS_PER_SEED = 128
HEX_BYTES = (1, 2, 7, 16, 31, 60, 128, 256, 512, 1513, 1514)


def local_values(seed):
    rng = random.Random(seed)
    scale = 1_000_000
    for index in range(TRIALS_PER_SEED):
        raw = rng.randbytes(HEX_BYTES[index % len(HEX_BYTES)])
        text = raw.hex()
        expected = ("bytes", text)
        yield "hex", text, expected
        yield "hex", text.upper(), expected
        irregular = (text[:-1], text[:1] + "\u200b" + text[2:], "0x" + text)
        yield "hex", irregular[index % len(irregular)], ("usage",)

        coefficient = rng.randrange(14 * scale)
        rational = Fraction(coefficient, scale)
        expected = ("float", float(rational).hex()) if Fraction(1, 1000) <= rational <= 10 else ("usage",)
        whole, fraction = divmod(coefficient, scale)
        yield "seconds", f"{whole}.{fraction:06d}", expected
        yield "seconds", f"+{coefficient:08d}E-006", expected
        irregular = (f"-{coefficient + 1}e-6", f"{whole},{fraction:06d}", f"{coefficient}_0e-7")
        yield "seconds", irregular[index % len(irregular)], ("usage",)


def observe(conversion, value):
    try:
        actual = conversion(value)
    except GuardViolation:
        raise
    except ec.UsageError as exc:
        return ("usage", str(exc)) if type(exc) is ec.UsageError else ("error", type(exc).__name__)
    except Exception as exc:
        return ("error", type(exc).__name__, str(exc))
    if type(actual) is bytes:
        return "bytes", actual.hex()
    if type(actual) is float:
        return "float", actual.hex()
    return "unexpected type", type(actual).__name__


def update_fingerprint(digest, row):
    digest.update(json.dumps(row, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n")


def check_generated_values():
    inputs = hashlib.sha256()
    results = hashlib.sha256()
    seen = set()
    per_seed = []
    examples = []
    conversions = {"hex": ec.parse_hex, "seconds": ec._parse_timeout}
    for seed in SEEDS:
        counts = Counter()
        for family, value, expected in local_values(seed):
            key = (family, value)
            counts["attempted"] += 1
            counts["duplicates"] += key in seen
            seen.add(key)
            counts[f"{family}/{expected[0]}"] += 1
            update_fingerprint(inputs, (seed, family, value))
            actual = observe(conversions[family], value)
            repeated = observe(conversions[family], value)
            update_fingerprint(results, (actual, repeated))
            if actual[:len(expected)] == expected and repeated == actual:
                counts["passed"] += 1
            else:
                counts["failed"] += 1
                if len(examples) < 12:
                    examples.append(dict(
                        seed=seed, family=family, case=counts["attempted"],
                        value=value[:96], chars=len(value),
                        expected=str(expected)[:140], actual=str(actual)[:140], repeated=str(repeated)[:140],
                    ))
        per_seed.append({"seed": seed, **counts})
    return dict(
        distinct=len(seen), per_seed=per_seed, input_sha256=inputs.hexdigest(),
        result_sha256=results.hexdigest(), counterexamples=examples,
    )


def inspect_fixture(data, chain_length, count):
    result = ec.inspect_frame(data)
    if (result.status is not ec.Status.OK or type(result.detail) is not ec.EtherCATFrame
            or result.detail.chain_length != chain_length or len(result.detail.datagrams) != count):
        raise AssertionError("approved inspection fixture changed")


def simulate_fixture(scenario, profile, status, elapsed, events):
    result = ec.simulate(scenario, 0.001, profile)
    detail = result.detail
    if (result.status is not status or result.origin is not ec.Origin.SYNTHETIC
            or type(detail) is not ec.ExchangeEvidence or detail.profile is not profile
            or detail.delivery is not ec.Delivery.ACCEPTED or detail.elapsed_ns != elapsed
            or detail.events != events or result.cleanup is not None):
        raise AssertionError("approved simulation outcome changed")


def close_memory_transport():
    clock = ec.VirtualClock()
    transport = ec.MemoryTransport(clock, ())
    transport.open(1)
    transport.close()
    transport.close()
    if transport.closed is not True or transport.sent_frame is not None or clock() != 0:
        raise AssertionError("local resource cycle changed")


def noop():
    return None


def timing(work, repetitions):
    samples = []
    for _ in range(repetitions):
        start = perf_counter_ns()
        work()
        samples.append(perf_counter_ns() - start)
    samples.sort()
    return dict(
        median_ns=median(samples), p05_ns=samples[(5 * repetitions + 99) // 100 - 1],
        p95_ns=samples[(95 * repetitions + 99) // 100 - 1], max_ns=samples[-1],
    )


def memory(work, repetitions):
    # Workloads and fixture buffers exist before tracing. Record the empty-loop
    # control separately because the sampler itself allocates small objects.
    gc.collect()
    tracemalloc.start(1)
    try:
        baseline, _ = tracemalloc.get_traced_memory()
        batches = []
        for batch in range(4):
            count = repetitions * (batch + 1) // 4 - repetitions * batch // 4
            tracemalloc.reset_peak()
            for _ in range(count):
                work()
            before_gc, peak = tracemalloc.get_traced_memory()
            gc.collect()
            retained, _ = tracemalloc.get_traced_memory()
            batches.append(dict(
                repetitions=count, before_gc_bytes=before_gc - baseline,
                retained_bytes=retained - baseline, peak_bytes=peak - baseline,
                tracer_bytes=tracemalloc.get_tracemalloc_memory(),
            ))
        return dict(baseline_bytes=baseline, batches=batches)
    finally:
        tracemalloc.stop()


def benchmark():
    large = single_payload(bytes(1486))
    workloads = (
        ("empty_call", 500, 0, noop),
        ("inspect_chained", 250, len(CHAINED), partial(inspect_fixture, CHAINED, 25, 2)),
        ("inspect_maximum", 250, len(large), partial(inspect_fixture, large, 1498, 1)),
        ("simulate_success", 250, None,
         partial(simulate_fixture, ec.Scenario.SUCCESS, ec.ReadProfile.FPRD, ec.Status.OK, 500_000, 1)),
        ("simulate_timeout", 250, None,
         partial(simulate_fixture, ec.Scenario.TIMEOUT, ec.ReadProfile.APRD, ec.Status.TIMEOUT, 1_000_000, 0)),
        ("memory_transport_cycle", 200, 0, close_memory_transport),
    )
    measures = {}
    for name, repetitions, size, work in workloads:
        for _ in range(10):
            work()
        measures[name] = dict(
            repetitions_per_measure=repetitions, input_bytes=size,
            timing=timing(work, repetitions), memory=memory(work, repetitions),
        )
    return measures


def main():
    start = perf_counter_ns()
    with OfflineGuard() as guard:
        generated = check_generated_values()
        measures = benchmark()
    summary = dict(
        python=platform.python_version(), executable=sys.executable, system=platform.platform(),
        generated=generated, workloads=measures, denied=guard.violations, import_events=guard.import_events,
        elapsed_ns=perf_counter_ns() - start,
    )
    print(json.dumps(summary, indent=2))
    failed = any(counts.get("failed") for counts in generated["per_seed"])
    return int(failed or generated["distinct"] < 2000 or bool(guard.import_events))


if __name__ == "__main__":
    raise SystemExit(main())
