#!/usr/bin/env python
"""
benchmark_baseline_inference.py

Lightweight, read-only performance benchmark for the BANTAI ML inference
component (``src/models/baseline_inference.py``).

It loads the existing saved artifacts (never training or overwriting them) and
prints Markdown-ready timing results to stdout. It writes NO files.

What it measures:
* environment metadata (OS, CPU, RAM, Python, package versions, timestamp),
* module import time (separate),
* three repeated predictor loads within one process (NOT true cold starts),
* warmed-up ``predict_email()`` latency for three small synthetic bodies,
* an INDICATIVE per-step breakdown (does not measure the exact call path),
* process working-set memory checkpoints via Windows APIs (if available).

It defines NO pass/fail latency thresholds and asserts no performance target.

Usage (from the repository root):
    machine-learning\\.venv\\Scripts\\python.exe machine-learning\\scripts\\benchmark_baseline_inference.py
"""

import ctypes
import importlib
import importlib.metadata as importlib_metadata
import math
import os
import platform
import statistics
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup (import the module by name so its import time can be measured)
# ---------------------------------------------------------------------------
ML_DIR = Path(__file__).resolve().parents[1]   # machine-learning/
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

MODULE_NAME = "src.models.baseline_inference"

# ---------------------------------------------------------------------------
# Benchmark configuration
# ---------------------------------------------------------------------------
REPETITIONS = 25          # measured warmed-up calls per body
LOAD_REPEATS = 3          # repeated predictor loads within this process
BREAKDOWN_REPETITIONS = 10  # indicative per-step timings per body

# Small synthetic bodies (no real email content). Tokens chosen from words
# already present in the fitted vocabulary; the third body has none.
BODIES = [
    ("B1_short", "the way you are"),
    ("B2_common", "please and you to not"),
    ("B3_no_known_tokens", "a b c"),
]

PACKAGES = [
    "shap", "xgboost", "scikit-learn", "numpy", "scipy", "joblib", "pandas",
]


# ---------------------------------------------------------------------------
# Helpers: environment metadata
# ---------------------------------------------------------------------------
def package_versions():
    versions = {}
    for name in PACKAGES:
        try:
            versions[name] = importlib_metadata.version(name)
        except Exception:  # noqa: BLE001
            versions[name] = "unavailable"
    return versions


def cpu_name():
    """Best-effort CPU name; falls back to platform.processor()."""
    if sys.platform.startswith("win"):
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            )
            value, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            winreg.CloseKey(key)
            if value:
                return value.strip()
        except Exception:  # noqa: BLE001, S110
            pass
    return platform.processor() or "unknown"


def total_ram_gb():
    """Total physical RAM via GlobalMemoryStatusEx (Windows); None if unavailable."""
    if not sys.platform.startswith("win") or not hasattr(ctypes, "windll"):
        return None
    try:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return None
        return status.ullTotalPhys / (1024 ** 3)
    except Exception:  # noqa: BLE001
        return None


def working_set_mb():
    """Current process working set via psapi; None if unavailable."""
    if not sys.platform.startswith("win") or not hasattr(ctypes, "windll"):
        return None
    try:
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
            wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        ok = psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(),
            ctypes.byref(counters),
            counters.cb,
        )
        if not ok:
            return None
        return counters.WorkingSetSize / (1024 ** 2)
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Helpers: statistics
# ---------------------------------------------------------------------------
def nearest_rank_percentile(values, percentile):
    """Nearest-rank percentile (values in ms)."""
    if not values:
        return float("nan")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = max(1, math.ceil(percentile / 100.0 * len(ordered)))
    return ordered[rank - 1]


def summarize(samples_ms):
    return {
        "n": len(samples_ms),
        "min": min(samples_ms),
        "median": statistics.median(samples_ms),
        "mean": statistics.mean(samples_ms),
        "p95": nearest_rank_percentile(samples_ms, 95),
        "max": max(samples_ms),
        "stdev": statistics.stdev(samples_ms) if len(samples_ms) > 1 else 0.0,
    }


def fmt_ms(value):
    return f"{value:.3f}"


# ---------------------------------------------------------------------------
# Benchmark sections
# ---------------------------------------------------------------------------
def print_metadata():
    print("## Environment metadata")
    print()
    print("| Item | Value |")
    print("|---|---|")
    print(f"| Timestamp | {datetime.now().isoformat(timespec='seconds')} |")
    print(f"| OS | {platform.platform()} |")
    print(f"| CPU | {cpu_name()} |")
    print(f"| CPU cores (logical) | {os.cpu_count()} |")
    ram = total_ram_gb()
    print(f"| Total RAM (GB) | {ram:.2f} |" if ram is not None else "| Total RAM (GB) | unavailable |")
    print(f"| Python | {sys.version.split()[0]} |")
    print(f"| Python executable | {sys.executable} |")
    print(f"| Working directory | {Path.cwd()} |")
    for name, version in package_versions().items():
        print(f"| {name} | {version} |")
    print()
    print(
        "> Reminder: record power/thermal conditions manually (AC vs battery, "
        "thermal throttling), since they affect laptop timing."
    )
    print()


def measure_import():
    print("## Module import time")
    print()
    start = time.perf_counter()
    module = importlib.import_module(MODULE_NAME)
    elapsed = time.perf_counter() - start
    print(
        f"- `import {MODULE_NAME}` took **{elapsed * 1000:.1f} ms** "
        "(includes importing shap/numpy/joblib)."
    )
    print()
    return module, elapsed


def measure_repeated_loads(module):
    print("## Repeated predictor loads (same process; NOT true cold starts)")
    print()
    print(
        "Each iteration clears the cached predictor via "
        "`get_predictor.cache_clear()` and reloads the vectorizer, model, and "
        "SHAP explainer."
    )
    print()
    durations = []
    for i in range(1, LOAD_REPEATS + 1):
        module.get_predictor.cache_clear()
        start = time.perf_counter()
        module.get_predictor()
        elapsed = time.perf_counter() - start
        durations.append(elapsed * 1000)
        print(f"- load {i}: {elapsed * 1000:.1f} ms")
    print()
    stats = summarize(durations)
    print("| loads | min (ms) | median (ms) | mean (ms) | max (ms) |")
    print("|---|---|---|---|---|")
    print(
        f"| {stats['n']} | {fmt_ms(stats['min'])} | {fmt_ms(stats['median'])} | "
        f"{fmt_ms(stats['mean'])} | {fmt_ms(stats['max'])} |"
    )
    print()


def measure_warm_latency(module):
    print("## Warmed-up predict_email() latency")
    print()
    print(
        f"One discarded warm-up call per body, then {REPETITIONS} measured "
        "calls. Includes TF-IDF transform, predict, predict_proba, raw margin, "
        "SHAP, and the additivity check."
    )
    print()
    print(
        "| body | n | min (ms) | median (ms) | mean (ms) | p95 (ms) | max (ms) | stdev (ms) |"
    )
    print("|---|---|---|---|---|---|---|---|")
    for label, body in BODIES:
        module.predict_email(body)  # discarded warm-up
        samples = []
        for _ in range(REPETITIONS):
            start = time.perf_counter()
            module.predict_email(body)
            samples.append((time.perf_counter() - start) * 1000)
        s = summarize(samples)
        print(
            f"| {label} | {s['n']} | {fmt_ms(s['min'])} | {fmt_ms(s['median'])} | "
            f"{fmt_ms(s['mean'])} | {fmt_ms(s['p95'])} | {fmt_ms(s['max'])} | "
            f"{fmt_ms(s['stdev'])} |"
        )
    print()


def measure_step_breakdown(module):
    print("## Indicative per-step breakdown")
    print()
    print(
        "> **Indicative only.** These timings call the model/explainer objects "
        "directly and do NOT measure the exact `predict_email()` call path; "
        "treat them as a rough attribution, not the component's latency."
    )
    print()
    print("| body | transform (ms) | predict (ms) | predict_proba (ms) | raw margin (ms) | SHAP (ms) |")
    print("|---|---|---|---|---|---|")
    predictor = module.get_predictor()
    for label, body in BODIES:
        X = predictor.vectorizer.transform([body])

        def timed(fn):
            fn()  # warm-up
            start = time.perf_counter()
            for _ in range(BREAKDOWN_REPETITIONS):
                fn()
            return (time.perf_counter() - start) / BREAKDOWN_REPETITIONS * 1000

        t_transform = timed(lambda: predictor.vectorizer.transform([body]))  # noqa: B023
        t_predict = timed(lambda: predictor.model.predict(X))  # noqa: B023
        t_proba = timed(lambda: predictor.model.predict_proba(X))  # noqa: B023
        t_margin = timed(lambda: predictor.model.predict(X, output_margin=True))  # noqa: B023
        t_shap = timed(lambda: predictor.explainer.shap_values(X))  # noqa: B023

        print(
            f"| {label} | {fmt_ms(t_transform)} | {fmt_ms(t_predict)} | "
            f"{fmt_ms(t_proba)} | {fmt_ms(t_margin)} | {fmt_ms(t_shap)} |"
        )
    print()


def print_memory():
    print("## Memory checkpoints (process working set)")
    print()
    print(
        "Measured with the Windows `GetProcessMemoryInfo` API. Values are "
        "approximate and machine/OS dependent."
    )
    print()
    current = working_set_mb()
    if current is None:
        print(
            "- Memory measurement **skipped**: the Windows psapi call is not "
            "available in this environment."
        )
        print()
        return None
    print("| checkpoint | working set (MB) |")
    print("|---|---|")
    print(f"| after warm-up | {current:.1f} |")
    print()
    return current


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("# BANTAI baseline inference - benchmark")
    print()
    print(
        "> Read-only benchmark of `src/models/baseline_inference.py`. "
        "No pass/fail thresholds are defined and no performance target is "
        "asserted. Results describe this machine only."
    )
    print()

    print_metadata()

    module, import_seconds = measure_import()  # noqa: RUF059
    if module is None:
        print("ERROR: module import failed; aborting benchmark.")
        return 1

    # Working set before any artifact load (after imports).
    before_load = working_set_mb()

    measure_repeated_loads(module)

    # Ensure the predictor is cached and warmed before latency measurement.
    module.warm_up()

    after_load = working_set_mb()
    if before_load is not None and after_load is not None:
        print("## Memory checkpoint: after artifact load")
        print()
        print("| checkpoint | working set (MB) | delta vs. post-import (MB) |")
        print("|---|---|---|")
        print(f"| after load | {after_load:.1f} | {after_load - before_load:+.1f} |")
        print()

    measure_warm_latency(module)
    measure_step_breakdown(module)
    print_memory()

    print("---")
    print()
    print(
        "*Measurements are single-process, in-process timings on this machine. "
        "They are not API-level or production latency figures. No inference "
        "behavior was changed and no artifacts were written.*"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
