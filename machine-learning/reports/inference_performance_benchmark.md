# Inference Performance Benchmark: TF-IDF + XGBoost Baseline

**Component:** `machine-learning/src/models/baseline_inference.py`
**Benchmark script:** `machine-learning/scripts/benchmark_baseline_inference.py`
**Run timestamp:** 2026-10-11T20:51:42 (local)
**Status:** one local, in-process measurement run. This is **not** a production
performance test; no pass/fail thresholds were defined and no target was set.

> All figures below are the exact observed output of a single run of the
> benchmark script. Nothing was re-run, estimated, or substituted.

## 1. Purpose and scope

Estimate the in-process cost of the reusable ML inference component on the
development laptop:

- how long the module takes to import,
- how long the predictor takes to (re)load the saved artifacts,
- warmed-up `predict_email()` latency on three small synthetic inputs,
- an indicative per-step attribution, and process working-set memory.

Out of scope: backend/API latency, HTTP request handling, concurrency, and any
production throughput or capacity claim.

## 2. Environment (verified by the run)

| Item | Value |
|---|---|
| Timestamp | 2026-10-11T20:51:42 |
| OS | Windows-10-10.0.19045-SP0 |
| CPU | 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz |
| CPU cores (logical) | 8 |
| Total RAM (GB) | 7.78 |
| Python | 3.9.13 |
| Python executable | `...\BANTAI_EmailThreatDetection\machine-learning\.venv\Scripts\python.exe` |
| Working directory | `D:\SCHOOL FILES\JUNIOR YEAR\BANTAI_EmailThreatDetection` |
| shap | 0.48.0 |
| xgboost | 2.1.4 |
| scikit-learn | 1.6.1 |
| numpy | 1.26.4 |
| scipy | 1.13.1 |
| joblib | 1.5.3 |
| pandas | 2.3.3 |

Power source and thermal state were **not recorded**; on a laptop these can
affect timing.

## 3. Module import time

- `import src.models.baseline_inference` took **28728.5 ms** (about 28.7 s) in
  this run. This includes importing `shap`, `numpy`, and `joblib`.

**Caveat:** import time was measured **once**, in a fresh process, on the first
import of `shap` and its dependencies. Cold disk cache and antivirus scanning
can dominate this number, so it should **not** be treated as representative
startup latency. It was not re-measured.

## 4. Repeated predictor loads (same process)

Each iteration calls `get_predictor.cache_clear()` and reloads the vectorizer,
model, and SHAP `TreeExplainer`.

| Iteration | Duration (ms) |
|---|---|
| load 1 | 825.8 |
| load 2 | 314.0 |
| load 3 | 311.8 |

| loads | min (ms) | median (ms) | mean (ms) | max (ms) |
|---|---|---|---|---|
| 3 | 311.793 | 314.027 | 483.884 | 825.832 |

**Caveat:** these are repeated loads **within one already-running process**,
not true cold starts. Python module imports, OS file cache, and already-imported
libraries were warm after the first iteration.

## 5. Warmed-up `predict_email()` latency

One discarded warm-up call per body, then 25 measured calls per body. Each call
includes TF-IDF transform, `predict`, `predict_proba`, raw margin, SHAP, and the
additivity check.

Synthetic bodies used (no real email content):

| Label | Body text |
|---|---|
| B1_short | `the way you are` |
| B2_common | `please and you to not` |
| B3_no_known_tokens | `a b c` |

| body | n | min (ms) | median (ms) | mean (ms) | p95 (ms) | max (ms) | stdev (ms) |
|---|---|---|---|---|---|---|---|
| B1_short | 25 | 18.038 | 19.160 | 22.036 | 44.817 | 57.383 | 9.144 |
| B2_common | 25 | 17.830 | 18.852 | 19.547 | 22.268 | 32.373 | 2.830 |
| B3_no_known_tokens | 25 | 18.117 | 19.462 | 23.852 | 69.564 | 83.191 | 15.948 |

In this run, medians were ~19 ms per single email. The `max`/`p95` outliers
(for example 83.191 ms on B3) show that occasional slower calls occur; the
spread should be read together with the medians.

## 6. Indicative per-step breakdown

> **Indicative only.** These timings call the model/explainer objects directly
> and do **not** measure the exact `predict_email()` call path. Treat them as a
> rough attribution, not as the component's latency.

10 repetitions per step per body:

| body | transform (ms) | predict (ms) | predict_proba (ms) | raw margin (ms) | SHAP (ms) |
|---|---|---|---|---|---|
| B1_short | 0.261 | 1.489 | 1.433 | 1.280 | 6.336 |
| B2_common | 0.260 | 1.315 | 1.289 | 1.298 | 6.131 |
| B3_no_known_tokens | 0.243 | 1.438 | 1.420 | 1.312 | 6.256 |

The breakdown suggests SHAP (~6.1-6.3 ms) and the four model calls
(~1.3-1.5 ms each) dominate; the TF-IDF transform is ~0.24-0.26 ms. These
parts do not sum exactly to the end-to-end medians in Section 5 because the
breakdown excludes validation, contribution mapping, and the additivity check,
and because it is a separate measurement.

## 7. Memory checkpoints (process working set)

Measured with the Windows `GetProcessMemoryInfo` API:

| checkpoint | working set (MB) | delta |
|---|---|---|
| after artifact load | 170.3 | +27.3 vs. post-import |
| after warm-up | 171.7 | +1.4 vs. after load |

**Limitations:** these are single snapshots of the process working set, not
peak or steady-state memory. Windows page movement, lazy allocation, and
garbage collection make the values approximate; they should not be read as an
exact memory requirement.

## 8. What these numbers are not

- Not backend, FastAPI, or API-level latency.
- Not a production performance test or capacity estimate.
- Not a validation or accuracy measurement.
- No pass/fail threshold was defined, and no performance target is claimed.

## 9. Limitations

- **One run only.** Single execution; no repeated benchmark sessions.
- **Import time measured once** and clearly affected by first-run effects
  (see Section 3).
- **Repeated loads are not true cold starts** (see Section 4).
- **Only three small synthetic bodies**, each dominated by a few tokens; real
  emails of different length/structure may behave differently.
- **Small repetition count:** 25 warmed-up calls per body and 10 repetitions
  per step, which is enough for a rough distribution but not for tight
  confidence intervals.
- **Variable machine conditions:** laptop power state, thermal throttling,
  background processes, and OS caching were not controlled or recorded.
- Results describe **this machine and environment only**.

## 10. Reproducing

From the repository root:

```
machine-learning\.venv\Scripts\python.exe machine-learning\scripts\benchmark_baseline_inference.py
```

The script is read-only: it loads the existing artifacts, writes no files, and
defines no performance thresholds. It never uses the held-out test set, never
processes the full dataset, and never retrains or overwrites artifacts.

## Related documents

- `machine-learning/reports/baseline_experiment_report.md` - baseline training/validation
- `machine-learning/reports/baseline_test_evaluation.md` - held-out test evaluation
- `machine-learning/reports/ml_inference_handoff.md` - backend integration handoff
- `machine-learning/reports/shap_prototype_notes.md` - SHAP prototype notes

---

*Recorded from the actual output of one benchmark run on 2026-10-11. No values
were estimated, invented, or replaced.*
