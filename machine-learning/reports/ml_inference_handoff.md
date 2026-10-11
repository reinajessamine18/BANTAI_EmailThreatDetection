# ML Inference Handoff: TF-IDF + XGBoost Baseline

**Audience:** the backend developer integrating the BANTAI ML component.

**Read this first:** backend integration **has not been implemented**. The ML
component described here exists and was tested on this machine, but the module
and its tests are **not yet committed** (currently untracked), and the model
artifacts are **gitignored**. Only the facts below are verified; everything
about how the backend should call the component is labeled as a **proposal**.

**Related documents** (all under `machine-learning/reports/`):
`baseline_experiment_report.md`, `baseline_test_evaluation.md`,
`shap_prototype_notes.md`, `dataset_preparation_manifest.json`.
The SHAP prototype that the component's SHAP logic mirrors is
`machine-learning/explain_one_email.py`.

---

## 1. Purpose and scope

The reusable inference component is:

`machine-learning/src/models/baseline_inference.py`

It performs **single-email inference** with the saved baseline artifacts:

- classifies one email body as **Safe (label 0)** or **Phishing (label 1)**,
- returns Safe and Phishing probabilities,
- returns SHAP token contributions for the phishing-class raw margin.

It is strictly read-only: it never trains, retunes, or writes artifacts,
datasets, or configuration.

**Out of scope (by design):** threat scores (0-100), risk tiers, and any
recommendation or action guidance. Those are intentionally not part of this
ML component.

## 2. Availability and repository status

| Item | Status (verified) |
|---|---|
| `src/models/baseline_inference.py` | Exists; **untracked** (inside `?? machine-learning/src/`) |
| `tests/test_baseline_inference.py` | Exists; **untracked** (inside `?? machine-learning/tests/`) |
| Model artifacts | Exist locally; **gitignored** via `.gitignore` rule `machine-learning/artifacts/baseline/` |
| `bantai-backend/` | Empty (`.gitkeep` only); no FastAPI app exists yet |

Consequences to resolve with the ML owner before integration:

1. Commit the module and tests to the shared branch; until then a teammate
   cannot import them from Git.
2. Agree an artifact **delivery strategy** (copy the `.pkl` files to the
   backend environment, or regenerate them with `train_baseline.py` on a
   machine that has the dataset).

## 3. Dependencies and verified versions

Verified by inspecting the project environment
`machine-learning/.venv/Scripts/python.exe`:

| Component | Verified version |
|---|---|
| Python | 3.9.13 |
| shap | 0.48.0 |
| xgboost | 2.1.4 |
| scikit-learn | 1.6.1 |
| numpy | 1.26.4 |
| scipy | 1.13.1 |
| joblib | 1.5.3 |
| pandas | 2.3.3 |

Notes:

- The inference module itself imports only `joblib`, `numpy`, and `shap`
  (plus the standard library). It does **not** import pandas at runtime.
- Loading the artifacts requires `scikit-learn` and `xgboost` to be importable
  in the backend process, because the `.pkl` files contain
  `TfidfVectorizer` / `XGBClassifier` objects.
- **There is no `requirements.txt`, `pyproject.toml`, or `setup.py` anywhere in
  the repository** (verified). The backend team must decide how to pin the
  environment.
- The backend's own Python version is **not determined by this document**;
  version compatibility with the serialized artifacts is a backend decision.

## 4. Import and usage

The package root is `machine-learning/`; put it on `sys.path` (this is exactly
what the test script does) and import the module:

```python
# PROPOSAL: configure this path per environment (env var or repo-relative);
# both the ML module and the tests resolve everything from their own location.
import os
import sys
from pathlib import Path

ml_dir = Path(os.environ.get("BANTAI_ML_DIR", Path(__file__).resolve().parents[2] / "machine-learning"))
sys.path.insert(0, str(ml_dir))

from src.models.baseline_inference import (
    MAX_BODY_CHARS,
    InferenceError,
    get_predictor,
    predict_email,
    warm_up,
)
```

Usage:

```python
warm_up()  # optional; preloads vectorizer + model + SHAP explainer (recommended once at startup)

result = predict_email(body, top_k=10)  # body: str; top_k default is 10
```

Verified behavior:

- `predict_email(body, top_k=10) -> PredictionResult` is the convenience
  wrapper; `get_predictor().predict(body, top_k)` does the same.
- `get_predictor()` returns a cached `BaselinePredictor` instance.
  `BaselinePredictor.load(artifacts_dir=...)` can load the artifacts from a
  custom directory if the backend ships them somewhere other than the default.
- The predictor is cached with `functools.lru_cache(maxsize=1)`: the
  vectorizer, model, and one SHAP `TreeExplainer` are loaded **once per
  process** and reused.
- `warm_up()` takes no arguments and returns `None`.

## 5. Result fields

### `PredictionResult` (frozen dataclass)

| Field | Type | Meaning |
|---|---|---|
| `label` | `int` | Predicted class: `0` = Safe, `1` = Phishing |
| `classification` | `str` | `"Safe"` or `"Phishing"` |
| `safe_probability` | `float` | Model probability for class 0 (probability space) |
| `phishing_probability` | `float` | Model probability for class 1 (probability space) |
| `shap_output_space` | `str` | Reported SHAP space; when returned it is `"raw model output (binary XGBoost margin/log-odds)"` |
| `shap_base_value` | `float` | SHAP base value (raw-margin / log-odds space) |
| `raw_margin` | `float` | Raw model output (log-odds margin) |
| `additivity_residual` | `float` | `abs(raw_margin - (shap_base_value + sum of all SHAP values))` |
| `top_contributions` | `tuple[TokenContribution, ...]` | Top tokens ranked by absolute contribution |

### `TokenContribution` (frozen dataclass)

| Field | Type | Meaning |
|---|---|---|
| `token` | `str` | TF-IDF vocabulary token that is present in this email |
| `contribution` | `float` | SHAP value for that token (raw-margin / log-odds space) |
| `direction` | `str` | `"toward_phishing"` (positive) or `"toward_safe"` (negative) |
| `tfidf_value` | `float` | TF-IDF weight of the token in this email |

Only features present in the submitted email are included, and tokens with a
zero contribution are omitted. `top_k` limits how many are returned.

## 6. Probabilities vs raw-margin SHAP contributions

These are two different spaces and must not be conflated:

- `safe_probability` and `phishing_probability` come from the model's
  `predict_proba`; they are probabilities and sum to approximately 1.
- `shap_base_value`, `raw_margin`, `additivity_residual`, and every
  `TokenContribution.contribution` are in the model's **raw-margin
  (log-odds)** space. They are **not** probabilities, do not sum to 100%,
  and must not be presented as percentages.
- Additivity is enforced at runtime: the component verifies
  `shap_base_value + sum(SHAP values) == raw_margin` within a tolerance of
  `1e-5`, and raises `InferenceError` if the check fails or if the SHAP
  output space cannot be verified as raw margin.

## 7. Input limits, exceptions, privacy, artifacts

### Input limits (verified in code)

| Rule | Behavior |
|---|---|
| `body` must be `str` | `TypeError` otherwise |
| Empty or whitespace-only body | `ValueError` |
| `body` longer than `MAX_BODY_CHARS` (200,000) | `ValueError`; input is **never silently truncated** |
| `top_k` must be a positive `int` | `ValueError` otherwise (default `10`) |

### Exceptions (verified in code)

| Condition | Exception |
|---|---|
| Body type/empty/length, invalid `top_k` | `TypeError` / `ValueError` |
| Artifact file missing | `FileNotFoundError` (message contains the artifact path) |
| SHAP computation failure | `InferenceError` (message contains the exception type) |
| SHAP output space not verified as raw margin | `InferenceError` |
| Unsupported SHAP shapes / feature-count mismatch / unexpected label / missing classes | `InferenceError` |
| Additivity residual above `1e-5` | `InferenceError` |

The module **fails loudly instead of returning an apparently complete
explanation** when the SHAP result cannot be verified.

### Privacy behavior (verified in code)

- The module never prints, logs, or returns the email body, and no exception
  message contains body text or excerpts (lengths, paths, shapes, and metric
  values only).
- The caller is responsible for not logging request bodies.

### Local artifact paths (verified; currently gitignored)

```
machine-learning/artifacts/baseline/tfidf_vectorizer.pkl
machine-learning/artifacts/baseline/xgboost_model.pkl
machine-learning/artifacts/baseline/experiment_config.json
```

Recorded artifact configuration (`experiment_config.json`): TF-IDF
`max_features=50000, lowercase=true, stop_words=null, ngram_range=[1,1]`;
XGBoost `random_state=42, n_jobs=1, eval_metric=logloss, n_estimators=100`.

## 8. Running the ML tests

Command (from the repository root, using the project venv):

```
machine-learning\.venv\Scripts\python.exe machine-learning\tests\test_baseline_inference.py
```

- Dependency-free: no pytest or extra packages required.
- Uses a few validation examples only (never the held-out test set), one at a
  time; does not modify artifacts or datasets.
- Skips gracefully with a clear message if local artifacts or the validation
  CSV are missing.
- **Last recorded run: 9 PASS, 0 FAIL, 0 SKIP (exit code 0).** This is the
  last recorded result of that run; it was **not** re-executed while writing
  this document, so treat it as a recorded result, not a new verification.

The 9 recorded checks were: row 0 (Phishing) label/probability/output
space/residual; row 1 (Safe) label/probability/residual; probabilities sum to
~1; top-contribution schema/order/direction; contributions are present
features; predictor caching; input validation; `MAX_BODY_CHARS` guard with no
body leakage in errors; and equivalence with the `explain_one_email.py`
prototype on row 0.

## 9. Limitations and decisions for the backend team

**Known limitations (verified):**

- No backend integration exists; `bantai-backend/` is empty.
- The module and tests are untracked, so they are not available through the
  shared Git branch yet.
- Model artifacts are gitignored; without an agreed delivery strategy the
  component cannot load them on another machine.
- There is no dependency file in the repository.
- No latency, throughput, or memory measurements have been recorded for the
  inference path.
- SHAP is always computed by a prediction; there is no optional switch.

**Decisions that require backend coordination (proposals only, not implemented):**

1. How the backend gets `machine-learning/` on `sys.path` (environment
   variable vs repo-relative path vs packaging as an installable module).
2. Where dependency pins live and which exact versions the backend
   environment uses.
3. The API contract: endpoint path, request field names, and whether `top_k`
   is exposed to clients.
4. How dataclasses are converted to JSON (for example
   `dataclasses.asdict(...)`) and which schema library the backend uses.
5. Error-to-HTTP mapping for `TypeError` / `ValueError` / `InferenceError` /
   `FileNotFoundError`, and whether validation errors must strip the echoed
   input body.
6. Startup policy: preload at application start (`warm_up()`) versus lazy
   load, and what to do if artifacts are missing.
7. Whether the response should reuse database naming
   (for example `malicious_probability`) and how results are persisted.
8. Whether a latency benchmark is needed and where it lives.

---

*Prepared from verified code and recorded reports only. No inference was run,
no dependencies were installed, and no artifacts or datasets were modified
while preparing this handoff.*
