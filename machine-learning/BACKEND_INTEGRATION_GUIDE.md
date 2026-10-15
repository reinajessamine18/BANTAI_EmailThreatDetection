# BANTAI Backend Integration Guide

**Audience:** the backend teammate who will call the BANTAI ML component from
the API layer.
**Companion document:** `reports/ml_inference_handoff.md` (short technical
reference for the same component). This guide is the practical, step-by-step
tutorial: setup, artifact installation, usage, proposed integration, testing,
and troubleshooting. Read both; this guide links to the handoff instead of
repeating it.

**Labels used throughout:**

| Label | Meaning |
|---|---|
| **[Verified]** | Confirmed against the actual code, artifacts, or recorded reports in this repository. |
| **[Proposal]** | A suggestion for the backend. Not implemented, not agreed, not tested. |
| **[Unresolved]** | Needs a team decision or information that does not exist in the repository yet. |

---

## 1. System overview

### 1.1 What the ML component does

Given one email body (plain text), the component returns:

1. a class label, `0 = Safe` or `1 = Phishing`;
2. probabilities for both classes (probability space);
3. SHAP token contributions that explain the phishing-class raw margin
   (log-odds space).

### 1.2 The pipeline [Verified]

```
email text (str)
    |
    v
TF-IDF vectorizer (already fitted, loaded from tfidf_vectorizer.pkl)
    |  transform only - never fit on new data
    v
sparse feature vector (1 x 50,000)
    |
    v
XGBoost classifier (already trained, loaded from xgboost_model.pkl)
    |                     \
    | predict_proba        \ predict(output_margin=True)
    v                       v
P(Safe), P(Phishing)     raw margin (log-odds)
                              |
                              v
                    SHAP TreeExplainer (one email)
                              |
                              v
        base value + per-token contributions (log-odds)
                              |
                              v
          additivity check: base + sum(SHAP) == raw margin
                     (tolerance 1e-5, else InferenceError)
```

### 1.3 Label meanings [Verified]

| Label | Meaning |
|---|---|
| `0` | Safe |
| `1` | Phishing |

The model's class order is read from `model.classes_` at load time; the code
does not assume column order.

### 1.4 Probabilities vs SHAP contributions [Verified]

This distinction matters and must survive into the API and the UI:

- `safe_probability` and `phishing_probability` come from
  `predict_proba`. They are probabilities, they sum to about 1, and they are
  the only numbers suitable for a user-facing "confidence" display.
- `shap_base_value`, `raw_margin`, `additivity_residual`, and every
  `TokenContribution.contribution` are in **raw-margin (log-odds)** units.
  They are **not** percentages, do **not** sum to 100 percent, and must not be
  converted or displayed as "how much percent this word contributed".
- A positive contribution pushes the margin **toward Phishing**; a negative
  contribution pushes **toward Safe**.
- SHAP explains how the model used its features for this email. It is not
  proof that an email is malicious and not a statement about cause.

---

## 2. Repository and branch setup

### 2.1 Get the code [Verified]

The ML work is committed and pushed on the feature branch:

- Branch: `feature/ml-baseline`
- Latest commit at the time of writing: `4857a9f`
  ("feat(ml): add reusable baseline inference and evaluation")
- The same branch exists on the remote as `origin/feature/ml-baseline`.

Teammates can either wait for the branch to be merged into `main`, or work
against the feature branch directly:

```bash
git clone https://github.com/reinajessamine18/BANTAI_EmailThreatDetection.git
cd BANTAI_EmailThreatDetection
git fetch origin
git switch feature/ml-baseline        # or: git switch main  (after it is merged)
```

If the branch is already merged, `main` is enough. Ask the ML owner which
state the shared branch is in before starting.

### 2.2 What Git tracks, and what it deliberately excludes [Verified]

Tracked ML files include the modules, tests, scripts, and reports:

```
machine-learning/explain_one_email.py
machine-learning/evaluate_baseline_test.py
machine-learning/prepare_dataset.py
machine-learning/train_baseline.py
machine-learning/verify_baseline.py
machine-learning/src/__init__.py
machine-learning/src/models/__init__.py
machine-learning/src/models/baseline_inference.py
machine-learning/tests/test_baseline_inference.py
machine-learning/tests/test_baseline_inference_robustness.py
machine-learning/scripts/benchmark_baseline_inference.py
machine-learning/reports/*.md
machine-learning/reports/dataset_preparation_manifest.json
```

Intentionally **not** tracked (ignored by `.gitignore` or excluded locally):

| Path | Why |
|---|---|
| `machine-learning/data/raw/` | 358 MB dataset; too large for Git |
| `machine-learning/data/processed/` | generated splits |
| `machine-learning/.venv/` | local virtual environment (never share) |
| `machine-learning/artifacts/baseline/` | trained model artifacts (delivered separately; see section 4) |
| `misclassified_row.json` | contains a full email body; local only |
| `__pycache__/`, `*.py[cod]` | generated Python files |
| `.vscode/` | personal editor settings (do not commit) |

**Important:** a fresh clone has **no model artifacts and no datasets**. The
ML code will import, but prediction/tests that need artifacts will fail or
skip until section 4 is done.

### 2.3 Deferred ML files [Verified]

A few ML files exist locally on the ML developer's machine but are
intentionally **not** committed yet, so do not expect them in the branch:

- `machine-learning/diagnose_misclassified.py` (depends on the local
  `misclassified_row.json`, which contains email content)
- `machine-learning/scripts/__init__.py`, `machine-learning/src/data/`,
  `machine-learning/src/features/`, `machine-learning/src/utils/`
  (empty scaffolding, not needed for the documented imports)

---

## 3. Python environment setup

### 3.1 Required versions [Verified]

Verified in the ML development environment:

| Component | Version |
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

- **Use Python 3.9.x** to match the environment where the artifacts were
  produced. Other versions may work but have not been verified. [Unresolved -
  the team may test and agree on a supported range.]
- `scikit-learn` and `xgboost` must be installed **in the backend process**
  because the `.pkl` artifacts contain `TfidfVectorizer` and `XGBClassifier`
  objects. Missing them causes an error when the artifacts are loaded.
- `pandas` is only needed if you run the ML scripts/tests that read CSV files;
  the inference module itself does not import pandas.
- There is **no `requirements.txt`** in the repository yet. [Unresolved -
  decide where backend dependency pins live.]

### 3.2 Create your own environment (do not reuse the ML developer's)

The ML developer's `machine-learning/.venv/` is personal and is ignored by
Git. Create a separate environment for the backend:

**Windows Command Prompt:**

```bat
cd D:\path\to\BANTAI_EmailThreatDetection
py -3.9 -m venv bantai-backend\.venv
bantai-backend\.venv\Scripts\activate
python -m pip install --upgrade pip
pip install fastapi "uvicorn[standard]" pydantic joblib==1.5.3 numpy==1.26.4 scipy==1.13.1 scikit-learn==1.6.1 xgboost==2.1.4 shap==0.48.0
```

**Git Bash (Windows):**

```bash
cd /d/path/to/BANTAI_EmailThreatDetection
python -m venv bantai-backend/.venv
source bantai-backend/.venv/Scripts/activate
python -m pip install --upgrade pip
pip install fastapi "uvicorn[standard]" pydantic joblib==1.5.3 numpy==1.26.4 scipy==1.13.1 scikit-learn==1.6.1 xgboost==2.1.4 shap==0.48.0
```

**Expected result:** `python -c "import sklearn, xgboost, shap, joblib, numpy"` completes with no output (no error).

**Common mistakes:**

- Reusing `machine-learning/.venv` - it is the ML developer's environment and
  is not shared; create your own.
- Installing only `shap` - loading the artifacts also needs `scikit-learn`
  and `xgboost`.
- Using a different Python major version without checking artifact loading.
- Adding `httpx` for API tests: needed for FastAPI `TestClient`, but treat it
  as a dev-only dependency. [Proposal]

---

## 4. Model artifact installation

### 4.1 Expected location and filenames [Verified]

The component loads exactly these files:

```
machine-learning/artifacts/baseline/tfidf_vectorizer.pkl
machine-learning/artifacts/baseline/xgboost_model.pkl
machine-learning/artifacts/baseline/experiment_config.json
```

If you need a different folder, `BaselinePredictor.load(artifacts_dir=...)`
accepts a custom directory. [Verified]

### 4.2 How to obtain the artifacts [Proposal]

The artifacts are **not stored in Git** (the folder is gitignored). The team
delivers them through the **trusted private Google Drive folder**:

1. Ask the team for the link to the folder (share it only with group members
   and the adviser). [Unresolved - the link is not recorded in the repository.]
2. Download the three files.
3. Place them exactly at the paths in section 4.1.
4. Never upload artifacts to a public location; they are model IP of the
   project.

### 4.3 Verify the files (checksums) [Verified - values verified against the files]

Always verify after copying. A corrupted or partial file can load with
mysterious errors later.

**Windows Command Prompt / PowerShell:**

```bat
Get-FileHash -Algorithm SHA256 machine-learning\artifacts\baseline\tfidf_vectorizer.pkl
Get-FileHash -Algorithm SHA256 machine-learning\artifacts\baseline\xgboost_model.pkl
Get-FileHash -Algorithm SHA256 machine-learning\artifacts\baseline\experiment_config.json
```

**Git Bash:**

```bash
sha256sum machine-learning/artifacts/baseline/tfidf_vectorizer.pkl
sha256sum machine-learning/artifacts/baseline/xgboost_model.pkl
sha256sum machine-learning/artifacts/baseline/experiment_config.json
```

**Expected SHA-256 values** (verified against the exact files on the ML
developer's machine on 2026-10-11):

| File | SHA-256 |
|---|---|
| `tfidf_vectorizer.pkl` | `3826E5BF3A1FD7937E2DF80411CAB5E015F5D3E42C250644CF4FBFE146720AD6` |
| `xgboost_model.pkl` | `48ADED9146EC2D95E6804DBE4C40E86DB6F4DEEAA6C4A813D045264ADF5C614D` |
| `experiment_config.json` | `19EF4E53F96F8A461314C5B77952DC29AA554766D2E27446627825FD7A9E0B2E` |

Also verified file sizes: `tfidf_vectorizer.pkl` 1,646,001 bytes;
`xgboost_model.pkl` 278,642 bytes; `experiment_config.json` 748 bytes.

If your hashes differ, do **not** continue - re-copy the files and ask the ML
owner. [Unresolved - these values are not yet recorded in a committed report;
the team should record the canonical hashes next to the Google Drive link.]

**Dataset checksum (for reference only):** the preparation manifest records
`Balanced_Dataset.csv` SHA-256 as
`ac83bf86beabbff654848e6f94389c0723d100865a3f7f2fc4299607c85c7569`
(`machine-learning/reports/dataset_preparation_manifest.json`). You do not
need the dataset just to run inference.

### 4.4 What `experiment_config.json` contains [Verified]

It records how the baseline was produced (TF-IDF
`max_features=50000, lowercase=true, stop_words=null, ngram_range=[1,1]`;
XGBoost `random_state=42, n_jobs=1, eval_metric=logloss, n_estimators=100`)
plus the recorded validation metrics. The inference component itself does not
need to read this file to predict; it is provenance documentation.

---

## 5. Using the ML interface

### 5.1 The real API [Verified]

From `machine-learning/src/models/baseline_inference.py`:

| Name | Purpose |
|---|---|
| `predict_email(body: str, top_k: int = 10) -> PredictionResult` | Convenience function: loads the cached predictor and predicts one email. |
| `warm_up() -> None` | Preloads the vectorizer, model, and SHAP explainer once (good at API startup). |
| `get_predictor() -> BaselinePredictor` | Returns the process-wide cached predictor. |
| `BaselinePredictor.load(artifacts_dir=None)` | Loads artifacts from the default or a custom directory. |
| `InferenceError` | Raised when SHAP computation fails or its output cannot be verified. |

Place `machine-learning/` on `sys.path`, then import. [Verified]

### 5.2 Minimal verified example [Verified against the module]

```python
import sys
from pathlib import Path

# Adjust to wherever the repository lives in your environment.
ML_DIR = Path("D:/path/to/BANTAI_EmailThreatDetection/machine-learning")
sys.path.insert(0, str(ML_DIR))

from src.models.baseline_inference import (  # noqa: E402
    MAX_BODY_CHARS,
    InferenceError,
    get_predictor,
    predict_email,
    warm_up,
)

warm_up()  # optional; preloads artifacts + explainer once

# Use a SHORT TEST STRING here, not a real private email.
result = predict_email("please verify your account and click the link", top_k=10)

print(result.label)                # 0 or 1
print(result.classification)       # "Safe" or "Phishing"
print(result.phishing_probability) # probability space
print(result.shap_base_value)      # raw-margin (log-odds) space
print(result.raw_margin)           # raw-margin (log-odds) space
print(result.additivity_residual)  # should be <= 1e-5
for c in result.top_contributions:
    print(c.token, c.contribution, c.direction, c.tfidf_value)
```

Do **not** print real email bodies in logs or examples.

### 5.3 Result fields [Verified]

`PredictionResult` (frozen dataclass):

| Field | Type | Meaning |
|---|---|---|
| `label` | int | 0 = Safe, 1 = Phishing |
| `classification` | str | `"Safe"` or `"Phishing"` |
| `safe_probability` | float | `predict_proba` for class 0 (probability space) |
| `phishing_probability` | float | `predict_proba` for class 1 (probability space) |
| `shap_output_space` | str | `"raw model output (binary XGBoost margin/log-odds)"` when returned |
| `shap_base_value` | float | SHAP base value (raw-margin space) |
| `raw_margin` | float | Model raw output (log-odds) |
| `additivity_residual` | float | `abs(raw_margin - (base + sum of SHAP))` |
| `top_contributions` | tuple of `TokenContribution` | Top present-feature tokens by absolute contribution |

`TokenContribution`:

| Field | Type | Meaning |
|---|---|---|
| `token` | str | TF-IDF token present in the email |
| `contribution` | float | SHAP value (raw-margin space) |
| `direction` | str | `"toward_phishing"` (positive) or `"toward_safe"` (negative) |
| `tfidf_value` | float | TF-IDF weight in this email |

### 5.4 Caching and startup [Verified]

- `get_predictor()` is cached with `functools.lru_cache(maxsize=1)`: the
  vectorizer, model, and one SHAP `TreeExplainer` load **once per process**.
- Call `warm_up()` once when the API starts so the first user request does not
  pay the load cost.
- `get_predictor().cache_clear()` exists (used by the benchmark); do not call
  it in production code. [Verified]

### 5.5 Input validation [Verified]

| Input | Behavior |
|---|---|
| Not a `str` | raises `TypeError` |
| Empty or whitespace-only | raises `ValueError` |
| Longer than `MAX_BODY_CHARS` (200,000) | raises `ValueError`; input is **never truncated** |
| `top_k` not a positive integer | raises `ValueError` |

### 5.6 Error behavior [Verified]

| Situation | Raised |
|---|---|
| Missing artifact file | `FileNotFoundError` |
| SHAP computation failure | `InferenceError` (message includes the exception type) |
| SHAP output space not verifiable as raw margin | `InferenceError` |
| Unexpected SHAP shape / feature count / label | `InferenceError` |
| Additivity residual above `1e-5` | `InferenceError` |

Error messages never contain the email body. The component fails loudly
rather than returning an apparently complete explanation.

### 5.7 Do not reimplement the ML parts [Required]

Do not re-implement TF-IDF, XGBoost, or SHAP in the backend. Call the module.
Duplicating the pipeline risks inconsistent features and explanations and
violates the project's component boundaries.

---

## 6. Backend integration [Proposals only]

### 6.1 Current backend state [Verified]

**There is no backend implementation in the repository.** `bantai-backend/`
contains only a `.gitkeep` file: no FastAPI app, no routes, no request or
response models, no API contract, and no `requirements.txt`. The frontend
also has **no API client** (no `fetch`/`axios`/`/api/` usage was found in
`bantai-frontend/src`).

Everything in this section is therefore a **proposal** to discuss with the
backend teammate. None of it exists yet.

### 6.2 Proposed integration sequence [Proposal]

1. Create the backend environment (section 3.2).
2. Obtain and verify the artifacts (section 4).
3. Add a small bootstrap that puts `machine-learning/` on `sys.path`
   (environment variable or repository-relative path).
4. Load the predictor once at application startup with `warm_up()`.
5. Expose one endpoint that accepts an email body and returns the structured
   result.
6. Convert the frozen dataclasses to JSON (for example
   `dataclasses.asdict(result)`; convert the contributions tuple to a list).
7. Map exceptions to responses and never echo the input body in errors.
8. Add backend tests (section 8.3).

### 6.3 Illustrative (proposed) API shape [Proposal - not implemented]

The following is a sketch only. Do not treat these names or shapes as an
existing contract; agree them first.

```python
# PROPOSAL ONLY - not implemented, not tested, not part of the repository.
from dataclasses import asdict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

import sys
from pathlib import Path

# PROPOSAL: configure this path per environment (env var or repo-relative).
ML_DIR = Path(__file__).resolve().parents[2] / "machine-learning"
sys.path.insert(0, str(ML_DIR))

from src.models.baseline_inference import (  # noqa: E402
    MAX_BODY_CHARS,
    InferenceError,
    predict_email,
    warm_up,
)

app = FastAPI()


@app.on_event("startup")  # PROPOSAL: modern replacements (lifespan) also work.
def _startup() -> None:
    warm_up()


class AnalyzeRequest(BaseModel):          # PROPOSAL
    body: str = Field(min_length=1, max_length=MAX_BODY_CHARS)


@app.post("/analyze")                     # PROPOSAL: path and method not agreed
def analyze(request: AnalyzeRequest):
    try:
        result = predict_email(request.body)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid email body")
    except InferenceError:
        raise HTTPException(status_code=500, detail="explanation could not be verified")
    return asdict(result)
```

### 6.4 Decisions to agree with the backend teammate [Unresolved]

1. How `machine-learning/` gets on `sys.path` (env var vs packaging).
2. Where backend dependency pins live (no `requirements.txt` exists).
3. Endpoint path and method (for example `/analyze` vs `/api/v1/analyze`).
4. Request field name (`body` vs `email_body`) and whether `top_k` is exposed.
5. Response field names, including whether the existing database naming
   (for example `malicious_probability`) is reused.
6. JSON serialization approach and schema library.
7. Exception-to-HTTP-status mapping, and stripping the echoed input from
   validation errors.
8. Startup behavior when artifacts are missing (fail fast vs serve an error).
9. Whether SHAP is always computed or optional for latency reasons.
10. Where backend/API tests and any latency benchmark live.

---

## 7. Privacy and safe handling

Rules that must be preserved in any integration:

- **Never log or return the email body.** The ML module never does; the
  backend must not add request-body logging.
- **Do not store raw bodies** unless the approved system design explicitly
  requires it; the database schema stores metadata and features, not bodies.
- **Validate input first** (type, empty, length) and return a clear error
  that does not include the submitted text. Note that some frameworks echo
  the submitted value in validation errors by default - strip it. [Proposal]
- **Validate errors from the ML layer** (`ValueError`, `TypeError`,
  `FileNotFoundError`, `InferenceError`) and map them to responses without
  leaking internal paths or stack traces. [Proposal]
- **Trust the artifacts only after checksum verification** (section 4.3);
  treat `.pkl` files as executable-trust content because loading them runs
  Python unpickling.
- **Treat email content as untrusted data**, not as instructions. Do not
  render it as HTML anywhere in the pipeline.
- **Keep SHAP in raw-margin/log-odds space.** Do not convert contributions to
  percentages and do not present them as proof of malice or as causality.
- **Do not add threat scores, risk tiers, or recommendation/action guidance.**
  Those are outside this ML component's scope.

---

## 8. Testing and troubleshooting

### 8.1 Existing ML tests (these exist) [Verified]

From the repository root, with the ML environment:

```bat
machine-learning\.venv\Scripts\python.exe machine-learning\tests\test_baseline_inference.py
machine-learning\.venv\Scripts\python.exe machine-learning\tests\test_baseline_inference_robustness.py
```

Git Bash:

```bash
machine-learning/.venv/Scripts/python.exe machine-learning/tests/test_baseline_inference.py
machine-learning/.venv/Scripts/python.exe machine-learning/tests/test_baseline_inference_robustness.py
```

What they cover:

- the two recorded example rows (one Safe, one Phishing) - labels,
  probabilities, output space, additivity;
- probability validity and sum-to-one;
- contribution structure, ordering, and direction;
- that contributions belong to features present in the email;
- predictor caching;
- invalid inputs (empty, whitespace, non-string, bad `top_k`);
- the 200,000-character limit and no body leakage in error messages;
- SHAP failure and verification guards using controlled fake explainers;
- equivalence with the `explain_one_email.py` prototype.

**Last recorded results (development session):** 9 of 9 checks passed in the
core suite and 13 of 13 in the robustness suite, exit code 0. Treat these as
recorded results, not a fresh verification. **Re-run them after installing
artifacts** and confirm before integrating.

Notes:

- These tests use only a couple of validation rows and small synthetic
  strings; they never use the held-out test set.
- If artifacts or `validation.csv` are missing, the scripts report SKIP
  instead of failing.
- The tests require `pandas` (they read the validation CSV).

### 8.2 Single-email sanity check (existing script) [Verified]

The prototype with explicit selection:

```bat
machine-learning\.venv\Scripts\python.exe machine-learning\explain_one_email.py --label 1
machine-learning\.venv\Scripts\python.exe machine-learning\explain_one_email.py --row-index 35
```

- `--label 1` explains the first Phishing-labeled validation row.
- `--row-index N` explains an exact 0-based positional row.
- No arguments = original behavior (first Safe row).
- It prints labels, probabilities, the SHAP output space, the additivity
  result, and top tokens; it does not print the body.

### 8.3 Backend/API integration tests [Proposal - do not exist yet]

There are **no** backend or API tests in the repository. When the backend is
implemented, add tests that:

- POST a short synthetic body and assert the response schema;
- assert the response never contains the submitted body text;
- assert empty/over-length inputs produce the agreed error status that does
  not echo the body;
- assert probabilities are in [0, 1] and sum to about 1;
- assert contributions are present and direction matches sign.

### 8.4 Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `FileNotFoundError: vectorizer artifact not found` | artifacts not installed | complete section 4 |
| `ImportError` / `ModuleNotFoundError: src` | `machine-learning/` not on `sys.path` | add it before importing (section 5.2) |
| Unpickling/version error loading `.pkl` | wrong `scikit-learn`/`xgboost` versions | install the verified versions (section 3.2) |
| `ValueError: email body is empty` | empty or whitespace-only input | validate client input first |
| `ValueError: ... exceeds MAX_BODY_CHARS` | body longer than 200,000 characters | reject at the API boundary; never truncate silently |
| `InferenceError` | SHAP failed or the additivity/output-space check failed | return an error to the caller; do not fabricate an explanation |
| `TypeError` | non-string input reached the module | fix the request schema |
| Tests report SKIP | artifacts or validation CSV missing | install artifacts / dataset locally |

---

## 9. Performance and limitations

### 9.1 What was measured [Verified - single recorded run]

From `reports/inference_performance_benchmark.md` (one run on the development
laptop: Windows 10, i5-1135G7, 7.78 GB RAM, Python 3.9.13):

- Module import time: 28,728.5 ms (one measurement; first `shap` import in a
  fresh process, so **not** representative startup latency).
- Repeated predictor loads inside one process: 825.8 / 314.0 / 311.8 ms
  (NOT true cold starts).
- Warmed-up `predict_email()` medians on three small synthetic bodies:
  19.160 ms, 18.852 ms, 19.462 ms (25 runs each; occasional outliers up to
  83 ms).
- Indicative per-step breakdown: SHAP about 6.1-6.3 ms; each model call
  about 1.3-1.5 ms; TF-IDF transform about 0.24-0.26 ms.
- Process working set: about 170-172 MB after loading.

### 9.2 Limitations that must be preserved [Verified]

- One recorded run, three synthetic bodies, 25 repetitions per body, and no
  control over laptop power/thermal state.
- These are **in-process ML measurements**, not API latency. Full end-to-end
  API latency has **not** been measured.
- The frontend contains a marketing claim of "under 100 milliseconds"
  (`bantai-frontend/src/components/Advantage.jsx`). That is UI copy, **not a
  verified result**. **Do not claim the under-100 ms end-to-end target has
  been achieved.**
- The split-leakage audit checked **exact** body overlap only. A full
  near-duplicate analysis was skipped because it exceeded the 8 GB RAM
  budget, so **near-duplicate leakage remains unaudited** (see
  `audit_split_overlap_explain.md`).

---

## 10. Team handoff checklist

### 10.1 ML responsibilities - status

| Item | Status |
|---|---|
| Reusable inference component (`src/models/baseline_inference.py`) | Done, committed on `feature/ml-baseline` |
| Core + robustness tests | Done (recorded: 9/9 and 13/13) |
| Benchmark script + report | Done, committed |
| SHAP prototype (`explain_one_email.py`) with row selection | Done, committed |
| Baseline validation report, test-evaluation report, SHAP notes, handoff doc | Done, committed |
| Artifacts | Local only (gitignored); delivery via Google Drive pending |
| Artifact hashes recorded in a committed document | **Pending** [Unresolved] |
| Near-duplicate leakage audit | **Pending / unaudited** |

### 10.2 Backend responsibilities - status

| Item | Status |
|---|---|
| Backend environment with verified dependency versions | Pending |
| Artifact download + checksum verification | Pending |
| Import bootstrap and startup `warm_up()` | Pending |
| Endpoint, request/response schema, status mapping | Pending (proposals in section 6) |
| JSON serialization of the dataclass result | Pending |
| Body-safe logging and error handling | Pending |
| Backend/API tests | Pending (proposals in section 8.3) |
| End-to-end latency measurement | Pending |

### 10.3 Verification before merging

1. Backend teammate installs artifacts and re-runs both ML test scripts.
2. Hashes match section 4.3.
3. A short synthetic body returns a well-formed result.
4. No email body appears in logs or responses.
5. Pull request reviewed by the ML owner and the backend teammate, with the
   agreed decisions from section 6.4 recorded.

---

## 11. Appendix

### 11.1 Quick reference

| Task | Command |
|---|---|
| Run core tests | `machine-learning\.venv\Scripts\python.exe machine-learning\tests\test_baseline_inference.py` |
| Run robustness tests | `machine-learning\.venv\Scripts\python.exe machine-learning\tests\test_baseline_inference_robustness.py` |
| Explain one Phishing row | `machine-learning\.venv\Scripts\python.exe machine-learning\explain_one_email.py --label 1` |
| Verify artifact hashes | `Get-FileHash -Algorithm SHA256 machine-learning\artifacts\baseline\tfidf_vectorizer.pkl` |
| Benchmark (read-only) | `machine-learning\.venv\Scripts\python.exe machine-learning\scripts\benchmark_baseline_inference.py` |

### 11.2 Related documents

- `reports/ml_inference_handoff.md` - concise technical handoff
- `reports/baseline_experiment_report.md` - training + validation record
- `reports/baseline_test_evaluation.md` - held-out test metrics
- `reports/inference_performance_benchmark.md` - benchmark methodology + results
- `reports/shap_prototype_notes.md` - SHAP interpretation notes
- `reports/dataset_preparation_manifest.json` - dataset and split record

---

*Prepared from verified repository contents. Proposals and unresolved items
are labeled as such. No model was trained or retrained, no artifacts were
modified, and no email bodies are included in this document.*
