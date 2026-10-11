# Baseline Experiment Report: TF-IDF + XGBoost

**Project:** BANTAI - XGBoost-Based Email Threat Detection and Analysis Engine using Explainability Framework

**Experiment identifier:** `baseline` (from the artifact directory `machine-learning/artifacts/baseline/`; no separate experiment ID was recorded)

**CRISP-DM phases covered:** Modeling (4) and Evaluation on the validation split (5, partial - the held-out test set was not used)

**Baseline executed:** 2026-10-09 (date recorded in the Stage 1 implementation report; artifact timestamps are consistent with it)

**Report compiled:** 2026-10-11

**Status:** Training and validation evaluation completed. The held-out test set has **not** been evaluated; no test metrics exist for this experiment.

> **Evidence policy.** Every number in this report was copied from the recorded outputs referenced in Section 11. No training, evaluation, or SHAP computation was performed while preparing this report, and no email body text is reproduced anywhere in this document. All metrics below are **validation metrics**, not test metrics.

---

## 1. Objective and scope

- **Goal:** establish a minimal, reproducible baseline that maps email body text to a Safe (0) / Phishing (1) classification, evaluated on the validation split only.
- **In scope for this experiment:** TF-IDF unigram features fit on the training split; a single XGBoost classifier with fixed parameters; evaluation on the validation split; saving the fitted vectorizer, the trained model, and an experiment configuration file.
- **Out of scope at this stage:** SHAP explainability, threat scores and risk tiers, hyperparameter tuning, baseline-model comparisons, and evaluation on the held-out test set.
- **Primary research classifier:** XGBoost. **Primary explainability method (planned, separate work):** SHAP TreeExplainer.

## 2. Dataset and preparation

The dataset is a text-classification dataset with two columns, `body` and `label`, where label 0 = Safe and label 1 = Phishing. Preparation was performed by `machine-learning/prepare_dataset.py`; exact figures and per-class counts are recorded in the [dataset preparation manifest](dataset_preparation_manifest.json).

| Item | Recorded value |
|---|---|
| Source file | `Balanced_Dataset.csv` (under `machine-learning/data/raw/`) |
| Source file SHA-256 | `ac83bf86beabbff654848e6f94389c0723d100865a3f7f2fc4299607c85c7569` |
| Raw rows | 198,450 |
| Rows with missing bodies (recorded) | 3 |
| Rows excluded for missing or blank bodies (combined) | 7 |
| Exact duplicate bodies removed | 3,405 |
| Prepared unique rows | 195,038 |
| Text transformation | None; raw body text preserved |
| Label conflicts (same body, different labels) | 0 |

The manifest records `missing_body_rows` = 3 and `rows_with_missing_or_blank_bodies` = 7. The exclusion step uses a combined "missing **or** blank" condition, and missing values are also treated as blank, so the 3 missing-body rows are included within the 7 excluded rows — the two figures overlap and are **not** additive. Arithmetic: 198,450 raw − 7 excluded − 3,405 duplicates = 195,038 prepared rows.

**Dataset origin, version, and license are not documented in the repository** (see open item 3 in Section 10).

## 3. Split design and leakage controls

- Splits are stratified by label with `random_state=42`, approximately 70% / 15% / 15% (train / validation / test).
- Row counts: train 136,526; validation 29,256; test 29,256 (per-class counts are in the manifest).
- The TF-IDF vectorizer was fit on the training split only; validation text was transformed with the fitted vectorizer.
- Exact-body overlap between all split pairs was audited: **0 overlapping bodies** and no identical bodies with conflicting labels. Details and the audit output are in [audit_split_overlap_explain.md](../audit_split_overlap_explain.md).

## 4. Feature representation

Recorded in `experiment_config.json` (`tfidf_params`):

| Parameter | Value |
|---|---|
| Vectorizer | `TfidfVectorizer` (scikit-learn) |
| `max_features` | 50,000 |
| `ngram_range` | (1, 1) - unigrams only |
| `lowercase` | `True` |
| `stop_words` | `None` (no stop-word removal) |
| Fitted vocabulary size | 50,000 |

## 5. Model and hyperparameters

Recorded in `experiment_config.json` (`xgb_params`):

| Parameter | Value |
|---|---|
| Model | `XGBClassifier` (XGBoost) |
| `n_estimators` | 100 |
| `random_state` | 42 |
| `n_jobs` | 1 |
| `eval_metric` | `logloss` |

**No hyperparameter search was performed.** These values were fixed for the baseline. Hyperparameters that were not set explicitly remained at XGBoost defaults and were not individually recorded (open item 2 in Section 10).

## 6. Evaluation protocol

- Evaluation was performed on the **validation split only**.
- Metrics were computed with scikit-learn: accuracy, binary precision, binary recall, binary F1-score, ROC-AUC (using `predict_proba`), and the confusion matrix.
- No `eval_set` was used during training, and the test CSV was not loaded during this experiment.
- **The held-out test set has not been evaluated.** No test metrics exist for this experiment.

## 7. Validation results

Recorded in `experiment_config.json` (`validation_metrics`); values below are rounded to 4 decimal places from the full-precision values stored there.

| Metric (validation) | Value |
|---|---|
| Accuracy | 0.9688 |
| Precision (Phishing) | 0.9600 |
| Recall (Phishing) | 0.9796 |
| F1-score (Phishing) | 0.9697 |
| ROC-AUC | 0.9956 |

Confusion matrix (rows = true label, columns = predicted label, per scikit-learn convention):

| | Predicted Safe | Predicted Phishing |
|---|---|---|
| **True Safe** | 13,766 | 608 |
| **True Phishing** | 304 | 14,578 |

Derived counts from the recorded matrix: false positives = 608, false negatives = 304. As an arithmetic consistency check, 14,578 / (14,578 + 608) = 0.9600 (precision) and 14,578 / (14,578 + 304) = 0.9796 (recall), which agree with the recorded metrics.

**These are validation metrics. They must not be quoted as test or final generalization performance.**

## 8. Artifact verification

`machine-learning/verify_baseline.py` performed a read-only sanity check against the saved artifacts using 5 validation rows: probabilities were finite, within [0, 1], and summed to approximately 1, and the TF-IDF matrix shape (5, 50,000) matched the vocabulary size. This confirms the artifacts load and score consistently; it is not a performance evaluation. Output and explanation: [VERIFY_README.md](../VERIFY_README.md).

## 9. Reproducibility and environment

- **Random seed:** 42, set for the data split (`RANDOM_STATE` in `prepare_dataset.py`; also recorded in the manifest) and for the XGBoost classifier (`XGB_PARAMS["random_state"]` in `train_baseline.py`). The TF-IDF vectorizer was configured without an explicit `random_state`, so no seed is attributed to it.
- **Training command (as used):** run from the repository root with the project virtual environment:
  `machine-learning\.venv\Scripts\python.exe machine-learning\train_baseline.py`
- **Overwrite guard:** `train_baseline.py` exits if the artifact directory already contains files, so it will not silently overwrite the existing baseline. Re-running it requires explicit, deliberate handling of the existing artifacts (per the project's artifact-preservation rule).
- **Data and artifacts are local-only:** the raw dataset, prepared splits, and `artifacts/baseline/` are ignored by `.gitignore`, so a fresh clone will not contain them; reproduction requires the raw dataset identified by the SHA-256 in Section 2.
- **Software environment** (versions in the table below were verified by a read-only inspection of `machine-learning/.venv/` on 2026-10-11; pandas and scikit-learn versions are also recorded in the manifest):

| Component | Version | Source |
|---|---|---|
| Python | 3.9.13 | `.venv` inspection |
| pandas | 2.3.3 | manifest + `.venv` inspection |
| scikit-learn | 1.6.1 | manifest + `.venv` inspection |
| XGBoost | 2.1.4 | `.venv` inspection |
| NumPy | 1.26.4 | `.venv` inspection |
| SciPy | 1.13.1 | `.venv` inspection |
| joblib | 1.5.3 | `.venv` inspection |
| SHAP | 0.48.0 | `.venv` inspection (installed for planned explainability work; not used by this baseline) |

**No `requirements.txt` or dependency lock file exists in the repository** (open item 4 in Section 10).

## 10. Limitations and open items

1. **Test evaluation pending.** The held-out test set has not been evaluated; final generalization performance is unknown and must not be claimed.
2. **No hyperparameter tuning.** The baseline uses fixed values; no search space, selected parameters, or tuning results exist. Unspecified XGBoost hyperparameters remained at library defaults and were not recorded individually.
3. **Dataset provenance missing.** The dataset origin (source, version, license) is not documented in the repository; only the file name and SHA-256 are recorded. This is required information under the project's data-documentation rules and remains an open item.
4. **No dependency file.** Package versions are not captured in a `requirements.txt` or lock file; the versions in Section 9 were verified ad hoc from the local virtual environment.
5. **No runtime or hardware measurements.** Training time, inference time, and hardware details were not recorded (the 8 GB RAM constraint appears only in script comments). The project rules call for recording relevant hardware and execution settings.
6. **Configuration-file provenance.** Filesystem timestamps for `experiment_config.json` show it was written later than the model and vectorizer files created during the training run. The cause is not recorded; the file's contents match the saved artifacts as verified on 2026-10-11.
7. **Threat score and risk tiers undefined.** The 0-100 threat score and Low/Medium/Critical tier thresholds are not defined; interface expectations exist, but the mapping is an open decision for the deployment stage.
8. **Explainability not included here.** SHAP work is a separate activity; no SHAP outputs are part of this experiment record. Prototype notes: `shap_prototype_notes.md`.
9. **Presentation rule.** All metrics in this report are validation metrics. Do not present them as test metrics or as final model performance.

## 11. Evidence sources and related documents

| Document | Availability | Purpose |
|---|---|---|
| [stage1_implementation_report.md](../../stage1_implementation_report.md) | Local only — excluded via `.git/info/exclude` | Historical Stage 1 plan, approved-conditions checklist, and outcome update |
| [dataset_preparation_manifest.json](dataset_preparation_manifest.json) | Committed (`e7b40b5`) | Recorded cleaning, deduplication, split, and version figures |
| [audit_split_overlap_explain.md](../audit_split_overlap_explain.md) | Local only — excluded via `.git/info/exclude` | Split-overlap audit explanation and output |
| [VERIFY_README.md](../VERIFY_README.md) | Local only — excluded via `.git/info/exclude` | Artifact verification write-up and output |
| [experiment_config.json](../artifacts/baseline/experiment_config.json) | Local only — ignored via `.gitignore` (`artifacts/baseline/`) | Recorded parameters, row counts, and full-precision validation metrics |
| [train_baseline.py](../train_baseline.py) | Committed (`e7b40b5`) | Training and evaluation code |
| [prepare_dataset.py](../prepare_dataset.py) | Committed (`e7b40b5`) | Data cleaning and split code |
| [verify_baseline.py](../verify_baseline.py) | Committed (`e7b40b5`) | Read-only artifact verification code |

> **Repository availability.** Entries marked "Local only" exist on this machine but are excluded from Git (via `.git/info/exclude` or `.gitignore`). A fresh clone, or any teammate, will **not** receive them automatically. Specifically, `stage1_implementation_report.md`, `VERIFY_README.md`, and `audit_split_overlap_explain.md` are excluded through `.git/info/exclude`, and `experiment_config.json` (under `artifacts/baseline/`) is ignored through `.gitignore`. This report file is also not yet committed. To share this documentation and its evidence, the relevant files must be committed, or the outputs regenerated: `experiment_config.json` and the trained artifacts can be reproduced only by re-running `train_baseline.py` against the raw dataset identified by the SHA-256 in Section 2.

The baseline and audit scripts were committed to the repository as commit `e7b40b5` ("feat(ml): add XGBoost baseline and dataset audits"). The trained artifacts and datasets are local-only and are not committed.
