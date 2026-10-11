# SHAP Prototype Notes (Local Validation)

**Status:** prototype / exploratory. Not part of the baseline experiment metrics.
**Related:** `machine-learning/explain_one_email.py`; `baseline_experiment_report.md`.

## Scope

Documents the single-email SHAP prototype and how to read its output. The script is
read-only: it loads the saved artifacts and explains one validation row.

## Method and output space

- Explainer: `shap.TreeExplainer(model)` (SHAP 0.48.0 default `model_output="raw"`).
- Model: `XGBClassifier`, objective `binary:logistic` (raw output = margin/log-odds).
- Contributions are in raw-margin space: `base_value + sum(SHAP)` reproduces the raw
  margin, checked against `model.predict(X, output_margin=True)` with tolerance `1e-5`.
  They are not probabilities and do not sum to 100%.

## One-row observation (first Phishing validation row)

- Validation row index: 0
- True label: 1 (Phishing)
- Predicted label: 1 (Phishing)
- P(Phishing): 0.9930
- SHAP output space: raw model output (binary XGBoost margin/log-odds)
- Additivity residual: 3.57627869e-07; check passed (tolerance 1e-5)

## Short tokens `ra`, `vi`, `st`

Verified by read-only inspection of the fitted vectorizer:

- All three are genuine vocabulary entries (indices 37069, 47587, 42596) and are
  present with nonzero TF-IDF weight in that row (TF-IDF values 0.0996, 0.0964,
  0.0717 respectively).
- The vectorizer uses `analyzer="word"`, `token_pattern="(?u)\b\w\w+\b"`,
  `lowercase=True`, `ngram_range=(1,1)`. Tokens require a minimum of two word
  characters, so single letters are dropped and 2-letter fragments are kept.
- Vocabulary length distribution: minimum length 2; 1,178 two-character and
  4,927 three-character tokens.
- In the observed row, 52 of 87 nonzero features are <=3 characters, so short
  fragments are a general property of this dataset's text and tokenization.
- The script's SHAP-index -> token mapping is a correct bijection
  (50,000 tokens / 50,000 indices; 0 mismatches), so the displayed token names
  match the features the model used.

## Limitations

- SHAP values are in raw-margin (log-odds) space; they are not probabilities.
- Tokens are TF-IDF unigrams; short fragments carry no inherent meaning and are not
  evidence that an email is malicious. SHAP shows how features influenced the model's
  output, not causation.
- Short tokens arise from the dataset's obfuscated text and the default tokenizer;
  they should not be reported as phishing indicators.
- This documents a single row (an anecdote), not general model behavior.
- Dataset origin, version, and license are not documented (see
  `baseline_experiment_report.md`).
