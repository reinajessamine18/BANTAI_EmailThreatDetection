#!/usr/bin/env python
"""
BANTAI — Phase 6: SHAP Explainability Framework and Token Contribution Verification

Executes:
  1. Cryptographic pre-flight verification of Candidate V2 and partition assignments.
  2. Sequential reconstruction of fold-specific models (Folds 0-4) for EXP-4.
  3. Numerical validation: |p_reconstructed - p_saved| <= 1e-5 on all 35,522 OOF predictions.
  4. SHAP TreeExplainer margin-space additivity verification:
     |base_value + sum(phi_i) - margin| <= 1e-5.
  5. Logistic link validation: p = 1 / (1 + exp(-margin)).
  6. Detailed token contribution extraction for representative cases:
     - A. True Positives (high-confidence phishing, credential harvesting, bank impersonation)
     - B. True Negatives (benign corporate Enron, SpamAssassin tech discussions)
     - C. False Negatives (subtle billing pretext, borderline miss, ultra-short lure)
     - D. Genuine False Positives (Category C legitimate Enron corporate correspondence)
     - E. Ground-Truth Contaminated Enron Records (Category A brand impersonation mislabeled as ham)
     - F. Extraction Anomaly (Category E unparsed Base64 .bmp attachment artifact)
  7. Verification of Exploratory Full-Dataset Model refit.
  8. Serialization of complete explainability artifacts to:
     machine-learning/artifacts/candidate_content_nlp_v2/explainability/

Strictly adheres to:
  - 8 GB RAM laptop safeguards (sequential execution, gc.collect(), n_jobs=1, sparse matrices).
  - Preserves benchmark ground-truth labels untouched.
  - Defangs and sanitizes all sample excerpts.
"""

import ctypes
import gc
import hashlib
import json
from pathlib import Path
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

import joblib
import numpy as np
import pandas as pd
import scipy.special
from sklearn.feature_extraction.text import TfidfVectorizer
import shap
import xgboost as xgb

# ---------------------------------------------------------------------------
# Path Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
ML_DIR = SCRIPT_DIR.parent
ROOT_DIR = ML_DIR.parent

V2_PROCESSED_DIR = ML_DIR / "data" / "processed" / "content_only_candidate_v2"
CANDIDATE_V2_CSV = V2_PROCESSED_DIR / "candidate_corpus_v2.csv"
CANDIDATE_V2_MANIFEST = V2_PROCESSED_DIR / "candidate_v2_manifest.json"
PARTITIONS_V2_CSV = V2_PROCESSED_DIR / "partition_assignments_v2.csv"
PARTITIONS_V2_MANIFEST = V2_PROCESSED_DIR / "partition_manifest_v2.json"

V1_PROCESSED_DIR = ML_DIR / "data" / "processed" / "content_only_candidate"
CANDIDATE_V1_CSV = V1_PROCESSED_DIR / "candidate_corpus.csv"

EXP4_DIR = ML_DIR / "artifacts" / "candidate_content_nlp_v2" / "exp-4"
EXP4_OOF_CSV = EXP4_DIR / "oof_predictions.csv"
EXP4_CONFIG_JSON = EXP4_DIR / "experiment_config.json"
EXP4_FULL_MODEL = EXP4_DIR / "exploratory_full_model.joblib"
EXP4_FULL_VEC = EXP4_DIR / "exploratory_full_vectorizer.joblib"

EXPLAINABILITY_DIR = ML_DIR / "artifacts" / "candidate_content_nlp_v2" / "explainability"
ADJUDICATION_CSV = ML_DIR / "reports" / "phase5_1_1_itemized_fp_adjudication.csv"

# Checksums for immutability verification
V1_CANDIDATE_SHA256 = "26e151b7c48dcad03752bf6da9aa3c2b41a965b1fb3ed3b1e5e99fac64496cd3"

# Model hyperparameters (EXP-4 authoritative specification)
TFIDF_PARAMS = {
    "lowercase": True,
    "stop_words": None,
    "token_pattern": r"(?u)\b\w\w+\b",
    "ngram_range": (1, 1),
    "max_features": 25000,
    "min_df": 5,
}

XGB_PARAMS = {
    "n_estimators": 100,
    "max_depth": 6,
    "learning_rate": 0.3,
    "random_state": 42,
    "n_jobs": 1,
    "eval_metric": "logloss",
    "tree_method": "hist",
}

# Designated representative cases across all categories
REPRESENTATIVE_TARGETS = [
    # True Positives
    {
        "source_record_id": "sample-3385.eml",
        "category_group": "A_TRUE_POSITIVE",
        "description": "Category A credential harvesting phish (account suspension pretext)",
        "expected_fold": 2,
    },
    {
        "source_record_id": "nazario_row_5",
        "category_group": "A_TRUE_POSITIVE",
        "description": "Vintage bank phishing lure with security verification pretext",
        "expected_fold": 4,
    },
    {
        "source_record_id": "nazario_row_4",
        "category_group": "A_TRUE_POSITIVE",
        "description": "High-confidence online service spoof lure",
        "expected_fold": 3,
    },
    # True Negatives
    {
        "source_record_id": "enron_row_0",
        "category_group": "B_TRUE_NEGATIVE",
        "description": "Routine internal Enron corporate communication",
        "expected_fold": 0,
    },
    {
        "source_record_id": "sa_row_0",
        "category_group": "B_TRUE_NEGATIVE",
        "description": "SpamAssassin technical community discussion regarding open-source tooling",
        "expected_fold": 0,
    },
    # False Negatives
    {
        "source_record_id": "sample-11359.eml",
        "category_group": "C_FALSE_NEGATIVE",
        "description": "PayPal recurring payment notification pretext with low urgency",
        "expected_fold": 2,
    },
    {
        "source_record_id": "nazario_row_700",
        "category_group": "C_FALSE_NEGATIVE",
        "description": "Borderline miss just below 0.50 threshold (prob ~0.498)",
        "expected_fold": 1,
    },
    {
        "source_record_id": "nazario_row_194",
        "category_group": "C_FALSE_NEGATIVE",
        "description": "Ultra-short attachment lure with minimal semantic body cues (prob ~0.145)",
        "expected_fold": 4,
    },
    # Genuine False Positives (Category C)
    {
        "source_record_id": "enron_row_1556",
        "category_group": "D_GENUINE_FALSE_POSITIVE",
        "description": "Enron registration confirmation with transactional password/access wording",
        "expected_fold": 0,
    },
    {
        "source_record_id": "enron_row_6151",
        "category_group": "D_GENUINE_FALSE_POSITIVE",
        "description": "Vince Kaminski trade publication notice containing subscription renewal cues",
        "expected_fold": 0,
    },
    {
        "source_record_id": "enron_row_23160",
        "category_group": "D_GENUINE_FALSE_POSITIVE",
        "description": "Academic / industry symposium invitation addressed to Raúl",
        "expected_fold": 2,
    },
    # Potentially Mislabeled Enron Records (Ground-truth contaminated Phishing in Enron)
    {
        "source_record_id": "enron_row_10240",
        "category_group": "E_CONTAMINATED_ENRON_PHISH",
        "description": "eBay billing suspension phish mislabeled as legitimate in Enron ham",
        "expected_fold": 0,
    },
    {
        "source_record_id": "enron_row_23778",
        "category_group": "E_CONTAMINATED_ENRON_PHISH",
        "description": "Barclays online banking security phish mislabeled as legitimate in Enron ham",
        "expected_fold": 1,
    },
    {
        "source_record_id": "enron_row_9466",
        "category_group": "E_CONTAMINATED_ENRON_PHISH",
        "description": "eBay account review alert mislabeled as legitimate in Enron ham",
        "expected_fold": 3,
    },
    {
        "source_record_id": "enron_row_20239",
        "category_group": "E_CONTAMINATED_ENRON_PHISH",
        "description": "Wells Fargo security notification mislabeled as legitimate in Enron ham",
        "expected_fold": 4,
    },
    # Extraction Anomaly (Category E)
    {
        "source_record_id": "sa_row_4038",
        "category_group": "F_EXTRACTION_ANOMALY",
        "description": "Japanese text with 290 KB unparsed Base64 .bmp attachment artifact",
        "expected_fold": 2,
    },
]


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------
class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_uint32),
        ("dwMemoryLoad", ctypes.c_uint32),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("sullAvailExtendedVirtual", ctypes.c_uint64),
    ]


def get_system_ram() -> dict:
    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
    return {
        "total_gb": round(stat.ullTotalPhys / (1024**3), 2),
        "avail_gb": round(stat.ullAvailPhys / (1024**3), 2),
        "memory_load_pct": int(stat.dwMemoryLoad),
    }


def compute_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def defang_text(text: str, max_chars: int = 350) -> str:
    """Defangs URLs, emails, and truncates text for safe display."""
    if not isinstance(text, str):
        return ""
    # Truncate
    snippet = text[:max_chars].strip()
    # Defang http/https
    snippet = snippet.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Replace email @ with [at]
    import re
    snippet = re.sub(r"([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", r"\1[at]\2", snippet)
    # Collapse excess whitespace
    snippet = re.sub(r"\s+", " ", snippet)
    if len(text) > max_chars:
        snippet += " ... [TRUNCATED]"
    return snippet


# ---------------------------------------------------------------------------
# Pre-Flight Verification
# ---------------------------------------------------------------------------
def preflight_checks():
    print("================================================================================")
    print("PHASE 6: PRE-FLIGHT INTEGRITY VERIFICATION")
    print("================================================================================")

    # 1. Candidate V2 Checksum
    with open(CANDIDATE_V2_MANIFEST, "r", encoding="utf-8") as f:
        v2_m = json.load(f)
    expected_v2_sha = v2_m["primary_candidate_corpus"]["sha256"]
    actual_v2_sha = compute_sha256(CANDIDATE_V2_CSV)
    if actual_v2_sha != expected_v2_sha:
        raise ValueError(f"Candidate V2 checksum mismatch: {actual_v2_sha} != {expected_v2_sha}")
    print(f"[OK] Candidate V2 corpus verified: {actual_v2_sha}")

    # 2. Partition V2 Checksum
    with open(PARTITIONS_V2_MANIFEST, "r", encoding="utf-8") as f:
        part_m = json.load(f)
    expected_part_sha = part_m["partition_assignments_file"]["sha256"]
    actual_part_sha = compute_sha256(PARTITIONS_V2_CSV)
    if actual_part_sha != expected_part_sha:
        raise ValueError(f"Partition V2 checksum mismatch: {actual_part_sha} != {expected_part_sha}")
    print(f"[OK] Partition assignments verified: {actual_part_sha}")

    # 3. Candidate V1 Preservation
    if CANDIDATE_V1_CSV.exists():
        actual_v1_sha = compute_sha256(CANDIDATE_V1_CSV)
        if actual_v1_sha != V1_CANDIDATE_SHA256:
            raise ValueError(f"Candidate V1 modified! {actual_v1_sha} != {V1_CANDIDATE_SHA256}")
        print(f"[OK] Candidate V1 preserved: {actual_v1_sha}")

    # 4. Check OOF file
    if not EXP4_OOF_CSV.exists():
        raise FileNotFoundError(f"Missing EXP-4 OOF predictions: {EXP4_OOF_CSV}")
    print(f"[OK] EXP-4 OOF predictions file verified: {EXP4_OOF_CSV}")

    ram = get_system_ram()
    print(f"[OK] System RAM: {ram['avail_gb']} GB available of {ram['total_gb']} GB ({ram['memory_load_pct']}% load)")
    print("================================================================================\n")
    return actual_v2_sha, actual_part_sha


# ---------------------------------------------------------------------------
# Main Verification and Explainability Routine
# ---------------------------------------------------------------------------
def run_explainability_pipeline():
    actual_v2_sha, actual_part_sha = preflight_checks()

    EXPLAINABILITY_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading Candidate V2 corpus, partitions, and saved EXP-4 OOF predictions...")
    df_cand = pd.read_csv(CANDIDATE_V2_CSV)
    df_part = pd.read_csv(PARTITIONS_V2_CSV)
    df_oof = pd.read_csv(EXP4_OOF_CSV)

    if len(df_cand) != 35522 or len(df_part) != 35522 or len(df_oof) != 35522:
        raise ValueError(f"Dataset length mismatch: cand={len(df_cand)}, part={len(df_part)}, oof={len(df_oof)}")

    # Map target records to row indices
    target_records_map = {}
    for tgt in REPRESENTATIVE_TARGETS:
        s_id = tgt["source_record_id"]
        matches = df_oof[df_oof["source_record_id"] == s_id]
        if len(matches) == 0:
            raise ValueError(f"Target record {s_id} not found in OOF predictions!")
        row_id = int(matches.iloc[0]["candidate_row_id"])
        fold = int(matches.iloc[0]["cv_fold"])
        if fold != tgt["expected_fold"]:
            raise ValueError(f"Target {s_id} fold mismatch: got {fold}, expected {tgt['expected_fold']}")
        target_records_map[row_id] = {
            **tgt,
            "candidate_row_id": row_id,
            "cv_fold": fold,
            "source_id": str(matches.iloc[0]["source_id"]),
            "ground_truth_label": int(matches.iloc[0]["label"]),
            "saved_y_prob": float(matches.iloc[0]["y_prob"]),
            "saved_y_pred": int(matches.iloc[0]["y_pred"]),
        }

    print(f"[OK] Located all {len(target_records_map)} designated representative cases across folds.")

    # Storage for outputs
    fold_reproduction_metrics = {}
    additivity_samples_log = []
    representative_explanations = []

    total_t0 = time.time()

    # -----------------------------------------------------------------------
    # Step 1: Reconstruct Fold-Specific Models and Verify Additivity
    # -----------------------------------------------------------------------
    for fold in range(5):
        t_fold_0 = time.time()
        print(f"\n--------------------------------------------------------------------------------")
        print(f"RECONSTRUCTING FOLD {fold} MODEL (EXP-4)...")
        print(f"--------------------------------------------------------------------------------")

        val_mask = (df_part["cv_fold"] == fold).values
        train_mask = ~val_mask

        val_indices = np.where(val_mask)[0]
        train_indices = np.where(train_mask)[0]

        X_train_text = df_cand.loc[train_indices, "email_body"].astype(str).tolist()
        y_train = df_cand.loc[train_indices, "label"].astype(int).values

        X_val_text = df_cand.loc[val_indices, "email_body"].astype(str).tolist()
        y_val = df_cand.loc[val_indices, "label"].astype(int).values

        # Fit TF-IDF on train text only
        vec = TfidfVectorizer(**TFIDF_PARAMS)
        X_train_tfidf = vec.fit_transform(X_train_text)
        vocab_size = len(vec.vocabulary_)
        feature_names = vec.get_feature_names_out()

        # Fit XGBoost
        model = xgb.XGBClassifier(**XGB_PARAMS)
        model.fit(X_train_tfidf, y_train)

        # Transform full validation set
        X_val_tfidf = vec.transform(X_val_text)

        # 1. Verify Numerical Reproduction of OOF Probabilities
        val_probs_recon = model.predict_proba(X_val_tfidf)[:, 1]
        saved_probs = df_oof.loc[val_indices, "y_prob"].values
        prob_diffs = np.abs(val_probs_recon - saved_probs)
        max_prob_diff = float(np.max(prob_diffs))
        mean_prob_diff = float(np.mean(prob_diffs))

        print(
            f"  [Fold {fold} Reproduction] Max |p_recon - p_saved|: {max_prob_diff:.8e} "
            f"(Mean: {mean_prob_diff:.8e})"
        )
        if max_prob_diff > 1e-5:
            raise ValueError(
                f"Fold {fold} OOF reproduction failure! Max diff {max_prob_diff} exceeds 1e-5 tolerance."
            )

        fold_reproduction_metrics[f"fold_{fold}"] = {
            "val_count": len(val_indices),
            "vocab_size": vocab_size,
            "max_prob_diff": max_prob_diff,
            "mean_prob_diff": mean_prob_diff,
            "reproduction_passed": bool(max_prob_diff <= 1e-5),
            "reconstruction_duration_seconds": round(time.time() - t_fold_0, 2),
        }

        # 2. Initialize SHAP TreeExplainer on Fold Model
        explainer = shap.TreeExplainer(model)

        # Select validation sample for additivity verification:
        # Include all designated targets in this fold + 50 random samples
        fold_target_row_ids = [r_id for r_id, info in target_records_map.items() if info["cv_fold"] == fold]
        
        # Relative index in val_indices
        np.random.seed(42 + fold)
        random_val_rel_idx = np.random.choice(len(val_indices), size=min(50, len(val_indices)), replace=False).tolist()
        
        # Combine target relative indices and random relative indices
        target_rel_indices = []
        for t_row_id in fold_target_row_ids:
            rel_idx = int(np.where(val_indices == t_row_id)[0][0])
            target_rel_indices.append(rel_idx)

        eval_rel_indices = list(dict.fromkeys(target_rel_indices + random_val_rel_idx))
        X_sample_tfidf = X_val_tfidf[eval_rel_indices]

        # Compute SHAP values and margins
        shap_values_sample = explainer.shap_values(X_sample_tfidf)
        # Note: explainer.expected_value is properly finalized after the first shap_values call
        base_value = float(np.ravel(explainer.expected_value)[0])
        margins_sample = model.predict(X_sample_tfidf, output_margin=True)

        # Verify additivity: base_value + sum(shap_values) == margin
        sum_shap_sample = np.sum(shap_values_sample, axis=1)
        recon_margins_sample = base_value + sum_shap_sample
        additivity_residuals = np.abs(margins_sample - recon_margins_sample)
        max_residual = float(np.max(additivity_residuals))
        mean_residual = float(np.mean(additivity_residuals))

        # Verify logistic sigmoid: 1 / (1 + exp(-margin)) == predict_proba
        sig_probs = scipy.special.expit(margins_sample)
        direct_probs = model.predict_proba(X_sample_tfidf)[:, 1]
        link_diffs = np.abs(sig_probs - direct_probs)
        max_link_diff = float(np.max(link_diffs))

        print(
            f"  [Fold {fold} SHAP Additivity] Evaluated {len(eval_rel_indices)} samples. "
            f"Max Residual: {max_residual:.8e} (Mean: {mean_residual:.8e})"
        )
        print(f"  [Fold {fold} Logistic Link] Max |sigmoid(margin) - prob|: {max_link_diff:.8e}")

        if max_residual > 1e-5:
            raise ValueError(
                f"Fold {fold} SHAP additivity failure! Max residual {max_residual} exceeds 1e-5."
            )
        if max_link_diff > 1e-5:
            raise ValueError(
                f"Fold {fold} logistic link failure! Max diff {max_link_diff} exceeds 1e-5."
            )

        additivity_samples_log.append({
            "fold": fold,
            "samples_evaluated": len(eval_rel_indices),
            "base_value": base_value,
            "max_additivity_residual": max_residual,
            "mean_additivity_residual": mean_residual,
            "max_logistic_link_diff": max_link_diff,
            "additivity_passed": bool(max_residual <= 1e-5),
        })

        # 3. Extract Detailed Explanations for Designated Targets in this Fold
        for t_row_id in fold_target_row_ids:
            tgt_info = target_records_map[t_row_id]
            s_rec_id = tgt_info["source_record_id"]
            raw_text = str(df_cand.loc[t_row_id, "email_body"])
            rel_idx = int(np.where(val_indices == t_row_id)[0][0])

            x_vec = X_val_tfidf[rel_idx]
            m_val = float(margins_sample[eval_rel_indices.index(rel_idx)])
            p_val = float(val_probs_recon[rel_idx])
            sv_row = shap_values_sample[eval_rel_indices.index(rel_idx)]

            # Non-zero feature indices
            nz_indices = x_vec.nonzero()[1]

            token_contributions = []
            for col_idx in nz_indices:
                tok_str = str(feature_names[col_idx])
                tfidf_val = float(x_vec[0, col_idx])
                phi_val = float(sv_row[col_idx])
                token_contributions.append({
                    "token": tok_str,
                    "feature_index": int(col_idx),
                    "tfidf_value": round(tfidf_val, 6),
                    "shap_contribution": round(phi_val, 6),
                })

            # Separate positive (pushing phishing) and negative (pushing safe)
            pos_tokens = sorted([t for t in token_contributions if t["shap_contribution"] > 0], key=lambda x: -x["shap_contribution"])
            neg_tokens = sorted([t for t in token_contributions if t["shap_contribution"] < 0], key=lambda x: x["shap_contribution"])

            sum_pos = float(sum(t["shap_contribution"] for t in pos_tokens))
            sum_neg = float(sum(t["shap_contribution"] for t in neg_tokens))
            sum_all = float(np.sum(sv_row))
            calc_margin = base_value + sum_all
            sample_residual = abs(m_val - calc_margin)

            # Audit record details if present in Phase 5.1.1 adjudication
            adjudication_info = None
            if ADJUDICATION_CSV.exists():
                df_adj = pd.read_csv(ADJUDICATION_CSV)
                adj_match = df_adj[df_adj["source_record_id"] == s_rec_id]
                if len(adj_match) > 0:
                    r_adj = adj_match.iloc[0]
                    adjudication_info = {
                        "provisional_category": str(r_adj["provisional_category"]),
                        "provisional_category_name": str(r_adj["provisional_category_name"]),
                        "rationale": str(r_adj["rationale"]),
                    }

            explanation_payload = {
                "candidate_row_id": t_row_id,
                "source_record_id": s_rec_id,
                "source_id": tgt_info["source_id"],
                "category_group": tgt_info["category_group"],
                "description": tgt_info["description"],
                "cv_fold": fold,
                "ground_truth_label": tgt_info["ground_truth_label"],
                "reconstructed_prob": round(p_val, 6),
                "saved_oof_prob": round(tgt_info["saved_y_prob"], 6),
                "predicted_label": int(p_val >= 0.50),
                "model_margin": round(m_val, 6),
                "base_value": round(base_value, 6),
                "sum_positive_contributions": round(sum_pos, 6),
                "sum_negative_contributions": round(sum_neg, 6),
                "sum_shap_values": round(sum_all, 6),
                "additivity_residual": round(sample_residual, 8),
                "additivity_verified": bool(sample_residual <= 1e-5),
                "clean_char_length": len(raw_text),
                "active_vocabulary_tokens_count": len(nz_indices),
                "top_10_positive_tokens": pos_tokens[:10],
                "top_10_negative_tokens": neg_tokens[:10],
                "defanged_body_excerpt": defang_text(raw_text, max_chars=400),
                "adjudication_context": adjudication_info,
            }

            representative_explanations.append(explanation_payload)
            print(
                f"    [Explained {s_rec_id}] Cat={tgt_info['category_group']}, "
                f"Prob={p_val:.4f}, Margin={m_val:.4f}, Base={base_value:.4f}, "
                f"SumPhi={sum_all:.4f}, Res={sample_residual:.2e}, "
                f"Top+={pos_tokens[0]['token'] if pos_tokens else 'None'}, "
                f"Top-={neg_tokens[0]['token'] if neg_tokens else 'None'}"
            )

        # Explicit RAM cleanup
        del X_train_text, X_val_text, X_train_tfidf, X_val_tfidf, vec, model, explainer
        del shap_values_sample, margins_sample
        gc.collect()

    # -----------------------------------------------------------------------
    # Step 2: Exploratory Full Model Verification
    # -----------------------------------------------------------------------
    print(f"\n--------------------------------------------------------------------------------")
    print("VERIFYING EXPLORATORY FULL-DATASET MODEL (ALL-DATA REFIT)...")
    print("--------------------------------------------------------------------------------")

    if not EXP4_FULL_MODEL.exists() or not EXP4_FULL_VEC.exists():
        raise FileNotFoundError(f"Missing exploratory full model artifacts in {EXP4_DIR}")

    full_model = joblib.load(EXP4_FULL_MODEL)
    full_vec = joblib.load(EXP4_FULL_VEC)
    full_explainer = shap.TreeExplainer(full_model)

    # Sample 50 arbitrary records across dataset
    np.random.seed(999)
    sample_full_idx = np.random.choice(len(df_cand), size=50, replace=False)
    X_full_sample_text = df_cand.loc[sample_full_idx, "email_body"].astype(str).tolist()
    X_full_sample_tfidf = full_vec.transform(X_full_sample_text)

    full_margins = full_model.predict(X_full_sample_tfidf, output_margin=True)
    full_shap_vals = full_explainer.shap_values(X_full_sample_tfidf)
    full_base_value = float(np.ravel(full_explainer.expected_value)[0])
    full_sum_shap = np.sum(full_shap_vals, axis=1)
    full_residuals = np.abs(full_margins - (full_base_value + full_sum_shap))
    max_full_residual = float(np.max(full_residuals))

    full_model_verification = {
        "full_model_path": str(EXP4_FULL_MODEL.relative_to(ROOT_DIR)).replace("\\", "/"),
        "full_vectorizer_path": str(EXP4_FULL_VEC.relative_to(ROOT_DIR)).replace("\\", "/"),
        "fitted_vocab_size": len(full_vec.vocabulary_),
        "samples_evaluated": len(sample_full_idx),
        "base_value": full_base_value,
        "max_additivity_residual": max_full_residual,
        "additivity_passed": bool(max_full_residual <= 1e-5),
        "methodological_note": (
            "The exploratory full-dataset model was refit on all 35,522 candidate records. "
            "It is intended exclusively for production inference and runtime deployment. "
            "Cross-validation error analysis and out-of-fold explanations must strictly use "
            "fold-specific models to prevent validation leakage."
        ),
    }

    print(f"[OK] Full model SHAP additivity verified: Max residual = {max_full_residual:.8e}")
    del full_model, full_vec, full_explainer, full_shap_vals
    gc.collect()

    # -----------------------------------------------------------------------
    # Step 3: Serialize Explainability Artifacts
    # -----------------------------------------------------------------------
    print(f"\n--------------------------------------------------------------------------------")
    print("SERIALIZING EXPLAINABILITY ARTIFACTS...")
    print("--------------------------------------------------------------------------------")

    # 1. Representative Explanations JSON
    rep_path = EXPLAINABILITY_DIR / "representative_explanations.json"
    with open(rep_path, "w", encoding="utf-8") as f:
        json.dump(representative_explanations, f, indent=2)
    print(f"[OK] Saved {len(representative_explanations)} explanations: {rep_path.name}")

    # 2. Additivity Verification Summary JSON
    additivity_summary = {
        "verification_objective": "Mathematical verification of SHAP TreeExplainer additivity residual <= 1e-5",
        "formula": "margin(x) = base_value + sum_i(phi_i(x))",
        "logistic_link": "p(x) = 1 / (1 + exp(-margin(x)))",
        "fold_samples_summary": additivity_samples_log,
        "overall_max_residual": float(max(s["max_additivity_residual"] for s in additivity_samples_log)),
        "all_folds_passed": all(s["additivity_passed"] for s in additivity_samples_log),
        "full_model_verification": full_model_verification,
    }
    add_path = EXPLAINABILITY_DIR / "additivity_verification.json"
    with open(add_path, "w", encoding="utf-8") as f:
        json.dump(additivity_summary, f, indent=2)
    print(f"[OK] Saved additivity verification summary: {add_path.name}")

    # 3. Fold Reproduction Metrics JSON
    repro_path = EXPLAINABILITY_DIR / "fold_reproduction_metrics.json"
    with open(repro_path, "w", encoding="utf-8") as f:
        json.dump(fold_reproduction_metrics, f, indent=2)
    print(f"[OK] Saved fold reproduction metrics: {repro_path.name}")

    # 4. Provenance Metadata JSON
    ram_final = get_system_ram()
    provenance = {
        "phase": "Phase 6: SHAP Explainability Framework and Token Contribution Verification",
        "date_executed": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_duration_seconds": round(time.time() - total_t0, 2),
        "primary_candidate": "EXP-4 (Unigram, 25k, min_df=5)",
        "xgboost_version": xgb.__version__,
        "shap_version": shap.__version__,
        "python_version": sys.version.split()[0],
        "system_ram_gb": ram_final["total_gb"],
        "random_seeds": {"fold_reconstruction": 42, "evaluation_sampling": 42},
        "inputs": {
            "candidate_v2_corpus_sha256": actual_v2_sha,
            "partition_assignments_v2_sha256": actual_part_sha,
            "exp4_oof_sha256": compute_sha256(EXP4_OOF_CSV),
        },
        "outputs": {
            "representative_explanations_sha256": compute_sha256(rep_path),
            "additivity_verification_sha256": compute_sha256(add_path),
            "fold_reproduction_metrics_sha256": compute_sha256(repro_path),
        },
    }
    prov_path = EXPLAINABILITY_DIR / "provenance.json"
    with open(prov_path, "w", encoding="utf-8") as f:
        json.dump(provenance, f, indent=2)
    print(f"[OK] Saved provenance metadata: {prov_path.name}")

    # 5. Explainability Directory Manifest
    manifest = {
        "explainability_suite_version": "v2.0",
        "primary_candidate": "EXP-4",
        "files": {
            rep_path.name: {
                "sha256": compute_sha256(rep_path),
                "bytes": rep_path.stat().st_size,
                "record_count": len(representative_explanations),
            },
            add_path.name: {
                "sha256": compute_sha256(add_path),
                "bytes": add_path.stat().st_size,
            },
            repro_path.name: {
                "sha256": compute_sha256(repro_path),
                "bytes": repro_path.stat().st_size,
            },
            prov_path.name: {
                "sha256": compute_sha256(prov_path),
                "bytes": prov_path.stat().st_size,
            },
        },
    }
    man_path = EXPLAINABILITY_DIR / "manifest.json"
    with open(man_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"[OK] Saved explainability manifest: {man_path.name}")

    print("\n================================================================================")
    print("PHASE 6 EXPLAINABILITY PIPELINE COMPLETED SUCCESSFULLY!")
    print(f"Total time elapsed: {time.time() - total_t0:.2f} seconds")
    print("================================================================================")


if __name__ == "__main__":
    run_explainability_pipeline()
