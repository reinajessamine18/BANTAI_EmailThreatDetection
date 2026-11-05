"""
BANTAI — Candidate Dataset Construction Script (Phase 4.3)
Formal Research Title: XGBoost-Based Email Threat Detection and Analysis Engine
Methodology: CRISP-DM Phase 3 (Data Preparation)

Constructs:
  1. candidate_corpus.csv (37,350 natural-language records: 3,509 Phish vs 33,841 Ham)
  2. quarantine_corpus.csv (27 quarantined non-linguistic / collision records)
  3. candidate_corpus_manifest.json (Cryptographic checksums, counts, schema, and provenance)
"""

import sys
import os
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Tuple
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

# Project imports
ML_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ML_DIR))

from src.preprocessing.content_cleaner import ContentOnlyCleaner
from src.preprocessing.dataset_sanitizer import DatasetSanitizer

# Output paths
PROCESSED_DIR = ML_DIR / "data" / "processed" / "content_only_candidate"
CANDIDATE_CSV = PROCESSED_DIR / "candidate_corpus.csv"
QUARANTINE_CSV = PROCESSED_DIR / "quarantine_corpus.csv"
MANIFEST_JSON = PROCESSED_DIR / "candidate_corpus_manifest.json"

# Raw source paths
ZENODO_DIR = ML_DIR / "data" / "raw" / "external" / "zenodo_8339691"
POT_DIR = ML_DIR / "data" / "raw" / "external" / "phishing_pot"

# Explicit 27 Exclusion Definitions
CATEGORY_A_COLLISIONS = {
    "nazario_row_46": "Cross-label collision ('.') with enron_row_9744; single non-word symbol; zero tokens",
    "enron_row_9744": "Cross-label collision ('.') with nazario_row_46; single non-word symbol; zero tokens",
    "nazario_row_551": "Cross-label collision ('1') with enron_row_29383; single character; zero tokens",
    "enron_row_29383": "Cross-label collision ('1') with nazario_row_551; single character; zero tokens",
}

CATEGORY_B_EMPTY_TOKENS = {
    "nazario_row_448": "Punctuation only ('..'); zero analyzer tokens",
    "nazario_row_905": "Punctuation only ('....'); zero analyzer tokens",
    "sample-10651.eml": "Empty markup artifact ('<> <>'); zero analyzer tokens",
    "sample-3085.eml": "Empty markup artifact ('<>\n\n<>'); zero analyzer tokens",
    "sample-3091.eml": "Empty markup artifact ('<>\n\n<>'); zero analyzer tokens",
    "sample-3583.eml": "Empty markup artifact ('<>\n\n<>'); zero analyzer tokens",
    "sample-4759.eml": "Ellipsis punctuation ('...'); zero analyzer tokens",
    "sample-7759.eml": "Decorative symbols ('~~:'); zero analyzer tokens",
    "enron_row_3514": "Single bracket ('>'); zero analyzer tokens",
    "enron_row_3518": "Character encoding corruption ('!????????...'); zero analyzer tokens",
    "enron_row_4086": "Character encoding corruption ('????????...'); zero analyzer tokens",
    "enron_row_10494": "Delimiter symbols ('- - >'); zero analyzer tokens",
    "enron_row_15299": "ASCII art box outline; single non-word characters; zero analyzer tokens",
    "enron_row_16691": "Single parenthesis (')'); zero analyzer tokens",
    "enron_row_17757": "ASCII diagram composed of spaced single characters; zero analyzer tokens",
    "enron_row_18455": "Character encoding corruption ('????????...:'); zero analyzer tokens",
    "enron_row_18831": "Single comma (','); zero analyzer tokens",
    "enron_row_19059": "Spaced single characters with punctuation ('??? p? r??...'); zero analyzer tokens",
    "enron_row_19201": "Spaced single letters ('e.. n.. o.. u.. g.. h'); zero analyzer tokens",
    "enron_row_20746": "Single punctuation pair ('?}'); zero analyzer tokens",
}

CATEGORY_B_UNDERSCORES = {
    "sample-8005.eml": "Repeated underscore line; zero alphanumeric characters; non-linguistic regex artifact",
    "sample-8011.eml": "Repeated underscore line; zero alphanumeric characters; non-linguistic regex artifact",
    "sample-8959.eml": "Repeated underscore/plus decoration; zero alphanumeric characters; non-linguistic regex artifact",
}


def compute_sha256(file_path: Path) -> str:
    """Computes SHA-256 checksum of a file on disk."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def build_candidate_dataset() -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """
    Extracts, sanitizes, tokenizes, and structures the primary candidate corpus
    and quarantine dataset.
    """
    cleaner = ContentOnlyCleaner()
    sanitizer = DatasetSanitizer(cleaner)

    # Standard TF-IDF analyzer configuration
    vec = TfidfVectorizer(lowercase=True, token_pattern=r"(?u)\b\w\w+\b")
    analyzer = vec.build_analyzer()

    candidate_records: List[Dict[str, Any]] = []
    quarantine_records: List[Dict[str, Any]] = []

    PROVENANCE_STR = "ContentOnlyCleaner:v3.4|DatasetSanitizer:v4.1.3"

    print("Step 1: Processing Nazario.csv...")
    df_naz = pd.read_csv(ZENODO_DIR / "Nazario.csv")
    for idx, row in df_naz.iterrows():
        rec_id = f"nazario_row_{idx}"
        res = sanitizer.sanitize_nazario_record(row)
        
        # Check exclusion from candidate modeling
        if res.is_quarantined or not res.cleaned_text.strip():
            # Preprocessing exclusion (mbox header or empty text)
            continue
            
        cleaned = res.cleaned_text
        words = len(cleaned.split())
        alnum = sum(c.isalnum() for c in cleaned)
        tokens = analyzer(cleaned)
        n_tokens = len(tokens)

        if rec_id in CATEGORY_A_COLLISIONS:
            quarantine_records.append({
                "source_id": "nazario",
                "source_record_id": rec_id,
                "label": 1,
                "email_body": cleaned,
                "n_words": words,
                "n_alnum": alnum,
                "n_tokens": n_tokens,
                "quarantine_category": "CATEGORY_A_CROSS_LABEL_COLLISION",
                "exclusion_reason": CATEGORY_A_COLLISIONS[rec_id],
                "provenance": PROVENANCE_STR,
            })
        elif rec_id in CATEGORY_B_EMPTY_TOKENS:
            quarantine_records.append({
                "source_id": "nazario",
                "source_record_id": rec_id,
                "label": 1,
                "email_body": cleaned,
                "n_words": words,
                "n_alnum": alnum,
                "n_tokens": n_tokens,
                "quarantine_category": "CATEGORY_B_EMPTY_TOKEN_SEQUENCE",
                "exclusion_reason": CATEGORY_B_EMPTY_TOKENS[rec_id],
                "provenance": PROVENANCE_STR,
            })
        else:
            token_str = " ".join(tokens)
            seq_hash = hashlib.sha256(token_str.encode("utf-8")).hexdigest()
            candidate_records.append({
                "email_body": cleaned,
                "label": 1,
                "source_id": "nazario",
                "source_record_id": rec_id,
                "analyzer_sequence_hash": seq_hash,
                "provenance": PROVENANCE_STR,
            })

    print("Step 2: Processing Phishing Pot (.eml)...")
    pot_files = sorted(list(POT_DIR.glob("*.eml")))
    for f in pot_files:
        rec_id = f.name
        raw_str = f.read_text(encoding="utf-8", errors="replace")
        res = sanitizer.sanitize_phishing_pot_record(raw_str)

        if res.is_quarantined or not res.cleaned_text.strip():
            continue

        cleaned = res.cleaned_text
        words = len(cleaned.split())
        alnum = sum(c.isalnum() for c in cleaned)
        tokens = analyzer(cleaned)
        n_tokens = len(tokens)

        if rec_id in CATEGORY_B_EMPTY_TOKENS:
            quarantine_records.append({
                "source_id": "phishing_pot",
                "source_record_id": rec_id,
                "label": 1,
                "email_body": cleaned,
                "n_words": words,
                "n_alnum": alnum,
                "n_tokens": n_tokens,
                "quarantine_category": "CATEGORY_B_EMPTY_TOKEN_SEQUENCE",
                "exclusion_reason": CATEGORY_B_EMPTY_TOKENS[rec_id],
                "provenance": PROVENANCE_STR,
            })
        elif rec_id in CATEGORY_B_UNDERSCORES:
            quarantine_records.append({
                "source_id": "phishing_pot",
                "source_record_id": rec_id,
                "label": 1,
                "email_body": cleaned,
                "n_words": words,
                "n_alnum": alnum,
                "n_tokens": n_tokens,
                "quarantine_category": "CATEGORY_B_UNDERSCORE_PSEUDO_TOKEN",
                "exclusion_reason": CATEGORY_B_UNDERSCORES[rec_id],
                "provenance": PROVENANCE_STR,
            })
        else:
            token_str = " ".join(tokens)
            seq_hash = hashlib.sha256(token_str.encode("utf-8")).hexdigest()
            candidate_records.append({
                "email_body": cleaned,
                "label": 1,
                "source_id": "phishing_pot",
                "source_record_id": rec_id,
                "analyzer_sequence_hash": seq_hash,
                "provenance": PROVENANCE_STR,
            })

    print("Step 3: Processing Enron.csv...")
    df_enron = pd.read_csv(ZENODO_DIR / "Enron.csv")
    for idx, row in df_enron.iterrows():
        rec_id = f"enron_row_{idx}"
        res = sanitizer.sanitize_enron_record(row)

        if res.is_quarantined or not res.cleaned_text.strip():
            continue

        cleaned = res.cleaned_text
        words = len(cleaned.split())
        alnum = sum(c.isalnum() for c in cleaned)
        tokens = analyzer(cleaned)
        n_tokens = len(tokens)

        if rec_id in CATEGORY_A_COLLISIONS:
            quarantine_records.append({
                "source_id": "enron_ham",
                "source_record_id": rec_id,
                "label": 0,
                "email_body": cleaned,
                "n_words": words,
                "n_alnum": alnum,
                "n_tokens": n_tokens,
                "quarantine_category": "CATEGORY_A_CROSS_LABEL_COLLISION",
                "exclusion_reason": CATEGORY_A_COLLISIONS[rec_id],
                "provenance": PROVENANCE_STR,
            })
        elif rec_id in CATEGORY_B_EMPTY_TOKENS:
            quarantine_records.append({
                "source_id": "enron_ham",
                "source_record_id": rec_id,
                "label": 0,
                "email_body": cleaned,
                "n_words": words,
                "n_alnum": alnum,
                "n_tokens": n_tokens,
                "quarantine_category": "CATEGORY_B_EMPTY_TOKEN_SEQUENCE",
                "exclusion_reason": CATEGORY_B_EMPTY_TOKENS[rec_id],
                "provenance": PROVENANCE_STR,
            })
        else:
            token_str = " ".join(tokens)
            seq_hash = hashlib.sha256(token_str.encode("utf-8")).hexdigest()
            candidate_records.append({
                "email_body": cleaned,
                "label": 0,
                "source_id": "enron_ham",
                "source_record_id": rec_id,
                "analyzer_sequence_hash": seq_hash,
                "provenance": PROVENANCE_STR,
            })

    print("Step 4: Processing SpamAssasin.csv (Ham only)...")
    df_sa = pd.read_csv(ZENODO_DIR / "SpamAssasin.csv")
    for idx, row in df_sa.iterrows():
        if int(row.get("label", 0)) != 0:
            continue
        rec_id = f"sa_row_{idx}"
        res = sanitizer.sanitize_spamassassin_record(row)

        if res.is_quarantined or not res.cleaned_text.strip():
            continue

        cleaned = res.cleaned_text
        tokens = analyzer(cleaned)
        token_str = " ".join(tokens)
        seq_hash = hashlib.sha256(token_str.encode("utf-8")).hexdigest()

        candidate_records.append({
            "email_body": cleaned,
            "label": 0,
            "source_id": "spamassassin_ham",
            "source_record_id": rec_id,
            "analyzer_sequence_hash": seq_hash,
            "provenance": PROVENANCE_STR,
        })

    # Convert to DataFrames
    df_candidate = pd.DataFrame(candidate_records)
    df_quarantine = pd.DataFrame(quarantine_records)

    # Verification checks
    print("\n--- IN-LINE VERIFICATION CHECKS ---")
    print(f"Candidate records: {len(df_candidate)} (Expected: 37,350)")
    print(f"Quarantine records: {len(df_quarantine)} (Expected: 27)")
    
    assert len(df_candidate) == 37350, f"Candidate count mismatch: {len(df_candidate)}"
    assert len(df_quarantine) == 27, f"Quarantine count mismatch: {len(df_quarantine)}"

    phish_count = int((df_candidate["label"] == 1).sum())
    ham_count = int((df_candidate["label"] == 0).sum())
    print(f"Candidate Phishing: {phish_count} (Expected: 3,509)")
    print(f"Candidate Ham:      {ham_count} (Expected: 33,841)")
    assert phish_count == 3509, f"Phishing count mismatch: {phish_count}"
    assert ham_count == 33841, f"Ham count mismatch: {ham_count}"

    # Group counts
    unique_groups = df_candidate["analyzer_sequence_hash"].nunique()
    print(f"Unique analyzer sequence groups: {unique_groups} (Expected: 36,468)")
    assert unique_groups == 36468, f"Group count mismatch: {unique_groups}"

    # Verify no cross-label groups
    grouped_labels = df_candidate.groupby("analyzer_sequence_hash")["label"].nunique()
    cross_label_groups = int((grouped_labels > 1).sum())
    print(f"Cross-label groups: {cross_label_groups} (Expected: 0)")
    assert cross_label_groups == 0, f"Found {cross_label_groups} cross-label groups!"

    # Save to disk
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    print(f"\nWriting candidate dataset to {CANDIDATE_CSV}...")
    df_candidate.to_csv(CANDIDATE_CSV, index=False, encoding="utf-8")
    
    print(f"Writing quarantine dataset to {QUARANTINE_CSV}...")
    df_quarantine.to_csv(QUARANTINE_CSV, index=False, encoding="utf-8")

    # Checksums
    candidate_sha = compute_sha256(CANDIDATE_CSV)
    quarantine_sha = compute_sha256(QUARANTINE_CSV)

    manifest_data = {
        "metadata": {
            "title": "BANTAI Content-Only Phishing Detection Candidate Corpus",
            "research_title": "XGBoost-Based Email Threat Detection and Analysis Engine using Explainability Framework",
            "crisp_dm_phase": "Phase 3 (Data Preparation) / Phase 4.3 (Candidate Dataset Construction)",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "target_branch": "feature/content-only-NLP",
        },
        "candidate_corpus": {
            "file_name": CANDIDATE_CSV.name,
            "sha256": candidate_sha,
            "total_records": int(len(df_candidate)),
            "class_distribution": {
                "class_1_credential_phishing": int(phish_count),
                "class_0_legitimate_ham": int(ham_count),
                "phishing_percentage": float(round(phish_count / len(df_candidate) * 100, 4)),
                "ham_percentage": float(round(ham_count / len(df_candidate) * 100, 4)),
                "imbalance_ratio": float(round(ham_count / phish_count, 4)),
            },
            "source_distribution": {str(k): int(v) for k, v in df_candidate["source_id"].value_counts().items()},
            "group_accounting": {
                "total_unique_analyzer_groups": int(unique_groups),
                "singleton_groups": int((df_candidate["analyzer_sequence_hash"].value_counts() == 1).sum()),
                "duplicate_groups": int((df_candidate["analyzer_sequence_hash"].value_counts() > 1).sum()),
                "total_duplicate_records": int(df_candidate["analyzer_sequence_hash"].value_counts()[df_candidate["analyzer_sequence_hash"].value_counts() > 1].sum()),
                "excess_duplicate_instances": int(df_candidate["analyzer_sequence_hash"].value_counts()[df_candidate["analyzer_sequence_hash"].value_counts() > 1].sum()) - int((df_candidate["analyzer_sequence_hash"].value_counts() > 1).sum()),
                "cross_label_groups": int(cross_label_groups),
                "cross_source_groups": int((df_candidate.groupby("analyzer_sequence_hash")["source_id"].nunique() > 1).sum()),
            },
            "tfidf_analyzer_specification": {
                "lowercase": True,
                "token_pattern": r"(?u)\b\w\w+\b",
                "hashing_algorithm": "SHA-256 of space-joined unigrams",
            },
            "schema": [
                {"name": "email_body", "type": "string", "description": "Canonical natural language body text, case-preserved"},
                {"name": "label", "type": "int64", "description": "Binary target label (1=phishing, 0=legitimate)"},
                {"name": "source_id", "type": "string", "description": "Originating source collection"},
                {"name": "source_record_id", "type": "string", "description": "Original raw row or message identifier"},
                {"name": "analyzer_sequence_hash", "type": "string", "description": "Deterministic SHA-256 hash of analyzer token sequence"},
                {"name": "provenance", "type": "string", "description": "Sanitization and cleaning pipeline version descriptor"},
            ],
        },
        "quarantine_corpus": {
            "file_name": QUARANTINE_CSV.name,
            "sha256": quarantine_sha,
            "total_records": int(len(df_quarantine)),
            "category_distribution": {str(k): int(v) for k, v in df_quarantine["quarantine_category"].value_counts().items()},
            "source_distribution": {str(k): int(v) for k, v in df_quarantine["source_id"].value_counts().items()},
            "label_distribution": {str(k): int(v) for k, v in df_quarantine["label"].value_counts().items()},
            "records": [
                {
                    "source_id": str(r["source_id"]),
                    "source_record_id": str(r["source_record_id"]),
                    "label": int(r["label"]),
                    "quarantine_category": str(r["quarantine_category"]),
                    "exclusion_reason": str(r["exclusion_reason"]),
                }
                for r in df_quarantine.to_dict(orient="records")
            ],
        },
    }

    print(f"Writing manifest to {MANIFEST_JSON}...")
    with open(MANIFEST_JSON, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2, default=lambda x: int(x) if hasattr(x, "item") else str(x))

    print("\nCandidate dataset construction complete and verified!")
    return df_candidate, df_quarantine, manifest_data


if __name__ == "__main__":
    build_candidate_dataset()

