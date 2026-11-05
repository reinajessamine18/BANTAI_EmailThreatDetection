"""
audit_full_corpus_cleaning.py

Full-corpus resource-conscious streaming audit of cleaning engine behavior:
Measures before-and-after term occurrences (monkey.org, jose, enron, ect, listinfo, linux)
and word/char retention across ALL rows of Nazario, Enron, and SpamAssassin.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
import pandas as pd

ML_DIR = Path(__file__).resolve().parents[1]
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from src.preprocessing.content_cleaner import CleanerConfig, ContentOnlyCleaner
from src.preprocessing.dataset_sanitizer import DatasetSanitizer

RAW_DIR = ML_DIR / "data" / "raw" / "external" / "zenodo_8339691"

cleaner = ContentOnlyCleaner(CleanerConfig(
    url_strategy="placeholder",
    email_strategy="placeholder",
    normalize_whitespace=True,
    normalize_punctuation_spacing=True,
    preserve_case=True,
))
sanitizer = DatasetSanitizer(cleaner)

TERMS = {
    "monkey.org": r"monkey\.org",
    "jose": r"\bjose\b",
    "enron": r"\benron\b",
    "ect": r"\bect\b",
    "listinfo": r"listinfo",
    "linux": r"\blinux\b",
}


def audit_nazario():
    print("Auditing Nazario.csv (entire corpus)...")
    df = pd.read_csv(RAW_DIR / "Nazario.csv")
    total = len(df)
    quarantined_mbox = 0
    quarantined_b64 = 0
    valid_count = 0

    before_counts = {t: 0 for t in TERMS}
    after_counts = {t: 0 for t in TERMS}
    total_raw_chars = 0
    total_clean_chars = 0
    total_raw_words = 0
    total_clean_words = 0

    for idx, row in df.iterrows():
        res = sanitizer.sanitize_nazario_record(row)
        if res.is_quarantined:
            if res.quarantine_reason == "mbox_metadata_folder_header":
                quarantined_mbox += 1
            else:
                quarantined_b64 += 1
            continue

        valid_count += 1
        raw_b = res.original_text
        clean_b = res.cleaned_text

        total_raw_chars += len(raw_b)
        total_clean_chars += len(clean_b)
        total_raw_words += len(raw_b.split())
        total_clean_words += len(clean_b.split())

        for tname, pat in TERMS.items():
            if re.search(pat, raw_b, re.IGNORECASE):
                before_counts[tname] += 1
            if re.search(pat, clean_b, re.IGNORECASE):
                after_counts[tname] += 1

    return {
        "total_rows": total,
        "valid_rows": valid_count,
        "quarantined_mbox": quarantined_mbox,
        "quarantined_b64": quarantined_b64,
        "raw_chars": total_raw_chars,
        "clean_chars": total_clean_chars,
        "raw_words": total_raw_words,
        "clean_words": total_clean_words,
        "char_retention_pct": round(total_clean_chars / total_raw_chars * 100, 2) if total_raw_chars > 0 else 0,
        "word_retention_pct": round(total_clean_words / total_raw_words * 100, 2) if total_raw_words > 0 else 0,
        "before_terms": before_counts,
        "after_terms": after_counts,
    }


def audit_enron():
    print("Auditing Enron.csv (entire corpus of 29,767 rows)...")
    # Stream in chunks of 5,000 rows
    total_rows = 0
    ham_rows = 0
    before_counts = {t: 0 for t in TERMS}
    after_counts = {t: 0 for t in TERMS}
    total_raw_chars = 0
    total_clean_chars = 0
    total_raw_words = 0
    total_clean_words = 0

    chunk_size = 5000
    for chunk in pd.read_csv(RAW_DIR / "Enron.csv", chunksize=chunk_size):
        ham_chunk = chunk[chunk["label"] == 0]
        total_rows += len(chunk)
        ham_rows += len(ham_chunk)

        for idx, row in ham_chunk.iterrows():
            res = sanitizer.sanitize_enron_record(row, strip_forwarding_headers=True)
            raw_b = res.original_text
            clean_b = res.cleaned_text

            total_raw_chars += len(raw_b)
            total_clean_chars += len(clean_b)
            total_raw_words += len(raw_b.split())
            total_clean_words += len(clean_b.split())

            for tname, pat in TERMS.items():
                if re.search(pat, raw_b, re.IGNORECASE):
                    before_counts[tname] += 1
                if re.search(pat, clean_b, re.IGNORECASE):
                    after_counts[tname] += 1

    return {
        "total_rows": total_rows,
        "ham_rows": ham_rows,
        "raw_chars": total_raw_chars,
        "clean_chars": total_clean_chars,
        "raw_words": total_raw_words,
        "clean_words": total_clean_words,
        "char_retention_pct": round(total_clean_chars / total_raw_chars * 100, 2) if total_raw_chars > 0 else 0,
        "word_retention_pct": round(total_clean_words / total_raw_words * 100, 2) if total_raw_words > 0 else 0,
        "before_terms": before_counts,
        "after_terms": after_counts,
    }


def audit_spamassassin():
    print("Auditing SpamAssasin.csv (entire corpus of 5,809 rows)...")
    df = pd.read_csv(RAW_DIR / "SpamAssasin.csv")
    total_rows = len(df)
    ham_df = df[df["label"] == 0]
    ham_rows = len(ham_df)

    before_counts = {t: 0 for t in TERMS}
    after_counts = {t: 0 for t in TERMS}
    total_raw_chars = 0
    total_clean_chars = 0
    total_raw_words = 0
    total_clean_words = 0

    for idx, row in ham_df.iterrows():
        res = sanitizer.sanitize_spamassassin_record(row, strip_mailman_footers=True)
        raw_b = res.original_text
        clean_b = res.cleaned_text

        total_raw_chars += len(raw_b)
        total_clean_chars += len(clean_b)
        total_raw_words += len(raw_b.split())
        total_clean_words += len(clean_b.split())

        for tname, pat in TERMS.items():
            if re.search(pat, raw_b, re.IGNORECASE):
                before_counts[tname] += 1
            if re.search(pat, clean_b, re.IGNORECASE):
                after_counts[tname] += 1

    return {
        "total_rows": total_rows,
        "ham_rows": ham_rows,
        "raw_chars": total_raw_chars,
        "clean_chars": total_clean_chars,
        "raw_words": total_raw_words,
        "clean_words": total_clean_words,
        "char_retention_pct": round(total_clean_chars / total_raw_chars * 100, 2) if total_raw_chars > 0 else 0,
        "word_retention_pct": round(total_clean_words / total_raw_words * 100, 2) if total_raw_words > 0 else 0,
        "before_terms": before_counts,
        "after_terms": after_counts,
    }


def main():
    report = {
        "nazario": audit_nazario(),
        "enron_ham": audit_enron(),
        "spamassassin_ham": audit_spamassassin(),
    }

    out_path = RAW_DIR / "full_corpus_cleaning_audit.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 70)
    print("FULL CORPUS AUDIT RESULTS")
    print("=" * 70)
    print(json.dumps(report, indent=2))
    print(f"\nSaved audit to: {out_path}")


if __name__ == "__main__":
    main()

