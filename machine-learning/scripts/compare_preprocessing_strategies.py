"""
compare_preprocessing_strategies.py

Controlled comparison of email cleaning strategies across Nazario, Enron, and SpamAssassin:
1. Config 1 (clean_format_only): URLs and emails kept, formatting and whitespace cleaned.
2. Config 2 (remove_entities): URLs and email addresses stripped entirely.
3. Config 3 (placeholder_entities): URLs replaced with [URL], email addresses replaced with [EMAIL_ADDRESS].
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
import pandas as pd

ML_DIR = Path(__file__).resolve().parents[1]
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from src.preprocessing.content_cleaner import CleanerConfig, ContentOnlyCleaner
from src.preprocessing.dataset_sanitizer import DatasetSanitizer

RAW_DIR = ML_DIR / "data" / "raw" / "external" / "zenodo_8339691"


def run_comparison():
    print("=" * 70)
    print("CONTROLLED PREPROCESSING STRATEGY COMPARISON")
    print("=" * 70)

    configs = {
        "config_1_format_only": CleanerConfig(
            url_strategy="keep",
            email_strategy="keep",
            normalize_whitespace=True,
            normalize_punctuation_spacing=True,
            preserve_case=True,
        ),
        "config_2_remove_entities": CleanerConfig(
            url_strategy="remove",
            email_strategy="remove",
            normalize_whitespace=True,
            normalize_punctuation_spacing=True,
            preserve_case=True,
        ),
        "config_3_placeholder_entities": CleanerConfig(
            url_strategy="placeholder",
            url_placeholder="[URL]",
            email_strategy="placeholder",
            email_placeholder="[EMAIL_ADDRESS]",
            normalize_whitespace=True,
            normalize_punctuation_spacing=True,
            preserve_case=True,
        ),
    }

    cleaners = {name: ContentOnlyCleaner(cfg) for name, cfg in configs.items()}

    # Load 100 representative rows from each file
    df_naz = pd.read_csv(RAW_DIR / "Nazario.csv")
    valid_naz = df_naz[~df_naz["subject"].fillna("").str.contains("FOLDER INTERNAL DATA", case=False)].head(100)

    df_enron = pd.read_csv(RAW_DIR / "Enron.csv")
    enron_ham = df_enron[df_enron["label"] == 0].head(100)

    df_sa = pd.read_csv(RAW_DIR / "SpamAssasin.csv")
    sa_ham = df_sa[df_sa["label"] == 0].head(100)

    samples = {
        "Nazario_Phishing": valid_naz,
        "Enron_Ham": enron_ham,
        "SpamAssassin_Ham": sa_ham,
    }

    results = {}

    for source_name, df_sample in samples.items():
        print(f"\n--- Evaluating Source: {source_name} (100 sample records) ---")
        results[source_name] = {}

        raw_bodies = df_sample["body"].fillna("").astype(str).tolist()
        raw_char_sum = sum(len(b) for b in raw_bodies)
        raw_word_sum = sum(len(b.split()) for b in raw_bodies)

        results[source_name]["baseline_raw"] = {
            "total_chars": raw_char_sum,
            "total_words": raw_word_sum,
            "avg_chars_per_email": round(raw_char_sum / len(raw_bodies), 1),
            "avg_words_per_email": round(raw_word_sum / len(raw_bodies), 1),
        }

        for cfg_name, cleaner in cleaners.items():
            cleaned_texts = [cleaner.clean(b) for b in raw_bodies]
            clean_char_sum = sum(len(c) for c in cleaned_texts)
            clean_word_sum = sum(len(c.split()) for c in cleaned_texts)

            # Check residual artifacts
            has_monkey = sum(1 for c in cleaned_texts if "monkey.org" in c.lower())
            has_jose = sum(1 for c in cleaned_texts if "jose" in c.lower())
            has_enron = sum(1 for c in cleaned_texts if "enron" in c.lower())
            has_ect = sum(1 for c in cleaned_texts if "ect" in c.lower())
            has_listinfo = sum(1 for c in cleaned_texts if "listinfo" in c.lower())
            has_url_tok = sum(1 for c in cleaned_texts if "[URL]" in c)
            has_email_tok = sum(1 for c in cleaned_texts if "[EMAIL_ADDRESS]" in c)

            results[source_name][cfg_name] = {
                "total_chars": clean_char_sum,
                "total_words": clean_word_sum,
                "char_retention_pct": round(clean_char_sum / raw_char_sum * 100, 2) if raw_char_sum > 0 else 0,
                "word_retention_pct": round(clean_word_sum / raw_word_sum * 100, 2) if raw_word_sum > 0 else 0,
                "residual_artifacts": {
                    "monkey_org": has_monkey,
                    "jose": has_jose,
                    "enron": has_enron,
                    "ect": has_ect,
                    "listinfo": has_listinfo,
                    "placeholder_url_count": has_url_tok,
                    "placeholder_email_count": has_email_tok,
                },
            }

            print(f"[{cfg_name}] Chars: {clean_char_sum:,} ({results[source_name][cfg_name]['char_retention_pct']}%) | "
                  f"Words: {clean_word_sum:,} ({results[source_name][cfg_name]['word_retention_pct']}%) | "
                  f"Artifacts: monkey={has_monkey}, enron={has_enron}, listinfo={has_listinfo}, [URL]={has_url_tok}, [EMAIL]={has_email_tok}")

    # Inspect representative qualitative before/after snippets for each source
    print("\n" + "=" * 70)
    print("QUALITATIVE INSPECTION OF REPRESENTATIVE EXAMPLES")
    print("=" * 70)

    examples = {
        "Nazario (Personalized Greeting)": valid_naz.iloc[10]["body"],
        "Enron (Forwarded Memo & Spaced Formatting)": enron_ham.iloc[1]["body"],
        "SpamAssassin (Mailing List Discussion & Footer)": sa_ham.iloc[0]["body"],
    }

    qualitative_reports = {}
    for label, raw_ex in examples.items():
        print(f"\n--- Example: {label} ---")
        qualitative_reports[label] = {
            "raw_snippet": raw_ex[:250],
            "outputs": {},
        }
        print(f"[RAW (first 200 chars)]:\n{repr(raw_ex[:200])}\n")
        for cfg_name, cleaner in cleaners.items():
            cleaned_ex = cleaner.clean(raw_ex)
            qualitative_reports[label]["outputs"][cfg_name] = cleaned_ex[:250]
            print(f"[{cfg_name} (first 200 chars)]:\n{repr(cleaned_ex[:200])}\n")

    out_file = RAW_DIR / "preprocessing_strategy_comparison.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({"metrics": results, "qualitative_examples": qualitative_reports}, f, indent=2)

    print(f"\nComparison results successfully saved to: {out_file}")


if __name__ == "__main__":
    run_comparison()

