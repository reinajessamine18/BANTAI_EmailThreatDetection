#!/usr/bin/env python3
"""Inspect a synthetic email CSV by showing five examples from each label.

This script is read-only. It does not modify the dataset or write sample files.
Expected columns: text, label, phishing_type, severity, confidence.
Labels: 0 = legitimate, 1 = phishing.

Usage:
    python inspect_content_email_dataset.py path/to/dataset.csv

Optional:
    python inspect_content_email_dataset.py path/to/dataset.csv --max-text-chars 1600
    python inspect_content_email_dataset.py path/to/dataset.csv --show-full-text
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

EXPECTED_COLUMNS = ("text", "label", "phishing_type", "severity", "confidence")
LABEL_NAMES = {0: "LEGITIMATE / SAFE", 1: "PHISHING"}


def parse_label(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"0", "0.0", "legitimate", "legit", "safe", "ham"}:
        return 0
    if normalized in {"1", "1.0", "phishing", "phish", "spam"}:
        return 1
    return None


def open_csv(path: Path) -> Tuple[object, str]:
    """Open with common CSV encodings; return (file handle, encoding)."""
    errors = []
    for encoding in ("utf-8-sig", "utf-8", "cp1252"):
        try:
            handle = path.open("r", encoding=encoding, newline="")
            # Force decoding to happen before returning, without loading the file.
            handle.read(4096)
            handle.seek(0)
            return handle, encoding
        except UnicodeDecodeError as exc:
            errors.append(f"{encoding}: {exc}")
            try:
                handle.close()  # type: ignore[possibly-undefined]
            except Exception:
                pass
    raise UnicodeError("Could not decode CSV with utf-8-sig, utf-8, or cp1252. " + " | ".join(errors))


def display_text(value: str, max_chars: int, show_full: bool) -> str:
    text = (value or "").replace("\r\n", "\n").replace("\r", "\n")
    if show_full or len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n... [truncated; {len(text)} characters total]"


def inspect_dataset(path: Path, samples_per_label: int, max_text_chars: int, show_full: bool) -> int:
    if not path.is_file():
        print(f"ERROR: CSV file not found: {path}", file=sys.stderr)
        return 2

    try:
        handle, encoding = open_csv(path)
    except (OSError, UnicodeError) as exc:
        print(f"ERROR: Could not open CSV: {exc}", file=sys.stderr)
        return 2

    counts: Counter = Counter()
    unknown_labels: Counter = Counter()
    blank_text_rows = 0
    malformed_rows = 0
    samples: Dict[int, List[dict]] = {0: [], 1: []}
    columns: List[str] = []

    with handle:
        reader = csv.DictReader(handle)
        columns = list(reader.fieldnames or [])
        if not columns:
            print("ERROR: CSV has no header row.", file=sys.stderr)
            return 2

        normalized_columns = {name.strip().lower(): name for name in columns if name}
        missing = [name for name in EXPECTED_COLUMNS if name not in normalized_columns]

        print("=" * 78)
        print("CONTENT-ONLY EMAIL DATASET INSPECTION (READ-ONLY)")
        print("=" * 78)
        print(f"File: {path.resolve()}")
        print(f"Size: {path.stat().st_size:,} bytes")
        print(f"Encoding: {encoding}")
        print(f"Columns ({len(columns)}): {columns}")

        if missing:
            print("\nWARNING: Expected columns not found:", ", ".join(missing))
            print("The script will still count labels where possible, but sample fields may be unavailable.")

        text_col = normalized_columns.get("text")
        label_col = normalized_columns.get("label")

        for row_number, row in enumerate(reader, start=2):
            if None in row:
                malformed_rows += 1
            label_raw = row.get(label_col, "") if label_col else ""
            label = parse_label(label_raw)
            if label is None:
                unknown_labels[str(label_raw).strip()] += 1
                continue

            counts[label] += 1
            body = row.get(text_col, "") if text_col else ""
            if not (body or "").strip():
                blank_text_rows += 1

            if len(samples[label]) < samples_per_label:
                samples[label].append({
                    "row_number": row_number,
                    "text": body or "",
                    "phishing_type": row.get(normalized_columns.get("phishing_type", ""), ""),
                    "severity": row.get(normalized_columns.get("severity", ""), ""),
                    "confidence": row.get(normalized_columns.get("confidence", ""), ""),
                })

    print("\nDATASET SUMMARY")
    print("-" * 78)
    print(f"Rows with recognized labels: {sum(counts.values()):,}")
    print(f"Label 0 — Legitimate/Safe: {counts[0]:,}")
    print(f"Label 1 — Phishing:        {counts[1]:,}")
    print(f"Blank text rows (recognized labels): {blank_text_rows:,}")
    print(f"Rows with extra CSV fields: {malformed_rows:,}")
    if unknown_labels:
        print("Unrecognized label values:")
        for value, count in unknown_labels.most_common():
            print(f"  {value!r}: {count:,}")

    print("\nSCHEMA CHECK")
    print("-" * 78)
    for column in EXPECTED_COLUMNS:
        status = "FOUND" if column in {c.strip().lower() for c in columns if c} else "MISSING"
        print(f"{column}: {status}")

    for label in (1, 0):
        print("\n" + "=" * 78)
        print(f"{LABEL_NAMES[label]} — FIRST {samples_per_label} SAMPLES")
        print("=" * 78)
        if not samples[label]:
            print("No examples found for this label.")
            continue

        for index, sample in enumerate(samples[label], start=1):
            print(f"\n[{index}] CSV row {sample['row_number']}")
            print(f"phishing_type: {sample['phishing_type']}")
            print(f"severity:      {sample['severity']}")
            print(f"confidence:    {sample['confidence']}")
            print("text:")
            print(display_text(sample["text"], max_text_chars, show_full))
            print("-" * 78)

    print("\nINSPECTION NOTES")
    print("- This script only reads the CSV and prints a small sample; it writes no files.")
    print("- For binary NLP training, use only 'text' as the input feature and 'label' as the target.")
    print("- Do not feed phishing_type, severity, or confidence into the classifier unless a separate, approved experiment explicitly requires it.")
    print("- Inspect duplicates, near-duplicates, label consistency, and template leakage before creating train/validation/test splits.")
    print("- Because this corpus is described as LLM-generated, do not use it as the only evidence of real-world detection accuracy.")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path", type=Path, help="Path to the downloaded email dataset CSV")
    parser.add_argument("--samples-per-label", type=int, default=5,
                        help="Number of examples to print for each label (default: 5)")
    parser.add_argument("--max-text-chars", type=int, default=1400,
                        help="Maximum body characters printed per sample (default: 1400)")
    parser.add_argument("--show-full-text", action="store_true",
                        help="Print full sample bodies instead of truncating them")
    args = parser.parse_args()

    if args.samples_per_label < 1:
        parser.error("--samples-per-label must be at least 1")
    if args.max_text_chars < 1 and not args.show_full_text:
        parser.error("--max-text-chars must be at least 1")

    return inspect_dataset(args.csv_path, args.samples_per_label, args.max_text_chars, args.show_full_text)


if __name__ == "__main__":
    raise SystemExit(main())
