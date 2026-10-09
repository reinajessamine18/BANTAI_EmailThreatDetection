#!/usr/bin/env python
"""Minimal audit script for split overlap — BANTAI project."""
from pathlib import Path
import pandas as pd

ML = Path(__file__).parent
files = {
    "train": ML / "data" / "processed" / "train.csv",
    "validation": ML / "data" / "processed" / "validation.csv",
    "test": ML / "data" / "processed" / "test.csv",
}

bs = {}  # body sets for overlap checking
summaries = {}

def desc(name, path):
    if not path.is_file():
        print(f"  {name}: not found")
        return None
    df = pd.read_csv(path, usecols=["body", "label"])
    df["label"] = df["label"].astype(int)
    n = len(df)
    mb = int(df["body"].isna().sum() + (df["body"].astype(str).str.strip() == "").sum())
    dups = int(df["body"].duplicated(keep=False).sum())
    dbody = int(df["body"].value_counts().gt(1).sum())
    lbl = df["label"].value_counts().to_dict()
    return {"rows": n, "missing": mb, "dup_bodies": dbody, "dup_rows": dups, "labels": lbl, "df": df}

print("--- SPLIT SUMMARIES ---")
for s in ["train", "validation", "test"]:
    res = desc(s, files[s])
    if res:
        summaries[s] = res
        bs[s] = set(res["df"]["body"].astype(str))
        print(f"  {s.upper()}: rows={res['rows']:,} missing={res['missing']:,} dup_bodies={res['dup_bodies']:,} dup_rows={res['dup_rows']:,} labels={res['labels']}")
    else:
        summaries[s] = None
    print()

print("--- OVERLAP CHECK ---")
pairs = [("train-val", "train", "validation"),
         ("train-test", "train", "test"),
         ("val-test", "validation", "test")]
for label, a, b in pairs:
    set_a = bs.get(a, set())
    set_b = bs.get(b, set())
    olen = len(set_a & set_b)
    total_a = summaries[a]["rows"]
    total_b = summaries[b]["rows"]
    pct_a = (olen / total_a * 100) if total_a > 0 else 0
    pct_b = (olen / total_b * 100) if total_b > 0 else 0
    print(f"  {label}: {olen} bodies in both")
    print(f"    as pct of {a}: {pct_a:.4f}%  as pct of {b}: {pct_b:.4f}%")

print("--- IDENTICAL BODIES WITH CONFLICTING LABELS ---")
# Check if any body appears in multiple splits with different labels
body_to_label = {}
conflicts = 0
for split, s in summaries.items():
    if s is None:
        continue
    for body, label in zip(s["df"]["body"].astype(str), s["df"]["label"]):
        if body in body_to_label:
            if body_to_label[body] != label:
                conflicts += 1
        else:
            body_to_label[body] = label

if conflicts == 0:
    print("  No identical bodies with conflicting labels across splits.")
else:
    print(f"  {conflicts} identical bodies have conflicting labels.")

print("--- SUMMARY ---")
print(f"Total rows: train={summaries['train']['rows']:,}  val={summaries['validation']['rows']:,}  test={summaries['test']['rows']:,}")
print(f"Max overlap pct: check output above")
print("Audit complete — no modifications made to any files.")