from pathlib import Path

import pandas as pd

file_path = (
    Path(__file__).parent
    / "data"
    / "raw"
    / "Balanced_Dataset.csv"
)

print("Loading email bodies and labels...")

df = pd.read_csv(file_path, usecols=["body", "label"])

print("\n--- Missing and Empty Values ---")
missing_bodies = df["body"].isna()
empty_bodies = (
    df["body"].fillna("").astype(str).str.strip().eq("")
)

print("Missing bodies:", int(missing_bodies.sum()))
print("Empty or whitespace-only bodies:", int(empty_bodies.sum()))
print("Rows affected by either condition:",
      int((missing_bodies | empty_bodies).sum()))

print("\n--- Duplicate Checks ---")

# Exact duplicate email bodies, regardless of label.
duplicate_bodies = df["body"].duplicated(keep=False)
print("Rows belonging to duplicated bodies:",
      int(duplicate_bodies.sum()))

# Identical body AND identical label.
duplicate_pairs = df.duplicated(
    subset=["body", "label"],
    keep=False,
)
print("Rows belonging to duplicated body-label pairs:",
      int(duplicate_pairs.sum()))

# Same body assigned to different labels.
labels_per_body = (
    df.dropna(subset=["body"])
    .groupby("body")["label"]
    .nunique()
)

conflicting_bodies = int((labels_per_body > 1).sum())
print("Bodies associated with multiple labels:",
      conflicting_bodies)

print("\n--- Label Validation ---")
print("Unique labels:", sorted(df["label"].dropna().unique().tolist()))

print("\nInspection complete. No rows were modified or deleted.")