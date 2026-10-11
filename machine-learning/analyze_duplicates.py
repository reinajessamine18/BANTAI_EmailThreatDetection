from pathlib import Path

import pandas as pd

file_path = (
    Path(__file__).parent
    / "data"
    / "raw"
    / "Balanced_Dataset.csv"
)

df = pd.read_csv(file_path, usecols=["body", "label"])

# Exclude missing and blank bodies for this analysis only.
valid = df.loc[
    df["body"].notna()
    & df["body"].astype(str).str.strip().ne("")
].copy()

# Count occurrences of each exact email body.
body_counts = valid["body"].value_counts()

duplicate_groups = body_counts[body_counts > 1]

print("--- Duplicate Analysis ---")
print("Total dataset rows:", f"{len(df):,}")
print("Rows with usable bodies:", f"{len(valid):,}")
print("Unique usable email bodies:", f"{valid['body'].nunique():,}")
print("Distinct bodies appearing more than once:",
      f"{len(duplicate_groups):,}")
print("Rows belonging to duplicate groups:",
      f"{int(duplicate_groups.sum()):,}")
print("Excess copies beyond one per body:",
      f"{int((duplicate_groups - 1).sum()):,}")

# Check the labels associated with repeated bodies.
label_counts = valid.groupby("body")["label"].nunique()
conflicting = label_counts[label_counts > 1]

print("Repeated bodies with conflicting labels:",
      f"{len(conflicting):,}")

print("\nAnalysis complete. Original CSV unchanged.")