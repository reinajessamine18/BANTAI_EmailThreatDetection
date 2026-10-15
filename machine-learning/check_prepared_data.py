from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).parent
RAW_FILE = BASE_DIR / "data" / "raw" / "Balanced_Dataset.csv"
PROCESSED_DIR = BASE_DIR / "data" / "processed"

print("--- Original Dataset ---")

raw = pd.read_csv(RAW_FILE, usecols=["body", "label"])

print("Rows:", f"{len(raw):,}")
print("Label counts:")
print(raw["label"].value_counts().sort_index().to_string())

usable = raw.loc[
    raw["body"].notna()
    & raw["body"].astype(str).str.strip().ne("")
].copy()

print("\n--- After Excluding Empty Bodies ---")
print("Rows:", f"{len(usable):,}")
print("Label counts:")
print(usable["label"].value_counts().sort_index().to_string())

deduplicated = usable.drop_duplicates(
    subset=["body"],
    keep="first",
)

print("\n--- After Exact Deduplication ---")
print("Rows:", f"{len(deduplicated):,}")
print("Label counts:")
print(
    deduplicated["label"]
    .value_counts()
    .sort_index()
    .to_string()
)

print("\n--- Saved Split Verification ---")

for name in ["train", "validation", "test"]:
    path = PROCESSED_DIR / f"{name}.csv"
    split = pd.read_csv(path, usecols=["body", "label"])

    print(f"\n{name.title()}: {len(split):,} rows")
    print(split["label"].value_counts().sort_index().to_string())

print("\nCheck complete. No files were modified.")