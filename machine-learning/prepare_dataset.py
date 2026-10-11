import hashlib
import json
from pathlib import Path

import pandas as pd
import sklearn
from sklearn.model_selection import train_test_split

# --------------------------------------------------
# 1. Paths and reproducibility settings
# --------------------------------------------------

BASE_DIR = Path(__file__).parent
RAW_FILE = BASE_DIR / "data" / "raw" / "Balanced_Dataset.csv"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
REPORT_DIR = BASE_DIR / "reports"

RANDOM_STATE = 42
TEST_SIZE = 0.30
VALIDATION_SHARE_OF_TEMP = 0.50

EXPECTED_LABELS = {0, 1}


def sha256_file(path):
    """Calculate the SHA-256 hash without loading the whole file."""
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


# --------------------------------------------------
# 2. Load and validate the original dataset
# --------------------------------------------------

if not RAW_FILE.exists():
    raise FileNotFoundError(f"Dataset not found: {RAW_FILE}")

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

print("Reading original dataset...")
original_hash = sha256_file(RAW_FILE)

df = pd.read_csv(
    RAW_FILE,
    usecols=["body", "label"],
)

original_rows = len(df)

if df["label"].isna().any():
    raise ValueError("Missing labels detected. Resolve them before splitting.")

if df["label"].nunique() != 2:
    raise ValueError("Expected exactly two label classes.")

if set(df["label"].unique()) != EXPECTED_LABELS:
    raise ValueError(
        f"Unexpected labels: {sorted(df['label'].unique().tolist())}"
    )

# Normalize labels to integers only after validation.
df["label"] = df["label"].astype(int)


# --------------------------------------------------
# 3. Exclude missing and blank bodies
# --------------------------------------------------

missing_body_count = int(df["body"].isna().sum())

blank_body_mask = (
    df["body"].fillna("").astype(str).str.strip().eq("")
)

unusable_body_mask = df["body"].isna() | blank_body_mask

unusable_body_count = int(unusable_body_mask.sum())

df = df.loc[~unusable_body_mask].copy()


# --------------------------------------------------
# 4. Check conflicting labels before deduplication
# --------------------------------------------------

labels_per_body = df.groupby("body")["label"].nunique()
conflicting_bodies = int((labels_per_body > 1).sum())

if conflicting_bodies:
    raise ValueError(
        f"Found {conflicting_bodies} email bodies with conflicting labels. "
        "Investigate them before continuing."
    )


# --------------------------------------------------
# 5. Remove exact duplicate bodies
# --------------------------------------------------

rows_before_deduplication = len(df)

df = df.drop_duplicates(
    subset=["body"],
    keep="first",
).copy()

duplicate_rows_removed = rows_before_deduplication - len(df)

if df["body"].duplicated().any():
    raise AssertionError("Duplicate bodies remain after deduplication.")

if df["body"].isna().any():
    raise AssertionError("Missing bodies remain after cleaning.")

# Verify both classes still exist.
if set(df["label"].unique()) != EXPECTED_LABELS:
    raise ValueError("Both label classes must remain after cleaning.")


# --------------------------------------------------
# 6. Create stratified train/validation/test splits
# --------------------------------------------------

train_df, temporary_df = train_test_split(
    df,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=df["label"],
)

validation_df, test_df = train_test_split(
    temporary_df,
    test_size=1 - VALIDATION_SHARE_OF_TEMP,
    random_state=RANDOM_STATE,
    stratify=temporary_df["label"],
)

splits = {
    "train": train_df.reset_index(drop=True),
    "validation": validation_df.reset_index(drop=True),
    "test": test_df.reset_index(drop=True),
}


# --------------------------------------------------
# 7. Verify no exact body overlaps between splits
# --------------------------------------------------

split_names = list(splits)

for i, first_name in enumerate(split_names):
    first_bodies = set(splits[first_name]["body"])

    for second_name in split_names[i + 1:]:
        second_bodies = set(splits[second_name]["body"])

        overlap = first_bodies.intersection(second_bodies)

        if overlap:
            raise AssertionError(
                f"Data leakage: {first_name} and {second_name} "
                f"share {len(overlap)} exact email bodies."
            )


# --------------------------------------------------
# 8. Save prepared datasets
# --------------------------------------------------

for split_name, split_df in splits.items():
    output_file = PROCESSED_DIR / f"{split_name}.csv"

    split_df.to_csv(
        output_file,
        index=False,
        encoding="utf-8",
    )

    print(f"Saved {split_name}: {len(split_df):,} rows")


# --------------------------------------------------
# 9. Create a preparation report
# --------------------------------------------------

def label_counts(frame):
    counts = frame["label"].value_counts().to_dict()

    return {
        str(label): int(counts.get(label, 0))
        for label in sorted(EXPECTED_LABELS)
    }


report = {
    "experiment": "BANTAI text-classification baseline",
    "source_file": RAW_FILE.name,
    "source_sha256": original_hash,
    "original_file_modified": False,
    "original_rows": int(original_rows),
    "missing_body_rows": missing_body_count,
    "rows_with_missing_or_blank_bodies": unusable_body_count,
    "unusable_body_rows_excluded": unusable_body_count,
    "conflicting_body_groups": conflicting_bodies,
    "duplicate_body_rows_removed": int(duplicate_rows_removed),
    "prepared_unique_rows": len(df),
    "label_mapping": {
        "0": "Safe",
        "1": "Phishing",
    },
    "deduplication": "Exact body match; keep first occurrence",
    "split_ratios_approximate": {
        "train": 0.70,
        "validation": 0.15,
        "test": 0.15,
    },
    "random_state": RANDOM_STATE,
    "stratified_by": "label",
    "text_transformation": "None; raw body text preserved",
    "python_pandas_version": pd.__version__,
    "scikit_learn_version": sklearn.__version__,
    "splits": {
        name: {
            "rows": len(frame),
            "label_counts": label_counts(frame),
        }
        for name, frame in splits.items()
    },
}

report_file = REPORT_DIR / "dataset_preparation_manifest.json"

with report_file.open("w", encoding="utf-8") as file:
    json.dump(report, file, indent=2)

print("\n--- Preparation Summary ---")
print("Original rows:", f"{original_rows:,}")
print("Unusable rows excluded:", f"{unusable_body_count:,}")
print("Duplicate rows removed:", f"{duplicate_rows_removed:,}")
print("Prepared unique rows:", f"{len(df):,}")

for name, frame in splits.items():
    print(f"\n{name.title()}: {len(frame):,} rows")
    print(frame["label"].value_counts().sort_index().to_string())

print("\nOriginal CSV SHA-256:", original_hash)
print("Preparation report:", report_file)
print("Preparation complete. No model was trained.")