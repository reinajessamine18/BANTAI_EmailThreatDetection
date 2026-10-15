
from collections import Counter
from pathlib import Path

import pandas as pd

file_path = (
    Path(__file__).parent
    / "data"
    / "raw"
    / "Balanced_Dataset.csv"
)

if not file_path.exists():
    raise FileNotFoundError(f"Dataset not found: {file_path}")

print("Dataset:", file_path.name)
print("File size (MB):", round(file_path.stat().st_size / (1024 * 1024), 2))

# Read the header only.
header = pd.read_csv(file_path, nrows=0)
print("\nColumns:", header.columns.tolist())

required_columns = {"body", "label"}

if not required_columns.issubset(header.columns):
    raise ValueError(
        f"Expected columns {required_columns}, "
        f"but found {set(header.columns)}"
    )

total_rows = 0
missing_bodies = 0
empty_bodies = 0
missing_labels = 0
label_counts = Counter()

print("\nInspecting the full dataset in chunks...")

for chunk in pd.read_csv(
    file_path,
    usecols=["body", "label"],
    chunksize=20_000,
):
    total_rows += len(chunk)

    missing_bodies += int(chunk["body"].isna().sum())
    missing_labels += int(chunk["label"].isna().sum())

    # Check empty or whitespace-only email bodies.
    valid_bodies = chunk["body"].dropna().astype(str)
    empty_bodies += int(valid_bodies.str.strip().eq("").sum())

    label_counts.update(
        chunk["label"].value_counts(dropna=False).to_dict()
    )


print("\n--- Dataset Summary ---")
print("Total rows:", f"{total_rows:,}")
print("Missing bodies:", f"{missing_bodies:,}")
print("Empty bodies:", f"{empty_bodies:,}")
print("Missing labels:", f"{missing_labels:,}")

print("\nLabel distribution:")
for label, count in sorted(label_counts.items(), key=lambda item: str(item[0])):
    print(f"  {label!r}: {count:,}")

print("\nInspection complete. No model was trained.")