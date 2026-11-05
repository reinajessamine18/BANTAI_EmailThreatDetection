import os
import sys
import re
import json
import hashlib
import numpy as np
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "raw", "external", "zenodo_8339691"))
FILES = ["Nazario.csv", "Nazario_5.csv", "Enron.csv", "SpamAssasin.csv"]

def normalize_text(text):
    if not isinstance(text, str):
        return ""
    # Standard normalization: lower, replace unicode whitespace with space, collapse multi-spaces, strip
    s = text.lower()
    s = re.sub(r"\s+", " ", s).strip()
    return s

def compute_hash(text):
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

def inspect_file(filename):
    filepath = os.path.join(BASE_DIR, filename)
    print(f"\n=======================================================")
    print(f"Inspecting file: {filename}")
    print(f"Path: {filepath}")
    
    # Try reading header first
    df_head = pd.read_csv(filepath, nrows=5)
    columns = list(df_head.columns)
    print(f"Columns ({len(columns)}): {columns}")
    
    # Read full CSV
    # Most files have columns: text / body / content and label / class
    df = pd.read_csv(filepath, low_memory=False)
    total_rows = len(df)
    print(f"Total rows: {total_rows:,}")
    
    # Data types and nulls
    null_info = df.isnull().sum().to_dict()
    print("Null counts per column:", null_info)
    
    # Identify text column and label column
    text_col = None
    for cand in ["text_combined", "text", "body", "email", "Email_Text", "content", "Message"]:
        if cand in df.columns:
            text_col = cand
            break
    if text_col is None:
        # Fallback to column with largest string length
        text_col = df.columns[0]
        
    label_col = None
    for cand in ["label", "Label", "target", "Target", "class", "Class"]:
        if cand in df.columns:
            label_col = cand
            break
            
    print(f"Identified text column: '{text_col}', label column: '{label_col}'")
    
    label_counts = {}
    if label_col:
        vc = df[label_col].value_counts(dropna=False).to_dict()
        label_counts = {str(k): int(v) for k, v in vc.items()}
        print(f"Label distribution: {label_counts}")
        
    # Analyze text column
    raw_texts = df[text_col].fillna("").astype(str)
    
    # Length distributions
    lengths_char = raw_texts.apply(len)
    lengths_words = raw_texts.apply(lambda x: len(x.split()))
    
    length_stats = {
        "char_min": int(lengths_char.min()),
        "char_max": int(lengths_char.max()),
        "char_mean": float(lengths_char.mean()),
        "char_median": float(lengths_char.median()),
        "char_p25": float(lengths_char.quantile(0.25)),
        "char_p75": float(lengths_char.quantile(0.75)),
        "word_min": int(lengths_words.min()),
        "word_max": int(lengths_words.max()),
        "word_mean": float(lengths_words.mean()),
        "word_median": float(lengths_words.median()),
    }
    print("Length stats (characters):", {k: round(v, 2) for k, v in length_stats.items() if "char" in k})
    print("Length stats (words):", {k: round(v, 2) for k, v in length_stats.items() if "word" in k})
    
    # Empty / whitespace-only
    empty_count = int((raw_texts.str.strip() == "").sum())
    print(f"Empty or whitespace-only bodies: {empty_count:,}")
    
    # Duplicate analysis
    exact_duplicates = int(raw_texts.duplicated().sum())
    unique_bodies = int(raw_texts.nunique())
    print(f"Unique email bodies: {unique_bodies:,} ({exact_duplicates:,} duplicate bodies)")
    
    # HTML / MIME / Header indicator analysis
    html_count = int(raw_texts.str.contains(r"<[a-zA-Z][^>]*>", regex=True).sum())
    mime_count = int(raw_texts.str.contains(r"content-type:|mime-version:|boundary=", case=False, regex=True).sum())
    header_count = int(raw_texts.str.contains(r"^(received:|from:|to:|subject:|date:)", case=False, regex=True).sum())
    
    print(f"Records containing HTML tags: {html_count:,} ({html_count/total_rows*100:.1f}%)")
    print(f"Records containing MIME fragments: {mime_count:,} ({mime_count/total_rows*100:.1f}%)")
    print(f"Records starting with email headers: {header_count:,} ({header_count/total_rows*100:.1f}%)")
    
    # Compute normalized text and hashes for cross-file comparison
    norm_texts = raw_texts.apply(normalize_text)
    norm_unique = int(norm_texts.nunique())
    print(f"Unique normalized bodies: {norm_unique:,}")
    
    return {
        "filename": filename,
        "total_rows": total_rows,
        "columns": columns,
        "null_counts": null_info,
        "text_col": text_col,
        "label_col": label_col,
        "label_distribution": label_counts,
        "empty_bodies": empty_count,
        "unique_raw_bodies": unique_bodies,
        "unique_norm_bodies": norm_unique,
        "length_stats": length_stats,
        "html_count": html_count,
        "mime_count": mime_count,
        "header_count": header_count,
        "df": df,
        "raw_texts": raw_texts,
        "norm_texts": norm_texts
    }

def main():
    results = {}
    for filename in FILES:
        filepath = os.path.join(BASE_DIR, filename)
        if not os.path.exists(filepath):
            print(f"File {filepath} does not exist! Wait for acquisition.")
            return
        results[filename] = inspect_file(filename)
        
    print("\n=======================================================")
    print("Cross-Dataset Overlap and Provenance Investigation")
    print("=======================================================")
    
    # Precompute SHA-256 hashes for each file
    hashes = {}
    for filename, res in results.items():
        df = res["df"]
        label_col = res["label_col"]
        norm_texts = res["norm_texts"]
        
        file_hashes = []
        for idx, text in enumerate(norm_texts):
            lbl = df[label_col].iloc[idx] if label_col else None
            h = compute_hash(text)
            file_hashes.append({"idx": idx, "label": lbl, "hash": h, "text_len": len(text)})
        hashes[filename] = file_hashes

    # 1. Nazario vs Nazario_5
    print("\n--- 1. Nazario.csv vs Nazario_5.csv ---")
    naz_hashes = {x["hash"] for x in hashes["Nazario.csv"]}
    naz5_hashes = {x["hash"] for x in hashes["Nazario_5.csv"]}
    naz5_phish = {x["hash"] for x in hashes["Nazario_5.csv"] if str(x["label"]) in ["1", "1.0"]}
    naz5_legit = {x["hash"] for x in hashes["Nazario_5.csv"] if str(x["label"]) in ["0", "0.0"]}
    
    overlap_naz_naz5 = naz_hashes.intersection(naz5_hashes)
    overlap_naz_naz5_phish = naz_hashes.intersection(naz5_phish)
    overlap_naz_naz5_legit = naz_hashes.intersection(naz5_legit)
    
    print(f"Nazario.csv total hashes: {len(naz_hashes):,}")
    print(f"Nazario_5.csv total hashes: {len(naz5_hashes):,} (Phishing hashes: {len(naz5_phish):,}, Legit hashes: {len(naz5_legit):,})")
    print(f"Overlap between Nazario and Nazario_5: {len(overlap_naz_naz5):,} ({len(overlap_naz_naz5)/len(naz_hashes)*100:.2f}% of Nazario)")
    print(f"Nazario overlap with Nazario_5 Phishing: {len(overlap_naz_naz5_phish):,}")
    print(f"Nazario overlap with Nazario_5 Legit: {len(overlap_naz_naz5_legit):,}")
    
    # 2. Nazario_5 Legit vs Enron
    print("\n--- 2. Nazario_5.csv Legitimate vs Enron.csv ---")
    enron_hashes_all = {x["hash"] for x in hashes["Enron.csv"]}
    enron_hashes_ham = {x["hash"] for x in hashes["Enron.csv"] if str(x["label"]) in ["0", "0.0"]}
    enron_hashes_spam = {x["hash"] for x in hashes["Enron.csv"] if str(x["label"]) in ["1", "1.0"]}
    
    overlap_naz5_legit_enron_ham = naz5_legit.intersection(enron_hashes_ham)
    overlap_naz5_legit_enron_spam = naz5_legit.intersection(enron_hashes_spam)
    overlap_naz5_legit_enron_all = naz5_legit.intersection(enron_hashes_all)
    
    print(f"Enron.csv unique hashes: Total {len(enron_hashes_all):,} (Ham: {len(enron_hashes_ham):,}, Spam: {len(enron_hashes_spam):,})")
    print(f"Nazario_5 Legit exact matches with Enron Ham: {len(overlap_naz5_legit_enron_ham):,} ({len(overlap_naz5_legit_enron_ham)/len(naz5_legit)*100:.2f}% of Nazario_5 Legit)")
    print(f"Nazario_5 Legit exact matches with Enron Spam: {len(overlap_naz5_legit_enron_spam):,}")
    print(f"Nazario_5 Legit total matches with Enron: {len(overlap_naz5_legit_enron_all):,}")

    # 3. Nazario_5 Legit vs SpamAssassin
    print("\n--- 3. Nazario_5.csv Legitimate vs SpamAssasin.csv ---")
    sa_hashes_all = {x["hash"] for x in hashes["SpamAssasin.csv"]}
    sa_hashes_ham = {x["hash"] for x in hashes["SpamAssasin.csv"] if str(x["label"]) in ["0", "0.0"]}
    sa_hashes_spam = {x["hash"] for x in hashes["SpamAssasin.csv"] if str(x["label"]) in ["1", "1.0"]}
    
    overlap_naz5_legit_sa_ham = naz5_legit.intersection(sa_hashes_ham)
    overlap_naz5_legit_sa_spam = naz5_legit.intersection(sa_hashes_spam)
    overlap_naz5_legit_sa_all = naz5_legit.intersection(sa_hashes_all)
    
    print(f"SpamAssassin unique hashes: Total {len(sa_hashes_all):,} (Ham: {len(sa_hashes_ham):,}, Spam: {len(sa_hashes_spam):,})")
    print(f"Nazario_5 Legit exact matches with SpamAssassin Ham: {len(overlap_naz5_legit_sa_ham):,} ({len(overlap_naz5_legit_sa_ham)/len(naz5_legit)*100:.2f}% of Nazario_5 Legit)")
    print(f"Nazario_5 Legit exact matches with SpamAssassin Spam: {len(overlap_naz5_legit_sa_spam):,}")
    print(f"Nazario_5 Legit total matches with SpamAssassin: {len(overlap_naz5_legit_sa_all):,}")

    # 4. Enron vs SpamAssassin Overlap
    print("\n--- 4. Enron.csv vs SpamAssasin.csv ---")
    overlap_enron_sa = enron_hashes_all.intersection(sa_hashes_all)
    overlap_enron_sa_ham = enron_hashes_ham.intersection(sa_hashes_ham)
    overlap_enron_sa_spam = enron_hashes_spam.intersection(sa_hashes_spam)
    print(f"Total hash overlap between Enron and SpamAssassin: {len(overlap_enron_sa):,}")
    print(f"Ham-Ham overlap: {len(overlap_enron_sa_ham):,}")
    print(f"Spam-Spam overlap: {len(overlap_enron_sa_spam):,}")
    
    # Save inspection summary json
    summary_data = {
        "files": {
            f: {k: v for k, v in results[f].items() if k not in ["df", "raw_texts", "norm_texts"]}
            for f in FILES
        },
        "overlap": {
            "nazario_in_nazario5": len(overlap_naz_naz5),
            "nazario5_legit_in_enron_ham": len(overlap_naz5_legit_enron_ham),
            "nazario5_legit_in_enron_spam": len(overlap_naz5_legit_enron_spam),
            "nazario5_legit_in_sa_ham": len(overlap_naz5_legit_sa_ham),
            "nazario5_legit_in_sa_spam": len(overlap_naz5_legit_sa_spam),
            "enron_sa_overlap": len(overlap_enron_sa)
        }
    }
    
    out_json = os.path.join(BASE_DIR, "empirical_inspection_summary.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)
    print(f"\nInspection summary successfully written to: {out_json}")

if __name__ == "__main__":
    main()

