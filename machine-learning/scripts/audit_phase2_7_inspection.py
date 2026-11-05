import os
import re
import sys
import json
import email
import email.policy
import hashlib
from datetime import datetime, timezone
from collections import Counter
import pandas as pd
import numpy as np

# Ensure machine-learning root is in path
ML_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ML_ROOT)

from src.preprocessing.content_cleaner import ContentOnlyCleaner, CleanerConfig

PHISHING_POT_DIR = os.path.join(ML_ROOT, "data", "raw", "external", "phishing_pot")
NIGERIAN_FRAUD_PATH = os.path.join(ML_ROOT, "data", "raw", "external", "nigerian_fraud", "Nigerian_Fraud.csv")
ZENODO_DIR = os.path.join(ML_ROOT, "data", "raw", "external", "zenodo_8339691")
SYNTHETIC_PATH = os.path.join(ML_ROOT, "data", "raw", "Balanced_Dataset.csv")
REPORTS_DIR = os.path.join(ML_ROOT, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

cleaner = ContentOnlyCleaner()

def audit_nigerian_fraud():
    print("\n--- Auditing Nigerian_Fraud.csv ---")
    df = pd.read_csv(NIGERIAN_FRAUD_PATH, low_memory=False)
    total_rows = len(df)
    columns = list(df.columns)
    print(f"Total rows: {total_rows:,}, Columns: {columns}")
    
    null_counts = {col: int(df[col].isna().sum()) for col in df.columns}
    print(f"Null counts: {null_counts}")
    
    # Clean bodies
    cleaned_bodies = []
    body_hashes = []
    word_counts = []
    raw_lengths = []
    
    for idx, row in df.iterrows():
        raw_b = str(row.get("body", "")) if pd.notna(row.get("body")) else ""
        raw_lengths.append(len(raw_b))
        cb = cleaner.clean(raw_b)
        cleaned_bodies.append(cb)
        h = hashlib.sha256(cb.encode("utf-8")).hexdigest() if cb else ""
        body_hashes.append(h)
        word_counts.append(len(cb.split()) if cb else 0)
        
    df["cleaned_body"] = cleaned_bodies
    df["body_hash"] = body_hashes
    df["clean_word_count"] = word_counts
    
    empty_clean = int((df["clean_word_count"] == 0).sum())
    unique_hashes = set(h for h in body_hashes if h)
    exact_duplicates = total_rows - len(unique_hashes) - (1 if empty_clean > 1 else 0)
    
    # Common fraud keywords
    fraud_keywords = ["transfer", "million", "fund", "funds", "bank", "barrister", "account", "usd", "assistance", "confidential", "security", "contract", "claim"]
    keyword_freq = {}
    for kw in fraud_keywords:
        c = int(df["cleaned_body"].str.contains(r"\b" + kw + r"\b", case=False, regex=True).sum())
        keyword_freq[kw] = c
        
    stats = {
        "total_rows": total_rows,
        "columns": columns,
        "null_counts": null_counts,
        "empty_cleaned_bodies": empty_clean,
        "unique_cleaned_bodies": len(unique_hashes),
        "exact_duplicates": exact_duplicates,
        "raw_char_len": {
            "min": int(np.min(raw_lengths)),
            "max": int(np.max(raw_lengths)),
            "median": float(np.median(raw_lengths)),
            "mean": float(np.mean(raw_lengths))
        },
        "clean_word_count": {
            "min": int(np.min(word_counts)),
            "max": int(np.max(word_counts)),
            "median": float(np.median(word_counts)),
            "mean": float(np.mean(word_counts))
        },
        "fraud_keyword_frequencies": keyword_freq
    }
    print(f"Empty bodies after cleaning: {empty_clean}")
    print(f"Unique cleaned bodies: {len(unique_hashes):,} (Duplicates: {exact_duplicates})")
    print(f"Clean word count median: {stats['clean_word_count']['median']}, mean: {stats['clean_word_count']['mean']:.1f}")
    return stats, df

def audit_phishing_pot():
    print("\n--- Auditing Phishing Pot .eml files ---")
    eml_files = [f for f in os.listdir(PHISHING_POT_DIR) if f.endswith(".eml")]
    total_files = len(eml_files)
    print(f"Total .eml files to inspect: {total_files}")
    
    records = []
    malformed_count = 0
    empty_body_count = 0
    content_types = Counter()
    dates = []
    senders = []
    subjects = []
    cleaned_bodies = []
    body_hashes = []
    word_counts = []
    phishing_at_pot_header = 0
    phishing_at_pot_body = 0
    
    # Category classifiers heuristics
    phish_brand_kw = re.compile(r"\b(microsoft|office\s*365|o365|sharepoint|onedrive|docusign|adobe|apple|icloud|google|gmail|paypal|bank|chase|wells\s*fargo|citi|fedex|dhl|usps|ups|meta|facebook|netflix|account|verify|password|suspended|urgent|action\s*required|invoice|payment)\b", re.IGNORECASE)
    spam_kw = re.compile(r"\b(unsubscribe|newsletter|discount|clearance|casino|viagra|cialis|keto|cbd|pills|slot|crypto|loan|debt|seo|marketing\s*agency)\b", re.IGNORECASE)
    fraud_kw = re.compile(r"\b(barrister|inheritance|consignment|diplomat|beneficiary|compensation|fund\s*transfer|next\s*of\s*kin)\b", re.IGNORECASE)
    malware_ext_kw = re.compile(r"\.(exe|scr|vbs|iso|img|hta|wsf|bat|cmd|ps1|jar|dll|bin)\b", re.IGNORECASE)
    
    preliminary_categories = Counter()
    
    for idx, fname in enumerate(eml_files):
        fpath = os.path.join(PHISHING_POT_DIR, fname)
        try:
            with open(fpath, "rb") as f:
                raw_bytes = f.read()
            msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
        except Exception as e:
            malformed_count += 1
            continue
            
        subj = str(msg.get("subject", "") or "")
        from_hdr = str(msg.get("from", "") or "")
        to_hdr = str(msg.get("to", "") or "")
        date_hdr = str(msg.get("date", "") or "")
        
        # Check presence of phishing@pot
        full_headers_str = "\n".join(f"{k}: {v}" for k, v in msg.items())
        if "phishing@pot" in full_headers_str.lower():
            phishing_at_pot_header += 1
            
        # Extract body
        body_str = ""
        try:
            if msg.is_multipart():
                plain_cand = ""
                html_cand = ""
                for part in msg.walk():
                    ctype = part.get_content_type()
                    content_types[ctype] += 1
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        try:
                            decoded = payload.decode(charset, errors="replace")
                        except Exception:
                            decoded = payload.decode("utf-8", errors="replace")
                        if ctype == "text/plain" and not plain_cand and decoded.strip():
                            plain_cand = decoded
                        elif ctype == "text/html" and not html_cand and decoded.strip():
                            html_cand = decoded
                body_str = plain_cand if plain_cand else html_cand
            else:
                ctype = msg.get_content_type()
                content_types[ctype] += 1
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    try:
                        body_str = payload.decode(charset, errors="replace")
                    except Exception:
                        body_str = payload.decode("utf-8", errors="replace")
        except Exception:
            pass
                        
        if "phishing@pot" in body_str.lower():
            phishing_at_pot_body += 1
            
        cb = cleaner.clean(body_str) if body_str else ""
        wc = len(cb.split()) if cb else 0
        if wc == 0:
            empty_body_count += 1
            
        bh = hashlib.sha256(cb.encode("utf-8")).hexdigest() if cb else ""
        
        # Check attachments for malware heuristics
        has_suspicious_attachment = False
        try:
            for part in msg.walk():
                fn = part.get_filename() or ""
                if fn and malware_ext_kw.search(fn):
                    has_suspicious_attachment = True
                    break
        except Exception:
            pass
                
        # Classify preliminary category
        combined_text = f"{subj} {cb}"
        if has_suspicious_attachment:
            cat = "Malware Delivery"
        elif fraud_kw.search(combined_text):
            cat = "Financial / Social Engineering Fraud"
        elif phish_brand_kw.search(combined_text):
            cat = "Confirmed Phishing Candidate"
        elif spam_kw.search(combined_text):
            cat = "Commercial Spam"
        elif wc > 0:
            cat = "Other Unsolicited / Uncertain"
        else:
            cat = "Empty / Incomplete Body"
            
        preliminary_categories[cat] += 1
        
        dates.append(date_hdr)
        senders.append(from_hdr)
        subjects.append(subj)
        cleaned_bodies.append(cb)
        body_hashes.append(bh)
        word_counts.append(wc)
        
        records.append({
            "filename": fname,
            "subject": subj,
            "from": from_hdr,
            "to": to_hdr,
            "date": date_hdr,
            "category": cat,
            "clean_body": cb,
            "clean_word_count": wc,
            "body_hash": bh
        })
        
    df_pot = pd.DataFrame(records)
    unique_hashes = set(h for h in body_hashes if h)
    exact_duplicates = len(records) - len(unique_hashes) - (1 if empty_body_count > 1 else 0)
    
    # Extract years from date headers
    years = []
    for d in dates:
        m = re.search(r"\b(201\d|202\d)\b", d)
        if m:
            years.append(m.group(1))
    year_distribution = dict(Counter(years).most_common())
    
    stats = {
        "total_files": total_files,
        "valid_messages": len(records),
        "malformed_files": malformed_count,
        "empty_cleaned_bodies": empty_body_count,
        "unique_cleaned_bodies": len(unique_hashes),
        "exact_duplicates": exact_duplicates,
        "content_type_distribution": dict(content_types),
        "year_distribution": year_distribution,
        "phishing_at_pot_in_headers": phishing_at_pot_header,
        "phishing_at_pot_in_body": phishing_at_pot_body,
        "preliminary_categories": dict(preliminary_categories),
        "clean_word_count": {
            "min": int(np.min(word_counts)) if word_counts else 0,
            "max": int(np.max(word_counts)) if word_counts else 0,
            "median": float(np.median(word_counts)) if word_counts else 0,
            "mean": float(np.mean(word_counts)) if word_counts else 0
        }
    }
    
    print(f"Valid messages: {stats['valid_messages']}, Malformed: {malformed_count}")
    print(f"Empty cleaned bodies: {empty_body_count}")
    print(f"Unique cleaned bodies: {len(unique_hashes):,} (Exact duplicates: {exact_duplicates})")
    print(f"Preliminary categories: {stats['preliminary_categories']}")
    print(f"Year distribution: {year_distribution}")
    print(f"phishing@pot in headers: {phishing_at_pot_header}, in body: {phishing_at_pot_body}")
    return stats, df_pot

def audit_cross_source_overlap(df_fraud, df_pot):
    print("\n--- Auditing Cross-Source Overlap ---")
    overlap_results = {}
    
    pot_hashes = set(df_pot["body_hash"].dropna()) - {""}
    fraud_hashes = set(df_fraud["body_hash"].dropna()) - {""}
    
    # Internal overlap between Phishing Pot and Nigerian Fraud
    internal_match = pot_hashes.intersection(fraud_hashes)
    overlap_results["pot_vs_nigerian_fraud"] = {
        "exact_matches": len(internal_match),
        "matches": list(internal_match)
    }
    print(f"Phishing Pot vs Nigerian Fraud exact matches: {len(internal_match)}")
    
    # Load Zenodo corpora
    zenodo_corpora = {
        "Nazario.csv": os.path.join(ZENODO_DIR, "Nazario.csv"),
        "Enron.csv": os.path.join(ZENODO_DIR, "Enron.csv"),
        "SpamAssasin.csv": os.path.join(ZENODO_DIR, "SpamAssasin.csv")
    }
    
    for cname, cpath in zenodo_corpora.items():
        if os.path.exists(cpath):
            cdf = pd.read_csv(cpath, low_memory=False)
            chashes = set()
            for b in cdf["body"].dropna():
                cb = cleaner.clean(str(b))
                if cb:
                    chashes.add(hashlib.sha256(cb.encode("utf-8")).hexdigest())
                    
            pot_overlap = len(pot_hashes.intersection(chashes))
            fraud_overlap = len(fraud_hashes.intersection(chashes))
            overlap_results[f"phishing_pot_vs_{cname}"] = pot_overlap
            overlap_results[f"nigerian_fraud_vs_{cname}"] = fraud_overlap
            print(f"Overlap with {cname}: Phishing Pot = {pot_overlap}, Nigerian Fraud = {fraud_overlap}")
        else:
            print(f"Corpus {cname} not found at {cpath}")
            
    # Load Synthetic baseline
    if os.path.exists(SYNTHETIC_PATH):
        syn_df = pd.read_csv(SYNTHETIC_PATH)
        syn_hashes = set()
        col = "body" if "body" in syn_df.columns else "text"
        for t in syn_df[col].dropna():
            cb = cleaner.clean(str(t))
            if cb:
                syn_hashes.add(hashlib.sha256(cb.encode("utf-8")).hexdigest())
        pot_syn = len(pot_hashes.intersection(syn_hashes))
        fraud_syn = len(fraud_hashes.intersection(syn_hashes))
        overlap_results["phishing_pot_vs_synthetic"] = pot_syn
        overlap_results["nigerian_fraud_vs_synthetic"] = fraud_syn
        print(f"Overlap with Balanced_Dataset.csv: Phishing Pot = {pot_syn}, Nigerian Fraud = {fraud_syn}")
        
    return overlap_results

def create_unified_manifest():
    manifest_path = os.path.join(ML_ROOT, "data", "raw", "external", "source_manifest_phase2_7.json")
    
    # Hash of Nigerian_Fraud.csv
    with open(NIGERIAN_FRAUD_PATH, "rb") as f:
        fraud_bytes = f.read()
    fraud_md5 = hashlib.md5(fraud_bytes).hexdigest()
    fraud_sha256 = hashlib.sha256(fraud_bytes).hexdigest()
    
    # Aggregated phishing_pot stats
    eml_files = [f for f in os.listdir(PHISHING_POT_DIR) if f.endswith(".eml")]
    pot_total_bytes = sum(os.path.getsize(os.path.join(PHISHING_POT_DIR, f)) for f in eml_files)
    
    manifest = {
        "manifest_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "phase": "2.7 - Controlled Acquisition of Independent Threat Corpora",
        "datasets": {
            "nigerian_fraud": {
                "dataset_name": "Nigerian Fraud Email Corpus (CLAIR 419 Collection)",
                "source_doi": "10.5281/zenodo.8339691",
                "source_url": "https://zenodo.org/records/8339691/files/Nigerian_Fraud.csv?download=1",
                "filename": "Nigerian_Fraud.csv",
                "local_path": "machine-learning/data/raw/external/nigerian_fraud/Nigerian_Fraud.csv",
                "acquisition_date": datetime.now(timezone.utc).isoformat(),
                "file_size_bytes": len(fraud_bytes),
                "official_md5": "65fd47ae7cb4ae762e4be42b11905d63",
                "computed_md5": fraud_md5,
                "computed_sha256": fraud_sha256,
                "integrity_match": fraud_md5 == "65fd47ae7cb4ae762e4be42b11905d63",
                "license": "CC BY 4.0 (Zenodo record-level); original CLAIR academic distribution",
                "attribution": "Champa, Rabbi, & Zibran (2023); CLAIR Group, University of Michigan (Dragomir Radev)",
                "description": "Historical 419 Advance-Fee Fraud solicitation emails. Pure social engineering with zero credential harvesting.",
                "classification_limitations": "Advance-fee financial fraud; must not be conflated with credential-harvesting phishing without subtype annotation."
            },
            "phishing_pot": {
                "dataset_name": "Phishing Pot (rf-peixoto/phishing_pot)",
                "source_repository": "https://github.com/rf-peixoto/phishing_pot",
                "commit_sha": "80a486701223f31e5c641024d6e45f2663f1b2cb",
                "acquisition_date": datetime.now(timezone.utc).isoformat(),
                "sample_selection_strategy": "Representative systematic uniform stride (every 6th file across 12,864 files)",
                "total_eml_files": len(eml_files),
                "total_bytes": pot_total_bytes,
                "license": "CC BY-NC 4.0 (Attribution-NonCommercial 4.0 International)",
                "maintainer": "Renato Peixoto (rf-peixoto)",
                "attribution": "Renato Peixoto, Phishing Pot (2022-2024)",
                "description": "Real-world honeypot email captures containing modern credential harvesting, brand impersonation, and unsolicited mail.",
                "classification_limitations": "Collected from honeypots; contains mixed threat types (phishing, commercial spam, fraud, malware delivery)."
            }
        }
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"\nPhase 2.7 Source Manifest created at: {manifest_path}")
    return manifest

def main():
    fraud_stats, df_fraud = audit_nigerian_fraud()
    pot_stats, df_pot = audit_phishing_pot()
    overlap_stats = audit_cross_source_overlap(df_fraud, df_pot)
    manifest = create_unified_manifest()
    
    full_audit = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nigerian_fraud": fraud_stats,
        "phishing_pot": pot_stats,
        "cross_source_overlap": overlap_stats
    }
    
    out_json = os.path.join(REPORTS_DIR, "phase2_7_acquisition_audit.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(full_audit, f, indent=2)
    print(f"\nAudit complete! Full results saved to: {out_json}")

if __name__ == "__main__":
    main()
