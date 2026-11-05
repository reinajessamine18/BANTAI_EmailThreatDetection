"""
BANTAI — Candidate V2 Dataset Construction Script (Phase 4.5.8)
Formal Research Title: XGBoost-Based Email Threat Detection and Analysis Engine
Methodology: CRISP-DM Phase 3/4 (Data Preparation & Modeling Formulation)

Constructs:
  1. candidate_corpus_v2.csv (35,522 records: 1,681 Phish vs 33,841 Ham)
  2. advance_fee_fraud_challenge.csv (15 records: 419 pretexts)
  3. fraudulent_prize_lures.csv (28 records: retail/sweepstakes lures)
  4. ordinary_casino_promotions.csv (138 records: casino marketing)
  5. commercial_advertising.csv (116 records: commercial/affiliate marketing)
  6. pending_category_g_pool.csv (1,043 records: residual bulk with adjudication overlay)
  7. noise_quarantine.csv (488 records: base64/noise and unparseable fragments)
  8. candidate_v2_manifest.json (Cryptographic checksums, counts, schema, and provenance)
"""

import sys
import os
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Tuple, Set
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

ML_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ML_DIR))

# Path definitions
PROCESSED_V1_DIR = ML_DIR / "data" / "processed" / "content_only_candidate"
PROCESSED_V2_DIR = ML_DIR / "data" / "processed" / "content_only_candidate_v2"
REPORTS_DIR = ML_DIR / "reports"

CANDIDATE_V1_CSV = PROCESSED_V1_DIR / "candidate_corpus.csv"
ADJUDICATION_TABLE_CSV = REPORTS_DIR / "phishing_pot_final_adjudication_table.csv"
CATEGORY_G_AUDIT_CSV = REPORTS_DIR / "category_g_147_priority_audit.csv"

# V2 Output paths
CANDIDATE_V2_CSV = PROCESSED_V2_DIR / "candidate_corpus_v2.csv"
CHALLENGE_ADVANCE_FEE_CSV = PROCESSED_V2_DIR / "advance_fee_fraud_challenge.csv"
CHALLENGE_PRIZE_LURES_CSV = PROCESSED_V2_DIR / "fraudulent_prize_lures.csv"
CHALLENGE_CASINO_CSV = PROCESSED_V2_DIR / "ordinary_casino_promotions.csv"
CHALLENGE_COMMERCIAL_CSV = PROCESSED_V2_DIR / "commercial_advertising.csv"
PENDING_CATEGORY_G_CSV = PROCESSED_V2_DIR / "pending_category_g_pool.csv"
NOISE_QUARANTINE_CSV = PROCESSED_V2_DIR / "noise_quarantine.csv"
MANIFEST_V2_JSON = PROCESSED_V2_DIR / "candidate_v2_manifest.json"

# Phishing Pot admission cohorts
POT_CAT_A_IDS: Set[str] = {"sample-3385.eml"}

POT_CAT_C_ADMITTED_IDS: Set[str] = {
    # 7 English verified records
    "sample-4855.eml", "sample-3277.eml", "sample-5569.eml", "sample-3931.eml",
    "sample-5125.eml", "sample-9745.eml", "sample-4963.eml",
    # 3 German FamBet simulated deposits
    "sample-10027.eml", "sample-10081.eml", "sample-9271.eml"
}

POT_CAT_C_ADVANCE_FEE_IDS: Set[str] = {
    "sample-11455.eml", "sample-6409.eml", "sample-2113.eml", "sample-6283.eml",
    "sample-6289.eml", "sample-6541.eml", "sample-6349.eml", "sample-6355.eml",
    "sample-6367.eml", "sample-7285.eml", "sample-5863.eml", "sample-6205.eml",
    "sample-6439.eml", "sample-7045.eml", "sample-2047.eml"
}

POT_CAT_C_NOISE_IDS: Set[str] = {
    "sample-1837.eml",  # Bayesian essay on US Constitution
    "sample-4921.eml",  # 136-char non-actionable filler
}


def compute_sha256(file_path: Path) -> str:
    """Computes SHA-256 checksum of a file on disk."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def build_candidate_v2():
    """Constructs Candidate V2 and all associated non-modeling collections."""
    print("=" * 80)
    print("BANTAI — Phase 4.5.8: Candidate V2 Dataset Construction")
    print("=" * 80)

    # 1. Ensure target directory exists
    PROCESSED_V2_DIR.mkdir(parents=True, exist_ok=True)

    # 2. Load V1 candidate corpus and adjudication tables
    print("\nLoading Candidate V1 corpus and Phase 4.5 adjudication metadata...")
    assert CANDIDATE_V1_CSV.exists(), f"Candidate V1 not found at {CANDIDATE_V1_CSV}"
    assert ADJUDICATION_TABLE_CSV.exists(), f"Adjudication table not found at {ADJUDICATION_TABLE_CSV}"

    df_v1 = pd.read_csv(CANDIDATE_V1_CSV)
    df_adj = pd.read_csv(ADJUDICATION_TABLE_CSV)
    df_g_priority = pd.read_csv(CATEGORY_G_AUDIT_CSV) if CATEGORY_G_AUDIT_CSV.exists() else None

    # Verify V1 integrity
    assert len(df_v1) == 37350, f"Expected 37,350 V1 records, found {len(df_v1)}"
    assert len(df_adj) == 1952, f"Expected 1,952 Phishing Pot records, found {len(df_adj)}"

    # 3. Apply Phase 4.5.6 reclassifications
    print("\nApplying Phase 4.5.6 reclassifications to Phishing Pot metadata...")
    adj_updated = df_adj.copy()
    # sample-4381.eml: D -> B (Microsoft account security phishing in French)
    adj_updated.loc[adj_updated['source_record_id'] == 'sample-4381.eml', 'cat_letter'] = 'B'
    adj_updated.loc[adj_updated['source_record_id'] == 'sample-4381.eml', 'audit_category'] = 'Confirmed account impersonation or unauthorized-access deception'
    
    # sample-6637.eml: D -> E (Ordinary casino advertisement)
    adj_updated.loc[adj_updated['source_record_id'] == 'sample-6637.eml', 'cat_letter'] = 'E'
    adj_updated.loc[adj_updated['source_record_id'] == 'sample-6637.eml', 'audit_category'] = 'Ordinary casino/gambling advertisement'
    
    # sample-6613.eml: D -> G (Southern Kitchen recipe newsletter)
    adj_updated.loc[adj_updated['source_record_id'] == 'sample-6613.eml', 'cat_letter'] = 'G'
    adj_updated.loc[adj_updated['source_record_id'] == 'sample-6613.eml', 'audit_category'] = 'Other unsolicited content without demonstrated phishing intent'

    # Extract ID sets
    pot_cat_b_ids = set(adj_updated[adj_updated['cat_letter'] == 'B']['source_record_id'])
    assert len(pot_cat_b_ids) == 113, f"Expected 113 Category B IDs, found {len(pot_cat_b_ids)}"

    pot_admitted_ids = POT_CAT_A_IDS | pot_cat_b_ids | POT_CAT_C_ADMITTED_IDS
    assert len(pot_admitted_ids) == 124, f"Expected 124 admitted Phishing Pot IDs, found {len(pot_admitted_ids)}"

    # 4. Construct Candidate V2 Primary Modeling Dataset
    print("\nConstructing Candidate V2 primary modeling population...")
    nazario_v2 = df_v1[df_v1['source_id'] == 'nazario'].copy()
    enron_v2 = df_v1[df_v1['source_id'] == 'enron_ham'].copy()
    sa_v2 = df_v1[df_v1['source_id'] == 'spamassassin_ham'].copy()
    pot_v2 = df_v1[(df_v1['source_id'] == 'phishing_pot') & (df_v1['source_record_id'].isin(pot_admitted_ids))].copy()

    # Re-verify counts
    assert len(nazario_v2) == 1557, f"Expected 1,557 Nazario records, got {len(nazario_v2)}"
    assert len(pot_v2) == 124, f"Expected 124 Phishing Pot records, got {len(pot_v2)}"
    assert len(enron_v2) == 29751, f"Expected 29,751 Enron records, got {len(enron_v2)}"
    assert len(sa_v2) == 4090, f"Expected 4,090 SpamAssassin records, got {len(sa_v2)}"

    df_v2 = pd.concat([nazario_v2, pot_v2, enron_v2, sa_v2], ignore_index=True)
    assert len(df_v2) == 35522, f"Expected 35,522 Candidate V2 records, got {len(df_v2)}"
    assert df_v2['label'].value_counts()[1] == 1681, f"Expected 1,681 Phishing records, got {df_v2['label'].value_counts()[1]}"
    assert df_v2['label'].value_counts()[0] == 33841, f"Expected 33,841 Legitimate records, got {df_v2['label'].value_counts()[0]}"

    # Standard TF-IDF Analyzer for verification
    print("Verifying analyzer sequence hashes and zero-token absence...")
    vec = TfidfVectorizer(lowercase=True, token_pattern=r"(?u)\b\w\w+\b")
    analyzer = vec.build_analyzer()

    recomputed_hashes = []
    for idx, r in df_v2.iterrows():
        tokens = analyzer(str(r['email_body']))
        assert len(tokens) > 0, f"Zero-token record detected at {r['source_record_id']}"
        token_str = " ".join(tokens)
        h = hashlib.sha256(token_str.encode('utf-8')).hexdigest()
        recomputed_hashes.append(h)

    assert (df_v2['analyzer_sequence_hash'] == recomputed_hashes).all(), "Analyzer sequence hash mismatch!"

    # Cross-label collisions
    collisions = df_v2.groupby('analyzer_sequence_hash')['label'].nunique()
    cross_label = collisions[collisions > 1]
    assert len(cross_label) == 0, f"Cross-label collisions found: {len(cross_label)}"

    # Save Candidate V2
    df_v2.to_csv(CANDIDATE_V2_CSV, index=False)
    print(f"-> Successfully saved candidate_corpus_v2.csv ({len(df_v2)} rows)")

    # 5. Construct Non-Modeling Collections
    print("\nConstructing separately traceable non-modeling collections...")
    df_pot_all = df_v1[df_v1['source_id'] == 'phishing_pot'].copy()

    # Collection 1: Advance-Fee Fraud Challenge (15 records)
    df_aff = df_pot_all[df_pot_all['source_record_id'].isin(POT_CAT_C_ADVANCE_FEE_IDS)].copy()
    assert len(df_aff) == 15, f"Expected 15 advance-fee fraud records, got {len(df_aff)}"
    df_aff['collection_type'] = "Out-of-Domain Fraud Challenge"
    df_aff['threat_category'] = "Advance-Fee Fraud (419 Pretext)"
    df_aff.to_csv(CHALLENGE_ADVANCE_FEE_CSV, index=False)
    print(f"-> Saved advance_fee_fraud_challenge.csv ({len(df_aff)} rows)")

    # Collection 2: Fraudulent Prize / Sweepstakes Lures (28 records)
    pot_cat_d_ids = set(adj_updated[adj_updated['cat_letter'] == 'D']['source_record_id'])
    assert len(pot_cat_d_ids) == 28, f"Expected 28 Category D records, got {len(pot_cat_d_ids)}"
    df_prize = df_pot_all[df_pot_all['source_record_id'].isin(pot_cat_d_ids)].copy()
    assert len(df_prize) == 28, f"Expected 28 prize lure records, got {len(df_prize)}"
    df_prize['collection_type'] = "Out-of-Domain Fraud Challenge"
    df_prize['threat_category'] = "Deceptive Prize / Sweepstakes / Gift Card Lure"
    df_prize.to_csv(CHALLENGE_PRIZE_LURES_CSV, index=False)
    print(f"-> Saved fraudulent_prize_lures.csv ({len(df_prize)} rows)")

    # Collection 3: Ordinary Casino Promotions (138 records)
    pot_cat_e_ids = set(adj_updated[adj_updated['cat_letter'] == 'E']['source_record_id'])
    assert len(pot_cat_e_ids) == 138, f"Expected 138 Category E records, got {len(pot_cat_e_ids)}"
    df_casino = df_pot_all[df_pot_all['source_record_id'].isin(pot_cat_e_ids)].copy()
    assert len(df_casino) == 138, f"Expected 138 casino records, got {len(df_casino)}"
    df_casino['collection_type'] = "Commercial Spam Challenge (Phase 5)"
    df_casino['threat_category'] = "Ordinary Casino & Gambling Promotions"
    df_casino.to_csv(CHALLENGE_CASINO_CSV, index=False)
    print(f"-> Saved ordinary_casino_promotions.csv ({len(df_casino)} rows)")

    # Collection 4: Commercial Advertising (116 records)
    pot_cat_f_ids = set(adj_updated[adj_updated['cat_letter'] == 'F']['source_record_id'])
    assert len(pot_cat_f_ids) == 116, f"Expected 116 Category F records, got {len(pot_cat_f_ids)}"
    df_comm = df_pot_all[df_pot_all['source_record_id'].isin(pot_cat_f_ids)].copy()
    assert len(df_comm) == 116, f"Expected 116 commercial records, got {len(df_comm)}"
    df_comm['collection_type'] = "Commercial Spam Challenge (Phase 5)"
    df_comm['threat_category'] = "Ordinary Commercial Advertising & Affiliate Marketing"
    df_comm.to_csv(CHALLENGE_COMMERCIAL_CSV, index=False)
    print(f"-> Saved commercial_advertising.csv ({len(df_comm)} rows)")

    # Collection 5: Pending Category G Pool (1,043 records with overlay)
    pot_cat_g_ids = set(adj_updated[adj_updated['cat_letter'] == 'G']['source_record_id'])
    assert len(pot_cat_g_ids) == 1043, f"Expected 1,043 Category G records, got {len(pot_cat_g_ids)}"
    df_cat_g = df_pot_all[df_pot_all['source_record_id'].isin(pot_cat_g_ids)].copy()
    assert len(df_cat_g) == 1043, f"Expected 1,043 Category G records, got {len(df_cat_g)}"
    
    # Merge overlay if available
    if df_g_priority is not None:
        overlay_dict = dict(zip(df_g_priority['source_record_id'], df_g_priority['provisional_decision']))
        df_cat_g['adjudication_status'] = df_cat_g['source_record_id'].map(overlay_dict).fillna("Unreviewed Residual Bulk Content")
    else:
        df_cat_g['adjudication_status'] = "Pending Second-Stage Review"
        
    df_cat_g['collection_type'] = "Pending Adjudication Hold Pool"
    df_cat_g['threat_category'] = "Residual Unsolicited Bulk Content"
    df_cat_g.to_csv(PENDING_CATEGORY_G_CSV, index=False)
    print(f"-> Saved pending_category_g_pool.csv ({len(df_cat_g)} rows)")

    # Collection 6: Noise Quarantine (488 records)
    pot_cat_h_ids = set(adj_updated[adj_updated['cat_letter'] == 'H']['source_record_id'])
    assert len(pot_cat_h_ids) == 486, f"Expected 486 initial Category H records, got {len(pot_cat_h_ids)}"
    noise_ids = pot_cat_h_ids | POT_CAT_C_NOISE_IDS
    assert len(noise_ids) == 488, f"Expected 488 total noise records, got {len(noise_ids)}"
    df_noise = df_pot_all[df_pot_all['source_record_id'].isin(noise_ids)].copy()
    assert len(df_noise) == 488, f"Expected 488 noise records, got {len(df_noise)}"
    
    # Tag noise reasons
    noise_reasons = []
    for sid in df_noise['source_record_id']:
        if sid == 'sample-1837.eml':
            noise_reasons.append("Disqualified from Cat C: Bayesian filter evasion (1,500 chars US Constitution essay)")
        elif sid == 'sample-4921.eml':
            noise_reasons.append("Disqualified from Cat C: Non-actionable filler text (136 chars; zero links/prompts)")
        else:
            reason = adj_updated[adj_updated['source_record_id'] == sid]['reason'].iloc[0]
            noise_reasons.append(reason)
            
    df_noise['quarantine_reason'] = noise_reasons
    df_noise['collection_type'] = "Unusable Noise Quarantine Archive"
    df_noise.to_csv(NOISE_QUARANTINE_CSV, index=False)
    print(f"-> Saved noise_quarantine.csv ({len(df_noise)} rows)")

    # Complete Phishing Pot Accounting Check
    print("\nVerifying complete Phishing Pot population accounting...")
    all_accounted_ids = pot_admitted_ids | POT_CAT_C_ADVANCE_FEE_IDS | pot_cat_d_ids | pot_cat_e_ids | pot_cat_f_ids | pot_cat_g_ids | noise_ids
    assert len(all_accounted_ids) == 1952, f"Phishing Pot accounting failed: expected 1,952, got {len(all_accounted_ids)}"
    assert all_accounted_ids == set(df_pot_all['source_record_id']), "ID mismatch with original Phishing Pot candidate records!"
    print("Zero omissions, zero duplications: exactly 1,952 Phishing Pot records accounted for.")

    # 6. Generate Candidate V2 Manifest
    print("\nGenerating candidate_v2_manifest.json...")
    manifest = {
        "manifest_version": "2.0.0",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "formal_research_title": "XGBoost-Based Email Threat Detection and Analysis Engine using Explainability Framework",
        "dataset_name": "BANTAI Content-Only Candidate Corpus V2",
        "provenance_standard": "ContentOnlyCleaner:v3.4|DatasetSanitizer:v4.1.3",
        "primary_candidate_corpus": {
            "file_name": CANDIDATE_V2_CSV.name,
            "total_records": len(df_v2),
            "phishing_records": int(df_v2['label'].sum()),
            "legitimate_records": int((df_v2['label'] == 0).sum()),
            "class_imbalance_ratio": f"{round((df_v2['label'] == 0).sum() / df_v2['label'].sum(), 2)} : 1",
            "source_distribution": {
                "enron_ham": len(enron_v2),
                "nazario": len(nazario_v2),
                "phishing_pot": len(pot_v2),
                "spamassassin_ham": len(sa_v2)
            },
            "unique_canonical_hashes": int(df_v2['email_body'].nunique()),
            "unique_analyzer_sequence_hashes": int(df_v2['analyzer_sequence_hash'].nunique()),
            "duplicate_analyzer_groups": int((df_v2['analyzer_sequence_hash'].value_counts() > 1).sum()),
            "cross_label_collisions": 0,
            "zero_token_records": 0,
            "sha256": compute_sha256(CANDIDATE_V2_CSV)
        },
        "phishing_pot_complete_accounting": {
            "total_source_records": 1952,
            "admitted_primary_records": len(pot_v2),
            "non_modeling_collections_records": len(df_aff) + len(df_prize) + len(df_casino) + len(df_comm) + len(df_cat_g) + len(df_noise),
            "breakdown": {
                "category_a_credential_harvesting": len(POT_CAT_A_IDS),
                "category_b_account_impersonation": len(pot_cat_b_ids),
                "category_c_admitted_financial_balances": len(POT_CAT_C_ADMITTED_IDS),
                "category_c_advance_fee_fraud_challenge": len(df_aff),
                "category_d_prize_sweepstakes_challenge": len(df_prize),
                "category_e_ordinary_casino_promotions": len(df_casino),
                "category_f_commercial_advertising": len(df_comm),
                "category_g_pending_adjudication_pool": len(df_cat_g),
                "category_h_noise_quarantine": len(df_noise)
            }
        },
        "non_modeling_collections": {
            "advance_fee_fraud_challenge": {
                "file_name": CHALLENGE_ADVANCE_FEE_CSV.name,
                "record_count": len(df_aff),
                "sha256": compute_sha256(CHALLENGE_ADVANCE_FEE_CSV)
            },
            "fraudulent_prize_lures": {
                "file_name": CHALLENGE_PRIZE_LURES_CSV.name,
                "record_count": len(df_prize),
                "sha256": compute_sha256(CHALLENGE_PRIZE_LURES_CSV)
            },
            "ordinary_casino_promotions": {
                "file_name": CHALLENGE_CASINO_CSV.name,
                "record_count": len(df_casino),
                "sha256": compute_sha256(CHALLENGE_CASINO_CSV)
            },
            "commercial_advertising": {
                "file_name": CHALLENGE_COMMERCIAL_CSV.name,
                "record_count": len(df_comm),
                "sha256": compute_sha256(CHALLENGE_COMMERCIAL_CSV)
            },
            "pending_category_g_pool": {
                "file_name": PENDING_CATEGORY_G_CSV.name,
                "record_count": len(df_cat_g),
                "overlay_status": {
                    "confirmed_in_scope_phishing": int((df_cat_g['adjudication_status'] == 'Confirmed In-Scope Phishing').sum()),
                    "confirmed_out_of_scope_commercial": int((df_cat_g['adjudication_status'] == 'Confirmed Out-of-Scope Commercial / Clickbait Spam').sum()),
                    "uncertain_insufficient_evidence": int((df_cat_g['adjudication_status'] == 'Uncertain / Insufficient Evidence').sum()),
                    "unreviewed_residual_bulk": int((df_cat_g['adjudication_status'] == 'Unreviewed Residual Bulk Content').sum())
                },
                "sha256": compute_sha256(PENDING_CATEGORY_G_CSV)
            },
            "noise_quarantine": {
                "file_name": NOISE_QUARANTINE_CSV.name,
                "record_count": len(df_noise),
                "sha256": compute_sha256(NOISE_QUARANTINE_CSV)
            }
        },
        "v1_preservation_verification": {
            "v1_candidate_corpus_sha256": compute_sha256(CANDIDATE_V1_CSV),
            "v1_record_count": len(df_v1),
            "status": "UNTOUCHED_AND_SEALED"
        }
    }

    with open(MANIFEST_V2_JSON, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"-> Successfully written candidate_v2_manifest.json")
    print("\nCandidate V2 Construction completed successfully!")


if __name__ == "__main__":
    build_candidate_v2()

