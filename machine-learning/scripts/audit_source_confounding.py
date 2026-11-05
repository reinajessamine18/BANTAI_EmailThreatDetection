import os
import re
import json
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import mutual_info_classif

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "raw", "external", "zenodo_8339691"))

def main():
    print("Loading datasets...")
    df_naz = pd.read_csv(os.path.join(BASE_DIR, "Nazario.csv"))
    valid_naz = df_naz[~df_naz["subject"].fillna("").str.contains("FOLDER INTERNAL DATA", case=False)].copy()
    
    df_enron = pd.read_csv(os.path.join(BASE_DIR, "Enron.csv"))
    enron_ham = df_enron[df_enron["label"] == 0].copy()
    enron_spam = df_enron[df_enron["label"] == 1].copy()
    
    df_sa = pd.read_csv(os.path.join(BASE_DIR, "SpamAssasin.csv"))
    sa_ham = df_sa[df_sa["label"] == 0].copy()
    sa_spam = df_sa[df_sa["label"] == 1].copy()

    # Step 5: Phishing phrases in Ham collections
    phish_patterns = [
        "confirm your account",
        "verify your account",
        "password reset",
        "suspended account",
        "security alert",
        "unauthorized login",
        "update your billing",
        "banking online"
    ]
    
    print("\n--- Phishing-like phrase scan in Ham collections ---")
    enron_hits = {}
    for p in phish_patterns:
        cnt = int(enron_ham["body"].fillna("").str.contains(p, case=False).sum())
        enron_hits[p] = cnt
        print(f"Enron Ham '{p}': {cnt}")
        
    sa_hits = {}
    for p in phish_patterns:
        cnt = int(sa_ham["body"].fillna("").str.contains(p, case=False).sum())
        sa_hits[p] = cnt
        print(f"SpamAssassin Ham '{p}': {cnt}")

    # Inspecting hits in Enron
    suspicious_enron = enron_ham[enron_ham["body"].fillna("").str.contains("security alert|verify your account", case=False)]
    print(f"Sample Enron Ham hits count: {len(suspicious_enron)}")
    if len(suspicious_enron) > 0:
        for idx, r in suspicious_enron.head(3).iterrows():
            print(f"  [Enron Ham Row {idx}] Subject: {r.get('subject')} | Body snippet: {repr(str(r.get('body'))[:120])}")

    # Step 6: Source-Label Confounding Analysis
    print("\n--- Source-Label Confounding & Lexical Specificity Analysis ---")
    # Take 1,563 Nazario phish, 1,563 Enron ham, 1,563 SA ham (subsampled)
    np.random.seed(42)
    sample_enron_ham = enron_ham.sample(n=min(len(valid_naz), len(enron_ham)), random_state=42)
    sample_sa_ham = sa_ham.sample(n=min(len(valid_naz), len(sa_ham)), random_state=42)
    
    # Corpus 1: Nazario (Phish=1) vs Enron Ham (Legit=0)
    df_naz_enron = pd.concat([
        pd.DataFrame({"text": valid_naz["body"].fillna(""), "label": 1, "source": "Nazario"}),
        pd.DataFrame({"text": sample_enron_ham["body"].fillna(""), "label": 0, "source": "Enron_Ham"})
    ], ignore_index=True)
    
    vec = TfidfVectorizer(max_features=500, stop_words="english", ngram_range=(1, 1))
    X_ne = vec.fit_transform(df_naz_enron["text"])
    feature_names = vec.get_feature_names_out()
    
    # Calculate difference in mean TF-IDF between Phish (Nazario) and Ham (Enron)
    mean_phish = np.asarray(X_ne[df_naz_enron["label"] == 1].mean(axis=0)).flatten()
    mean_ham_enron = np.asarray(X_ne[df_naz_enron["label"] == 0].mean(axis=0)).flatten()
    diff_ne = mean_phish - mean_ham_enron
    
    top_phish_ne = [feature_names[i] for i in np.argsort(diff_ne)[-15:][::-1]]
    top_ham_enron = [feature_names[i] for i in np.argsort(diff_ne)[:15]]
    
    print("\nTop features predicting Phish (Nazario) vs Enron Ham:")
    print("  Indicative of Nazario Phish:", top_phish_ne)
    print("  Indicative of Enron Ham:    ", top_ham_enron)
    
    # Corpus 2: Nazario (Phish=1) vs SpamAssassin Ham (Legit=0)
    df_naz_sa = pd.concat([
        pd.DataFrame({"text": valid_naz["body"].fillna(""), "label": 1, "source": "Nazario"}),
        pd.DataFrame({"text": sample_sa_ham["body"].fillna(""), "label": 0, "source": "SA_Ham"})
    ], ignore_index=True)
    
    vec2 = TfidfVectorizer(max_features=500, stop_words="english", ngram_range=(1, 1))
    X_ns = vec2.fit_transform(df_naz_sa["text"])
    feature_names2 = vec2.get_feature_names_out()
    
    mean_phish2 = np.asarray(X_ns[df_naz_sa["label"] == 1].mean(axis=0)).flatten()
    mean_ham_sa = np.asarray(X_ns[df_naz_sa["label"] == 0].mean(axis=0)).flatten()
    diff_ns = mean_phish2 - mean_ham_sa
    
    top_phish_ns = [feature_names2[i] for i in np.argsort(diff_ns)[-15:][::-1]]
    top_ham_sa = [feature_names2[i] for i in np.argsort(diff_ns)[:15]]
    
    print("\nTop features predicting Phish (Nazario) vs SA Ham:")
    print("  Indicative of Nazario Phish:", top_phish_ns)
    print("  Indicative of SA Ham:       ", top_ham_sa)

    # Stylistic and Era comparison
    print("\n--- Era, Vocabulary, and Style Metrics ---")
    stats = {}
    for name, s_df in [("Nazario_Phish", valid_naz), ("Enron_Ham", enron_ham), ("Enron_Spam", enron_spam), ("SA_Ham", sa_ham), ("SA_Spam", sa_spam)]:
        bodies = s_df["body"].fillna("").astype(str)
        char_lens = bodies.str.len()
        word_lens = bodies.apply(lambda x: len(x.split()))
        stats[name] = {
            "count": len(s_df),
            "median_chars": float(char_lens.median()),
            "mean_chars": float(char_lens.mean()),
            "median_words": float(word_lens.median()),
            "mean_words": float(word_lens.mean()),
            "uppercase_ratio": float(bodies.apply(lambda x: sum(1 for c in x if c.isupper()) / (len(x) + 1)).mean()),
            "digits_ratio": float(bodies.apply(lambda x: sum(1 for c in x if c.isdigit()) / (len(x) + 1)).mean())
        }
    print(json.dumps(stats, indent=2))
    
    # Save results
    out_path = os.path.join(BASE_DIR, "source_confounding_audit.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "phish_patterns_in_ham": {"enron": enron_hits, "sa": sa_hits},
            "top_features_nazario_vs_enron": {"phish": top_phish_ne, "ham": top_ham_enron},
            "top_features_nazario_vs_sa": {"phish": top_phish_ns, "ham": top_ham_sa},
            "style_metrics": stats
        }, f, indent=2)
    print(f"\nAudit saved to {out_path}")

if __name__ == "__main__":
    main()

