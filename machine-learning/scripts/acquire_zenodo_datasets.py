import os
import sys
import json
import time
import hashlib
import subprocess
import urllib.request
from datetime import datetime, timezone

ZENODO_RECORD_ID = "8339691"
ZENODO_DOI = "10.5281/zenodo.8339691"
ZENODO_API_URL = f"https://zenodo.org/api/records/{ZENODO_RECORD_ID}"

APPROVED_FILES = [
    "Nazario.csv",
    "Nazario_5.csv",
    "SpamAssasin.csv",
    "Enron.csv"
]

TARGET_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "data", "raw", "external", "zenodo_8339691"
))

def get_zenodo_metadata():
    print(f"Fetching Zenodo record metadata from {ZENODO_API_URL}...")
    req = urllib.request.Request(ZENODO_API_URL, headers={"User-Agent": "BANTAI-Research/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))

def download_file_curl(url, dest_path, expected_size):
    retries = 0
    max_retries = 30
    while retries < max_retries:
        current_size = os.path.getsize(dest_path) if os.path.exists(dest_path) else 0
        if current_size >= expected_size:
            print(f"File {dest_path} reached expected size ({current_size:,} bytes).")
            break
        print(f"Transferring {dest_path} (current: {current_size:,} / {expected_size:,} bytes)...")
        # Run curl with resume
        cmd = [
            "curl.exe", "-L", "-C", "-",
            "--retry", "10",
            "--retry-all-errors",
            "--retry-delay", "2",
            "--connect-timeout", "30",
            "-o", dest_path,
            url
        ]
        res = subprocess.run(cmd)
        current_size = os.path.getsize(dest_path) if os.path.exists(dest_path) else 0
        if current_size >= expected_size:
            break
        retries += 1
        print(f"Connection closed at {current_size:,} bytes. Retrying (attempt {retries}/{max_retries})...")
        time.sleep(2)

def download_and_verify():
    os.makedirs(TARGET_DIR, exist_ok=True)
    record_meta = get_zenodo_metadata()
    all_files = {f.get("key"): f for f in record_meta.get("files", [])}

    manifest_entries = {}
    acquisition_timestamp = datetime.now(timezone.utc).isoformat()

    for filename in APPROVED_FILES:
        file_info = all_files.get(filename)
        if not file_info:
            raise RuntimeError(f"Metadata not found for {filename}")

        expected_size = file_info.get("size")
        expected_checksum_raw = file_info.get("checksum", "")
        expected_md5 = expected_checksum_raw.replace("md5:", "").strip() if "md5:" in expected_checksum_raw else expected_checksum_raw
        download_url = f"https://zenodo.org/records/{ZENODO_RECORD_ID}/files/{filename}?download=1"

        dest_path = os.path.join(TARGET_DIR, filename)

        print(f"\n=======================================================")
        print(f"File: {filename}")
        print(f"Expected Size: {expected_size:,} bytes")
        print(f"Expected MD5:  {expected_md5}")
        print(f"Download URL:  {download_url}")

        download_file_curl(download_url, dest_path, expected_size)

        # Verify checksums
        actual_size = os.path.getsize(dest_path)
        print(f"Calculating MD5 and SHA-256 for {filename} ({actual_size:,} bytes)...")
        md5_calc = hashlib.md5()
        sha256_calc = hashlib.sha256()
        with open(dest_path, "rb") as f:
            while chunk := f.read(65536):
                md5_calc.update(chunk)
                sha256_calc.update(chunk)

        calc_md5 = md5_calc.hexdigest().lower()
        calc_sha256 = sha256_calc.hexdigest().lower()

        print(f"Official MD5: {expected_md5}")
        print(f"Local MD5:    {calc_md5}")
        print(f"Local SHA256: {calc_sha256}")

        if calc_md5 != expected_md5:
            raise ValueError(f"Checksum MISMATCH for {filename}! Expected {expected_md5}, got {calc_md5}")
        if actual_size != expected_size:
            raise ValueError(f"Size MISMATCH for {filename}! Expected {expected_size}, got {actual_size}")

        print(f"Integrity check PASSED for {filename}.")

        manifest_entries[filename] = {
            "original_filename": filename,
            "download_url": download_url,
            "zenodo_reported_size_bytes": expected_size,
            "actual_size_bytes": actual_size,
            "official_md5": expected_md5,
            "local_md5": calc_md5,
            "local_sha256": calc_sha256,
            "integrity_match": True,
            "doi": ZENODO_DOI,
            "acquisition_timestamp": acquisition_timestamp,
            "local_path": dest_path
        }

    manifest_path = os.path.join(TARGET_DIR, "source_manifest.json")
    manifest_data = {
        "zenodo_record_id": ZENODO_RECORD_ID,
        "zenodo_doi": ZENODO_DOI,
        "record_title": record_meta.get("metadata", {}).get("title"),
        "license": record_meta.get("metadata", {}).get("license"),
        "publication_date": record_meta.get("metadata", {}).get("publication_date"),
        "creators": record_meta.get("metadata", {}).get("creators", []),
        "acquisition_date": acquisition_timestamp,
        "files": manifest_entries
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)

    print(f"\nSource manifest written to: {manifest_path}")
    print("All 4 files successfully acquired and cryptographically verified.")

if __name__ == "__main__":
    download_and_verify()
