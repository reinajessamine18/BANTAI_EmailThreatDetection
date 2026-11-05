import os
import sys
import json
import time
import hashlib
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

TARGET_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "data", "raw", "external", "phishing_pot"
))
COMMIT_SHA = "80a486701223f31e5c641024d6e45f2663f1b2cb"
TREE_URL = f"https://api.github.com/repos/rf-peixoto/phishing_pot/git/trees/{COMMIT_SHA}?recursive=1"
RAW_BASE_URL = f"https://raw.githubusercontent.com/rf-peixoto/phishing_pot/{COMMIT_SHA}"
MAX_DOWNLOAD_BYTES = 250 * 1024 * 1024  # 250 MB ceiling
TARGET_COUNT = 2000

def get_tree_items():
    print(f"Fetching repository tree at commit {COMMIT_SHA}...")
    req = urllib.request.Request(TREE_URL, headers={"User-Agent": "BANTAI-Research/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    
    eml_items = [it for it in data.get("tree", []) if it.get("path", "").endswith(".eml")]
    
    def get_num(item):
        p = item.get("path", "")
        base = p.split("/")[-1].replace(".eml", "").replace("sample-", "")
        try:
            return int(base)
        except ValueError:
            return 999999
            
    eml_sorted = sorted(eml_items, key=get_num)
    print(f"Total .eml files in repository tree: {len(eml_sorted)}")
    return eml_sorted

def select_representative_subset(eml_sorted, target_count=TARGET_COUNT):
    # Stride across all items to guarantee uniform temporal representation
    step = len(eml_sorted) // target_count
    subset = eml_sorted[::step][:target_count]
    total_expected_bytes = sum(f.get("size", 0) for f in subset)
    print(f"Selected {len(subset)} files using stride {step}.")
    print(f"Expected aggregate size: {total_expected_bytes:,} bytes ({total_expected_bytes / (1024*1024):.2f} MB)")
    if total_expected_bytes > MAX_DOWNLOAD_BYTES:
        raise RuntimeError(f"Subset size {total_expected_bytes} exceeds limit {MAX_DOWNLOAD_BYTES}!")
    return subset

def download_single_eml(item):
    rel_path = item.get("path")
    expected_size = item.get("size", 0)
    filename = os.path.basename(rel_path)
    dest_path = os.path.join(TARGET_DIR, filename)
    
    # If already downloaded and size matches, calculate hash and return
    if os.path.exists(dest_path) and os.path.getsize(dest_path) == expected_size:
        with open(dest_path, "rb") as f:
            content = f.read()
        sha256 = hashlib.sha256(content).hexdigest()
        md5 = hashlib.md5(content).hexdigest()
        return {
            "filename": filename,
            "relative_repo_path": rel_path,
            "bytes": len(content),
            "sha256": sha256,
            "md5": md5,
            "status": "cached"
        }
        
    url = f"{RAW_BASE_URL}/{rel_path}"
    req = urllib.request.Request(url, headers={"User-Agent": "BANTAI-Research/1.0"})
    
    retries = 3
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read()
            with open(dest_path, "wb") as f:
                f.write(content)
            sha256 = hashlib.sha256(content).hexdigest()
            md5 = hashlib.md5(content).hexdigest()
            return {
                "filename": filename,
                "relative_repo_path": rel_path,
                "bytes": len(content),
                "sha256": sha256,
                "md5": md5,
                "status": "downloaded"
            }
        except Exception as e:
            if attempt == retries - 1:
                return {
                    "filename": filename,
                    "relative_repo_path": rel_path,
                    "error": str(e),
                    "status": "failed"
                }
            time.sleep(1)

def main():
    os.makedirs(TARGET_DIR, exist_ok=True)
    eml_items = get_tree_items()
    subset = select_representative_subset(eml_items, TARGET_COUNT)
    
    print(f"\nStarting parallel download of {len(subset)} .eml files to {TARGET_DIR}...")
    start_time = time.time()
    
    manifest_entries = []
    completed = 0
    total_bytes = 0
    failed = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(download_single_eml, item): item for item in subset}
        for future in as_completed(futures):
            res = future.result()
            completed += 1
            if res.get("status") == "failed":
                failed.append(res)
            else:
                total_bytes += res.get("bytes", 0)
                manifest_entries.append(res)
                
            if completed % 200 == 0 or completed == len(subset):
                elapsed = time.time() - start_time
                print(f"Progress: {completed}/{len(subset)} files ({total_bytes / (1024*1024):.2f} MB downloaded) in {elapsed:.1f}s")
                
    elapsed = time.time() - start_time
    print(f"\nDownload complete in {elapsed:.1f}s!")
    print(f"Successfully downloaded: {len(manifest_entries)} files")
    print(f"Failed: {len(failed)} files")
    print(f"Total downloaded size: {total_bytes:,} bytes ({total_bytes / (1024*1024):.2f} MB)")
    
    manifest_path = os.path.join(TARGET_DIR, "phishing_pot_subset_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump({
            "repository": "https://github.com/rf-peixoto/phishing_pot",
            "commit_sha": COMMIT_SHA,
            "license": "CC BY-NC 4.0",
            "acquisition_date": datetime.now(timezone.utc).isoformat(),
            "target_count": TARGET_COUNT,
            "downloaded_count": len(manifest_entries),
            "total_bytes": total_bytes,
            "files": sorted(manifest_entries, key=lambda x: x["filename"])
        }, f, indent=2)
    print(f"Subset catalog written to: {manifest_path}")

if __name__ == "__main__":
    main()

