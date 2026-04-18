"""
RDDS — OUI Database Expander
Downloads the full IEEE OUI database and converts it to oui.json.

Usage:
    python expand_oui.py

This replaces the existing 40-entry oui.json with a full database of 36,000+ entries.
"""

import json, os, re, pathlib

OUI_PATH = pathlib.Path("data/oui.json")

def build_from_local_txt():
    """
    Try to build from a locally downloaded oui.txt file.
    Download from: https://standards-oui.ieee.org/oui/oui.txt
    Place at: data/oui.txt
    """
    txt_path = pathlib.Path("data/oui.txt")
    if not txt_path.exists():
        return None
    
    oui_db = {}
    with open(txt_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            # Lines like: 70B64F     (base 16)        TP-Link Technologies Co.,Ltd.
            m = re.match(r"([0-9A-F]{6})\s+\(base 16\)\s+(.+)", line.strip())
            if m:
                prefix = m.group(1).upper()
                vendor = m.group(2).strip()[:30]  # truncate long names
                oui_db[prefix] = vendor
    return oui_db


def build_from_ieee_csv():
    """
    Download IEEE OUI CSV directly (smaller and cleaner format).
    CSV URL: https://standards-oui.ieee.org/oui/oui.csv
    Returns None if download fails.
    """
    try:
        import urllib.request, io, csv
        print("[*] Downloading IEEE OUI CSV from standards-oui.ieee.org...")
        url = "https://standards-oui.ieee.org/oui/oui.csv"
        with urllib.request.urlopen(url, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
        
        oui_db = {}
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            # Columns: Registry,Assignment,Organization Name,Organization Address
            prefix = row.get("Assignment", "").strip().upper()
            vendor = row.get("Organization Name", "").strip()[:35]
            if prefix and vendor:
                oui_db[prefix] = vendor
        
        print(f"[+] Downloaded {len(oui_db)} OUI entries from IEEE.")
        return oui_db
    except Exception as e:
        print(f"[!] Download failed: {e}")
        return None


def main():
    # Keep existing entries as fallback
    existing = {}
    if OUI_PATH.exists():
        try:
            with open(OUI_PATH, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception as e:
            print(f"[*] Could not read existing OUI DB ({e}), starting fresh.")
    
    print(f"[*] Base OUI DB: {len(existing)} entries")

    # Try local file first, then download
    new_db = build_from_local_txt()
    if not new_db:
        new_db = build_from_ieee_csv()

    if not new_db:
        print("[!] Could not build new OUI database.")
        print("    Manual option:")
        print("    1. Download: https://standards-oui.ieee.org/oui/oui.txt")
        print("    2. Save as: data/oui.txt")
        print("    3. Run this script again.")
        return

    # Merge: new entries override existing, preserving any custom ones
    merged = {**new_db, **existing}  # existing custom entries take precedence
    
    with open(OUI_PATH, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)
    
    print(f"[+] OUI DB updated: {len(existing)} -> {len(merged)} entries")
    print(f"[+] Saved to {OUI_PATH.resolve()}")


if __name__ == "__main__":
    main()
