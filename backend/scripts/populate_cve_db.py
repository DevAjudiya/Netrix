#!/usr/bin/env python3
"""
Fetch ~1000 CVEs from NVD API v2 and merge into the offline database.

Run inside the backend container:
    python3 scripts/populate_cve_db.py

Fetches CVEs across all severities: CRITICAL, HIGH, MEDIUM, LOW.
Skips CVEs already in the database.
"""

import json
import os
import sys
import time

import requests

# ── Config ────────────────────────────────────────────────────────────────────
API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY  = os.environ.get("NVD_API_KEY", "")
DB_PATH  = "./data/cve_offline.json"
TARGET   = 1000          # total entries wanted in the DB after this run
PAGE_SIZE = 2000         # NVD max per request
# With API key: 50 req/30 s → sleep ~0.65 s between requests
# Without key:  5 req/30 s  → sleep ~6 s
SLEEP    = 0.7 if API_KEY else 6.5

# ── HTTP session ──────────────────────────────────────────────────────────────
session = requests.Session()
session.headers["User-Agent"] = "Netrix/1.0"
if API_KEY:
    session.headers["apiKey"] = API_KEY


# ── Helpers ───────────────────────────────────────────────────────────────────

def _score_to_severity(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score  > 0.0: return "low"
    return "info"


def _parse_item(item: dict):
    """Return (cve_id, entry_dict) or (None, None) if unparseable."""
    cve_data = item.get("cve", {})
    cve_id   = cve_data.get("id", "").upper()
    if not cve_id:
        return None, None

    # English description
    desc = next(
        (d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )

    # CVSS — prefer v3.1, then v3.0, then v2
    metrics    = cve_data.get("metrics", {})
    cvss_score  = 0.0
    cvss_vector = ""
    severity    = "info"

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        mlist = metrics.get(key, [])
        if not mlist:
            continue
        m0 = mlist[0]
        cd = m0.get("cvssData", {})
        cvss_score  = float(cd.get("baseScore", 0.0))
        cvss_vector = cd.get("vectorString", "")
        # baseSeverity lives at different depths across v2/v3
        sev = (m0.get("baseSeverity") or cd.get("baseSeverity") or "")
        severity = sev.lower() if sev else _score_to_severity(cvss_score)
        break


    published = cve_data.get("published", "")[:10]

    # References (cap at 5)
    refs = [r.get("url", "") for r in cve_data.get("references", [])[:5] if r.get("url")]

    # Affected products from CPE configurations (cap at 5)
    affected = []
    for cfg in cve_data.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 6:
                    product = f"{parts[3]} {parts[4]}"
                    version = parts[5] if parts[5] not in ("*", "-") else ""
                    if version:
                        product += f" {version}"
                    if product not in affected:
                        affected.append(product)
                if len(affected) >= 5:
                    break

    short = (desc[:100] + "…") if len(desc) > 100 else desc
    title = f"{cve_id} — {short}" if short else cve_id

    entry = {
        "title":        title,
        "description":  desc,
        "cvss_score":   cvss_score,
        "cvss_vector":  cvss_vector,
        "severity":     severity,
        "published_date": published,
        "affected":     affected,
        "remediation":  (
            f"Apply vendor-supplied patches for {cve_id}. "
            "Update affected software to the latest version. "
            "Restrict network exposure where possible."
        ),
        "references":   refs,
    }
    return cve_id, entry


def fetch_page(severity: str, start: int) -> dict | None:
    params = {
        "cvssV3Severity":  severity,
        "resultsPerPage":  PAGE_SIZE,
        "startIndex":      start,
    }
    for attempt in range(3):
        try:
            r = session.get(API_URL, params=params, timeout=30)
            if r.status_code == 429:
                print("  ⚠ Rate-limited — sleeping 35 s …")
                time.sleep(35)
                continue
            r.raise_for_status()
            return r.json()
        except requests.RequestException as exc:
            print(f"  ✗ Request error (attempt {attempt+1}/3): {exc}")
            time.sleep(5)
    return None


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # Load existing DB
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    try:
        with open(DB_PATH, encoding="utf-8") as fh:
            db = json.load(fh)
        print(f"Loaded offline DB: {len(db)} existing entries")
    except (FileNotFoundError, json.JSONDecodeError):
        db = {}
        print("Starting with empty offline DB")

    need    = max(0, TARGET - len(db))
    added   = 0
    skipped = 0

    if need == 0:
        print(f"DB already has {len(db)} entries — nothing to do.")
        return

    print(f"Need {need} more CVEs to reach {TARGET} total (all severities).\n")

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if added >= need:
            break

        start       = 0
        page_total  = None

        while added < need:
            print(f"[{severity}] Fetching page startIndex={start} …")
            data = fetch_page(severity, start)

            if not data:
                print("  Skipping severity due to repeated fetch failures.")
                break

            page_total = data.get("totalResults", 0)
            vulns      = data.get("vulnerabilities", [])
            print(f"  Got {len(vulns)} items  (NVD total for {severity}: {page_total})")

            if not vulns:
                break

            for item in vulns:
                if added >= need:
                    break
                cve_id, entry = _parse_item(item)
                if not cve_id:
                    continue
                if cve_id in db:
                    skipped += 1
                    continue
                db[cve_id] = entry
                added += 1

            print(f"  Added this page: {added}  |  DB total: {len(db)}")

            start += len(vulns)
            if start >= page_total:
                break

            time.sleep(SLEEP)

    # Save
    with open(DB_PATH, "w", encoding="utf-8") as fh:
        json.dump(db, fh, indent=2, ensure_ascii=False)

    print(f"\n✓ Done — added {added} CVEs, skipped {skipped} duplicates.")
    print(f"✓ Offline DB now contains {len(db)} entries → {DB_PATH}")


if __name__ == "__main__":
    main()
