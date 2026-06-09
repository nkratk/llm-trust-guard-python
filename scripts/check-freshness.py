#!/usr/bin/env python3
"""
Freshness gate (G10) + scan helper. See VERIFICATION.md.

Per-push (no network): fails if the research re-check cadence has lapsed —
i.e. `lastFullScan` or any tracked topic's `checkedAt` is older than `ttlDays`
in freshness.json. This makes staleness BLOCK a push instead of silently
lingering in RESEARCH_LOG.md.

--links (network, used by the weekly cron): also verifies each tracked source
URL still resolves, catching link rot.

Exit code: 0 = fresh, 1 = stale / dead links / missing manifest.

NOTE: this verifies the *recency* signals machine-objectively. Judging whether
NEW research is *relevant* is a human/LLM step — that's what the weekly cron
surfaces via a GitHub issue, not something a script decides.
"""
import argparse
import datetime
import json
import os
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--links", action="store_true", help="also check source URLs resolve (network)")
    ap.add_argument("--file", default="freshness.json")
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, args.file)
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        print(f"  {args.file} missing")
        return 1

    ttl = int(doc.get("ttlDays", 180))
    today = datetime.date.today()

    def age(s: str) -> int:
        return (today - datetime.date.fromisoformat(s)).days

    rc = 0
    overdue = []
    if age(doc["lastFullScan"]) > ttl:
        overdue.append(f"lastFullScan {doc['lastFullScan']} ({age(doc['lastFullScan'])}d > {ttl}d TTL)")
    for t in doc.get("tracked", []):
        a = age(t["checkedAt"])
        if a > ttl:
            overdue.append(f"{t['topic']}: checkedAt {t['checkedAt']} ({a}d > {ttl}d)")

    if overdue:
        print(f"  STALE — research re-check overdue (TTL {ttl}d):")
        for o in overdue:
            print("    - " + o)
        print("  Re-scan sources, decide relevance, then bump freshness.json (checkedAt/lastFullScan)")
        print("  and add a RESEARCH_LOG.md entry before pushing.")
        rc = 1
    else:
        print(f"  fresh — all within {ttl}d TTL (lastFullScan {doc['lastFullScan']}, {len(doc.get('tracked', []))} topics)")

    if args.links:
        import urllib.request

        dead = []
        for t in doc.get("tracked", []):
            url = t.get("source", "")
            ok = False
            for method in ("HEAD", "GET"):
                try:
                    req = urllib.request.Request(url, method=method, headers={"User-Agent": "freshness-check"})
                    urllib.request.urlopen(req, timeout=15)
                    ok = True
                    break
                except Exception:  # noqa: BLE001 - any failure means try GET / mark dead
                    continue
            if not ok:
                dead.append(f"{t['topic']}: {url}")
        if dead:
            print("  DEAD LINKS:")
            for d in dead:
                print("    - " + d)
            rc = 1
        else:
            print(f"  all {len(doc.get('tracked', []))} source links resolve")

    return rc


if __name__ == "__main__":
    sys.exit(main())
