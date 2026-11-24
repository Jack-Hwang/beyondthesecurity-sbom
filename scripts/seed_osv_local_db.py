"""Seed the local OSV database (bts_sbom_osv_local.db) from the advisories the scans already recorded.

The full ecosystem dump import (osv_local_db.import_ecosystem_dump, hundreds of MB per ecosystem) is the
bulk path; this is the small path: every advisory id found in evidence/runs project records is fetched as a
full OSV document from api.osv.dev, stored once in `vulns`, and linked through `pkg_map` with the same
affected-package derivation the dump import uses - so nl2sql answers over the user's actually-scanned
packages instead of an empty shell. import_meta records the provenance as ecosystem key "scan-seed".

Usage: python scripts/seed_osv_local_db.py [--runs evidence/runs]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bts_sbom._internal import osv_local_db            # noqa: E402  (init_db/_connect + the schema contract)
from bts_sbom_app import osv as osv_client             # noqa: E402  (api.osv.dev client, threaded)

SKIP = (".cdx.json", ".spdx.json", ".prev.json", ".vex.json", "report.json")


def advisory_ids(runs: str) -> list:
    """(vuln_id -> ecosystem) for every advisory recorded in the scan runs, aliases included."""
    out = {}
    for p in sorted(glob.glob(os.path.join(runs, "*", "*.json"))):
        base = os.path.basename(p)
        if base.endswith(SKIP):
            continue
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(d, dict) or "components" not in d:
            continue
        for v in d.get("vulns") or []:
            eco = v.get("ecosystem") or ""
            for vid in [v.get("id")] + list(v.get("osv_ids") or []) + list(v.get("aliases") or []):
                if vid and vid not in out:
                    out[vid] = eco
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default=os.path.join("evidence", "runs"))
    args = ap.parse_args()

    wanted = advisory_ids(args.runs)
    if not wanted:
        print("no scan advisories found under %s - nothing to seed" % args.runs)
        return 1
    print("advisory ids from scan runs: %d" % len(wanted))

    docs = osv_client.get_vulns(list(wanted))               # threaded, ~8 workers
    good = {vid: doc for vid, doc in docs.items() if isinstance(doc, dict) and doc.get("id")}
    missing = sorted(set(wanted) - set(good))
    print("full OSV documents fetched: %d (unresolved: %d)" % (len(good), len(missing)))

    osv_local_db.init_db()
    conn = osv_local_db._connect()
    cur = conn.cursor()
    nv = np = 0
    try:
        for vid, doc in good.items():
            eco = wanted[vid] or "PyPI"
            cur.execute("INSERT OR REPLACE INTO vulns (ecosystem, vuln_id, vuln_json) VALUES (?,?,?)",
                        (eco, vid, json.dumps(doc)))
            nv += 1
            seen = set()
            for aff in doc.get("affected") or []:
                pname = (aff.get("package") or {}).get("name") or ""
                pl = pname.lower()
                if not pl or pl in seen:
                    continue
                seen.add(pl)
                cur.execute("INSERT OR REPLACE INTO pkg_map (ecosystem, package_name, vuln_id) VALUES (?,?,?)",
                            (eco, pl, vid))
                np += 1
        cur.execute("INSERT OR REPLACE INTO import_meta (ecosystem, vuln_count, imported_at) VALUES (?,?,?)",
                    ("scan-seed", nv, time.time()))
        conn.commit()
    finally:
        conn.close()

    print("seeded: %d vulns, %d pkg_map links -> %s" % (nv, np, osv_local_db.DB_PATH))
    if missing:
        print("unresolved ids (kept honest, not stored): %s" % ", ".join(missing[:8]) + (" ..." if len(missing) > 8 else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
