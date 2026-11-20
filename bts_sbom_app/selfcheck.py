"""Self-check in the FOSSLight Hub style: the OSS-review sheet an SBOM project would hand to a reviewer, generated from the
analysed record - one row per component with its name, version, license (never guessed: an unresolved license stays empty) and the
recorded provenance.

Feature inspiration: FOSSLight Hub / FOSSLight Scanner self-check sheets (github.com/fosslight, Apache-2.0). The code is ours;
the sheet is deterministic CSV (stdlib ``csv``) so it opens in any spreadsheet without a third-party dependency. It is a
pre-review CHECKLIST, not a review result: nothing here claims an OSS is cleared for shipping.
"""
from __future__ import annotations

import csv
import io
from typing import Any, Dict, List

SCHEMA = "bts-sbom.selfcheck.v1"
HEADER = ["OSS Name", "OSS Version", "License", "License Category", "License Source", "Ecosystem", "Vulnerabilities", "Files"]
HONESTY = ["an unresolved license stays empty on purpose: it is a question for the reviewer, never a guess",
           "this sheet is a pre-review checklist generated from one analysis, not a review result"]


def build(rec: Dict[str, Any]) -> Dict[str, Any]:
    comps = [c for c in rec.get("components") or [] if isinstance(c, dict) and c.get("name")]
    rows = [{"oss_name": str(c.get("name")), "oss_version": str(c.get("version") or ""), "license": str(c.get("license") or ""),
             "category": str(c.get("license_category") or ("unknown" if not c.get("license") else "")),
             "license_source": str(c.get("license_source") or ""), "ecosystem": str(c.get("ecosystem") or ""),
             "vulns": int(c.get("vulns") or 0), "files": (c.get("files") or [])[:4]} for c in comps]
    return {"schema": SCHEMA, "status": "OK", "name": str(rec.get("name") or ""), "components": len(rows),
            "with_license": sum(1 for r in rows if r["license"]), "rows": rows, "honesty": HONESTY}


def to_csv(rec: Dict[str, Any]) -> str:
    c = build(rec)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(HEADER)
    for r in c["rows"]:
        w.writerow([r["oss_name"], r["oss_version"], r["license"], r["category"], r["license_source"], r["ecosystem"], r["vulns"],
                    "; ".join(r["files"])])
    return buf.getvalue()


def to_md(c: Dict[str, Any]) -> str:
    out = ["# Self-check sheet of %s" % c.get("name", ""), "",
           "%d component(s), %d with a recorded license - %d left empty on purpose for the reviewer." % (
               c.get("components", 0), c.get("with_license", 0), c.get("components", 0) - c.get("with_license", 0)), "",
           "| OSS Name | OSS Version | License | Category | Source | Vulns |", "|---|---|---|---|---|---|"]
    for r in (c.get("rows") or [])[:50]:
        out.append("| %s | %s | %s | %s | %s | %d |" % (r["oss_name"], r["oss_version"], r["license"] or "(unresolved)",
                                                        r["category"] or "-", r["license_source"] or "-", r["vulns"]))
    out += ["", "> " + "; ".join(HONESTY) + "."]
    return "\n".join(out) + "\n"
