"""Human-readable reports (Markdown + self-contained HTML) for one project and for a batch."""
from __future__ import annotations

import html
from typing import Any, Dict, List

_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
_COLOR = {"CRITICAL": "#8e1b1b", "HIGH": "#c2410c", "MEDIUM": "#b7791f", "LOW": "#2f6f4f", "UNKNOWN": "#555"}


def project_md(rec: Dict[str, Any], top: int = 15) -> str:
    m = rec.get("metrics") or {}
    L: List[str] = ["# %s" % rec["name"], ""]
    if rec.get("error"):
        return "\n".join(L + ["**FAILED**: " + rec["error"], ""])
    lin = rec.get("lineage") or {}
    L += ["- source: `%s` (commit `%s`)" % (rec.get("source"), (lin.get("commit") or "")[:10]),
          "- components: %s - vulnerabilities: %s %s" % (m.get("components"), m.get("vulns"), m.get("severity")),
          "- license resolved: %s of %s (%s) from %s" % (m.get("license_resolved"), m.get("license_total"), m.get("license_resolved_rate"), m.get("license_sources")),
          "- project license: %s (%s)" % ((rec.get("license") or {}).get("project_license") or "not detected", (rec.get("license") or {}).get("project_license_source") or "-"),
          "- SBOM: CycloneDX valid=%s, SPDX valid=%s, affects refs resolved=%s" % (m.get("cyclonedx_valid"), m.get("spdx_valid"), m.get("sbom_ref_rate")), ""]
    vs = sorted(rec.get("vulns") or [], key=lambda v: (_SEV_ORDER.index(v["severity"]) if v["severity"] in _SEV_ORDER else 9, -(v.get("cvss") or 0)))[:top]
    if vs:
        L += ["## Top vulnerabilities", "", "| id | package | version | severity | CVSS | fixed in |", "|---|---|---|---|---|---|"]
        L += ["| %s | %s | %s | %s | %s | %s |" % (v["id"], v["package"], v["version"], v["severity"], v.get("cvss") if v.get("cvss") is not None else "-", v["fixed_version"] or "-") for v in vs]
        L.append("")
    ups = [p for p in rec.get("plans") or [] if p["status"] == "upgrade"][:top]
    if ups:
        L += ["## Remediation plan (verified against OSV)", "", "| component | from | to | clears | major | verified clean |", "|---|---|---|---|---|---|"]
        L += ["| %s | %s | %s | %d | %s | %s |" % (p["component"], p["current_version"], p["safe_version"], len(p["clears"]), p["major_bump"], p["verification"].get("clean")) for p in ups]
        L.append("")
    pa = rec.get("patch") or {}
    if pa.get("status") not in (None, "not_requested"):
        L += ["## Patch", "", "- status: **%s** (approved=%s), applied components: %s, rescan fixed: %s" % (pa.get("status"), pa.get("approved"), pa.get("applied_components"), pa.get("rescan_fixed_total")), ""]
        if pa.get("note"):
            L += ["- note: " + pa["note"], ""]
        if pa.get("regenerate"):
            L += ["- regenerate lockfiles: " + "; ".join("`%s`" % x for x in pa["regenerate"][:5]), ""]
    a = rec.get("arch") or {}
    if a:
        g = a.get("graph") or {}
        L += ["## Architecture", "", "- %s files, %s LOC, %s import edges, %s cycles (tangle %s)" % ((a.get("stack") or {}).get("files"), (a.get("stack") or {}).get("loc"), g.get("import_edges"), g.get("cycle_count"), g.get("tangle_ratio"))]
        for h in (a.get("hotspots") or [])[:5]:
            L.append("- hotspot `%s`: %d commits, %d LOC, score %s" % (h["file"], h["commits"], h["loc"], h["score"]))
        for r in (a.get("runtime_eol") or [])[:4]:
            L.append("- runtime %s %s: %s (%s)" % (r["product"], r["cycle"], r["status"], r["source"]))
        for n in a.get("notes") or []:
            L.append("- note: " + n)
        L.append("")
    if rec.get("sectors"):
        L += ["## Industry reports", "", "| industry | verdict | pass | gap | not_evidence | draft |", "|---|---|---|---|---|---|"]
        for k, r in rec["sectors"].items():
            s = r.get("summary") or {}
            L.append("| %s | %s | %s | %s | %s | %s |" % (k, r.get("verdict"), s.get("pass"), s.get("gap"), s.get("not_evidence"), bool(r.get("draft"))))
        L.append("")
    pr = rec.get("proposals") or {}
    if pr:
        L += ["## Proposals (%s%s)" % (pr.get("source"), (" - " + pr["llm_note"]) if pr.get("llm_note") else ""), ""]
        if pr.get("summary"):
            L += [pr["summary"], ""]
        L += ["- [%s/%s] %s - %s" % (i["action"], i["risk"], i["title"], i["rationale"]) for i in pr.get("items") or []]
        L.append("")
    if rec.get("stage_errors"):
        L += ["## Stage errors", ""] + ["- %s: %s" % kv for kv in rec["stage_errors"].items()] + [""]
    return "\n".join(L)


def batch_md(summary: Dict[str, Any], recs: List[Dict[str, Any]]) -> str:
    s = summary["summary"]
    L = ["# SBOM+ batch %s" % summary.get("tag", ""), "",
         "- projects: %s (errors %s) - components %s - vulnerabilities %s %s" % (s["projects"], s["errors"], s["components"], s["vulns"], s["severity"]),
         "- license resolved rate: %s - by source %s" % (s["license_resolved_rate"], s["license_sources"]),
         "- plans verified clean: %s of %s - patch: %s" % (s["plans_verified_clean"], s["plans_upgrade"], s["patch"]),
         "- avg analysis: %ss - proposals: %s" % (s["analysis_s_avg"], s["proposals"]), "",
         "| project | components | vulns | license | plans clean | patch | arch edges | proposals |", "|---|---|---|---|---|---|---|---|"]
    for r in recs:
        m = r.get("metrics") or {}
        L.append("| %s | %s | %s | %s | %s/%s | %s | %s | %s |" % (r["name"], m.get("components", "-") if not r.get("error") else "ERR", m.get("vulns", "-"), m.get("license_resolved_rate", "-"),
                                                                m.get("plans_verified_clean", "-"), m.get("plans_upgrade", "-"), m.get("patch_status", "-"), m.get("arch_edges", "-"), m.get("proposal_source", "-")))
    return "\n".join(L) + "\n"


def batch_html(summary: Dict[str, Any], recs: List[Dict[str, Any]]) -> str:
    e = html.escape
    s = summary["summary"]
    sev = "".join('<span class="b" style="background:%s">%s %d</span>' % (_COLOR[k], k, s["severity"].get(k, 0)) for k in _SEV_ORDER if s["severity"].get(k))
    rows = []
    for r in recs:
        m = r.get("metrics") or {}
        rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s/%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            e(r["name"]), e(str(m.get("components", "ERR"))), e(str(m.get("vulns", "-"))), e(str(m.get("license_resolved_rate", "-"))),
            e(str(m.get("plans_verified_clean", "-"))), e(str(m.get("plans_upgrade", "-"))), e(str(m.get("patch_status", "-"))),
            e(str(m.get("arch_edges", "-"))), e(str(m.get("proposal_source", r.get("error") or "-")))))
    return ("<!doctype html><html lang='ko'><meta charset='utf-8'><title>SBOM+ batch</title><style>body{font:14px system-ui;margin:2rem;color:#1a1a1a}"
            "table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px 8px}th{background:#f3f3f3}.b{color:#fff;padding:2px 8px;border-radius:10px;margin-right:6px}</style>"
            "<h1>SBOM+ batch %s</h1><p>%s</p><p>projects %s - components %s - vulnerabilities %s - license resolved %s - avg analysis %ss</p>"
            "<table><tr><th>project</th><th>components</th><th>vulns</th><th>license</th><th>plans clean</th><th>patch</th><th>arch edges</th><th>proposals</th></tr>%s</table></html>"
            % (e(str(summary.get("tag", ""))), sev, s["projects"], s["components"], s["vulns"], s["license_resolved_rate"], s["analysis_s_avg"], "".join(rows)))
