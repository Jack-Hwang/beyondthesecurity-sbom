"""Rewrite support after the SBOM: WHICH components must be rewritten, WHY (with the evidence), and a developer
dossier with everything a developer needs to rewrite one of them.

Entry (trigger) - the clean-room lane used to start only from a strong-copyleft licence. A component enters the same
rewrite path for any of these reasons, each read from data the tool already records (nothing is invented):

  license         strong-/network-copyleft category on the component                       (measured, scan record)
  no_fix          its advisories have no fixed version - a patch cannot exist                (measured, remediation plan)
  fix_incomplete  the verified upgrade still leaves advisories - a patch does not close it   (measured, plan verification)
  eol             end-of-life / end-of-support / deprecated / unmaintained                   (declared: the eol input, the same
                                                                                              {component: {eol, status}} contract
                                                                                              the sector reports read)
  incompatible    the component cannot be moved to the target runtime / upgraded             (declared by the operator, verbatim)
  -- context only (listed, never a trigger on their own): runtime_eol (the manifest that declares it targets an EOL
  runtime), major_bump_fix (the only fix is a major-version jump, compatibility untested), eol_scheduled.

A reason that is not assessed is said so (``not_assessed``): no EOL input means EOL is unknown, not "supported".

Developer dossier - ``build_dossier`` assembles, per component: the reasons and their sources, identity and manifests,
the advisories and the upgrade plan, licence obligations and whether a clean-room is legally required, the usage sites
inside the analysed project (which public symbols it actually calls), the legacy public interface with contracts, the
REA analysis (facts, coverage, unknowns - or the exact commands to run when REA is absent), the architecture-pattern
guidance with provenance, and the verification plan with what stays unverified. The dossier is READER-side and for
humans: the generator never receives it (it only ever receives spec.md), and it carries no implementation bodies.
"""
from __future__ import annotations

import ast
import datetime
import json
import os
import re
import warnings
from typing import Any, Dict, List, Optional, Tuple

from . import engine, licenses, rea_adapter

SCHEMA = "bts-sbom.rewrite.v1"
DOSSIER_SCHEMA = "bts-sbom.rewrite.dossier.v1"
TRIGGER_KINDS = ("license", "no_fix", "fix_incomplete", "eol", "incompatible")
DECLARABLE = ("eol", "incompatible", "license")
_COPYLEFT = ("strong-copyleft", "network-copyleft")
_EOL_STATUS = ("eol", "eos", "end-of-life", "end-of-support", "unmaintained", "deprecated", "abandoned")
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "work", ".tox", "site-packages"}
MAX_SCAN_FILES = 3000
MAX_SCAN_BYTES = 400_000
MAX_USAGE_ROWS = 40


# ------------------------------------------------------------------ inputs: the eol map and operator declarations


def load_eol(path: str) -> Dict[str, Any]:
    """The same ``{component: {"eol": date|bool, "status": ...}}`` file the sector reports take (``--eol``)."""
    with open(path, "r", encoding="utf-8") as fh:
        d = json.load(fh)
    if not isinstance(d, dict):
        raise ValueError("the eol file must be a {component: {...}} object")
    return d


def clean_declared(items: Any) -> List[Dict[str, str]]:
    """Operator declarations: [{component, kind, note}]. Bounded and validated - they are the operator's CLAIM and are
    recorded as such (source operator), never as a measurement."""
    out: List[Dict[str, str]] = []
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict):
            continue
        comp, kind = str(it.get("component") or "").strip()[:120], str(it.get("kind") or "").strip().lower()
        if comp and kind in DECLARABLE:
            out.append({"component": comp, "kind": kind, "note": re.sub(r"\s+", " ", str(it.get("note") or "")).strip()[:300]})
    return out[:50]


def _date(v: Any) -> Optional[datetime.date]:
    try:
        return datetime.date.fromisoformat(str(v)[:10])
    except ValueError:
        return None


def _eol_entry(comp: Dict[str, Any], eol: Dict[str, Any]) -> Optional[Any]:
    for key in (comp.get("name"), comp.get("purl"), "%s@%s" % (comp.get("name"), comp.get("version"))):
        if key and isinstance(eol.get(key), dict):
            return eol[key]
    return None


def _eol_reason(entry: Dict[str, Any], today: datetime.date) -> Tuple[Optional[Dict[str, str]], Optional[Dict[str, str]]]:
    """(trigger reason, context reason) for one eol-map entry."""
    status = str(entry.get("status") or "").strip().lower()
    if status == "incompatible":
        return {"kind": "incompatible", "strength": "declared", "source": "eol input",
                "evidence": "declared incompatible in the eol input"}, None
    raw = entry.get("eol", entry.get("eos", entry.get("end_of_support")))
    when = _date(raw)
    if raw is True or status in _EOL_STATUS or (when is not None and when <= today):
        ev = "end-of-life%s" % ((" since %s" % when.isoformat()) if when else "") + ((" (status %s)" % status) if status else "")
        return {"kind": "eol", "strength": "declared", "source": "eol input", "evidence": ev}, None
    if when is not None:
        return None, {"kind": "eol_scheduled", "strength": "context", "source": "eol input",
                      "evidence": "end-of-life scheduled for %s (not reached)" % when.isoformat()}
    return None, None


# ------------------------------------------------------------------ the trigger


def candidates(rec: Dict[str, Any], *, eol: Optional[Dict[str, Any]] = None, declared: Optional[List[Dict[str, str]]] = None,
               today: Optional[datetime.date] = None) -> Dict[str, Any]:
    """Which components of a scan record must be rewritten, with the evidence of each reason."""
    today = today or datetime.date.today()
    comps = [c for c in rec.get("components") or [] if isinstance(c, dict) and c.get("name")]
    plans: Dict[tuple, Dict[str, Any]] = {}
    for p in rec.get("plans") or []:
        plans[((p.get("ecosystem") or "").lower(), engine._canon(p.get("ecosystem") or "", p.get("component")), p.get("current_version"))] = p
    rt = [r for r in ((rec.get("arch") or {}).get("runtime_eol") or []) if r.get("status") == "eol"]
    decl = clean_declared(declared)
    rows: List[Dict[str, Any]] = []
    for c in comps:
        triggers: List[Dict[str, str]] = []
        context: List[Dict[str, str]] = []
        if c.get("license_category") in _COPYLEFT:
            triggers.append({"kind": "license", "strength": "measured", "source": "scan record: license %s" % (c.get("license_source") or "?"),
                             "evidence": "%s (%s) - a patch cannot change a licence" % (c.get("license") or "?", c["license_category"])})
        plan = plans.get(((c.get("ecosystem") or "").lower(), engine._canon(c.get("ecosystem") or "", c["name"]), c.get("version")))
        if plan and plan.get("status") == "no_fix":
            triggers.append({"kind": "no_fix", "strength": "measured", "source": "remediation plan",
                             "evidence": "%d advisory(ies), max severity %s, no fixed version published" % (plan.get("cve_count") or 0, plan.get("max_severity"))})
        elif plan and (plan.get("verification") or {}).get("clean") is False:
            triggers.append({"kind": "fix_incomplete", "strength": "measured", "source": "remediation plan verification",
                             "evidence": "upgrade to %s still leaves %s" % (plan.get("safe_version"), ", ".join((plan["verification"].get("residual") or [])[:4]) or "advisories")})
        if plan and plan.get("status") == "upgrade" and plan.get("major_bump"):
            context.append({"kind": "major_bump_fix", "strength": "context", "source": "remediation plan",
                            "evidence": "the only verified fix is %s -> %s (a major-version jump, compatibility not tested)" % (plan.get("current_version"), plan.get("safe_version"))})
        for r in rt:
            if any(str(r.get("declared_in")) == str(f) or str(f).endswith(str(r.get("declared_in"))) for f in c.get("files") or []):
                context.append({"kind": "runtime_eol", "strength": "context", "source": "architecture analysis: %s" % r.get("source"),
                                "evidence": "declared in %s which targets %s %s (EOL since %s)" % (r.get("declared_in"), r.get("product"), r.get("cycle"), r.get("eol_date"))})
                break
        if isinstance(eol, dict):
            ent = _eol_entry(c, eol)
            if ent is not None:
                t, ctx = _eol_reason(ent, today)
                if t:
                    triggers.append(t)
                if ctx:
                    context.append(ctx)
        for d in decl:
            if d["component"] in (c["name"], "%s@%s" % (c["name"], c.get("version"))):
                triggers.append({"kind": d["kind"], "strength": "declared", "source": "operator",
                                 "evidence": d["note"] or "declared by the operator (no note given)"})
        if triggers or context:
            rows.append({"component": c["name"], "version": c.get("version"), "ecosystem": c.get("ecosystem"), "purl": c.get("purl"),
                         "relationship": c.get("relationship"), "license": c.get("license"), "license_category": c.get("license_category"),
                         "files": (c.get("files") or [])[:6], "reasons": triggers, "context": context,
                         "triggered": bool(triggers), "clean_room_required": any(t["kind"] == "license" for t in triggers)})
    rows.sort(key=lambda r: (not r["triggered"], -len(r["reasons"]), str(r["component"]).lower()))
    not_assessed: List[str] = []
    if not isinstance(eol, dict) and not any(d["kind"] == "eol" for d in decl):
        not_assessed.append("component end-of-life is not assessed: no eol input was supplied (same {component: {eol, status}} file as the sector reports), so absence of an EOL reason means unknown, not supported")
    if not (rec.get("plans") or []):
        not_assessed.append("no remediation plan is recorded: no_fix / fix_incomplete were not assessed")
    unresolved = sum(1 for c in comps if not c.get("license"))
    if unresolved:
        not_assessed.append("%d component(s) have no resolved licence: the licence reason is not assessed for them" % unresolved)
    not_assessed.append("incompatibility is only what the operator declares; the tool does not measure it")
    trig = [r for r in rows if r["triggered"]]
    return {"schema": SCHEMA, "project": rec.get("name"), "components": len(comps), "candidates": trig[:200], "watch": [r for r in rows if not r["triggered"]][:100],
            "counts": {"candidates": len(trig), **{k: sum(1 for r in trig if any(t["kind"] == k for t in r["reasons"])) for k in TRIGGER_KINDS}},
            "not_assessed": not_assessed}


def find(report: Dict[str, Any], target: str) -> Optional[Dict[str, Any]]:
    """A candidate by ``name@version`` or ``name`` (first match)."""
    for r in report.get("candidates") or []:
        if target in (r["component"], "%s@%s" % (r["component"], r["version"])):
            return r
    return None


def why_text(row: Optional[Dict[str, Any]]) -> str:
    if not row or not row.get("reasons"):
        return ""
    return "; ".join("%s: %s" % (t["kind"], t["evidence"]) for t in row["reasons"])[:600]


def trigger_record(row: Dict[str, Any]) -> Dict[str, Any]:
    keep = ("component", "version", "ecosystem", "purl", "relationship", "files", "license", "license_category")
    return dict({k: row.get(k) for k in keep}, reasons=row["reasons"], context=row.get("context") or [],
                clean_room_required=bool(row.get("clean_room_required")))


# ------------------------------------------------------------------ usage sites inside the analysed project


def usage_sites(project_root: str, names: List[str]) -> Dict[str, Any]:
    """Where the project itself uses the dependency and WHICH public symbols it touches (Python by ``ast``, JS by
    require/import statements). Bounded; ``truncated`` says when the bound was hit. This is what a developer needs to
    size the rewrite: symbols nobody calls can be dropped from the replacement."""
    want = {n for n in names if n}
    out: Dict[str, Any] = {"scanned": False, "files_scanned": 0, "truncated": False, "sites": [], "symbols_used": [], "reason": ""}
    if not project_root or not os.path.isdir(project_root) or not want:
        out["reason"] = "no project source tree is available to scan"
        return out
    out["scanned"] = True
    symbols: set = set()
    js_pat = re.compile(r"""(?:require\(\s*|from\s+|import\s+)['"](%s)(?:/[^'"]*)?['"]""" % "|".join(re.escape(n) for n in sorted(want)))
    for dp, dns, fns in os.walk(project_root):
        dns[:] = [d for d in dns if d not in _SKIP_DIRS]
        for fn in sorted(fns):
            ext = os.path.splitext(fn)[1].lower()
            if ext not in (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
                continue
            if out["files_scanned"] >= MAX_SCAN_FILES:
                out["truncated"] = True
                break
            fp = os.path.join(dp, fn)
            try:
                if os.path.getsize(fp) > MAX_SCAN_BYTES:
                    continue
                text = open(fp, "r", encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            out["files_scanned"] += 1
            rel = os.path.relpath(fp, project_root).replace("\\", "/")
            if ext == ".py":
                _py_usage(text, rel, want, out["sites"], symbols)
            else:
                for m in js_pat.finditer(text):
                    out["sites"].append({"file": rel, "line": text.count("\n", 0, m.start()) + 1, "kind": "js-import", "names": [m.group(1)]})
        if out["truncated"]:
            break
    out["sites"] = out["sites"][:MAX_USAGE_ROWS]
    out["symbols_used"] = sorted(symbols)[:80]
    return out


def _py_usage(text: str, rel: str, want: set, sites: List[Dict[str, Any]], symbols: set) -> None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")                    # legacy sources are full of invalid-escape warnings
            tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return
    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in want:
                    aliases[a.asname or a.name.split(".")[0]] = a.name
                    sites.append({"file": rel, "line": node.lineno, "kind": "import", "names": [a.name]})
        elif isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in want:
            names = [a.name for a in node.names]
            symbols.update(n for n in names if n != "*")
            sites.append({"file": rel, "line": node.lineno, "kind": "from-import", "names": names})
    if aliases:
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in aliases:
                symbols.add(node.attr)


# ------------------------------------------------------------------ the dossier


def build_dossier(*, row: Optional[Dict[str, Any]], rec: Optional[Dict[str, Any]], iface: Dict[str, Any], usage: Optional[Dict[str, Any]],
                  rea: Optional[Dict[str, Any]], patterns: Optional[Dict[str, Any]], result: Dict[str, Any],
                  adopted: Optional[Dict[str, List[str]]], target_artifact: str = "") -> Dict[str, Any]:
    """Everything a developer needs to rewrite ONE component, as data (``dossier_markdown`` renders it)."""
    d: Dict[str, Any] = {"schema": DOSSIER_SCHEMA, "component": result.get("component"), "generated": result.get("started"), "gaps": []}
    d["why"] = (row or {}).get("reasons") or []
    d["context"] = (row or {}).get("context") or []
    if not row:
        d["gaps"].append("no SBOM trigger was supplied: the reason for this rewrite is whatever the operator typed (why)")
    d["identity"] = {k: (row or {}).get(k) for k in ("component", "version", "ecosystem", "purl", "relationship", "files")} if row else None
    if rec and row:
        nm = row["component"]
        vs = [v for v in rec.get("vulns") or [] if v.get("package") == nm and (v.get("version") == row.get("version"))]
        d["advisories"] = [{"id": v.get("id"), "severity": v.get("severity"), "cvss": v.get("cvss"), "fixed_version": v.get("fixed_version"),
                            "summary": str(v.get("summary") or "")[:160]} for v in vs[:25]]
        pl = [p for p in rec.get("plans") or [] if p.get("component") == nm and p.get("current_version") == row.get("version")]
        d["upgrade_plan"] = ({k: pl[0].get(k) for k in ("status", "safe_version", "major_bump", "breaking_risk", "clears", "uncleared")} |
                             {"verification": (pl[0].get("verification") or {}).get("clean")}) if pl else None
    else:
        d["advisories"], d["upgrade_plan"] = [], None
        d["gaps"].append("no scan record: advisories and the upgrade plan are not shown")
    cat = (row or {}).get("license_category") or "unknown"
    d["license"] = {"id": (row or {}).get("license"), "category": cat, "obligations": licenses.OBLIGATIONS.get(cat, []),
                    "clean_room_required": bool((row or {}).get("clean_room_required")),
                    "note": ("a clean-room is legally motivated" if (row or {}).get("clean_room_required") else
                             "no copyleft reason: the clean-room walls and the copy gate are applied by policy so the replacement stays independent of the legacy code, not because the licence forces it")}
    d["usage"] = usage or {"scanned": False, "reason": "usage sites were not scanned"}
    if not d["usage"].get("scanned"):
        d["gaps"].append("usage sites inside the analysed project were not scanned: %s" % d["usage"].get("reason"))
    used = set(d["usage"].get("symbols_used") or [])
    api = [{"name": f["name"], "kind": "function", "args": f["args"], "contract": f["contract"],
            "used_by_project": (f["name"] in used) if d["usage"].get("scanned") else None} for f in iface.get("functions") or []]
    api += [{"name": c["name"], "kind": "class", "methods": c["methods"], "contract": c["contract"],
             "used_by_project": (c["name"] in used) if d["usage"].get("scanned") else None} for c in iface.get("classes") or []]
    d["legacy_interface"] = {"module": iface.get("module"), "imports": iface.get("imports") or [], "api": api,
                             "examples": (iface.get("examples") or [])[:12]}
    d["rea"] = rea_adapter.summary(rea)
    d["rea_facts"] = (rea or {}).get("facts") if rea and rea.get("state") == "ok" else None
    d["rea_playbook"] = rea_adapter.playbook(target_artifact) if target_artifact else []
    if not rea or rea.get("state") != "ok":
        d["gaps"].append("REA analysis is %s: %s" % ((rea or {}).get("state", "off"), (rea or {}).get("reason") or "rea was not requested"))
    d["patterns"] = {"tier": (patterns or {}).get("tier"), "patterns": [{"name": p.get("name"), "ref": p.get("ref")} for p in (patterns or {}).get("patterns") or []]} if patterns else None
    if not patterns:
        d["gaps"].append("no architecture-pattern guidance was inferred")
    cg = result.get("copy_gate") or {}
    d["verification"] = {"verdict": result.get("verdict"), "reason": result.get("reason"), "generated_by": result.get("generated_by"),
                         "copy_gate": {"overlap": cg.get("overlap"), "threshold": cg.get("threshold"), "passed": cg.get("passed")} if cg else None,
                         "contract_tests": ({"ok": result["tests"].get("ok"), "tail": str(result["tests"].get("tail") or "")[-120:]} if result.get("tests") else None),
                         "legacy_oracle": {"files": [os.path.basename(x) for x in (adopted or {}).get("tests", [])],
                                           "ok": (result.get("adopted_tests") or {}).get("ok")} if (adopted or {}).get("tests") else None,
                         "runtime": result.get("runtime")}
    if result.get("verdict") == "not_run":
        d["gaps"].append("the clean-room lane has not run for this component: the legacy interface, REA facts and verification are empty until it does")
    elif not d["verification"]["legacy_oracle"]:
        d["gaps"].append("the legacy component ships no test suite: behaviour is verified against generated contract tests only (names and arity), not against the legacy behaviour")
    if result.get("verdict") == "dossier_only":
        d["gaps"].append(result.get("reason") or "no code was generated")
    if result.get("generated_by") == "scaffold":
        d["gaps"].append("no LLM generated the bodies: the artefact is a scaffold (signatures only)")
    return d


def preview(rec: Dict[str, Any], row: Dict[str, Any], project_root: Optional[str] = None) -> Dict[str, Any]:
    """The dossier before any lane run: reasons, exposure, licence, usage - from the scan record alone."""
    names = [row["component"], str(row["component"]).replace("-", "_").lower()]
    usage = usage_sites(project_root or "", names) if project_root else None
    iface: Dict[str, Any] = {"module": row["component"], "functions": [], "classes": [], "imports": [], "examples": []}
    res = {"component": row["component"], "verdict": "not_run", "reason": "", "started": None}
    return build_dossier(row=row, rec=rec, iface=iface, usage=usage, rea=None, patterns=None, result=res, adopted=None, target_artifact="")


def dossier_markdown(d: Dict[str, Any]) -> str:
    L: List[str] = ["# Rewrite dossier: %s" % d.get("component"), "",
                    "For the developer who rewrites this component. Reader-side material: the generator never sees this file "
                    "(it only receives spec.md), and it holds no implementation bodies.", ""]
    L += ["## 1. Why this component is rewritten"]
    if d["why"]:
        for t in d["why"]:
            L.append("- **%s** (%s; source: %s): %s" % (t["kind"], t["strength"], t["source"], t["evidence"]))
    else:
        L.append("- (no SBOM reason supplied)")
    for t in d.get("context") or []:
        L.append("- context, not a trigger - %s: %s [%s]" % (t["kind"], t["evidence"], t["source"]))
    ident = d.get("identity")
    if ident:
        L += ["", "## 2. Identity", "- %s %s (%s), %s dependency, purl %s" % (ident["component"], ident["version"], ident["ecosystem"], ident["relationship"], ident["purl"]),
              "- declared in: %s" % (", ".join(ident.get("files") or []) or "(unknown)")]
    L += ["", "## 3. Exposure"]
    if d["advisories"]:
        for a in d["advisories"]:
            L.append("- %s [%s%s] fixed in: %s - %s" % (a["id"], a["severity"], (" %.1f" % a["cvss"]) if isinstance(a.get("cvss"), (int, float)) else "", a["fixed_version"] or "none published", a["summary"]))
    else:
        L.append("- no advisory recorded for this exact version")
    up = d.get("upgrade_plan")
    if up:
        L.append("- upgrade plan: %s -> %s, breaking risk %s, verified clean: %s" % (up["status"], up["safe_version"] or "none", up["breaking_risk"], up["verification"]))
    lic = d["license"]
    L += ["", "## 4. Licence", "- %s (%s)" % (lic["id"] or "unresolved", lic["category"]),
          "- obligations: %s" % ("; ".join(lic["obligations"]) or "none recorded"), "- %s" % lic["note"],
          "- this is a policy screening of the recorded licence, not legal advice"]
    us = d["usage"]
    L += ["", "## 5. How this project uses it"]
    if us.get("scanned"):
        L.append("- scanned %d file(s)%s; %d import site(s); symbols used: %s" % (us["files_scanned"], " (bound hit)" if us.get("truncated") else "", len(us["sites"]), ", ".join(us["symbols_used"]) or "(no attribute/from-import use found)"))
        for s in us["sites"][:15]:
            L.append("  - %s:%d %s %s" % (s["file"], s["line"], s["kind"], ", ".join(s["names"])))
    else:
        L.append("- not scanned: %s" % us.get("reason"))
    li = d["legacy_interface"]
    L += ["", "## 6. Legacy public interface (signatures and contracts, no bodies)", "- module `%s`, imports: %s" % (li["module"], ", ".join(li["imports"]) or "none")]
    for a in li["api"]:
        flag = {True: "used by this project", False: "NOT used by this project (candidate to drop)", None: "usage unknown"}[a["used_by_project"]]
        sig = "%s(%s)" % (a["name"], ", ".join(a.get("args") or [])) if a["kind"] == "function" else "class %s [%s]" % (a["name"], ", ".join(a.get("methods") or []))
        L.append("- `%s` - %s%s" % (sig, flag, (": " + a["contract"].split("\n")[0][:140]) if a.get("contract") else ""))
    r = d["rea"]
    L += ["", "## 7. REA analysis of the legacy artefact (%s)" % r.get("state")]
    if d.get("rea_facts"):
        f = d["rea_facts"]
        L += ["- coverage %s; modules: %s" % (f.get("coverage"), ", ".join(f.get("modules") or []) or "none"),
              "- imported dependencies: %s" % (", ".join(f.get("imports") or []) or "none")]
        for k, names in (f.get("boundaries") or {}).items():
            L.append("- %s: %s" % (k, ", ".join(names)))
        L += ["- limitations REA reported: %s" % ("; ".join(f.get("limitations") or []) or "none"),
              "- what REA does NOT tell you: behaviour inside functions; anything outside its coverage"]
    else:
        L.append("- not available (%s): %s" % (r.get("state"), r.get("reason")))
    if d.get("rea_playbook"):
        L += ["", "Run these yourself (rea installed: `npm install --global rea-agents`; analyse only software you own or are authorised to examine). Command names are from rea's CLI documentation:"]
        for p in d["rea_playbook"]:
            L.append("- `%s` - %s%s" % (p["command"], p["gives"], " [the tool runs this]" if p.get("wired") else ""))
    L += ["", "## 8. Architecture guidance"]
    pt = d.get("patterns")
    if pt and pt.get("patterns"):
        L.append("- tier %s" % pt["tier"])
        L += ["- %s [%s]" % (str(p["name"])[:80], str(p["ref"])[:140]) for p in pt["patterns"]]
    else:
        L.append("- none inferred")
    v = d["verification"]
    L += ["", "## 9. Verification plan and result", "- verdict: %s%s" % (v["verdict"], (" - " + v["reason"]) if v.get("reason") else ""), "- generated by: %s" % v.get("generated_by")]
    if v.get("copy_gate"):
        L.append("- copy gate: overlap %s (threshold %s, %s)" % (v["copy_gate"]["overlap"], v["copy_gate"]["threshold"], "passed" if v["copy_gate"]["passed"] else "FAILED"))
    L.append("- contract tests: %s" % (("ok" if v["contract_tests"]["ok"] else "FAILED") if v.get("contract_tests") else "not run"))
    L.append("- legacy test suite as oracle: %s" % (("%s (%s)" % ("passed" if v["legacy_oracle"]["ok"] else "not passed", ", ".join(v["legacy_oracle"]["files"]))) if v.get("legacy_oracle") else "none shipped"))
    L.append("- runtime the tests ran on: %s" % (v.get("runtime") or "unknown"))
    L += ["", "## 10. What is NOT established (honest gaps)"]
    L += ["- %s" % g for g in d["gaps"]] or ["- none"]
    return "\n".join(L) + "\n"
