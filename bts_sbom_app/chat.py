"""Grounded chatbot: tools over analysed projects + hybrid RAG over the knowledge base.

Every answer is a list of CLAIMS; each claim carries the exact ``quote`` it rests on and the ``source`` document it was
cut from, and ``verify_claims`` re-checks that the quote is a verbatim substring of that document (whitespace
normalised). A question that no tool matches and whose retrieval confidence is below the gate returns
``found=False`` - the bot says it does not know instead of improvising. An optional EXAONE pass may rephrase, but
only claims whose quotes survive verification are kept; otherwise the extractive answer is returned
(``answer_source`` says which one produced the text).
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence

from . import ai, rag
from .llm import ChatClient, LLMError, LLMUnavailable

_ID = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+|GO-\d{4}-\d+)\b", re.I)
_INDUSTRY = {"finance": ("금융", "finance", "financial", "은행"), "medical": ("의료", "medical", "fda", "의료기기"),
             "defense": ("방산", "국방", "defense", "dod", "군"), "automotive": ("자동차", "automotive", "r155", "차량"),
             "maritime": ("선박", "해사", "maritime", "iacs", "조선"), "cra": ("cra", "eu 사이버", "cyber resilience"),
             "robot": ("로봇", "robot")}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def verify_claims(claims: Sequence[Dict[str, Any]], docs: Dict[str, str]) -> Dict[str, Any]:
    ok = [c for c in claims if c.get("source") in docs and c.get("quote") and _norm(c["quote"]) in _norm(docs[c["source"]])]
    return {"claims": len(claims), "verified": len(ok), "accuracy": round(len(ok) / len(claims), 3) if claims else 1.0, "kept": ok}


# ------------------------------------------------------------------ project tools (each returns lines of fact text)
def _overview(rec: Dict[str, Any]) -> List[str]:
    sev: Dict[str, int] = {}
    for v in rec.get("vulns") or []:
        sev[v["severity"]] = sev.get(v["severity"], 0) + 1
    ls = (rec.get("license") or {}).get("stats") or {}
    sev_txt = ", ".join("%s %d" % (k, sev[k]) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN") if k in sev) or "none"
    return ["Project %s: %d components, %d vulnerabilities (%s), license resolved rate %s." % (
        rec["name"], len(rec.get("components") or []), len(rec.get("vulns") or []), sev_txt,
        ls.get("resolved_rate") if ls.get("resolved_rate") is not None else "n/a")]


def _top_vulns(rec: Dict[str, Any], n: int = 5) -> List[str]:
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    vs = sorted(rec.get("vulns") or [], key=lambda v: (-rank.get(v["severity"], 0), -(v.get("cvss") or 0)))[:n]
    return ["%s affects %s %s, severity %s%s, fixed in %s." % (v["id"], v["package"], v["version"], v["severity"],
                                                             (" (CVSS %s)" % v["cvss"]) if v.get("cvss") is not None else "",
                                                             v["fixed_version"] or "no known version") for v in vs] or \
           ["No vulnerabilities were found in %s." % rec["name"]]


def _vuln(rec: Dict[str, Any], vid: str) -> List[str]:
    out = []
    for v in rec.get("vulns") or []:
        if vid.lower() in [v["id"].lower()] + [a.lower() for a in v.get("aliases") or []] + [o.lower() for o in v.get("osv_ids") or []]:
            out.append("%s affects %s %s, severity %s%s, fixed in %s. %s" % (
                v["id"], v["package"], v["version"], v["severity"], (" (CVSS %s)" % v["cvss"]) if v.get("cvss") is not None else "",
                v["fixed_version"] or "no known version", v.get("summary", "")))
    return out or ["%s is not present in the analysed findings of %s." % (vid, rec["name"])]


def _component(rec: Dict[str, Any], name: str) -> List[str]:
    out = []
    for c in rec.get("components") or []:
        if c["name"].lower() == name.lower():
            plan = next((p for p in rec.get("plans") or [] if p["component"].lower() == c["name"].lower() and p["current_version"] == c["version"]), None)
            out.append("Component %s %s (%s): license %s%s, %d known vulnerabilities%s." % (
                c["name"], c["version"], c["ecosystem"], c.get("license") or "unresolved",
                (" from " + c["license_source"]) if c.get("license_source") else "", c.get("vulns", 0),
                (", safe upgrade target %s" % plan["safe_version"]) if plan and plan.get("safe_version") else ""))
    return out


def _license(rec: Dict[str, Any]) -> List[str]:
    lic = rec.get("license") or {}
    st = lic.get("stats") or {}
    cats: Dict[str, int] = {}
    for c in rec.get("components") or []:
        k = c.get("license_category") or "unknown"
        cats[k] = cats.get(k, 0) + 1
    lines = ["License resolution for %s: %s of %s components resolved; by source %s." % (
        rec["name"], st.get("resolved"), st.get("total"), json.dumps(st.get("by_source") or {}, sort_keys=True))]
    lines.append("License categories: " + ", ".join("%s %d" % (k, v) for k, v in sorted(cats.items(), key=lambda kv: -kv[1])) + ".")
    if lic.get("project_license"):
        lines.append("Project license detected: %s (%s)." % (lic["project_license"], lic.get("project_license_source") or "n/a"))
    for f in (lic.get("policy") or [])[:4]:
        lines.append("Policy finding: %s - %s." % (f["verdict"], f["detail"]))
    return lines


def _patch(rec: Dict[str, Any]) -> List[str]:
    plans = rec.get("plans") or []
    ups = [p for p in plans if p["status"] == "upgrade"]
    lines = ["Remediation plan for %s: %d upgrade plans, %d packages without a fixed version, %d verified clean against OSV." % (
        rec["name"], len(ups), len(plans) - len(ups), sum(1 for p in ups if p["verification"].get("clean") is True))]
    pa = rec.get("patch") or {}
    if pa:
        lines.append("Patch status: %s (approved=%s)%s." % (pa.get("status"), pa.get("approved"),
                                                         (", branch " + pa["branch"]) if pa.get("branch") else ""))
    for p in ups[:3]:
        lines.append("Upgrade %s from %s to %s (clears %d advisories%s)." % (p["component"], p["current_version"], p["safe_version"],
                                                                         len(p["clears"]), ", major bump" if p["major_bump"] else ""))
    return lines


def _arch(rec: Dict[str, Any]) -> List[str]:
    a = rec.get("arch") or {}
    g = a.get("graph") or {}
    lines = ["Architecture of %s: %s files, %s LOC, %s internal import edges, %s dependency cycles." % (
        rec["name"], (a.get("stack") or {}).get("files"), (a.get("stack") or {}).get("loc"), g.get("import_edges"), g.get("cycle_count"))]
    for h in (a.get("hotspots") or [])[:3]:
        lines.append("Hotspot %s: %d commits, %d LOC, score %s." % (h["file"], h["commits"], h["loc"], h["score"]))
    for r in (a.get("runtime_eol") or [])[:3]:
        lines.append("Runtime %s %s is %s (%s)." % (r["product"], r["cycle"], r["status"], r["source"]))
    return lines


def _sector(rec: Dict[str, Any], ind: Optional[str]) -> List[str]:
    sec = rec.get("sectors") or {}
    keys = [ind] if ind and ind in sec else sorted(sec)
    out = []
    for k in keys:
        s = sec[k]
        sm = s.get("summary") or {}
        out.append("Sector %s (%s): verdict %s, %s pass, %s gap, %s not_evidence." % (k, s.get("sector_title", ""), s.get("verdict"),
                                                                                     sm.get("pass"), sm.get("gap"), sm.get("not_evidence")))
    return out or ["No sector report was produced for %s." % rec["name"]]


# ------------------------------------------------------------------ bot
class Chatbot:
    def __init__(self, index: rag.Index, projects: Optional[Dict[str, Dict[str, Any]]] = None, client: Optional[ChatClient] = None):
        self.index = index
        self.projects = projects or {}
        self.client = client

    def _no_client_note(self, use_llm: bool) -> str:
        """Honesty: when EXAONE was requested but there is no client, say so instead of silently answering extractively."""
        if use_llm and self.client is None:
            return "EXAONE requested but unavailable (no API key configured: set EXAONE_API_KEY or BTS_SBOM_LLM_CONFIG) -> extractive answer"
        return ""

    def _pick_project(self, q: str, project: Optional[str]) -> Optional[Dict[str, Any]]:
        if project and project in self.projects:
            return self.projects[project]
        low = q.lower()
        named = [p for n, p in self.projects.items() if n.lower() in low]
        if named:
            return named[0]
        return next(iter(self.projects.values())) if len(self.projects) == 1 else None

    def _tools(self, q: str, rec: Dict[str, Any]) -> List[Dict[str, Any]]:
        low = q.lower()
        steps: List[tuple] = []
        ids = _ID.findall(q)
        for i in ids:
            steps.append(("vuln_lookup", _vuln(rec, i)))
        names = [c["name"] for c in rec.get("components") or [] if len(c["name"]) >= 3 and re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(c["name"].lower()), low)]
        for n in list(dict.fromkeys(names))[:2]:
            steps.append(("component_lookup", _component(rec, n)))
        if re.search(r"취약|vulnerab|cve|critical|심각|위험", low) and not ids:
            steps.append(("overview", _overview(rec)))
            steps.append(("top_vulns", _top_vulns(rec)))
        if re.search(r"라이선스|license|copyleft|gpl|spdx", low):
            steps.append(("license", _license(rec)))
        if re.search(r"패치|수정|업그레이드|patch|fix|upgrade|remediat", low):
            steps.append(("patch", _patch(rec)))
        if re.search(r"아키텍처|레거시|순환|핫스팟|architecture|legacy|cycle|hotspot|현대화|런타임|eol", low):
            steps.append(("architecture", _arch(rec)))
        ind = next((k for k, ws in _INDUSTRY.items() if any(w in low for w in ws)), None)
        if ind or re.search(r"규제|sector|산업|compliance|준수", low):
            steps.append(("sector", _sector(rec, ind)))
        if re.search(r"요약|개요|overview|summary|현황|상태", low) and not any(s[0] == "overview" for s in steps):
            steps.insert(0, ("overview", _overview(rec)))
        out = []
        for tool, lines in steps:
            out.append({"tool": tool, "source": "project:%s:%s" % (rec["name"], tool), "lines": lines})
        return out

    def ask(self, question: str, *, project: Optional[str] = None, use_llm: bool = False, k: int = 4) -> Dict[str, Any]:
        rec = self._pick_project(question, project)
        docs: Dict[str, str] = {}
        claims: List[Dict[str, Any]] = []
        tools_used: List[str] = []
        if rec is not None:
            for t in self._tools(question, rec):
                tools_used.append(t["tool"])
                docs[t["source"]] = "\n".join(t["lines"])
                claims.extend({"text": ln, "quote": ln, "source": t["source"]} for ln in t["lines"])
        flt: Optional[Dict[str, Any]] = {"kind": ["knowledge", "evidence"]} if not rec else {"kind": ["knowledge"]}
        res = self.index.search(question, k=k, filters=flt)
        retrieval = {"found": res["found"], "coverage": res["coverage"],
                     "top": [{"source": r["chunk"]["source"], "heading": r["chunk"]["heading"], "rrf": r["rrf"]} for r in res["results"][:k]]}
        if res["found"]:
            qtok = set(rag.tokenize(question, for_query=True))
            for r in res["results"][:2]:
                ch = r["chunk"]
                docs[ch["id"]] = ch["text"]
                sents = [s.strip() for s in re.split(r"(?<=[.!?。])\s+|\n+", ch["text"]) if 25 <= len(s.strip()) <= 360]
                sents.sort(key=lambda s: -len(qtok & set(rag.tokenize(s))))
                for s in sents[:2]:
                    if qtok & set(rag.tokenize(s)):
                        claims.append({"text": s, "quote": s, "source": ch["id"]})
        if not claims:
            return {"found": False, "answer": "I could not find this in the analysed projects or the knowledge base.", "claims": [],
                    "answer_source": "none", "tools": [], "retrieval": retrieval, "citation_accuracy": 1.0,
                    "llm_note": self._no_client_note(use_llm)}
        ver = verify_claims(claims, docs)
        answer = "\n".join("- " + c["text"] for c in ver["kept"])
        src = "tools" if tools_used else "rag"
        llm_note = self._no_client_note(use_llm)
        if use_llm and self.client is not None:
            try:
                passages = "\n\n".join("[%s]\n%s" % (sid, txt[:1400]) for sid, txt in list(docs.items())[:6])
                raw = self.client.complete(
                    "Answer the question using ONLY the passages. Return JSON {\"answer\": string, \"claims\": [{\"text\", \"quote\", \"source\"}]}; "
                    "each quote must be copied verbatim from the cited passage IN ITS ORIGINAL LANGUAGE (never translate a quote) and source "
                    "must be that passage's id exactly as written inside the brackets, without the brackets. Only the answer text follows the "
                    "question's language. If the passages do not contain the answer say so.",
                    "QUESTION: %s\n\nPASSAGES:\n%s" % (question, passages), max_tokens=4096, json_mode=True)
                obj = ai._parse_json(raw)
                lc = [c for c in obj.get("claims", []) if isinstance(c, dict)]
                for c in lc:                                   # normalise the pointer: "[id]" -> "id"; if the id is still unknown but the
                    s = str(c.get("source", "")).strip().strip("[]").strip()     # quote sits verbatim in exactly ONE of this question's
                    if s not in docs:                                             # documents, point at that document
                        hit = [sid for sid, d in docs.items() if c.get("quote") and _norm(str(c["quote"])) in _norm(d)]
                        s = hit[0] if len(hit) == 1 else s
                    c["source"] = s
                v2 = verify_claims(lc, docs)
                if v2["kept"] and isinstance(obj.get("answer"), str) and v2["accuracy"] >= 0.8:
                    answer, ver, src = obj["answer"], v2, "exaone"
                else:
                    llm_note = "EXAONE answer rejected (citation accuracy %s) -> extractive answer" % v2["accuracy"]
            except (LLMUnavailable, LLMError, ValueError, TypeError, AttributeError) as exc:
                llm_note = "EXAONE unavailable -> extractive answer: " + str(exc)[:160]
        return {"found": True, "answer": answer, "claims": ver["kept"], "answer_source": src, "tools": tools_used,
                "retrieval": retrieval, "citation_accuracy": ver["accuracy"], "llm_note": llm_note}
