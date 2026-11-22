"""Arch Intel: one input (a local folder or a git URL) -> a license verdict + an AI architecture deep-dive.

The web screen's counterpart module (``/api/arch/...``, pane "Arch Intel"). The pipeline is staged like
``pipeline.run_project``; every stage is timed and reported through the same ``progress`` callback contract:

  prepare    workspace.prepare (git URL / owner/repo shorthand / local folder -> an isolated work copy)
  license    project-license detection + category + obligations + a distribution verdict + a GPL/AGPL notice
             checklist + a pairwise compatibility matrix (license_categories.compatible)
  structure  deterministic architecture facts (arch.analyze: stack / import graph / cycles / clusters /
             hotspots) + entry-point detection + a bounded key-file selection
  ai         EXAONE architecture analysis following ai.propose's contract: prompt-hash cache -> one JSON call
             -> four validation layers -> deterministic fallback that never invents scenario data
  anchors    bounded code snippets for the key files, server-side syntax highlighting
  persist    result.json + report.md written ONLY under the caller-provided out_dir

Clean-room guardrails (why this module exists the way it does, see ADR-0014):
  * The LLM prompt carries METADATA ONLY (paths, LOC, import edges, entry points) - never a line of source.
  * Any LLM output that contains markdown code fences or code-shaped lines is DROPPED by the validation layers,
    so the tool can never become a code-echo channel for a copyleft work.
  * Diagrams are generated deterministically from the VALIDATED analysis (the model never writes Mermaid),
    and every file reference must exist in the analysed tree or the item is dropped (grounding).
  * Nothing in the analysed tree is ever executed; the "dynamic" views are static inferences and are labelled
    as such.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from bts_sbom._internal import license_categories, oss_common

from . import arch, arch_flow, licenses, workspace
from . import __version__
from .ai import _parse_json as parse_json
from .llm import ChatClient, LLMError, LLMUnavailable
from .util import clip

SCHEMA = "bts-sbom.arch-intel.v1"
PROMPT_VERSION = "arch-intel-v1"

SNIPPET_MAX_LINES = 60
SNIPPET_WINDOW = 44
MAX_KEY_FILES = 12
MAX_COMPONENTS = 6
MAX_SCENARIOS = 3
MAX_ACTIVITY = 2
MAX_STEPS = 12
MAX_ENTRY_POINTS = 8
DISTRIBUTIONS = ("binary", "saas", "internal")

_PY_MAIN_RE = re.compile(r"if\s+__name__\s*==\s*[\"']__main__[\"']")
_GO_MAIN_RE = re.compile(r"^package\s+main\b", re.M)
_JAVA_MAIN_RE = re.compile(r"static\s+(?:\w+\s+)*void\s+main\s*\(")
_DOCKER_RE = re.compile(r"^\s*(?:CMD|ENTRYPOINT)\b", re.M)
_MAKE_RE = re.compile(r"^([A-Za-z0-9_.-]+)\s*:", re.M)
_COMPOSE_RE = re.compile(r"^\s*services\s*:", re.M)
_SINGLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]*$")
_CODE_SHAPE_RE = re.compile(
    r"```|^\s*(?:def |class |function |func |fn |import |from \S+ import|package |#include|using |public static void)"
    r"|=>\s*\{|;\s*\}|\breturn\s+\w+\s*[;(]")
_COMPAT_CANDIDATES = ["MIT", "Apache-2.0", "MPL-2.0", "LGPL-3.0-only", "GPL-3.0-only", "AGPL-3.0-only"]

SYSTEM = ("You are a software architect reading a metadata-only evidence JSON about one open-source project: file "
          "paths, sizes, import edges and entry points - NEVER source code. Produce an architecture analysis. "
          "Respond with ONLY valid JSON of shape "
          "{\"overview\": string, \"components\": [{\"name\": string, \"role\": string, \"files\": [paths]}], "
          "\"scenarios\": [{\"name\": string, \"description\": string, \"participants\": [component names or "
          "entry-point paths], \"steps\": [{\"actor\": string, \"action\": string, \"target\": string}]}], "
          "\"activity\": [{\"name\": string, \"steps\": [strings], \"decisions\": [{\"after_step\": int, "
          "\"question\": string, \"then_step\": int, \"else_step\": int}]}], \"license_note\": string}. "
          "At most 6 components, 3 scenarios, 2 activity flows and 12 steps per scenario/flow. Every path in "
          "components.files must be copied EXACTLY from the evidence modules/entry_points. participants, actors and "
          "targets must be component names, entry-point paths or \"User\". NEVER include source code, pseudocode, "
          "markdown fences or code-shaped identifiers: describe behaviour and responsibility, not code text. "
          "Never invent numbers, paths or files that the evidence does not contain.")


# --------------------------------------------------------------------------- tiny helpers
def _norm_rel(p: str) -> str:
    return str(p).replace("\\", "/").strip().lstrip("./")


def looks_like_code(s: str) -> bool:
    """True when a model string carries code-shaped content (fences, function headers, brace-block shapes)."""
    return bool(_CODE_SHAPE_RE.search(str(s or "")))


def _dom_of(path: str, depth: int = 2) -> str:
    parts = path.strip("/").split("/")
    return "/".join(parts[:depth]) if len(parts) > depth else ("/".join(parts[:-1]) or ".")


def mermaid_label(s: str, limit: int = 80) -> str:
    """Sanitise a model-produced string into a safe Mermaid label: no quotes, no angle brackets (so no edge syntax
    can survive - ``-->`` loses its ``>``), no control characters."""
    t = re.sub(r"[\x00-\x1f\x7f]", " ", str(s or ""))
    t = t.replace('"', "'").replace(";", ",").replace(">", ")").replace("<", "(")
    t = re.sub(r"\s+", " ", t).strip()
    return clip(t, limit)


# --------------------------------------------------------------------------- entry points
_ENTRY_MANIFESTS = ("package.json", "Dockerfile", "dockerfile", "Makefile", "docker-compose.yml", "compose.yml")


def entry_points(root: str, files: List[str], *, max_read: int = 8000) -> List[Dict[str, Any]]:
    """Deterministic, bounded entry-point detection. A file qualifies by CONTENT (a ``__main__`` guard, a ``main``
    function) or by DECLARATION (package.json main/bin/scripts.start, Dockerfile CMD/ENTRYPOINT, Makefile, compose).
    Declared manifests are checked on disk (collect_files only walks code extensions). Never more than
    :data:`MAX_ENTRY_POINTS`, never more than 700 files read."""
    fileset = set(files)
    for cand in _ENTRY_MANIFESTS:                                   # collect_files never walks these (no code suffix)
        if os.path.isfile(os.path.join(root, cand)):
            fileset.add(cand)
    entries: List[Dict[str, Any]] = []

    def add(path: str, kind: str, note: str = "") -> None:
        path = _norm_rel(path)
        if len(entries) >= MAX_ENTRY_POINTS or path not in fileset:
            return
        if any(e["path"] == path and e["kind"] == kind for e in entries):
            return
        entries.append({"path": path, "kind": kind, **({"note": clip(note, 90)} if note else {})})

    for f in files:
        if os.path.basename(f) == "__main__.py":
            add(f, "python-main")
    scanned = 0
    for f in files:
        if len(entries) >= MAX_ENTRY_POINTS or scanned >= 400:
            break
        if not f.endswith(".py"):
            continue
        scanned += 1
        try:
            with open(os.path.join(root, f), "r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(max_read)
        except OSError:
            continue
        if _PY_MAIN_RE.search(head):
            add(f, "python-entry")
    if "package.json" in fileset:
        try:
            with open(os.path.join(root, "package.json"), "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            data = {}
        if isinstance(data, dict):
            main = data.get("main")
            if isinstance(main, str):
                add(main, "npm-main")
            bins = data.get("bin")
            if isinstance(bins, str):
                add(bins, "npm-bin")
            elif isinstance(bins, dict):
                for v in list(bins.values())[:3]:
                    if isinstance(v, str):
                        add(v, "npm-bin")
            scripts = data.get("scripts")
            if isinstance(scripts, dict) and isinstance(scripts.get("start"), str):
                add("package.json", "npm-start", note="scripts.start: " + scripts["start"])
    scanned = 0
    for f in files:
        if len(entries) >= MAX_ENTRY_POINTS or scanned >= 300:
            break
        ext = os.path.splitext(f)[1].lower()
        if ext not in (".go", ".java"):
            continue
        scanned += 1
        try:
            with open(os.path.join(root, f), "r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(max_read)
        except OSError:
            continue
        if ext == ".go" and _GO_MAIN_RE.search(head) and re.search(r"\bfunc\s+main\s*\(", head):
            add(f, "go-main")
        elif ext == ".java" and _JAVA_MAIN_RE.search(head):
            add(f, "java-main")
    for cand, kind, rx in (("Dockerfile", "dockerfile-entry", _DOCKER_RE), ("dockerfile", "dockerfile-entry", _DOCKER_RE),
                           ("Makefile", "makefile-target", _MAKE_RE), ("docker-compose.yml", "compose-services", _COMPOSE_RE),
                           ("compose.yml", "compose-services", _COMPOSE_RE)):
        if cand in fileset and len(entries) < MAX_ENTRY_POINTS:
            try:
                with open(os.path.join(root, cand), "r", encoding="utf-8", errors="replace") as fh:
                    if rx.search(fh.read(4000)):
                        add(cand, kind)
            except OSError:
                pass
    return entries


def _anchor_res_for(kind: str) -> List[re.Pattern]:
    if kind.startswith("python"):
        return [_PY_MAIN_RE, re.compile(r"^(?:class|def)\s+\w+", re.M)]
    if kind == "go-main":
        return [re.compile(r"\bfunc\s+main\s*\(")]
    if kind == "java-main":
        return [_JAVA_MAIN_RE]
    if kind in ("npm-main", "npm-bin"):
        return [re.compile(r"(?:module\.exports|export\s+default|define\s*\()"), re.compile(r"^(?:class|function)\s+\w+", re.M)]
    return [re.compile(r"^(?:class|def|function|func)\s+\w+", re.M)]


def key_files(files: List[str], entries: List[Dict[str, Any]], hotspots: List[Dict[str, Any]],
              edges: Set[Tuple[str, str]], *, limit: int = MAX_KEY_FILES) -> List[Dict[str, Any]]:
    """A bounded, deduplicated selection: entry points first, then hotspots, then the best-connected file of the
    biggest directories. Every returned path is guaranteed to be in ``files``."""
    fileset = set(_norm_rel(f) for f in files)
    fileset.update(e["path"] for e in entries)                      # a declared manifest may anchor a snippet too
    chosen: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def take(path: str, role: str, anchors: Optional[List[re.Pattern]] = None) -> None:
        path = _norm_rel(path)
        if path in seen or path not in fileset or len(chosen) >= limit:
            return
        seen.add(path)
        chosen.append({"path": path, "role": role, "anchors": [r.pattern for r in (anchors or [])]})

    for e in entries[:4]:
        take(e["path"], "entry point (%s)" % e["kind"], _anchor_res_for(e["kind"]))
    for h in (hotspots or [])[:4]:
        take(h["file"], "hotspot (%s commits)" % h.get("commits", "?"))
    degree: Dict[str, int] = {}
    for a, b in edges:
        degree[a] = degree.get(a, 0) + 1
        degree[b] = degree.get(b, 0) + 1
    dirs: Dict[str, str] = {}
    for f in sorted(fileset):
        dirs.setdefault(_dom_of(f), f)
    for d, f in sorted(dirs.items(), key=lambda t: -degree.get(t[1], 0))[:4]:
        take(f, "best-connected module of %s/" % d)
    return chosen


# --------------------------------------------------------------------------- structure stage
def structure(root: str) -> Dict[str, Any]:
    """Deterministic architecture facts + entry points + key files + a bounded module/edge projection for the prompt."""
    files = [_norm_rel(f) for f in arch.collect_files(root, 4000)]
    a = arch.analyze(root, online=False)
    edges, _ = arch.import_graph(root, files)
    entries = entry_points(root, files)
    hot = [{"file": h["file"], "commits": h["commits"], "score": h["score"]} for h in a.get("hotspots") or []]
    kf = key_files(files, entries, hot, edges)
    locs = _loc_map(root, [k["path"] for k in kf])
    fan_in: Dict[str, int] = {}
    fan_out: Dict[str, int] = {}
    for a_, b_ in edges:
        fan_out[a_] = fan_out.get(a_, 0) + 1
        fan_in[b_] = fan_in.get(b_, 0) + 1
    ranked = sorted(set(list(fan_in) + list(fan_out)), key=lambda m: (-(fan_in.get(m, 0) + fan_out.get(m, 0)), m))
    modules = [{"path": m, "loc": locs.get(m, 0), "fan_in": fan_in.get(m, 0), "fan_out": fan_out.get(m, 0)}
               for m in ranked[:25]]
    edge_rank = sorted(edges, key=lambda e: (-(fan_in.get(e[1], 0) + fan_out.get(e[0], 0)), e))[:60]
    for k in kf:
        k["loc"] = locs.get(k["path"], 0)
    total_loc = int((a.get("stack") or {}).get("loc") or 0)
    return {"stack": a.get("stack") or {}, "graph": a.get("graph") or {}, "clusters": (a.get("clusters") or [])[:8],
            "hotspots": hot, "runtime_eol": a.get("runtime_eol") or [], "notes": (a.get("notes") or [])[:6],
            "coupling": a.get("coupling") or {"pairs": [], "hidden_dependencies": 0, "pairs_total": 0},
            "files": files, "files_all": files, "files_count": len(files), "total_loc": total_loc,
            "manifests": _manifests(root),
            "entry_points": entries, "key_files": kf, "modules": modules, "edges": edge_rank}


def _loc_map(root: str, paths: List[str], *, cap: int = 60, bytes_cap: int = 200_000) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for p in paths[:cap]:
        try:
            with open(os.path.join(root, p), "r", encoding="utf-8", errors="replace") as fh:
                out[p] = sum(1 for _ in fh)
        except OSError:
            continue
    return out


def _manifests(root: str) -> Dict[str, Any]:
    """Which deployment/entry manifests exist, plus a rough compose service count (heuristic input only)."""
    out: Dict[str, Any] = {}
    for m in ("docker-compose.yml", "compose.yml", "docker-compose.yaml", "Dockerfile", "dockerfile",
              "Makefile", "package.json", "pyproject.toml", "go.mod", "pom.xml"):
        out[m] = os.path.isfile(os.path.join(root, m))
    for m in ("docker-compose.yml", "compose.yml", "docker-compose.yaml"):
        p = os.path.join(root, m)
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    body = fh.read(200_000)
                out["compose_services"] = len(re.findall(r"^ {2}[A-Za-z0-9_.-]+:\s*$", body, re.M))
            except OSError:
                pass
            break
    return out


# --------------------------------------------------------------------------- license verdict
def notice_checklist(license_id: str, category: str, distribution: str) -> Dict[str, Any]:
    """What the detected license demands - as a checklist of clause references, honest about the distribution mode.
    This is compliance-support evidence, not a legal assessment."""
    cl: List[Dict[str, str]] = []
    network_clause = False
    if category == "strong-copyleft":
        cl = [{"clause": "GPL-3.0 §4", "req": "convey 시 저작권 고지·보증 부인 유지, 라이선스 전문 동봉"},
              {"clause": "GPL-3.0 §5", "req": "수정 사실과 날짜 고지, 저작물 전체를 GPL-3.0으로 라이선스"},
              {"clause": "GPL-3.0 §6", "req": "바이너리 배포 시 Corresponding Source + 설치 정보 제공"},
              {"clause": "GPL-3.0 §7", "req": "추가 조건 적용 여부 확인"}]
    elif category == "network-copyleft":
        cl = [{"clause": "AGPL-3.0 §4-6", "req": "GPL과 동일한 고지·소스 제공 의무"},
              {"clause": "AGPL-3.0 §13", "req": "네트워크로 상호작용하는 모든 사용자에게 소스 제공 경로를 눈에 띄게 제공"}]
        network_clause = True
    elif category == "weak-copyleft":
        cl = [{"clause": "NOTICE", "req": "저작권·라이선스 고지 유지"},
              {"clause": "LIBRARY", "req": "라이브러리 자체의 수정본 공개 및 재링크 허용(LGPL)"}]
    elif category in ("permissive", "public-domain"):
        cl = [{"clause": "NOTICE", "req": "저작권 + 라이선스 고지 유지"}]
    else:
        cl = [{"clause": "REVIEW", "req": "라이선스 식별이 먼저입니다 - council/수동 검토 필요"}]
    verdicts = []
    for dist in DISTRIBUTIONS:
        if dist == "binary":
            if category == "network-copyleft":
                verdicts.append({"distribution": dist, "verdict": "deny", "why": "기본 정책상 network-copyleft는 바이너리 배포 금지"})
            elif category == "strong-copyleft":
                verdicts.append({"distribution": dist, "verdict": "review", "why": "배포 시 소스 제공 의무 발생(§6)"})
            elif category == "weak-copyleft":
                verdicts.append({"distribution": dist, "verdict": "review", "why": "라이브러리 수정본 공개 필요"})
            else:
                verdicts.append({"distribution": dist, "verdict": "ok", "why": "고지 유지로 충분"})
        elif dist == "saas":
            if category == "network-copyleft":
                verdicts.append({"distribution": dist, "verdict": "deny", "why": "§13: 네트워크 사용자에게 소스 제공 의무(수정본 포함)"})
            else:
                verdicts.append({"distribution": dist, "verdict": "ok" if category in ("permissive", "public-domain") else "review",
                                 "why": "배포(convey)가 없어 카피레프트 트리거 없음" if category in ("strong-copyleft", "weak-copyleft") else "고지 유지"})
        else:
            verdicts.append({"distribution": dist, "verdict": "ok", "why": "내부 전용: convey 없음 - 고지 의무만 유지"})
    return {"distribution": distribution, "checklist": cl, "network_clause": network_clause,
            "verdicts": verdicts, "note": "법적 판단이 아니라 의무 증거 수집 도구입니다 - 배포 전 전문 확인 필요"}


def compat_matrix(license_id: str) -> Dict[str, Any]:
    """Pairwise verdicts of the detected license against the common product-license classes (license_categories)."""
    if not license_id or not _SINGLE_ID_RE.match(license_id):
        return {"rows": [], "note": "compound or unknown license expression - review per SPDX id"}
    rows = []
    for cand in _COMPAT_CANDIDATES:
        status, reason = license_categories.compatible(license_id, cand)
        rows.append({"their": license_id, "your": cand, "status": status, "reason": clip(reason, 160)})
    return {"rows": rows, "note": ""}


def license_verdict(root: str, distribution: str = "binary") -> Dict[str, Any]:
    lt = licenses.scan_tree(root)
    expr = str(lt.get("project_license") or "")
    cat = licenses.category(expr) if expr else "unknown"
    return {"project_license": expr, "project_license_source": str(lt.get("project_license_source") or ""),
            "category": cat, "obligations": licenses.OBLIGATIONS.get(cat, ["identify the license first"]),
            "license_files": [{"file": f["file"], "license": f["license"], "detected": f["detected"]}
                              for f in (lt.get("license_files") or [])[:20]],
            "vendored": [{"file": f["file"], "license": f["license"] or "?"} for f in (lt.get("vendored") or [])[:15]],
            "spdx_header_counts": lt.get("spdx_header_counts") or {},
            "notice": notice_checklist(expr, cat, distribution), "compat": compat_matrix(expr)}


# --------------------------------------------------------------------------- the AI lane
def prompt_evidence(name: str, lic: Dict[str, Any], struct: Dict[str, Any],
                    insights: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The evidence the model sees. METADATA ONLY - paths, counts, edges. A test asserts no source line ever lands here."""
    ins = insights or {}
    fb = ins.get("flow_blockers") or {}
    bcc = ins.get("bounded_context_candidates") or {}
    return {"project": name, "prompt_version": PROMPT_VERSION,
            "license": {"project_license": lic["project_license"], "category": lic["category"],
                        "obligations": lic["obligations"]},
            "stack": {k: v for k, v in struct["stack"].items() if not str(k).startswith("_")},
            "totals": {"files": struct["files_count"], "loc": struct["total_loc"]},
            "entry_points": struct["entry_points"],
            "modules": struct["modules"],
            "import_edges": [[a, b] for a, b in struct["edges"]],
            "cycles": (struct["graph"].get("cycles") or [])[:5],
            "hotspots": [h["file"] for h in struct["hotspots"][:8]],
            "clusters": [{"domain": c["domain"], "modules": c["modules"]} for c in struct["clusters"][:8]],
            "insights": {"flow_blockers": fb.get("count"),
                         "bounded_context_candidates": [c["name"] for c in (bcc.get("candidates") or [])[:5]],
                         "style_hypothesis": (ins.get("style_hypothesis") or {}).get("style") or ""},
            "notes": struct["notes"]}


def _clean_step(s: Any) -> Optional[Dict[str, str]]:
    if not isinstance(s, dict):
        return None
    actor, action, target = str(s.get("actor") or "").strip(), str(s.get("action") or "").strip(), str(s.get("target") or "").strip()
    if not actor or not action or not target:
        return None
    if any(looks_like_code(x) for x in (actor, action, target)):
        return None
    return {"actor": clip(actor, 80), "action": clip(action, 160), "target": clip(target, 80)}


def validate_arch(obj: Any, files: Set[str], entry_paths: Set[str]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """Four validation layers (schema / rule / semantic grounding / cross-field). An item that fails any layer is
    dropped and counted - the counts land in the result so the pane can say exactly what the model lost."""
    dropped = {"schema": 0, "rule": 0, "semantic": 0, "cross_field": 0}
    if not isinstance(obj, dict):
        raise ValueError("LLM answer is not a JSON object")
    overview = str(obj.get("overview") or "").strip()
    if looks_like_code(overview):
        overview = ""
    comps: List[Dict[str, Any]] = []
    names: Set[str] = set()
    for c in (obj.get("components") or [])[:12]:
        if not (isinstance(c, dict) and isinstance(c.get("name"), str) and c["name"].strip()):
            dropped["schema"] += 1
            continue
        name = clip(c["name"].strip(), 60)
        role = clip(str(c.get("role") or "").strip(), 300)
        if looks_like_code(name) or looks_like_code(role):
            dropped["rule"] += 1
            continue
        if name.lower() in names:
            dropped["rule"] += 1
            continue
        cfiles = []
        bad_ref = False
        for f in (c.get("files") or [])[:8]:
            rel = _norm_rel(f)
            if rel in files:
                cfiles.append(rel)
            else:
                bad_ref = True                      # one invented path grounds the whole component unverifiable
        if bad_ref:
            dropped["semantic"] += 1
            continue
        if not cfiles:
            dropped["cross_field"] += 1
            continue
        comps.append({"name": name, "role": role, "files": cfiles})
        names.add(name.lower())
    known = names | {p.lower() for p in entry_paths} | {"user"}
    scen: List[Dict[str, Any]] = []
    for s in (obj.get("scenarios") or [])[:6]:
        if not (isinstance(s, dict) and isinstance(s.get("name"), str) and s["name"].strip() and isinstance(s.get("steps"), list)):
            dropped["schema"] += 1
            continue
        parts = [clip(str(p), 80) for p in (s.get("participants") or [])[:4] if str(p).strip()]
        if any(p.lower() not in known for p in parts):
            dropped["semantic"] += 1
            continue
        steps = [st for st in (_clean_step(x) for x in s["steps"][:16]) if st]
        if any(st["actor"].lower() not in known or st["target"].lower() not in known for st in steps):
            dropped["semantic"] += 1
            continue
        if len(steps) < 2:
            dropped["cross_field"] += 1
            continue
        desc = clip(str(s.get("description") or "").strip(), 500)
        if looks_like_code(desc):
            desc = ""
        scen.append({"name": clip(s["name"].strip(), 100), "description": desc, "participants": parts,
                     "steps": steps[:MAX_STEPS], "inferred": False})
    flows: List[Dict[str, Any]] = []
    for a in (obj.get("activity") or [])[:4]:
        if not (isinstance(a, dict) and isinstance(a.get("name"), str) and a["name"].strip() and isinstance(a.get("steps"), list)):
            dropped["schema"] += 1
            continue
        steps = [clip(str(x), 160) for x in a["steps"][:16] if str(x).strip() and not looks_like_code(x)]
        decisions = []
        for d in (a.get("decisions") or [])[:4]:
            try:
                i0, i1, i2 = int(d.get("after_step")), int(d.get("then_step")), int(d.get("else_step"))
            except (TypeError, ValueError):
                dropped["schema"] += 1
                continue
            if not (0 <= i0 < len(steps) and 0 <= i1 < len(steps) and 0 <= i2 < len(steps)):
                dropped["semantic"] += 1
                continue
            decisions.append({"after_step": i0, "question": clip(str(d.get("question") or "condition"), 120),
                              "then_step": i1, "else_step": i2})
        if len(steps) < 2:
            dropped["cross_field"] += 1
            continue
        flows.append({"name": clip(a["name"].strip(), 100), "steps": steps[:MAX_STEPS], "decisions": decisions})
    note = str(obj.get("license_note") or "").strip()
    if looks_like_code(note):
        note = ""
    return ({"overview": clip(overview, 1200), "components": comps[:MAX_COMPONENTS], "scenarios": scen[:MAX_SCENARIOS],
             "activity": flows[:MAX_ACTIVITY], "license_note": clip(note, 900)}, dropped)


def deterministic_analysis(ev: Dict[str, Any], lang: str = "ko") -> Dict[str, Any]:
    """The honest no-LLM fallback: components from measured clusters, one static-inference startup scenario, and
    NO invented scenario data (activity flows stay empty and the pane says an LLM key is needed for them)."""
    comps: List[Dict[str, Any]] = []
    mod_paths = [m["path"] for m in ev.get("modules") or []]
    for c in (ev.get("clusters") or [])[:MAX_COMPONENTS]:
        members = [p for p in mod_paths if _dom_of(p) == c["domain"]][:6]
        if not members:
            members = mod_paths[:1]
        role = ("%d modules, %d inbound / %d outbound edges (measured, deterministic)" %
                (c.get("modules", 0), c.get("inbound", 0), c.get("outbound", 0))) if lang == "en" else \
               ("모듈 %d개, 유입 엣지 %d / 유출 엣지 %d (측정값, 결정론적 분석)" %
                (c.get("modules", 0), c.get("inbound", 0), c.get("outbound", 0)))
        comps.append({"name": clip(c["domain"], 60), "role": role, "files": members})
    scen: List[Dict[str, Any]] = []
    entry = (ev.get("entry_points") or [{}])[0]
    if entry:
        targets = [b for a, b in (ev.get("import_edges") or []) if a == entry.get("path")][:8]
        steps = [{"actor": "User", "action": "runs the entry point (static inference)", "target": entry["path"]}]
        steps += [{"actor": entry["path"], "action": "imports (static edge)", "target": t} for t in targets]
        scen.append({"name": "Startup / entry flow (static inference)" if lang == "en" else "기동 흐름 (정적 유추)",
                     "description": "LLM 없이 임포트 엣지에서 유추한 기동 흐름입니다 - 시나리오 수준 분석은 EXAONE 키가 있을 때 제공됩니다."
                     if lang != "en" else "Derived from import edges without an LLM; scenario-level flows need an EXAONE key.",
                     "participants": ([entry["path"]] + targets[:3]), "steps": steps, "inferred": True})
    tot = ev.get("totals") or {}
    langs = sorted(((ev.get("stack") or {}).get("languages") or {}).keys())
    overview = ("%d files / %d LOC across %s; %d entry points; import graph: %d edges, %s cycles. Deterministic "
                "fallback analysis (no LLM)." %
                (tot.get("files", 0), tot.get("loc", 0), ", ".join(langs[:5]) or "unknown languages",
                 len(ev.get("entry_points") or []), len(ev.get("import_edges") or []),
                 len(ev.get("cycles") or []))) if lang == "en" else \
               ("파일 %d개 / %d LOC (%s). 엔트리포인트 %d개, 임포트 엣지 %d개, 사이클 %s개. LLM 미사용 결정론적 분석입니다." %
                (tot.get("files", 0), tot.get("loc", 0), ", ".join(langs[:5]) or "언어 미확인",
                 len(ev.get("entry_points") or []), len(ev.get("import_edges") or []), len(ev.get("cycles") or [])))
    lic = ev.get("license") or {}
    note = ("%s (%s): %s" % (lic.get("project_license") or "unknown", lic.get("category") or "unknown",
                             "; ".join(lic.get("obligations") or [])))
    return {"overview": overview, "components": comps, "scenarios": scen, "activity": [], "license_note": clip(note, 900)}


def propose_arch(ev: Dict[str, Any], *, client: Optional[ChatClient] = None, cache_dir: Optional[str] = None,
                 use_llm: bool = True, lang: str = "ko",
                 files: Optional[Set[str]] = None, entry_paths: Optional[Set[str]] = None) -> Dict[str, Any]:
    """ai.propose's contract for architecture analysis: prompt-hash cache -> one EXAONE JSON call -> validate ->
    honest deterministic fallback (``source="deterministic"`` + the cause in ``llm_note``)."""
    files = files if files is not None else {m["path"] for m in ev.get("modules") or []}
    entry_paths = entry_paths if entry_paths is not None else {e["path"] for e in ev.get("entry_points") or []}
    prompt = json.dumps(ev, ensure_ascii=False, sort_keys=True)
    sys_prompt = SYSTEM + (" Write overview, role, description, steps and license_note in Korean." if lang == "ko"
                           else " Write in English.")
    key = hashlib.sha256((PROMPT_VERSION + sys_prompt + prompt).encode()).hexdigest()[:20]
    cpath = os.path.join(cache_dir, "arch_" + key + ".json") if cache_dir else None
    note = ""
    raw: Optional[str] = None
    cached = False
    if cpath and os.path.isfile(cpath):
        try:
            with open(cpath, "r", encoding="utf-8") as fh:
                raw = fh.read()
            cached = True
            note = "cached EXAONE response for identical evidence (no new call)"
        except OSError:
            raw = None
    if raw is None and use_llm and client is not None:
        try:
            raw = client.complete(sys_prompt, prompt, max_tokens=8192, json_mode=True)
        except LLMUnavailable as exc:
            note = "EXAONE unavailable -> deterministic analysis: " + clip(str(exc), 220)
        except LLMError as exc:
            note = "EXAONE error -> deterministic analysis: " + clip(str(exc), 220)
    elif raw is None:
        note = "use_llm=false" if not use_llm else "no LLM client configured"
    if raw is not None:
        try:
            analysis, dropped = validate_arch(parse_json(raw), files, entry_paths)
            if analysis["components"] or analysis["scenarios"]:
                if cpath and not cached:
                    os.makedirs(cache_dir, exist_ok=True)
                    with open(cpath, "w", encoding="utf-8") as fh:
                        fh.write(raw)
                return {"source": "exaone", "model": getattr(client, "model", "") if client else "cached",
                        "analysis": analysis, "dropped": dropped, "llm_note": note, "cached": cached,
                        "cache_key": key, "prompt_version": PROMPT_VERSION}
            note = (note + " | " if note else "") + "no analysis survived validation (dropped=%s) -> deterministic" % dropped
        except (ValueError, TypeError) as exc:
            note = (note + " | " if note else "") + "unparseable EXAONE output -> deterministic: " + type(exc).__name__
    return {"source": "deterministic", "model": "", "analysis": deterministic_analysis(ev, lang), "dropped": {},
            "llm_note": note, "cached": False, "cache_key": key, "prompt_version": PROMPT_VERSION}


# --------------------------------------------------------------------------- diagrams (deterministic)
def mermaid_components(analysis: Dict[str, Any], edges: List[Tuple[str, str]]) -> Tuple[str, str]:
    """Component graph as Mermaid ``flowchart TD``. Edges are aggregated from real import edges via the components'
    verified file lists (never invented); fallback edge source: scenario steps between components."""
    comps = analysis.get("components") or []
    if not comps:
        return "", "no components to draw"
    owner: Dict[str, int] = {}
    for i, c in enumerate(comps):
        for f in c.get("files") or []:
            owner.setdefault(f, i)
    agg: Dict[Tuple[int, int], int] = {}
    for a, b in edges:
        ia, ib = owner.get(a), owner.get(b)
        if ia is not None and ib is not None and ia != ib:
            agg[(min(ia, ib), max(ia, ib))] = agg.get((min(ia, ib), max(ia, ib)), 0) + 1
    lines = ["flowchart TD"]
    for i, c in enumerate(comps):
        label = mermaid_label(c["name"]) + "<br/>" + mermaid_label(c.get("role") or "", 60)
        lines.append('  c%d["%s"]' % (i, label))
    if not agg:
        for s in analysis.get("scenarios") or []:
            name_of = {c["name"].lower(): i for i, c in enumerate(comps)}
            for st in s.get("steps") or []:
                ia, ib = name_of.get(str(st["actor"]).lower()), name_of.get(str(st["target"]).lower())
                if ia is not None and ib is not None and ia != ib:
                    agg[(min(ia, ib), max(ia, ib))] = agg.get((min(ia, ib), max(ia, ib)), 0) + 1
    for (ia, ib), n in sorted(agg.items()):
        lines.append("  c%d -->|%d| c%d" % (ia, n, ib))
    return "\n".join(lines), ""


def mermaid_sequence(scenario: Dict[str, Any]) -> str:
    pids: Dict[str, str] = {}

    def pid(name: str) -> str:
        key = str(name).lower()
        if key not in pids:
            pids[key] = "p%d" % (len(pids) + 1)
        return pids[key]

    lines = ["sequenceDiagram", "  autonumber"]
    seen: Set[str] = set()
    for p in scenario.get("participants") or []:
        k = str(p).lower()
        if k not in seen:
            seen.add(k)
            lines.append("  participant %s as %s" % (pid(p), mermaid_label(p, 50)))
    for st in scenario.get("steps") or []:
        for side in (st["actor"], st["target"]):
            k = str(side).lower()
            if k not in seen:
                seen.add(k)
                lines.append("  participant %s as %s" % (pid(side), mermaid_label(side, 50)))
        arrow = "-->>" if str(st["target"]).lower() == "user" else "->>"
        lines.append("  %s%s%s: %s" % (pid(st["actor"]), arrow, pid(st["target"]), mermaid_label(st["action"], 70)))
    return "\n".join(lines)


def mermaid_activity(flow: Dict[str, Any]) -> Tuple[str, str]:
    steps = flow.get("steps") or []
    if len(steps) < 2:
        return "", "fewer than 2 steps - nothing to draw"
    lines = ["flowchart TD"]
    for i, s in enumerate(steps):
        lines.append('  a%d["%d. %s"]' % (i, i + 1, mermaid_label(s, 70)))
    dec = flow.get("decisions") or []
    dnode = {}
    for j, d in enumerate(dec):
        dnode[d["after_step"]] = "d%d" % j
    for i in range(len(steps) - 1):
        if i in dnode:
            lines.append("  a%d --> %s" % (i, dnode[i]))
        else:
            lines.append("  a%d --> a%d" % (i, i + 1))
    for j, d in enumerate(dec):
        q = mermaid_label(d.get("question") or "condition", 60)
        lines.append('  d%d{"%s"}' % (j, q))
        lines.append("  d%d -- yes --> a%d" % (j, d["then_step"]))
        lines.append("  d%d -- no --> a%d" % (j, d["else_step"]))
    return "\n".join(lines), ""


def build_diagrams(analysis: Dict[str, Any], edges: List[Tuple[str, str]]) -> Dict[str, Any]:
    comp_src, comp_note = mermaid_components(analysis, edges)
    seqs = [{"name": s["name"], "mermaid": mermaid_sequence(s), "steps": s.get("steps") or [],
             "inferred": bool(s.get("inferred"))} for s in analysis.get("scenarios") or []]
    acts = []
    for f in analysis.get("activity") or []:
        src, note = mermaid_activity(f)
        acts.append({"name": f["name"], "mermaid": src, "note": note, "steps": f.get("steps") or []})
    return {"components": {"mermaid": comp_src, "note": comp_note}, "sequence": seqs, "activity": acts}


# --------------------------------------------------------------------------- code snippets + highlighting
_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "py": ("def class return import from if elif else for while try except finally with as pass break continue "
           "lambda yield global nonlocal assert raise del in is not and or None True False async await match case"),
    "js": ("var let const function return if else for while do switch case break continue new typeof instanceof "
           "class extends super this import export from default try catch finally throw async await yield of in null true false undefined"),
    "go": ("package import func var const type struct interface map chan go defer return if else for range switch "
           "case break continue select nil true false string int int64 float64 bool error"),
    "java": ("package import class interface enum extends implements public private protected static final void "
             "return if else for while do switch case break continue try catch finally throw throws new this super "
             "null true false int long double boolean String"),
    "c": ("include define typedef struct union enum static const void int char long unsigned float double return "
          "if else for while do switch case break continue sizeof NULL"),
    "cs": ("using namespace class struct interface enum public private protected static readonly void return if "
           "else for foreach while switch case break continue try catch finally throw new this null true false string int var"),
    "rb": ("def class module end if elsif else unless while until for do begin rescue ensure return yield require "
           "require_relative attr_accessor self nil true false puts proc lambda"),
    "rs": ("fn let mut const static struct enum impl trait pub use mod crate self super match if else loop while "
           "for in return break continue where as dyn ref move async await unsafe true false Some None Ok Err"),
    "php": ("function return if else elseif foreach for while switch case break continue class interface extends "
            "implements public private protected static new try catch finally throw echo print require include null true false"),
}
_LANG_OF = {".py": "py", ".pyw": "py", ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js",
            ".tsx": "js", ".go": "go", ".java": "java", ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c",
            ".hpp": "c", ".hxx": "c", ".cs": "cs", ".rb": "rb", ".rs": "rs", ".php": "php"}
_PATTERNS: Dict[str, Any] = {}


def _pattern(fam: str):
    if fam not in _PATTERNS:
        kws = "|".join(re.escape(k) for k in sorted(_KEYWORDS[fam].split(), key=len, reverse=True))
        comments = r"//[^\n]*|/\*.*?\*/" if fam != "py" and fam != "rb" else r"#[^\n]*"
        if fam == "py":
            comments += r"|#[^\n]*"
        if fam == "py":
            strings = r'"""(?:[^"\\]|\\.)*?"""|\'\'\'(?:[^\'\\]|\\.)*?\'\'\'|"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\''
        elif fam == "rb":
            strings = r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\''
        else:
            strings = r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|`(?:[^`\\]|\\.)*`'
        _PATTERNS[fam] = re.compile(r"(?P<com>%s)|(?P<str>%s)|(?P<num>\b\d+(?:\.\d+)?\b)|(?P<kw>\b(?:%s)\b)"
                                    % (comments, strings, kws), re.S)
    return _PATTERNS[fam]


def highlight(code: str, lang: Optional[str]) -> str:
    """Escape first, then wrap known token classes in whitelisted spans (tok-com/str/num/kw). ``lang`` is a family
    name ("py", "js", ...) or a file extension (".py", "py"). An unknown language renders as escaped plain text -
    never raw HTML."""
    import html as _html
    text = _html.escape(str(code or ""), quote=False)
    low = (lang or "").lower().lstrip(".")
    fam = low if low in _KEYWORDS else _LANG_OF.get(low)
    if fam is None or fam not in _KEYWORDS:
        return text
    rx = _pattern(fam)
    out: List[str] = []
    pos = 0
    for m in rx.finditer(text):
        out.append(text[pos:m.start()])
        out.append('<span class="tok-%s">%s</span>' % (m.lastgroup, m.group()))
        pos = m.end()
    out.append(text[pos:])
    return "".join(out)


def lang_of(path: str) -> Optional[str]:
    return _LANG_OF.get(os.path.splitext(path)[1].lower())


def _snippet_lines(text: str, anchor_patterns: List[str]) -> Tuple[List[str], int, int]:
    lines = text.splitlines()
    if len(lines) <= SNIPPET_MAX_LINES:
        return lines, 1, len(lines)
    anchors = [re.compile(p) for p in anchor_patterns]
    for rx in anchors:
        for i, ln in enumerate(lines):
            if rx.search(ln):
                start = max(0, i - 6)
                end = min(len(lines), start + SNIPPET_WINDOW)
                return lines[start:end], start + 1, end
    return lines[:SNIPPET_MAX_LINES], 1, SNIPPET_MAX_LINES


def code_snippets(root: str, key_files: List[Dict[str, Any]], *, project_license: str = "") -> List[Dict[str, Any]]:
    """Bounded highlighted snippets for the key files. The window centres on the entry-point anchor when one is
    found, otherwise the file head. Every string is escaped by :func:`highlight` before it becomes HTML."""
    out: List[Dict[str, Any]] = []
    for kf in key_files[:MAX_KEY_FILES]:
        full = os.path.join(root, kf["path"])
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(120_000)
        except OSError:
            continue
        lines, start, end = _snippet_lines(text, kf.get("anchors") or [])
        lang = lang_of(kf["path"])
        total = text.count("\n") + (0 if text.endswith("\n") or not text else 1)
        out.append({"path": kf["path"], "role": kf.get("role", ""), "lang": lang or "text",
                    "total_lines": max(total, 0), "start_line": start, "end_line": end,
                    "truncated": end < total or start > 1,
                    "html": highlight("\n".join(lines), lang), "license": project_license})
    return out


# --------------------------------------------------------------------------- report
def report_md(res: Dict[str, Any]) -> str:
    lic = res.get("license") or {}
    meta = res.get("meta") or {}
    an = res.get("analysis") or {}
    dg = res.get("diagrams") or {}
    lines: List[str] = ["# Arch Intel — %s" % (meta.get("source") or meta.get("name") or "project"), "",
                        "schema: `%s` · generated by BTS-SBOM %s" % (SCHEMA, meta.get("tool_version") or ""), ""]
    lines += ["## License verdict", "",
              "- project license: **%s** (%s, %s)" % (lic.get("project_license") or "unknown", lic.get("category") or "unknown",
                                                      lic.get("project_license_source") or "no source"),
              "- obligations: %s" % "; ".join(lic.get("obligations") or []), ""]
    nv = lic.get("notice") or {}
    if nv.get("checklist"):
        lines += ["| clause | requirement |", "|---|---|"]
        lines += ["| %s | %s |" % (c.get("clause"), c.get("req")) for c in nv["checklist"]]
        lines.append("")
    cm = lic.get("compat") or {}
    if cm.get("rows"):
        lines += ["| this package | your product license | verdict | why |", "|---|---|---|---|"]
        lines += ["| %s | %s | %s | %s |" % (r["their"], r["your"], r["status"], r["reason"]) for r in cm["rows"]]
        lines.append("")
    lines += ["## Overview (%s)" % (res.get("ai_source") or "deterministic"), "", an.get("overview") or "—", ""]
    if an.get("components"):
        lines += ["| component | role | files |", "|---|---|---|"]
        lines += ["| %s | %s | %s |" % (c["name"], c.get("role"), ", ".join("`%s`" % f for f in c.get("files") or []))
                  for c in an["components"]]
        lines.append("")
    for kind, key in (("Component diagram", "components"), ("Sequence diagrams", "sequence"), ("Activity flows", "activity")):
        items = dg.get(key)
        if not items:
            continue
        if key == "components":
            items = [items] if isinstance(items, dict) else items
        for item in items:
            src = (item or {}).get("mermaid") or ""
            name = (item or {}).get("name") or kind
            if src:
                lines += ["### %s" % name, "", "```mermaid", src, "```", ""]
    ins = res.get("insights") or {}
    if ins:
        lines += ["## Insights (measured, heuristic)", ""]
        fb = (ins.get("flow_blockers") or {})
        if fb.get("blockers"):
            lines += ["| flow blocker | where | why |", "|---|---|---|"]
            lines += ["| %s | %s | %s |" % (b.get("kind"), clip(str(b.get("what")), 120), b.get("why"))
                      for b in fb["blockers"]]
            lines.append("")
        bcc = (ins.get("bounded_context_candidates") or {})
        if bcc.get("candidates"):
            lines += ["Bounded context candidates: %s" % ", ".join("`%s`" % c["name"] for c in bcc["candidates"]), ""]
        sh = (ins.get("style_hypothesis") or {})
        if sh.get("style"):
            lines += ["Style hypothesis: **%s** — %s" % (sh["style"], sh.get("why")), ""]
        ap = (ins.get("antipattern_signals") or {})
        if ap.get("signals"):
            lines += ["Antipattern signals: %s" % "; ".join(s.get("code") for s in ap["signals"]), ""]
        mod = (ins.get("modularity") or {})
        if mod:
            lines += ["Modularity: avg cohesion %s, acyclic %s%%, tangle %s." %
                      (mod.get("avg_cohesion"), mod.get("acyclic_percent"), mod.get("tangle_ratio")), ""]
    code = res.get("code") or []
    if code:
        lines += ["## Key files (excerpts)", ""]
        lines += ["### `%s` (%s, lines %d-%d of %d)" % (c["path"], c.get("role"), c.get("start_line"), c.get("end_line"),
                                                        c.get("total_lines")) for c in code]
        lines.append("")
    lines += ["---", "", "Honesty: the analysed tree was never executed; the dynamic views are static inferences; "
                        "the AI prompt carried metadata only (no source code). This report shows excerpts of a "
                        "copyrighted work under %s — redistributing it triggers that license's obligations."
              % (lic.get("project_license") or "the detected license")]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- the pipeline
def run(src: str, *, work_root: str, out_dir: str, jid: str = "manual", client: Optional[ChatClient] = None,
        use_llm: bool = True, lang: str = "ko", distribution: str = "binary", ref: Optional[str] = None,
        cache_dir: Optional[str] = None, progress: Optional[Any] = None, cancel: Optional[Any] = None) -> Dict[str, Any]:
    """Staged pipeline; returns the result dict (also persisted as ``<out_dir>/result.json`` + ``report.md``) or
    ``{"error": ...}``. The work copy is always removed before returning."""
    if distribution not in DISTRIBUTIONS:
        distribution = "binary"

    def on_progress(etype: str, **fields: Any) -> None:
        if progress is not None:
            try:
                progress(etype, **fields)
            except Exception:                                         # noqa: BLE001 - telemetry must never kill the run
                pass

    def stage(name: str) -> float:
        if cancel is not None and cancel.is_set():
            raise oss_common.Cancelled("cancelled")
        on_progress("step_start", name=name)
        return time.monotonic()

    def stage_done(name: str, t0: float, ok: bool = True, error: str = "") -> None:
        on_progress("step_end", name=name, ok=ok, seconds=round(time.monotonic() - t0, 3),
                    **({"error": clip(error, 200)} if error else {}))

    result: Dict[str, Any] = {"schema": SCHEMA}
    work_copy: Optional[str] = None
    try:
        t0 = stage("prepare")
        prep = workspace.prepare(src, work_root, ref=ref)
        if not prep.get("ok"):
            return {"error": str(prep.get("error") or "prepare failed")}
        work_copy = prep["path"]
        root = prep["path"]
        stage_done("prepare", t0)

        t0 = stage("license")
        try:
            lic = license_verdict(root, distribution)
        except Exception as exc:                                      # noqa: BLE001 - a license stage error is survivable
            lic = {"project_license": "", "category": "unknown", "obligations": ["identify the license first"],
                   "license_files": [], "vendored": [], "spdx_header_counts": {},
                   "notice": notice_checklist("", "unknown", distribution), "compat": {"rows": [], "note": str(exc)[:160]},
                   "stage_error": clip(str(exc), 200)}
        stage_done("license", t0)

        t0 = stage("structure")
        st = structure(root)
        stage_done("structure", t0)

        t0 = stage("insights")
        insights = arch_flow.build_insights(st, st.get("manifests"))
        stage_done("insights", t0)

        t0 = stage("ai")
        ev = prompt_evidence(prep.get("name") or "project", lic, st, insights)
        use = use_llm and client is not None and getattr(client, "available", False)
        ai_res = propose_arch(ev, client=client if use else None, cache_dir=cache_dir, use_llm=use, lang=lang,
                              files=set(st["files"]), entry_paths={e["path"] for e in st["entry_points"]})
        stage_done("ai", t0)

        t0 = stage("anchors")
        snippets = code_snippets(root, st["key_files"], project_license=lic["project_license"])
        if not ai_res["analysis"].get("scenarios"):
            # the validator dropped every LLM scenario (unverifiable component references): fall back to the
            # deterministic static-inference scenario so the Sequence view never silently disappears
            # (user test 2026-11-22: django.nV lost all sequences this way). Labeled inferred, as usual.
            fb = deterministic_analysis(ev, lang=lang)
            ai_res["analysis"]["scenarios"] = fb["scenarios"]
            if fb["scenarios"]:
                ai_res["llm_note"] = (ai_res["llm_note"] + " | " if ai_res.get("llm_note") else "") + \
                    ("모든 LLM 시나리오가 검증에서 드롭되어 결정론적 기동 흐름으로 대체했습니다"
                     if lang != "en" else "all LLM scenarios were dropped by validation; replaced by the deterministic startup flow")
        diagrams = build_diagrams(ai_res["analysis"], st["edges"])
        stage_done("anchors", t0)

        structure_pub = {k: v for k, v in st.items() if k != "files"}
        structure_pub["modules"] = st["modules"][:25]
        result.update({
            "meta": {"id": jid, "source": src, "kind": prep.get("kind"), "name": prep.get("name"),
                     "lang": lang, "distribution": distribution, "use_llm": bool(use),
                     "finished": _now(), "tool_version": __version__},
            "lineage": prep.get("lineage") or {},
            "license": lic, "structure": structure_pub,
            "ai_source": ai_res["source"], "ai_model": ai_res["model"], "ai_note": ai_res["llm_note"],
            "ai_dropped": ai_res["dropped"], "analysis": ai_res["analysis"],
            "insights": insights,
            "diagrams": diagrams, "code": snippets,
            "honesty": {"executed": False, "dynamic_view": "static inference (the tree is never executed)",
                        "prompt_contains_source": False}})
        t0 = stage("persist")
        persist(out_dir, result)
        stage_done("persist", t0)
        return result
    except oss_common.Cancelled:
        return {"error": "cancelled"}
    except Exception as exc:                                          # noqa: BLE001 - the API layer reports it honestly
        return {"error": "%s: %s" % (type(exc).__name__, clip(str(exc), 200))}
    finally:
        if work_copy:
            try:
                shutil.rmtree(work_copy, onerror=workspace._force_remove)
            except OSError:
                pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def persist(out_dir: str, result: Dict[str, Any]) -> None:
    """Write result.json + report.md under ``out_dir`` (the caller chooses it; only this function writes there)."""
    os.makedirs(out_dir, exist_ok=True)
    for name, obj_ in (("result.json", result), ("report.md", report_md(result))):
        tmp = os.path.join(out_dir, name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            if isinstance(obj_, str):
                fh.write(obj_)
            else:
                json.dump(obj_, fh, ensure_ascii=False, sort_keys=True, default=str)
        os.replace(tmp, os.path.join(out_dir, name))


def load_result(out_dir: str) -> Optional[Dict[str, Any]]:
    try:
        with open(os.path.join(out_dir, "result.json"), "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


def load_report(out_dir: str) -> Optional[str]:
    try:
        with open(os.path.join(out_dir, "report.md"), "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


__all__ = ["SCHEMA", "PROMPT_VERSION", "run", "persist", "load_result", "load_report", "report_md",
           "entry_points", "key_files", "structure", "license_verdict", "notice_checklist", "compat_matrix",
           "prompt_evidence", "validate_arch", "propose_arch", "deterministic_analysis", "build_diagrams",
           "mermaid_components", "mermaid_sequence", "mermaid_activity", "highlight", "lang_of", "code_snippets",
           "looks_like_code", "mermaid_label", "DISTRIBUTIONS", "MAX_COMPONENTS", "MAX_SCENARIOS", "MAX_ACTIVITY"]
