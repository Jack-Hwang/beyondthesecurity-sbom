"""Batch clean-room reimplementation experiment (brief 6 hardening loop): run the reimpl lane across a
curated list of REAL old PyPI packages, accumulate a measured dataset, and summarise what correlates with
behaviour compatibility.

Per package: pick the OLDEST PyPI release that satisfies the lane's bounds (pure-python, root-level module,
small) -> download the sdist -> quick offline scan -> reimpl(attempts=2, live Azure lane) -> record one
dataset row (dataset.jsonl) with the measured verdict and compatibility numbers.

Usage: python scripts/batch_reimpl.py [--limit 25] [--attempts 2] [--skip-scan] [--only name,name]
Dataset: evidence/reimpl_batch/dataset.jsonl + evidence/reimpl_batch/summary.json (regenerated each run).
"""
from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import time
import zipfile
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import urlopen

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bts_sbom_app import llm, reimpl  # noqa: E402
from bts_sbom_app.llm import ChatClient  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BATCH_DIR = os.path.join(ROOT, "evidence", "reimpl_batch")
DATASET = os.path.join(BATCH_DIR, "dataset.jsonl")
SUMMARY = os.path.join(BATCH_DIR, "summary.json")

# classic, mostly-2010-or-earlier pure-python packages (a curated candidate pool - the runner picks the
# oldest release of each that fits the lane's bounds, and skips honestly when none does)
CANDIDATES = [
    "mimeparse", "six", "argparse", "unittest2", "httplib2", "decorator", "webob", "formencode",
    "routes", "beaker", "mako", "genshi", "sqlobject", "nose", "mock", "docutils", "jinja2",
    "python-dateutil", "pytz", "simplejson", "kitchen", "isodate", "xmltodict", "petl", "breadcrumbs",
    "elementtree", "celementtree", "clientform", "mechanize", "beautifulsoup", "feedparser",
    "pep8", "pyflakes", "logilab-common", "sqlalchemy-migrate", "pastescript", "paste",
    "wsgiproxy", "roundup",
    "html5lib", "webencodings", "idna", "chardet", "certifi", "click", "itsdangerous", "blinker",
    "argh", "pathtools", "sortedcontainers", "toposort", "humanize", "tabulate", "validators",
    "wrapt", "south", "supervisor", "pika", "kombu", "anyjson", "pyte", "jawfish", "unidecode",
]
SKIP_DIRS = {".git", "__pycache__", ".eggs", "build", "dist", "tests", "test"}


def pypi_json(name: str) -> Optional[dict]:
    try:
        with urlopen("https://pypi.org/pypi/%s/json" % name, timeout=45) as r:
            return json.load(r)
    except Exception:                                              # noqa: BLE001 - network misses are data
        return None


def release_candidates(name: str) -> List[Tuple[str, str, int]]:
    """(version, sdist url, size) of releases oldest-first that fit the size bounds. The caller iterates -
    a Python-2-era release that cannot parse on this runtime is skipped for the next one."""
    d = pypi_json(name)
    if not d or not d.get("releases"):
        return []
    rels = d["releases"]

    def vkey(v: str):
        import re
        nums = re.findall(r"\d+", v)
        return [int(x) for x in nums[:4]] or [0]

    out: List[Tuple[str, str, int]] = []
    for v in sorted(rels, key=vkey):
        for u in rels[v]:
            fn = u.get("filename") or u.get("url", "").rsplit("/", 1)[-1]
            if not (fn.endswith(".tar.gz") or fn.endswith(".zip")):
                continue
            size = int(u.get("size") or 0)
            if 200 <= size <= 3_000_000:
                out.append((v, u["url"], size))
    return out


def fetch(url: str, dest: str) -> bool:
    try:
        with urlopen(url, timeout=180) as r, open(dest, "wb") as fh:
            fh.write(r.read())
        return os.path.getsize(dest) > 200
    except Exception:                                              # noqa: BLE001
        return False


def extract(archive: str, dest: str) -> Optional[str]:
    """Extract and return the root folder that holds the source (the one containing .py files)."""
    os.makedirs(dest, exist_ok=True)
    try:
        if archive.endswith(".zip"):
            zipfile.ZipFile(archive).extractall(dest)
        else:
            tarfile.open(archive).extractall(dest)
    except Exception:                                              # noqa: BLE001
        return None
    for dp, _, fns in os.walk(dest):
        pys = [f for f in fns if f.endswith(".py") and f != "setup.py"]
        if pys:
            return dp
    return None


def component_pick(folder: str) -> Optional[str]:
    """The root-level module with the most public top-level defs/classes (heuristic, bounded)."""
    best, best_n = None, 0
    for fn in sorted(os.listdir(folder)):
        if not fn.endswith(".py") or fn in ("setup.py", "conftest.py") or fn.startswith("test"):
            continue
        fp = os.path.join(folder, fn)
        try:
            src = open(fp, "r", encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        n = sum(1 for ln in src.splitlines() if ln.startswith("def ") or ln.startswith("class "))
        if n > best_n:
            best, best_n = fn, n
    return best if best_n >= 2 else None


def license_ok_of(folder: str) -> Tuple[bool, str]:
    lic = ""
    for cand in ("PKG-INFO", "setup.py", "README", "README.txt"):
        fp = os.path.join(folder, cand)
        if os.path.exists(fp):
            try:
                txt = open(fp, "r", encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for ln in txt.splitlines():
                low = ln.lower()
                if low.startswith("license:") or (cand == "setup.py" and "license" in low and "=" in ln):
                    lic = ln.split(":", 1)[-1].strip()[:80] if ":" in ln else ln[:80]
                    break
            if lic:
                break
    risky = any(k in lic.upper() for k in ("GPL", "AGPL"))
    return (not risky), (lic or "unknown")


def run_one(name: str, client: Any, attempts: int, do_scan: bool, tmp: str) -> Dict[str, Any]:
    row: Dict[str, Any] = {"package": name, "started": time.strftime("%Y-%m-%dT%H:%M:%S")}
    t0 = time.time()
    import ast as ast_mod
    cands = release_candidates(name)[:6]                     # oldest-first, bounded
    if not cands:
        row.update(skipped="no fitting release on PyPI")
        return row
    version = url = comp = src = None
    for v, u, size in cands:                                 # skip releases that cannot parse on py3
        archive = os.path.join(tmp, "%s-%s" % (name, v))
        os.makedirs(archive, exist_ok=True)
        fn = u.rsplit("/", 1)[-1]
        if not fetch(u, os.path.join(archive, fn)):
            continue
        src = extract(os.path.join(archive, fn), os.path.join(archive, "x"))
        if not src:
            continue
        comp = component_pick(src)
        if not comp:
            continue
        try:
            ast_mod.parse(open(os.path.join(src, comp), "r", encoding="utf-8", errors="replace").read())
        except (SyntaxError, ValueError, OSError):
            continue                                          # py2-era syntax: try the next release
        version, url = v, u
        break
    if not (version and comp):
        row.update(skipped="no python3-parseable release with a root module")
        return row
    row.update({"version": version, "sdist_bytes": os.path.getsize(os.path.join(archive, fn))})
    row["component"] = comp
    lic_ok, lic = license_ok_of(src)
    row["license"] = lic
    if do_scan:
        try:
            from bts_sbom_app import pipeline
            pipeline.run_project(src, work_root=os.path.join(archive, "w"), out_dir=os.path.join(BATCH_DIR, name, "scan"),
                                 use_llm=False, offline=True, run_arch=False)
            row["scanned"] = True
        except Exception as exc:                                   # noqa: BLE001
            row["scanned"] = "failed: %s" % str(exc)[:80]
    events: list = []
    out = os.path.join(BATCH_DIR, name, "reimpl")
    try:
        res = reimpl.reimpl(src, comp, out, client=client, license_ok=lic_ok, why="legacy reimpl experiment",
                            attempts=attempts, publish_dest=None, progress=events.append)
        row.update({"verdict": res.get("verdict"), "reason": (res.get("reason") or "")[:160],
                    "generated_by": res.get("generated_by"), "attempts": res.get("attempts"),
                    "copy_overlap": (res.get("copy_gate") or {}).get("overlap"),
                    "tests_ok": (res.get("tests") or {}).get("ok"),
                    "adopted": res.get("adopted_tests"),
                    "compatibility": res.get("compatibility")})
    except Exception as exc:                                       # noqa: BLE001
        row.update(verdict="error", reason=str(exc)[:200])
    row["elapsed_s"] = round(time.time() - t0, 1)
    return row


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--attempts", type=int, default=2)
    ap.add_argument("--skip-scan", action="store_true")
    ap.add_argument("--only", default=None, help="comma-separated package names (subset run)")
    a = ap.parse_args()

    os.makedirs(BATCH_DIR, exist_ok=True)
    client = None
    cfg = os.path.join(ROOT, "evidence", ".llm_config.json")
    if os.path.exists(cfg):
        os.environ["BTS_SBOM_LLM_CONFIG"] = cfg
        client = ChatClient.from_env(ledger=os.path.join(ROOT, "evidence", ".llm_ledger.json"))
        client = client if client.available else None
    names = [x.strip() for x in a.only.split(",")] if a.only else CANDIDATES[:a.limit]
    print("batch: %d packages, attempts=%d, llm=%s" % (len(names), a.attempts, bool(client)), flush=True)
    rows: List[Dict[str, Any]] = []
    tmp = tempfile.mkdtemp(prefix="reimpl_batch_")
    with open(DATASET, "a", encoding="utf-8") as ds:
        for name in names:
            print("== %s" % name, flush=True)
            row = run_one(name, client, a.attempts, not a.skip_scan, tmp)
            rows.append(row)
            ds.write(json.dumps(row, ensure_ascii=False) + "\n")
            ds.flush()
            print("   -> %s %s (%.1fs)" % (row.get("verdict") or row.get("skipped") or "?",
                                           (row.get("reason") or row.get("compatibility") or "")[:90],
                                           row.get("elapsed_s", 0)), flush=True)
    ok = sum(1 for r in rows if r.get("verdict") == "ok")
    compat = sum(1 for r in rows if r.get("verdict") == "compatibility_failed")
    summary = {"packages": len(rows), "ok": ok, "compatibility_failed": compat,
               "skipped_or_error": sum(1 for r in rows if r.get("verdict") not in ("ok", "compatibility_failed")),
               "rows": rows}
    io.open(SUMMARY, "w", encoding="utf-8", newline="\n").write(json.dumps(summary, ensure_ascii=False, indent=1))
    print("summary: %s" % json.dumps({k: v for k, v in summary.items() if k != "rows"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
