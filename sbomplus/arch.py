"""Legacy / architecture analysis of a source tree (read-only, deterministic, no code execution).

  stack       languages, files, LOC (extension based)
  hotspots    change frequency x complexity proxy (git history; shallow clones are flagged)
  coupling    files that change together without an import edge between them = hidden dependencies
  graph       internal import graph per language (py/js/ts/java/go/c/cpp/rust), strongly connected components
              (cycles), layering (longest path on the condensation), fan-in/fan-out, instability
  clusters    directory based domain candidates with cohesion; high-cohesion/low-inbound ones = extraction candidates
  runtime_eol runtime/toolchain versions found in manifests vs end-of-life data (online when allowed)
Honesty: every analysis that cannot run (no .git, unsupported language) is recorded in ``notes``; nothing is guessed.
"""
from __future__ import annotations

import ast
import os
import re
from collections import Counter, defaultdict
from datetime import date
from typing import Any, Dict, List, Optional, Set, Tuple

from . import net, workspace
from .util import read_text

_SKIP = {".git", "node_modules", "vendor", "dist", "build", "target", "__pycache__", ".venv", "venv", "third_party",
         "thirdparty", "external", "deps", ".tox", "site-packages", "bower_components"}
_LANG = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
         ".java": "java", ".kt": "kotlin", ".go": "go", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp",
         ".hpp": "cpp", ".cxx": "cpp", ".rs": "rust", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".swift": "swift",
         ".scala": "scala"}
_GRAPH_LANGS = {"python", "javascript", "typescript", "java", "go", "c", "cpp", "rust", "ruby"}
_DECISION = re.compile(r"\b(?:if|for|while|case|catch|except|elif|when|match)\b|&&|\|\||\?\s*[^:\s]")


# ------------------------------------------------------------------ inventory
def collect_files(root: str, max_files: int = 4000) -> List[str]:
    out: List[str] = []
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in _SKIP and not d.startswith("."))
        for fn in sorted(fns):
            if os.path.splitext(fn)[1].lower() in _LANG:
                out.append(os.path.relpath(os.path.join(dp, fn), root).replace("\\", "/"))
                if len(out) >= max_files:
                    return out
    return out


def stack(root: str, files: List[str]) -> Dict[str, Any]:
    loc: Counter = Counter()
    nfiles: Counter = Counter()
    cplx: Dict[str, int] = {}
    size: Dict[str, int] = {}
    for rel in files:
        lang = _LANG[os.path.splitext(rel)[1].lower()]
        txt = read_text(os.path.join(root, rel), 400_000)
        n = txt.count("\n") + 1
        loc[lang] += n
        nfiles[lang] += 1
        size[rel] = n
        cplx[rel] = 1 + len(_DECISION.findall(txt))
    return {"languages": {k: {"files": nfiles[k], "loc": loc[k]} for k, _ in loc.most_common()},
            "files": len(files), "loc": sum(loc.values()), "_cplx": cplx, "_size": size}


# ------------------------------------------------------------------ git history
def _git_history(root: str, max_commits: int) -> Tuple[List[Tuple[str, List[Tuple[str, int]]]], Dict[str, Any]]:
    if not os.path.isdir(os.path.join(root, ".git")):
        return [], {"error": "no .git directory"}
    rc, out, err = workspace.git(root, "log", "-n", str(max_commits), "--no-merges", "--numstat", "--format=@@%H",
                                 timeout=240)
    if rc != 0:
        return [], {"error": err.strip()[-120:] or "git log failed"}
    commits: List[Tuple[str, List[Tuple[str, int]]]] = []
    cur: Optional[List[Tuple[str, int]]] = None
    sha = ""
    for line in out.splitlines():
        if line.startswith("@@"):
            if cur is not None:
                commits.append((sha, cur))
            sha, cur = line[2:], []
        elif line.strip() and cur is not None:
            parts = line.split("\t")
            if len(parts) == 3:
                a, d, f = parts
                ch = (int(a) if a.isdigit() else 0) + (int(d) if d.isdigit() else 0)
                cur.append((f.replace("\\", "/"), ch))
    if cur is not None:
        commits.append((sha, cur))
    rc2, shallow, _ = workspace.git(root, "rev-parse", "--is-shallow-repository")
    return commits, {"commits": len(commits), "shallow": shallow.strip() == "true"}


def _pct_rank(vals: Dict[str, float]) -> Dict[str, float]:
    order = sorted(vals, key=lambda k: vals[k])
    n = max(1, len(order) - 1)
    return {k: i / n for i, k in enumerate(order)}


def hotspots(commits, st: Dict[str, Any], top: int = 10) -> List[Dict[str, Any]]:
    freq: Counter = Counter()
    churn: Counter = Counter()
    for _, files in commits:
        for f, ch in files:
            if f in st["_cplx"]:
                freq[f] += 1
                churn[f] += ch
    if not freq:
        return []
    rf = _pct_rank({f: freq[f] for f in freq})
    rc = _pct_rank({f: st["_cplx"][f] * (1 + st["_size"][f] / 400) for f in freq})
    rows = [{"file": f, "commits": freq[f], "churn": churn[f], "loc": st["_size"][f], "complexity": st["_cplx"][f],
             "score": round(100 * rf[f] * rc[f], 1)} for f in freq]
    rows.sort(key=lambda r: (-r["score"], -r["commits"], r["file"]))
    return rows[:top]


def coupling(commits, st: Dict[str, Any], edges: Set[Tuple[str, str]], min_shared: int = 3, top: int = 10) -> Dict[str, Any]:
    cnt: Counter = Counter()
    pair: Counter = Counter()
    for _, files in commits:
        fs = sorted({f for f, _ in files if f in st["_cplx"]})
        if not 2 <= len(fs) <= 30:
            continue
        for f in fs:
            cnt[f] += 1
        for i in range(len(fs)):
            for j in range(i + 1, len(fs)):
                pair[(fs[i], fs[j])] += 1
    rows = []
    for (a, b), s in pair.items():
        if s < min_shared:
            continue
        jac = s / (cnt[a] + cnt[b] - s)
        if jac >= 0.3:
            rows.append({"a": a, "b": b, "shared": s, "jaccard": round(jac, 2),
                         "hidden": (a, b) not in edges and (b, a) not in edges})
    rows.sort(key=lambda r: (-r["jaccard"], -r["shared"], r["a"]))
    return {"pairs": rows[:top], "hidden_dependencies": sum(1 for r in rows if r["hidden"]), "pairs_total": len(rows)}


# ------------------------------------------------------------------ import graph
def _py_edges(root: str, files: List[str]) -> Set[Tuple[str, str]]:
    pyf = [f for f in files if f.endswith(".py")]
    dotted: Dict[str, str] = {}
    for f in pyf:
        d = f[:-3].replace("/", ".")
        if d.endswith(".__init__"):
            d = d[: -len(".__init__")]
        dotted[d] = f

    def find(cand: str) -> Optional[str]:
        if cand in dotted:
            return dotted[cand]
        hits = [v for k, v in dotted.items() if k.endswith("." + cand)]
        return hits[0] if len(hits) == 1 else None

    edges: Set[Tuple[str, str]] = set()
    for f in pyf:
        try:
            tree = ast.parse(read_text(os.path.join(root, f), 600_000))
        except (SyntaxError, ValueError, MemoryError, RecursionError):
            continue
        pkg = f[:-3].replace("/", ".").rsplit(".", 1)[0] if "/" in f else ""
        for n in ast.walk(tree):
            cands: List[str] = []
            if isinstance(n, ast.Import):
                cands = [a.name for a in n.names]
            elif isinstance(n, ast.ImportFrom):
                base = n.module or ""
                if n.level:
                    parts = pkg.split(".") if pkg else []
                    parts = parts[: max(0, len(parts) - (n.level - 1))]
                    base = ".".join(parts + ([base] if base else []))
                cands = [base] + [base + "." + a.name for a in n.names if a.name != "*"]
            for c in cands:
                t = find(c) if c else None
                if t and t != f:
                    edges.add((f, t))
    return edges


def _js_edges(root: str, files: List[str]) -> Set[Tuple[str, str]]:
    jsf = [f for f in files if _LANG[os.path.splitext(f)[1].lower()] in ("javascript", "typescript")]
    fset = set(jsf)
    rx = re.compile(r"""(?:from\s+|require\(\s*|import\(\s*|import\s+)['"](\.{1,2}/[^'"]*)['"]""")
    edges: Set[Tuple[str, str]] = set()
    for f in jsf:
        base = os.path.dirname(f)
        for m in rx.finditer(read_text(os.path.join(root, f), 400_000)):
            p = os.path.normpath(os.path.join(base, m.group(1))).replace("\\", "/")
            for cand in [p] + [p + e for e in (".js", ".ts", ".jsx", ".tsx")] + [p + "/index" + e for e in (".js", ".ts", ".tsx")]:
                if cand in fset and cand != f:
                    edges.add((f, cand))
                    break
    return edges


def _java_edges(root: str, files: List[str]) -> Set[Tuple[str, str]]:
    jf = [f for f in files if f.endswith((".java", ".kt", ".scala"))]
    by_suffix: Dict[str, str] = {}
    for f in jf:
        by_suffix[os.path.splitext(f)[0].replace("/", ".")] = f
    rx = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+?)(?:\.\*)?\s*;?\s*$", re.M)
    edges: Set[Tuple[str, str]] = set()
    for f in jf:
        for m in rx.finditer(read_text(os.path.join(root, f), 300_000)):
            name = m.group(1)
            hit = next((v for k, v in by_suffix.items() if k.endswith("." + name) or k == name), None)
            if hit is None and "." in name:
                hit = next((v for k, v in by_suffix.items() if k.endswith("." + name.rsplit(".", 1)[0])), None)
            if hit and hit != f:
                edges.add((f, hit))
    return edges


def _go_edges(root: str, files: List[str]) -> Set[Tuple[str, str]]:
    gf = [f for f in files if f.endswith(".go")]
    mod = ""
    for m in re.finditer(r"^module\s+(\S+)", read_text(os.path.join(root, "go.mod"), 20000), re.M):
        mod = m.group(1)
    if not mod:
        return set()
    dirs = {os.path.dirname(f) or "." for f in gf}
    edges: Set[Tuple[str, str]] = set()
    rx = re.compile(r'"(%s[^"]*)"' % re.escape(mod))
    for f in gf:
        src = os.path.dirname(f) or "."
        for m in rx.finditer(read_text(os.path.join(root, f), 300_000)):
            d = m.group(1)[len(mod):].lstrip("/") or "."
            if d in dirs and d != src:
                edges.add((src + "/", d + "/"))
    return edges


def _c_edges(root: str, files: List[str]) -> Set[Tuple[str, str]]:
    cf = [f for f in files if _LANG[os.path.splitext(f)[1].lower()] in ("c", "cpp")]
    fset = set(cf)
    by_base: Dict[str, List[str]] = defaultdict(list)
    for f in cf:
        by_base[os.path.basename(f)].append(f)
    rx = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.M)
    edges: Set[Tuple[str, str]] = set()
    for f in cf:
        for m in rx.finditer(read_text(os.path.join(root, f), 300_000)):
            inc = m.group(1)
            local = os.path.normpath(os.path.join(os.path.dirname(f), inc)).replace("\\", "/")
            cand = local if local in fset else (by_base.get(os.path.basename(inc)) or [None])[0] \
                if len(by_base.get(os.path.basename(inc), [])) == 1 else None
            if cand and cand != f:
                edges.add((f, cand))
    return edges


def _rust_edges(root: str, files: List[str]) -> Set[Tuple[str, str]]:
    rf = [f for f in files if f.endswith(".rs")]
    fset = set(rf)
    edges: Set[Tuple[str, str]] = set()
    rx = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", re.M)
    for f in rf:
        d = os.path.dirname(f)
        stem = os.path.splitext(os.path.basename(f))[0]
        base = d if stem in ("mod", "lib", "main") else (d + "/" + stem if d else stem)
        for m in rx.finditer(read_text(os.path.join(root, f), 300_000)):
            for cand in ((base + "/" if base else "") + m.group(1) + ".rs", (base + "/" if base else "") + m.group(1) + "/mod.rs"):
                if cand in fset and cand != f:
                    edges.add((f, cand))
                    break
    return edges


def _ruby_edges(root: str, files: List[str]) -> Set[Tuple[str, str]]:
    """require_relative + require of project files. Rails autoloaded constants are NOT resolved (reported as partial)."""
    rf = [f for f in files if f.endswith(".rb")]
    fset = set(rf)
    rx_rel = re.compile(r"^\s*require_relative\s+['\"]([^'\"]+)['\"]", re.M)
    rx_req = re.compile(r"^\s*require\s+['\"]([^'\"]+)['\"]", re.M)
    edges: Set[Tuple[str, str]] = set()
    for f in rf:
        txt = read_text(os.path.join(root, f), 300_000)
        for m in rx_rel.finditer(txt):
            p = os.path.normpath(os.path.join(os.path.dirname(f), m.group(1))).replace("\\", "/")
            p = p if p.endswith(".rb") else p + ".rb"
            if p in fset and p != f:
                edges.add((f, p))
        for m in rx_req.finditer(txt):
            name = m.group(1) if m.group(1).endswith(".rb") else m.group(1) + ".rb"
            hits = [g for g in rf if g == name or g.endswith("/" + name)]
            if len(hits) == 1 and hits[0] != f:
                edges.add((f, hits[0]))
    return edges


def import_graph(root: str, files: List[str]) -> Tuple[Set[Tuple[str, str]], Dict[str, Any]]:
    present = {_LANG[os.path.splitext(f)[1].lower()] for f in files}
    edges: Set[Tuple[str, str]] = set()
    for lang, fn in (("python", _py_edges), ("javascript", _js_edges), ("typescript", _js_edges), ("java", _java_edges),
                     ("kotlin", _java_edges), ("go", _go_edges), ("c", _c_edges), ("cpp", _c_edges), ("rust", _rust_edges), ("ruby", _ruby_edges)):
        if lang in present:
            edges |= fn(root, files)
    nodes: Set[str] = {a for a, _ in edges} | {b for _, b in edges}
    return edges, {"languages_analysed": sorted(present & _GRAPH_LANGS),
                   "languages_without_import_analysis": sorted(present - _GRAPH_LANGS), "nodes": len(nodes)}


def sccs(nodes: Set[str], edges: Set[Tuple[str, str]]) -> List[List[str]]:
    """Tarjan strongly connected components (iterative)."""
    adj: Dict[str, List[str]] = defaultdict(list)
    for a, b in edges:
        adj[a].append(b)
    idx: Dict[str, int] = {}
    low: Dict[str, int] = {}
    onst: Set[str] = set()
    stk: List[str] = []
    out: List[List[str]] = []
    n = 0
    for s in sorted(nodes):
        if s in idx:
            continue
        work = [(s, 0)]
        while work:
            v, i = work.pop()
            if i == 0:
                idx[v] = low[v] = n
                n += 1
                stk.append(v)
                onst.add(v)
            nbrs = adj.get(v, [])
            if i < len(nbrs):
                work.append((v, i + 1))
                w = nbrs[i]
                if w not in idx:
                    work.append((w, 0))
                elif w in onst:
                    low[v] = min(low[v], idx[w])
            else:
                if work:
                    pv = work[-1][0]
                    low[pv] = min(low[pv], low[v])
                if low[v] == idx[v]:
                    comp = []
                    while True:
                        w = stk.pop()
                        onst.discard(w)
                        comp.append(w)
                        if w == v:
                            break
                    out.append(sorted(comp))
    return out


def graph_metrics(edges: Set[Tuple[str, str]], files: List[str]) -> Dict[str, Any]:
    nodes = {a for a, _ in edges} | {b for _, b in edges}
    if not nodes:
        return {"modules": len(files), "import_edges": 0}
    comps = sccs(nodes, edges)
    cyc = sorted([c for c in comps if len(c) > 1], key=lambda c: (-len(c), c[0]))
    where = {m: i for i, c in enumerate(comps) for m in c}
    dag: Dict[int, Set[int]] = defaultdict(set)
    for a, b in edges:
        if where[a] != where[b]:
            dag[where[a]].add(where[b])
    memo: Dict[int, int] = {}

    def depth(u: int) -> int:                       # layer = longest dependency chain below the node
        if u in memo:
            return memo[u]
        memo[u] = 0
        memo[u] = 1 + max((depth(v) for v in dag.get(u, ())), default=-1)
        return memo[u]

    fan_in: Counter = Counter(b for _, b in edges)
    fan_out: Counter = Counter(a for a, _ in edges)
    layers: Counter = Counter(depth(where[m]) for m in nodes)
    inst = {m: fan_out[m] / (fan_in[m] + fan_out[m]) for m in nodes}
    return {"modules": len(files), "nodes_in_graph": len(nodes), "import_edges": len(edges),
            "cycles": [c[:8] for c in cyc[:8]], "cycle_count": len(cyc),
            "modules_in_cycles": sum(len(c) for c in cyc), "tangle_ratio": round(sum(len(c) for c in cyc) / len(nodes), 3),
            "layers": dict(sorted(layers.items())), "max_depth": max(layers) if layers else 0,
            "fan_in_top": fan_in.most_common(5), "fan_out_top": fan_out.most_common(5),
            "unstable_hubs": sorted(((m, round(inst[m], 2)) for m in nodes if fan_in[m] >= 5 and inst[m] > 0.5),
                                    key=lambda t: -t[1])[:5]}


def clusters(edges: Set[Tuple[str, str]], files: List[str], depth: int = 2) -> List[Dict[str, Any]]:
    def dom(f: str) -> str:
        parts = f.strip("/").split("/")
        return "/".join(parts[:depth]) if len(parts) > depth else ("/".join(parts[:-1]) or ".")

    mods: Dict[str, Set[str]] = defaultdict(set)
    for f in files:
        mods[dom(f)].add(f)
    inner: Counter = Counter()
    out_e: Counter = Counter()
    in_e: Counter = Counter()
    for a, b in edges:
        da, db = dom(a), dom(b)
        if da == db:
            inner[da] += 1
        else:
            out_e[da] += 1
            in_e[db] += 1
    rows = []
    for d, ms in mods.items():
        tot = inner[d] + out_e[d] + in_e[d]
        coh = round(inner[d] / tot, 2) if tot else None
        rows.append({"domain": d, "modules": len(ms), "internal_edges": inner[d], "outbound": out_e[d], "inbound": in_e[d],
                     "cohesion": coh,
                     "extraction_candidate": bool(coh is not None and coh >= 0.6 and len(ms) >= 3 and in_e[d] <= max(2, len(ms) // 3))})
    rows.sort(key=lambda r: (-r["modules"], r["domain"]))
    return rows[:20]


# ------------------------------------------------------------------ runtime EOL
_EOL_STATIC = {   # embedded fallback, UNVERIFIED: cycle -> EOL date (ISO). Prefer the online data (endoflife.date).
    "python": {"3.6": "2021-12-23", "3.7": "2023-06-27", "3.8": "2024-10-07", "3.9": "2025-10-31", "3.10": "2026-10-31",
               "3.11": "2027-10-31", "3.12": "2028-10-31", "2.7": "2020-01-01"},
    "nodejs": {"10": "2021-04-30", "12": "2022-04-30", "14": "2023-04-30", "16": "2023-09-11", "18": "2025-04-30",
               "20": "2026-04-30", "22": "2027-04-30"},
    "go": {},
    "php": {"7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31", "8.3": "2027-12-31"},
    "ruby": {"2.7": "2023-03-31", "3.0": "2024-04-23", "3.1": "2025-03-31", "3.2": "2026-03-31", "3.3": "2027-03-31"},
    "dotnet": {"3.1": "2022-12-13", "5.0": "2022-05-10", "6.0": "2024-11-12", "7.0": "2024-05-14", "8.0": "2026-11-10"},
}
_EOL_CACHE: Dict[str, Any] = {}


def eol_lookup(product: str, cycle: str, online: bool) -> Dict[str, Any]:
    """{status: eol|supported|unknown, eol_date, source}"""
    today = date.today().isoformat()
    if online:
        if product not in _EOL_CACHE:
            _EOL_CACHE[product] = net.http_json("https://endoflife.date/api/%s.json" % product, timeout=15)
        for row in _EOL_CACHE[product] or []:
            if str(row.get("cycle")) == cycle:
                e = row.get("eol")
                if e is False:
                    return {"status": "supported", "eol_date": None, "source": "endoflife.date"}
                if isinstance(e, str):
                    return {"status": "eol" if e <= today else "supported", "eol_date": e, "source": "endoflife.date"}
    e = _EOL_STATIC.get(product, {}).get(cycle)
    if e:
        return {"status": "eol" if e <= today else "supported", "eol_date": e, "source": "embedded-table (UNVERIFIED)"}
    return {"status": "unknown", "eol_date": None, "source": "none"}


def runtimes(root: str, online: bool) -> List[Dict[str, Any]]:
    found: List[Tuple[str, str, str]] = []

    def add(prod: str, ver: str, src: str) -> None:
        m = re.match(r"^v?(\d+)(?:\.(\d+))?", str(ver).strip())
        if m:
            cyc = "%s.%s" % (m.group(1), m.group(2)) if prod in ("python", "php", "ruby", "dotnet", "go") and m.group(2) else m.group(1)
            if (prod, cyc, src) not in found:
                found.append((prod, cyc, src))

    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in _SKIP]
        if os.path.relpath(dp, root).count(os.sep) > 2:
            continue
        for fn in fns:
            low = fn.lower()
            fp = os.path.join(dp, fn)
            rel = os.path.relpath(fp, root).replace("\\", "/")
            if low in (".python-version", "runtime.txt"):
                add("python", read_text(fp, 200).replace("python-", "").strip(), rel)
            elif low == ".nvmrc":
                add("nodejs", read_text(fp, 100).replace("v", "").strip(), rel)
            elif low == "go.mod":
                m = re.search(r"^go\s+(\d+\.\d+)", read_text(fp, 20000), re.M)
                if m:
                    add("go", m.group(1), rel)
            elif low == "package.json":
                m = re.search(r'"node"\s*:\s*"[^"\d]*(\d+)', read_text(fp, 50000))
                if m:
                    add("nodejs", m.group(1), rel)
            elif low in ("pyproject.toml", "setup.py", "setup.cfg"):
                m = re.search(r"python_requires\s*[=:]\s*[\"']?[><=~!^ ]*(\d+\.\d+)", read_text(fp, 50000)) or \
                    re.search(r"requires-python\s*=\s*[\"'][><=~!^ ]*(\d+\.\d+)", read_text(fp, 50000))
                if m:
                    add("python", m.group(1), rel)
            elif low.startswith("dockerfile") or low.endswith(".dockerfile"):
                for img, ver in re.findall(r"^\s*FROM\s+(?:[\w./-]+/)?(python|node|golang|php|ruby)[:@]v?(\d+(?:\.\d+)?)",
                                           read_text(fp, 20000), re.M | re.I):
                    add({"golang": "go", "node": "nodejs"}.get(img.lower(), img.lower()), ver, rel)
            elif low == "composer.json":
                m = re.search(r'"php"\s*:\s*"[^"\d]*(\d+\.\d+)', read_text(fp, 50000))
                if m:
                    add("php", m.group(1), rel)
    rows = []
    for prod, cyc, src in found[:20]:
        rows.append(dict(product=prod, cycle=cyc, declared_in=src, **eol_lookup(prod, cyc, online)))
    return rows


# ------------------------------------------------------------------ entry point
def analyze(root: str, *, online: bool = False, max_commits: int = 400, max_files: int = 4000) -> Dict[str, Any]:
    notes: List[str] = []
    files = collect_files(root, max_files)
    if len(files) >= max_files:
        notes.append("file list capped at %d" % max_files)
    st = stack(root, files)
    edges, ginfo = import_graph(root, files)
    gm = graph_metrics(edges, files)
    commits, hinfo = _git_history(root, max_commits)
    out: Dict[str, Any] = {"stack": {k: v for k, v in st.items() if not k.startswith("_")}, "graph": dict(gm, **ginfo),
                           "clusters": clusters(edges, files), "history": hinfo, "notes": notes}
    if commits:
        out["hotspots"] = hotspots(commits, st)
        out["coupling"] = coupling(commits, st, edges)
        if hinfo.get("shallow"):
            notes.append("shallow clone: hotspots/coupling use only the last %d commits" % hinfo["commits"])
    else:
        notes.append("hotspots/coupling skipped: %s" % hinfo.get("error", "no history"))
        out["hotspots"], out["coupling"] = [], {"pairs": [], "hidden_dependencies": 0, "pairs_total": 0}
    if not edges:
        notes.append("no internal import edges resolved (unsupported language or flat layout) - graph metrics are empty, not zero-risk")
    if any(f.endswith(".rb") for f in files):
        notes.append("ruby: only require/require_relative edges are resolved; Rails autoloaded constants are not (graph is partial)")
    out["runtime_eol"] = runtimes(root, online)
    out["modernization"] = modernization(out)
    return out


def modernization(a: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Deterministic modernization candidates derived from the measurements above (each cites its evidence)."""
    props: List[Dict[str, Any]] = []
    for r in a.get("runtime_eol") or []:
        if r["status"] == "eol":
            props.append({"kind": "upgrade_runtime", "priority": "high", "target": "%s %s" % (r["product"], r["cycle"]),
                          "why": "end-of-life since %s (%s) declared in %s" % (r["eol_date"], r["source"], r["declared_in"])})
    g = a.get("graph") or {}
    for c in (g.get("cycles") or [])[:3]:
        props.append({"kind": "break_cycle", "priority": "medium", "target": ", ".join(c[:4]),
                      "why": "%d modules form a dependency cycle - blocks independent change and strangler extraction" % len(c)})
    for h in (a.get("hotspots") or [])[:3]:
        if h["score"] >= 50:
            props.append({"kind": "refactor_hotspot", "priority": "medium", "target": h["file"],
                          "why": "changed in %d commits, %d LOC, complexity %d (hotspot score %s)" % (h["commits"], h["loc"], h["complexity"], h["score"])})
    for p in ((a.get("coupling") or {}).get("pairs") or [])[:3]:
        if p["hidden"]:
            props.append({"kind": "make_dependency_explicit", "priority": "low", "target": "%s <-> %s" % (p["a"], p["b"]),
                          "why": "co-changed %d times (jaccard %s) with no import between them" % (p["shared"], p["jaccard"])})
    for c in a.get("clusters") or []:
        if c.get("extraction_candidate"):
            props.append({"kind": "extraction_candidate", "priority": "low", "target": c["domain"],
                          "why": "cohesion %s, %d modules, only %d inbound edges" % (c["cohesion"], c["modules"], c["inbound"])})
    return props[:12]
