"""REA adapter: an OPTIONAL external reverse-engineering tool used as the reader-side analysis of a legacy artefact
when a component has to be rewritten (EOL / incompatible / cannot be patched / copyleft).

What REA is (studied from https://github.com/morluto/rea, MIT): a Node.js CLI + MCP server ("rea-agents" on npm) that
inspects a target locally - JavaScript/Electron apps and ASARs without any native engine, native binaries through
Hopper/Ghidra/IDA/Kuna, .NET assemblies, Android APKs, firmware - and returns an Evidence record with the observed
facts, their limitations and coverage. It is not a Python library, so it cannot be vendored into a stdlib-only app;
it is invoked as a subprocess when (and only when) it is installed. Nothing here downloads or installs it.

Where it sits (SBOM -> rewrite): the clean-room lane (``reimpl.py``) reads a legacy component, writes a spec and has a
generator write NEW code behind a copy gate. REA's output is READER-SIDE material. It enters the spec only through
``extract_facts()``, a fail-closed allow-list:

  * only a recognised structure is read (the documented ``JavaScriptApplicationGraph``); ``raw_result`` - where a provider
    puts decompiled/original text - is never traversed;
  * only identifier/path/URL-shaped strings survive (no whitespace, quotes, brackets or operators), length- and
    count-capped, so a statement or a function body cannot ride along as a "fact";
  * everything REA could not establish (coverage, limitations) is carried as an explicit Unknowns block so the
    generator is told not to guess.

The facts are never an operand of the copy gate (that stays generated code vs original source). Honest states: an
absent tool is ``absent``, an artefact REA does not cover is ``not_applicable``, a run that failed or returned an
unrecognised shape is ``failed`` / ``unrecognised_shape`` - none of them is ever reported as an analysis that passed.
Use REA only on software you own or are authorised to examine (REA's own DISCLAIMER.md says the same).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "bts-sbom.rea.facts.v1"
UPSTREAM = {"repo": "https://github.com/morluto/rea", "package": "rea-agents", "licence": "MIT",
            "docs": "https://rea.tools/"}
ENV_CMD = "BTS_REA_CMD"                    # a path to the executable, or a JSON array of argv words
DETECT_TIMEOUT = 25
ANALYZE_TIMEOUT = 600
MAX_EVIDENCE_BYTES = 96 * 1024 * 1024       # larger Evidence is refused (too_large), never silently truncated
JS_COMMAND = "analyze-javascript-application"   # the documented static provider: no native engine needed

# the documented node vocabulary of REA's JavaScript Application Graph, grouped by what a rewrite needs from it
_MODULE_KINDS = ("javascript-module", "javascript-asset", "javascript-chunk", "electron-main", "electron-preload",
                 "electron-renderer", "electron-utility", "source-module")
_BOUNDARY_KINDS = ("ipc-channel", "ipc-handler", "context-bridge-api", "url-scheme", "native-addon", "native-export",
                   "storage", "worker", "service-worker")
_KNOWN_KINDS = set(_MODULE_KINDS) | set(_BOUNDARY_KINDS) | {"package", "installer", "artifact", "asar-entry", "endpoint",
                                                              "browser-window", "frame", "target", "source-map",
                                                              "javascript-expression", "unknown"}
_COVERAGE = ("complete", "partial", "unknown", "unavailable")

_NAME = re.compile(r"^[A-Za-z0-9_@./:$#\-]{1,120}$")          # identifier / path / channel / URL-shaped, nothing else
_PROSE = re.compile(r"^[A-Za-z0-9 ,.;:()'/_\-]{3,200}$")        # REA-authored limitation sentences (bounded charset)
CAPS = {"modules": 60, "imports": 40, "boundaries": 40, "endpoints": 30, "limitations": 12}
_ENV_KEEP = ("PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR", "HOME",
             "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES", "PROGRAMDATA", "LANG", "LC_ALL", "NO_COLOR")
_SHELL_META = set('&|<>^%"!`\n\r')


# ------------------------------------------------------------------ detection (never installs anything)


def _argv_from_env(raw: str) -> Optional[List[str]]:
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith("["):
        try:
            words = json.loads(raw)
        except ValueError:
            return None
        return [str(w) for w in words] if isinstance(words, list) and words and all(isinstance(w, str) for w in words) else None
    return [raw]


def _run_capture(argv: List[str], timeout: int, env: Dict[str, str]) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
                           cwd=tempfile.gettempdir(), env=env, shell=False)
    except subprocess.TimeoutExpired:
        return -9, "", "timed out after %ds" % timeout
    except OSError as exc:
        return -1, "", str(exc)
    return p.returncode, p.stdout or "", p.stderr or ""


def _clean_env(environ: Dict[str, str]) -> Dict[str, str]:
    """REA is told only what it needs (PATH, temp, home, REA_*/NODE_* settings) - the app's own environment (LLM keys,
    tokens) is not handed to a third-party process."""
    keep = {k: v for k, v in environ.items() if k.upper() in _ENV_KEEP or k.upper().startswith(("REA_", "NODE_", "NPM_CONFIG_"))}
    keep.setdefault("NO_COLOR", "1")
    return keep


def detect(environ: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """{state: available|absent|unsupported_runtime|error, command, version, reason}. ``absent`` is the honest default."""
    environ = dict(os.environ) if environ is None else dict(environ)
    explicit = environ.get(ENV_CMD, "")
    argv = _argv_from_env(explicit)
    if explicit.strip() and argv is None:
        return {"state": "error", "command": None, "version": None,
                "reason": "%s must be an executable path or a JSON array of words" % ENV_CMD, "upstream": UPSTREAM}
    if argv is None:
        found = shutil.which("rea", path=environ.get("PATH"))
        if not found:
            return {"state": "absent", "command": None, "version": None, "upstream": UPSTREAM,
                    "reason": "the rea CLI is not installed (npm install --global rea-agents, or set %s); nothing was analysed" % ENV_CMD}
        argv = [found]
    else:
        head = shutil.which(argv[0], path=environ.get("PATH")) or (argv[0] if os.path.isfile(argv[0]) else None)
        if not head:
            return {"state": "absent", "command": None, "version": None, "upstream": UPSTREAM,
                    "reason": "%s points at %r which is not an executable" % (ENV_CMD, argv[0])}
        argv = [head] + argv[1:]
    rc, out, err = _run_capture(argv + ["--version", "--json"], DETECT_TIMEOUT, _clean_env(environ))
    try:
        info = json.loads(out)
    except ValueError:
        info = None
    if rc != 0 or not isinstance(info, dict):
        return {"state": "error", "command": argv, "version": None, "upstream": UPSTREAM,
                "reason": "rea --version --json failed (exit %s): %s" % (rc, (err or out).strip()[:160])}
    sup = info.get("supported_runtime") if isinstance(info.get("supported_runtime"), dict) else {}
    runtime = info.get("runtime") if isinstance(info.get("runtime"), dict) else {}
    res = {"state": "available", "command": argv, "version": str(info.get("version") or "")[:40], "upstream": UPSTREAM,
           "runtime": "%s %s" % (runtime.get("id", "?"), runtime.get("version", "?")), "reason": ""}
    if sup.get("satisfied") is False:
        res.update(state="unsupported_runtime", reason="the Node.js runtime is outside rea's supported range %s" % str(sup.get("range"))[:60])
    return res


_DETECT_CACHE: Dict[str, Any] = {"at": 0.0, "value": None}


def detect_cached(ttl: float = 30.0) -> Dict[str, Any]:
    """detect() spawns a process; the UI polls it, so the answer is reused for ``ttl`` seconds."""
    now = time.monotonic()
    if _DETECT_CACHE["value"] is None or now - _DETECT_CACHE["at"] > ttl:
        _DETECT_CACHE.update(at=now, value=detect())
    return _DETECT_CACHE["value"]


# ------------------------------------------------------------------ applicability


def applicable(target: str) -> Tuple[Optional[str], str]:
    """(kind, reason). Only the static JavaScript/Electron provider is wired: it needs no native analysis engine.
    Native / .NET / Android targets need a configured provider and produce no recognised facts here, so they are
    reported as not applicable instead of being run for nothing."""
    if not target or not os.path.exists(target):
        return None, "the analysis target does not exist"
    if os.path.isfile(target):
        if target.lower().endswith(".asar"):
            return "javascript", "ASAR archive"
        return None, "a single file is not a JavaScript/Electron application directory or ASAR (native/.NET/Android targets need a configured rea provider and are not wired in this version)"
    seen = 0
    for dp, dns, fns in os.walk(target):
        dns[:] = [d for d in dns if d not in (".git", "__pycache__")]
        for fn in fns:
            seen += 1
            if fn == "package.json" or fn.lower().endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".asar")):
                return "javascript", "JavaScript sources found (%s)" % os.path.relpath(os.path.join(dp, fn), target).replace("\\", "/")[:80]
            if seen > 4000:
                break
        if seen > 4000:
            break
    return None, "no JavaScript/Electron artefact under the target (rea's static provider covers JS/ASAR; a Python source is read by the lane's own ast reader)"


# ------------------------------------------------------------------ what the developer can run (documented commands)


def _magic(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return ""
    return "elf" if head == bytes.fromhex("7f454c46") else "pe" if head[:2] == b"MZ" else "macho" if head.hex() in ("cffaedfe", "feedfacf", "cafebabe") else ""


def playbook(target: str) -> List[Dict[str, Any]]:
    """The rea commands that fit this artefact - names taken from rea's CLI documentation, none of them executed by
    this function. ``wired`` marks the one command this tool runs itself (static JavaScript/Electron). Everything
    else is for the developer to run: that is how a developer gets the facts the lane cannot ingest."""
    p = os.path.abspath(target) if target else ""
    out: List[Dict[str, Any]] = []

    def add(cmd: str, gives: str, wired: bool = False) -> None:
        out.append({"command": "rea %s --json" % cmd.format(p=p), "gives": gives, "wired": wired})

    if not p or not os.path.exists(p):
        return out
    kind, _ = applicable(p)
    if kind == "javascript":
        add(JS_COMMAND + " {p}", "modules, imports, Electron boundaries (IPC, preload, contextBridge), endpoints, coverage and limitations", True)
    if os.path.isfile(p):
        low, magic = p.lower(), _magic(p)
        if low.endswith(".pyc"):
            add("inspect-python-pyc {p}", "Python bytecode module facts (version, names)")
        if low.endswith(".nupkg"):
            add("inspect-nuget-nupkg {p}", "package identity, dependency groups, licence, contents")
        if magic == "elf":
            add("inspect-elf-dependencies {p}", "DT_NEEDED, SONAME, undefined imports - the library surface the binary depends on")
            add("inspect-go-binary {p}", "embedded Go modules and build settings, when it is a Go binary")
            add("inspect-rust-binary {p}", "embedded cargo-auditable crates, when it is a Rust binary")
        if magic == "pe" or low.endswith((".dll", ".exe")):
            add("inspect-pe-imports {p}", "imported DLLs and functions")
            add("inspect-managed-members {p}", "types and methods, when it is a .NET assembly")
        if magic:
            add("analyze {p} --provider <hopper|ghidra|ida|kuna>", "pseudocode/assembly through a native engine you installed: READ IT YOURSELF - it is implementation text and must not be pasted into the spec")
    else:
        add("import-reference-source {p} --detail summary", "inventory of the source tree: languages, manifests, relationships (Linux/macOS hosts only)")
    return out


# ------------------------------------------------------------------ running it


def _kill_tree(proc: "subprocess.Popen[Any]") -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, timeout=15)
        else:
            proc.kill()
    except Exception:                                        # noqa: BLE001 - best effort; the caller already reports the timeout
        try:
            proc.kill()
        except Exception:                                    # noqa: BLE001
            pass


def run_analysis(det: Dict[str, Any], target: str, kind: str, *, environ: Optional[Dict[str, str]] = None,
                 timeout: int = ANALYZE_TIMEOUT) -> Dict[str, Any]:
    """Run REA once. Returns {state: ok|failed|timeout|too_large, evidence (parsed JSON or None), evidence_sha256,
    evidence_bytes, stderr_tail}. The Evidence goes through a temp file (it can be hundreds of MB) and is deleted."""
    argv = list(det["command"])
    target = os.path.abspath(target)
    if os.path.splitext(argv[0])[1].lower() in (".cmd", ".bat") and any(c in _SHELL_META for c in target):
        return {"state": "failed", "evidence": None, "stderr_tail": "target path holds shell metacharacters and rea is a .cmd shim"}
    argv += [JS_COMMAND, target, "--json"]
    tmp = tempfile.mkdtemp(prefix="bts_rea_")
    out_path, err_path = os.path.join(tmp, "evidence.json"), os.path.join(tmp, "stderr.txt")
    try:
        with open(out_path, "wb") as fo, open(err_path, "wb") as fe:
            try:
                proc = subprocess.Popen(argv, stdout=fo, stderr=fe, cwd=tmp, env=_clean_env(dict(os.environ if environ is None else environ)),
                                        shell=False)
            except OSError as exc:
                return {"state": "failed", "evidence": None, "stderr_tail": str(exc)[:200]}
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _kill_tree(proc)
                proc.wait()
                return {"state": "timeout", "evidence": None, "stderr_tail": "rea did not finish within %ds" % timeout}
        size = os.path.getsize(out_path)
        tail = _tail(err_path)
        if rc != 0:
            return {"state": "failed", "evidence": None, "stderr_tail": ("exit %s: %s" % (rc, tail))[:300]}
        if size > MAX_EVIDENCE_BYTES:
            return {"state": "too_large", "evidence": None, "evidence_bytes": size,
                    "stderr_tail": "the Evidence is %d bytes (limit %d); not read" % (size, MAX_EVIDENCE_BYTES)}
        h = hashlib.sha256()
        with open(out_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        try:
            with open(out_path, "r", encoding="utf-8") as fh:
                evidence = json.load(fh)
        except (ValueError, UnicodeError) as exc:
            return {"state": "failed", "evidence": None, "evidence_bytes": size, "stderr_tail": "stdout was not JSON: %s" % str(exc)[:120]}
        return {"state": "ok", "evidence": evidence, "evidence_sha256": h.hexdigest(), "evidence_bytes": size, "stderr_tail": tail}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _tail(path: str, n: int = 300) -> str:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - 4000))
            data = fh.read().decode("utf-8", "replace")
    except OSError:
        return ""
    lines = [ln for ln in data.splitlines() if ln.strip() and '"rea_progress"' not in ln]
    return " | ".join(lines)[-n:]


# ------------------------------------------------------------------ fact extraction (the allow-list)


def _find_graph(evidence: Any) -> Optional[Dict[str, Any]]:
    """The documented JavaScriptApplicationGraph, found by its schema tag anywhere in the Evidence - except under
    ``raw_result`` (a provider's own representation, which can hold original text): that key is never traversed."""
    stack: List[Tuple[Any, int]] = [(evidence, 0)]
    budget = 300000
    while stack and budget > 0:
        cur, depth = stack.pop()
        budget -= 1
        if isinstance(cur, dict):
            if cur.get("schema") == "JavaScriptApplicationGraph" and isinstance(cur.get("nodes"), list):
                return cur
            if depth < 9:
                stack.extend((v, depth + 1) for k, v in cur.items() if k != "raw_result" and isinstance(v, (dict, list)))
        elif isinstance(cur, list) and depth < 9:
            stack.extend((v, depth + 1) for v in cur if isinstance(v, (dict, list)))
    return None


def _label(node: Dict[str, Any]) -> Optional[str]:
    for ob in node.get("observations") or []:
        if isinstance(ob, dict) and isinstance(ob.get("label"), str):
            return ob["label"]
    return None


def _safe_name(s: Any) -> Optional[str]:
    return s if isinstance(s, str) and _NAME.match(s) else None


def _is_external(label: str) -> bool:
    return not label.startswith((".", "/")) and ":" not in label.split("/")[0]


def extract_facts(evidence: Any) -> Dict[str, Any]:
    """Evidence -> facts (``SCHEMA``), or {} when the structure is not the documented graph. Fail closed: anything
    that does not match the allow-list is dropped and counted, never passed through."""
    norm = evidence.get("normalized_result") if isinstance(evidence, dict) and isinstance(evidence.get("normalized_result"), dict) else evidence
    graph = _find_graph(norm)
    if graph is None:
        return {}
    nodes = [n for n in graph["nodes"] if isinstance(n, dict) and n.get("kind") in _KNOWN_KINDS]
    by_id = {n.get("node_id"): n for n in nodes if isinstance(n.get("node_id"), str)}
    dropped = {"unsafe_names": 0, "over_cap": 0, "unknown_kind_nodes": len(graph["nodes"]) - len(nodes)}

    def take(names: List[Optional[str]], cap: int) -> List[str]:
        good = sorted({x for x in names if x})
        dropped["unsafe_names"] += sum(1 for x in names if x is None)
        if len(good) > cap:
            dropped["over_cap"] += len(good) - cap
        return good[:cap]

    kinds: Dict[str, int] = {}
    for n in nodes:
        kinds[n["kind"]] = kinds.get(n["kind"], 0) + 1
    modules = take([_safe_name(_label(n)) if _label(n) else None for n in nodes if n["kind"] in _MODULE_KINDS and _label(n)], CAPS["modules"])
    imports: List[Optional[str]] = []
    for e in graph.get("edges") or []:
        if isinstance(e, dict) and e.get("relation") == "imports":
            tgt = by_id.get(e.get("target_node_id"))
            lab = _label(tgt) if tgt else None
            if lab:
                safe = _safe_name(lab)
                if safe is None or _is_external(safe):
                    imports.append(safe)
    boundaries: Dict[str, List[str]] = {}
    for kind in _BOUNDARY_KINDS:
        names = [_safe_name(_label(n)) for n in nodes if n["kind"] == kind and _label(n)]
        if names:
            boundaries[kind] = take(names, CAPS["boundaries"])
    endpoints = take([_safe_name(_label(n)) for n in nodes if n["kind"] == "endpoint" and _label(n)], CAPS["endpoints"])
    cov = graph.get("coverage")
    cov_status = cov.get("status") if isinstance(cov, dict) else cov
    limits = [re.sub(r"\s+", " ", x).strip() for x in graph.get("limitations") or [] if isinstance(x, str)]
    kept_limits = [x for x in limits if _PROSE.match(x)]
    dropped["unsafe_names"] += len(limits) - len(kept_limits)
    return {"schema": SCHEMA, "target_kind": "javascript", "coverage": cov_status if cov_status in _COVERAGE else "unknown",
            "counts": {"nodes": len(graph["nodes"]), "edges": len(graph.get("edges") or []), "by_kind": dict(sorted(kinds.items()))},
            "modules": modules, "imports": take(imports, CAPS["imports"]), "boundaries": boundaries, "endpoints": endpoints,
            "limitations": kept_limits[:CAPS["limitations"]], "dropped": dropped}


def evidence_id_of(evidence: Any) -> Optional[str]:
    for src in (evidence, (evidence or {}).get("structuredContent") if isinstance(evidence, dict) else None):
        if isinstance(src, dict) and isinstance(src.get("evidence_id"), str) and re.match(r"^ev_[0-9a-f]{8,64}$", src["evidence_id"]):
            return src["evidence_id"]
    return None


# ------------------------------------------------------------------ the spec channel


def facts_section(pack: Dict[str, Any]) -> str:
    """Spec text for an ``ok`` pack ('' otherwise). Names and relations only, plus the Unknowns block."""
    f = pack.get("facts") or {}
    if pack.get("state") != "ok" or not f:
        return ""
    tool = pack.get("tool") or {}
    out = ["## Recovered behaviour facts (REA static analysis of the legacy artefact)",
           "(reader-side analysis with rea %s: names and relations only - no implementation text, no decompiled code; "
           "they constrain the public surface and boundaries, they are not a design)" % (tool.get("version") or "?"),
           "- coverage: %s; %d node(s), %d relationship(s)" % (f.get("coverage"), (f.get("counts") or {}).get("nodes", 0),
                                                              (f.get("counts") or {}).get("edges", 0))]
    if f.get("modules"):
        out.append("- modules (%d): %s" % (len(f["modules"]), ", ".join(f["modules"])))
    if f.get("imports"):
        out.append("- imported dependencies (%d): %s" % (len(f["imports"]), ", ".join(f["imports"])))
    for kind, names in (f.get("boundaries") or {}).items():
        out.append("- %s (%d): %s" % (kind, len(names), ", ".join(names)))
    if f.get("endpoints"):
        out.append("- network endpoints (%d): %s" % (len(f["endpoints"]), ", ".join(f["endpoints"])))
    out += ["", "## Unknowns (do not guess)",
            "- REA establishes structure only: behaviour inside functions is NOT established by these facts - follow the contracts above."]
    if f.get("coverage") != "complete":
        out.append("- REA coverage is %s: a module, import or boundary missing from the lists above is unknown, not absent." % f.get("coverage"))
    for lim in f.get("limitations") or []:
        out.append("- REA limitation: %s" % lim)
    return "\n".join(out)


# ------------------------------------------------------------------ one call for the lane


def collect(target: str, *, environ: Optional[Dict[str, str]] = None, timeout: int = ANALYZE_TIMEOUT,
            detection: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The adapter's whole job for one artefact. Always returns a pack with an honest ``state``:
    ok | absent | unsupported_runtime | error | not_applicable | failed | timeout | too_large | unrecognised_shape."""
    det = detection if detection is not None else detect(environ)
    pack: Dict[str, Any] = {"schema": SCHEMA, "state": det["state"], "reason": det.get("reason") or "", "facts": None,
                            "target": os.path.abspath(target) if target else "",
                            "tool": {"name": "rea-agents", "version": det.get("version"), "runtime": det.get("runtime"),
                                     "repo": UPSTREAM["repo"], "licence": UPSTREAM["licence"]}}
    kind, why = applicable(target)
    if kind is None:
        pack.update(state="not_applicable", reason=why)                       # decided before the tool state: it explains why rea is idle
        return pack
    if det["state"] != "available":
        return pack
    run = run_analysis(det, target, kind, environ=environ, timeout=timeout)
    if run["state"] != "ok":
        pack.update(state=run["state"], reason=run.get("stderr_tail") or run["state"])
        return pack
    ev = run["evidence"]
    pack["evidence"] = {"sha256": run.get("evidence_sha256"), "bytes": run.get("evidence_bytes"), "evidence_id": evidence_id_of(ev),
                        "retained": False}
    facts = extract_facts(ev)
    if not facts:
        pack.update(state="unrecognised_shape",
                    reason="rea answered but its Evidence holds no JavaScriptApplicationGraph this adapter can read; nothing was admitted to the spec")
        return pack
    pack.update(state="ok", facts=facts, reason="")
    return pack


def summary(pack: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The small record that rides the lane result / verdict card (no facts, no paths of the analysed code)."""
    if not pack:
        return {"state": "off", "reason": "rea was not requested"}
    f = pack.get("facts") or {}
    return {"state": pack.get("state"), "reason": pack.get("reason") or "", "version": (pack.get("tool") or {}).get("version"),
            "coverage": f.get("coverage"), "modules": len(f.get("modules") or []), "imports": len(f.get("imports") or []),
            "boundaries": sum(len(v) for v in (f.get("boundaries") or {}).values()),
            "dropped": f.get("dropped"), "evidence": pack.get("evidence")}
