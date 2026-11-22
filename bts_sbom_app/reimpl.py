"""Clean-room reimplementation workbench (brief 6, scenario 5): architecture/engine analysis -> AI writes
NEW code -> tests -> publish, with every stage streamed live.

Legal spine (two walls + a measured gate):
  Wall 1 - the READER parses the original with `ast` and exports ONLY the public interface (signatures +
           docstring contracts). Implementation bodies never leave the reader.
  Wall 2 - the GENERATOR receives the spec JSON only. Its prompt is built without the original source;
           this is structural (the generator never opens the source), and tested.
  Gate   - shingle_overlap() compares the generated code against the original line-shingles; overlap above
           COPY_THRESHOLD rejects the output (clean-room compliance becomes a measurement, not a claim).
License gate: the caller passes license_ok from a council/verdict decision - a compliance-risky component
is refused before any generation. Honesty: without an LLM client the lane produces a deterministic
scaffold (signatures + generated tests) and SAYS the bodies need an LLM; failing stages report partial
results with reasons (4-3차시 envelope philosophy). Nothing is ever executed in-place: generated code runs
in an isolated work folder under a subprocess timeout, and publish defaults to folder/branch, refusing to
overwrite the analysed source.
"""
from __future__ import annotations

import ast
import datetime
import json
import os
import shutil
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Set

from . import __version__, arch_map
from .binscan import _LICENSE_STRINGS

SCHEMA = "bts-sbom.reimpl.v1"
COPY_THRESHOLD = 0.05
SHINGLE_N = 4
TEST_TIMEOUT = 120
HONESTY = ["without an LLM client only a deterministic scaffold is produced; implementation bodies need the LLM lane",
           "import-table style evidence: the generated code passing tests proves the contracts hold, not that behaviour is byte-identical"]

# ------------------------------------------------------------------ wall 1: interface extraction (reader)


def extract_interface(path: str) -> Dict[str, Any]:
    """Public interface of one module: functions/classes with signatures and the docstring's first line as
    the behaviour contract. Implementation bodies are deliberately NOT read into the result."""
    src = open(path, "r", encoding="utf-8", errors="replace").read()
    tree = ast.parse(src)
    funcs: List[Dict[str, Any]] = []
    classes: List[Dict[str, Any]] = []
    for node in tree.body:                                         # top level only: the public surface
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            args = [a.arg for a in node.args.args if a.arg not in ("self", "cls")]
            doc = ast.get_docstring(node) or ""
            funcs.append({"name": node.name, "args": args,
                          "contract": doc.split("\n")[0][:160], "async": isinstance(node, ast.AsyncFunctionDef)})
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            methods = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and not n.name.startswith("_")]
            doc = ast.get_docstring(node) or ""
            classes.append({"name": node.name, "methods": methods, "contract": doc.split("\n")[0][:160]})
    deps: Set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            deps.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            deps.add(node.module.split(".")[0])
    return {"module": os.path.splitext(os.path.basename(path))[0], "path": path.replace("\\", "/"),
            "functions": funcs, "classes": classes, "imports": [d for d in deps if d != os.path.splitext(os.path.basename(path))[0]]}


def spec_document(iface: Dict[str, Any], why: str) -> str:
    """The spec the generator is allowed to see: requirements + contracts, no implementation text."""
    out = ["# Clean-room spec: %s" % iface["module"], "",
           "Why reimplementation: %s" % why, "",
           "## Requirements", "",
           "- reimplement the public surface below as a NEW module named `%s.py`" % iface["module"],
           "- same public names and signatures; behaviour follows each contract", "- no third-party dependencies beyond: %s"
           % (", ".join(iface["imports"]) or "none (stdlib only)"), ""]
    if iface["functions"]:
        out.append("## Function contracts")
        for f in iface["functions"]:
            out.append("- `%s(%s)`%s: %s" % (f["name"], ", ".join(f["args"]), " [async]" if f["async"] else "",
                                             f["contract"] or "(contract unspecified - keep total behaviour)"))
    if iface["classes"]:
        out += ["", "## Class contracts"]
        for c in iface["classes"]:
            out.append("- `%s` methods %s: %s" % (c["name"], ", ".join(c["methods"]) or "(none)",
                                                  c["contract"] or "(contract unspecified)"))
    out += ["", "## Clean-room rule", "", "Write original code. Do not reproduce any existing implementation text.", ""]
    return "\n".join(out)


# ------------------------------------------------------------------ the measured gate: copy detection


def _strip_docstrings(text: str) -> str:
    """Contracts (docstrings) come FROM THE SPEC by design - they are not copied expression. The gate
    measures implementation copying, so docstrings are stripped from both sides first (ast when the text
    parses, unchanged otherwise)."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return text
    lines = text.splitlines(keepends=True)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue                                           # only these carry a docstring statement
        body = node.body
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            start, end = body[0].lineno - 1, body[0].end_lineno
            for i in range(start, min(end, len(lines))):
                lines[i] = ""
    return "".join(lines)


def _shingles(text: str, n: int = SHINGLE_N) -> Set[Any]:
    lines = [ln.strip() for ln in _strip_docstrings(text).splitlines()]
    lines = [ln for ln in lines if ln]
    grams: Set[Any] = set()
    for i in range(max(1, len(lines) - n + 1)):
        grams.add(tuple(lines[i:i + n]))
    if not grams and lines:
        grams = {tuple(lines)}
    return grams


def shingle_overlap(new_code: str, original_code: str, n: int = SHINGLE_N) -> float:
    new, orig = _shingles(new_code, n), _shingles(original_code, n)
    if not new or not orig:
        return 0.0
    return round(len(new & orig) / len(new), 4)


def license_strings_in(text: str) -> List[str]:
    found = [s for s in _LICENSE_STRINGS if s.casefold() in text.casefold()]
    return found


# ------------------------------------------------------------------ wall 2: generation (spec-only input)


def scaffold_code(module_name: str, iface: Dict[str, Any]) -> str:
    """Deterministic offline fallback: the public surface as runnable stubs + honest marker."""
    out = ['"""SCAFFOLD ONLY: generated clean-room skeleton for %s - implementation bodies need the LLM lane."""' % module_name,
           "", ""]
    for f in iface["functions"]:
        args = ", ".join(f["args"])
        body = "        ...  # scaffold: implement from the spec"
        if f["async"]:
            out += ["async def %s(%s):" % (f["name"], args), body, ""]
        else:
            out += ["def %s(%s):" % (f["name"], args), body, ""]
    for c in iface["classes"]:
        out += ["class %s:" % c["name"], '    """%s"""' % (c["contract"] or c["name"]), ""]
        for m in c["methods"]:
            out += ["    def %s(self, *args, **kwargs):" % m, "        ...  # scaffold", ""]
    if not iface["functions"] and not iface["classes"]:
        out += ["# no public surface found in the spec - empty module is the honest scaffold", ""]
    return "\n".join(out)


def llm_generate(spec: str, client: Any, prior_fail: Optional[str] = None) -> str:
    """Wall 2 in code: the prompt is built ONLY from the spec text - the original source is not a parameter
    of this function, so it structurally cannot leak into the prompt. ``prior_fail`` carries the previous
    attempt's failing legacy-test output (loop engineering): the retry fixes THAT behaviour, not a paraphrase."""
    system = ("You are the implementation team inside a clean-room process. Below is a SPEC only. Write a NEW "
              "implementation that satisfies it. Return JSON {\"code\": string} where code is a complete Python "
              "module. Original code was never shown to you and must not be guessed at or quoted.")
    if prior_fail:
        system += (" IMPORTANT: your previous implementation failed the legacy acceptance suite. The failures "
                   "were:\n%s\n\nFix exactly those behaviours while keeping the rest of the contract." % prior_fail[:800])
    raw = client.complete(
        system + "\n\nRespond with ONLY valid JSON, no prose, no code fences.",
        "SPEC:\n" + spec, max_tokens=4096, json_mode=True)
    from . import ai
    obj = ai._parse_json(raw)
    code = obj.get("code")
    if not isinstance(code, str) or len(code.strip()) < 10:
        raise ValueError("the model returned no usable code field")
    return code


# ------------------------------------------------------------------ tests (deterministic, self-runnable)


def gen_tests(module_name: str, iface: Dict[str, Any]) -> str:
    out = ["\"\"\"Generated contract tests for the reimplementation of %s (self-runnable without pytest).\"\"\"" % module_name,
           "", "import importlib, sys, traceback", "",
           "mod = importlib.import_module(%s)" % json.dumps(module_name), "", "def test_import_roundtrip():",
           "    assert mod is not None", ""]
    names: List[str] = []
    for f in iface["functions"]:
        if not f["args"]:
            names.append("test_call_%s" % f["name"])
            out += ["def %s():" % names[-1], "    r = mod.%s()" % f["name"],
                    "    assert True  # calling with no args must not raise", ""]
    for c in iface["classes"]:
        names.append("test_class_%s_instantiable" % c["name"])
        out += ["def %s():" % names[-1], "    inst = mod.%s()" % c["name"],
                "    for m in %s:" % json.dumps(c["methods"]), "        assert hasattr(inst, m)", ""]
    names.append("test_public_surface")
    out += ["def test_public_surface():", "    for name in %s:" % json.dumps([f["name"] for f in iface["functions"]]),
            "        assert hasattr(mod, name)", ""]
    out += ["if __name__ == '__main__':", "    failed = 0", "    for name in %s:" % json.dumps(names),
            "        try:", "            globals()[name]()", "        except Exception:",
            "            failed += 1", "            traceback.print_exc()",
            "    print('tests: %%d run, %%d failed' %% (len(%s), failed))" % json.dumps(names),
            "    sys.exit(1 if failed else 0)"]
    return "\n".join(out) + "\n"


def run_tests(work: str, module_name: str) -> Dict[str, Any]:
    """Execute the generated tests in an isolated subprocess (generated code is untrusted): plain python,
    bounded time, work folder only. Paths are absolutised - the subprocess changes directory, so relative
    arguments would resolve against the wrong root."""
    work = os.path.abspath(work)
    test_file = os.path.abspath(os.path.join(work, "test_%s.py" % module_name))
    return _run_py(test_file, work)


# The legacy-suite compatibility shim, verbatim: old suites (2008-era) crash on Python 3.11+ unittest
# (functools.partial test callables have no __name__) and often ignore their own failure count. The shim
# neutralises addDuration and turns the runner's result into an exit code - so a legacy oracle can grade a
# fresh implementation on this runtime.
LEGACY_SHIM = (
    "import functools, unittest, runpy, sys\n"
    "class Partial(functools.partial):\n"                       # 2008-era suites build tests from partials,
    "    __name__ = 'legacy_partial_test'\n"                    # which Python 3.11+ unittest cannot stringify
    "functools.partial = Partial\n"                             # one patch neutralises every str(test) surface
    "unittest.result.TestResult.addDuration = lambda self, test, elapsed: None\n"
    "unittest.case.TestCase.addDuration = lambda self, elapsed: None\n"
    "if hasattr(unittest, 'runner'):\n"
    "    unittest.runner.TextTestRunner.getDescription = lambda self, test: (\n"
    "        test.shortDescription() or test.id())\n"
    "_orig = unittest.TextTestRunner.run\n"
    "def _run(self, suite):\n"
    "    r = _orig(self, suite)\n"
    "    if not r.wasSuccessful():\n"
    "        sys.exit(1)\n"
    "unittest.TextTestRunner.run = _run\n"
    "runpy.run_path(sys.argv[1], run_name='__main__')\n"
)


def discover_adopted_tests(source_root: str) -> Dict[str, List[str]]:
    """Upstream test files (test_*.py / *_test.py) plus their data fixtures (.json/.txt/.xml/.csv/.yaml in
    the same folder) - the legacy behaviour oracle a reimplementation must satisfy. Absolute paths."""
    tests: List[str] = []
    data: List[str] = []
    for fn in sorted(os.listdir(source_root)):
        fp = os.path.join(source_root, fn)
        if not os.path.isfile(fp):
            continue
        low = fn.lower()
        if low.startswith("test_") or low.endswith("_test.py"):
            tests.append(fp)
        elif low.endswith((".json", ".txt", ".xml", ".csv", ".yaml", ".yml")):
            data.append(fp)
    return {"tests": tests, "data": data}


def run_adopted_tests(work: str, adopted: Dict[str, List[str]]) -> Dict[str, Any]:
    """Run the upstream (legacy) test suite inside the work folder under the compatibility shim. The
    shim's exit code is the verdict: legacy runners often print results without exiting non-zero."""
    work = os.path.abspath(work)
    for src in adopted.get("tests", []) + adopted.get("data", []):
        shutil.copyfile(src, os.path.join(work, os.path.basename(src)))
    tails: List[str] = []
    all_ok = True
    for src in adopted.get("tests", []):
        p = subprocess.run([sys.executable, "-X", "utf8", "-c", LEGACY_SHIM, os.path.basename(src)],
                           capture_output=True, text=True, encoding="utf-8", timeout=TEST_TIMEOUT, cwd=work)
        tail = ((p.stdout or "") + (p.stderr or "")).strip()[-300:]
        tails.append("%s -> %s" % (os.path.basename(src), "OK" if p.returncode == 0 else "FAILED"))
        tails.append(tail)
        if p.returncode != 0:
            all_ok = False
    return {"ran": True, "ok": all_ok, "files": [os.path.basename(x) for x in adopted.get("tests", [])],
            "tail": "\n".join(tails)[-500:]}


def _run_py(test_file: str, work: str) -> Dict[str, Any]:
    try:
        p = subprocess.run([sys.executable, "-X", "utf8", test_file], capture_output=True, text=True,
                           encoding="utf-8", timeout=TEST_TIMEOUT, cwd=work)
        tail = ((p.stdout or "") + (p.stderr or "")).strip()[-400:]
        return {"ran": True, "ok": p.returncode == 0, "code": p.returncode, "tail": tail, "timeout": False}
    except subprocess.TimeoutExpired:
        return {"ran": True, "ok": False, "code": None, "tail": "test subprocess timed out after %ds" % TEST_TIMEOUT,
                "timeout": True}


# ------------------------------------------------------------------ orchestrator


def _emit(progress: Optional[Callable[[Dict[str, Any]], None]], event: str, **fields: Any) -> None:
    if progress:
        ev = {"event": event, "ts": datetime.datetime.now().astimezone().isoformat(timespec="seconds"), **fields}
        try:
            progress(ev)
        except Exception:                                          # noqa: BLE001 - telemetry never kills the lane
            pass


def reimpl(source_root: str, component: str, out_dir: str, *, client: Any = None, license_ok: bool = True,
           why: str = "compliance-risky license (clean-room reimplementation)", copy_threshold: float = COPY_THRESHOLD,
           publish_dest: Optional[str] = None, allow_inplace: bool = False,
           progress: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
    """The whole lane. Returns a verdict record; every stage is emitted through ``progress`` (SSE-ready)."""
    res: Dict[str, Any] = {"schema": SCHEMA, "tool": "bts-sbom-app reimpl", "version": __version__,
                           "source": os.path.abspath(source_root), "component": component,
                           "started": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                           "copy_threshold": copy_threshold, "stages": []}
    if not license_ok:
        res.update(verdict="refused", reason="the license gate refused this component (license_ok=False)")
        _emit(progress, "refused", reason=res["reason"])
        return res
    src_path = os.path.join(source_root, component)
    if not os.path.isfile(src_path):
        res.update(verdict="refused", reason="component not found under the source root: %s" % component)
        _emit(progress, "refused", reason=res["reason"])
        return res
    os.makedirs(out_dir, exist_ok=True)
    module_name = os.path.splitext(os.path.basename(component))[0]

    # wall 1: read the interface (bodies stay here, in the reader)
    iface = extract_interface(src_path)
    original_src = open(src_path, "r", encoding="utf-8", errors="replace").read()
    res["interface"] = {"functions": [f["name"] for f in iface["functions"]],
                        "classes": [c["name"] for c in iface["classes"]], "imports": iface["imports"]}
    _emit(progress, "interface_ready", functions=iface["functions"], classes=iface["classes"])

    # stage B: spec + diagram
    spec = spec_document(iface, why)
    dgml = arch_map.to_dgml("Reimplementation of %s" % component,
                            sorted({iface["module"], *iface["imports"]}),
                            [(iface["module"], d) for d in iface["imports"]])
    spec_path = os.path.join(out_dir, "spec.md")
    dgml_path = os.path.join(out_dir, "dependencies.dgml")
    io_wrap(spec_path, spec)
    io_wrap(dgml_path, dgml)
    res["artifacts"] = {"spec": spec_path, "dgml": dgml_path}
    _emit(progress, "spec_ready", spec=spec_path)
    _emit(progress, "diagram_ready", dgml=dgml_path)

    # stages C..E2 in a loop-engineering cycle (max 2 attempts): generate -> clean-room gate -> contract
    # tests -> the upstream legacy suite as the behaviour oracle; a compatibility failure regenerates ONCE
    # with the failing output attached (the nl2sql precedent). Scaffold mode has nothing to retry from -
    # it exits honestly after its single pass.
    work = os.path.join(out_dir, "work")
    os.makedirs(work, exist_ok=True)
    tests = gen_tests(module_name, iface)
    verdict = None
    prior_fail = None
    attempt = 0
    while True:
        attempt += 1
        code, generated_by = "", "scaffold"
        if client is not None:
            try:
                code = llm_generate(spec, client, prior_fail=prior_fail)
                generated_by = "llm"
            except Exception as exc:                               # noqa: BLE001 - degrade honestly to the scaffold
                res["llm_error"] = str(exc)[:160]
        if generated_by == "scaffold":
            code = scaffold_code(module_name, iface)
        code_path = os.path.join(out_dir, "%s.py" % module_name)
        io_wrap(code_path, code)
        res["generated_by"] = generated_by
        res["attempts"] = attempt
        res["artifacts"]["code"] = code_path
        _emit(progress, "code_ready", by=generated_by, path=code_path, attempt=attempt)

        # stage D: the measured clean-room gate
        overlap = shingle_overlap(code, original_src)
        lic = license_strings_in(code)
        gate = {"overlap": overlap, "threshold": copy_threshold, "license_strings": lic,
                "passed": overlap <= copy_threshold and not lic}
        res["copy_gate"] = gate
        _emit(progress, "copy_gate", overlap=overlap, passed=gate["passed"])
        if not gate["passed"]:
            res.update(verdict="rejected", reason="copy gate failed: shingle overlap %.3f > %.3f%s" % (
                overlap, copy_threshold, " and/or license strings present" if lic else ""))
            _emit(progress, "copy_gate_failed", overlap=overlap)
            break

        # stage E: generated contract tests in an isolated work folder
        shutil.copyfile(code_path, os.path.join(work, "%s.py" % module_name))
        io_wrap(os.path.join(work, "test_%s.py" % module_name), tests)
        _emit(progress, "tests_running", module=module_name)
        tr = run_tests(work, module_name)
        res["tests"] = tr
        _emit(progress, "tests_passed" if tr["ok"] else "tests_failed", tail=tr["tail"][:200])
        if not tr["ok"]:
            res.update(verdict="tests_failed", reason="the generated tests failed against the implementation")
            break

        # stage E2: the upstream (legacy) test suite as the behaviour oracle - a reimplementation that
        # passes its own contracts but fails the 2008 suite is NOT compatible. Under the legacy shim.
        adopted = discover_adopted_tests(source_root)
        if adopted.get("tests"):
            res["adopted_tests"] = {"files": [os.path.basename(x) for x in adopted["tests"]]}
            _emit(progress, "adopted_tests_running", files=len(adopted["tests"]))
            atr = run_adopted_tests(work, adopted)
            res["adopted_tests"].update(ok=atr["ok"], tail=atr["tail"])
            _emit(progress, "adopted_tests_passed" if atr["ok"] else "adopted_tests_failed", tail=atr["tail"][:200])
            if atr["ok"]:
                verdict = "ok"
                break
            if generated_by == "scaffold" or attempt >= 2:
                res.update(verdict="compatibility_failed",
                           reason="the upstream legacy test suite failed - the reimplementation is not behaviour-compatible yet")
                break
            prior_fail = atr["tail"][-800:]                        # loop engineering: the failures ride along
            _emit(progress, "regenerating", reason="compatibility failure - one retry with the failures attached")
            continue
        verdict = "ok"
        break
    # stage F: publish only a fully passing lane (folder copy; the analysed source is never overwritten
    # without an explicit flag)
    if verdict == chr(111) + chr(107) and publish_dest:
        dest = os.path.abspath(publish_dest)
        if os.path.abspath(source_root) == dest and not allow_inplace:
            res.update(verdict="publish_refused", reason="inplace publish needs allow_inplace=True")
            _emit(progress, "publish_refused", reason=res["reason"])
            return res
        os.makedirs(dest, exist_ok=True)
        shutil.copyfile(code_path, os.path.join(dest, "%s.py" % module_name))
        shutil.copyfile(os.path.join(work, "test_%s.py" % module_name), os.path.join(dest, "test_%s.py" % module_name))
        res["published_to"] = dest
        _emit(progress, "published", dest=dest)
    if not res.get("verdict"):                                  # a loop break already set an honest verdict
        res["verdict"] = "ok"
    res["honesty"] = HONESTY
    return res


def io_wrap(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
