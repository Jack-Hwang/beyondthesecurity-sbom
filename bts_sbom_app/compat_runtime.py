"""Opt-in runtime differential: do the project's OWN tests behave the same on the patched dependencies?

``compat`` (the static gate) catches a removed symbol, a rejected call shape and a resolver conflict, but not a changed
behaviour behind an unchanged signature. The only measurement for that is to run the project's tests on both dependency
sets and compare, test by test:

  baseline   copy of the work tree + a fresh venv with the ORIGINAL pins installed -> run the suite -> passed/failed sets
  after      a copy of the PATCHED tree, the same venv with the patched requirements installed -> run again
  verdict    regression  a test that passed on the baseline does not pass now (or the patched pins do not install)
             ok          >= 1 test ran and none regressed (baseline failures are reported, never blamed on the patch)
             unverified  no runner / no tests / the baseline itself could not be installed or run

Safety (this executes the scanned project's code, so it is OFF unless the caller asks for it):
  * the origin and the work copy are never run in place - each run uses a throw-away copy (no .git);
  * installs use ``--only-binary=:all:`` so no sdist ``setup.py`` of a dependency is executed;
  * the test process gets a minimal environment (no tokens, no proxy/index credentials - only pip steps see proxy settings);
  * every subprocess has a timeout; a timeout is an ``unverified`` reason, not a pass.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Set

SCHEMA = "bts-sbom.compat-runtime.v1"
_COPY_IGNORE = shutil.ignore_patterns(".git", "__pycache__", "node_modules", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache")
_PIP_ENV_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                 "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CERT", "PIP_TRUSTED_HOST")
_BASE_ENV_KEYS = ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "LANG", "LC_ALL", "COMSPEC", "PATHEXT")
HONESTY = [
    "this executes the project's own test suite: it is opt-in and runs only in throw-away copies with a minimal environment",
    "a project without tests (or whose tests fail on the baseline) yields unverified, never ok",
    "the whole patch is judged at once: a regression reverts the patch, it does not bisect which package caused it",
]


def _req_like(path: str) -> bool:
    b = os.path.basename(path).lower()
    return bool(re.match(r"^(requirements.*|constraints.*)\.(txt|in)$", b)) or (b.startswith("requirements") and b.endswith(".txt"))


def requirement_files(plans: Sequence[Dict[str, Any]]) -> List[str]:
    """requirements*.txt files that carry the pypi upgrades (the only manifests this layer can install)."""
    out: Set[str] = set()
    for p in plans:
        if p.get("status") == "upgrade" and str(p.get("ecosystem") or "").lower() == "pypi":
            out.update(f for f in (p.get("files") or []) if _req_like(f))
    return sorted(out)


def detect_runner(root: str) -> Optional[str]:
    """'pytest' | 'unittest' | None. pytest when it is configured or imported by the tests, unittest when a tests folder exists."""
    def has(rel: str, needle: str) -> bool:
        try:
            with open(os.path.join(root, rel), "r", encoding="utf-8", errors="replace") as fh:
                return needle in fh.read()
        except OSError:
            return False
    if os.path.isfile(os.path.join(root, "pytest.ini")) or has("pyproject.toml", "[tool.pytest") or has("tox.ini", "[pytest]") \
            or has("setup.cfg", "[tool:pytest]") or os.path.isfile(os.path.join(root, "conftest.py")):
        return "pytest"
    tests: List[str] = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git", "node_modules", "venv", ".venv", "__pycache__", "site-packages")]
        tests += [os.path.join(dp, f) for f in fns if f.endswith(".py") and (f.startswith("test_") or f.endswith("_test.py"))]
        if len(tests) > 60:
            break
    if not tests:
        return None
    for fp in tests[:40]:
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                if re.search(r"^\s*(import pytest|from pytest\b)", fh.read(), re.M):
                    return "pytest"
        except OSError:
            continue
    return "unittest"


def _venv_python(venv: str) -> str:
    return os.path.join(venv, "Scripts", "python.exe") if os.name == "nt" else os.path.join(venv, "bin", "python")


def _env(pip: bool) -> Dict[str, str]:
    keys = _BASE_ENV_KEYS + (_PIP_ENV_KEYS if pip else ())
    env = {k: os.environ[k] for k in keys if k in os.environ}
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_INPUT="1", CI="1")
    return env


def _run(cmd: List[str], cwd: str, timeout: float, pip: bool = False) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, env=_env(pip))
        return {"rc": p.returncode, "out": (p.stdout or "") + (p.stderr or ""), "timeout": False}
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
        return {"rc": None, "out": out, "timeout": True}
    except OSError as exc:
        return {"rc": None, "out": "%s: %s" % (type(exc).__name__, exc), "timeout": False}


_PYTEST_LINE = re.compile(r"^(PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)\s+(\S+)", re.M)
_UNITTEST_LINE = re.compile(r"^(.*?) \.\.\. (ok|FAIL|ERROR|skipped .*|expected failure|unexpected success)\s*$", re.M)


def parse_results(runner: str, out: str) -> Dict[str, Set[str]]:
    passed: Set[str] = set()
    failed: Set[str] = set()
    if runner == "pytest":
        for st, tid in _PYTEST_LINE.findall(out):
            (passed if st in ("PASSED", "XPASS") else failed if st in ("FAILED", "ERROR") else set()).add(tid)
    else:
        for tid, st in _UNITTEST_LINE.findall(out):
            (passed if st in ("ok", "expected failure") else failed if st in ("FAIL", "ERROR", "unexpected success") else set()).add(tid.strip())
    return {"passed": passed, "failed": failed}


def run_suite(python: str, workdir: str, runner: str, timeout: float) -> Dict[str, Any]:
    if runner == "pytest":
        cmd = [python, "-m", "pytest", "-q", "-rA", "--no-header", "-p", "no:cacheprovider"]
    else:
        cmd = [python, "-m", "unittest", "discover", "-v"]
    r = _run(cmd, workdir, timeout)
    res = parse_results(runner, r["out"])
    return {"ran": len(res["passed"]) + len(res["failed"]), "passed": res["passed"], "failed": res["failed"],
            "rc": r["rc"], "timeout": r["timeout"], "tail": r["out"][-600:]}


class Differential:
    """baseline() once BEFORE the patch is applied, after() once AFTER; close() always (removes the venv and the copies)."""

    def __init__(self, root: str, req_files: Sequence[str], *, pip_args: Sequence[str] = (), timeout: float = 900.0,
                 runner: Optional[str] = None) -> None:
        self.root, self.req_files, self.pip_args, self.timeout = root, list(req_files), list(pip_args), timeout
        self.runner = runner or detect_runner(root)
        self.tmp = tempfile.mkdtemp(prefix="bts-compat-rt-")
        self.python = ""
        self._base: Optional[Dict[str, Any]] = None
        self._t0 = time.time()

    def _copy(self, name: str) -> str:
        dst = os.path.join(self.tmp, name)
        shutil.copytree(self.root, dst, ignore=_COPY_IGNORE)
        return dst

    def _install(self, workdir: str) -> Dict[str, Any]:
        last: Dict[str, Any] = {"rc": 0, "out": ""}
        for rf in self.req_files:
            last = _run([self.python, "-m", "pip", "install", "--only-binary=:all:", "-r", rf, *self.pip_args], workdir, self.timeout, pip=True)
            if last["rc"] != 0:
                break
        return last

    def baseline(self) -> Dict[str, Any]:
        if not self.runner:
            return {"status": "unverified", "reason": "no test runner detected (no pytest config and no test_*.py files)"}
        if not self.req_files:
            return {"status": "unverified", "reason": "no requirements*.txt carries the upgrades: this layer installs requirements files only"}
        work = self._copy("base")
        venv = os.path.join(self.tmp, "venv")
        mk = _run([sys.executable, "-m", "venv", venv], self.tmp, 300.0)
        self.python = _venv_python(venv)
        if mk["rc"] != 0 or not os.path.exists(self.python):
            return {"status": "unverified", "reason": "could not create the virtual environment: " + mk["out"][-160:]}
        ins = self._install(work)
        if ins["rc"] != 0:
            return {"status": "unverified", "reason": "baseline requirements did not install (%s): %s" % (
                "timeout" if ins.get("timeout") else "pip failed", ins["out"][-200:].strip())}
        if self.runner == "pytest" and _run([self.python, "-c", "import pytest"], work, 60.0)["rc"] != 0:
            pi = _run([self.python, "-m", "pip", "install", "--only-binary=:all:", "pytest", *self.pip_args], work, self.timeout, pip=True)
            if pi["rc"] != 0:
                return {"status": "unverified", "reason": "pytest is not installable in the sandbox: " + pi["out"][-160:]}
        run = run_suite(self.python, work, self.runner, self.timeout)
        if run["timeout"]:
            return {"status": "unverified", "reason": "the baseline test run timed out after %ds" % int(self.timeout)}
        if run["ran"] == 0:
            return {"status": "unverified", "reason": "the baseline run collected 0 tests: %s" % run["tail"][-160:].strip()}
        self._base = run
        return {"status": "ready", "runner": self.runner, "ran": run["ran"], "passed": len(run["passed"]), "failed": len(run["failed"])}

    def after(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"schema": SCHEMA, "runner": self.runner, "honesty": HONESTY}
        if self._base is None:
            out.update(status="unverified", reason="no usable baseline was recorded (run baseline() first)")
            return out
        work = self._copy("after")
        ins = self._install(work)
        base = self._base
        out["baseline"] = {"ran": base["ran"], "passed": len(base["passed"]), "failed": len(base["failed"])}
        if ins["rc"] != 0:
            out.update(status="regression", reason="the patched requirements do not install on the baseline environment (%s): %s" % (
                "timeout" if ins.get("timeout") else "pip failed", ins["out"][-240:].strip()), regressions=[], install_failed=True)
            return out
        run = run_suite(self.python, work, self.runner or "unittest", self.timeout)
        out["after"] = {"ran": run["ran"], "passed": len(run["passed"]), "failed": len(run["failed"])}
        if run["timeout"]:
            out.update(status="unverified", reason="the patched test run timed out after %ds" % int(self.timeout))
            return out
        regs = sorted(base["passed"] - run["passed"])
        out["regressions"] = regs[:30]
        out["fixed"] = sorted(base["failed"] & run["passed"])[:30]
        out["baseline_failing"] = len(base["failed"])
        if regs:
            out.update(status="regression", reason="%d test(s) that passed on the baseline do not pass on the patched pins: %s" % (len(regs), ", ".join(regs[:3])))
        else:
            out.update(status="ok", reason="%d baseline-passing test(s) still pass on the patched pins%s" % (
                len(base["passed"]), " (%d baseline failure(s) are pre-existing, not blamed on the patch)" % len(base["failed"]) if base["failed"] else ""))
        out["seconds"] = round(time.time() - self._t0, 1)
        return out

    def close(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


__all__ = ["Differential", "detect_runner", "requirement_files", "parse_results", "run_suite", "SCHEMA", "HONESTY"]
