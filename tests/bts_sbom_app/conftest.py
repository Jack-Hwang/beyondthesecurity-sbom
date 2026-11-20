"""Shared fixtures: a fake OSV / deps.dev / PyPI / EXAONE world so no test touches the network."""
from __future__ import annotations

import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

import pytest

# tests/bts_sbom_app/conftest.py -> repository root. The SBOM core (bts_sbom) lives in the same tree, so it is imported from here
# unless BTS_SBOM_PATH pins another checkout (e.g. a tagged snapshot for a reproducible loop pass).
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_BTS = os.environ.get("BTS_SBOM_PATH", "")
sys.path.insert(0, ROOT)
if _BTS and os.path.isdir(os.path.join(_BTS, "bts_sbom")):
    sys.path.insert(0, _BTS)

from bts_sbom_app import llm, net, osv  # noqa: E402

V3_98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V3_75 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
V3_61 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
SHA = "74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5"


def adv(vid: str, aliases: List[str], pkg: str, eco: str, intro: str, fixed: Optional[str], vec: str, summary: str = "advisory") -> Dict[str, Any]:
    ev = [{"introduced": intro}] + ([{"fixed": fixed}] if fixed else [])
    return {"id": vid, "aliases": aliases, "summary": summary, "published": "2020-01-01T00:00:00Z", "modified": "2020-01-02T00:00:00Z",
            "severity": [{"type": "CVSS_V3", "score": vec}],
            "affected": [{"package": {"name": pkg, "ecosystem": eco},
                          "ranges": [{"type": "ECOSYSTEM", "events": ev}, {"type": "GIT", "repo": "https://example.invalid/x", "events": [{"introduced": "0"}, {"fixed": SHA}]}]}],
            "references": [{"type": "ADVISORY", "url": "https://example.invalid/" + vid}]}


# advisory "families": the first doc is the canonical GHSA, the rest are alias duplicates (PYSEC / CVE records)
FAMILIES: List[List[Dict[str, Any]]] = [
    [adv("GHSA-req1-aaaa-aaaa", ["CVE-2020-1111", "PYSEC-2020-1"], "requests", "PyPI", "0", "2.20.0", V3_98),
     adv("PYSEC-2020-1", ["CVE-2020-1111", "GHSA-req1-aaaa-aaaa"], "requests", "PyPI", "0", "2.20.0", V3_98),
     adv("CVE-2020-1111", ["GHSA-req1-aaaa-aaaa", "PYSEC-2020-1"], "requests", "PyPI", "0", "2.20.0", V3_98)],
    [adv("GHSA-req2-bbbb-bbbb", ["CVE-2020-2222"], "requests", "PyPI", "0", "2.31.0", V3_61)],
    [adv("GHSA-fla1-cccc-cccc", ["CVE-2020-3333"], "flask", "PyPI", "0", "1.0", V3_75)],
    [adv("GHSA-fla2-dddd-dddd", ["CVE-2020-4444"], "flask", "PyPI", "1.0", "1.0.1", V3_75)],
    [adv("GHSA-yml1-eeee-eeee", ["CVE-2020-5555"], "pyyaml", "PyPI", "0", "5.4", V3_98)],
    [adv("GHSA-nof1-ffff-ffff", ["CVE-2020-6666"], "legacylib", "PyPI", "0", None, V3_75)],          # no fixed version
]
DOCS: Dict[str, Dict[str, Any]] = {d["id"]: d for fam in FAMILIES for d in fam}
LICENSES = {"requests": ["Apache-2.0"], "pyyaml": ["MIT"], "flask": None, "legacylib": None}      # flask: deps.dev has none -> registry


def _in_range(doc: Dict[str, Any], name: str, version: str) -> bool:
    from bts_sbom_app import engine
    fx, hit = engine.fixed_versions(doc, name, "PyPI", version)
    return hit


def advisories_for(name: str, version: str) -> List[List[Dict[str, Any]]]:
    return [fam for fam in FAMILIES if fam[0]["affected"][0]["package"]["name"] == name.lower() and _in_range(fam[0], name.lower(), version)]


class FakeScanner:
    """Stands in for bts_sbom.OsvScanner: reads requirements.txt files under ``path`` (name==version)."""

    def __init__(self, fail: bool = False):
        self.fail = fail
        self.scans = 0

    def scan(self, path: str, with_licenses: bool = False, guided_remediation: bool = False) -> Dict[str, Any]:
        self.scans += 1
        results = []
        for dp, _, fns in os.walk(path):
            if ".git" in dp.split(os.sep):
                continue
            for fn in fns:
                if fn.lower() != "requirements.txt":
                    continue
                pkgs = []
                for line in open(os.path.join(dp, fn), encoding="utf-8").read().splitlines():
                    m = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([^\s#;]+)", line)
                    if not m:
                        continue
                    name, ver = m.group(1), m.group(2)
                    docs = [d for fam in advisories_for(name, ver) for d in fam]
                    pkgs.append({"package": {"name": name, "version": ver, "ecosystem": "PyPI"},
                                 "identity": {"name": name, "ecosystem": "PyPI", "version": ver, "purl": "pkg:pypi/%s@%s" % (name.lower(), ver),
                                              "relationship": "direct", "depth": 0, "dependency_path": []},
                                 "query_status": "queried_online", "vulnerabilities": docs})
                results.append({"source": {"path": os.path.join(dp, fn), "type": "lockfile"}, "packages": pkgs})
        return {"results": results, "scan_status": {"sources": len(results), "packages": sum(len(r["packages"]) for r in results), "mode": "online"},
                "completeness": {"data_status": "complete", "vulnerability_presence": "found"}, "notes": []}


def _forbid(url: str, headers: Dict[str, str], body: Any) -> Tuple[int, Any]:
    raise AssertionError("unexpected network call: %s" % url)


def _forbid_llm(url: str, headers: Dict[str, str], body: Any) -> Tuple[int, str]:
    raise AssertionError("unexpected LLM call: %s" % url)


class FakeWorld:
    def __init__(self) -> None:
        self.calls: List[str] = []
        self.fail_osv = False
        self.llm_calls = 0
        self.llm_handler = None

    def http(self, url: str, headers: Dict[str, str], body: Any) -> Tuple[int, Any]:
        self.calls.append(url)
        if "api.osv.dev" in url:
            if self.fail_osv:
                return 503, None
            if url.endswith("/querybatch"):
                out = []
                for q in body["queries"]:
                    fams = advisories_for(q["package"]["name"], q["version"])
                    out.append({"vulns": [{"id": f[0]["id"], "modified": "x"} for f in fams]})
                return 200, {"results": out}
            m = re.search(r"/vulns/(.+)$", url)
            if m:
                d = DOCS.get(m.group(1))
                return (200, d) if d else (404, None)
        if "api.deps.dev" in url:
            m = re.search(r"/packages/([^/]+)/versions/", url)
            name = m.group(1).lower() if m else ""
            lic = LICENSES.get(name)
            return (200, {"licenses": lic}) if lic else (404, None)
        if "pypi.org/pypi/" in url:
            if "/flask/" in url:
                return 200, {"info": {"license": "BSD"}}
            return 404, None
        if "registry.npmjs.org/body/5.1.0" in url:
            return 200, {"licenses": [{"type": "MIT", "url": "https://example.invalid/LICENSE"}]}
        if "registry.npmjs.org/" in url:
            return 404, None
        if "repo1.maven.org/maven2/org/example/lib/1.0/lib-1.0.pom" in url:
            return 200, "<project><licenses><license><name>Apache License, Version 2.0</name></license></licenses></project>"
        if "repo1.maven.org/maven2/" in url:
            return 404, None
        raise AssertionError("unexpected network call: %s" % url)

    def llm(self, url: str, headers: Dict[str, str], body: Dict[str, Any]) -> Tuple[int, str]:
        self.llm_calls += 1
        assert self.llm_handler is not None, "LLM called but no handler set"
        return self.llm_handler(body)


@pytest.fixture(autouse=True)
def no_network():
    net.TRANSPORT, llm.TRANSPORT = _forbid, _forbid_llm
    osv.clear_cache()
    net.reset_stats()
    yield
    net.TRANSPORT, llm.TRANSPORT = None, None


@pytest.fixture(autouse=True)
def _reset_circuit_breakers():
    """Course package A: net.py's per-host circuit breakers are module-level state, so one test's failures must
    never carry over and open a breaker for the next test (or vice versa)."""
    net.reset_breakers()
    yield
    net.reset_breakers()


@pytest.fixture
def world() -> FakeWorld:
    w = FakeWorld()
    net.TRANSPORT = w.http
    llm.TRANSPORT = w.llm
    return w


def run_git(path: str, *args: str) -> str:
    p = subprocess.run(["git", "-C", path, "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert p.returncode == 0, p.stderr
    return p.stdout


@pytest.fixture
def make_repo(tmp_path):
    def _make(files: Dict[str, str], name: str = "proj", extra_commits: Optional[List[Dict[str, str]]] = None) -> str:
        d = tmp_path / name
        d.mkdir(parents=True, exist_ok=True)
        run_git(str(d), "init", "-q", "-b", "main")
        for batch in [files] + list(extra_commits or []):
            for rel, txt in batch.items():
                fp = d / rel
                fp.parent.mkdir(parents=True, exist_ok=True)
                fp.write_text(txt, encoding="utf-8", newline="\n")
            run_git(str(d), "add", "-A")
            run_git(str(d), "commit", "-q", "-m", "c%d" % len(run_git(str(d), "rev-list", "--all").split()))
        return str(d)
    return _make
