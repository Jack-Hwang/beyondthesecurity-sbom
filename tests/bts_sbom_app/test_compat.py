"""Patch compatibility gate (compat.py) + the opt-in runtime differential (compat_runtime.py).

Static layer: fake releases are plain ``{relpath: source}`` trees behind an injectable provider, so no test touches the network.
Runtime layer: real throw-away venvs, but fed from hand-built local wheels (``--no-index --find-links``), so it is offline too.
"""
from __future__ import annotations

import io
import os
import sys
import tarfile
import textwrap
import zipfile
from typing import Any, Dict, List, Optional

import pytest

from bts_sbom_app import compat, compat_runtime, engine, net, patch, pipeline, remediate, review

from conftest import FakeScanner

REQ3 = "requests==2.19.1\nflask==0.12\npyyaml==3.12\n"


def _d(s: str) -> str:
    return textwrap.dedent(s).lstrip("\n")


class FakeProvider:
    """Stands in for compat.PyPIProvider: ``releases`` maps (canonical name, version) -> source tree, ``requires`` -> Requires-Dist."""

    def __init__(self, releases: Dict[tuple, Dict[str, str]], requires: Optional[Dict[tuple, List[str]]] = None) -> None:
        self.releases, self.requires, self.calls = releases, requires or {}, []

    def meta(self, name: str, version: str) -> Optional[Dict[str, Any]]:
        k = (engine._canon("pypi", name), version)
        self.calls.append(("meta",) + k)
        if k not in self.releases and k not in self.requires:
            return None
        return {"requires_dist": self.requires.get(k, []), "requires_python": ">=3.8", "files": []}

    def artifact(self, name: str, version: str) -> Optional[compat.Artifact]:
        k = (engine._canon("pypi", name), version)
        self.calls.append(("artifact",) + k)
        tree = self.releases.get(k)
        return None if tree is None else compat.Artifact(tree, {}, "wheel", "x.whl")


def _plan(name: str, cur: str, to: str, eco: str = "PyPI", **kw: Any) -> Dict[str, Any]:
    p = {"component": name, "ecosystem": eco, "current_version": cur, "safe_version": to, "status": "upgrade", "breaking_risk": "low",
         "files": ["requirements.txt"], "verification": {"clean": True}}
    p.update(kw)
    return p


def _comp(name: str, ver: str) -> Dict[str, Any]:
    return {"name": name, "version": ver, "ecosystem": "PyPI", "relationship": "direct", "files": ["requirements.txt"]}


def _project(tmp_path, files: Dict[str, str], name: str = "proj") -> str:
    root = tmp_path / name
    for rel, txt in files.items():
        fp = root / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(txt, encoding="utf-8", newline="\n")
    return str(root)


# ----------------------------------------------------------------------------------------------------- the toy library
OLD = {
    "toylib/__init__.py": _d('''
        from .core import fetch, Client, old_name, Legacy
        from .util import *
        __all__ = ["fetch", "Client", "old_name", "helper", "Legacy"]
    '''),
    "toylib/core.py": _d('''
        def fetch(url, timeout=10, verify=True):
            return url
        def old_name(x):
            return x
        class Client:
            def __init__(self, base, retries=3):
                self.base = base
            def get(self, path):
                return path
            def legacy(self):
                return 1
        class Legacy:
            def run(self):
                return 1
            def stop(self):
                return 2
    '''),
    "toylib/util.py": "def helper(a, b=1):\n    return a\n",
}
NEW = {
    "toylib/__init__.py": _d('''
        from .core import fetch, Client, old_name_v2, Legacy
        from .util import *
        __all__ = ["fetch", "Client", "old_name_v2", "helper", "Legacy"]
    '''),
    "toylib/core.py": _d('''
        import warnings
        def fetch(url, *, timeout=10):
            return url
        def old_name_v2(x):
            return x
        class Client:
            def __init__(self, base, retries=3, token=None):
                self.base = base
            def get(self, path):
                return path
        class Legacy:
            def run(self):
                warnings.warn("run is deprecated", DeprecationWarning)
                return 1
    '''),
    "toylib/util.py": "def helper(a, b, c=1):\n    return a\n",
}
APP = _d('''
    import toylib
    from toylib import fetch, Client, old_name
    from toylib.util import helper

    r = fetch("u", 5, True)
    r2 = fetch("u", verify=False)
    ok = toylib.fetch("x", timeout=3)
    c = Client("b", retries=1)
    c.legacy()
    old_name(1)
    helper(1)
''')


def _run_assess(root: str, old: Dict[str, str], new: Dict[str, str], *, name: str = "toylib", **kw: Any) -> Dict[str, Any]:
    prov = FakeProvider({(name, "1.0"): old, (name, "2.0"): new})
    res = compat.assess(root, [_plan(name, "1.0", "2.0")], [_comp(name, "1.0")], provider=prov, **kw)
    return res["plans"][0] | {"_held": res["held"], "_summary": res["summary"]}


# ============================================================================================ AC-630: used-API diff
def test_used_api_diff_classifies_removed_rejected_calls_and_keeps_compatible_ones(tmp_path):
    """AC: BSA-AC-630. The project calls fetch(url, 5, True) / fetch(url, verify=False) / helper(1) / old_name(1) / Client(...): the
    new release rejects 4 shapes (positional count, dropped keyword, new required parameter, removed symbol) and still
    accepts toylib.fetch(timeout=3) and Client("b", retries=1) - no finding may be raised for the accepted ones."""
    root = _project(tmp_path, {"app.py": APP})
    r = _run_assess(root, OLD, NEW)
    by = {(f["symbol"], f["rule"]) for f in r["findings"]}
    assert ("toylib.old_name", "CMP-REMOVED") in by
    calls = [f for f in r["findings"] if f["rule"] == "CMP-CALL"]
    assert {f["symbol"] for f in calls} == {"toylib.fetch", "toylib.util.helper"}
    assert sum(1 for f in calls if f["symbol"] == "toylib.fetch") == 2                    # positional count + dropped keyword
    assert any("keyword 'verify' is not accepted" in f["detail"] for f in calls)
    assert any("3 positional argument(s) passed, 1 accepted" in f["detail"] for f in calls)
    assert any("required parameter 'b' is not supplied" in f["detail"] for f in calls)
    assert all(f["sites"] and f["sites"][0]["file"] == "app.py" for f in calls)           # evidence names the call site
    assert not [f for f in r["findings"] if f["symbol"] in ("toylib.Client",) and f["level"] == "breaking"]
    assert r["status"] == "breaking" and r["counts"]["breaking"] == 4
    assert r["_held"] == {"pypi|toylib|1.0": r["reason"]}                                  # block mode holds exactly this plan


def test_identical_release_is_the_negative_control_and_reports_compatible(tmp_path):
    """AC: BSA-AC-630. The same tree as both releases: every used symbol verified, 0 findings, coverage 1.0, nothing held."""
    root = _project(tmp_path, {"app.py": APP})
    r = _run_assess(root, OLD, OLD)
    assert r["status"] == "compatible" and r["findings"] == []
    assert r["coverage"] == 1.0 and r["counts"]["used"] == r["counts"]["verified"] > 0
    assert r["counts"]["call_sites_checked"] >= 5 and r["_held"] == {}


def test_review_level_findings_deprecation_removed_method_and_subclass(tmp_path):
    """AC: BSA-AC-630. Things that still import but deserve a human look are `review`, not `breaking`: a method removed from a class the
    project calls by the same attribute name, a newly deprecated class method used as base, and the removed-symbol hint
    names where a symbol moved. 3 of 3 review shapes, 0 breaking."""
    app = _d('''
        from toylib import Client, Legacy
        c = Client("b")
        c.legacy()
        class Mine(Legacy):
            pass
    ''')
    root = _project(tmp_path, {"app.py": app})
    r = _run_assess(root, OLD, NEW)
    rules = {f["rule"] for f in r["findings"]}
    assert "CMP-METHOD" in rules                                                          # Client.legacy removed, project calls .legacy()
    assert "CMP-BASE" in rules                                                            # Legacy subclassed, stop() removed upstream
    assert not [f for f in r["findings"] if f["level"] == "breaking"]
    assert r["status"] == "review"
    moved = compat.build_surface(compat.Artifact({"pkg/__init__.py": "from .a import thing\n", "pkg/a.py": "def thing(): pass\n"}, {}, "wheel", "w"), ["pkg"])
    assert "now defined in pkg.a" in compat._hint(moved, "pkg.b.thing")


def test_call_shape_rules_cover_star_calls_keyword_only_and_positional_only():
    """AC: BSA-AC-630. The call-shape check itself: 6 of 6 cases (star args skip the arity/required checks, keyword-only given by position,
    positional-only given by keyword, **kwargs accepting anything, unknown signature -> None)."""
    def sig(src):
        import ast
        return compat._sig(ast.parse(src).body[0], drop_first=False)
    s = sig("def f(a, /, b, *, c, d=1): pass")
    call = lambda npos=0, kw=(), star=False, dstar=False: {"npos": npos, "kw": list(kw), "star": star, "dstar": dstar}   # noqa: E731
    assert compat.call_problems(s, call(2, ["c"])) == []
    assert any("positional" in x for x in compat.call_problems(s, call(3, ["c"])))
    assert any("'a'" in x for x in compat.call_problems(s, call(0, ["a", "c"])) if "not accepted" in x)  # a is positional-only
    assert any("'c'" in x for x in compat.call_problems(s, call(2, [])))                  # keyword-only required, not supplied
    assert compat.call_problems(s, call(star=True, kw=["c"])) == []                       # *args: arity/required unknowable, keyword still fine
    assert compat.call_problems(sig("def g(**kw): pass"), call(0, ["anything"])) == []
    assert compat.call_problems(None, call()) is None


# ============================================================================================ AC-631: archives parsed safely
def _wheel(files: Dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, b in files.items():
            zf.writestr(n, b)
    return buf.getvalue()


def test_archive_parsing_is_in_memory_bounded_and_ignores_unsafe_members():
    """AC: BSA-AC-631. A wheel with a traversal name, an absolute name, an oversize file and a metadata file: 3 of 3 unsafe members are
    dropped, the good module and top_level.txt kept - and the module's top-level `raise SystemExit` proves nothing executes."""
    big = b"x = 1\n" * (compat.MAX_FILE_BYTES // 6 + 10)
    data = _wheel({"pkg/__init__.py": b"raise SystemExit('must never run')\ndef ok(): pass\n", "../evil.py": b"x=1", "/abs.py": b"x=1",
                   "pkg/huge.py": big, "pkg-1.0.dist-info/top_level.txt": b"pkg\n", "pkg/data.bin": b"\x00\x01"})
    art = compat.parse_archive(data, "pkg-1.0-py3-none-any.whl", "wheel")
    assert sorted(art.tree) == ["pkg/__init__.py"] and art.meta["top_level.txt"].strip() == "pkg"
    assert compat.import_roots(art, "pkg") == ["pkg"]
    assert "ok" in compat.build_surface(art, ["pkg"]).modules["pkg"].members              # parsed with ast, never imported


def test_sdist_top_directory_is_stripped_links_are_ignored_and_src_layout_is_found():
    """AC: BSA-AC-631. A tar sdist: `name-1.0/` stripped, a symlink member never followed, a src/ layout detected (3 of 3 shapes)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        def add(name, payload=b"", link=None):
            ti = tarfile.TarInfo(name)
            if link:
                ti.type, ti.linkname = tarfile.SYMTYPE, link
                tf.addfile(ti)
            else:
                ti.size = len(payload)
                tf.addfile(ti, io.BytesIO(payload))
        add("lib-1.0/setup.py", b"print('never executed')\n")
        add("lib-1.0/src/lib/__init__.py", b"def f(a): pass\n")
        add("lib-1.0/src/lib/link.py", link="/etc/passwd")
        add("lib-1.0/tests/__init__.py", b"")
    art = compat.parse_archive(buf.getvalue(), "lib-1.0.tar.gz", "sdist")
    assert "src/lib/__init__.py" in art.tree and "src/lib/link.py" not in art.tree
    prefix, roots = compat.find_roots(art.tree)
    assert prefix == "src/" and roots == ["lib"]                                          # tests/ is not an importable root
    assert "lib" in compat.build_surface(art, roots).modules


def test_pick_file_prefers_pure_wheel_then_sdist_and_skips_yanked_and_oversized():
    """AC: BSA-AC-631. File choice: pure wheel > sdist > smallest wheel; yanked and over-cap files never chosen (4 of 4 rules)."""
    pure = {"url": "u1", "packagetype": "bdist_wheel", "filename": "p-1-py3-none-any.whl", "size": 100}
    sd = {"url": "u2", "packagetype": "sdist", "filename": "p-1.tar.gz", "size": 50}
    plat = {"url": "u3", "packagetype": "bdist_wheel", "filename": "p-1-cp312-win_amd64.whl", "size": 10}
    assert compat.pick_file([sd, pure, plat])["url"] == "u1"
    assert compat.pick_file([sd, plat])["url"] == "u2"
    assert compat.pick_file([plat])["url"] == "u3"
    assert compat.pick_file([dict(pure, yanked=True), dict(sd, size=compat.MAX_ARTIFACT_BYTES + 1)]) is None


def test_default_provider_reads_pypi_json_and_the_archive_through_net(world):
    """AC: BSA-AC-631. PyPIProvider end to end over the fake transport: JSON -> file pick -> bytes fetch -> in-memory parse; a TRUNCATED download
    (hit the byte cap) is refused and the plan stays unverified instead of judging half an archive."""
    wheel = _wheel({"toylib/__init__.py": b"def f(a): pass\n", "toylib-1.0.dist-info/top_level.txt": b"toylib\n"})

    def transport(url, headers, body):
        if url.endswith("/toylib/1.0/json"):
            return 200, {"info": {"requires_dist": ["idna (>=2.5)"], "requires_python": ">=3.7"},
                         "urls": [{"url": "https://files.example.invalid/toylib-1.0-py3-none-any.whl", "packagetype": "bdist_wheel",
                                   "filename": "toylib-1.0-py3-none-any.whl", "size": len(wheel)}]}
        if url.endswith("toylib-1.0-py3-none-any.whl"):
            return 200, wheel
        raise AssertionError(url)
    net.TRANSPORT = transport
    prov = compat.PyPIProvider()
    assert prov.meta("toylib", "1.0")["requires_dist"] == ["idna (>=2.5)"]
    art = prov.artifact("toylib", "1.0")
    assert art is not None and "toylib/__init__.py" in art.tree
    old_limit = compat.MAX_ARTIFACT_BYTES
    try:
        compat.MAX_ARTIFACT_BYTES = len(wheel) + 5                                       # accepted by pick_file ...
        net.TRANSPORT = lambda u, h, b: transport(u, h, b) if not u.endswith(".whl") else (200, wheel + b"\0" * 10)   # ... but the body hits the cap
        prov2 = compat.PyPIProvider()
        prov2.meta("toylib", "1.0")
        net.TRANSPORT = lambda u, h, b: transport(u, h, b) if not u.endswith(".whl") else (200, b"\0" * (compat.MAX_ARTIFACT_BYTES))
        assert prov2.artifact("toylib", "1.0") is None
    finally:
        compat.MAX_ARTIFACT_BYTES = old_limit


# ============================================================================================ AC-632: pin constraints
def test_specifier_evaluation_table():
    """AC: BSA-AC-632. The specifier evaluator behind the resolver check: 9 of 9 operator cases."""
    ok = compat.satisfies
    assert ok("1.5", [(">=", "1.0"), ("<", "2")]) and not ok("2.0", [(">=", "1.0"), ("<", "2")])
    assert ok("1.26.18", [("<", "2"), ("!=", "1.25.0")]) and not ok("1.25.0", [("!=", "1.25.0")])
    assert ok("2.2.5", [("~=", "2.2")]) and not ok("3.0", [("~=", "2.2")])
    assert ok("1.4.9", [("~=", "1.4.2")]) and not ok("1.5.0", [("~=", "1.4.2")])
    assert ok("1.2.7", [("==", "1.2.*")]) and not ok("1.3.0", [("==", "1.2.*")])
    assert ok("1.3.0", [("!=", "1.2.*")]) and not ok("1.2.1", [("!=", "1.2.*")])
    assert compat.parse_requirement('urllib3 (<1.24,>=1.21.1) ; python_version >= "3"') == ("urllib3", [("<", "1.24"), (">=", "1.21.1")], 'python_version >= "3"')
    assert compat.parse_requirement("idna>=2.5")[1] == [(">=", "2.5")]
    assert compat.parse_requirement("PySocks!=1.5.7,>=1.5.6; extra == 'socks'")[2] == "extra == 'socks'"


def test_pin_conflicts_forward_reverse_marker_conditional_and_joint_upgrade(tmp_path):
    """AC: BSA-AC-632. The resolver failure that blocks real upgrades, measured from Requires-Dist: (a) reverse - requests==2.19.1 caps
    urllib3<1.24 and the plan raises urllib3 to 1.26.18 -> breaking; (b) forward - the target requires idna>=3 but the project pins
    idna==2.8 -> breaking; (c) a marker-conditional cap is only `review`; (d) upgrading both together is accepted."""
    root = _project(tmp_path, {"app.py": "import urllib3\nurllib3.PoolManager()\n"})
    tree = {"urllib3/__init__.py": "class PoolManager:\n    pass\n"}
    comps = [_comp("urllib3", "1.22"), _comp("requests", "2.19.1"), _comp("idna", "2.8")]
    prov = FakeProvider({("urllib3", "1.22"): tree, ("urllib3", "1.26.18"): tree},
                        {("requests", "2.19.1"): ["urllib3 (<1.24,>=1.21.1)", "idna (<2.8,>=2.5)"], ("idna", "2.8"): [],
                         ("urllib3", "1.26.18"): ["idna>=3.0"]})
    res = compat.assess(root, [_plan("urllib3", "1.22", "1.26.18")], comps, provider=prov)
    f = res["plans"][0]["findings"]
    assert {x["rule"] for x in f} == {"CMP-DEP-REVERSE", "CMP-DEP-FORWARD"} and res["plans"][0]["status"] == "breaking"
    assert any("requests==2.19.1 requires urllib3<1.24" in x["detail"] for x in f)
    assert any("requires idna>=3.0 but the project pins idna==2.8" in x["detail"] for x in f)
    assert res["held"] == {"pypi|urllib3|1.22": res["plans"][0]["reason"]}
    # (c) the same cap behind an environment marker is conditional evidence: review, not a hold
    prov.requires[("requests", "2.19.1")] = ['urllib3 (<1.24) ; python_version < "3.6"']
    prov.requires[("urllib3", "1.26.18")] = []
    res = compat.assess(root, [_plan("urllib3", "1.22", "1.26.18")], comps, provider=prov)
    assert res["plans"][0]["status"] == "review" and res["held"] == {}
    # (d) requests is upgraded in the same patch: the pins are overlaid with the post-patch versions, so the conflict disappears
    prov.requires[("requests", "2.19.1")] = ["urllib3 (<1.24)"]
    prov.requires[("requests", "2.31.0")] = ["urllib3 (<3,>=1.21.1)"]
    prov.releases[("requests", "2.31.0")] = {}
    both = [_plan("urllib3", "1.22", "1.26.18"), _plan("requests", "2.19.1", "2.31.0")]
    res = compat.assess(root, both, comps, provider=prov)
    assert [p for p in res["plans"] if p["component"] == "urllib3"][0]["findings"] == [] and res["held"] == {}


# ============================================================================================ AC-633: honesty
def test_thin_evidence_is_unverified_or_partial_never_compatible(tmp_path):
    """AC: BSA-AC-633. 6 of 6 thin-evidence shapes - offline, a non-PyPI ecosystem, no archive, a dynamic module, an unresolvable (C-extension)
    symbol, the plan budget - none may report `compatible`, and none may hold the plan (absence of evidence is not a break)."""
    root = _project(tmp_path, {"app.py": "import toylib\ntoylib.fetch('x')\n"})
    prov = FakeProvider({("toylib", "1.0"): OLD, ("toylib", "2.0"): NEW})
    comps = [_comp("toylib", "1.0")]
    off = compat.assess(root, [_plan("toylib", "1.0", "2.0")], comps, offline=True)
    assert off["plans"][0]["status"] == "unverified" and "offline" in off["plans"][0]["reason"]
    npm = compat.assess(root, [_plan("left-pad", "1.0.0", "1.3.0", eco="npm")], comps, provider=prov)
    assert npm["plans"][0]["status"] == "unverified" and "not covered" in npm["plans"][0]["reason"]
    noart = compat.assess(root, [_plan("toylib", "1.0", "9.9")], comps, provider=prov)
    assert noart["plans"][0]["status"] == "unverified" and "no readable source archive" in noart["plans"][0]["reason"]
    # a module-level __getattr__ makes absence meaningless: the new release can resolve anything lazily
    lazy = dict(NEW, **{"toylib/__init__.py": "def __getattr__(name):\n    raise AttributeError(name)\n"})
    r = _run_assess(root, OLD, lazy)
    assert r["status"] in ("unverified", "partial") and r["counts"]["unresolved"] >= 1 and not r["findings"]
    # C extension: the symbol is not Python source in the OLD release, so there is nothing to compare against
    cext = {"toylib/__init__.py": "from ._speedups import fast\n"}
    r = _run_assess(_project(tmp_path, {"app.py": "import toylib\ntoylib.fast(1)\n"}, "p2"), cext, cext)
    assert r["status"] == "unverified" and r["counts"]["verified"] <= 1
    cap = compat.assess(root, [_plan("a", "1", "2"), _plan("b", "1", "2")], comps, provider=prov, max_plans=1)
    assert [p["status"] for p in cap["plans"]][1] == "unverified" and "budget" in cap["plans"][1]["reason"]
    for res in (off, npm, noart, cap):
        assert res["held"] == {} and all(p["status"] != "compatible" for p in res["plans"])


def test_transitive_only_package_is_not_direct_and_partial_when_some_symbols_are_unknown(tmp_path):
    """AC: BSA-AC-633. A package the project never imports is `not_direct` (only the pin check applies); a package whose used symbols are only
    partly resolvable is `partial` with the coverage fraction - 2 of 2 statuses."""
    root = _project(tmp_path, {"app.py": "import os\nos.getcwd()\n"})
    r = _run_assess(root, OLD, NEW)
    assert r["status"] == "not_direct" and r["counts"]["used"] == 0
    root2 = _project(tmp_path, {"app.py": "import toylib\ntoylib.fetch('x')\ntoylib.generated_at_runtime(1)\n"}, "p3")
    r2 = _run_assess(root2, OLD, OLD)
    assert r2["status"] == "partial" and 0 < r2["coverage"] < 1 and r2["counts"]["unresolved"] == 1


# ============================================================================================ AC-634: the gate in the patch loop
def _world_repo(make_repo, world, files: Optional[Dict[str, str]] = None):
    app = _d('''
        import requests
        import yaml
        from flask import Flask

        requests.get("https://example.invalid", timeout=3)
        cfg = yaml.load("a: 1")
        app = Flask(__name__)
    ''')
    repo = make_repo({"requirements.txt": REQ3, "app.py": app, **(files or {})})
    ana = engine.analyze(repo, scanner=FakeScanner())
    plans = remediate.plan(ana["components"], ana["vulns"])
    remediate.verify(plans)
    return repo, {"components": ana["components"], "vulns": ana["vulns"], "plans": plans}


def _releases(yaml_new_loader_required: bool = True) -> FakeProvider:
    req = {"requests/__init__.py": "def get(url, params=None, **kwargs):\n    pass\n"}
    flask = {"flask/__init__.py": "class Flask:\n    def __init__(self, import_name):\n        pass\n"}
    yaml_old = {"yaml/__init__.py": "def load(stream, Loader=None):\n    pass\n"}
    yaml_new = {"yaml/__init__.py": "def load(stream, Loader):\n    pass\n" if yaml_new_loader_required else "def load(stream, Loader=None):\n    pass\n"}
    return FakeProvider({("requests", "2.19.1"): req, ("requests", "2.31.0"): req, ("flask", "0.12"): flask, ("flask", "1.0.1"): flask,
                         ("pyyaml", "3.12"): yaml_old, ("pyyaml", "5.4"): yaml_new})


def test_block_mode_holds_only_the_breaking_upgrade_and_applies_the_rest(make_repo, world):
    """AC: BSA-AC-634. requests and flask are compatible, pyyaml 5.4 makes Loader required while the project calls yaml.load("a: 1"): the loop
    applies 2 of 3 upgrades, the pyyaml line in requirements.txt is untouched, the result row says `held` with the call site, the
    approval digest is the one computed over all 3 plans, and the review names the held package without rejecting."""
    repo, rec = _world_repo(make_repo, world)
    digest = patch.approval_digest(rec["plans"])
    out = pipeline._patch_loop(rec, repo, approved=True, token=digest, rounds=1, offline=True, scanner=FakeScanner(), verify_rounds=1,
                               compat_provider=_releases())
    text = open(os.path.join(repo, "requirements.txt"), encoding="utf-8").read()
    assert "pyyaml==3.12" in text and "requests==2.31.0" in text and "flask==1.0.1" in text
    rows = {r["component"]: r for ro in out["rounds"] for r in ro["results"]}
    assert rows["pyyaml"]["status"] == "held" and "app.py:" in rows["pyyaml"]["detail"] and rows["pyyaml"]["detail"].startswith("compat:")
    assert rows["requests"]["status"] == "applied" and rows["flask"]["status"] == "applied"
    assert out["status"] == "applied" and out["rounds"][0]["held"] == 1 and out["rounds"][0]["applied"] == 2
    assert list(out["compat"]["held"]) == ["pypi|pyyaml|3.12"] and out["compat"]["summary"]["held"] == 1
    assert out["compat"]["summary"]["breaking"] == 1 and out["compat"]["summary"]["compatible"] == 2
    held_rule = [f for f in out["review"]["findings"] if f["rule"] == "RV-COMPAT-HELD"]
    assert held_rule and out["review"]["verdict"] in ("approve", "changes_requested")      # held is informational, never a reject
    assert not [f for f in out["review"]["findings"] if f["rule"] == "RV-COMPAT-BREAKING"]


def test_when_every_upgrade_is_held_nothing_is_written_and_the_status_says_so(make_repo, world):
    """AC: BSA-AC-634. All 3 plans breaking -> status compat_held, 0 files changed, the manifest byte-identical, and the note points at the evidence."""
    repo, rec = _world_repo(make_repo, world)
    before = open(os.path.join(repo, "requirements.txt"), encoding="utf-8").read()
    prov = _releases()
    prov.releases[("requests", "2.31.0")] = {"requests/__init__.py": "def get(url, params=None):\n    pass\n"}   # kwargs gone: timeout= rejected
    prov.releases[("flask", "1.0.1")] = {"flask/__init__.py": "class Flask:\n    def __init__(self, import_name, extra):\n        pass\n"}
    out = pipeline._patch_loop(rec, repo, approved=True, token=None, rounds=1, offline=True, scanner=FakeScanner(), verify_rounds=1, compat_provider=prov)
    assert out["status"] == "compat_held" and out["applied_components"] == 0 and "held back" in out["note"]
    assert open(os.path.join(repo, "requirements.txt"), encoding="utf-8").read() == before
    assert out["compat"]["summary"]["held"] == 3


def test_warn_mode_applies_everything_and_the_review_rejects_the_breaking_one(make_repo, world):
    """AC: BSA-AC-634. `warn` reports without holding: pyyaml IS applied, the review carries RV-COMPAT-BREAKING and the verdict is reject
    (2 of 2 rules: nothing held, one reject finding)."""
    repo, rec = _world_repo(make_repo, world)
    out = pipeline._patch_loop(rec, repo, approved=True, token=None, rounds=1, offline=True, scanner=FakeScanner(), verify_rounds=1,
                               compat_mode="warn", compat_provider=_releases())
    assert "pyyaml==5.4" in open(os.path.join(repo, "requirements.txt"), encoding="utf-8").read()
    assert out["compat"]["held"] == {}
    assert out["review"]["verdict"] == "reject" and any(f["rule"] == "RV-COMPAT-BREAKING" for f in out["review"]["findings"])


def test_off_mode_never_touches_the_provider_and_a_failing_assessment_never_stops_the_loop(make_repo, world):
    """AC: BSA-AC-634. `off` makes 0 provider calls; a provider that raises is recorded in compat_error as unverified plans and the patch still applies
    all 3 upgrades (the gate can hold a package back, it can never take the loop down)."""
    repo, rec = _world_repo(make_repo, world)
    prov = _releases()
    out = pipeline._patch_loop(rec, repo, approved=True, token=None, rounds=1, offline=True, scanner=FakeScanner(), verify_rounds=1,
                               compat_mode="off", compat_provider=prov)
    assert prov.calls == [] and out["status"] == "applied" and "compat" not in out

    class Boom(FakeProvider):
        def artifact(self, name, version):
            raise RuntimeError("provider exploded")
    repo2, rec2 = _world_repo(make_repo, world, {})
    out2 = pipeline._patch_loop(rec2, repo2, approved=True, token=None, rounds=1, offline=True, scanner=FakeScanner(), verify_rounds=1,
                                compat_provider=Boom({}))
    assert out2["status"] == "applied" and out2["applied_components"] == 3
    assert out2["compat"]["summary"]["unverified"] == 3 and all("RuntimeError" in p["reason"] for p in out2["compat"]["plans"])


def test_the_plan_a_reviewer_approves_already_carries_the_measured_compatibility(make_repo, world):
    """AC: BSA-AC-634. Without approval nothing is written, but every plan row carries `compat` (status, reason, findings) so the human sees the
    break BEFORE approving: 3 plans annotated, the digest unchanged by the annotation."""
    repo, rec = _world_repo(make_repo, world)
    digest_before = patch.approval_digest(rec["plans"])
    out = pipeline._patch_loop(rec, repo, approved=False, token=None, rounds=1, offline=True, scanner=FakeScanner(), verify_rounds=1,
                               compat_provider=_releases())
    assert out["status"] == "not_approved" and out["digest"] == digest_before == patch.approval_digest(rec["plans"])
    by = {p["component"]: p for p in out["plans"]}
    assert by["pyyaml"]["compat"]["status"] == "breaking" and by["requests"]["compat"]["status"] == "compatible"
    assert by["pyyaml"]["compat"]["findings"][0]["sites"][0]["file"] == "app.py"
    assert open(os.path.join(repo, "requirements.txt"), encoding="utf-8").read() == REQ3


def test_review_rules_over_measured_compatibility_and_runtime():
    """AC: BSA-AC-634. review() over compat/runtime records: 6 of 6 rules - held informational, applied breaking rejects, applied review asks for changes,
    unverified informational, runtime regression rejects, no compat argument leaves the old verdict untouched."""
    base = dict(plan_digest="d", changed_files=["requirements.txt"], planned_manifests=["requirements.txt"], diff_stats={"lines_changed": 2},
                impact={"verdict": "clean", "summary": "ok"}, plan_summary={"major_bumps": 0})
    assert review.review(**base)["verdict"] == "approve"
    plans = lambda *st: {"plans": [{"component": "p%d" % i, "from": "1", "to": "2", "status": s, "key": "pypi|p%d|1" % i} for i, s in enumerate(st)], "held": {}}   # noqa: E731
    held = {"plans": [{"component": "p", "from": "1", "to": "2", "status": "breaking", "key": "pypi|p|1"}], "held": {"pypi|p|1": "x"}}
    r = review.review(**base, compat=held)
    assert r["verdict"] == "approve" and [f["rule"] for f in r["findings"]] == ["RV-COMPAT-HELD"]
    assert review.review(**base, compat=plans("breaking"))["verdict"] == "reject"
    assert review.review(**base, compat=plans("review"))["verdict"] == "changes_requested"
    unv = review.review(**base, compat=plans("unverified", "compatible"))
    assert unv["verdict"] == "approve" and [f["rule"] for f in unv["findings"]] == ["RV-COMPAT-UNVERIFIED"]
    rt = review.review(**base, compat_runtime={"baseline": {"status": "ready"}, "after": {"status": "regression", "reason": "2 tests regressed"}})
    assert rt["verdict"] == "reject" and rt["findings"][0]["rule"] == "RV-RUNTIME-REGRESSION"


# ============================================================================================ AC-635: runtime differential
def _local_wheel(wheel_dir, name: str, version: str, files: Dict[str, str]) -> None:
    di = "%s-%s.dist-info" % (name, version)
    members = dict(files)
    members[di + "/METADATA"] = "Metadata-Version: 2.1\nName: %s\nVersion: %s\n" % (name, version)
    members[di + "/WHEEL"] = "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    members[di + "/RECORD"] = "".join("%s,,\n" % n for n in list(members) + [di + "/RECORD"])
    with zipfile.ZipFile(str(wheel_dir / ("%s-%s-py3-none-any.whl" % (name, version))), "w") as zf:
        for n, t in members.items():
            zf.writestr(n, t)


def _rt_project(tmp_path, wheel_dir, *, greet_v2: str) -> str:
    """A project whose unittest suite exercises `toylib`; v2.0 keeps every signature but may change what greet() returns."""
    _local_wheel(wheel_dir, "toylib", "1.0", {"toylib/__init__.py": "def add(a, b):\n    return a + b\ndef greet(n):\n    return 'hi ' + n\n"})
    _local_wheel(wheel_dir, "toylib", "2.0", {"toylib/__init__.py": "def add(a, b):\n    return a + b\ndef greet(n):\n    return %s + n\n" % greet_v2})
    return _project(tmp_path, {
        "requirements.txt": "toylib==1.0\n", "tests/__init__.py": "",
        "tests/test_app.py": _d('''
            import unittest, toylib
            class T(unittest.TestCase):
                def test_add(self):
                    self.assertEqual(toylib.add(1, 2), 3)
                def test_greet(self):
                    self.assertEqual(toylib.greet("a"), "hi a")
        ''')}, "rtproj")


def _patched(root: str) -> None:
    with open(os.path.join(root, "requirements.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("toylib==2.0\n")


def test_runtime_differential_flags_a_behaviour_change_the_static_gate_cannot_see(tmp_path):
    """AC: BSA-AC-635. toylib 2.0 keeps every signature (the static gate says compatible) but greet() now says 'hello': the project's own
    test that passed on 1.0 fails on 2.0 -> `regression` naming that test; the second test, unchanged, is not blamed (1 of 2)."""
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    root = _rt_project(tmp_path, wheels, greet_v2="'hello '")
    sig_same = compat.assess(root, [_plan("toylib", "1.0", "2.0")], [_comp("toylib", "1.0")], provider=FakeProvider(
        {("toylib", "1.0"): {"toylib/__init__.py": "def add(a, b): pass\ndef greet(n): pass\n"},
         ("toylib", "2.0"): {"toylib/__init__.py": "def add(a, b): pass\ndef greet(n): pass\n"}}))
    assert sig_same["plans"][0]["status"] in ("not_direct", "compatible")                 # tests import toylib; no breaking static finding
    diff = compat_runtime.Differential(root, ["requirements.txt"], pip_args=["--no-index", "--find-links", str(wheels)])
    try:
        base = diff.baseline()
        assert base["status"] == "ready" and base["ran"] == 2 and base["passed"] == 2 and base["failed"] == 0
        _patched(root)
        res = diff.after()
    finally:
        diff.close()
    assert res["status"] == "regression" and len(res["regressions"]) == 1 and "test_greet" in res["regressions"][0]
    assert res["after"]["passed"] == 1 and res["baseline"]["passed"] == 2


def test_runtime_differential_is_ok_when_the_tests_keep_passing_and_the_loop_reverts_on_a_regression(make_repo, world, tmp_path):
    """AC: BSA-AC-635. Through the real loop with compat_runtime=True: (a) a behaviour-preserving 5.4 -> status applied, runtime `ok`; (b) a
    behaviour-changing 5.4 -> status compat_runtime_reverted, requirements.txt back at 3.12 and the review rejects (2 of 2)."""
    def build(name, yaml_ret):
        wheels = tmp_path / ("w_" + name)
        wheels.mkdir()
        _local_wheel(wheels, "pyyaml", "3.12", {"yaml/__init__.py": "def safe(x):\n    return 'ok:' + x\n"})
        _local_wheel(wheels, "pyyaml", "5.4", {"yaml/__init__.py": "def safe(x):\n    return %s + x\n" % yaml_ret})
        repo = make_repo({"requirements.txt": "pyyaml==3.12\n", "tests/__init__.py": "",
                          "tests/test_y.py": "import unittest, yaml\nclass T(unittest.TestCase):\n    def test_safe(self):\n        self.assertEqual(yaml.safe('a'), 'ok:a')\n"},
                         name="rt_" + name)
        ana = engine.analyze(repo, scanner=FakeScanner())
        plans = remediate.plan(ana["components"], ana["vulns"])
        remediate.verify(plans)
        return repo, {"components": ana["components"], "vulns": ana["vulns"], "plans": plans}, ["--no-index", "--find-links", str(wheels)]

    repo, rec, pip_args = build("same", "'ok:'")
    out = pipeline._patch_loop(rec, repo, approved=True, token=None, rounds=1, offline=True, scanner=FakeScanner(), verify_rounds=1,
                               compat_mode="off", compat_runtime=True, compat_pip_args=pip_args)
    assert out["status"] == "applied" and out["compat_runtime"]["after"]["status"] == "ok"
    assert "pyyaml==5.4" in open(os.path.join(repo, "requirements.txt"), encoding="utf-8").read()

    repo, rec, pip_args = build("changed", "'changed:'")
    out = pipeline._patch_loop(rec, repo, approved=True, token=None, rounds=1, offline=True, scanner=FakeScanner(), verify_rounds=1,
                               compat_mode="off", compat_runtime=True, compat_pip_args=pip_args)
    assert out["status"] == "compat_runtime_reverted" and "test_safe" in out["note"]
    assert open(os.path.join(repo, "requirements.txt"), encoding="utf-8").read() == "pyyaml==3.12\n"
    assert out["review"]["verdict"] == "reject" and any(f["rule"] == "RV-RUNTIME-REGRESSION" for f in out["review"]["findings"])


def test_runtime_differential_is_unverified_without_tests_a_runner_or_a_baseline_and_runs_with_a_minimal_env(tmp_path, monkeypatch):
    """AC: BSA-AC-635. Honest unverified, never ok: no tests, no requirements file, unparseable baseline - 3 of 3 - and the test process env carries
    none of the 2 secrets planted in the parent while pip steps still see the proxy variable."""
    empty = _project(tmp_path, {"requirements.txt": "toylib==1.0\n", "app.py": "x = 1\n"}, "notests")
    assert compat_runtime.detect_runner(empty) is None
    d = compat_runtime.Differential(empty, ["requirements.txt"])
    try:
        assert d.baseline()["status"] == "unverified" and "no test runner" in d.baseline()["reason"]
    finally:
        d.close()
    withtests = _project(tmp_path, {"test_a.py": "import unittest\nclass T(unittest.TestCase):\n    def test_x(self):\n        pass\n"}, "noreq")
    d2 = compat_runtime.Differential(withtests, [])
    try:
        assert "requirements" in d2.baseline()["reason"]
        assert d2.after()["status"] == "unverified"
    finally:
        d2.close()
    monkeypatch.setenv("MY_SECRET_TOKEN", "s3cret")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    test_env, pip_env = compat_runtime._env(False), compat_runtime._env(True)
    assert "MY_SECRET_TOKEN" not in test_env and "OPENAI_API_KEY" not in test_env and "MY_SECRET_TOKEN" not in pip_env
    assert "HTTPS_PROXY" not in test_env and pip_env.get("HTTPS_PROXY") == "http://proxy.invalid:3128"
    assert compat_runtime.requirement_files([_plan("a", "1", "2", files=["requirements-dev.txt", "package.json"])]) == ["requirements-dev.txt"]


def test_test_result_parsers_and_runner_detection():
    """AC: BSA-AC-635. pytest -rA and unittest -v output parsed into passed/failed sets (4 of 4 line shapes), pytest chosen by config or import."""
    py = "PASSED tests/test_a.py::test_x\nFAILED tests/test_a.py::test_y - assert 1 == 2\nERROR tests/test_b.py::test_z\nSKIPPED [1] x\n"
    r = compat_runtime.parse_results("pytest", py)
    assert r["passed"] == {"tests/test_a.py::test_x"} and r["failed"] == {"tests/test_a.py::test_y", "tests/test_b.py::test_z"}
    ut = "test_a (tests.test_x.T.test_a) ... ok\ntest_b (tests.test_x.T.test_b) ... FAIL\ntest_c (tests.test_x.T.test_c) ... skipped 'no'\n"
    u = compat_runtime.parse_results("unittest", ut)
    assert u["passed"] == {"test_a (tests.test_x.T.test_a)"} and u["failed"] == {"test_b (tests.test_x.T.test_b)"}
    assert sys.version_info >= (3, 8)


# ============================================================================================ AC-636: the console shows it
def test_patch_pane_shows_measured_compatibility_held_rounds_and_the_runtime_verdict():
    """AC: BSA-AC-636. The patch pane renders the gate: a Compat column on both plan tables, a Held column per round, the findings table with the
    exact rule and call site, the compat_held / compat_runtime_reverted outcomes and the runtime verdict (5 of 5 surfaces); the two
    pure renderers are executed under Node (skipped when Node is absent): partial shows its coverage, breaking is `bad`."""
    import re
    import shutil
    import subprocess
    web = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "bts_sbom_app", "web")
    src = open(os.path.join(web, "bts_console.js"), encoding="utf-8").read()
    assert src.count("'Compat (measured)'") == 2 and "compatPill(p.compat)" in src and "compatEvidence(p.plans)" in src
    assert "'Held'" in src and "compat_runtime_reverted" in src and "were held back</b>" in src and "Runtime differential" in src
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    m = re.search(r"function compatPill\(c\).*?(?=\n  function fixPlan)", src, re.S)
    assert m
    js = ("function pill(t,c){return '['+c+':'+t+']';}\nfunction heading(t,s){return '#'+t;}\nfunction note(h,c){return 'NOTE';}\n"
          "function table(h,r){return JSON.stringify(r);}\n" + m.group(0) + "\n"
          "console.log(compatPill({status:'partial',coverage:0.5}), compatPill({status:'breaking',coverage:0.8}), compatPill(null), compatPill({status:'compatible',coverage:1}));\n"
          "console.log(compatEvidence([{component:'pyyaml',compat:{findings:[{level:'breaking',rule:'CMP-CALL',detail:'app.py:6 rejected'}]}}]));\n"
          "console.log(JSON.stringify(compatEvidence([{component:'x',compat:{findings:[]}}])));\n")
    out = subprocess.run([node, "-e", js], capture_output=True, text=True, encoding="utf-8", timeout=30).stdout.splitlines()
    assert out[0] == "[warn:partial 50%] [bad:breaking 80%] — [ok:compatible 100%]"
    assert "CMP-CALL" in out[1] and "[bad:breaking]" in out[1] and "app.py:6 rejected" in out[1]
    assert out[2] == '""'


# ============================================================================================ hardening found in self-review
def test_a_gzip_bomb_sdist_is_refused_before_it_inflates(monkeypatch):
    """AC: BSA-AC-631. A tar.gz whose stream inflates past the cap is refused (1 of 1 bomb, 2 of 2 unsupported codecs); the provider turns that
    into 'no archive' (unverified) instead of burning CPU or memory."""
    import gzip
    monkeypatch.setattr(compat, "MAX_UNCOMPRESSED", 1_000_000)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as g:
        g.write(b"\0" * 5_000_000)                                                           # 5 MB of zeros compresses to ~5 KB
    with pytest.raises(ValueError, match="inflates past"):
        compat.parse_archive(buf.getvalue(), "bomb-1.0.tar.gz", "sdist")
    for magic in (b"BZh9" + b"\0" * 20, b"\xfd7zXZ\x00" + b"\0" * 20):
        with pytest.raises(ValueError, match="unsupported"):
            compat.parse_archive(magic, "x-1.0.tar.bz2", "sdist")


def test_a_decorated_function_downgrades_a_rejected_call_to_review(tmp_path):
    """AC: BSA-AC-630. A function wrapped by an unknown decorator (click.command / app.route shape) can have a different runtime signature than its
    source: the same rejected call is `review` (CMP-CALL-DECORATED), while a transparent decorator (lru_cache) and a plain function stay
    `breaking` (3 of 3 shapes)."""
    old = {"lib/__init__.py": _d('''
        import functools
        def deco(f):
            return f
        @deco
        def wrapped(a, b=1):
            pass
        @functools.lru_cache(maxsize=None)
        def cached(a, b=1):
            pass
        def plain(a, b=1):
            pass
    ''')}
    new = {"lib/__init__.py": old["lib/__init__.py"].replace("(a, b=1)", "(a)")}
    root = _project(tmp_path, {"app.py": "import lib\nlib.wrapped(1, 2)\nlib.cached(1, 2)\nlib.plain(1, 2)\n"})
    r = _run_assess(root, old, new, name="lib")
    rule = {f["symbol"]: f["rule"] for f in r["findings"]}
    assert rule == {"lib.wrapped": "CMP-CALL-DECORATED", "lib.cached": "CMP-CALL", "lib.plain": "CMP-CALL"}
    assert {f["symbol"]: f["level"] for f in r["findings"]}["lib.wrapped"] == "review"


def test_the_assessment_budget_also_bounds_the_pin_constraint_loop(tmp_path, monkeypatch):
    """AC: BSA-AC-633. The deadline is enforced INSIDE a plan, not only between plans: a clock that jumps past the budget while the target's metadata
    is fetched stops the 30-package metadata loop (1 meta call, 0 archive calls) and the plan is unverified with the budget as the reason."""
    root = _project(tmp_path, {"app.py": "import toylib\ntoylib.fetch('x')\n"})
    clock = [0.0]
    monkeypatch.setattr(compat.time, "monotonic", lambda: clock[0])

    class SlowProvider(FakeProvider):
        def meta(self, name, version):
            r = super().meta(name, version)
            if (name, version) == ("toylib", "2.0"):
                clock[0] += 100.0                                                             # the target's metadata took longer than the whole budget
            return r
    prov = SlowProvider({("toylib", "1.0"): OLD, ("toylib", "2.0"): NEW})
    comps = [_comp("toylib", "1.0")] + [_comp("dep%d" % i, "1.0") for i in range(30)]
    res = compat.assess(root, [_plan("toylib", "1.0", "2.0")], comps, provider=prov, budget_s=50.0)
    p = res["plans"][0]
    assert p["status"] == "unverified" and "budget" in p["reason"] and res["held"] == {}
    assert [c for c in prov.calls if c[0] == "meta"] == [("meta", "toylib", "2.0")]
    assert not [c for c in prov.calls if c[0] == "artifact"]
    # a budget that is already spent before the first plan makes 0 provider calls at all
    prov2 = FakeProvider({("toylib", "1.0"): OLD, ("toylib", "2.0"): NEW})
    clock[0] = 0.0
    compat.assess(root, [_plan("toylib", "1.0", "2.0")], comps, provider=prov2, budget_s=-1.0)
    assert prov2.calls == []


def _installed_artifact(dist: str):
    """The REAL source of an installed distribution as a compat.Artifact (skips the test when it is not installed)."""
    import importlib.metadata as md
    try:
        d = md.distribution(dist)
    except md.PackageNotFoundError:
        pytest.skip("%s is not installed" % dist)
    base, tree, meta = str(d.locate_file("")), {}, {}
    for f in d.files or []:
        s = str(f).replace("\\", "/")
        if s.endswith(".py") and not s.startswith(".."):
            with open(os.path.join(base, s), encoding="utf-8", errors="replace") as fh:
                tree[s] = fh.read()
        elif s.endswith("top_level.txt"):
            with open(os.path.join(base, s), encoding="utf-8", errors="replace") as fh:
                meta["top_level.txt"] = fh.read()
    return d.version, compat.Artifact(tree, meta, "wheel", dist)


def test_real_package_sources_reproduce_known_upgrade_breaks_and_do_not_crash():
    """AC: BSA-AC-630. Real installed sources (skipped when absent): PyYAML >= 6 REALLY requires Loader, so yaml.load(stream) is rejected; Jinja2 >= 3.1
    REALLY dropped jinja2.Markup (missing) while a lazily provided name is `dynamic`, not a false 'removed'; requests resolves a method through
    its class and a re-export; 0 unparsed files on 4 of 4 real packages (the surface builder survives decorators, star imports, __getattr__)."""
    ver, art = _installed_artifact("pyyaml")
    if int(ver.split(".")[0]) < 6:
        pytest.skip("PyYAML < 6")
    surf = compat.build_surface(art, compat.import_roots(art, "pyyaml"))
    sig = compat._sig_of(surf, surf.resolve("yaml.load").member)[1]
    assert compat.call_problems(sig, {"npos": 1, "kw": [], "star": False, "dstar": False}) == ["required parameter 'Loader' is not supplied"]
    assert compat.call_problems(sig, {"npos": 1, "kw": ["Loader"], "star": False, "dstar": False}) == []
    assert surf.unparsed == 0
    jver, jart = _installed_artifact("jinja2")
    if tuple(int(x) for x in jver.split(".")[:2]) >= (3, 1):
        js = compat.build_surface(jart, ["jinja2"])
        assert js.resolve("jinja2.Environment").status == "found" and js.resolve("jinja2.Markup").status == "missing"
        assert js.unparsed == 0
    _, rart = _installed_artifact("requests")
    rs = compat.build_surface(rart, ["requests"])
    assert rs.resolve("requests.get").status == "found" and rs.resolve("requests.Session.get").status == "found"
    assert rs.resolve("requests.adapters.HTTPAdapter").member.kind == "class" and rs.resolve("requests.definitely_not_there").status == "missing"
    _, cart = _installed_artifact("click")
    cs = compat.build_surface(cart, ["click"])
    assert cs.unparsed == 0 and cs.modules["click"].dynamic is True                       # click lazily provides deprecated names
    assert cs.resolve("click.some_lazily_provided_name").status == "dynamic"              # absence there proves nothing
