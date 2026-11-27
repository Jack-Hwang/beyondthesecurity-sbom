"""C / C++ side of the patch compatibility gate (compat_c.py, reached through compat.assess for non-Python upgrades).

Header trees come from local directories or local git repositories (tags), so nothing touches the network; the compiler differential runs the real
gcc/g++ and is skipped when none is on PATH.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
from typing import Any, Dict

import pytest

from bts_sbom_app import compat, compat_c, cparse

TC = compat_c._toolchain()
needs_cc = pytest.mark.skipif(not TC["cc"], reason="no C compiler on PATH")


def _w(root: str, rel: str, text: str) -> None:
    fp = os.path.join(root, rel)
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    with open(fp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(textwrap.dedent(text).lstrip("\n"))


OLD_H = '''
    #ifndef FOO_H
    #define FOO_H
    #define FOO_OK 0
    #define FOO_FLAG_A 1
    #define FOO_OLD_MACRO(x) ((x)+1)
    #define FOO_PAIR(a, b) ((a) + (b))
    typedef struct foo_ctx { int refs; char name[16]; int legacy; } foo_ctx;
    enum foo_mode { FOO_FAST = 1, FOO_SLOW = 2, FOO_OLD = 3 };
    int foo_open(foo_ctx *c, const char *name);
    int foo_read(foo_ctx *c, char *buf, int len);
    void foo_close(foo_ctx *c);
    int foo_removed(int x);
    int foo_ret(int x);
    int foo_type(int x, const char *s);
    extern int foo_verbose;
    #endif
'''
NEW_H = '''
    #ifndef FOO_H
    #define FOO_H
    #define FOO_OK 0
    #define FOO_FLAG_A 2
    #define FOO_PAIR(a, b, c) ((a) + (b) + (c))
    typedef struct foo_ctx { char name[16]; int refs; } foo_ctx;
    enum foo_mode { FOO_FAST = 1, FOO_SLOW = 4 };
    int foo_open(foo_ctx *c, const char *name);
    int foo_read(foo_ctx *c, char *buf, int len, int flags);
    void foo_close(foo_ctx *c);
    long foo_ret(int x);
    int foo_type(int x, unsigned long s);
    #endif
'''
APP_C = '''
    #include <foo.h>
    int main(void) {
        foo_ctx c;
        char b[8];
        int m = FOO_OLD;
        int f = FOO_FLAG_A;
        int y = FOO_OLD_MACRO(2);
        int p = FOO_PAIR(1, 2);
        foo_open(&c, "x");
        foo_read(&c, b, 8);
        if (c.legacy) { return 1; }
        foo_removed(3);
        foo_verbose = 1;
        foo_ret(1);
        foo_type(1, "s");
        foo_close(&c);
        return m + f + y + p;
    }
'''


def _libs(tmp_path, old_h: str = OLD_H, new_h: str = NEW_H, app: str = APP_C):
    base = str(tmp_path)
    _w(base, "foo-1.0/include/foo.h", old_h)
    _w(base, "foo-2.0/include/foo.h", new_h)
    _w(base, "app/src/main.c", app)
    prov = compat_c.DirProvider({("foo", "1.0"): os.path.join(base, "foo-1.0"), ("foo", "2.0"): os.path.join(base, "foo-2.0")})
    return os.path.join(base, "app"), prov


def _plan(eco: str = "conan") -> Dict[str, Any]:
    return {"component": "foo", "ecosystem": eco, "current_version": "1.0", "safe_version": "2.0", "status": "upgrade", "breaking_risk": "high", "files": ["conanfile.txt"]}


def _assess(root: str, prov: Any, **kw: Any) -> Dict[str, Any]:
    res = compat.assess(root, [_plan()], [{"name": "foo", "version": "1.0", "ecosystem": "conan"}], c_provider=prov, **kw)
    return res["plans"][0] | {"_held": res["held"], "_summary": res["summary"]}


# ============================================================================================ the declaration diff
def test_header_diff_reports_each_kind_of_break_with_the_proving_call_site(tmp_path):
    """AC: BSA-AC-641. The project uses 14 symbols of a library; the target release removes a function, a macro, an enumerator and a variable, changes the argument count of
    a function and of a function-like macro the project calls, drops a struct field the project reads - each is a breaking finding naming its call site (7 of 7 kinds)."""
    root, prov = _libs(tmp_path)
    r = _assess(root, prov, compile_check=False)
    by = {(f["symbol"], f["rule"]) for f in r["findings"] if f["level"] == "breaking"}
    assert by == {("foo_removed", "CMP-C-REMOVED"), ("FOO_OLD_MACRO", "CMP-C-REMOVED"), ("FOO_OLD", "CMP-C-REMOVED"), ("foo_verbose", "CMP-C-REMOVED"),
                  ("foo_read", "CMP-C-CALL"), ("FOO_PAIR", "CMP-C-CALL"), ("foo_ctx", "CMP-C-FIELD")}
    read = next(f for f in r["findings"] if f["rule"] == "CMP-C-CALL" and f["symbol"] == "foo_read")
    assert "passes 3 argument(s)" in read["detail"] and "takes 4" in read["detail"] and read["sites"][0] == {"file": "src/main.c", "line": 10}
    fld = next(f for f in r["findings"] if f["rule"] == "CMP-C-FIELD")
    assert "`legacy`" in fld["detail"] and fld["sites"][0]["file"] == "src/main.c"
    assert r["status"] == "breaking" and r["_held"] == {"conan|foo|1.0": r["reason"]} and r["basis"] == "c-header-diff"


def test_changed_types_values_and_layouts_are_review_not_breaking(tmp_path):
    """AC: BSA-AC-641. Things that still compile but change meaning are `review`: a constant's value (FOO_FLAG_A 1 -> 2), a parameter type (const char* -> unsigned long), a
    return type (int -> long) - and the struct whose layout changed is flagged only when the project does not already break on a removed field (4 of 4)."""
    root, prov = _libs(tmp_path)
    r = _assess(root, prov, compile_check=False)
    rev = {(f["symbol"], f["rule"]) for f in r["findings"] if f["level"] == "review"}
    assert ("FOO_FLAG_A", "CMP-C-VALUE") in rev and ("foo_type", "CMP-C-TYPE") in rev and ("foo_ret", "CMP-C-RET") in rev
    layout_only = NEW_H.replace("typedef struct foo_ctx { char name[16]; int refs; } foo_ctx;", "typedef struct foo_ctx { char name[16]; int refs; int legacy; } foo_ctx;")
    root2, prov2 = _libs(tmp_path / "second", OLD_H, layout_only, APP_C.replace("c.legacy", "c.refs"))
    r2 = _assess(root2, prov2, compile_check=False)
    assert ("foo_ctx", "CMP-C-LAYOUT") in {(f["symbol"], f["rule"]) for f in r2["findings"]}                # reordered fields: ABI review


def test_appended_fields_and_an_identical_release_are_compatible_with_zero_findings(tmp_path):
    """AC: BSA-AC-641. Negative controls: the very same headers -> 0 findings, coverage 1.0; a struct that only GAINED fields at its end and a prototype that kept its
    shape -> still no finding (2 of 2)."""
    root, prov = _libs(tmp_path, OLD_H, OLD_H)
    r = _assess(root, prov, compile_check=False)
    assert r["findings"] == [] and r["status"] == "compatible" and r["coverage"] == 1.0
    appended = OLD_H.replace("int legacy; }", "int legacy; int extra; }")
    root2, prov2 = _libs(tmp_path / "b", OLD_H, appended)
    assert _assess(root2, prov2, compile_check=False)["findings"] == []


def test_cplusplus_headers_are_read_with_namespaces_and_overloads(tmp_path):
    """AC: BSA-AC-641. C++ release pair: an overload set keeps working when ANY overload accepts the call's argument count; the call a removed overload used to accept
    is breaking; a function that moved into a namespace is still found by name (3 of 3)."""
    old = "namespace lib { int run(int a); int run(int a, int b); void gone(int x); }\n"
    new = "namespace lib { int run(int a); void gone2(int x); }\n"
    app = '#include <lib.hpp>\nint main() { lib::run(1); lib::run(1, 2); lib::gone(3); return 0; }\n'
    base = str(tmp_path)
    _w(base, "lib-1/lib.hpp", old)
    _w(base, "lib-2/lib.hpp", new)
    _w(base, "app/main.cpp", app)
    prov = compat_c.DirProvider({("foo", "1.0"): os.path.join(base, "lib-1"), ("foo", "2.0"): os.path.join(base, "lib-2")})
    r = _assess(os.path.join(base, "app"), prov, compile_check=False)
    rules = {(f["symbol"], f["rule"]) for f in r["findings"]}
    assert ("run", "CMP-C-CALL") in rules and ("gone", "CMP-C-REMOVED") in rules
    assert not [f for f in r["findings"] if f["symbol"] == "run" and "passes 1" in f["detail"]] and r["language"] == "c++"


# ============================================================================================ the compiler differential
@needs_cc
def test_compiler_differential_measures_errors_that_exist_only_with_the_new_headers(tmp_path):
    """AC: BSA-AC-642. The real compiler on the project's source: 0 errors against the old headers, >= 5 NEW errors against the new ones (undeclared enumerator/macro,
    too few arguments, missing member, undeclared function/variable) - each reported with file:line and gcc's own message as `CMP-C-COMPILE`."""
    root, prov = _libs(tmp_path)
    r = _assess(root, prov, compile_check=True)
    assert r["compile"]["available"] and r["compile"]["checked"] == 1 and r["compile"]["baseline_errors"] == 0 and r["compile"]["new_errors"] >= 5
    regs = r["compile"]["regressions"]
    msgs = " | ".join("%s:%d %s" % (x["file"], x["line"], x["message"]) for x in regs)
    assert "too few arguments to function 'foo_read'" in msgs and "no member named 'legacy'" in msgs and "'FOO_OLD' undeclared" in msgs
    assert "src/main.c:10 too few arguments" in msgs and any(f["rule"] == "CMP-C-COMPILE" for f in r["findings"])


@needs_cc
def test_errors_present_with_both_header_sets_cancel_out(tmp_path):
    """AC: BSA-AC-642. A project file that fails for reasons unrelated to the upgrade (an include of a header nobody has, a syntax slip) fails identically against old and new
    headers: 0 NEW errors, no finding, and the baseline error count shows what was ignored (1 of 1 cancelled error)."""
    app = '#include <foo.h>\n#include <nobody_has_this.h>\nint main(void) { foo_ctx c; foo_open(&c, "x"); return 0; }\n'
    root, prov = _libs(tmp_path, OLD_H, OLD_H, app)
    r = _assess(root, prov, compile_check=True)
    assert r["compile"]["baseline_errors"] >= 1 and r["compile"]["new_errors"] == 0 and r["findings"] == []
    assert r["status"] in ("compatible", "partial")


@needs_cc
def test_a_compatible_upgrade_is_confirmed_by_the_compiler(tmp_path):
    """AC: BSA-AC-642. The target adds a parameter with a default-less new function and keeps everything the project uses: the header diff finds nothing, the compiler
    compiles the project file against the new headers (checked 1, 0 new errors) and the verdict is compatible - the compiler is what lifts `partial` to `compatible`."""
    new = OLD_H.replace("int foo_removed(int x);", "int foo_added(int x);")
    app = '#include <foo.h>\nint main(void) { foo_ctx c; char b[4]; foo_open(&c, "x"); foo_read(&c, b, 4); foo_close(&c); return FOO_OK + FOO_FLAG_A; }\n'
    root, prov = _libs(tmp_path, OLD_H, new, app)
    r = _assess(root, prov, compile_check=True)
    assert r["findings"] == [] and r["compile"]["checked"] == 1 and r["compile"]["new_errors"] == 0 and r["status"] == "compatible" and "compiler differential" in r["reason"]


# ============================================================================================ honesty + dispatch
def test_thin_evidence_for_c_is_unverified_or_not_direct_never_compatible_and_never_holds(tmp_path):
    """AC: BSA-AC-643. 4 of 4 thin-evidence shapes: a C library with no header source provided, a provider that returns nothing for one release, a project that uses
    no symbol of the library, and an ecosystem the gate does not cover - none is `compatible`, none is held."""
    root, prov = _libs(tmp_path)
    none = compat.assess(root, [_plan()], [], c_provider=None)
    assert none["plans"][0]["status"] == "unverified" and "no header source was provided" in none["plans"][0]["reason"] and none["held"] == {}
    half = compat_c.DirProvider({("foo", "1.0"): os.path.join(os.path.dirname(root), "foo-1.0")})
    h = compat.assess(root, [_plan()], [], c_provider=half)
    assert h["plans"][0]["status"] == "unverified" and "no public headers" in h["plans"][0]["reason"] and h["held"] == {}
    _w(os.path.dirname(root), "other/src/x.c", "int main(void) { return 0; }\n")
    nd = compat.assess(os.path.join(os.path.dirname(root), "other"), [_plan()], [], c_provider=prov, mode="block", offline=False)
    assert nd["plans"][0]["status"] == "not_direct" and nd["held"] == {}
    rust = compat.assess(root, [dict(_plan("crates.io"), ecosystem="crates.io")], [], c_provider=prov)
    assert rust["plans"][0]["status"] == "unverified" and "not covered" in rust["plans"][0]["reason"]


def test_c_plans_dispatch_by_ecosystem_or_language_and_python_plans_are_untouched(tmp_path):
    """AC: BSA-AC-643. `compat.assess` routes a plan to the C backend by ecosystem name (conan/vcpkg/oss-fuzz/...) or by an explicit language field; PyPI plans in the same call still
    use the Python backend (provider untouched by the C one) - 3 of 3 routes."""
    root, prov = _libs(tmp_path)
    for eco in ("conan", "vcpkg", "OSS-Fuzz"):
        res = compat.assess(root, [_plan(eco)], [], c_provider=prov, compile_check=False)
        assert res["plans"][0]["basis"] == "c-header-diff", eco
    odd = dict(_plan("whatever"), language="c")
    assert compat.assess(root, [odd], [], c_provider=prov, compile_check=False)["plans"][0]["basis"] == "c-header-diff"
    assert compat.assess(root, [dict(odd, language="")], [], c_provider=prov)["plans"][0]["status"] == "unverified"


def _git(cwd: str, *args: str) -> None:
    subprocess.run(["git", "-C", cwd, "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


@pytest.mark.skipif(not shutil.which("git"), reason="git is not installed")
def test_git_provider_fetches_headers_from_release_tags_and_gates_the_upgrade(tmp_path):
    """AC: BSA-AC-644. A real (local) git repository with tags v1.0 and 2.0 (two tag spellings tried in order): GitProvider clones each shallowly, reads the public headers only
    (tests/ and docs/ skipped) and the gate holds the breaking upgrade; an unknown tag yields no headers -> unverified (3 of 3)."""
    repo = str(tmp_path / "foo.git")
    os.makedirs(repo)
    _git(repo, "init", "-q", "-b", "main")
    _w(repo, "include/foo.h", OLD_H)
    _w(repo, "tests/helper.h", "#define TEST_ONLY 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "one")
    _git(repo, "tag", "v1.0")
    _w(repo, "include/foo.h", NEW_H)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "two")
    _git(repo, "tag", "2.0")
    prov = compat_c.GitProvider(lambda name, ver: (repo, ["v" + ver, ver]))
    t1 = prov.headers("foo", "1.0")
    assert t1 is not None and list(t1) == ["include/foo.h"] and "foo_removed" in t1["include/foo.h"]
    app = _w(str(tmp_path), "app/src/main.c", APP_C)
    r = _assess(str(tmp_path / "app"), prov, compile_check=False)
    assert r["status"] == "breaking" and "conan|foo|1.0" in r["_held"]
    assert compat_c.GitProvider(lambda n, v: (repo, ["nope"])).headers("foo", "9.9") is None


def test_report_shape_is_the_same_as_the_python_backend_so_the_loop_and_the_ui_need_nothing_new(tmp_path):
    """AC: BSA-AC-644. The C result carries the same keys the patch loop, the review and the console read (status, reason, coverage, counts, findings with level/rule/symbol/sites,
    key) and attaches to the plan row as `plan['compat']` - 1 of 1 shape."""
    root, prov = _libs(tmp_path)
    plan = _plan()
    res = compat.assess(root, [plan], [], c_provider=prov, compile_check=False)
    compat.attach([plan], res)
    c = plan["compat"]
    assert {"status", "reason", "coverage", "counts", "findings", "basis"} <= set(c) and c["status"] == "breaking"
    assert {"symbol", "level", "rule", "detail", "sites"} <= set(c["findings"][0]) and res["plans"][0]["key"] == "conan|foo|1.0"


def test_the_compiler_runs_in_the_c_locale_so_its_diagnostics_use_ascii_quotes(monkeypatch, tmp_path):
    """AC: BSA-AC-642. gcc prints curly quotes under a UTF-8 locale (the CI runners' LANG=C.UTF-8) while the compile differential parses its diagnostics with ASCII-quote
    patterns, so the compiler must be called with LC_ALL=C - the first-use message then reads `'X' undeclared` instead of the curly-quoted form that matched nothing."""
    seen: Dict[str, Any] = {}

    def fake_run(cmd, **kw):
        seen["env"] = kw.get("env")
        return subprocess.CompletedProcess(cmd, 1, "", "a.c:1:1: error: 'X' undeclared (first use in this function)\n")

    monkeypatch.setattr(compat_c.subprocess, "run", fake_run)
    out = compat_c._errors("gcc", "a.c", str(tmp_path), [], "c")
    assert seen["env"] is not None and seen["env"]["LC_ALL"] == "C" and seen["env"]["LANGUAGE"] == "C"
    assert out == {("a.c", 1, "'X' undeclared (first use in this function)")}
