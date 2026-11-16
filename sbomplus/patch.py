"""Approved patching of dependency manifests (never the origin, never a lockfile hash).

Pipeline contract
  * ``apply()`` without ``approved=True`` changes 0 files and returns the plan (status ``not_approved``).
  * With approval it edits the MANIFEST that declares the dependency (requirements*.txt, package.json, go.mod,
    Cargo.toml, pom.xml, composer.json, Gemfile). Lockfiles are never hand-edited (their integrity hashes cannot be
    recomputed offline) - a ready-to-run regeneration command is returned instead (``manual_command``).
  * An upgrade that would violate an upper bound / needs a module-path change is reported as ``blocked``,
    never silently forced.
  * Each edit is a pure text function (unit-testable); results are committed on a fix branch of the work copy.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from . import engine, versions, workspace

Edit = Tuple[str, int, str]      # (new_text, n_changes, detail) ; detail starting with "blocked:" = refused


# ------------------------------------------------------------------ pure text edits
_REQ_LINE = re.compile(r"^(?P<pre>\s*)(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?\s*"
                       r"(?P<spec>(?:(?:===|==|~=|>=|<=|!=|>|<)\s*[^\s;#,]+\s*,?\s*)+)(?P<rest>.*)$")


def edit_requirements(text: str, name: str, new: str) -> Edit:
    canon = engine._canon("pypi", name)
    out: List[str] = []
    n = 0
    detail = ""
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        eol = line[len(body):]
        m = _REQ_LINE.match(body)
        if not m or engine._canon("pypi", m.group("name")) != canon:
            out.append(line)
            continue
        clauses = [c.strip() for c in m.group("spec").split(",") if c.strip()]
        new_clauses: List[str] = []
        blocked = ""
        for cl in clauses:
            mm = re.match(r"(===|==|~=|>=|<=|!=|>|<)\s*(\S+)$", cl)
            if not mm:
                new_clauses.append(cl)
                continue
            op, ver = mm.groups()
            if op in ("==", "==="):
                new_clauses.append("%s%s" % (op, new))
            elif op in (">=", "~=") and versions.compare(ver, new) < 0:
                new_clauses.append("%s%s" % (op, new))
            elif op == "<" and versions.compare(new, ver) >= 0:
                blocked = "upper bound <%s excludes %s" % (ver, new)
                new_clauses.append(cl)
            elif op == "<=" and versions.compare(new, ver) > 0:
                blocked = "upper bound <=%s excludes %s" % (ver, new)
                new_clauses.append(cl)
            else:
                new_clauses.append(cl)
        if blocked:
            detail = "blocked: " + blocked
            out.append(line)
            continue
        rewritten = "%s%s%s%s%s" % (m.group("pre"), m.group("name"), m.group("extras") or "", ",".join(new_clauses),
                                    (" " + m.group("rest").lstrip()) if m.group("rest").strip() else "")
        out.append(rewritten + eol)
        n += 1 if rewritten != body else 0
    return "".join(out), n, detail or ("%d line(s) updated" % n)


def _indent_of(text: str) -> str:
    m = re.search(r'\n([ \t]+)"', text)
    return m.group(1) if m else "  "


def _range_prefix(old: str) -> str:
    m = re.match(r"^\s*([\^~]|>=|=)?\s*v?\d", old or "")
    return (m.group(1) or "") if m and m.group(1) in ("^", "~") else ("^" if not old or not re.match(r"^\s*=?\s*v?\d", old) else "")


_NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def edit_package_json(text: str, name: str, new: str, *, lock_flavor: str = "npm") -> Edit:
    try:
        doc = json.loads(text)
    except ValueError as exc:
        return text, 0, "blocked: package.json is not valid JSON (%s)" % str(exc)[:60]
    n = 0
    where: List[str] = []
    for sec in _NPM_SECTIONS:
        d = doc.get(sec)
        if isinstance(d, dict) and name in d:
            old = str(d[name])
            if re.match(r"^(git|http|file|link|workspace|npm:|github:)", old):
                return text, 0, "blocked: %s uses a non-registry specifier %r" % (name, old[:40])
            d[name] = _range_prefix(old) + new
            n += 1
            where.append(sec)
    if n:
        pat = re.compile(r'("%s"\s*:\s*")([^"]*)(")' % re.escape(name))
        ind = _indent_of(text)
        # minimal-diff path: regex replace the version string inside the matched sections
        new_text = text
        for sec in where:
            m = re.search(r'"%s"\s*:\s*\{.*?\n?\s*\}' % sec, new_text, re.S)
            if m:
                block = m.group(0)
                nb = pat.sub(lambda mm: mm.group(1) + _range_prefix(mm.group(2)) + new + mm.group(3), block, count=1)
                new_text = new_text[:m.start()] + nb + new_text[m.end():]
        if new_text != text:
            return new_text, n, "direct dependency in " + ",".join(where)
        return json.dumps(doc, indent=ind, ensure_ascii=False) + ("\n" if text.endswith("\n") else ""), n, \
            "direct dependency in " + ",".join(where) + " (reformatted)"
    key = {"npm": "overrides", "yarn": "resolutions"}.get(lock_flavor, "overrides")
    if lock_flavor == "pnpm":
        pn = doc.setdefault("pnpm", {})
        ov = pn.setdefault("overrides", {})
    else:
        ov = doc.setdefault(key, {})
    if not isinstance(ov, dict):
        return text, 0, "blocked: %s is not an object" % key
    ov[name] = new
    return json.dumps(doc, indent=_indent_of(text), ensure_ascii=False) + ("\n" if text.endswith("\n") else ""), 1, \
        "transitive dependency pinned via %s (needs lockfile regeneration)" % ("pnpm.overrides" if lock_flavor == "pnpm" else key)


def edit_go_mod(text: str, module: str, new: str) -> Edit:
    ver = new if new.startswith("v") else "v" + new
    mj = versions.major(ver) or 0
    if mj >= 2 and not re.search(r"/v\d+$", module) and "gopkg.in" not in module:
        return text, 0, "blocked: v%d needs a module path change (%s/v%d) and import rewrites" % (mj, module, mj)
    pat = re.compile(r"^(\s*(?:require\s+)?)(%s)(\s+)(v[^\s]+)(.*)$" % re.escape(module), re.M)
    count = 0

    def sub(m: "re.Match[str]") -> str:
        nonlocal count
        if m.group(4) == ver:
            return m.group(0)
        count += 1
        return m.group(1) + m.group(2) + m.group(3) + ver + m.group(5)

    return pat.sub(sub, text), count, "%d require line(s) updated (run `go mod tidy` to refresh go.sum)" % count


def edit_cargo_toml(text: str, crate: str, new: str) -> Edit:
    n = 0

    def pref(old: str) -> str:
        m = re.match(r"^\s*(\^|~|=|>=)?", old)
        return (m.group(1) or "") if m else ""

    def s1(m: "re.Match[str]") -> str:
        nonlocal n
        n += 1
        return m.group(1) + pref(m.group(2)) + new + m.group(3)

    t = re.sub(r'(^\s*%s\s*=\s*")([^"]*)(")' % re.escape(crate), s1, text, flags=re.M)
    t = re.sub(r'(^\s*%s\s*=\s*\{[^}\n]*?\bversion\s*=\s*")([^"]*)(")' % re.escape(crate), s1, t, flags=re.M)
    t = re.sub(r'(\[(?:dev-|build-)?dependencies\.%s\][^\[]*?\bversion\s*=\s*")([^"]*)(")' % re.escape(crate), s1, t, flags=re.S)
    return t, n, "%d requirement(s) updated (run `cargo update -p %s` to refresh Cargo.lock)" % (n, crate)


def edit_pom_xml(text: str, ga: str, new: str) -> Edit:
    if ":" not in ga:
        return text, 0, "blocked: maven component name is not group:artifact"
    g, a = ga.split(":", 1)
    n = 0
    detail = ""
    prop_updates: List[Tuple[str, str]] = []

    def sub(m: "re.Match[str]") -> str:
        nonlocal n, detail
        blk = m.group(0)
        if "<groupId>%s</groupId>" % g not in blk or "<artifactId>%s</artifactId>" % a not in blk:
            return blk
        vm = re.search(r"<version>\s*([^<]*?)\s*</version>", blk)
        if not vm:
            detail = "manual: version is managed by a parent/BOM - add a dependencyManagement override pinning %s" % ga
            return blk
        v = vm.group(1)
        pm = re.fullmatch(r"\$\{([^}]+)\}", v)
        if pm:
            prop_updates.append((pm.group(1), new))
            return blk
        n += 1
        return blk[:vm.start(1)] + new + blk[vm.end(1):]

    t = re.sub(r"<dependency>.*?</dependency>", sub, text, flags=re.S)
    for prop, nv in prop_updates:
        t2, k = re.subn(r"(<%s>\s*)[^<]*?(\s*</%s>)" % (re.escape(prop), re.escape(prop)), lambda m: m.group(1) + nv + m.group(2), t, count=1)
        if k:
            t, n = t2, n + 1
            detail = "version property <%s> updated (affects every dependency using it)" % prop
    return t, n, detail or ("%d dependency version(s) updated" % n)


def edit_composer_json(text: str, name: str, new: str) -> Edit:
    try:
        doc = json.loads(text)
    except ValueError:
        return text, 0, "blocked: composer.json is not valid JSON"
    n = 0
    for sec in ("require", "require-dev"):
        d = doc.get(sec)
        if isinstance(d, dict) and name in d:
            d[name] = _range_prefix(str(d[name])) + new
            n += 1
    if not n:
        return text, 0, "manual: transitive composer dependency - run `composer update %s`" % name
    return json.dumps(doc, indent=_indent_of(text), ensure_ascii=False) + ("\n" if text.endswith("\n") else ""), n, \
        "composer.json updated (run `composer update %s` to refresh composer.lock)" % name


def edit_gemfile(text: str, name: str, new: str) -> Edit:
    pat = re.compile(r"""^(\s*gem\s+['"]%s['"])(?:\s*,\s*['"]([^'"]*)['"])?""" % re.escape(name), re.M)
    n = 0

    def sub(m: "re.Match[str]") -> str:
        nonlocal n
        n += 1
        old = m.group(2) or ""
        op = (re.match(r"^\s*(~>|>=|=)?", old).group(1) or "~>") if old else ">="
        return "%s, '%s %s'" % (m.group(1), op, new)

    t = pat.sub(sub, text, count=1)
    return t, n, ("Gemfile constraint updated (run `bundle update %s`)" % name) if n else \
        "manual: transitive gem (not declared in Gemfile) - run `bundle update --conservative %s`" % name


# ------------------------------------------------------------------ file routing
_LOCK_TO_MANIFEST = {"package-lock.json": "package.json", "npm-shrinkwrap.json": "package.json", "yarn.lock": "package.json",
                     "pnpm-lock.yaml": "package.json", "cargo.lock": "Cargo.toml", "gemfile.lock": "Gemfile",
                     "composer.lock": "composer.json", "go.sum": "go.mod"}
_MANUAL_CMD = {"poetry.lock": "poetry update {name}", "pipfile.lock": "pipenv update {name}",
               "pubspec.lock": "dart pub upgrade {name}", "mix.lock": "mix deps.update {name}",
               "gradle.lockfile": "update the version in build.gradle, then ./gradlew dependencies --write-locks",
               "packages.lock.json": "dotnet add package {name} --version {to}", "conanfile.txt": "edit the requires line",
               "conanfile.py": "edit the requires line", "vcpkg.json": "edit the version>= constraint in vcpkg.json",
               "build.gradle": "edit the dependency version in build.gradle(.kts)", "build.gradle.kts": "edit the dependency version in build.gradle.kts"}
_REGEN = {"package.json": "npm install --package-lock-only --ignore-scripts  (or yarn/pnpm equivalent)",
          "go.mod": "go mod tidy", "Cargo.toml": "cargo update -p {name}", "Gemfile": "bundle update {name}",
          "composer.json": "composer update {name}", "pom.xml": "mvn -q versions:display-dependency-updates"}


def _targets_for(plan: Dict[str, Any], root: str) -> List[Tuple[str, str]]:
    """[(manifest_rel, kind)] candidate files to edit for this plan, ordered by preference."""
    out: List[Tuple[str, str]] = []
    for f in plan.get("files") or []:
        d, base = os.path.split(f)
        low = base.lower()
        if re.match(r"^(requirements.*|constraints.*)\.(txt|in)$", low) or (low.startswith("requirements") and low.endswith(".txt")):
            out.append((f, "requirements"))
        elif low in ("package.json", "go.mod", "pom.xml", "composer.json", "gemfile"):
            out.append((f, {"package.json": "package.json", "go.mod": "go.mod", "pom.xml": "pom.xml",
                            "composer.json": "composer.json", "gemfile": "gemfile"}[low]))
        elif low == "cargo.toml":
            out.append((f, "cargo"))
        elif low in _LOCK_TO_MANIFEST:
            mf = os.path.join(d, _LOCK_TO_MANIFEST[low]).replace("\\", "/")
            if os.path.isfile(os.path.join(root, mf)):
                out.append((mf, {"package.json": "package.json", "Cargo.toml": "cargo", "Gemfile": "gemfile",
                                 "composer.json": "composer.json", "go.mod": "go.mod"}[_LOCK_TO_MANIFEST[low]]))
    seen = set()
    return [t for t in out if not (t in seen or seen.add(t))]


def _lock_flavor(root: str, manifest_rel: str) -> str:
    d = os.path.dirname(os.path.join(root, manifest_rel))
    if os.path.isfile(os.path.join(d, "yarn.lock")):
        return "yarn"
    if os.path.isfile(os.path.join(d, "pnpm-lock.yaml")):
        return "pnpm"
    return "npm"


def _edit(kind: str, text: str, plan: Dict[str, Any], root: str, rel: str) -> Edit:
    name, new = plan["component"], plan["safe_version"]
    if kind == "requirements":
        return edit_requirements(text, name, new)
    if kind == "package.json":
        return edit_package_json(text, name, new, lock_flavor=_lock_flavor(root, rel))
    if kind == "go.mod":
        return edit_go_mod(text, name, new)
    if kind == "cargo":
        return edit_cargo_toml(text, name, new)
    if kind == "pom.xml":
        return edit_pom_xml(text, name, new)
    if kind == "composer.json":
        return edit_composer_json(text, name, new)
    if kind == "gemfile":
        return edit_gemfile(text, name, new)
    return text, 0, "blocked: no patcher for %s" % kind


# ------------------------------------------------------------------ approval + apply
def approval_digest(plans: List[Dict[str, Any]]) -> str:
    items = sorted((p["ecosystem"], p["component"], p["current_version"], p.get("safe_version") or "") for p in plans
                   if p.get("status") == "upgrade")
    return hashlib.sha256(json.dumps(items).encode()).hexdigest()[:16]


def apply(root: str, plans: List[Dict[str, Any]], *, approved: bool, token: Optional[str] = None, dry_run: bool = False,
          branch: str = "sbomplus/auto-fix", only_verified: bool = False) -> Dict[str, Any]:
    ups = [p for p in plans if p.get("status") == "upgrade" and p.get("safe_version")]
    digest = approval_digest(ups)
    out: Dict[str, Any] = {"approved": bool(approved), "digest": digest, "results": [], "changed_files": [],
                           "branch": None, "commit": None, "dry_run": dry_run}
    if not approved:
        out["status"] = "not_approved"
        out["note"] = "no file was changed: patching needs explicit approval (approved=true)"
        return out
    if token is not None and token != digest:
        out["status"] = "digest_mismatch"
        out["note"] = "approval token does not match the current plan (plan changed since it was reviewed)"
        return out
    pending: Dict[str, str] = {}                 # rel -> current (possibly edited) text
    base_sha = workspace.head(root).get("commit", "") if os.path.isdir(os.path.join(root, ".git")) else ""
    for p in ups:
        if only_verified and p["verification"].get("clean") is not True:
            out["results"].append({"component": p["component"], "from": p["current_version"], "to": p["safe_version"],
                                   "status": "skipped", "detail": "only_verified: candidate not verified clean"})
            continue
        targets = _targets_for(p, root)
        res = {"component": p["component"], "ecosystem": p["ecosystem"], "from": p["current_version"], "to": p["safe_version"],
               "status": "manual", "file": "", "detail": ""}
        applied = False
        for rel, kind in targets:
            fp = os.path.join(root, rel)
            text = pending.get(rel)
            if text is None:
                try:
                    with open(fp, "r", encoding="utf-8", newline="") as fh:
                        text = fh.read()
                except OSError as exc:
                    res["detail"] = "cannot read %s: %s" % (rel, exc)
                    continue
            new_text, n, detail = _edit(kind, text, p, root, rel)
            if n and not detail.startswith("blocked:"):
                pending[rel] = new_text
                res.update(status="applied", file=rel, detail=detail)
                applied = True
                break
            res["detail"] = ("%s: %s" % (rel, detail)) if detail else res["detail"]
            if detail.startswith("blocked:"):
                res["status"] = "blocked"
            elif detail.startswith("manual:"):                     # nothing is wrong - a human/tool must run a command
                m = re.search(r"run `([^`]+)`", detail)
                res["manual_command"] = m.group(1) if m else detail[len("manual:"):].strip()
        if not applied and res["status"] != "blocked":
            low = (p.get("files") or [""])[0].lower().rsplit("/", 1)[-1]
            cmd = _MANUAL_CMD.get(low, "")
            res.setdefault("manual_command", cmd.format(name=p["component"], to=p["safe_version"]) if cmd else
                           "edit the dependency declaration of %s to >= %s, then regenerate the lockfile" % (p["component"], p["safe_version"]))
            res["detail"] = res["detail"] or "no manifest edit possible for %s (lock-only or unsupported ecosystem)" % (p.get("files") or ["?"])[0]
        out["results"].append(res)
    regen: List[str] = []
    for rel in pending:
        base = os.path.basename(rel)
        if base in _REGEN:
            regen.append("%s: %s" % (rel, _REGEN[base].format(name="<pkg>")))
    out["regenerate"] = regen
    out["changed_files"] = sorted(pending)
    if dry_run or not pending:
        out["status"] = "dry_run" if dry_run else "nothing_applied"
        out["preview"] = {rel: txt for rel, txt in list(pending.items())[:5]} if dry_run else {}
        return out
    for rel, txt in pending.items():
        with open(os.path.join(root, rel), "w", encoding="utf-8", newline="") as fh:
            fh.write(txt)
    out["status"] = "applied"
    if base_sha:
        workspace.git(root, "checkout", "-q", "-B", branch)
        workspace.git(root, "add", "--", *sorted(pending))
        rc, _, err = workspace.git(root, "commit", "-q", "-m",
                                   "sbomplus: dependency security update (%d change(s))\n\napproval digest: %s" % (
                                       sum(1 for r in out["results"] if r["status"] == "applied"), digest))
        out["branch"] = branch
        out["commit"] = workspace.head(root).get("commit") if rc == 0 else None
        out["base_commit"] = base_sha
        if rc != 0:
            out["commit_error"] = err.strip()[-200:]
    return out


def revert(root: str, base_commit: str) -> bool:
    """Hard-reset the WORK COPY to the pre-patch commit (used when a re-scan shows a regression)."""
    rc, _, _ = workspace.git(root, "reset", "-q", "--hard", base_commit)
    return rc == 0


def diff(root: str, base_commit: str, limit: int = 80000) -> Dict[str, str]:
    _, stat, _ = workspace.git(root, "diff", "--stat", base_commit, "HEAD")
    _, full, _ = workspace.git(root, "diff", base_commit, "HEAD")
    return {"stat": stat[-2000:], "patch": full[:limit]}
