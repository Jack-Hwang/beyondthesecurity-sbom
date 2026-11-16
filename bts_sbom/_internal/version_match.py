# round-2 engine feature E2 (REA 21 §7) — new module, stdlib-only.
"""
Precise version-range matching for pip (PEP 440), npm/cargo (SemVer) and go.

Complements ``version_ranges.py`` (which evaluates OSV event lists and
advisory range strings) with the SPECIFIER-STRING lane: constraint lists
such as ``>=1.0,<2.0`` / ``~=1.4.2`` / ``==2.2.*`` (PEP 440) and npm/cargo
range syntax ``^1.2.3`` / ``~1.2`` / ``1.x`` / ``*``.

Public API
----------
match_range(version, constraints, ecosystem) -> bool
    True iff EVERY constraint is satisfied (conjunction — like a
    comma-separated PEP 440 specifier set or npm space-separated range).
    Fail-closed: an unparsable constraint never matches (False), never
    guesses.
explain_match(version, constraints, ecosystem) -> dict
    {version, ecosystem, constraints, constraint, verdict, reason,
     approx, all}
    ``constraint`` is the FIRST failing constraint (or the first of the
    list when everything passes); ``all`` carries one verdict per
    constraint. ``approx`` is True whenever a simplified/best-effort
    comparison decided the verdict (generic fallback for unparsable
    versions, ``===`` byte equality, ignored local-version segment,
    wildcard operator misuse, unknown-ecosystem ordering).
eco_compare(a, b, ecosystem) -> int
    Ecosystem-aware -1/0/1 ordering, used by remediation (smallest fixed
    version selection) and by osvscanner fixed-bound containment.

Ecosystem families (prefix match, case-insensitive; "Debian:12"-style
qualifiers are stripped):
    pip   ("pip", "pypi", "python")       -> PEP 440 specifiers
    npm   ("npm", "node")                 -> npm range syntax
    cargo ("cargo", "crates.io", "rust")  -> cargo range syntax
    go    ("go", "golang")                -> semver-ish (v-prefix optional;
                                             Go pseudo-versions order via the
                                             semver prerelease rule, with a
                                             tolerant fallback when even that
                                             cannot parse)
    anything else                          -> generic tolerant comparator

Honest limitations (documented, not hidden)
-------------------------------------------
* PEP 440: pre/post/dev ordering uses the package's sort-key comparator
  (``version_ranges._pep440_key``); the standard orderings hold
  (1.0rc1 < 1.0 < 1.0.post1 < 2.0). This is a sort-key implementation of
  PEP 440 ordering, not the full PEP 508 normalization algorithm —
  exotic spellings parse through the same regex or fall back to the
  tolerant generic comparator with ``approx: true``.
* PEP 440 ``===`` (arbitrary equality) is byte-exact string equality
  after strip; no normalization. Always ``approx: true``.
* PEP 440 local version segments (``1.0+local``) are IGNORED in
  comparisons per PEP 440 comparison rules; matches involving them are
  flagged ``approx: true``.
* Epochs (``1!2.0``): the PEP 440 sort key carries the epoch, so
  ``1!2.0 > 2.0`` orders correctly; there is no separate epoch operator.
* npm prerelease opt-in is implemented (node-semver rule): a prerelease
  candidate satisfies a comparator set only when some comparator in the
  same set pins the same [major,minor,patch] with its own prerelease.
  Partial-bound edge cases (a prerelease inside an x-range bound) are
  simplified: the bound's own prerelease participates in ordering but
  grants opt-in only for its exact triple.
* npm/cargo partial ordered bounds follow node-semver semantics:
  ``>=1.2`` -> ``>=1.2.0``, ``<1.2`` -> ``<1.2.0``, ``>1.2`` ->
  ``>=1.3.0``, ``<=1.2`` -> ``<1.3.0``.
* ``||`` (npm OR syntax) is NOT implemented — an ``||``-containing
  constraint fails closed with a reason, never a guessed verdict.

Zero new dependencies: everything is stdlib (re) plus the package's own
version_ranges comparators.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from bts_sbom._internal.version_cmp import compare_versions
from bts_sbom._internal.version_ranges import (
    _pad_release,
    _pep440_key,
    _semver_key,
)

SCHEMA = "bts-version-match/1"

# ── ecosystem family dispatch ─────────────────────────────────────────────────

_PIP_ECOS = {"pip", "pypi", "python"}
_NPM_ECOS = {"npm", "node"}
_CARGO_ECOS = {"cargo", "crates.io", "crates", "rust"}
_GO_ECOS = {"go", "golang"}


def family_for(ecosystem: str) -> str:
    """Map an ecosystem string to a matcher family: pip|npm|cargo|go|generic."""
    base = (ecosystem or "").strip().lower().split(":", 1)[0].strip()
    if base in _PIP_ECOS:
        return "pip"
    if base in _NPM_ECOS:
        return "npm"
    if base in _CARGO_ECOS:
        return "cargo"
    if base in _GO_ECOS:
        return "go"
    return "generic"


# ── shared ordering helpers ───────────────────────────────────────────────────

def _cmp_keys(ka: Tuple, kb: Tuple) -> int:
    return (ka > kb) - (ka < kb)


def eco_compare(a: str, b: str, ecosystem: str = "generic") -> int:
    """Ecosystem-aware version ordering. Returns -1/0/1.

    Falls back to the tolerant generic comparator whenever the family
    comparator cannot parse either side (the caller sees this as
    ``approx`` in explain_match; here it is just an ordering)."""
    fam = family_for(ecosystem)
    if fam == "pip":
        ka, kb = _pep440_key(a), _pep440_key(b)
        if ka is not None and kb is not None:
            ra, rb = _pad_release(ka[1], kb[1])
            return _cmp_keys((ka[0], ra) + ka[2:], (kb[0], rb) + kb[2:])
    elif fam in ("npm", "cargo", "go"):
        ka, kb = _semver_key(a), _semver_key(b)
        if ka is not None and kb is not None:
            return _cmp_keys(ka, kb)
    return compare_versions(a, b)


def _has_local(v: str) -> bool:
    return "+" in (v or "")


def _strip_local(v: str) -> str:
    return (v or "").split("+", 1)[0].strip()


def _strip_v(v: str) -> str:
    v = (v or "").strip()
    return v[1:] if v[:1] in ("v", "V") and len(v) > 1 and v[1].isdigit() else v


# ── per-constraint verdict rows ───────────────────────────────────────────────

def _row(version: str, constraint: str, verdict: bool, reason: str,
         approx: bool) -> Dict[str, Any]:
    return {"constraint": constraint, "verdict": bool(verdict),
            "reason": reason, "approx": bool(approx)}


# ── PEP 440 (pip) ─────────────────────────────────────────────────────────────

_PIP_OP_RE = re.compile(r"^\s*(===|==|!=|<=|>=|<|>|~=|=)\s*(.*)$")


def _pep440_prefix_match(version: str, prefix_body: str) -> Tuple[bool, str, bool]:
    """PEP 440 prefix (wildcard) match ``==2.2.*``: epoch + release prefix
    equality; pre/post/dev do not affect the prefix match (2.2.1rc1 matches
    ==2.2.*). Returns (verdict, reason, approx)."""
    base = prefix_body.strip()
    if _has_local(base):
        base = _strip_local(base)
    kc = _pep440_key(base)
    kv = _pep440_key(_strip_local(version))
    if kc is None or kv is None:
        ok = _strip_local(version).startswith(base)
        return ok, ("unparsable element — plain string prefix match "
                    "(approx)" if ok else "unparsable element — string prefix "
                    "compare failed (approx)"), True
    prefix = kc[1]
    n = len(prefix)
    vrel = kv[1] + (0,) * max(0, n - len(kv[1]))
    ok = kv[0] == kc[0] and vrel[:n] == prefix
    return ok, ("release prefix %s %s epoch %d" %
                (".".join(str(x) for x in prefix),
                 "matches" if ok else "does not match", kc[0])), False


def _pip_eval(version: str, constraint: str) -> Dict[str, Any]:
    c = constraint.strip()
    m = _PIP_OP_RE.match(c)
    if not m:
        if c == "" or c == "*":
            return _row(version, constraint, True, "empty constraint matches all", False)
        # bare version -> equality (requirements-style "django==3" spelled bare)
        return _pip_eval(version, "== " + c)
    op, body = m.group(1), m.group(2).strip()
    if op == "=":
        op = "=="
    if op == "===":
        ok = version.strip() == body.strip()
        return _row(version, constraint, ok,
                    "arbitrary (byte-exact) equality — no normalization", True)
    if body.endswith(".*"):
        if op == "==":
            ok, reason, approx = _pep440_prefix_match(version, body[:-2])
            return _row(version, constraint, ok, reason, approx)
        if op == "!=":
            ok, reason, approx = _pep440_prefix_match(version, body[:-2])
            return _row(version, constraint, not ok,
                        "negated: " + reason, approx)
        return _row(version, constraint, False,
                    "wildcard (.* ) is only valid with == or != — "
                    "constraint cannot be evaluated (fail-closed)", True)
    if op == "~=":
        kc = _pep440_key(body)
        if kc is None or "." not in body:
            return _row(version, constraint, False,
                        "~= requires at least two release segments and a "
                        "parsable version (fail-closed)", True)
        prefix = kc[1][:-1]
        kv = _pep440_key(_strip_local(version))
        if kv is None:
            cc = compare_versions(version, body)
            ok = cc >= 0
            return _row(version, constraint, ok,
                        "unparsable candidate — tolerant >= compare only "
                        "(approx; prefix check skipped)", True)
        ra, rb = _pad_release(kv[1], kc[1])
        ge = _cmp_keys((kv[0], ra) + kv[2:], (kc[0], rb) + kc[2:]) >= 0
        vrel = kv[1] + (0,) * max(0, len(prefix) - len(kv[1]))
        pre_ok = kv[0] == kc[0] and vrel[:len(prefix)] == prefix
        ok = ge and pre_ok
        return _row(version, constraint, ok,
                    "~= means >=%s and ==%s.* -> %s" %
                    (body, ".".join(str(x) for x in prefix),
                     "both hold" if ok else "not both held"), False)
    # ordered / equality ops via sort keys
    approx = False
    note = ""
    if _has_local(version) or _has_local(body):
        approx = True
        note = "local version segment ignored per PEP 440; "
    kv = _pep440_key(_strip_local(version))
    kc = _pep440_key(_strip_local(body))
    if kv is None or kc is None:
        cc = compare_versions(_strip_local(version), _strip_local(body))
        reasons = {"==": cc == 0, "!=": cc != 0, "<=": cc <= 0,
                   ">=": cc >= 0, "<": cc < 0, ">": cc > 0}
        return _row(version, constraint, reasons[op],
                    note + "unparsable under PEP 440 — tolerant generic "
                    "comparator decided (approx)", True)
    ra, rb = _pad_release(kv[1], kc[1])
    cc = _cmp_keys((kv[0], ra) + kv[2:], (kc[0], rb) + kc[2:])
    verdicts = {"==": cc == 0, "!=": cc != 0, "<=": cc <= 0,
                ">=": cc >= 0, "<": cc < 0, ">": cc > 0}
    return _row(version, constraint, verdicts[op],
                note + "PEP 440 key order: %s %s %s" %
                (version, {"==": "==", "!=": "!=", "<=": "<=", ">=": ">=",
                           "<": "<", ">": ">"}[op], body), approx)


# ── npm / cargo / go (SemVer) ─────────────────────────────────────────────────

_SEMVER_PARTIAL_RE = re.compile(
    r"^(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z.-]+)?$")

_SEM_OP_RE = re.compile(r"^\s*(>=|<=|>|<|=|==|\^|~)\s*(.+)$")


def _partial(body: str) -> Optional[Dict[str, Any]]:
    """Parse a possibly-partial semver into components; None when unparsable."""
    m = _SEMVER_PARTIAL_RE.match(_strip_v(body))
    if not m:
        return None
    def _num(tok: Optional[str]) -> Optional[int]:
        if tok is None or tok in ("x", "X", "*"):
            return None
        return int(tok)
    maj, mi, pa = _num(m.group(1)), _num(m.group(2)), _num(m.group(3))
    if maj is None:                       # "*" / "x" alone
        return {"maj": None, "mi": None, "pa": None,
                "pre": m.group(4), "wild": True}
    return {"maj": maj, "mi": mi, "pa": pa, "pre": m.group(4),
            "wild": mi is None or pa is None}


def _fmt(p: Dict[str, Any]) -> str:
    maj = p["maj"] if p["maj"] is not None else 0
    mi = p["mi"] if p["mi"] is not None else 0
    pa = p["pa"] if p["pa"] is not None else 0
    s = "%d.%d.%d" % (maj, mi, pa)
    if p.get("pre"):
        s += "-" + p["pre"]
    return s


def _triple(p: Dict[str, Any]) -> Tuple[int, int, int]:
    return (p["maj"] or 0, p["mi"] or 0, p["pa"] or 0)


def _atomic(op: str, p: Dict[str, Any]) -> List[Tuple[str, str, Tuple[int, int, int], bool]]:
    """Turn one npm/cargo comparator into concrete bounds.

    Follows node-semver partial-bound semantics:
      >=1.2 -> >=1.2.0 ; <1.2 -> <1.2.0 ; >1.2 -> >=1.3.0 ; <=1.2 -> <1.3.0
      =1.2 / 1.2 (partial) -> >=1.2.0 <1.3.0 (x-range)
    Returns a list of (kind, bound_version, triple_of_bound, bound_has_pre)
    where kind in {"lo" (inclusive), "lo_ex" (exclusive), "hi" (exclusive),
    "hi_in" (inclusive), "point", "any"}."""
    has_pre = bool(p["pre"])
    tri = _triple(p)
    if op == "any":
        return [("any", "", (0, 0, 0), False)]
    if op == "=":
        if p["wild"] or p["mi"] is None:
            return _xr(p)
        return [("point", _fmt(p), tri, has_pre)]
    if op == "^":
        return _caret(p)
    if op == "~":
        return _tilde(p)
    if op == ">=":
        return [("lo", _fmt(_zero(p)), tri, has_pre)]
    if op == "<":
        return [("hi", _fmt(_zero(p)), tri, has_pre)]
    if op == ">":
        if p["pa"] is not None:
            return [("lo_ex", _fmt(p), tri, has_pre)]
        bumped = _bump(p)
        return [("lo", _fmt(bumped), bumped["__tri"], False)]
    if op == "<=":
        if p["pa"] is not None:
            return [("hi_in", _fmt(p), tri, has_pre)]
        bumped = _bump(p)
        return [("hi", _fmt(bumped), bumped["__tri"], False)]
    return []                                       # unknown op: fail-closed


def _zero(p: Dict[str, Any]) -> Dict[str, Any]:
    return {"maj": p["maj"] or 0, "mi": p["mi"] or 0, "pa": p["pa"] or 0,
            "pre": p["pre"]}


def _bump(p: Dict[str, Any]) -> Dict[str, Any]:
    """node-semver bumped upper bound: >1.2 / <=1.2 -> the next series up."""
    if p["mi"] is None:
        return {"maj": (p["maj"] or 0) + 1, "mi": 0, "pa": 0, "pre": None,
                "__tri": ((p["maj"] or 0) + 1, 0, 0)}
    return {"maj": p["maj"], "mi": p["mi"] + 1, "pa": 0, "pre": None,
            "__tri": (p["maj"], p["mi"] + 1, 0)}


def _xr(p: Dict[str, Any]) -> List[Tuple[str, str, Tuple[int, int, int], bool]]:
    """x-range / partial equality: 1.x -> >=1.0.0 <2.0.0; 1.2.x -> >=1.2.0 <1.3.0."""
    lo = {"maj": p["maj"] or 0, "mi": p["mi"] or 0, "pa": p["pa"] or 0}
    if p["mi"] is None:
        hi = {"maj": (p["maj"] or 0) + 1, "mi": 0, "pa": 0}
        tri = ((p["maj"] or 0) + 1, 0, 0)
    else:
        hi = {"maj": p["maj"], "mi": p["mi"] + 1, "pa": 0}
        tri = (p["maj"], p["mi"] + 1, 0)
    return [("lo", _fmt(lo), _triple(lo), bool(p["pre"])),
            ("hi", _fmt(hi), tri, False)]


def _caret(p: Dict[str, Any]) -> List[Tuple[str, str, Tuple[int, int, int], bool]]:
    """npm/cargo caret: ^1.2.3 -> >=1.2.3 <2.0.0 ; ^0.2.3 -> >=0.2.3 <0.3.0 ;
    ^0.0.3 -> >=0.0.3 <0.0.4 ; ^0.0 -> >=0.0.0 <0.1.0 ; ^0 -> >=0.0.0 <1.0.0."""
    maj, mi, pa = p["maj"] or 0, p["mi"], p["pa"]
    lo = _zero(p)
    if maj > 0 or mi is None:
        hi = {"maj": maj + 1, "mi": 0, "pa": 0}
    elif pa is None or (mi or 0) > 0 or pa > 0:
        # ^0.2.3 -> <0.3.0 ; ^0.2 -> <0.3.0 ; ^0.0.3 -> <0.0.4
        if (mi or 0) > 0 or pa is None:
            hi = {"maj": maj, "mi": (mi or 0) + 1, "pa": 0}
        else:
            hi = {"maj": maj, "mi": mi or 0, "pa": pa + 1}
    else:
        hi = {"maj": maj, "mi": mi or 0, "pa": (pa or 0) + 1}
    return [("lo", _fmt(lo), _triple(lo), bool(p["pre"])),
            ("hi", _fmt(hi), _triple(hi), False)]


def _tilde(p: Dict[str, Any]) -> List[Tuple[str, str, Tuple[int, int, int], bool]]:
    """npm/cargo tilde: ~1.2.3 -> >=1.2.3 <1.3.0 ; ~1.2 -> >=1.2.0 <1.3.0 ;
    ~1 -> >=1.0.0 <2.0.0."""
    lo = _zero(p)
    if p["mi"] is None:
        hi = {"maj": (p["maj"] or 0) + 1, "mi": 0, "pa": 0}
    else:
        hi = {"maj": p["maj"], "mi": (p["mi"] or 0) + 1, "pa": 0}
    return [("lo", _fmt(lo), _triple(lo), bool(p["pre"])),
            ("hi", _fmt(hi), _triple(hi), False)]


def _semver_token(version: str, token: str,
                  fam: str) -> Tuple[Optional[List], str]:
    """Parse ONE npm/cargo/go range token into atomic comparators.
    Returns (atomics, error). atomics None on a fail-closed error."""
    t = token.strip()
    if t in ("", "*", "x", "X"):
        return [("any", "", (0, 0, 0), False)], ""
    if "||" in t:
        return None, "npm OR ('||') syntax is not implemented — failing closed"
    m = _SEM_OP_RE.match(t)
    if m:
        op, body = m.group(1), m.group(2).strip()
        if op == "==":
            op = "="
    else:
        op, body = ("=" if fam == "npm" else "^"), t   # bare-version semantics
        # A wildcard segment (1.2.* / 1.x) is an x-range in every family,
        # even under cargo's caret bare-version default.
        if re.search(r"(?:^|\.)[xX*](?:$|\.)", body.split("-", 1)[0]):
            op = "="
    p = _partial(body)
    if p is None:
        return None, "unparsable semver bound %r" % body
    atomics = _atomic(op, p)
    if not atomics:
        return None, "unsupported comparator %r (fail-closed)" % op
    return atomics, ""


def _semver_eval(version: str, constraints: List[str], fam: str) -> List[Dict[str, Any]]:
    kv = _semver_key(_strip_local(version))
    rows: List[Dict[str, Any]] = []
    # npm prerelease opt-in is an npm/cargo rule; go pseudo-versions are
    # ordinary versions in their ecosystem, so go never applies it.
    optin = fam in ("npm", "cargo")
    for token in constraints:
        atomics, err = _semver_token(version, token, fam)
        if atomics is None:
            rows.append(_row(version, token, False, err + " (fail-closed)", True))
            continue
        # npm prerelease opt-in: a prerelease candidate only matches when some
        # comparator in the same set pins the same triple with a prerelease.
        allowed: set = set()
        for _, _, tri, has_pre in atomics:
            if has_pre:
                allowed.add(tri)
        if kv is None:
            # candidate unparsable as semver (e.g. an exotic pseudo-version the
            # semver regex rejects) — tolerant fallback per token
            ok, reason, approx = _generic_token(version, token)
            rows.append(_row(version, token, ok,
                             "candidate unparsable as semver; " + reason, True))
            continue
        cand_pre = _candidate_prerelease(version)
        cand_tri = (kv[0], kv[1], kv[2])
        if optin and cand_pre and cand_tri not in allowed:
            rows.append(_row(version, token, False,
                             "prerelease candidate and no comparator in this "
                             "set pins %d.%d.%d with a prerelease "
                             "(npm opt-in rule)" % cand_tri, False))
            continue
        ok = True
        why = []
        for kind, bound, _tri, _pre in atomics:
            if kind == "any":
                continue
            kb = _semver_key(bound)
            if kb is None:
                cc = compare_versions(_strip_local(version), bound)
            else:
                cc = _cmp_keys(kv, kb)
            if kind == "lo":
                good = cc >= 0
                why.append(">=%s:%s" % (bound, "yes" if good else "no"))
            elif kind == "lo_ex":
                good = cc > 0
                why.append(">%s:%s" % (bound, "yes" if good else "no"))
            elif kind == "hi":
                good = cc < 0
                why.append("<%s:%s" % (bound, "yes" if good else "no"))
            elif kind == "hi_in":
                good = cc <= 0
                why.append("<=%s:%s" % (bound, "yes" if good else "no"))
            else:                                     # point
                good = cc == 0
                why.append("=%s:%s" % (bound, "yes" if good else "no"))
            ok = ok and good
        rows.append(_row(version, token, ok,
                         " ; ".join(why) if why else "matches any version", False))
    return rows


def _candidate_prerelease(version: str) -> bool:
    m = _SEMVER_PARTIAL_RE.match(_strip_v(_strip_local(version)))
    return bool(m and m.group(4))


# ── generic family ────────────────────────────────────────────────────────────

_GEN_OP_RE = re.compile(r"^\s*(<=|>=|<|>|==|=)\s*(.*)$")


def _generic_token(version: str, token: str) -> Tuple[bool, str, bool]:
    t = token.strip()
    if t in ("", "*", "x", "X"):
        return True, "empty/wildcard constraint matches all", False
    m = _GEN_OP_RE.match(t)
    if not m:
        ok = version.strip() == _strip_v(t)
        return ok, ("bare version equality %s" %
                    ("held" if ok else "not held")), False
    op, body = m.group(1), m.group(2).strip()
    if op == "==":
        op = "="
    cc = compare_versions(version, body)
    verdicts = {"=": cc == 0, "<=": cc <= 0, ">=": cc >= 0, "<": cc < 0, ">": cc > 0}
    return verdicts[op], ("tolerant generic comparator: %s %s %s" %
                          (version, op, body)), True


# ── public API ────────────────────────────────────────────────────────────────

def _split_constraints(raw: List[str], fam: str) -> List[str]:
    """Split raw constraint strings into atomic constraint tokens per family:
    pip splits on commas (PEP 440 specifier sets); npm/cargo/go split on
    whitespace (npm AND semantics, after collapsing spaces between an
    operator and its version); generic splits on commas."""
    out: List[str] = []
    for c in raw:
        s = str(c).strip()
        if not s:
            continue
        if fam in ("npm", "cargo", "go"):
            s = re.sub(r"(>=|<=|>|<|==|=|\^|~)\s+", r"\1", s)
            out.extend(t for t in re.split(r"[\s,]+", s) if t)
        else:                                   # pip + generic: comma sets
            out.extend(t.strip() for t in s.split(",") if t.strip())
    return out


def _evaluate_all(version: str, constraints: List[str],
                  ecosystem: str) -> List[Dict[str, Any]]:
    fam = family_for(ecosystem)
    v = str(version or "").strip()
    tokens = _split_constraints([str(c) for c in (constraints or [])], fam)
    if not tokens:
        return [_row(v, "", True, "no constraints", False)]
    rows: List[Dict[str, Any]] = []
    if fam == "pip":
        for c in tokens:
            rows.append(_pip_eval(v, c))
    elif fam in ("npm", "cargo", "go"):
        rows = _semver_eval(v, tokens, fam)
    else:
        for c in tokens:
            ok, reason, ap = _generic_token(v, c)
            rows.append(_row(v, c, ok, reason, ap or fam == "generic"))
    return rows


def match_range(version: str, constraints: List[str], ecosystem: str = "generic") -> bool:
    """True iff EVERY constraint in `constraints` is satisfied by `version`
    under the ecosystem's ordering rules. Fail-closed: unparsable or
    unsupported constraint syntax yields False (never a guessed match)."""
    if not constraints:
        return True
    rows = _evaluate_all(str(version), list(constraints), str(ecosystem))
    return all(r["verdict"] for r in rows)


def explain_match(version: str, constraints: List[str],
                  ecosystem: str = "generic") -> Dict[str, Any]:
    """Explain the verdict for a constraint list: the FIRST failing
    constraint (or the first constraint when everything passes), with the
    reason and an honesty flag for simplified comparisons."""
    v = str(version or "").strip()
    cons = [str(c) for c in (constraints or [])]
    rows = _evaluate_all(v, cons, str(ecosystem))
    first = rows[0] if rows else _row(v, "", True, "no constraints", False)
    for r in rows:
        if not r["verdict"]:
            first = r
            break
    return {
        "schema": SCHEMA,
        "version": v,
        "ecosystem": str(ecosystem),
        "family": family_for(ecosystem),
        "constraints": cons,
        "constraint": first["constraint"],
        "verdict": bool(all(r["verdict"] for r in rows)),
        "reason": first["reason"],
        "approx": bool(any(r["approx"] for r in rows)),
        "all": rows,
    }


__all__ = ["SCHEMA", "match_range", "explain_match", "eco_compare",
           "family_for"]
