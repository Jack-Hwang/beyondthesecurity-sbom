# vendored from common/version_ranges.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
Ecosystem-aware vulnerable-version-range evaluation (Snyk parity).

Advisory feeds express "which versions are vulnerable" in two shapes:

  1. OSV range events  - [{"introduced": "0"}, {"fixed": "1.2.8"},
                          {"introduced": "2.0.0"}, {"last_affected": "2.0.3"}]
  2. advisory strings  - ">= 1.0.0, < 1.2.3"  /  "<1.2"  /  "~1.2.3"  /  "1.0 - 2.0"

Whether a version falls inside depends on the ECOSYSTEM's ordering rules,
which differ where it matters most - pre-releases:

    npm   (SemVer 2.0.0)  1.2.3-rc1 < 1.2.3      ; build metadata ignored
    PyPI  (PEP 440)       1.2rc1 < 1.2 ; 1.2.post1 > 1.2 ; 1!2.0 epoch
    Maven (Java)          1.2-SNAPSHOT < 1.2 < 1.2-sp1 ; 1.2 == 1.2.0
    Go    pseudo+semver   v0.0.0-20240101-hash < any real tag
    other (generic)       tolerant firmware comparator (common/version_cmp)

The public entry points (affects / intervals_from_events /
parse_range_string) never raise on malformed input - they return False /
best-effort intervals / None, so callers can stay honest instead of
guessing (CLAUDE.md 2.1).

Zero new dependencies: SemVer / PEP 440 / Maven comparators are implemented
here (the ordering rules only), and the generic path reuses
common/version_cmp.compare_versions.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from bts_sbom._internal.version_cmp import compare_versions

# --------------------------------------------------------------------------
# ordering selection
# --------------------------------------------------------------------------

# ecosystem (lower-cased prefix match) -> comparator name
_ECOSYSTEM_ORDERINGS: List[Tuple[str, str]] = [
    # longest/most-specific first; prefix match on the OSV ecosystem string
    ("npm", "semver"), ("node", "semver"), ("go", "semver"),
    ("crates.io", "semver"), ("cargo", "semver"), ("cargo crates", "semver"),
    ("packagist", "semver"), ("composer", "semver"),
    ("rubygems", "semver"), ("nuget", "semver"),
    ("pypi", "pep440"), ("python", "pep440"),
    ("maven", "maven"), ("apache maven", "maven"), ("java", "maven"),
    ("android", "maven"), ("sbt", "maven"), ("gradle", "maven"),
]

# OSV range "type" field -> comparator override (SEMVER/ECOSYSTEM/GIT)
_RANGE_TYPE_ORDERINGS = {
    "SEMVER": "semver",
    "GIT": "semver",      # tags follow semver-ish ordering; fallback is safe
}


def detect_ordering(ecosystem: Optional[str],
                    range_type: Optional[str] = None) -> str:
    """Pick the comparator name for an ecosystem / OSV range type."""
    if range_type:
        t = _RANGE_TYPE_ORDERINGS.get((range_type or "").strip().upper())
        if t:
            return t
    eco = (ecosystem or "").strip().lower()
    if eco:
        # distro-qualified ecosystems: "Debian:12", "Alpine:v3.18" -> distro part
        base = eco.split(":", 1)[0].strip()
        for prefix, name in _ECOSYSTEM_ORDERINGS:
            if base == prefix or base.startswith(prefix):
                return name
        if base:
            return "generic"
    return "generic"


# --------------------------------------------------------------------------
# SemVer 2.0.0 comparator (npm / Go / crates / rubygems / nuget / composer)
# --------------------------------------------------------------------------

_SEMVER_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z.-]+)?$")


def _semver_key(v: str) -> Optional[Tuple]:
    """Sort key implementing SemVer precedence. None when unparsable."""
    m = _SEMVER_RE.match((v or "").strip())
    if not m:
        return None
    maj, mi, pa = (int(m.group(i) or 0) for i in (1, 2, 3))
    pre = m.group(4)
    if pre is None:
        pre_key = (1,)                # release > any pre-release
    else:
        ids = []
        for tok in pre.split("."):
            if tok.isdigit():
                ids.append((0, int(tok), ""))   # numeric < alphanumeric
            else:
                ids.append((1, 0, tok.lower()))
        ids.append((-1, 0, ""))       # shorter pre-list sorts first
        pre_key = (0, tuple(ids))
    return (maj, mi, pa, pre_key)


# --------------------------------------------------------------------------
# PEP 440 comparator (PyPI)
# --------------------------------------------------------------------------

_PEP440_RE = re.compile(
    r"^v?(?:(\d+)!)?(\d+(?:\.\d+)*)"
    r"(?:[-_.]?(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\d*))?"
    r"(?:[-_.]?(post|rev|r)[-_.]?(\d*))?"
    r"(?:[-_.]?(dev)[-_.]?(\d*))?"
    r"(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$",
    re.IGNORECASE)

_PEP440_PRE_NORM = {"a": "a", "alpha": "a", "b": "b", "beta": "b",
                    "c": "rc", "pre": "rc", "preview": "rc", "rc": "rc"}
_PEP440_PRE_ORDER = {"a": 0, "b": 1, "rc": 2}


class _Inf:
    """Singleton that compares greater than everything (PEP 440 keys)."""
    def __lt__(self, other): return False
    def __gt__(self, other): return not isinstance(other, _Inf)
    def __eq__(self, other): return isinstance(other, _Inf)
    def __le__(self, other): return isinstance(other, _Inf)
    def __ge__(self, other): return True


class _NegInf:
    """Singleton that compares less than everything (PEP 440 keys)."""
    def __lt__(self, other): return not isinstance(other, _NegInf)
    def __gt__(self, other): return False
    def __eq__(self, other): return isinstance(other, _NegInf)
    def __le__(self, other): return True
    def __ge__(self, other): return isinstance(other, _NegInf)


_INF, _NEGINF = _Inf(), _NegInf()


def _pep440_key(v: str) -> Optional[Tuple]:
    """Sort key implementing PEP 440 ordering. None when unparsable."""
    s = (v or "").strip().lower()
    m = _PEP440_RE.match(s)
    if not m:
        return None
    epoch = int(m.group(1) or 0)
    release = tuple(int(x) for x in m.group(2).split("."))
    pre_raw, pre_num = m.group(3), m.group(4)
    post_raw, post_num = m.group(5), m.group(6)
    dev_raw, dev_num = m.group(7), m.group(8)

    # pre: normalized letter -> ('a'|'b'|'rc', n); None -> +inf, except the
    # dev-only case (1.0.dev1 < 1.0a1) where dev without pre/post sorts first
    if pre_raw:
        letter = _PEP440_PRE_NORM[pre_raw]
        pre_key: object = (letter, int(pre_num or 0))
    elif post_raw is None and dev_raw is not None:
        pre_key = _NEGINF
    else:
        pre_key = _INF
    # post: None -> -inf so 1.0.post1 > 1.0 and 1.0.dev1 < 1.0
    post_key: object = int(post_num or 0) if post_raw else _NEGINF
    dev_key: object = _INF if dev_raw is None else int(dev_num or 0)
    return (epoch, release, pre_key, post_key, dev_key)


# --------------------------------------------------------------------------
# Maven comparator
# --------------------------------------------------------------------------

_MAVEN_QUAL_ORDER = {"alpha": 0, "a": 0, "beta": 1, "b": 1,
                     "milestone": 2, "m": 2, "preview": 2,
                     "rc": 3, "cr": 3, "snapshot": 4,
                     "": 5, "final": 5, "ga": 5, "release": 5,   # final
                     "sp": 6}

def _maven_key(v: str) -> Optional[Tuple]:
    """Sort key implementing Maven ComparableVersion ordering.

    Qualifier precedence: alpha < beta < milestone < rc < snapshot <
    (empty/final/ga) < sp; unknown qualifiers sort lexically after sp.
    The remainder is tokenised into alpha/digit runs so glued forms
    ("milestone2", "sp1", "rc1") split into qualifier + number.
    """
    s = (v or "").strip().lower().rstrip("-.")
    if not s:
        return None
    nums = re.match(r"^(\d+(?:\.\d+)*)", s)
    if not nums:
        return None
    release = tuple(int(x) for x in nums.group(1).split("."))
    rest = s[nums.end():].strip("-.")
    toks = re.findall(r"[a-z]+|\d+", rest)
    quals: List[Tuple[int, str, int]] = []
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok.isdigit():
            quals.append((5, "", int(tok)))          # bare number == final rank
        else:
            num = 0
            if i + 1 < len(toks) and toks[i + 1].isdigit():
                num = int(toks[i + 1])
                i += 1
            rank = _MAVEN_QUAL_ORDER.get(tok, 7)
            quals.append((rank, tok if rank == 7 else "", num))
        i += 1
    if not quals:
        quals.append((5, "", 0))
    return (release, tuple(quals))


# --------------------------------------------------------------------------
# comparator dispatch
# --------------------------------------------------------------------------

def _key_for(ordering: str, v: str) -> Optional[Tuple]:
    if ordering == "semver":
        k = _semver_key(v)
        if k is not None:
            return k
    elif ordering == "pep440":
        k = _pep440_key(v)
        if k is not None:
            return k
    elif ordering == "maven":
        k = _maven_key(v)
        if k is not None:
            return k
    # generic fallback (also the "other" ordering): tolerant firmware compare
    return ("g",)


def _pad_release(t1: Tuple[int, ...], t2: Tuple[int, ...]
                 ) -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
    """Zero-pad two release tuples to equal length (1.0 == 1.0.0)."""
    n = max(len(t1), len(t2))
    return t1 + (0,) * (n - len(t1)), t2 + (0,) * (n - len(t2))


def compare_eco(a: str, b: str, ordering: str = "generic") -> int:
    """Compare two versions under an ecosystem ordering.

    Returns -1/0/1. Ecosystem-specific keys win; if either side fails to
    parse under that key the pair falls back to the tolerant generic
    comparator (common/version_cmp) so messy real-world strings still order.
    """
    if ordering == "semver":
        ka, kb = _semver_key(a), _semver_key(b)
        if ka is not None and kb is not None:
            return (ka > kb) - (ka < kb)
    elif ordering == "pep440":
        ka, kb = _pep440_key(a), _pep440_key(b)
        if ka is not None and kb is not None:
            ra, rb = _pad_release(ka[1], kb[1])
            ka, kb = (ka[0], ra) + ka[2:], (kb[0], rb) + kb[2:]
            return (ka > kb) - (ka < kb)
    elif ordering == "maven":
        ka, kb = _maven_key(a), _maven_key(b)
        if ka is not None and kb is not None:
            ra, rb = _pad_release(ka[0], kb[0])
            ka, kb = (ra, ka[1]), (rb, kb[1])
            return (ka > kb) - (ka < kb)
    return compare_versions(a, b)


# --------------------------------------------------------------------------
# intervals
# --------------------------------------------------------------------------

class Interval:
    """Version vulnerability window.

    low  - lower bound ("" means unbounded, i.e. introduced:"0")
    high - upper bound ("" means unbounded / still vulnerable)
    low_inclusive / high_inclusive - bound closedness. Defaults: low closed,
        high open (OSV introduced/fixed semantics).
    """

    __slots__ = ("low", "high", "low_inclusive", "high_inclusive")

    def __init__(self, low: str = "", high: str = "",
                 low_inclusive: bool = True, high_inclusive: bool = False):
        self.low = low
        self.high = high
        self.low_inclusive = low_inclusive
        self.high_inclusive = high_inclusive

    def contains(self, version: str, ordering: str = "generic") -> bool:
        if self.low and self.low != "0":
            c = compare_eco(version, self.low, ordering)
            if c < 0 or (c == 0 and not self.low_inclusive):
                return False
        if self.high:
            c = compare_eco(version, self.high, ordering)
            if c < 0:
                return True
            return c == 0 and self.high_inclusive
        return True

    def __repr__(self):  # pragma: no cover - debugging aid
        lop = ">=" if self.low_inclusive else ">"
        hop = "<=" if self.high_inclusive else "<"
        lo = f"{lop}{self.low}" if self.low else "*"
        hi = f"{hop}{self.high}" if self.high else "*"
        return f"Interval({lo} {hi})"


def intervals_from_events(events: List[dict],
                          ordering: str = "generic") -> List[Interval]:
    """Convert OSV range events into vulnerability intervals.

    Handles multiple introduced/fixed pairs (a vuln re-opened in a later
    series: 0..1.2.8 AND 2.0.0..2.0.4) and last_affected (inclusive) ends.
    Malformed events are skipped, never guessed from.
    """
    out: List[Interval] = []
    cur: Optional[Interval] = None
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        if "introduced" in ev:
            if cur is not None:          # unterminated previous window
                out.append(cur)
            cur = Interval(low=str(ev["introduced"] or ""))
        elif "fixed" in ev:
            if cur is None:
                cur = Interval(low="")   # fixed without introduced: from 0
            cur.high = str(ev["fixed"] or "")
            cur.high_inclusive = False
            out.append(cur)
            cur = None
        elif "last_affected" in ev:
            if cur is None:
                cur = Interval(low="")
            cur.high = str(ev["last_affected"] or "")
            cur.high_inclusive = True
            out.append(cur)
            cur = None
        elif "limit" in ev:              # OSV limit event - informational
            continue
    if cur is not None:
        out.append(cur)                  # window never closed: still open
    return out


# --------------------------------------------------------------------------
# advisory range strings (GitHub / Snyk style)
# --------------------------------------------------------------------------

_OPS = [">=", "<=", "==", ">", "<", "="]    # longest match first
_CARET_TILDE_RE = re.compile(r"^[\^~]\s*v?[0-9][0-9A-Za-z.\-+]*$")


def parse_range_string(rng: str, ordering: str = "generic") -> Optional[List[Interval]]:
    """Parse an advisory range string into intervals. None when unparsable.

    Supported forms:
      ">= 1.0, < 1.2"   comma-separated comparator conjunction
      "<1.2.3" / ">1.0" / "<=2.0" / "=1.5" / "==2.0"
      "1.0 - 2.0"       hyphen range (inclusive both ends, high exclusive
                        as advisory convention: 1.0 <= v < 2.0 boundary at
                        the last stated version series)
      "~1.2.3" / "^1.2.3"  npm caret/tilde shorthand (semver ordering only)
      "*" / ""          everything
    """
    s = (rng or "").strip()
    if not s or s == "*":
        return [Interval()]
    # caret / tilde - meaningful under semver ordering; approximate for others
    if _CARET_TILDE_RE.match(s):
        return _caret_tilde(s, ordering)

    # hyphen range "1.0 - 2.0" (space-hyphen-space)
    m = re.match(r"^\s*v?([0-9][0-9A-Za-z.\-+]*)\s+-\s+v?([0-9][0-9A-Za-z.\-+]*)\s*$", s)
    if m:
        return [Interval(low=m.group(1), high=m.group(2))]

    # comparator conjunction ">= 1.0.0, < 1.2.3"
    lo, lo_inc, hi, hi_inc = "", True, "", False
    saw = 0
    for part in s.split(","):
        p = part.strip()
        if not p:
            continue
        op, ver = None, None
        for cand_op in _OPS:                    # longest-match operator scan
            if p.startswith(cand_op):
                op, ver = cand_op, p[len(cand_op):].strip()
                break
        if op is None:                          # bare version == equality
            op, ver = "=", p
        ver = ver.lstrip("v") or ver
        saw += 1
        if op in (">", ">="):
            if lo == "" or compare_eco(ver, lo, ordering) >= 0:
                lo, lo_inc = ver, (op == ">=")
        elif op in ("<", "<="):
            if hi == "" or compare_eco(ver, hi, ordering) <= 0:
                hi, hi_inc = ver, (op == "<=")
        elif op in ("=", "=="):
            return [Interval(low=ver, high=ver, high_inclusive=True)]
    if not saw:
        return None
    return [Interval(low=lo, high=hi,
                     low_inclusive=lo_inc, high_inclusive=hi_inc)]


def _bump(ver: str, idx: int) -> str:
    """Bump the idx-th numeric component of a dotted version, zeroing rest."""
    parts = re.findall(r"\d+", ver)
    while len(parts) <= idx:
        parts.append("0")
    parts = parts[: idx + 1]
    parts[idx] = str(int(parts[idx]) + 1)
    return ".".join(parts)


def _caret_tilde(s: str, ordering: str) -> Optional[List[Interval]]:
    kind, rest = s[0], s[1:].strip().lstrip("v")
    m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", rest)
    if not m:
        return None
    base = rest
    if kind == "~":                             # ~1.2.3 -> <1.3.0 ; ~1.2 -> <1.3
        hi = _bump(base, 1)
    else:
        # npm caret: bump the leftmost non-zero component
        #   ^1.2.3 -> <2.0.0   ^0.2.3 -> <0.3.0   ^0.0.3 -> <0.0.4
        #   ^0.2   -> <0.3.0   ^0.0    -> <0.1.0   ^0    -> <1.0.0
        maj = int(m.group(1) or 0)
        mi_g, pa_g = m.group(2), m.group(3)
        if maj > 0:
            hi = _bump(base, 0)
        elif mi_g is not None and int(mi_g) > 0:
            hi = _bump(base, 1)
        elif pa_g is not None:
            hi = _bump(base, 2)
        elif mi_g is not None:
            hi = _bump(base, 1)
        else:
            hi = _bump(base, 0)
    return [Interval(low=base, high=hi)]


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------

def affects(version: str,
            ecosystem: Optional[str] = None,
            *,
            events: Optional[List[dict]] = None,
            range_string: Optional[str] = None,
            range_type: Optional[str] = None,
            versions: Optional[List[str]] = None,
            ordering: Optional[str] = None) -> bool:
    """Does `version` fall inside a vulnerability range?

    Exactly one of `events` (OSV event list), `range_string` (advisory text)
    or `versions` (explicit list) should describe the range; precedence:
    versions > events > range_string. Never raises - unparsable range means
    False (cannot prove affected -> report nothing, honest mode).
    """
    if not version:
        return False
    order = ordering or detect_ordering(ecosystem, range_type)
    if versions:
        return version.strip() in [str(v).strip() for v in versions]
    if events:
        return any(iv.contains(version, order)
                   for iv in intervals_from_events(events, order))
    if range_string:
        ivs = parse_range_string(range_string, order)
        if ivs is None:
            return False
        return any(iv.contains(version, order) for iv in ivs)
    return False
