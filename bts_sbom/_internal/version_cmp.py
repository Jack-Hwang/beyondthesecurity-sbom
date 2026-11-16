# vendored from common/version_cmp.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
Tolerant version comparison for CPE / CVE version-range matching.

Native firmware components use messy, non-semver versions: openssl `1.0.2k`,
zlib `1.2.11`, busybox `1.35.0`, dropbear `2019.78`, kernel `5.4.0-rc1`, debian
epochs `1:2.3`, and `~`/`+`/`-` separators. Getting the ordering right is the #1
source of false positives/negatives in CPE matching, so this comparator is
deliberately explicit and unit-tested by the SCA benchmark.

Rules:
  - strip a leading 'v' and any debian epoch 'N:'.
  - split into components on . _ - + ~ , then each component into maximal runs of
    digits and non-digits.
  - compare component-wise, token-wise: digit runs numerically, alpha runs
    case-insensitively lexicographically.
  - when one side runs out of tokens, the side with an EXTRA token is greater,
    UNLESS that extra leading token is a pre-release word (rc/alpha/beta/pre/dev/
    snapshot), in which case it is LESS (1.0.0-rc1 < 1.0.0).
"""
import re
from typing import List, Tuple

_PRERELEASE = {"rc", "alpha", "beta", "pre", "dev", "snapshot"}
# INTENTIONALLY excludes the single-letter abbreviations "a", "b", "m":
# OpenSSL and many firmware components use single-letter suffixes as PATCH releases
# (1.0.2a … 1.0.2u, 1.0.2m, etc.).  Including "a"/"b"/"m" caused those versions to
# compare as LESS THAN the bare base (e.g. 1.0.2a < 1.0.2), which produced false-
# negative CVE range matches: a range versionEndExcluding:1.0.2a failed to flag
# version 1.0.2 as affected.  True alpha/beta pre-releases should use the full word
# ("alpha", "beta") or the "rc" prefix rather than single-letter abbreviations.
_EPOCH_RE = re.compile(r"^\d+:")

# ── Format-specific patterns for compare_versions() dispatcher ────────────────

# Go pseudo-version: v0.0.0-YYYYMMDD-abcdef012345
_GO_PSEUDO_RE = re.compile(r'^v?0\.0\.0-(\d{8})-[0-9a-f]{12}$')

# CalVer: YYYY  or  YYYY.MM  or  YYYY.MM.DD  (4-digit year required)
_CALVER_RE = re.compile(r'^\d{4}(\.\d{1,2}){0,2}$')

# RPM Epoch:Version-Release  e.g. 2:1.2.3-4.el8
_RPM_EPOCH_FULL_RE = re.compile(r'^(\d+):(.+)-(.+)$')
# RPM Epoch:Version without release  e.g. 1:2.3.4
_RPM_EPOCH_NREL_RE = re.compile(r'^(\d+):(.+)$')


def _normalize(v: str) -> str:
    v = (v or "").strip().lower()
    if v.startswith("v"):
        v = v[1:]
    v = _EPOCH_RE.sub("", v)            # drop debian epoch "1:"
    return v


def _tokenize(v: str) -> List[Tuple[int, object]]:
    """Return a flat token list; each token is (kind, value) where kind 0=digit
    (value int) and kind 1=alpha (value str). Separators split components."""
    tokens: List[Tuple[int, object]] = []
    for comp in re.split(r"[._\-+~,]", _normalize(v)):
        for run in re.findall(r"\d+|[a-z]+", comp):
            if run.isdigit():
                tokens.append((0, int(run)))
            else:
                tokens.append((1, run))
    return tokens


def compare(a: str, b: str) -> int:
    """Return -1 if a<b, 0 if equal, 1 if a>b."""
    ta, tb = _tokenize(a), _tokenize(b)
    n = min(len(ta), len(tb))
    for i in range(n):
        ka, va = ta[i]
        kb, vb = tb[i]
        if ka != kb:
            # A numeric token outranks an alpha token at the same position
            # (1.0.2 vs 1.0.2a is handled by the tail rule below, not here):
            # e.g. 1.0 vs 1.a -> 0 > a, numeric is greater.
            return 1 if ka == 0 else -1
        if va != vb:
            if ka == 0:
                return -1 if va < vb else 1
            return -1 if va < vb else 1
    if len(ta) == len(tb):
        return 0
    # One side has extra trailing tokens. Inspect the first extra token.
    longer, sign = (ta, 1) if len(ta) > len(tb) else (tb, -1)
    kind, val = longer[n]
    if kind == 1 and str(val) in _PRERELEASE:
        return -sign          # extra pre-release token → the longer side is LESS
    return sign               # otherwise the longer side is greater


def lt(a, b): return compare(a, b) < 0
def le(a, b): return compare(a, b) <= 0
def gt(a, b): return compare(a, b) > 0
def ge(a, b): return compare(a, b) >= 0
def eq(a, b): return compare(a, b) == 0


# ─── Format-specific comparators ──────────────────────────────────────────────

def _detect_format(v: str) -> str:
    """Classify a version string into one of four format tokens."""
    v = (v or "").strip()
    if _RPM_EPOCH_FULL_RE.match(v) or _RPM_EPOCH_NREL_RE.match(v):
        return "rpm_epoch"
    if _GO_PSEUDO_RE.match(v):
        return "go_pseudo"
    if _CALVER_RE.match(v):
        return "calver"
    return "semver"


def _parse_rpm(v: str) -> Tuple[int, str, str]:
    """Parse an RPM Epoch:Version-Release string.

    Returns (epoch, version, release).  No epoch prefix is treated as epoch 0.
    No release component is treated as an empty string.
    """
    m = _RPM_EPOCH_FULL_RE.match(v)
    if m:
        return int(m.group(1)), m.group(2), m.group(3)
    m = _RPM_EPOCH_NREL_RE.match(v)
    if m:
        return int(m.group(1)), m.group(2), ""
    # No epoch prefix — treat as epoch 0.
    if "-" in v:
        ver, rel = v.rsplit("-", 1)
        return 0, ver, rel
    return 0, v, ""


def _compare_go_pseudo(a: str, b: str) -> int:
    """Compare Go pseudo-versions against each other or real semver tags.

    A real semver tag (v1.2.3, v0.1.0, …) always beats a pseudo-version
    because pseudo-versions represent unreleased commits.  Two pseudo-versions
    are ordered by their embedded date integer.
    """
    ma = _GO_PSEUDO_RE.match((a or "").strip())
    mb = _GO_PSEUDO_RE.match((b or "").strip())

    if ma and mb:
        da, db = int(ma.group(1)), int(mb.group(1))
        return -1 if da < db else (1 if da > db else 0)
    if ma and not mb:
        return -1   # a is pseudo, b is real semver → a < b
    if not ma and mb:
        return 1    # a is real semver, b is pseudo → a > b
    return compare(a, b)   # both are real semver — fall through to default


def _compare_calver(a: str, b: str) -> int:
    """Compare CalVer strings (YYYY, YYYY.MM, or YYYY.MM.DD).

    Components are compared as integers: year, then month, then day.
    Missing components default to 0 so '2023' < '2023.1' < '2023.1.15'.
    """
    def _parts(v: str) -> List[int]:
        result = []
        for seg in v.strip().split("."):
            try:
                result.append(int(seg))
            except ValueError:
                result.append(0)
        while len(result) < 3:
            result.append(0)
        return result

    pa, pb = _parts(a), _parts(b)
    for x, y in zip(pa, pb):
        if x != y:
            return -1 if x < y else 1
    return 0


def _compare_rpm_epoch(a: str, b: str) -> int:
    """Compare RPM Epoch:Version-Release strings.

    Priority: Epoch (integer) > Version (semver compare) > Release (string lex).
    A string without an epoch prefix is treated as epoch 0.
    """
    ea, va, ra = _parse_rpm((a or "").strip())
    eb, vb, rb = _parse_rpm((b or "").strip())

    if ea != eb:
        return -1 if ea < eb else 1
    vc = compare(va, vb)
    if vc != 0:
        return vc
    if ra != rb:
        return -1 if ra < rb else 1
    return 0


# ─── Dispatcher ───────────────────────────────────────────────────────────────

def compare_versions(a: str, b: str) -> int:
    """Compare two version strings, dispatching to the appropriate handler.

    Format detection order
    ----------------------
    1. RPM Epoch:Version-Release  — if either side carries an epoch prefix
       the RPM comparator handles both (no-epoch side treated as epoch 0).
    2. Go pseudo-version          — if either side is a Go pseudo-version
       (v0.0.0-YYYYMMDD-hash); real semver always beats pseudo.
    3. CalVer                     — only when *both* sides are CalVer
       (YYYY / YYYY.MM / YYYY.MM.DD).
    4. Semver / legacy fallback   — delegates to the existing compare().

    Returns -1, 0, or 1 with the same semantics as compare().
    """
    a_fmt = _detect_format(a)
    b_fmt = _detect_format(b)

    if a_fmt == "rpm_epoch" or b_fmt == "rpm_epoch":
        return _compare_rpm_epoch(a, b)

    if a_fmt == "go_pseudo" or b_fmt == "go_pseudo":
        return _compare_go_pseudo(a, b)

    if a_fmt == "calver" and b_fmt == "calver":
        return _compare_calver(a, b)

    return compare(a, b)
