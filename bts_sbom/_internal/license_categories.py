# vendored from common/license_categories.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
Single source of truth for "what kind of license is this" + a category-based
compatibility engine.

Before this module the SCA license layer had five overlapping knowledge bases
(`license_analyzer.SPDX_OBLIGATIONS` / `_COPYLEFT_PRIORITY` / `LICENSE_COMPAT`,
`license_norm._copyleft_set`, `license_utils._LICENSE_MAP`, `api._LICENSE_RISK_MAP`)
and `check_compatibility` treated any pair NOT in its ~55-entry hand table as
"compatible" -- an unsafe silent default for a compliance tool.

Here we classify each canonical SPDX id into ONE category and derive pairwise
verdicts (compatible / conditional / incompatible / unknown) from category +
GPL-version direction rules. The hand table stays as an override for nuance the
category model can't express (Apache-2.0 patent-termination vs GPL-2.0-only, etc).

Categories
----------
  public-domain   CC0-1.0, Unlicense, 0BSD, WTFPL  -- no obligations
  permissive      MIT, BSD-*, Apache-2.0, ISC, Zlib, BSL-1.0, MPL-1.0(historical)
  weak-copyleft   LGPL-*, MPL-2.0, EPL-*, CDDL-*, MS-RL, EUPL-*, CECILL-C, Artistic-2.0
  strong-copyleft GPL-*, OSL-*, CECILL-2.*, SSPL is separate
  network-copyleft AGPL-*, SSPL-1.0, EUPL is weak but has a compatibility list
  proprietary     Proprietary, Commercial, LicenseRef-*, NOASSERTION-with-text
  unknown         anything we cannot map (NEVER silently assumed safe)
"""
from __future__ import annotations

import re
from typing import Dict, Optional, Tuple

PUBLIC_DOMAIN = "public-domain"
PERMISSIVE = "permissive"
WEAK_COPYLEFT = "weak-copyleft"
STRONG_COPYLEFT = "strong-copyleft"
NETWORK_COPYLEFT = "network-copyleft"
PROPRIETARY = "proprietary"
UNKNOWN = "unknown"

# Restrictiveness ladder (higher = more obligations imposed on the combined work).
RESTRICTIVENESS = {
    PUBLIC_DOMAIN: 0, PERMISSIVE: 1, WEAK_COPYLEFT: 2,
    STRONG_COPYLEFT: 3, NETWORK_COPYLEFT: 4, PROPRIETARY: 5, UNKNOWN: 2,
}

# Exact canonical-SPDX -> category. Keys are lowercased for lookup.
_EXACT: Dict[str, str] = {}


def _add(cat: str, *ids: str) -> None:
    for i in ids:
        _EXACT[i.lower()] = cat


_add(PUBLIC_DOMAIN, "CC0-1.0", "Unlicense", "0BSD", "WTFPL", "blessing", "MIT-0")
_add(PERMISSIVE,
     "MIT", "MIT-Modern-Variant", "X11", "ISC",
     "BSD-1-Clause", "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear", "BSD-4-Clause",
     "BSD-2-Clause-Patent",
     "Apache-2.0", "Apache-1.1",
     "Zlib", "libpng-2.0", "Libpng", "bzip2-1.0.6",
     "BSL-1.0", "PostgreSQL", "Python-2.0", "PSF-2.0", "NCSA",
     "curl", "OpenSSL", "SSLeay", "Unicode-DFS-2016", "Zend-2.0",
     "MS-PL", "Boost", "UPL-1.0")
_add(WEAK_COPYLEFT,
     "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later",
     "LGPL-3.0-only", "LGPL-3.0-or-later",
     "MPL-2.0", "MPL-1.1",
     "EPL-1.0", "EPL-2.0",
     "CDDL-1.0", "CDDL-1.1",
     "MS-RL", "Ms-RL",
     "CECILL-C", "CECILL-B",
     "Artistic-2.0", "Artistic-1.0", "ClArtistic",
     "APSL-2.0", "IPL-1.0", "CPL-1.0", "Sleepycat",
     "EUPL-1.1", "EUPL-1.2", "OSL-1.0")
_add(STRONG_COPYLEFT,
     "GPL-1.0-only", "GPL-1.0-or-later",
     "GPL-2.0-only", "GPL-2.0-or-later",
     "GPL-3.0-only", "GPL-3.0-or-later",
     "OSL-2.0", "OSL-2.1", "OSL-3.0",
     "CECILL-2.0", "CECILL-2.1",
     "QPL-1.0", "RPL-1.5", "RPSL-1.0", "GFDL-1.3-only", "GFDL-1.3-or-later",
     "CC-BY-SA-4.0", "CC-BY-SA-3.0")
_add(NETWORK_COPYLEFT,
     "AGPL-3.0-only", "AGPL-3.0-or-later", "AGPL-1.0-only", "AGPL-1.0-or-later",
     "SSPL-1.0", "CPAL-1.0", "OSL-3.0-network")
_add(PROPRIETARY, "Proprietary", "Commercial", "NONFREE", "SEE-LICENSE-IN-FILE")

# Substring fallbacks when the exact id is not known (applied on lowercased text).
_SUBSTRING = [
    ("agpl", NETWORK_COPYLEFT), ("sspl", NETWORK_COPYLEFT),
    ("lgpl", WEAK_COPYLEFT),
    ("gpl", STRONG_COPYLEFT),         # after lgpl/agpl so those win
    ("mpl", WEAK_COPYLEFT), ("cddl", WEAK_COPYLEFT), ("epl", WEAK_COPYLEFT),
    ("cecill-c", WEAK_COPYLEFT), ("cecill", STRONG_COPYLEFT),
    ("osl-", STRONG_COPYLEFT), ("eupl", WEAK_COPYLEFT),
    ("cc-by-sa", STRONG_COPYLEFT),
    ("bsd", PERMISSIVE), ("mit", PERMISSIVE), ("apache", PERMISSIVE),
    ("isc", PERMISSIVE), ("zlib", PERMISSIVE), ("boost", PERMISSIVE),
    ("bsl-1.0", PERMISSIVE), ("artistic", WEAK_COPYLEFT),
    ("public domain", PUBLIC_DOMAIN), ("cc0", PUBLIC_DOMAIN), ("unlicense", PUBLIC_DOMAIN),
    ("proprietary", PROPRIETARY), ("commercial", PROPRIETARY),
    ("licenseref-", PROPRIETARY),
]

_NONE = {"", "unknown", "none", "noassertion", "n/a", "unlicensed",
         "nonstandard", "non-standard"}

_GPL_RE = re.compile(r"^(a?gpl)-(\d)\.(\d)(?:-(only|or-later))?$", re.I)


def category(spdx_id: Optional[str]) -> str:
    """Return the license category for a single (non-compound) SPDX id."""
    raw = (spdx_id or "").strip()
    low = raw.lower()
    if not low or low in _NONE:
        return UNKNOWN
    if low in _EXACT:
        return _EXACT[low]
    # deprecated-id shims
    low2 = (low.replace("gpl-2.0+", "gpl-2.0-or-later")
                .replace("gpl-3.0+", "gpl-3.0-or-later")
                .replace("lgpl-2.1+", "lgpl-2.1-or-later")
                .replace("lgpl-3.0+", "lgpl-3.0-or-later")
                .replace("agpl-3.0+", "agpl-3.0-or-later"))
    if low2 in _EXACT:
        return _EXACT[low2]
    for needle, cat in _SUBSTRING:
        if needle in low:
            return cat
    if low.startswith("licenseref-"):
        return PROPRIETARY
    return UNKNOWN


def gpl_family(spdx_id: Optional[str]) -> Optional[Tuple[str, int, int, str]]:
    """('gpl'|'agpl', major, minor, 'only'|'or-later') for a GPL/AGPL id, else None."""
    m = _GPL_RE.match((spdx_id or "").strip().replace("+", "-or-later"))
    if not m:
        return None
    fam = m.group(1).lower()
    return fam, int(m.group(2)), int(m.group(3)), (m.group(4) or "only").lower()


def _gpl_versions_compatible(a: Tuple, b: Tuple) -> Tuple[str, str]:
    """Compatibility of two GPL/AGPL ids by version direction.

    - same (fam, major, minor)                       -> compatible
    - one side is '-or-later' whose (major,minor) <= the other's -> compatible
      (the or-later side can move up to the other's version)
    - AGPL vs GPL of the SAME version                -> compatible (AGPL is a superset)
    - different fixed versions ('-only' vs '-only')  -> incompatible
    """
    fa, maja, mina, ra = a
    fb, majb, minb, rb = b
    va, vb = (maja, mina), (majb, minb)
    if (fa, va) == (fb, vb):
        return "compatible", "same GPL version"
    # AGPL is GPL + network clause; combining across GPL/AGPL of the same version is OK
    if va == vb:
        return "compatible", "GPL and AGPL of the same version interoperate"
    if ra == "or-later" and va <= vb:
        return "compatible", f"{fa.upper()}-{maja}.{mina}-or-later can adopt the newer version"
    if rb == "or-later" and vb <= va:
        return "compatible", f"{fb.upper()}-{majb}.{minb}-or-later can adopt the newer version"
    return "incompatible", "different fixed GPL versions cannot be combined"


# Category-pair verdicts (order-independent). Missing pair -> derived below.
_CAT_PAIR: Dict[frozenset, Tuple[str, str]] = {
    frozenset({PERMISSIVE, PERMISSIVE}): ("compatible", "both permissive"),
    frozenset({PERMISSIVE, PUBLIC_DOMAIN}): ("compatible", "permissive + public domain"),
    frozenset({PUBLIC_DOMAIN, PUBLIC_DOMAIN}): ("compatible", "both public domain"),
    frozenset({PERMISSIVE, WEAK_COPYLEFT}): ("compatible", "permissive flows into weak copyleft"),
    frozenset({PERMISSIVE, STRONG_COPYLEFT}): ("compatible", "permissive into strong copyleft; combined work is copyleft"),
    frozenset({PERMISSIVE, NETWORK_COPYLEFT}): ("conditional", "network-copyleft obligations govern the combined/served work"),
    frozenset({PUBLIC_DOMAIN, WEAK_COPYLEFT}): ("compatible", "public domain into weak copyleft"),
    frozenset({PUBLIC_DOMAIN, STRONG_COPYLEFT}): ("compatible", "public domain into strong copyleft"),
    frozenset({PUBLIC_DOMAIN, NETWORK_COPYLEFT}): ("conditional", "network-copyleft obligations govern"),
    frozenset({WEAK_COPYLEFT, WEAK_COPYLEFT}): ("conditional", "two weak-copyleft licenses -- verify per-file / relinking obligations of each"),
    frozenset({WEAK_COPYLEFT, STRONG_COPYLEFT}): ("conditional", "weak + strong copyleft -- combination method (linking vs derivation) decides"),
    frozenset({WEAK_COPYLEFT, NETWORK_COPYLEFT}): ("conditional", "network-copyleft obligations govern the combined work"),
    frozenset({STRONG_COPYLEFT, NETWORK_COPYLEFT}): ("conditional", "AGPL/SSPL network clause governs; version direction still applies"),
    frozenset({NETWORK_COPYLEFT, NETWORK_COPYLEFT}): ("conditional", "two network-copyleft licenses -- reconcile which governs the service"),
    frozenset({STRONG_COPYLEFT, STRONG_COPYLEFT}): ("conditional", "two strong-copyleft licenses -- resolved by GPL version rules where applicable"),
}


def compatible(a: Optional[str], b: Optional[str]) -> Tuple[str, str]:
    """Pairwise verdict for two single SPDX ids.

    Returns (status, reason) with status in
    'compatible' | 'conditional' | 'incompatible' | 'unknown'.
    Unknown category on EITHER side yields 'unknown' -- never a silent 'compatible'.
    """
    ca, cb = category(a), category(b)
    if UNKNOWN in (ca, cb):
        which = a if ca == UNKNOWN else b
        return "unknown", f"'{which}' is not a recognized SPDX license -- manual review required"
    if PROPRIETARY in (ca, cb):
        other = cb if ca == PROPRIETARY else ca
        if other in (STRONG_COPYLEFT, NETWORK_COPYLEFT):
            return "incompatible", "a proprietary component cannot be combined with (A)GPL-class copyleft under one distribution"
        return "conditional", "proprietary component present -- confirm redistribution rights"

    ga, gb = gpl_family(a), gpl_family(b)
    if ga and gb:
        return _gpl_versions_compatible(ga, gb)

    key = frozenset({ca, cb})
    if key in _CAT_PAIR:
        return _CAT_PAIR[key]
    # symmetric single-category fallthrough
    if ca == cb:
        return _CAT_PAIR.get(frozenset({ca}), ("conditional", f"two {ca} licenses -- verify obligations"))
    return "conditional", f"{ca} + {cb} -- category interaction needs review"
