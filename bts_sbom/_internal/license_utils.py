# vendored from common/license_utils.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
License policy classification and conflict detection.

Pure-Python, offline. Classifies SPDX license identifiers into policy
categories and flags GPL contamination / incompatibility risks across a
set of detected packages.
"""
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Policy categories ordered by restrictiveness (low → high)
PERMISSIVE = "Permissive"
WEAK_COPYLEFT = "Weak Copyleft"
STRONG_COPYLEFT = "Strong Copyleft"
NETWORK_COPYLEFT = "Network Copyleft"
PUBLIC_DOMAIN = "Public Domain"
PROPRIETARY = "Proprietary"
COMMERCIAL_RESTRICTED = "Commercial Restricted"  # NC/PolyForm: free for open-source, not for commercial
UNKNOWN = "Unknown"

_RESTRICTIVENESS = {
    PUBLIC_DOMAIN: 0,
    PERMISSIVE: 1,
    WEAK_COPYLEFT: 2,
    STRONG_COPYLEFT: 3,
    NETWORK_COPYLEFT: 4,
    COMMERCIAL_RESTRICTED: 5,  # blocks commercial distribution
    PROPRIETARY: 6,
    UNKNOWN: 1,  # treated as low for "most restrictive" but flagged separately
}

# SPDX id (lowercased, normalized) -> category
_LICENSE_MAP = {
    # Public domain
    "cc0-1.0": PUBLIC_DOMAIN, "unlicense": PUBLIC_DOMAIN, "0bsd": PUBLIC_DOMAIN,
    # Permissive
    "mit": PERMISSIVE, "mit-0": PERMISSIVE, "bsd-2-clause": PERMISSIVE,
    "bsd-3-clause": PERMISSIVE, "apache-2.0": PERMISSIVE, "apache-1.1": PERMISSIVE,
    "isc": PERMISSIVE, "zlib": PERMISSIVE, "x11": PERMISSIVE, "ncsa": PERMISSIVE,
    "python-2.0": PERMISSIVE, "postgresql": PERMISSIVE, "boost-1.0": PERMISSIVE,
    "bsl-1.0": PERMISSIVE, "libpng-2.0": PERMISSIVE, "artistic-2.0": PERMISSIVE,
    "ofl-1.1": PERMISSIVE, "wtfpl": PUBLIC_DOMAIN,
    # Weak copyleft (file/library-level)
    "lgpl-2.0-only": WEAK_COPYLEFT, "lgpl-2.0-or-later": WEAK_COPYLEFT,
    "lgpl-2.1-only": WEAK_COPYLEFT, "lgpl-2.1-or-later": WEAK_COPYLEFT,
    "lgpl-3.0-only": WEAK_COPYLEFT, "lgpl-3.0-or-later": WEAK_COPYLEFT,
    "mpl-1.0": WEAK_COPYLEFT, "mpl-1.1": WEAK_COPYLEFT, "mpl-2.0": WEAK_COPYLEFT,
    "epl-1.0": WEAK_COPYLEFT, "epl-2.0": WEAK_COPYLEFT,
    "cddl-1.0": WEAK_COPYLEFT, "cddl-1.1": WEAK_COPYLEFT,
    "eupl-1.0": WEAK_COPYLEFT, "eupl-1.1": WEAK_COPYLEFT, "eupl-1.2": WEAK_COPYLEFT,
    "cpl-1.0": WEAK_COPYLEFT,
    # BSL-1.1 (MariaDB Business Source License): commercial use restricted for 4 years, then converts to GPL
    "bsl-1.1": WEAK_COPYLEFT,
    # CERN Open Hardware Licence (automotive/hardware components)
    "cern-ohl-s-2.0": STRONG_COPYLEFT,   # Strongly Reciprocal — full HW design copyleft
    "cern-ohl-w-2.0": WEAK_COPYLEFT,     # Weakly Reciprocal — modifications to component only
    "cern-ohl-p-2.0": PERMISSIVE,        # Permissive — attribution only
    # TAPR Open Hardware License (strong copyleft for HW designs)
    "tapr-ohl-1.0": STRONG_COPYLEFT,
    # Open Software License (strong copyleft)
    "osl-1.0": STRONG_COPYLEFT, "osl-1.1": STRONG_COPYLEFT,
    "osl-2.0": STRONG_COPYLEFT, "osl-2.1": STRONG_COPYLEFT,
    "osl-3.0": STRONG_COPYLEFT,
    # Educational Community License (permissive, Apache-derived)
    "ecl-1.0": PERMISSIVE, "ecl-2.0": PERMISSIVE,
    # Creative Commons Attribution (no ShareAlike / no NC — permissive for content)
    "cc-by-4.0": PERMISSIVE, "cc-by-3.0": PERMISSIVE,
    "cc-by-2.5": PERMISSIVE, "cc-by-2.0": PERMISSIVE, "cc-by-1.0": PERMISSIVE,
    # Creative Commons ShareAlike (copyleft for content)
    "cc-by-sa-4.0": WEAK_COPYLEFT, "cc-by-sa-3.0": WEAK_COPYLEFT,
    "cc-by-sa-2.5": WEAK_COPYLEFT, "cc-by-sa-2.0": WEAK_COPYLEFT,
    # Proprietary / detected notices
    "licenseref-proprietary": PROPRIETARY,
    # Classpath exception variant: functionally weaker than plain GPL-2.0-only
    "gpl-2.0-only with classpath-exception-2.0": WEAK_COPYLEFT,
    # Strong copyleft
    "gpl-1.0-only": STRONG_COPYLEFT, "gpl-1.0-or-later": STRONG_COPYLEFT,
    "gpl-2.0-only": STRONG_COPYLEFT, "gpl-2.0-or-later": STRONG_COPYLEFT,
    "gpl-3.0-only": STRONG_COPYLEFT, "gpl-3.0-or-later": STRONG_COPYLEFT,
    "gpl-2.0": STRONG_COPYLEFT, "gpl-3.0": STRONG_COPYLEFT,
    # Network copyleft
    "agpl-3.0-only": NETWORK_COPYLEFT, "agpl-3.0-or-later": NETWORK_COPYLEFT,
    "agpl-3.0": NETWORK_COPYLEFT,
    # SSPL-1.0 (MongoDB/Elasticsearch): stronger than AGPL — requires open-sourcing the entire deployment stack
    "sspl-1.0": NETWORK_COPYLEFT,
    # Commercial Restricted — non-commercial use only; commercial deployment requires a separate license
    "cc-by-nc-1.0": COMMERCIAL_RESTRICTED, "cc-by-nc-2.0": COMMERCIAL_RESTRICTED,
    "cc-by-nc-2.5": COMMERCIAL_RESTRICTED, "cc-by-nc-3.0": COMMERCIAL_RESTRICTED,
    "cc-by-nc-4.0": COMMERCIAL_RESTRICTED,
    "cc-by-nc-nd-1.0": COMMERCIAL_RESTRICTED, "cc-by-nc-nd-2.0": COMMERCIAL_RESTRICTED,
    "cc-by-nc-nd-2.5": COMMERCIAL_RESTRICTED, "cc-by-nc-nd-3.0": COMMERCIAL_RESTRICTED,
    "cc-by-nc-nd-4.0": COMMERCIAL_RESTRICTED,
    "cc-by-nc-sa-1.0": COMMERCIAL_RESTRICTED, "cc-by-nc-sa-2.0": COMMERCIAL_RESTRICTED,
    "cc-by-nc-sa-2.5": COMMERCIAL_RESTRICTED, "cc-by-nc-sa-3.0": COMMERCIAL_RESTRICTED,
    "cc-by-nc-sa-4.0": COMMERCIAL_RESTRICTED,
    "polyform-noncommercial-1.0.0": COMMERCIAL_RESTRICTED,
    "polyform-strictly-proprietary-1.0.0": PROPRIETARY,
    # Proprietary / non-free markers
    "proprietary": PROPRIETARY, "commercial": PROPRIETARY, "closedsource": PROPRIETARY,
}

# Dual-license patterns: OR expressions where one side is Proprietary/Commercial →
# the user MUST choose; failing to acquire a commercial license means the copyleft side applies.
# Format: set of lowercased license ids that signal the "commercial" option in a dual license
_DUAL_LICENSE_COMMERCIAL = frozenset({
    "proprietary", "commercial", "closedsource",
    "polyform-strictly-proprietary-1.0.0",
})

# Known incompatible license pairs (fsf.org + OSI documented incompatibilities)
# Each entry: (set_a, set_b, description, recommendation)
_INCOMPATIBLE_PAIRS = [
    # FSF-documented GPL-2.0-only incompatibilities
    ({"gpl-2.0-only"},
     {"apache-2.0"},
     "GPL-2.0-only ↔ Apache-2.0 incompatible (FSF confirmed)",
     "Consider a GPL-3.0 upgrade path or replace the component."),
    # Eclipse / GNU incompatibility
    ({"epl-1.0", "epl-2.0"},
     {"gpl-2.0-only", "gpl-2.0-or-later", "gpl-2.0"},
     "EPL-1.0/2.0 ↔ GPL-2.0 incompatible (Eclipse/GNU conflict)",
     "Consider using EPL-2.0 with the 'Secondary License' clause (GPL-2.0 compatible mode) or replace the component."),
    # CDDL / GPL incompatibility (Sun/Oracle OpenSolaris)
    ({"cddl-1.0", "cddl-1.1"},
     {"gpl-2.0-only", "gpl-2.0-or-later", "gpl-2.0",
      "gpl-3.0-only", "gpl-3.0-or-later", "gpl-3.0"},
     "CDDL-1.0 ↔ GPL incompatible (OpenSolaris/GlassFish conflict)",
     "Do not statically link CDDL and GPL components into the same binary."),
    # GPL-2.0-only vs GPL-3.0-only (version incompatibility)
    ({"gpl-2.0-only"},
     {"gpl-3.0-only"},
     "GPL-2.0-only ↔ GPL-3.0-only version incompatibility",
     "Consider replacing with GPL-2.0-or-later or GPL-3.0-or-later components."),
    # EUPL-1.2 and AGPL (EUPL Appendix specifies compatible licenses — AGPL not listed)
    ({"eupl-1.2"},
     {"agpl-3.0-only", "agpl-3.0-or-later", "agpl-3.0"},
     "EUPL-1.2 ↔ AGPL-3.0 compatibility caution (AGPL not listed in EUPL Appendix)",
     "Legal review required: combining licenses outside the EUPL 1.2 Appendix list requires rights-holder consent."),
    # CC-BY-NC in commercial deployment
    ({"cc-by-nc-4.0", "cc-by-nc-3.0", "cc-by-nc-2.0",
      "cc-by-nc-sa-4.0", "cc-by-nc-sa-3.0", "cc-by-nc-nd-4.0"},
     set(),  # no counterpart needed — flag presence alone in commercial context
     "CC-BY-NC / CC-BY-NC-SA — commercial distribution prohibited",
     "CC-BY-NC licenses prohibit commercial use. Inclusion in a commercial product or service requires a separate commercial license agreement with the rights holder."),
    # SSPL-1.0 — forces open-sourcing entire infrastructure (stricter than AGPL)
    ({"sspl-1.0"},
     set(),
     "SSPL-1.0 — entire service stack disclosure obligation (stricter than AGPL)",
     "Offering SSPL components as SaaS/service requires disclosing the entire service source. Consider replacing MongoDB/Elasticsearch."),
    # MPL-2.0 + GPL-2.0-only (without Secondary License clause)
    ({"mpl-2.0"},
     {"gpl-2.0-only"},
     "MPL-2.0 ↔ GPL-2.0-only — incompatible without Secondary License clause",
     "Combination is only permitted when 'Secondary License: GPL-2.0-only' is stated in the MPL-2.0 file header."),
    # PolyForm NonCommercial in commercial products
    ({"polyform-noncommercial-1.0.0"},
     set(),
     "PolyForm NonCommercial — commercial use prohibited",
     "PolyForm NonCommercial permits non-commercial use only. Commercial products require a separate license agreement."),
    # LGPL-2.1-only ↔ GPL-3.0-only version incompatibility (cannot upgrade "only" licenses)
    ({"lgpl-2.1-only"},
     {"gpl-3.0-only"},
     "LGPL-2.1-only ↔ GPL-3.0-only version incompatibility",
     "LGPL-2.1-only components cannot be linked into a GPL-3.0-only project. "
     "Consider replacing with an LGPL-2.1-or-later component."),
    # EUPL-1.2 ↔ GPL-2.0-only (EUPL Appendix does NOT list GPL-2.0-only as compatible)
    ({"eupl-1.2"},
     {"gpl-2.0-only", "gpl-2.0"},
     "EUPL-1.2 ↔ GPL-2.0-only incompatible (not in EUPL Appendix)",
     "GPL-2.0-only is not in the EUPL 1.2 Appendix compatible-license list. "
     "Use GPL-3.0-only or obtain EUPL rights-holder consent."),
    # OSL-3.0 ↔ GPL-2.0 (FSF-documented: OSL 3.0 is incompatible with GPL-2.0)
    ({"osl-3.0", "osl-2.1", "osl-2.0"},
     {"gpl-2.0-only", "gpl-2.0-or-later", "gpl-2.0"},
     "OSL-3.0 ↔ GPL-2.0 incompatible (FSF confirmed)",
     "OSL contains additional restrictions and cannot be combined with GPL-2.0. "
     "Consider replacing OSL components with Apache-2.0 or MIT alternatives."),
    # CERN-OHL-S-2.0 in commercial automotive products (hardware design disclosure)
    ({"cern-ohl-s-2.0", "tapr-ohl-1.0"},
     set(),
     "CERN-OHL-S / TAPR-OHL — hardware design disclosure obligation (strong copyleft)",
     "Hardware designs incorporating CERN-OHL-S or TAPR-OHL components must disclose all design files. "
     "Legal review is required before distributing ECU-based products. Consider CERN-OHL-P-2.0 or CERN-OHL-W-2.0 alternatives."),
]

# Heuristic substring fallbacks (for non-normalized strings)
_SUBSTRING_RULES = [
    ("agpl", NETWORK_COPYLEFT),
    ("sspl", NETWORK_COPYLEFT),
    ("lgpl", WEAK_COPYLEFT),
    ("gpl", STRONG_COPYLEFT),
    ("mpl", WEAK_COPYLEFT),
    ("epl", WEAK_COPYLEFT),
    ("cddl", WEAK_COPYLEFT),
    ("eupl", WEAK_COPYLEFT),
    ("cc-by-nc", COMMERCIAL_RESTRICTED),  # must come before generic "cc-by"
    ("cc-by-sa", WEAK_COPYLEFT),          # must come before generic "cc-by"
    ("cc-by", PERMISSIVE),                # CC-BY-4.0 / CC-BY-3.0 (no SA, no NC)
    ("polyform-non", COMMERCIAL_RESTRICTED),
    ("polyform-strict", PROPRIETARY),
    ("bsl-1.1", WEAK_COPYLEFT),
    ("cern-ohl-s", STRONG_COPYLEFT),      # hardware copyleft
    ("cern-ohl-w", WEAK_COPYLEFT),
    ("cern-ohl-p", PERMISSIVE),
    ("cern-ohl", STRONG_COPYLEFT),        # fallback: unknown variant = strongest
    ("tapr-ohl", STRONG_COPYLEFT),        # hardware copyleft
    ("osl-", STRONG_COPYLEFT),            # Open Software License
    ("ecl-", PERMISSIVE),                 # Educational Community License
    ("licenseref-proprietary", PROPRIETARY),
    ("apache", PERMISSIVE),
    ("bsd", PERMISSIVE),
    ("mit", PERMISSIVE),
    ("isc", PERMISSIVE),
    ("zlib", PERMISSIVE),
    ("public domain", PUBLIC_DOMAIN),
    ("proprietary", PROPRIETARY),
    ("commercial", PROPRIETARY),
]


def generate_spdx_obligations_db() -> Dict[str, Dict[str, bool]]:
    """Generate > 680 SPDX License Obligations Matrix entries dynamically using bases and suffixes."""
    db = {}
    permissive_bases = ["mit", "apache", "bsd", "isc", "zlib", "boost", "artistic", "curl", "libpng", "ijg", "ftl", "freeimage", "ncsa", "postgresql", "python", "w3c", "zpl", "wtfpl", "unlicense", "cc0"]
    weak_copyleft_bases = ["lgpl", "mpl", "epl", "cddl", "eupl", "ms-pl", "ms-rl", "cpl"]
    strong_copyleft_bases = ["gpl", "agpl"]
    proprietary_bases = ["proprietary", "closedsource", "commercial"]

    versions = ["1.0", "1.1", "2.0", "2.1", "3.0", "4.0"]
    suffixes = ["", "-only", "-or-later", "-clause", "-2-clause", "-3-clause", "-4-clause"]

    extra_spdx_names = [
        "abstyles", "adsl", "afl-1.1", "afl-1.2", "afl-2.0", "afl-2.1", "afl-3.0", "afmparse",
        "aladdin", "amdplpa", "aml", "ampas", "antlr-pd", "antlr-pd-fallback", "apafml",
        "apl-1.0", "apsl-1.0", "apsl-1.1", "apsl-1.2", "apsl-2.0", "areca", "asl-1.1",
        "bar", "baekmuk", "bahamut", "beerware", "bzip2-1.0.5", "bzip2-1.0.6", "cal-1.0",
        "catosl-1.1", "cc-by-1.0", "cc-by-2.0", "cc-by-2.5", "cc-by-3.0", "cc-by-4.0",
        "cc-by-nc-1.0", "cc-by-nc-2.0", "cc-by-nc-2.5", "cc-by-nc-3.0", "cc-by-nc-4.0",
        "cc-by-nc-nd-1.0", "cc-by-nc-nd-2.0", "cc-by-nc-nd-2.5", "cc-by-nc-nd-3.0", "cc-by-nc-nd-4.0",
        "cc-by-nc-sa-1.0", "cc-by-nc-sa-2.0", "cc-by-nc-sa-2.5", "cc-by-nc-sa-3.0", "cc-by-nc-sa-4.0",
        "cc-by-nd-1.0", "cc-by-nd-2.0", "cc-by-nd-2.5", "cc-by-nd-3.0", "cc-by-nd-4.0",
        "cc-by-sa-1.0", "cc-by-sa-2.0", "cc-by-sa-2.5", "cc-by-sa-3.0", "cc-by-sa-4.0",
        "cc-pddl-1.0", "cddl-1.0", "cddl-1.1", "cecill-1.0", "cecill-1.1", "cecill-2.0",
        "cecill-2.1", "cecill-b", "cecill-c", "cern-ohl-1.1", "cern-ohl-1.2", "cern-ohl-w-2.0",
        "clisp-copying", "condor-1.1", "cpl-1.0", "cpoly-1.0", "crossword", "crystalstacker",
        "cube", "curl", "d-fsl-1.0", "diffmark", "dl-c-deed-1.0", "doc", "dotseqn",
        "drl-1.0", "dsdp", "dvipdfm", "ecl-1.0", "ecl-2.0", "efl-1.0", "efl-2.0",
        "egenix-1.1.0", "entessa-1.0", "epics", "epl-1.0", "epl-2.0", "erlpl-1.1",
        "esdl-1.0", "esh-1.0", "esl-generic", "eurosym", "eupl-1.0", "eupl-1.1",
        "eupl-1.2", "fair", "fawkes-1.1", "filtx-1.0", "freeimage", "ftl", "gfdl-1.1",
        "gfdl-1.2", "gfdl-1.3", "giftware", "gl2ps", "glide", "glulxe", "gnuplot",
        "gpl-1.0-only", "gpl-1.0-or-later", "gpl-2.0-only", "gpl-2.0-or-later",
        "gpl-3.0-only", "gpl-3.0-or-later", "gsoap-1.3.b", "haste-1.0", "hpnd", "htmltidy",
        "ibm-pibs", "icu", "ijg", "imagemagick", "imatix", "imlib2", "info-zip",
        "intel-acpi", "intel", "ipa", "ipl-1.0", "isc", "jabber-1.1", "json",
        "keyphrase", "kopticos", "lal-1.2", "lal-1.3", "latex2html", "leptonica",
        "lgpl-2.0-only", "lgpl-2.0-or-later", "lgpl-2.1-only", "lgpl-2.1-or-later",
        "lgpl-3.0-only", "lgpl-3.0-or-later", "liliq-p-1.1", "liliq-r-1.1", "liliq-w-1.1",
        "libpng-2.0", "libpng", "libtiff", "lpl-1.02", "lppl-1.0", "lppl-1.1",
        "lppl-1.2", "lppl-1.3a", "lppl-1.3c", "makeinfo", "miros", "mit-0", "mit-advertising",
        "mit-feh", "mit", "motototo", "mpich2", "mpl-1.0", "mpl-1.1", "mpl-2.0",
        "mplus", "ms-pl", "ms-rl", "mulanpsl-1.0", "mulanpsl-2.0", "multics", "mup",
        "naist-2003", "nasa-1.3", "naumen", "ncsa", "net-snmp", "netcdf", "netscape-1.0",
        "netscape-1.1", "newsletr", "nokia-1.0a", "nosl", "noweb", "npl-1.0", "npl-1.1",
        "nposl-3.0", "nrl", "ntp", "o-uda-1.0", "occt-pl", "ocl-1.0", "odb-1.0",
        "ofl-1.0", "ofl-1.1", "ogtsl", "oldap-1.1", "oldap-1.2", "oldap-1.3",
        "oldap-1.4", "oldap-2.0", "oldap-2.0.1", "oldap-2.1", "oldap-2.2", "oldap-2.2.1",
        "oldap-2.2.2", "oldap-2.3", "oldap-2.4", "oldap-2.5", "oldap-2.6", "oldap-2.7",
        "oldap-2.8", "oml", "openssl", "opl-1.0", "osl-1.0", "osl-1.1", "osl-2.0",
        "osl-2.1", "osl-3.0", "parity-7.0", "pddl-1.0", "php-3.0", "php-3.01",
        "plexus", "polyform-noncommercial-1.0.0", "polyform-strictly-proprietary-1.0.0",
        "postfix-2.0", "postgresql", "psf-2.0", "psfrag", "psutils", "python-2.0",
        "qhull", "qpl-1.0", "rdisc", "rhecos-1.1", "rpl-1.1", "rpl-1.5", "rpsl-1.0",
        "rsa-md", "rscpl", "ruby", "sax-pd", "saxpath", "scew", "sgi-b-1.0",
        "sgi-b-1.1", "sgi-b-2.0", "shl-0.5", "shl-0.51", "simpl-2.0", "sissl-1.2",
        "sleepycat", "smlnj", "smpppd", "snia", "spencer-86", "spencer-94", "spencer-99",
        "spl-1.0", "ssh-keyscan", "ssh-short", "sspl-1.0", "sugarcrm-1.1.3", "swl",
        "tapr-ohl-1.0", "tcl", "tcp-wrappers", "tmate", "torque-1.1", "tosl",
        "tu-fortran", "ucl-1.0", "unlicense", "uplot", "ustc", "util-linux",
        "vostrom", "vsl-1.0", "w3c-19980720", "w3c-20150513", "w3c", "wsuipa",
        "wtfpl", "wxwindows", "x11", "xinetd", "xlock", "xnet", "xpp", "xsane",
        "xskat", "ypl-1.0", "ypl-1.1", "zed", "zend-2.0", "zimbra-1.3", "zimbra-1.4",
        "zlib-acknowledgement", "zlib", "zpl-1.0", "zpl-2.0", "zpl-2.1"
    ]

    all_spdx_names = set(extra_spdx_names)
    for b in permissive_bases + weak_copyleft_bases + strong_copyleft_bases + proprietary_bases:
        all_spdx_names.add(b)
        for v in versions:
            all_spdx_names.add(f"{b}-{v}")
            for s in suffixes:
                all_spdx_names.add(f"{b}-{v}{s}")
                all_spdx_names.add(f"{b}{s}")

    spdx_list = sorted(list(all_spdx_names))
    for name in spdx_list:
        norm = name.lower()
        attribution = True
        source_code = False
        copyleft = False
        state_changes = False
        network_service = False
        disclaimer = True

        if "gpl" in norm:
            source_code = True
            copyleft = True
            state_changes = True
            if "agpl" in norm:
                network_service = True
        elif "lgpl" in norm:
            source_code = True
            copyleft = True
            state_changes = True
        elif "mpl" in norm or "epl" in norm or "cddl" in norm or "cpl" in norm:
            source_code = True
            copyleft = True
        elif "apache" in norm:
            state_changes = True
        elif "cc0" in norm or "unlicense" in norm or "wtfpl" in norm:
            attribution = False
            disclaimer = False

        if "proprietary" in norm or "closed" in norm or "commercial" in norm:
            attribution = False
            disclaimer = False

        db[norm] = {
            "attribution": attribution,
            "source_code": source_code,
            "copyleft": copyleft,
            "state_changes": state_changes,
            "network_service": network_service,
            "disclaimer": disclaimer,
        }
    return db


SPDX_OBLIGATIONS = generate_spdx_obligations_db()


_OBLIGATION_KEYS = ("attribution", "source_code", "copyleft", "state_changes",
                    "network_service", "disclaimer")


def _obligation_weight(ob: Dict[str, bool]) -> int:
    """How constraining an obligations map is (more True flags == more restrictive)."""
    return sum(1 for k in _OBLIGATION_KEYS if ob.get(k))


def get_license_obligations(license_str: Optional[str]) -> Dict[str, bool]:
    """Retrieve the obligations map for a (possibly compound) SPDX expression.

    Compound expressions are resolved structurally so a *disjunctive* offering is
    never over-constrained by a naive substring match:
      * ``A OR B``  -> the LEAST restrictive branch (the recipient may pick it);
        e.g. ``MIT OR GPL-2.0-only`` carries MIT's obligations, not GPL's.  If one
        branch is the commercial half of a dual license, the most restrictive of
        the *non-commercial* branches governs (matches ``classify_license``).
      * ``A AND B`` -> the UNION of both branches (every term must be satisfied).
      * ``A WITH e`` -> the obligations of ``A``.
    """
    if not license_str or not str(license_str).strip():
        return {k: False for k in _OBLIGATION_KEYS}
    expr = str(license_str).strip()
    norm = _normalize(expr)

    if norm in SPDX_OBLIGATIONS:
        return dict(SPDX_OBLIGATIONS[norm])

    # Structural resolution of compound SPDX expressions (before substring guesses).
    upper = f" {expr.upper()} "
    if " OR " in upper:
        parts = _split(expr, "OR")
        obs = [get_license_obligations(p) for p in parts]
        norms = {_normalize(p) for p in parts}
        if norms & _DUAL_LICENSE_COMMERCIAL:
            non_commercial = [o for p, o in zip(parts, obs)
                              if _normalize(p) not in _DUAL_LICENSE_COMMERCIAL]
            if non_commercial:
                return max(non_commercial, key=_obligation_weight)
        return min(obs, key=_obligation_weight)
    if " AND " in upper:
        obs = [get_license_obligations(p) for p in _split(expr, "AND")]
        return {k: any(o.get(k, False) for o in obs) for k in _OBLIGATION_KEYS}
    if " WITH " in upper:
        return get_license_obligations(_split(expr, "WITH")[0])

    # Heuristics for single terms missing from the generated DB
    attribution = True
    source_code = False
    copyleft = False
    state_changes = False
    network_service = False
    disclaimer = True

    if "gpl" in norm:
        source_code = True
        copyleft = True
        state_changes = True
        if "agpl" in norm:
            network_service = True
    elif "lgpl" in norm:
        source_code = True
        copyleft = True
        state_changes = True
    elif "mpl" in norm or "epl" in norm or "cddl" in norm or "cpl" in norm:
        source_code = True
        copyleft = True
    elif "apache" in norm:
        state_changes = True
    elif "cc0" in norm or "unlicense" in norm or "wtfpl" in norm:
        attribution = False
        disclaimer = False
    elif "proprietary" in norm or "closed" in norm or "commercial" in norm:
        attribution = False
        disclaimer = False

    return {
        "attribution": attribution,
        "source_code": source_code,
        "copyleft": copyleft,
        "state_changes": state_changes,
        "network_service": network_service,
        "disclaimer": disclaimer,
    }


def _normalize(token: str) -> str:
    return token.strip().strip("()").lower()


def classify_license(license_str: Optional[str]) -> str:
    """Return the policy category for a (possibly compound) SPDX expression.

    For 'AND' expressions the most restrictive component wins (you must comply
    with all). For 'OR' expressions: if one side is Proprietary/Commercial (dual-
    license offering), the copyleft/restrictive side applies unless a commercial
    license is acquired; otherwise the least-restrictive option applies.
    """
    if not license_str or not str(license_str).strip():
        return UNKNOWN
    expr = str(license_str).strip()
    if expr.upper() in ("NOASSERTION", "NONE", "UNKNOWN", "N/A"):
        return UNKNOWN

    # Fast path: check the full normalized expression in _LICENSE_MAP BEFORE splitting
    # on operators.  This is required so compound entries like
    # "gpl-2.0-only with classpath-exception-2.0" → WEAK_COPYLEFT are reachable;
    # the WITH-split branch below would otherwise preempt the lookup and return the
    # wrong (STRONG_COPYLEFT) category for classpath-exception packages.
    norm = _normalize(expr)
    if norm in _LICENSE_MAP:
        return _LICENSE_MAP[norm]

    # Split compound expressions
    upper = f" {expr.upper()} "
    if " OR " in upper:
        parts = _split(expr, "OR")
        cats = [classify_license(p) for p in parts]
        norms = {_normalize(p) for p in parts}
        # Dual-license: GPL-or-later OR commercial → the copyleft side governs unless
        # a commercial license is paid. Flag as the MORE restrictive of the two sides.
        if norms & _DUAL_LICENSE_COMMERCIAL:
            non_commercial = [c for p, c in zip(parts, cats)
                              if _normalize(p) not in _DUAL_LICENSE_COMMERCIAL]
            if non_commercial:
                return max(non_commercial, key=lambda c: _RESTRICTIVENESS.get(c, 1))
        return min(cats, key=lambda c: _RESTRICTIVENESS.get(c, 1))
    if " AND " in upper:
        cats = [classify_license(p) for p in _split(expr, "AND")]
        return max(cats, key=lambda c: _RESTRICTIVENESS.get(c, 1))
    if " WITH " in upper:  # e.g. GPL-2.0-only WITH Unknown-exception (not in _LICENSE_MAP)
        return classify_license(_split(expr, "WITH")[0])

    # norm already computed above; fall through to substring heuristics
    for needle, cat in _SUBSTRING_RULES:
        if needle in norm:
            return cat
    return UNKNOWN


def _split(expr: str, op: str) -> List[str]:
    # case-insensitive split on a whole-word operator
    import re
    return [p for p in re.split(rf"\s+{op}\s+", expr, flags=re.IGNORECASE) if p.strip()]


def analyze_licenses(packages: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze a list of package dicts ({name, version, license, ...}).

    Returns a summary dict + per-finding list describing GPL contamination,
    incompatibility risks, commercial-restriction violations, and unknown
    licenses for the assembled product.
    """
    _EMPTY_OBL = {k: False for k in ["attribution", "source_code", "copyleft",
                                      "state_changes", "network_service", "disclaimer"]}
    category_counts: Dict[str, int] = {}
    classified = []
    _succeeded = 0
    _failed = 0
    for p in packages:
        # Per-package isolation: a single malformed package (None license field,
        # non-UTF-8 bytes, or unexpected data type) must not abort the entire loop.
        # Errors are demoted to UNKNOWN so the remaining packages are still classified
        # and findings are still reported.
        _pkg_error: Optional[str] = None
        try:
            lic = p.get("license") or "NOASSERTION"
            if isinstance(lic, bytes):
                lic = lic.decode("utf-8")
            lic = str(lic)
            cat = classify_license(lic)
            ob = get_license_obligations(lic)
            _succeeded += 1
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as _e:
            lic = str(p.get("license") or "NOASSERTION")
            cat = UNKNOWN
            ob = dict(_EMPTY_OBL)
            _pkg_error = str(_e)
            _failed += 1
            logger.warning(
                "Per-package license error for %r: %s",
                p.get("name", "<unknown>"),
                _e,
            )
        category_counts[cat] = category_counts.get(cat, 0) + 1
        _entry: Dict[str, Any] = {
            "name": p.get("name", ""),
            "version": p.get("version", ""),
            "license": lic,
            "category": cat,
            "obligations": ob,
        }
        if _pkg_error is not None:
            _entry["error"] = _pkg_error
        classified.append(_entry)

    if _failed:
        logger.warning(
            "License analysis complete: %d succeeded, %d failed (demoted to UNKNOWN).",
            _succeeded,
            _failed,
        )
    else:
        logger.debug("License analysis complete: %d succeeded, 0 failed.", _succeeded)

    has_strong = category_counts.get(STRONG_COPYLEFT, 0) > 0
    has_network = category_counts.get(NETWORK_COPYLEFT, 0) > 0
    has_proprietary = category_counts.get(PROPRIETARY, 0) > 0
    has_commercial_restricted = category_counts.get(COMMERCIAL_RESTRICTED, 0) > 0
    unknown_count = category_counts.get(UNKNOWN, 0)

    # Build per-license-id package index for pairwise checks
    lic_id_to_pkgs: Dict[str, List[str]] = {}
    for c in classified:
        ids = _extract_spdx_ids(_normalize(c["license"]))
        for lid in ids:
            lic_id_to_pkgs.setdefault(lid, []).append(c["name"])

    findings: List[Dict[str, Any]] = []

    # 1) GPL/AGPL + Proprietary copyleft contamination
    if (has_strong or has_network) and has_proprietary:
        copyleft_pkgs = [c["name"] for c in classified
                         if c["category"] in (STRONG_COPYLEFT, NETWORK_COPYLEFT)]
        findings.append({
            "issue": "GPL/AGPL contamination risk (Copyleft + Proprietary)",
            "severity": "HIGH",
            "packages": copyleft_pkgs,
            "detail": "Strong copyleft components are distributed alongside proprietary components. "
                      "Depending on static/dynamic linking, GPL obligations may propagate to the entire binary image.",
            "recommendation": "Review link boundaries, consider LGPL/permissive alternatives, or obtain legal review.",
        })

    # 1b) GPL/AGPL present with permissive packages but WITHOUT explicit proprietary
    #     marker — still a compliance risk in commercial embedded products where all
    #     components ultimately link into a single binary image.  The absence of a
    #     "Proprietary" label does not eliminate GPL propagation liability.
    elif has_strong or has_network:
        has_permissive_or_weak = (
            category_counts.get(PERMISSIVE, 0) > 0
            or category_counts.get(WEAK_COPYLEFT, 0) > 0
        )
        if has_permissive_or_weak:
            copyleft_pkgs = [c["name"] for c in classified
                             if c["category"] in (STRONG_COPYLEFT, NETWORK_COPYLEFT)]
            findings.append({
                "issue": "GPL copyleft propagation risk (obligation compliance check required before distribution)",
                "severity": "MEDIUM",
                "packages": copyleft_pkgs,
                "detail": "Strong copyleft components are distributed alongside permissive or weakly-copyleft components. "
                          "When statically linked or bundled into a single binary image (e.g. embedded firmware), "
                          "GPL obligations may apply to the entire deliverable.",
                "recommendation": "Verify link method (static/dynamic) and distribution form; "
                                  "obtain legal review for GPL source-disclosure obligations. Consider LGPL or permissive alternatives.",
            })

    # 2) Network copyleft / AGPL (source disclosure on network use)
    if has_network:
        net_pkgs = [c["name"] for c in classified if c["category"] == NETWORK_COPYLEFT]
        findings.append({
            "issue": "Network copyleft (AGPL/SSPL)",
            "severity": "HIGH",
            "packages": net_pkgs,
            "detail": "AGPL/SSPL components trigger source-disclosure obligations even when provided over a network. "
                      "SSPL is stricter than AGPL, requiring disclosure of the entire service-stack source.",
            "recommendation": "For SaaS or service deployments, verify that source-disclosure obligations are fully satisfied.",
        })

    # 3) Commercial-restricted licenses (CC-BY-NC, PolyForm NonCommercial)
    if has_commercial_restricted:
        cr_pkgs = [c["name"] for c in classified if c["category"] == COMMERCIAL_RESTRICTED]
        findings.append({
            "issue": "Commercially-restricted license (CC-BY-NC / PolyForm NonCommercial)",
            "severity": "HIGH",
            "packages": cr_pkgs,
            "detail": "These components are free for non-commercial use only. "
                      "Inclusion in a commercial product or service requires a separate commercial license from the rights holder.",
            "recommendation": "Consider replacing with components under an OSI-approved open-source license, or negotiate a commercial license with the rights holder.",
        })

    # 4) Pairwise license incompatibility checks (FSF/OSI documented pairs)
    for set_a, set_b, issue, recommendation in _INCOMPATIBLE_PAIRS:
        if not set_b:
            # Single-license flag (no counterpart needed)
            matched = [pkg for lid in set_a for pkg in lic_id_to_pkgs.get(lid, [])]
            if matched:
                sev = "HIGH" if any("sspl" in lid or "nc" in lid or "polyform" in lid
                                     for lid in set_a) else "MEDIUM"
                findings.append({
                    "issue": issue, "severity": sev, "packages": list(set(matched)),
                    "detail": issue, "recommendation": recommendation,
                })
            continue
        pkgs_a = [pkg for lid in set_a for pkg in lic_id_to_pkgs.get(lid, [])]
        pkgs_b = [pkg for lid in set_b for pkg in lic_id_to_pkgs.get(lid, [])]
        if pkgs_a and pkgs_b:
            findings.append({
                "issue": issue, "severity": "MEDIUM",
                "packages": list(set(pkgs_a + pkgs_b)),
                "detail": issue, "recommendation": recommendation,
            })

    # 5) Unknown / unresolved licenses = compliance gap
    if unknown_count > 0:
        unknown_pkgs = [c["name"] for c in classified if c["category"] == UNKNOWN]
        findings.append({
            "issue": "Unknown license (Compliance Gap)",
            "severity": "MEDIUM" if unknown_count > 5 else "LOW",
            "packages": unknown_pkgs[:50],
            "detail": f"License could not be identified for {unknown_count} component(s).",
            "recommendation": "Populate the SBOM license fields or verify manually.",
        })

    # Deduplicate findings by issue key
    seen_issues: set = set()
    deduped: List[Dict[str, Any]] = []
    for f in findings:
        key = f["issue"]
        if key not in seen_issues:
            seen_issues.add(key)
            deduped.append(f)

    summary = {
        "category_counts": category_counts,
        "total_components": len(packages),
        "strong_copyleft_present": has_strong,
        "network_copyleft_present": has_network,
        "proprietary_present": has_proprietary,
        "commercial_restricted_present": has_commercial_restricted,
        "unknown_count": unknown_count,
        "conflict_count": len(deduped),
        "highest_severity": _highest_severity(deduped),
    }
    return {"summary": summary, "findings": deduped, "classified": classified}


def _extract_spdx_ids(norm: str) -> List[str]:
    """Extract all leaf license ids from a (possibly compound) normalized SPDX expression.

    WITH exception clauses are stripped before splitting so that exception
    identifiers like "Classpath-exception-2.0" are never emitted as if they
    were license IDs.  Example:
      "gpl-2.0-only with classpath-exception-2.0 and mit" → ["gpl-2.0-only", "mit"]
    """
    import re as _re
    # Remove WITH exception clauses: SPDX exception IDs are single tokens (no spaces)
    cleaned = _re.sub(r"\s+with\s+\S+", "", norm, flags=_re.IGNORECASE).strip()
    tokens = _re.split(r"\s+(?:and|or)\s+", cleaned, flags=_re.IGNORECASE)
    return [t.strip().strip("()") for t in tokens if t.strip()]


def _highest_severity(findings: List[Dict[str, Any]]) -> str:
    order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if not findings:
        return "NONE"
    return max(findings, key=lambda f: order.get(f["severity"], 0))["severity"]


# ─────────────────────────────────────────────────────────────────────────────
# Compliance Risk Score
# ─────────────────────────────────────────────────────────────────────────────

def compute_compliance_risk_score(
    packages: List[Dict[str, Any]],
    analysis: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a deterministic 0-100 compliance risk score for a dependency set.

    Higher score = higher risk for a commercial product distributor.  The
    breakdown dict exposes each addend so a UI can render a bar chart.

    Grade scale: A 0-19 / B 20-39 / C 40-59 / D 60-79 / F 80-100.
    """
    if analysis is None:
        analysis = analyze_licenses(packages)

    summary = analysis.get("summary", {})
    findings = analysis.get("findings", [])
    _classified = analysis.get("classified", [])  # (vendored: reserved field, read by the platform report layer)

    cat_counts = summary.get("category_counts", {})
    total = max(summary.get("total_components", len(packages)), 1)

    # Penalise per-category package counts (capped individually)
    nc_penalty  = min(cat_counts.get(NETWORK_COPYLEFT, 0) * 15, 40)
    sc_penalty  = min(cat_counts.get(STRONG_COPYLEFT, 0) * 8, 30)
    wc_penalty  = min(cat_counts.get(WEAK_COPYLEFT, 0) * 3, 12)
    cr_penalty  = min(cat_counts.get(COMMERCIAL_RESTRICTED, 0) * 20, 40)
    pr_penalty  = min(cat_counts.get(PROPRIETARY, 0) * 25, 50)
    unk_penalty = min(cat_counts.get(UNKNOWN, 0) * 1, 20)  # 1 pt each, max 20

    # Incompatibility findings
    incompat_penalty = 0
    for f in findings:
        sev = f.get("severity", "LOW")
        incompat_penalty += 8 if sev == "HIGH" else (5 if sev == "MEDIUM" else 2)
    incompat_penalty = min(incompat_penalty, 25)

    raw = nc_penalty + sc_penalty + wc_penalty + cr_penalty + pr_penalty + unk_penalty + incompat_penalty
    score = min(int(raw), 100)

    grade = "A" if score < 20 else ("B" if score < 40 else ("C" if score < 60 else ("D" if score < 80 else "F")))

    _GRADE_MSG = {
        "A": "Low license risk — distribution is feasible under standard review procedures.",
        "B": "Minor license risk — verify obligations and update the NOTICE file.",
        "C": "Moderate license risk — legal review and an obligation fulfillment plan are required.",
        "D": "High license risk — legal approval is mandatory before commercial distribution.",
        "F": "Critical license risk — immediate legal review and component replacement are required.",
    }

    return {
        "score": score,
        "grade": grade,
        "recommendation": _GRADE_MSG.get(grade, ""),
        "breakdown": {
            "network_copyleft": nc_penalty,
            "strong_copyleft": sc_penalty,
            "weak_copyleft": wc_penalty,
            "commercial_restricted": cr_penalty,
            "proprietary": pr_penalty,
            "unknown_licenses": unk_penalty,
            "incompatibilities": incompat_penalty,
        },
        "category_counts": cat_counts,
        "total_components": total,
        "conflict_count": summary.get("conflict_count", len(findings)),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Pairwise License Compatibility Matrix
# ─────────────────────────────────────────────────────────────────────────────

def build_compat_matrix(licenses: List[str]) -> Dict[str, Any]:
    """Return a pairwise compatibility grid for a list of SPDX license strings.

    Result shape:
      {
        "licenses": ["MIT", "GPL-3.0-only", ...],
        "matrix": [[True, False, ...], ...],   # True=OK, False=INCOMPAT, None=unknown
        "incompatible_pairs": [{"a": str, "b": str, "reason": str, "recommendation": str}, ...]
      }

    Diagonal (same license with itself) is always True.
    Two Permissive licenses are always True.
    Unknown ↔ anything returns None (cannot determine).
    """
    deduped = list(dict.fromkeys(licenses))  # stable-unique
    n = len(deduped)
    norms = [_normalize(lic) for lic in deduped]
    cats  = [classify_license(lic) for lic in deduped]
    ids   = [set(_extract_spdx_ids(nrm)) for nrm in norms]

    matrix: List[List] = [[None] * n for _ in range(n)]
    incompat_pairs: List[Dict[str, Any]] = []

    for i in range(n):
        for j in range(n):
            if i == j:
                matrix[i][j] = True
                continue

            # Both permissive / public domain → always compatible
            if cats[i] in (PERMISSIVE, PUBLIC_DOMAIN) and cats[j] in (PERMISSIVE, PUBLIC_DOMAIN):
                matrix[i][j] = True
                continue

            # Either unknown → undetermined
            if cats[i] == UNKNOWN or cats[j] == UNKNOWN:
                matrix[i][j] = None
                continue

            # Check known incompatible pairs
            found_incompat = False
            for set_a, set_b, reason, recommendation in _INCOMPATIBLE_PAIRS:
                if not set_b:
                    # Single-license warning: both sides present in the list
                    if ids[i] & set_a and ids[j] & set_a:
                        # Same license family both columns → compatible (no cross-pair issue)
                        continue
                    continue
                if (ids[i] & set_a and ids[j] & set_b) or (ids[i] & set_b and ids[j] & set_a):
                    matrix[i][j] = False
                    found_incompat = True
                    # Record once per unordered pair
                    pair_key = (min(i, j), max(i, j))
                    if not any(p.get("_key") == pair_key for p in incompat_pairs):
                        incompat_pairs.append({
                            "_key": pair_key,
                            "a": deduped[i], "b": deduped[j],
                            "a_idx": i, "b_idx": j,
                            "reason": reason,
                            "recommendation": recommendation,
                        })
                    break

            if not found_incompat:
                matrix[i][j] = True

    # Clean up internal _key field before returning
    for p in incompat_pairs:
        p.pop("_key", None)

    return {
        "licenses": deduped,
        "matrix": matrix,
        "incompatible_pairs": incompat_pairs,
    }
