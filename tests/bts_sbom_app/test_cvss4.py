"""CVSS v4.0 scoring (FIRST reference tables) and its use for findings that carry a v4 vector."""
from __future__ import annotations

import itertools

import pytest

from bts_sbom_app import cvss, cvss4, cvss4_data, engine, sbom
from conftest import V3_98, adv

B = "CVSS:4.0/"
V4_93 = B + "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

#: (vector without prefix, score published by FIRST for it). Base, threat (E), environmental (modified metrics) and combinations.
REFERENCE = [
    ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
    ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
    ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
    ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", 9.3),
    ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A", 8.7),
    ("AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.4),
    ("AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.3),
    ("AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.7),
    ("AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 5.2),
    ("AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N", 8.3),
    ("AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 4.6),
    ("AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1),
    ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 6.9),
    ("AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N", 5.9),
    ("AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H", 6.4),
    ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 7.1),
    ("AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 8.2),
    ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L", 8.7),
    ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:U", 6.6),
    ("AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N", 8.5),
    ("AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", 5.1),
    ("AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1),
    ("AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P", 8.2),
    ("AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L", 5.5),
    ("AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L", 8.1),
]


def test_scores_equal_the_published_reference_examples():
    """AC: BSA-AC-250"""
    wrong = [(v, exp, cvss4.score(B + v)) for v, exp in REFERENCE if cvss4.score(B + v) != exp]
    assert wrong == [] and len(REFERENCE) == 25
    assert cvss4.nomenclature(B + REFERENCE[2][0]) == "CVSS-B" and cvss4.nomenclature(B + REFERENCE[8][0]) == "CVSS-BT"
    assert cvss4.nomenclature(B + REFERENCE[-1][0]) == "CVSS-BE" and cvss4.nomenclature(B + REFERENCE[-2][0]) == "CVSS-BTE"
    assert cvss4.nomenclature(B + REFERENCE[3][0]) == "CVSS-BT"                                       # E:A is stated, so it is a threat-group vector


def test_incomplete_or_invalid_vectors_are_never_scored_and_the_optional_groups_default_as_specified():
    """AC: BSA-AC-251"""
    base = REFERENCE[2][0]
    for bad in (None, "", "text", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", B + "AV:N/AC:L/AT:N/PR:N/UI:N", B + base + "/AV:N", B + base + "/XX:N",
                B + base.replace("AV:N", "AV:Z"), B + base + "/E:Q", "CVSS:4.0", "CVSS:4.0/", B + base.replace("/SA:N", "")):
        assert cvss4.score(bad) is None and cvss4.parse_vector(bad) is None, bad
    s = cvss4.score(B + base)
    assert cvss4.score(B + base + "/E:X") == s == cvss4.score(B + base + "/E:A")                          # E:X means E:A
    assert cvss4.score(B + base + "/CR:X/IR:X/AR:X") == s == cvss4.score(B + base + "/CR:H/IR:H/AR:H")  # requirement X means H
    assert cvss4.score(B + base + "/MAV:X/MAC:X") == s                                                  # a modified metric of X keeps the base metric
    assert cvss4.score(B + base + "/S:P/AU:Y/R:I/V:D/RE:H/U:Red") == s                                  # supplemental metrics never move the score
    assert cvss4.score(B + base + "/E:U") < s and cvss4.score(B + base + "/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N") == 0.0


def test_the_table_is_exactly_the_270_valid_macro_vectors_and_every_base_vector_scores_within_range():
    """AC: BSA-AC-252"""
    valid = {a + b + c + d + e + f for a in "012" for b in "01" for c in "012" for d in "012" for e in "012" for f in "01" if not (c == "2" and f == "0")}
    assert len(cvss4_data.LOOKUP) == 270 and set(cvss4_data.LOOKUP) == valid and len(cvss4_data.METRICS) == 32
    assert all(0.0 <= v <= 10.0 for v in cvss4_data.LOOKUP.values()) and cvss4_data.LOOKUP["000000"] == 10.0
    n = bad = 0
    for combo in itertools.product("NALP", "LH", "NP", "NLH", "NPA", *("HLN",) * 6):
        n += 1
        if n % 64:
            continue
        s = cvss4.score(B + "AV:%s/AC:%s/AT:%s/PR:%s/UI:%s/VC:%s/VI:%s/VA:%s/SC:%s/SI:%s/SA:%s" % combo)
        bad += s is None or not 0.0 <= s <= 10.0 or round(s, 1) != s
    assert n == 104976 and bad == 0                                                                    # a 1-in-64 sweep of the whole base space (1640 vectors)


def _doc(vid, *vectors):
    d = adv(vid, ["CVE-2025-%s" % vid[-4:].replace("-", "")], "demo", "PyPI", "0", "2.0", V3_98)
    d["severity"] = [{"type": "CVSS_V4" if v.startswith("CVSS:4") else "CVSS_V3", "score": v} for v in vectors]
    return d


def test_severity_uses_the_v4_vector_when_there_is_no_v3_and_the_preference_decides_when_there_are_both():
    """AC: BSA-AC-253"""
    only4 = _doc("GHSA-v4v4-aaaa-aaaa", V4_93)
    assert cvss.severity_of(only4) == ("CRITICAL", 9.3, "cvss_v4_vector")                               # before: UNKNOWN / the advisory label
    both = _doc("GHSA-both-aaaa-aaaa", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", B + "AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L")
    assert cvss.scores_of(both) == {"v3": 7.5, "v4": 8.7}
    assert cvss.severity_of(both) == ("HIGH", 7.5, "cvss_v3_vector") and cvss.severity_of(both, prefer="v4") == ("HIGH", 8.7, "cvss_v4_vector")
    assert cvss.severity_of(_doc("GHSA-novec-aaaa-aaaa")) == ("UNKNOWN", None, "none")                   # no vector, no label: unknown, never guessed
    label_only = {"id": "X", "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}], "database_specific": {"severity": "HIGH"}}
    assert cvss.severity_of(label_only) == ("HIGH", None, "advisory_label")                             # an unscorable vector falls back to the label, never a guess

    def finding(*docs):
        pk = {"package": {"name": "demo", "version": "1.0", "ecosystem": "PyPI"}, "identity": {"name": "demo", "ecosystem": "PyPI", "version": "1.0", "purl": "pkg:pypi/demo@1.0",
                                                                                              "relationship": "direct", "depth": 0}, "query_status": "queried_online", "vulnerabilities": list(docs)}
        nat = {"results": [{"source": {"path": "requirements.txt", "type": "lockfile"}, "packages": [pk]}], "scan_status": {}, "completeness": {}, "notes": []}
        return engine.normalize(nat, ".")["vulns"][0]

    f4 = finding(only4)
    assert f4["severity"] == "CRITICAL" and f4["cvss"] == 9.3 and f4["cvss_v4"] == 9.3 and "cvss_v3" not in f4 and f4["score_source"] == "cvss_v4_vector"
    split = finding(_doc("GHSA-spl1-aaaa-aaaa", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), _doc("GHSA-spl2-aaaa-aaaa", V4_93))
    assert split["cvss_v3"] == 7.5 and split["cvss_v4"] == 9.3 and split["cvss"] in (7.5, 9.3)           # scores are kept per version across the alias group


def test_cyclonedx_states_the_method_of_each_rating_and_keeps_both_scores():
    """AC: BSA-AC-254"""
    comp = {"name": "demo", "version": "1.0", "ecosystem": "PyPI", "purl": "pkg:pypi/demo@1.0", "relationship": "direct", "license": "MIT", "files": ["requirements.txt"]}

    def doc_for(**kw):
        v = dict({"id": "CVE-2025-0001", "aliases": [], "osv_ids": ["GHSA-aaaa-bbbb-cccc"], "package": "demo", "version": "1.0", "ecosystem": "PyPI", "purl": "pkg:pypi/demo@1.0",
                  "severity": "CRITICAL", "cvss": 9.3, "score_source": "cvss_v4_vector", "fixed_version": "2.0", "summary": "s", "references": []}, **kw)
        d = sbom.cyclonedx("p", [comp], [v])
        assert sbom.validate_cyclonedx(d) == []
        return d["vulnerabilities"][0]["ratings"]

    only4 = doc_for()
    assert [(r["method"], r["score"]) for r in only4] == [("CVSSv4", 9.3)]
    both = doc_for(cvss_v3=7.5, cvss_v4=9.3)
    assert [(r["method"], r["score"], r["severity"]) for r in both] == [("CVSSv4", 9.3, "critical"), ("CVSSv31", 7.5, "high")]
    v3 = doc_for(score_source="cvss_v3_vector", cvss=7.5, severity="HIGH", cvss_v3=7.5, cvss_v4=8.7)
    assert [(r["method"], r["score"]) for r in v3] == [("CVSSv31", 7.5), ("CVSSv4", 8.7)]
    same = doc_for(score_source="cvss_v3_vector", cvss=7.5, severity="HIGH", cvss_v3=7.5, cvss_v4=7.5)
    assert len(same) == 1                                                                              # an identical second score adds nothing
    with pytest.raises(KeyError):
        cvss4._extract("ZZ", "AV:N/")
