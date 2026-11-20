"""Untrusted XML: a DOCTYPE / ENTITY is refused wherever it sits and in whatever encoding."""
from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from bts_sbom._internal import oss_manifests_extra, safe_xml, xlsx_min

EVIL = '<!DOCTYPE a [<!ENTITY x "boom">]><a>&x;</a>'


def test_plain_document_parses():
    assert safe_xml.fromstring("<a><b>1</b></a>").find("b").text == "1"


@pytest.mark.parametrize("doc", [
    EVIL,
    EVIL.encode("utf-8"),
    EVIL.encode("utf-16"),                                              # a byte search for '<!DOCTYPE' never matches this
    ('<?xml version="1.0"?>' + "<!-- " + "x" * 9000 + " -->" + EVIL).encode("utf-8"),   # declaration far beyond a 4 KiB prefix
    '<!doctype a SYSTEM "file:///etc/passwd"><a/>',                    # lower case is still a DOCTYPE to expat? (not XML: must not slip)
])
def test_dtd_is_refused_in_any_position_and_encoding(doc):
    # lower-case 'doctype' is not well-formed XML at all, so it is a parse error rather than a DTD; both are refusals
    with pytest.raises((safe_xml.DtdNotAllowed, ET.ParseError)):
        safe_xml.fromstring(doc)


def test_malformed_xml_is_a_parse_error_not_a_crash():
    with pytest.raises(ET.ParseError):
        safe_xml.fromstring("<a><b></a>")


def test_xlsx_reader_rejects_a_doctype_hidden_behind_a_long_comment_or_utf16():
    for doc in (("<!-- " + "x" * 9000 + " -->" + EVIL).encode("utf-8"), EVIL.encode("utf-16")):
        with pytest.raises(xlsx_min.XlsxError):
            xlsx_min._parse(doc)


def test_manifest_xml_rejects_a_doctype_after_a_long_comment():
    text = '<?xml version="1.0"?><!-- ' + "x" * 9000 + " -->" + EVIL
    with pytest.raises(ValueError, match="DOCTYPE"):
        oss_manifests_extra._xml_root(text, "demo.csproj")
