"""XML from untrusted trees: DTDs and entity declarations are refused, in every encoding XML allows.

The scanners read ``pom.xml`` / ``.csproj`` / workbook XML out of directories and archives somebody else wrote.  A
``<!DOCTYPE`` with internal entities is the classic entity-expansion ("billion laughs") vector and an external one is
XXE.  ``xml.etree`` (expat) does not fetch external entities, but we do not rely on library defaults: the document is
first walked by a bare expat parser whose DOCTYPE / ENTITY handlers raise, then handed to ``xml.etree``.

A byte search for ``<!DOCTYPE`` is not enough on its own - an UTF-16 document spells it ``<\\0!\\0D\\0...`` and a prefix
check misses a declaration placed after a long comment - so the check is done by the parser itself, which sees the
declaration however it is encoded or positioned in the prolog.  Standard library only.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Union
from xml.parsers import expat

__all__ = ["DtdNotAllowed", "reject_dtd", "fromstring"]


class DtdNotAllowed(ValueError):
    """The document declares a DOCTYPE or an ENTITY."""


def reject_dtd(data: Union[str, bytes]) -> None:
    """Raise :class:`DtdNotAllowed` when ``data`` has a DOCTYPE or ENTITY declaration.

    Malformed XML is *not* reported here (the real parse that follows reports it); only a declaration found before the
    document stops being well-formed counts, which is also exactly where the real parser would have acted on it."""
    def _refuse(*_args: object) -> None:
        raise DtdNotAllowed("DOCTYPE/ENTITY declarations are not allowed")

    parser = expat.ParserCreate()
    parser.StartDoctypeDeclHandler = _refuse
    parser.EntityDeclHandler = _refuse
    # no ExternalEntityRefHandler is installed, so expat never resolves an external entity
    try:
        parser.Parse(data, True)
    except DtdNotAllowed:
        raise
    except expat.ExpatError:
        return


def fromstring(data: Union[str, bytes]) -> ET.Element:
    """``ET.fromstring`` after :func:`reject_dtd`; parse errors surface as ``ET.ParseError`` as usual."""
    reject_dtd(data)
    return ET.fromstring(data)
