# vendored from common/license/spdx.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""SPDX license-expression syntax: tokenizer + recursive-descent parser (P0-LIC-1).

Implements the SPDX License Expression grammar (spec section "SPDX License
Expressions") with the documented operator precedence, LOWEST to HIGHEST:

    OR  <  AND  <  WITH

i.e. ``A OR B AND C WITH E`` parses as ``A OR ((B AND C) WITH E)`` ... the
WITH applies to the immediately preceding license id, AND binds tighter than
OR, and parentheses override both.

Supported token forms:
  * license ids            [A-Za-z0-9.-]+ with optional trailing '+'
                           (the legacy GNU ``GPL-2.0+`` spelling)
  * LicenseRef-* ids       ``LicenseRef-[A-Za-z0-9.-]+`` (document-local)
  * exception ids after WITH (same charset, e.g. Classpath-exception-2.0)
  * NOASSERTION / NONE     the SPDX sentinel values, parsed as atoms so the
                           evaluation layer can route them to review
  * ( ) and the keywords AND / OR / WITH, case-insensitive, any whitespace

Anything else raises :class:`SpdxParseError` with a human-readable position -
parse failures NEVER silently degrade to a permissive interpretation.

This module is pure syntax: it knows nothing about license semantics. The
semantic layer (classify.evaluate_expression / compat.check_compatibility)
consumes the AST.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Union


class SpdxParseError(ValueError):
    """Raised when a string is not a valid SPDX license expression."""


@dataclass(frozen=True)
class LicenseAtom:
    """One license id, optionally bound to a ``WITH`` exception.

    ``ident`` is upper-cased (SPDX short identifiers are case-insensitive in
    practice across tooling); ``exception``/``raw_exception`` keep the
    exception id as written (compare case-insensitively against the official
    exception list). ``raw`` keeps the original spelling for display and
    legacy split consumers. A ``WITH`` exception is part of the ATOMIC
    choice: it must survive splitting/grouping and reach the gate.
    """
    ident: str
    exception: Optional[str] = None
    raw: str = ""
    raw_exception: str = ""

    def display(self) -> str:
        base = self.raw or self.ident
        if not self.exception:
            return base
        return "%s WITH %s" % (base, self.raw_exception or self.exception)


@dataclass
class And:
    """Conjunction: BOTH sides apply (obligations merge)."""
    terms: List["Node"] = field(default_factory=list)


@dataclass
class Or:
    """Disjunction: exactly ONE alternative applies, chosen by the licensor
    at distribution time. The gate may only collapse it when every
    alternative leads to the same outcome (or a policy records the choice)."""
    alternatives: List["Node"] = field(default_factory=list)


Node = Union[LicenseAtom, And, Or]


# ---------------------------------------------------------------- tokenizer
_ID_RE = re.compile(r"[A-Za-z0-9.\-]+")
# DocumentRef-<doc>:LicenseRef-<id> is ONE token unit (a cross-document
# license reference); AdditionRef-* follows the same shape (SPDX 3.x).
_DOCREF_RE = re.compile(r"(DocumentRef-[A-Za-z0-9.-]+):(LicenseRef-[A-Za-z0-9.-]+)")
_ADDREF_RE = re.compile(r"AdditionRef-[A-Za-z0-9.-]+")
_KEYWORDS = {"AND", "OR", "WITH"}


def _tokenize(text: str) -> List[tuple]:
    """Yield (kind, value) tokens: ('id', s) | ('kw', AND|OR|WITH) |
    ('lp',) | ('rp',). Raises SpdxParseError on a stray character."""
    if not isinstance(text, str):
        raise SpdxParseError("expression must be a string")
    tokens: List[tuple] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "(":
            tokens.append(("lp", ch))
            i += 1
            continue
        if ch == ")":
            tokens.append(("rp", ch))
            i += 1
            continue
        if ch.isspace():
            i += 1
            continue
        # DocumentRef-x:LicenseRef-y is a single token (contains ':', which
        # the plain id charset excludes) - SPDX 2.x cross-document reference
        dm = _DOCREF_RE.match(text, i)
        if dm:
            tokens.append(("id", dm.group(0).upper(), dm.group(0)))
            i = dm.end()
            continue
        m = _ID_RE.match(text, i)
        if not m:
            raise SpdxParseError("unexpected character %r at position %d" % (ch, i))
        raw = m.group(0)
        # a legacy '+' suffix glues to the id (GPL-2.0+); extra '+' are invalid
        j = m.end()
        plus = 0
        while j < n and text[j] == "+":
            plus += 1
            j += 1
        if plus > 1:
            raise SpdxParseError("multiple '+' after %r at position %d" % (raw, i))
        word = raw + ("+" if plus else "")
        upper = word.upper()
        if upper in _KEYWORDS:
            if plus:
                raise SpdxParseError("keyword %r cannot carry '+' at position %d" % (raw, i))
            tokens.append(("kw", upper, raw))
        else:
            tokens.append(("id", upper, raw))
        i = j
    return tokens


# ---------------------------------------------------------------- parser
class _Parser:
    def __init__(self, tokens: List[tuple]):
        self.toks = tokens
        self.pos = 0

    def _peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def _next(self):
        tok = self._peek()
        if tok is None:
            raise SpdxParseError("unexpected end of expression")
        self.pos += 1
        return tok

    def parse(self) -> Node:
        node = self._or_expr()
        if self._peek() is not None:
            raise SpdxParseError("unexpected token %r after position %d"
                                 % (self._peek()[1], self.pos))
        return node

    def _or_expr(self) -> Node:
        terms = [self._and_expr()]
        while True:
            tok = self._peek()
            if tok and tok[0] == "kw" and tok[1] == "OR":
                self._next()
                terms.append(self._and_expr())
            else:
                break
        return terms[0] if len(terms) == 1 else Or(terms)

    def _and_expr(self) -> Node:
        terms = [self._unary()]
        while True:
            tok = self._peek()
            if tok and tok[0] == "kw" and tok[1] == "AND":
                self._next()
                terms.append(self._unary())
            else:
                break
        return terms[0] if len(terms) == 1 else And(terms)

    def _unary(self) -> Node:
        tok = self._peek()
        if tok is None:
            raise SpdxParseError("unexpected end of expression (expected a license id or '(')")
        if tok[0] == "lp":
            self._next()
            node = self._or_expr()
            closing = self._next()
            if closing[0] != "rp":
                raise SpdxParseError("missing ')' - got %r" % (closing[1],))
            return self._with_suffix(node)
        if tok[0] == "kw":
            raise SpdxParseError("unexpected keyword %r" % (tok[1],))
        if tok[0] == "rp":
            raise SpdxParseError("unexpected ')'")
        self._next()
        atom = LicenseAtom(tok[1], None, tok[2])
        return self._with_suffix(atom)

    def _with_suffix(self, node: Node) -> Node:
        """Consume ``WITH <exception-id>``. Per the SPDX grammar WITH applies
        to a license id; applying it to a parenthesized group is malformed."""
        tok = self._peek()
        if not (tok and tok[0] == "kw" and tok[1] == "WITH"):
            return node
        if not isinstance(node, LicenseAtom):
            raise SpdxParseError("'WITH' may only follow a license id, not a group")
        self._next()
        exc = self._next()
        if exc[0] != "id":
            raise SpdxParseError("'WITH' must be followed by an exception id, got %r" % (exc[1],))
        return LicenseAtom(node.ident, exc[2] or exc[1], node.raw, exc[2])


def parse_expression(text: str) -> Node:
    """Parse an SPDX license expression into an AST.

    Raises SpdxParseError on any syntax violation - never returns a partial
    or guessed tree.
    """
    if not (text and text.strip()):
        raise SpdxParseError("empty expression")
    return _Parser(_tokenize(text)).parse()


# ---------------------------------------------------------------- walkers
def iter_atoms(node: Node) -> Iterator[LicenseAtom]:
    """Every LicenseAtom in the tree, in source order."""
    if isinstance(node, LicenseAtom):
        yield node
    elif isinstance(node, And):
        for t in node.terms:
            yield from iter_atoms(t)
    elif isinstance(node, Or):
        for a in node.alternatives:
            yield from iter_atoms(a)


def alternatives(node: Node) -> List[List[LicenseAtom]]:
    """Flatten into OR-branches: one list of atoms per license choice.

    ``A OR (B AND C)`` -> [[A], [B, C]]. A tree with no OR yields one branch.
    """
    if isinstance(node, LicenseAtom):
        return [[node]]
    if isinstance(node, And):
        branches: List[List[LicenseAtom]] = [[]]
        for t in node.terms:
            sub = alternatives(t)
            merged: List[List[LicenseAtom]] = []
            for prefix in branches:
                for extra in sub:
                    merged.append(prefix + extra)
            branches = merged
        return branches
    if isinstance(node, Or):
        out: List[List[LicenseAtom]] = []
        for a in node.alternatives:
            out.extend(alternatives(a))
        return out
    raise TypeError("unknown node %r" % (node,))


def expression_string(node: Node) -> str:
    """Canonical re-rendering of the AST (round-trip display form)."""
    if isinstance(node, LicenseAtom):
        return node.display()
    if isinstance(node, And):
        return "(" + " AND ".join(expression_string(t) for t in node.terms) + ")"
    if isinstance(node, Or):
        return "(" + " OR ".join(expression_string(a) for a in node.alternatives) + ")"
    raise TypeError("unknown node %r" % (node,))


# SPDX exception ids recognized by the official license-list (subset that
# matters for gating; anything else is treated as unknown -> review).
KNOWN_EXCEPTIONS = frozenset({
    "CLASSPATH-EXCEPTION-2.0", "GCC-EXCEPTION-3.1", "AUTOCONF-EXCEPTION-3.0",
    "AUTOCONF-EXCEPTION-2.0", "BISON-EXCEPTION-2.2", "BOOTLOADER-EXCEPTION",
    "CLISP-EXCEPTION-2.0", "DIGIRULE-FOSS-EXCEPTION", "ECOS-EXCEPTION-2.0",
    "FAWKES-RUNTIME-EXCEPTION", "FLTK-EXCEPTION", "FONT-EXCEPTION-2.0",
    "FREERTOS-EXCEPTION-2.0", "GNU-JAVA-EXCEPTION", "I2P-GPL-JAVA-EXCEPTION",
    "LIBTOOL-EXCEPTION", "LINUX-SYSCALL-NOTE", "LLVM-EXCEPTION",
    "LZMA-EXCEPTION", "MIF-EXCEPTION", "NOKIA-QT-EXCEPTION-1.1",
    "OCCT-EXCEPTION-1.0", "OPENJDK-ASSEMBLY-EXCEPTION-1.0",
    "OPENVPN-OPENSSL-EXCEPTION", "PS-OR-PDF-FONT-EXCEPTION-2.0",
    "QT-GPL-EXCEPTION-1.1", "QT-LGPL-EXCEPTION-1.1", "QWT-EXCEPTION-1.0",
    "SHL-2.0", "SHL-2.1", "SWIFT-EXCEPTION", "U-BOOT-EXCEPTION-2.0",
    "UNIVERSAL-FOSS-EXCEPTION-1.0", "WxWINDOWS-EXCEPTION-3.1",
})

# SPDX sentinel values: not licenses, must reach review
SENTINELS = frozenset({"NOASSERTION", "NONE"})


__all__ = [
    "SpdxParseError", "LicenseAtom", "And", "Or", "Node",
    "parse_expression", "iter_atoms", "alternatives", "expression_string",
    "KNOWN_EXCEPTIONS", "SENTINELS",
]
