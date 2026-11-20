"""A small, bounded YAML-subset reader/writer (stdlib only).

Why it exists: the toolkit may not depend on PyYAML, yet the OSS-compliance ecosystem speaks YAML (sbom-info.yaml
correction files, pnpm-lock.yaml, pubspec.yaml, Chart.yaml, Podfile.lock, report files).  This module reads the
regular block/flow YAML those files use and nothing else; anything it does not understand raises ``YamlError``
rather than being guessed at (a mis-parsed lockfile would silently drop components).

Supported:   block mappings and sequences (incl. a sequence at the SAME indent as its key), nested flow ``[..]``
             and ``{..}``, plain / 'single' / "double" quoted scalars, ``|`` and ``>`` block scalars with the
             ``-``/``+`` chomping indicators, ``#`` comments, ``---`` / ``...`` document markers (first document only),
             multi-line plain scalars (folded with a space), ``key:`` with a null value, ``? `` is NOT supported.
Not supported (-> YamlError): anchors/aliases (&a, *a), tags (!!x), merge keys (<<), tab indentation, multiple
             documents with content after the first, complex (non-scalar) keys.
Scalar typing: every scalar is returned as a ``str`` except ``true/false`` (bool) and ``null/~/empty`` (None).
             Numbers are deliberately NOT converted - a version such as ``1.10`` must stay ``1.10``.
Bounds:      MAX_BYTES input, MAX_DEPTH nesting - a hostile file cannot exhaust memory or the interpreter stack.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

MAX_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 64


class YamlError(ValueError):
    pass


_BOOL_T = {"true", "True", "TRUE"}
_BOOL_F = {"false", "False", "FALSE"}
_NULL = {"", "~", "null", "Null", "NULL"}
_KEY_RE = re.compile(r"""^(?P<key>"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s#'"\[\]{},&*!|>%@`-][^#]*?|-[^\s#][^#]*?)\s*:(?:\s+(?P<rest>.*))?$""")


def _strip_comment(s: str) -> str:
    """Remove a trailing ' #...' comment that is outside quotes."""
    out: List[str] = []
    quote: Optional[str] = None
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if quote:
            out.append(c)
            if quote == '"' and c == "\\" and i + 1 < n:
                out.append(s[i + 1])
                i += 2
                continue
            if c == quote:
                if quote == "'" and i + 1 < n and s[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                quote = None
        else:
            if c in "\"'" and (not out or out[-1] in " \t[{,:" or not "".join(out).strip()):
                quote = c
                out.append(c)
            elif c == "#" and (not out or out[-1] in " \t"):
                break
            else:
                out.append(c)
        i += 1
    return "".join(out).rstrip()


class _Line:
    __slots__ = ("indent", "text", "no", "raw")

    def __init__(self, indent: int, text: str, no: int, raw: str) -> None:
        self.indent, self.text, self.no, self.raw = indent, text, no, raw


def _unquote_double(s: str, lineno: int) -> str:
    out: List[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= len(s):
            raise YamlError("line %d: dangling backslash" % lineno)
        e = s[i]
        simple = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", '"': '"', "\\": "\\", "/": "/", " ": " ", "a": "\a",
                  "b": "\b", "f": "\f", "v": "\v", "e": "\x1b"}
        if e in simple:
            out.append(simple[e])
            i += 1
        elif e in "xuU":
            width = {"x": 2, "u": 4, "U": 8}[e]
            hexs = s[i + 1:i + 1 + width]
            if len(hexs) != width or not re.fullmatch(r"[0-9a-fA-F]+", hexs):
                raise YamlError("line %d: bad \\%s escape" % (lineno, e))
            out.append(chr(int(hexs, 16)))
            i += 1 + width
        else:
            raise YamlError("line %d: unknown escape \\%s" % (lineno, e))
    return "".join(out)


def _scalar(tok: str, lineno: int) -> Any:
    t = tok.strip()
    if t.startswith('"'):
        if len(t) < 2 or not t.endswith('"'):
            raise YamlError("line %d: unterminated double-quoted scalar" % lineno)
        return _unquote_double(t[1:-1], lineno)
    if t.startswith("'"):
        if len(t) < 2 or not t.endswith("'"):
            raise YamlError("line %d: unterminated single-quoted scalar" % lineno)
        return t[1:-1].replace("''", "'")
    if t[:1] in ("&", "*", "!"):
        raise YamlError("line %d: anchors, aliases and tags are not supported (%r)" % (lineno, t[:12]))
    if t in _NULL:
        return None
    if t in _BOOL_T:
        return True
    if t in _BOOL_F:
        return False
    return t


def _parse_flow(s: str, lineno: int) -> Any:
    pos = [0]
    n = len(s)

    def ws() -> None:
        while pos[0] < n and s[pos[0]] in " \t":
            pos[0] += 1

    def parse_value(depth: int, in_map_key: bool = False) -> Any:
        if depth > MAX_DEPTH:
            raise YamlError("line %d: flow nesting too deep" % lineno)
        ws()
        if pos[0] >= n:
            raise YamlError("line %d: unexpected end of flow collection" % lineno)
        c = s[pos[0]]
        if c == "[":
            pos[0] += 1
            items: List[Any] = []
            ws()
            if pos[0] < n and s[pos[0]] == "]":
                pos[0] += 1
                return items
            while True:
                items.append(parse_value(depth + 1))
                ws()
                if pos[0] >= n:
                    raise YamlError("line %d: unterminated flow sequence" % lineno)
                if s[pos[0]] == ",":
                    pos[0] += 1
                    ws()
                    if pos[0] < n and s[pos[0]] == "]":      # trailing comma
                        pos[0] += 1
                        return items
                    continue
                if s[pos[0]] == "]":
                    pos[0] += 1
                    return items
                raise YamlError("line %d: expected ',' or ']'" % lineno)
        if c == "{":
            pos[0] += 1
            d: Dict[str, Any] = {}
            ws()
            if pos[0] < n and s[pos[0]] == "}":
                pos[0] += 1
                return d
            while True:
                ws()
                k = parse_value(depth + 1, in_map_key=True)
                ws()
                if pos[0] >= n or s[pos[0]] != ":":
                    raise YamlError("line %d: expected ':' in flow mapping" % lineno)
                pos[0] += 1
                ws()
                if pos[0] < n and s[pos[0]] in ",}":
                    v = None
                else:
                    v = parse_value(depth + 1)
                d[str(k) if k is not None else ""] = v
                ws()
                if pos[0] >= n:
                    raise YamlError("line %d: unterminated flow mapping" % lineno)
                if s[pos[0]] == ",":
                    pos[0] += 1
                    ws()
                    if pos[0] < n and s[pos[0]] == "}":
                        pos[0] += 1
                        return d
                    continue
                if s[pos[0]] == "}":
                    pos[0] += 1
                    return d
                raise YamlError("line %d: expected ',' or '}'" % lineno)
        if c in "\"'":
            q = c
            j = pos[0] + 1
            while j < n:
                if s[j] == "\\" and q == '"':
                    j += 2
                    continue
                if s[j] == q:
                    if q == "'" and j + 1 < n and s[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            else:
                raise YamlError("line %d: unterminated quoted scalar in flow collection" % lineno)
            tok = s[pos[0]:j + 1]
            pos[0] = j + 1
            return _scalar(tok, lineno)
        j = pos[0]
        stops = ",]}:" if in_map_key else ",]}"
        while j < n and s[j] not in stops:
            if s[j] == ":" and j + 1 < n and s[j + 1] not in " ,]}":
                j += 1
                continue
            j += 1
        tok = s[pos[0]:j]
        pos[0] = j
        return _scalar(tok, lineno)

    val = parse_value(0)
    ws()
    if pos[0] != n:
        raise YamlError("line %d: trailing characters after flow collection: %r" % (lineno, s[pos[0]:pos[0] + 20]))
    return val


class _Parser:
    def __init__(self, text: str) -> None:
        self.lines: List[_Line] = []
        raw_lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        started = False
        for no, raw in enumerate(raw_lines, 1):
            if raw.startswith("﻿") and no == 1:
                raw = raw[1:]
            stripped = raw.strip()
            if not started and (not stripped or stripped.startswith("#") or stripped.startswith("%")):
                continue
            if raw.startswith("---"):
                if started:
                    # a second document: only blank/comment lines may follow
                    rest = [r for r in raw_lines[no:] if r.strip() and not r.strip().startswith("#")]
                    if rest:
                        raise YamlError("line %d: multiple YAML documents are not supported" % no)
                    break
                tail = raw[3:].strip()
                started = True
                if tail and not tail.startswith("#"):
                    self.lines.append(_Line(0, _strip_comment(tail), no, raw))
                continue
            if raw.startswith("...") and not stripped[3:].strip():
                break
            started = True
            if "\t" in raw[:len(raw) - len(raw.lstrip(" \t"))]:
                raise YamlError("line %d: tab characters in indentation are not allowed" % no)
            indent = len(raw) - len(raw.lstrip(" "))
            self.lines.append(_Line(indent, raw[indent:], no, raw))
        self.i = 0

    # -- helpers ---------------------------------------------------------------------------------------------
    def _peek_content(self) -> Optional[_Line]:
        """Next line that is not blank / comment-only."""
        while self.i < len(self.lines):
            ln = self.lines[self.i]
            t = ln.text.strip()
            if not t or t.startswith("#"):
                self.i += 1
                continue
            return ln
        return None

    def parse(self) -> Any:
        ln = self._peek_content()
        if ln is None:
            return None
        val = self._block(ln.indent, 0)
        nxt = self._peek_content()
        if nxt is not None:
            raise YamlError("line %d: unexpected content (bad indentation?): %r" % (nxt.no, nxt.text[:40]))
        return val

    def _block(self, indent: int, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise YamlError("nesting deeper than %d levels" % MAX_DEPTH)
        ln = self._peek_content()
        if ln is None:
            return None
        text = _strip_comment(ln.text)
        if text == "-" or text.startswith("- "):
            return self._sequence(ln.indent, depth)
        if _KEY_RE.match(text) and not text.startswith(("[", "{")):
            return self._mapping(ln.indent, depth)
        # a lone scalar / flow collection document
        self.i += 1
        return self._inline_value(text, ln, depth, indent_of_parent=indent - 1)

    def _inline_value(self, text: str, ln: _Line, depth: int, indent_of_parent: int) -> Any:
        t = text.strip()
        if t.startswith(("[", "{")):
            # flow collections may span lines; brackets inside a quoted scalar do not count
            buf = t
            depth, quote = _flow_depth(0, "", t)
            guard = 0
            while (depth > 0 or quote) and guard < 10000:
                nxt = self._peek_content()
                if nxt is None:
                    break
                self.i += 1
                piece = _strip_comment(nxt.text).strip()
                buf += " " + piece
                depth, quote = _flow_depth(depth, quote, " " + piece)
                guard += 1
            return _parse_flow(buf, ln.no)
        if t and t[0] in "|>":
            return self._block_scalar(t, ln, indent_of_parent)
        # multi-line plain scalar continuation
        if t and t[0] not in "\"'":
            parts = [t]
            while self.i < len(self.lines):
                nxt = self.lines[self.i]
                nt = nxt.text.strip()
                if not nt or nt.startswith("#") or nxt.indent <= indent_of_parent:
                    break
                if nt == "-" or nt.startswith("- ") or _KEY_RE.match(_strip_comment(nt) or nt):
                    break
                parts.append(_strip_comment(nt))
                self.i += 1
            return _scalar(" ".join(parts), ln.no)
        return _scalar(t, ln.no)

    def _block_scalar(self, header: str, ln: _Line, parent_indent: int) -> str:
        style = header[0]
        chomp = ""
        explicit = None
        for ch in header[1:]:
            if ch in "+-":
                chomp = ch
            elif ch.isdigit():
                explicit = int(ch)
            else:
                raise YamlError("line %d: bad block scalar header %r" % (ln.no, header))
        body: List[str] = []
        block_indent: Optional[int] = None
        while self.i < len(self.lines):
            nxt = self.lines[self.i]
            if not nxt.text.strip():
                body.append("")
                self.i += 1
                continue
            if nxt.indent <= parent_indent:
                break
            if block_indent is None:
                block_indent = (parent_indent + explicit) if explicit else nxt.indent
            if nxt.indent < block_indent:
                break
            body.append(nxt.raw[block_indent:] if len(nxt.raw) >= block_indent else "")
            self.i += 1
        trailing = 0
        while body and body[-1] == "":
            body.pop()
            trailing += 1
        if style == "|":
            text = "\n".join(body)
        else:
            out: List[str] = []
            for idx, b in enumerate(body):
                if idx == 0:
                    out.append(b)
                elif b == "":
                    out.append("\n")
                elif out and out[-1].endswith("\n"):
                    out.append(b)
                else:
                    out.append(" " + b)
            text = "".join(out)
        if not body:
            return ""
        if chomp == "-":
            return text
        if chomp == "+":
            return text + "\n" * (trailing + 1)
        return text + "\n"

    def _sequence(self, indent: int, depth: int) -> List[Any]:
        items: List[Any] = []
        while True:
            ln = self._peek_content()
            if ln is None or ln.indent != indent:
                if ln is not None and ln.indent > indent:
                    raise YamlError("line %d: bad indentation inside a sequence" % ln.no)
                break
            text = _strip_comment(ln.text)
            if not (text == "-" or text.startswith("- ")):
                break
            rest = text[1:].strip()
            self.i += 1
            if not rest:
                nxt = self._peek_content()
                if nxt is not None and nxt.indent > indent:
                    items.append(self._block(nxt.indent, depth + 1))
                else:
                    items.append(None)
                continue
            # "- key: value" opens a mapping whose indent is the column of "key"
            child_indent = indent + (len(ln.text) - len(ln.text[1:].lstrip()))
            inner = _KEY_RE.match(rest) and not rest.startswith(("[", "{", '"', "'")) or (
                rest[:1] in "\"'" and _KEY_RE.match(rest) is not None)
            if rest == "-" or rest.startswith("- "):
                # nested sequence on the same line: re-inject as its own line
                self.lines[self.i - 1] = _Line(child_indent, rest, ln.no, " " * child_indent + rest)
                self.i -= 1
                items.append(self._sequence(child_indent, depth + 1))
            elif inner:
                self.lines[self.i - 1] = _Line(child_indent, rest, ln.no, " " * child_indent + rest)
                self.i -= 1
                items.append(self._mapping(child_indent, depth + 1))
            else:
                items.append(self._inline_value(rest, ln, depth + 1, indent_of_parent=indent))
        return items

    def _mapping(self, indent: int, depth: int) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        while True:
            ln = self._peek_content()
            if ln is None or ln.indent != indent:
                if ln is not None and ln.indent > indent:
                    raise YamlError("line %d: bad indentation inside a mapping" % ln.no)
                break
            text = _strip_comment(ln.text)
            if text == "-" or text.startswith("- "):
                break
            m = _KEY_RE.match(text)
            if not m or text.startswith(("[", "{")):
                raise YamlError("line %d: expected 'key: value', got %r" % (ln.no, text[:40]))
            key_tok = m.group("key").strip()
            if key_tok[:1] in "&*!" or key_tok == "<<":
                raise YamlError("line %d: anchors/aliases/merge keys are not supported" % ln.no)
            key = _scalar(key_tok, ln.no)
            key = "" if key is None else str(key if not isinstance(key, bool) else str(key).lower())
            rest = (m.group("rest") or "").strip()
            self.i += 1
            if rest:
                out[key] = self._inline_value(rest, ln, depth + 1, indent_of_parent=indent)
                continue
            nxt = self._peek_content()
            if nxt is None:
                out[key] = None
            elif nxt.indent > indent:
                out[key] = self._block(nxt.indent, depth + 1)
            elif nxt.indent == indent and (_strip_comment(nxt.text) == "-" or _strip_comment(nxt.text).startswith("- ")):
                out[key] = self._sequence(indent, depth + 1)     # "key:\n- a" (sequence at the key's own indent)
            else:
                out[key] = None
        return out


def _flow_depth(depth: int, quote: str, s: str) -> Tuple[int, str]:
    """Bracket depth of a flow collection after ``s``, ignoring brackets inside quoted scalars (a quote opens a scalar only
    at the start of a token, so the apostrophe of ``don't`` does not).  ``quote`` carries an open quote across lines."""
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if quote == '"':
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                quote = ""
        elif quote == "'":
            if ch == "'":
                if i + 1 < n and s[i + 1] == "'":
                    i += 2
                    continue
                quote = ""
        elif ch in "\"'":
            if i == 0 or s[i - 1] in " \t[{,:":
                quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        i += 1
    return depth, quote


def loads(text: str) -> Any:
    if not isinstance(text, str):
        raise YamlError("YAML input must be text")
    if len(text.encode("utf-8", "replace")) > MAX_BYTES:
        raise YamlError("YAML input larger than %d bytes" % MAX_BYTES)
    return _Parser(text).parse()


def load_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8-sig") as fh:
        return loads(fh.read(MAX_BYTES + 1))


# --------------------------------------------------------------------------------------------------- writer
_PLAIN_OK = re.compile(r"^[A-Za-z0-9_./][A-Za-z0-9_./ +@=()-]*$")


def _needs_quote(s: str) -> bool:
    if s == "" or s != s.strip() or s in _NULL or s in _BOOL_T or s in _BOOL_F:
        return True
    if not _PLAIN_OK.match(s) or s.endswith(" ") or ": " in s or " #" in s:
        return True
    if re.fullmatch(r"[-+]?[0-9][0-9_.eE+-]*", s):
        return True                          # looks numeric: quote so a round trip keeps the text
    return False


def _quote(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20 or o == 0x7f:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _emit_scalar(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    return _quote(s) if _needs_quote(s) else s


def _block_ok(v: str) -> bool:
    """May ``v`` be written as a literal block scalar and read back identically?  Only the plain shapes: several lines, no
    more than one trailing newline, no leading/trailing blanks on a line, no tabs or control characters, no empty edge.
    Everything else (``"  lead\\nz"``, ``"a\\n\\n\\n"``, ...) is written as a double-quoted scalar with escapes."""
    if "\n" not in v.strip("\n") or not v.strip() or v.endswith("\n\n") or v.startswith("\n"):
        return False
    for line in v.rstrip("\n").split("\n"):
        if line != line.strip() or any(ord(c) < 0x20 or ord(c) == 0x7f for c in line):
            return False
    return True


def dumps(obj: Any, indent: int = 2) -> str:
    lines: List[str] = []

    def emit(o: Any, level: int, in_seq: bool = False) -> None:
        pad = " " * (level * indent)
        if isinstance(o, dict):
            if not o:
                lines.append(pad + "{}")
                return
            for k, v in o.items():
                key = _emit_scalar(str(k))
                if isinstance(v, (dict, list)) and v:
                    lines.append("%s%s:" % (pad, key))
                    emit(v, level + 1)
                elif isinstance(v, (dict, list)):
                    lines.append("%s%s: %s" % (pad, key, "{}" if isinstance(v, dict) else "[]"))
                elif isinstance(v, str) and _block_ok(v):
                    lines.append("%s%s: |%s" % (pad, key, "" if v.endswith("\n") else "-"))
                    for part in v.rstrip("\n").split("\n"):
                        lines.append(pad + " " * indent + part if part else "")
                else:
                    lines.append("%s%s: %s" % (pad, key, _emit_scalar(v)))
        elif isinstance(o, list):
            if not o:
                lines.append(pad + "[]")
                return
            for v in o:
                if isinstance(v, dict) and v:
                    first = True
                    sub: List[str] = []
                    saved = lines[:]
                    del lines[:]
                    emit(v, level + 1)
                    sub = lines[:]
                    lines[:] = saved
                    for s in sub:
                        if first:
                            lines.append(pad + "- " + s[(level + 1) * indent:])
                            first = False
                        else:
                            lines.append(s)
                elif isinstance(v, list) and v:
                    lines.append(pad + "-")
                    emit(v, level + 1)
                elif isinstance(v, (dict, list)):
                    lines.append(pad + "- " + ("{}" if isinstance(v, dict) else "[]"))
                else:
                    lines.append(pad + "- " + _emit_scalar(v))
        else:
            lines.append(pad + _emit_scalar(o))

    emit(obj, 0)
    return "\n".join(lines) + "\n"
