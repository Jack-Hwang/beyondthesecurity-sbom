"""C / C++ declaration reader and usage scanner (standard library only).

Why: open source is mostly C and C++, and both the compatibility gate (``compat_c``) and the clean-room lane (``reimpl_c``)
need the same two facts the Python side gets from ``ast``: WHAT a library publishes (functions, types, macros, constants,
with their doc comments) and WHAT a project actually uses of it. No libclang is assumed (the service runs stdlib-only), so
this is a tokenizer plus a brace/paren-aware declaration splitter - deliberately a *declaration* reader, not a compiler:

  * it never evaluates ``#if``: every branch is read (the first declaration of a name wins, later ones are flagged
    ``conditional``), ``extern "C" {`` / ``namespace`` blocks are entered, function bodies are skipped, not read;
  * it understands what API compatibility needs - prototypes (+ qualifiers, attributes, C++ methods/ctors/templates), struct /
    union / class layouts, enums with evaluated values, typedefs, object- and function-like macros, globals;
  * whatever it cannot classify is dropped silently from the model but counted in ``skipped`` - the caller can see how
    much of a header was NOT understood instead of trusting a clean-looking result.

Cross-checked against Universal Ctags on real headers (tests/bts_sbom_app/test_cparse.py, skipped when ctags is absent).
Bodies are never part of the result: ``functions[].defined`` says a body existed, nothing more (clean-room wall 1).
"""
from __future__ import annotations

import ast
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

SCHEMA = "bts-sbom.cparse.v1"
C_EXT = (".c",)
CPP_EXT = (".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".ipp", ".inl")
HEADER_EXT = (".h", ".hh", ".hpp", ".hxx", ".h++", ".inl", ".ipp")
SOURCE_EXT = C_EXT + CPP_EXT
ALL_EXT = (".c", ".h") + CPP_EXT

_TOKEN = re.compile(r'''
    (?P<pp>^[ \t]*\#(?:\\\r?\n|/\*.*?\*/|[^\n])*)
   |(?P<ws>[ \t\r\f\v]+)
   |(?P<nl>\n)
   |(?P<lc>//(?:\\\r?\n|[^\n])*)
   |(?P<bc>/\*.*?\*/)
   |(?P<str>(?:u8|u|U|L)?"(?:\\.|[^"\\\n])*")
   |(?P<chr>(?:u8|u|U|L)?'(?:\\.|[^'\\\n])+')
   |(?P<num>0[xX][0-9a-fA-F']+[uUlLzZ]*|0[bB][01']+[uUlL]*|(?:\d[\d']*(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?[uUlLfFzZ]*)
   |(?P<id>[A-Za-z_$][A-Za-z0-9_$]*)
   |(?P<p3>\.\.\.|<<=|>>=|->\*|<=>)
   |(?P<p2>::|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||\+=|-=|\*=|/=|%=|&=|\|=|\^=|\#\#)
   |(?P<p1>.)
''', re.X | re.S | re.M)

_STORAGE = {"static", "extern", "inline", "__inline", "__inline__", "_Noreturn", "constexpr", "consteval", "constinit", "virtual", "explicit",
            "friend", "register", "thread_local", "_Thread_local", "mutable", "__forceinline", "noreturn"}
_ATTR_PAREN = {"__attribute__", "__attribute", "__declspec", "alignas", "_Alignas", "__asm__", "__asm", "asm", "noexcept", "__cdecl_attr",
               "__printf", "__scanf", "__aligned", "__packed_attr", "_Pragma"}
_CALLCONV = {"__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall", "WINAPI", "APIENTRY", "CALLBACK", "__extension__", "__restrict",
             "__restrict__", "restrict", "_Nonnull", "_Nullable", "__unused", "__always_inline", "__noinline", "__wur", "__THROW", "__nonnull"}
_API_MACRO = re.compile(r"^(?:[A-Z][A-Z0-9]*_)*(?:API|EXPORT|IMPORT|DECL|CALL|VISIBLE|DLL|PUBLIC|EXTERN)(?:_[A-Z0-9]+)*$")
_TYPE_WORDS = {"void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool", "bool", "wchar_t", "size_t", "ssize_t",
               "_Complex", "__int128", "char8_t", "char16_t", "char32_t", "auto"}
_QUAL = {"const", "volatile", "restrict", "__restrict", "__restrict__", "struct", "union", "enum", "class", "typename", "_Atomic"}
_NOT_DECL = {"return", "if", "else", "while", "for", "do", "switch", "case", "default", "goto", "break", "continue", "sizeof", "typeof",
             "__typeof__", "defined"}
_ACCESS = {"public", "private", "protected"}
# __rcode / __init / __weak / __maybe_unused ...: section/attribute marker words (but not __u32, __le16, __int128, __kernel_* type names)
_ATTR_WORD = re.compile(r"^__(?!u\d|s\d|le\d|be\d|int\d|kernel|uint|size|ssize|time|off|pid|uid|gid|mode)[a-z][a-z0-9_]*$")
_KNR_MACROS = {"OF", "__P", "_P", "__PMT", "PARAMS", "_PARAMS", "P_", "__PROTO"}      # f OF((args)) : an old prototype-compat wrapper
_INT_SUFFIX = re.compile(r"(?<=[0-9a-fA-F])[uUlLzZ]+\b")


class Tok:
    __slots__ = ("kind", "text", "line", "doc")

    def __init__(self, kind: str, text: str, line: int, doc: Optional[str] = None) -> None:
        self.kind, self.text, self.line, self.doc = kind, text, line, doc

    def __repr__(self) -> str:                                    # pragma: no cover - debugging aid
        return "Tok(%s,%r,%d)" % (self.kind, self.text, self.line)


_IF0 = re.compile(r"^[ \t]*#[ \t]*if[ \t]+\(?[ \t]*0[ \t]*\)?[ \t]*(?://.*|/\*.*\*/)?[ \t]*$")
_PP_OPEN = re.compile(r"^[ \t]*#[ \t]*(if|ifdef|ifndef)\b")
_PP_ELSE = re.compile(r"^[ \t]*#[ \t]*(else|elif)\b")
_PP_END = re.compile(r"^[ \t]*#[ \t]*endif\b")


def strip_dead_blocks(src: str) -> str:
    """Blank out ``#if 0`` ... ``#else``/``#endif`` regions (line count preserved): they are comments in disguise, not API."""
    if "#" not in src or not re.search(r"^[ \t]*#[ \t]*if[ \t]+\(?[ \t]*0", src, re.M):
        return src
    out: List[str] = []
    depth_dead = 0                                   # nesting depth inside a dead region (0 = live)
    nest = 0
    for ln in src.split("\n"):
        if depth_dead:
            if _PP_OPEN.match(ln):
                nest += 1
            elif _PP_END.match(ln):
                if nest == 0:
                    depth_dead = 0
                else:
                    nest -= 1
            elif nest == 0 and _PP_ELSE.match(ln):
                depth_dead = 0
            out.append("")
            continue
        if _IF0.match(ln):
            depth_dead, nest = 1, 0
            out.append("")
            continue
        out.append(ln)
    return "\n".join(out)


def tokenize(src: str) -> Tuple[List[Tok], List[Tuple[int, str]]]:
    """(significant tokens with the adjacent doc comment attached to the first token after it, preprocessor lines [(line, text)])."""
    src = strip_dead_blocks(src)
    toks: List[Tok] = []
    pps: List[Tuple[int, str]] = []
    line = 1
    pos = 0
    pend: Optional[Tuple[int, str]] = None                        # (end line, comment text) waiting for its declaration
    last_sig_line = 0
    n = len(src)
    while pos < n:
        m = _TOKEN.match(src, pos)
        if not m:
            pos += 1
            continue
        kind, text = m.lastgroup, m.group()
        start_line = line
        line += text.count("\n")
        pos = m.end()
        if kind in ("ws",):
            continue
        if kind == "nl":
            continue
        if kind in ("lc", "bc"):
            body = _comment_body(text)
            if pend and start_line - pend[0] <= 1 and kind == "lc":
                pend = (line, pend[1] + "\n" + body)               # a run of // lines is one comment
            else:
                pend = (line, body)
            continue
        if kind == "pp":
            pps.append((start_line, text))
            pend = None
            continue
        doc = None
        if pend is not None and start_line - pend[0] <= 1:
            doc = pend[1]
        pend = None
        toks.append(Tok(kind if kind in ("id", "num", "str", "chr") else "p", text, start_line, doc))
        last_sig_line = start_line
    return toks, pps


def _comment_body(text: str) -> str:
    if text.startswith("//"):
        return text[2:].lstrip("/!").strip()
    body = text[2:-2]
    out = []
    for ln in body.splitlines():
        ln = ln.strip()
        ln = re.sub(r"^\*+\s?", "", ln) if ln.startswith("*") else ln
        out.append(ln.rstrip())
    return "\n".join(out).strip("*\n ").strip()


# ============================================================================================ small helpers
def _match(toks: Sequence[Tok], i: int, open_: str, close: str) -> int:
    """index of the token closing the bracket opened at toks[i] (len(toks) when unbalanced)."""
    depth = 0
    for k in range(i, len(toks)):
        t = toks[k]
        if t.kind == "p":
            if t.text == open_:
                depth += 1
            elif t.text == close:
                depth -= 1
                if depth == 0:
                    return k
    return len(toks)


def _join(toks: Iterable[Tok]) -> str:
    out: List[str] = []
    for t in toks:
        s = t.text
        if out and re.match(r"[A-Za-z0-9_$\"']", s) and re.search(r"[A-Za-z0-9_$\"']$", out[-1]):
            out.append(" ")
        elif out and s in ("*", "&") and re.search(r"[A-Za-z0-9_$]$", out[-1]):        # `char *p`, not `char*p`
            out.append(" ")
        elif out and out[-1] == "," and s != ")":
            out.append(" ")
        out.append(s)
    return "".join(out)


def _split_commas(toks: Sequence[Tok], cpp: bool = False) -> List[List[Tok]]:
    parts: List[List[Tok]] = [[]]
    depth = 0
    angle = 0
    for t in toks:
        if t.kind == "p":
            if t.text in "([{":
                depth += 1
            elif t.text in ")]}":
                depth -= 1
            elif cpp and t.text == "<" and depth == 0 and parts[-1]:
                angle += 1
            elif cpp and t.text == ">" and angle:
                angle -= 1
            elif t.text == "," and depth == 0 and angle == 0:
                parts.append([])
                continue
        parts[-1].append(t)
    return [p for p in parts if p] if any(parts) else []


def _eval_int(expr: str, env: Optional[Dict[str, int]] = None) -> Optional[int]:
    """Constant-fold an integer expression made of literals, previously known names and C operators; None when it is anything else."""
    e = _INT_SUFFIX.sub("", expr.strip().replace("'", ""))
    if not e or len(e) > 160:
        return None
    e = re.sub(r"\(\s*(?:unsigned|signed|int|long|short|char|u?int\d+_t|size_t|uint)\b[\w\s*]*\)", "", e)       # casts to integer types
    if re.search(r"[^\w\s+\-*/%<>|&^~()!=,]", e):
        return None
    e = e.replace("&&", " and ").replace("||", " or ")
    e = re.sub(r"!(?!=)", " not ", e)
    try:
        tree = ast.parse(e.strip(), mode="eval")
    except SyntaxError:
        return None

    def ev(n: ast.AST) -> int:
        if isinstance(n, ast.Expression):
            return ev(n.body)
        if isinstance(n, ast.Constant) and isinstance(n.value, int):
            return n.value
        if isinstance(n, ast.Name):
            if env and n.id in env:
                return env[n.id]
            raise ValueError(n.id)
        if isinstance(n, ast.UnaryOp):
            v = ev(n.operand)
            if isinstance(n.op, ast.USub):
                return -v
            if isinstance(n.op, ast.UAdd):
                return v
            if isinstance(n.op, ast.Invert):
                return ~v
            if isinstance(n.op, ast.Not):
                return int(not v)
        if isinstance(n, ast.BinOp):
            a, b = ev(n.left), ev(n.right)
            op = n.op
            if isinstance(op, ast.Add):
                return a + b
            if isinstance(op, ast.Sub):
                return a - b
            if isinstance(op, ast.Mult):
                return a * b
            if isinstance(op, (ast.Div, ast.FloorDiv)):
                if not b:
                    raise ValueError("division by zero")            # not a constant expression: never guessed
                return int(a / b)
            if isinstance(op, ast.Mod):
                if not b:
                    raise ValueError("modulo by zero")
                return a % b
            if isinstance(op, ast.LShift) and 0 <= b < 128:
                return a << b
            if isinstance(op, ast.RShift) and 0 <= b < 128:
                return a >> b
            if isinstance(op, ast.BitOr):
                return a | b
            if isinstance(op, ast.BitAnd):
                return a & b
            if isinstance(op, ast.BitXor):
                return a ^ b
        raise ValueError("unsupported")
    try:
        return ev(tree)
    except (ValueError, ZeroDivisionError, RecursionError):
        return None


def normalize_type(text: str, strip_const: bool = True) -> str:
    """Canonical type spelling for comparing two releases: qualifiers/struct keywords dropped, int spellings unified, spacing fixed."""
    t = re.sub(r"\s+", " ", text.strip())
    if strip_const:
        t = re.sub(r"\b(?:const|volatile|restrict|__restrict__?|register|static|extern|inline|_Atomic)\b", " ", t)
    t = re.sub(r"\b(?:struct|union|enum|class|typename)\b", " ", t)
    t = re.sub(r"\s*\*\s*", "*", t)
    t = re.sub(r"\s*&\s*", "&", t)
    t = re.sub(r"\s+", " ", t).strip()
    words = t.split(" ")
    base, rest = [], ""
    for w in words:
        base.append(w)
    t = " ".join(base)
    t = re.sub(r"\bunsigned\b(?! (?:char|short|int|long))", "unsigned int", t)
    t = re.sub(r"\bsigned\b(?! (?:char|short|int|long))", "int", t)
    t = re.sub(r"\bsigned (char|short|int|long)\b", r"\1", t)
    t = re.sub(r"\b(short|long|unsigned long|unsigned short|long long|unsigned long long) int\b", r"\1", t)
    t = re.sub(r"\blong unsigned( int)?\b", "unsigned long", t)
    return t.strip()


# ============================================================================================ the declaration reader
class _Reader:
    def __init__(self, src: str, path: str, language: str) -> None:
        self.src, self.path, self.cpp = src, path, language == "c++"
        self.toks, self.pps = tokenize(src)
        self.model: Dict[str, Any] = {"schema": SCHEMA, "path": path.replace("\\", "/"), "language": language, "functions": [], "types": [],
                                      "macros": [], "variables": [], "includes": [], "skipped": 0, "conditional_names": []}
        self._seen: Set[Tuple[str, str]] = set()

    # ------------------------------------------------------------------ preprocessor
    def preprocess(self) -> None:
        for line, text in self.pps:
            body = re.sub(r"\\\r?\n", " ", text)
            body = re.sub(r"/\*.*?\*/", " ", body, flags=re.S)
            body = re.sub(r"//.*$", "", body).strip()
            m = re.match(r"#\s*include\s*([<\"])([^>\"]+)[>\"]", body)
            if m:
                self.model["includes"].append({"path": m.group(2), "system": m.group(1) == "<", "line": line})
                continue
            m = re.match(r"#\s*define\s+([A-Za-z_]\w*)(\([^)]*\))?\s*(.*)$", body, re.S)
            if m:
                name, params, value = m.group(1), m.group(2), m.group(3).strip()
                guard = (not params and not value and bool(re.search(r"(?:_H|_H_|_HPP|_HPP_|_INCLUDED|_INCLUDED_)$", name))) or name.startswith("__") and name.endswith("_H__")
                self.model["macros"].append({"name": name, "params": [p.strip() for p in params[1:-1].split(",") if p.strip()] if params else None,
                                             "variadic": bool(params and "..." in params), "body": value[:300], "value": None if params else _eval_int(value),
                                             "guard": guard, "line": line})

    # ------------------------------------------------------------------ scope walker
    def parse(self) -> Dict[str, Any]:
        self.preprocess()
        self._scope(0, len(self.toks), [], None)
        vals: Dict[str, int] = {}
        for m in self.model["macros"]:
            if m["value"] is not None:
                vals[m["name"]] = m["value"]
        for m in self.model["macros"]:                                      # macros defined from earlier macros
            if m["params"] is None and m["value"] is None:
                m["value"] = _eval_int(m["body"], vals)
                if m["value"] is not None:
                    vals[m["name"]] = m["value"]
        return self.model

    def _scan_stmt(self, i: int, end: int) -> Tuple[int, str, int]:
        """(index of the terminating token, ';' or '{', brace-paren depth marker). A '{' that starts an initializer is skipped over."""
        pd = 0
        k = i
        while k < end:
            t = self.toks[k]
            if t.kind == "p":
                if t.text in "([":
                    pd += 1
                elif t.text in ")]":
                    pd -= 1
                elif t.text == ";" and pd <= 0:
                    return k, ";", pd
                elif t.text == "{" and pd <= 0:
                    prev = self.toks[k - 1] if k > i else None
                    if prev is not None and prev.kind == "p" and prev.text in ("=", ",", "(") or (prev is not None and prev.text == "]" and self._is_array_init(i, k)):
                        k = _match(self.toks, k, "{", "}") + 1
                        continue
                    return k, "{", pd
                elif t.text == "}" and pd <= 0:
                    return k, "}", pd
            k += 1
        return end, ";", pd

    def _is_array_init(self, i: int, k: int) -> bool:
        return any(t.kind == "p" and t.text == "=" for t in self.toks[i:k])

    def _scope(self, start: int, end: int, prefix: List[str], cls: Optional[Dict[str, Any]]) -> None:
        i = start
        toks = self.toks
        access = "private" if (cls and cls.get("kind") == "class") else "public"
        while i < end:
            t = toks[i]
            if t.kind == "p" and t.text in (";", "}"):
                i += 1
                continue
            if t.kind == "id" and t.text in _ACCESS and i + 1 < end and toks[i + 1].text == ":":
                access = t.text
                i += 2
                continue
            if t.kind == "id" and t.text == "template" and i + 1 < end and toks[i + 1].text == "<":
                j = self._skip_angle(i + 1, end)
                tail = i
                i = j
                self._template_next = True
                continue
            k, term, _ = self._scan_stmt(i, end)
            chunk = toks[i:k]
            doc = toks[i].doc if i < len(toks) else None
            templ = getattr(self, "_template_next", False)
            self._template_next = False
            if term == "}":                                               # stray close brace inside this scope
                i = k + 1
                continue
            if not chunk:
                i = k + 1
                continue
            if term == "{":
                body_end = _match(toks, k, "{", "}")
                i = self._with_body(chunk, i, k, body_end, end, prefix, cls, access, doc, templ)
            else:
                self._declaration(chunk, None, prefix, cls, access, doc, templ, defined=False)
                i = k + 1

    def _skip_angle(self, i: int, end: int) -> int:
        depth = 0
        k = i
        while k < end:
            t = self.toks[k]
            if t.kind == "p":
                if t.text == "<":
                    depth += 1
                elif t.text == ">":
                    depth -= 1
                    if depth == 0:
                        return k + 1
                elif t.text == ">>" and depth >= 2:
                    depth -= 2
                    if depth == 0:
                        return k + 1
                elif t.text in (";", "{"):
                    return k
            k += 1
        return end

    # ------------------------------------------------------------------ statements with a { body }
    def _with_body(self, chunk: List[Tok], i: int, k: int, body_end: int, end: int, prefix: List[str], cls: Optional[Dict[str, Any]],
                   access: str, doc: Optional[str], templ: bool) -> int:
        toks = self.toks
        words = [t.text for t in chunk]
        first = words[0]
        if first == "extern" and len(chunk) >= 2 and chunk[1].kind == "str":
            self._scope(k + 1, body_end, prefix, cls)
            return body_end + 1
        if first == "namespace" or (len(words) > 1 and words[0] == "inline" and words[1] == "namespace"):
            name = next((w for w in words[1:] if re.match(r"[A-Za-z_]", w) and w != "namespace"), "")
            self._scope(k + 1, body_end, prefix + ([name] if name else []), cls)
            return body_end + 1
        agg = next((n for n, w in enumerate(words) if w in ("struct", "union", "enum", "class")), None)
        has_paren = any(t.kind == "p" and t.text == "(" for t in chunk)
        is_typedef = first == "typedef" or (first == "using")
        if agg is not None and (not has_paren or self._agg_before_paren(chunk, agg)):
            return self._aggregate(chunk, agg, i, k, body_end, end, prefix, cls, access, doc, is_typedef, templ)
        # a function (or method / ctor) definition: record the declaration, skip the body
        self._declaration(chunk, None, prefix, cls, access, doc, templ, defined=True)
        return body_end + 1

    @staticmethod
    def _agg_before_paren(chunk: List[Tok], agg: int) -> bool:
        for n, t in enumerate(chunk):
            if t.kind == "p" and t.text == "(":
                return agg < n and not any(x.text in ("typedef",) for x in chunk[:agg]) and False
        return True

    def _aggregate(self, chunk: List[Tok], agg: int, i: int, k: int, body_end: int, end: int, prefix: List[str], cls: Optional[Dict[str, Any]],
                   access: str, doc: Optional[str], is_typedef: bool, templ: bool) -> int:
        toks = self.toks
        kind = chunk[agg].text
        rest = chunk[agg + 1:]
        enum_class = kind == "enum" and rest and rest[0].text in ("class", "struct")
        if enum_class:
            rest = rest[1:]
        # name (before ':' base list), skipping attributes
        name = ""
        bases: List[str] = []
        stop = next((n for n, t in enumerate(rest) if t.text == ":" and t.kind == "p"), len(rest))
        for t in rest[:stop]:
            if t.kind == "id" and t.text not in _ATTR_PAREN and t.text not in ("final", "alignas"):
                name = t.text
        if stop < len(rest):
            bases = [_join(p).replace("public ", "").replace("private ", "").replace("protected ", "").replace("virtual ", "").strip()
                     for p in _split_commas(rest[stop + 1:], cpp=True)]
        # declarators after the closing brace, up to ';'
        j = body_end + 1
        tail_start = j
        while j < end and not (toks[j].kind == "p" and toks[j].text == ";"):
            if toks[j].kind == "p" and toks[j].text in "({":
                j = _match(toks, j, toks[j].text, ")" if toks[j].text == "(" else "}")
            j += 1
        tail = toks[tail_start:j]
        qual = "::".join(prefix + ([name] if name else []))
        entry: Dict[str, Any] = {"kind": "class" if kind == "class" else kind, "name": name, "scope": "::".join(prefix), "qualified": qual, "bases": bases,
                                 "fields": [], "enumerators": [], "methods": [], "doc": doc or (chunk[0].doc if chunk else None), "line": chunk[0].line,
                                 "template": templ, "scoped_enum": bool(enum_class), "opaque": False}
        if kind == "enum":
            self._enum_body(entry, k + 1, body_end)
        else:
            sub = {"kind": kind, "name": name, "entry": entry}
            self._members(entry, k + 1, body_end, prefix + ([name] if name else []), sub)
        if name:
            self._add_type(entry)
        elif is_typedef is False and not tail:
            pass                                                          # an anonymous aggregate without declarators is dropped
        names = self._declarator_names(tail)
        if is_typedef or chunk[0].text == "typedef":
            for tn, ptr in names:
                if not entry["name"] and tn == names[0][0]:
                    entry["name"] = tn
                    entry["anon_typedef"] = True                       # `typedef struct { ... } tn;` - no tag, the typedef name IS the type
                    entry["qualified"] = "::".join(prefix + [tn])
                    self._add_type(entry)
                    continue
                self.model["types"].append({"kind": "typedef", "name": tn, "target": ("%s %s%s" % (kind, name, "*" * ptr)).strip() if name else
                                            "%s %s" % (kind, entry["name"]), "scope": "::".join(prefix), "doc": doc, "line": chunk[0].line, "pointer": ptr})
        else:
            for tn, ptr in names:
                self.model["variables"].append({"name": tn, "type": ("%s %s%s" % (kind, name, "*" * ptr)).strip(), "storage": [], "scope": "::".join(prefix),
                                                "line": chunk[0].line, "doc": doc})
        return j + 1

    @staticmethod
    def _declarator_names(tail: List[Tok]) -> List[Tuple[str, int]]:
        out: List[Tuple[str, int]] = []
        for part in _split_commas(tail):
            ptr = sum(1 for t in part if t.text == "*")
            ids = [t.text for t in part if t.kind == "id" and t.text not in _QUAL]
            if ids:
                out.append((ids[-1], ptr))
        return out

    def _add_type(self, entry: Dict[str, Any]) -> None:
        key = ("type", entry["qualified"] or entry["name"])
        if key in self._seen:
            for ex in self.model["types"]:
                if (ex.get("qualified") or ex["name"]) == (entry["qualified"] or entry["name"]):
                    if entry["fields"] or entry["enumerators"]:
                        if not ex["fields"] and not ex["enumerators"]:
                            ex.update({k: entry[k] for k in ("fields", "enumerators", "methods", "bases", "doc") if entry.get(k)})
                            ex["opaque"] = False
                        else:
                            self.model["conditional_names"].append(entry["name"])
                    return
            return
        self._seen.add(key)
        self.model["types"].append(entry)

    def _enum_body(self, entry: Dict[str, Any], a: int, b: int) -> None:
        env: Dict[str, int] = {}
        nxt = 0
        for part in _split_commas(self.toks[a:b]):
            ids = [t for t in part if t.kind == "id"]
            if not ids:
                continue
            eq = next((n for n, t in enumerate(part) if t.text == "="), None)
            name = ids[0].text
            expr = _join(part[eq + 1:]) if eq is not None else ""
            val = _eval_int(expr, env) if eq is not None else nxt
            if val is not None:
                env[name] = val
                nxt = val + 1
            else:
                nxt += 1
            entry["enumerators"].append({"name": name, "expr": expr, "value": val, "doc": part[0].doc})

    def _members(self, entry: Dict[str, Any], a: int, b: int, prefix: List[str], sub: Dict[str, Any]) -> None:
        saved = (self.model["functions"], self.model["variables"])
        i = a
        toks = self.toks
        access = "private" if entry["kind"] == "class" else "public"
        while i < b:
            t = toks[i]
            if t.kind == "p" and t.text in (";", "}"):
                i += 1
                continue
            if t.kind == "id" and t.text in _ACCESS and i + 1 < b and toks[i + 1].text == ":":
                access = t.text
                i += 2
                continue
            if t.kind == "id" and t.text == "template" and i + 1 < b and toks[i + 1].text == "<":
                i = self._skip_angle(i + 1, b)
                self._template_next = True
                continue
            k, term, _ = self._scan_stmt(i, b)
            chunk = toks[i:k]
            if not chunk:
                i = k + 1
                continue
            if term == "{":
                body_end = _match(toks, k, "{", "}")
                words = [x.text for x in chunk]
                agg = next((n for n, w in enumerate(words) if w in ("struct", "union", "enum", "class")), None)
                if agg is not None and not any(x.text == "(" for x in chunk[:agg + 3]):
                    self._member_aggregate(entry, chunk, agg, k, body_end, b, prefix)
                    j = body_end + 1
                    while j < b and not (toks[j].kind == "p" and toks[j].text == ";"):
                        j += 1
                    i = j + 1
                    continue
                self._declaration(chunk, entry, prefix[:-1] if prefix else [], entry, access, chunk[0].doc, False, defined=True)
                i = body_end + 1
                continue
            self._declaration(chunk, entry, prefix[:-1] if prefix else [], entry, access, chunk[0].doc, getattr(self, "_template_next", False), defined=False)
            self._template_next = False
            i = k + 1

    def _member_aggregate(self, entry: Dict[str, Any], chunk: List[Tok], agg: int, k: int, body_end: int, end: int, prefix: List[str]) -> None:
        """A nested struct/union/enum inside a struct: an anonymous one becomes a field type, a named one a type of its own."""
        kind = chunk[agg].text
        nm = next((t.text for t in chunk[agg + 1:] if t.kind == "id" and t.text not in _ATTR_PAREN), "")
        nested: Dict[str, Any] = {"kind": kind, "name": nm, "scope": "::".join(prefix[:-1]), "qualified": "::".join(prefix + ([nm] if nm else [])), "bases": [],
                                  "fields": [], "enumerators": [], "methods": [], "doc": chunk[0].doc, "line": chunk[0].line, "template": False,
                                  "scoped_enum": False, "opaque": False}
        if kind == "enum":
            self._enum_body(nested, k + 1, body_end)
        else:
            self._members(nested, k + 1, body_end, prefix + ([nm] if nm else []), {})
        if nm:
            self._add_type(nested)
        j = body_end + 1
        tail_start = j
        while j < end and not (self.toks[j].kind == "p" and self.toks[j].text == ";"):
            j += 1
        for fname, ptr in self._declarator_names(self.toks[tail_start:j]):
            entry["fields"].append({"name": fname, "type": ("%s %s" % (kind, nm or "{...}")).strip() + "*" * ptr, "norm": normalize_type("%s %s%s" % (kind, nm or "anon", "*" * ptr)),
                                    "bits": None, "array": None, "nested": nested if not nm else None, "access": "public", "doc": chunk[0].doc})

    # ------------------------------------------------------------------ one declaration (no body, or a function body already skipped)
    def _clean(self, chunk: List[Tok]) -> Tuple[List[Tok], List[str], bool]:
        """chunk without attributes / calling conventions; (tokens, attribute words, deprecated?)"""
        out: List[Tok] = []
        attrs: List[str] = []
        depr = False
        i = 0
        while i < len(chunk):
            t = chunk[i]
            if t.kind == "id" and t.text in _ATTR_PAREN and i + 1 < len(chunk) and chunk[i + 1].text == "(":
                j = _match(chunk, i + 1, "(", ")")
                body = _join(chunk[i + 2:j])
                if "deprecated" in body.lower() or "deprecated" in t.text.lower():
                    depr = True
                attrs.append(t.text)
                i = j + 1
                continue
            if t.kind == "p" and t.text == "[" and i + 1 < len(chunk) and chunk[i + 1].text == "[":
                j = _match(chunk, i, "[", "]")
                body = _join(chunk[i + 2:j])
                if "deprecated" in body.lower():
                    depr = True
                i = j + 1
                continue
            if t.kind == "id" and re.match(r"^_*[A-Z][A-Z0-9_]*$", t.text) and i + 1 < len(chunk) and chunk[i + 1].text == "(" and t.text not in _KNR_MACROS:
                j = _match(chunk, i + 1, "(", ")")
                rest = chunk[j + 1:]
                if any(x.kind == "id" and n + 1 < len(rest) and rest[n + 1].text == "(" for n, x in enumerate(rest)):   # another f( follows: this was an attribute macro
                    if "deprecat" in _join(chunk[i:j + 1]).lower():
                        depr = True
                    i = j + 1
                    continue
            if t.kind == "id" and (t.text in _CALLCONV or t.text in ("__deprecated", "DEPRECATED", "G_GNUC_DEPRECATED", "__attribute_deprecated__")):
                depr = depr or "deprecated" in t.text.lower() or t.text == "DEPRECATED"
                i += 1
                continue
            out.append(t)
            i += 1
        return out, attrs, depr

    def _declaration(self, chunk: List[Tok], owner: Optional[Dict[str, Any]], prefix: List[str], cls: Optional[Dict[str, Any]], access: str,
                     doc: Optional[str], templ: bool, defined: bool) -> None:
        words = [t.text for t in chunk]
        if not chunk:
            return
        if words[0] == "typedef" or (words[0] == "using" and "=" in words):
            self._typedef(chunk, prefix, doc)
            return
        if words[0] in ("static_assert", "_Static_assert", "using", "friend", "extern") and (words[0] != "extern" or len(chunk) > 2 and chunk[1].kind == "str" and False):
            if words[0] in ("static_assert", "_Static_assert", "using", "friend"):
                return
        toks, attrs, depr = self._clean(chunk)
        words = [t.text for t in toks]
        # first top-level '=' (an initializer, or `= 0` / `= default` after a method's parameter list); never one inside the
        # parameter list (a default argument) and never `operator=`
        eq = None
        depth = 0
        for n, t in enumerate(toks):
            if t.kind == "p":
                if t.text in "([{":
                    depth += 1
                elif t.text in ")]}":
                    depth -= 1
                elif t.text == "=" and depth == 0 and not (n and toks[n - 1].text == "operator"):
                    eq = n
                    break
        full = toks
        head = toks if eq is None else toks[:eq]
        po = next((n for n, t in enumerate(head) if t.kind == "p" and t.text == "("), None)
        if po is None:
            self._variables(head, owner, prefix, doc, access)
            return
        # function pointer variable:  T (*name)(args)
        if po + 1 < len(head) and head[po + 1].text in ("*", "^") and not (po > 0 and head[po - 1].kind == "id" and head[po - 1].text not in _TYPE_WORDS and po >= 2 and False):
            self._variables(head, owner, prefix, doc, access, funcptr=True)
            return
        if po >= 2 and head[po - 1].kind == "id" and head[po - 1].text in _KNR_MACROS and po + 1 < len(head) and head[po + 1].text == "(":
            inner_open = po + 1                                  # `deflate OF((a, b))`: drop OF and the outer parens -> `deflate (a, b)`
            inner_close = _match(head, inner_open, "(", ")")
            head = head[:po - 1] + head[inner_open:inner_close + 1] + head[inner_close + 2:]
            po -= 1
        # C++ call operator:  operator()(args)
        if po >= 1 and head[po - 1].text == "operator" and po + 2 < len(head) and head[po + 1].text == ")" and head[po + 2].text == "(":
            head = head[:po] + [Tok("p", "()", head[po].line)] + head[po + 2:]
            po += 1
        j = _match(head, po, "(", ")")
        prev = head[po - 1] if po > 0 else None
        if prev is None:
            self.model["skipped"] += 1
            return
        # the name chain  a::b::name / operator== / ~Name
        n0 = po - 1
        name_parts: List[str] = []
        if prev.kind == "p" and prev.text not in (">",):
            # operator symbol(s)
            q = po - 1
            while q > 0 and head[q].kind == "p" and head[q].text not in ("::",):
                q -= 1
            if q >= 0 and head[q].text == "operator":
                name_parts = ["operator" + _join(head[q + 1:po])]
                n0 = q
            else:
                self.model["skipped"] += 1
                return
        elif prev.kind == "id":
            name_parts = [prev.text]
            n0 = po - 1
            if n0 >= 1 and head[n0 - 1].text == "operator":
                name_parts = ["operator " + prev.text]
                n0 -= 1
        else:
            self.model["skipped"] += 1
            return
        # qualified (Class::method) and destructors
        while n0 >= 2 and head[n0 - 1].text == "::" and head[n0 - 2].kind == "id":
            name_parts.insert(0, head[n0 - 2].text)
            n0 -= 2
        if n0 >= 1 and head[n0 - 1].text == "~":
            name_parts[-1] = "~" + name_parts[-1]
            n0 -= 1
        name = name_parts[-1]
        if name in _NOT_DECL or name.startswith("__section"):
            self.model["skipped"] += 1                                    # sizeof(...) / attribute-like macro, not a function
            return
        qual_prefix = "::".join(name_parts[:-1])
        before = [t for t in head[:n0] if not (t.kind == "id" and (t.text in _STORAGE or _API_MACRO.match(t.text) and len(head[:n0]) > 1))]
        # project export / linkage macros (ZEXTERN, ZEXPORT, EFIAPI ...): ALL-CAPS words are dropped when a real type word remains
        real = [t for t in before if t.kind == "id" and t.text not in _QUAL and not re.match(r"^_*[A-Z][A-Z0-9_]*$", t.text)
                and not _ATTR_WORD.match(t.text)]
        if real:
            before = [t for t in before if not (t.kind == "id" and re.match(r"^_*[A-Z][A-Z0-9_]{2,}$", t.text) and t.text not in _TYPE_WORDS)
                      and not (t.kind == "id" and _ATTR_WORD.match(t.text))]
        storage = [t.text for t in head[:n0] if t.kind == "id" and t.text in _STORAGE]
        ret_toks = before
        is_ctor = False
        if cls is not None and (name == cls.get("name") or name == "~" + str(cls.get("name"))):
            is_ctor = True
        if not ret_toks and not is_ctor and not name.startswith("operator"):
            self.model["skipped"] += 1                                    # SOME_MACRO(args);  - not a declaration
            return
        if not ret_toks and not is_ctor and name.startswith("operator") and not (name.startswith("operator ")):
            pass
        params, variadic = self._params(head[po + 1:j])
        tail = [t.text for t in head[j + 1:]] + ([t.text for t in full[eq:]] if eq is not None else [])
        scope = "::".join(prefix + ([cls["name"]] if cls and cls.get("name") else []) + ([qual_prefix] if qual_prefix else []))
        ret = _join(ret_toks)
        fn: Dict[str, Any] = {
            "name": name, "scope": scope, "qualified": ("%s::%s" % (scope, name)) if scope else name,
            "kind": "dtor" if name.startswith("~") else "ctor" if is_ctor else "method" if (cls is not None or qual_prefix) else "function",
            "ret": ret, "ret_norm": normalize_type(ret), "params": params, "variadic": variadic, "storage": storage, "attrs": attrs, "deprecated": depr,
            "doc": doc, "line": chunk[0].line, "defined": defined, "template": templ, "access": access if cls is not None else "public",
            "const": "const" in tail, "virtual": "virtual" in storage or "override" in tail, "pure": "0" in tail and "=" in tail, "noexcept": "noexcept" in tail,
            "static": "static" in storage, "inline": any(s in storage for s in ("inline", "__inline", "__inline__", "__forceinline", "constexpr")),
            "deleted": "delete" in tail,
        }
        fn["proto"] = "%s %s(%s)" % (ret, name, ", ".join([p["text"] for p in params] + (["..."] if variadic else []) or ["void"])) if ret else \
            "%s(%s)" % (name, ", ".join([p["text"] for p in params] + (["..."] if variadic else [])))
        if owner is not None and cls is not None:
            owner["methods"].append(fn["name"])
        key = ("fn", fn["qualified"] + "(" + ",".join(p["norm"] for p in params) + ")")
        if key in self._seen:
            self.model["conditional_names"].append(fn["name"])
            for ex in self.model["functions"]:
                if ex["qualified"] == fn["qualified"] and [p["norm"] for p in ex["params"]] == [p["norm"] for p in params]:
                    if defined and not ex["defined"]:
                        ex["defined"] = True
                        ex["doc"] = ex["doc"] or doc
                    elif doc and not ex["doc"]:
                        ex["doc"] = doc
            return
        self._seen.add(key)
        self.model["functions"].append(fn)

    def _params(self, toks: List[Tok]) -> Tuple[List[Dict[str, Any]], bool]:
        parts = _split_commas(toks, cpp=self.cpp)
        out: List[Dict[str, Any]] = []
        variadic = False
        for p in parts:
            words = [t.text for t in p]
            if words == ["..."] or words[-1:] == ["..."] and len(p) == 1:
                variadic = True
                continue
            if words == ["void"]:
                continue
            if "..." in words:
                variadic = True
                p = [t for t in p if t.text != "..."]
            eq = next((n for n, t in enumerate(p) if t.text == "="), None)
            default = None
            if eq is not None:
                default = _join(p[eq + 1:])
                p = p[:eq]
            p, _a, _d = self._clean(p)
            if not p:
                continue
            name = ""
            tp = p
            fp = next((n for n, t in enumerate(p) if t.text == "(" and n + 1 < len(p) and p[n + 1].text in ("*", "^", "&")), None)
            if fp is not None:
                nm = next((t.text for t in p[fp + 2:] if t.kind == "id"), "")
                name = nm
                tp = [t for t in p if not (t.kind == "id" and t.text == nm and nm)] if nm else p
            else:
                last = p[-1]
                arr = ""
                core = p
                while core and core[-1].text == "]":                       # trailing [N] belongs to the declarator
                    o = max(n for n, t in enumerate(core) if t.text == "[")
                    arr = _join(core[o:]) + arr
                    core = core[:o]
                if len(core) >= 2 and core[-1].kind == "id" and core[-1].text not in _TYPE_WORDS and core[-1].text not in _QUAL \
                        and not (core[-2].kind == "p" and core[-2].text == "::") and not (len(core) == 2 and core[0].text in _QUAL and core[0].text in ("struct", "union", "enum", "class", "typename")):
                    name = core[-1].text
                    core = core[:-1]
                tp = core + ([Tok("p", "*", core[-1].line)] if arr and core else [])
            tt = _join(tp)
            out.append({"type": tt, "norm": normalize_type(tt), "strict": normalize_type(tt, strip_const=False), "name": name, "default": default is not None,
                        "funcptr": fp is not None, "text": _join(p)})
        return out, variadic

    def _variables(self, head: List[Tok], owner: Optional[Dict[str, Any]], prefix: List[str], doc: Optional[str], access: str,
                   funcptr: bool = False) -> None:
        if not head:
            return
        storage = [t.text for t in head if t.kind == "id" and t.text in _STORAGE]
        body = [t for t in head if not (t.kind == "id" and t.text in _STORAGE)]
        if len(body) < 2 and not funcptr:
            self.model["skipped"] += 1
            return
        parts = _split_commas(body, cpp=self.cpp) if not funcptr else [body]
        base_tokens: List[Tok] = []
        for n, part in enumerate(parts):
            if funcptr:
                m = next((q for q, t in enumerate(part) if t.text == "(" and q + 1 < len(part) and part[q + 1].text in ("*", "^")), None)
                nm = next((t.text for t in part[(m or 0) + 2:] if t.kind == "id"), "")
                tp = _join(part[:m]) + "(*)(...)" if m is not None else _join(part)
                self._emit_var(owner, prefix, nm, tp, storage, doc, part[0].line, access, None, None, decl=_join(part))
                continue
            bits = None
            arr = None
            core = part
            bm = next((q for q, t in enumerate(core) if t.text == ":" and t.kind == "p"), None)
            if bm is not None:
                bits = _eval_int(_join(core[bm + 1:]))
                core = core[:bm]
            while core and core[-1].text == "]":
                o = max(q for q, t in enumerate(core) if t.text == "[")
                arr = _join(core[o:]) + (arr or "")
                core = core[:o]
            if n == 0:
                ids = [q for q, t in enumerate(core) if t.kind == "id" and t.text not in _QUAL]
                if not ids:
                    continue
                if len(core) < 2 and bits is None:
                    continue
                nm_i = ids[-1]
                base_tokens = [t for t in core[:nm_i] if t.text != "*"]
                stars = sum(1 for t in core[:nm_i] if t.text == "*")
                tp_txt = _join(core[:nm_i])
                nm = core[nm_i].text
            else:
                stars = sum(1 for t in core if t.text == "*")
                ids = [t.text for t in core if t.kind == "id"]
                if not ids:
                    continue
                nm = ids[-1]
                tp_txt = _join(base_tokens) + "*" * stars
            self._emit_var(owner, prefix, nm, tp_txt, storage, doc, part[0].line, access, bits, arr)

    def _emit_var(self, owner: Optional[Dict[str, Any]], prefix: List[str], name: str, tp: str, storage: List[str], doc: Optional[str], line: int,
                  access: str, bits: Optional[int], arr: Optional[str], decl: Optional[str] = None) -> None:
        if not name:
            return
        norm = normalize_type(tp + (arr or ""), strip_const=False)
        if owner is not None:
            owner["fields"].append({"name": name, "type": tp, "norm": normalize_type(tp), "strict": norm, "bits": bits, "array": arr, "access": access,
                                    "doc": doc, "static": "static" in storage,
                                    "decl": decl or ("%s %s%s%s" % (tp, name, arr or "", (" : %d" % bits) if bits else ""))})
            return
        key = ("var", "::".join(prefix + [name]))
        if key in self._seen:
            return
        self._seen.add(key)
        self.model["variables"].append({"name": name, "type": tp, "norm": normalize_type(tp), "array": arr, "storage": storage, "scope": "::".join(prefix),
                                        "line": line, "doc": doc, "const": "const" in tp.split(), "extern": "extern" in storage})

    def _typedef(self, chunk: List[Tok], prefix: List[str], doc: Optional[str]) -> None:
        words = [t.text for t in chunk]
        if words[0] == "using":
            eq = words.index("=")
            name = words[1] if eq == 2 else words[eq - 1]
            target = _join(chunk[eq + 1:])
            self.model["types"].append({"kind": "typedef", "name": name, "target": target, "scope": "::".join(prefix), "doc": doc, "line": chunk[0].line,
                                        "norm": normalize_type(target), "funcptr": False, "pointer": 0})
            return
        body, _attrs, _d = self._clean(chunk[1:])
        fp = next((n for n, t in enumerate(body) if t.text == "(" and n + 1 < len(body) and body[n + 1].text in ("*", "^")), None)
        if fp is not None:
            nm = next((t.text for t in body[fp + 2:] if t.kind == "id"), "")
            self.model["types"].append({"kind": "typedef", "name": nm, "target": _join(body[:fp]) + "(*)(...)", "scope": "::".join(prefix), "doc": doc,
                                        "line": chunk[0].line, "norm": "funcptr", "funcptr": True, "pointer": 0, "decl": "typedef " + _join(body)})
            return
        parts = _split_commas(body)
        base_text = ""
        for n, part in enumerate(parts):
            core = list(part)
            while core and core[-1].text == "]":
                o = max(q for q, t in enumerate(core) if t.text == "[")
                core = core[:o]
            ids = [q for q, t in enumerate(core) if t.kind == "id" and t.text not in _QUAL]
            if not ids:
                continue
            ni = ids[-1]
            stars = sum(1 for t in core[:ni] if t.text == "*")
            if n == 0:
                if ni == 0:
                    continue
                first_star = next((q for q, t in enumerate(core[:ni]) if t.text == "*"), ni)
                base_text = _join(core[:first_star])
            tgt = base_text + "*" * stars
            self.model["types"].append({"kind": "typedef", "name": core[ni].text, "target": tgt, "scope": "::".join(prefix), "doc": doc,
                                        "line": chunk[0].line, "norm": normalize_type(tgt), "funcptr": False, "pointer": stars,
                                        "decl": "typedef %s %s" % (tgt, core[ni].text)})


# ============================================================================================ public API
def detect_language(path: str, src: str = "") -> str:
    low = path.lower()
    if low.endswith(CPP_EXT):
        return "c++"
    if low.endswith(".h") and re.search(r"\b(?:class\s+\w+\s*[{:]|namespace\s+\w+|template\s*<|std::|operator\s*\W|constexpr|nullptr|public:|private:)", src):
        return "c++"
    return "c"


def parse(src: str, path: str = "", language: Optional[str] = None) -> Dict[str, Any]:
    """Read one C/C++ source or header into the declaration model (see the module docstring for what it contains)."""
    lang = language or detect_language(path, src)
    return _Reader(src, path, lang).parse()


def parse_file(path: str, language: Optional[str] = None) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse(fh.read(), path, language)


def merge(models: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """One model over several headers: the first occurrence of a function/type/macro/variable wins, later ones are counted as duplicates."""
    out: Dict[str, Any] = {"schema": SCHEMA, "path": ",".join(m.get("path", "") for m in models[:3]), "language": "c", "functions": [], "types": [],
                           "macros": [], "variables": [], "includes": [], "skipped": 0, "conditional_names": [], "duplicates": 0, "files": len(models)}
    seen: Set[Tuple[str, str]] = set()
    for m in models:
        if m.get("language") == "c++":
            out["language"] = "c++"
        out["skipped"] += int(m.get("skipped") or 0)
        out["includes"].extend(m.get("includes") or [])
        for kind in ("functions", "types", "macros", "variables"):
            for e in m.get(kind) or []:
                if kind == "functions":
                    k = (kind, e["qualified"] + "(" + ",".join(p["norm"] for p in e["params"]) + ")")
                elif kind == "types":
                    k = (kind, e.get("qualified") or e["name"] + ("#td" if e["kind"] == "typedef" else ""))
                else:
                    k = (kind, e.get("qualified") or e["name"])
                if k in seen:
                    out["duplicates"] += 1
                    if kind == "types" and e["kind"] in ("struct", "union", "enum", "class"):
                        for ex in out["types"]:
                            if (ex.get("qualified") or ex["name"]) == (e.get("qualified") or e["name"]) and not ex["fields"] and not ex["enumerators"] \
                                    and (e["fields"] or e["enumerators"]):
                                ex.update({kk: e[kk] for kk in ("fields", "enumerators", "bases", "doc") if e.get(kk)})
                    continue
                seen.add(k)
                out[kind].append(e)
    return out


def external_functions(model: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Functions with external linkage: not static, not an inline-only header helper, not a method of an unnamed scope."""
    return [f for f in model["functions"] if not f["static"] and f["kind"] in ("function", "method", "ctor", "dtor")]


# ============================================================================================ what a project uses
def local_definitions(src: str, path: str = "") -> Set[str]:
    """Names of functions/macros the project DEFINES itself - they shadow a library symbol of the same name."""
    m = parse(src, path)
    return {f["name"] for f in m["functions"] if f["defined"]} | {x["name"] for x in m["macros"]}


def interest_set(api: Dict[str, Any]) -> Dict[str, Set[str]]:
    fields: Set[str] = set()
    for t in api["types"]:
        for f in t.get("fields") or []:
            fields.add(f["name"])
    return {"functions": {f["name"] for f in api["functions"] if f["kind"] in ("function", "method")},
            "macros": {m["name"] for m in api["macros"] if not m["guard"]},
            "enumerators": {e["name"] for t in api["types"] for e in (t.get("enumerators") or [])},
            "types": {t["name"] for t in api["types"] if t["name"]},
            "variables": {v["name"] for v in api["variables"]},
            "fields": fields}


def scan_usage(src: str, path: str, interest: Dict[str, Set[str]], shadow: Optional[Set[str]] = None, sink: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """What one project file uses of the library: call sites with their argument count, constant / macro / type / variable references and
    struct-field accesses (by name - no type inference, so field matches are evidence, not proof)."""
    sink = sink if sink is not None else {"symbols": {}, "fields": {}, "includes": []}
    toks, pps = tokenize(src)
    shadow = shadow or set()
    for line, text in pps:
        m = re.match(r"#\s*include\s*([<\"])([^>\"]+)[>\"]", text)
        if m:
            sink["includes"].append({"path": m.group(2), "file": path, "line": line})
    all_names = interest["functions"] | interest["macros"] | interest["enumerators"] | interest["types"] | interest["variables"]
    n = len(toks)
    for i, t in enumerate(toks):
        if t.kind == "p" and t.text in ("->", ".") and i + 1 < n and toks[i + 1].kind == "id" and toks[i + 1].text in interest["fields"]:
            d = sink["fields"].setdefault(toks[i + 1].text, {"count": 0, "sites": []})
            d["count"] += 1
            if len(d["sites"]) < 4:
                d["sites"].append({"file": path, "line": t.line})
            continue
        if t.kind != "id" or t.text not in all_names or t.text in shadow or t.text in _NOT_DECL:
            continue
        prev = toks[i - 1] if i else None
        if prev is not None and prev.kind == "p" and prev.text in ("->", ".", "::") and t.text not in interest["functions"]:
            continue
        d = sink["symbols"].setdefault(t.text, {"calls": [], "refs": 0, "sites": []})
        d["refs"] += 1
        if len(d["sites"]) < 4:
            d["sites"].append({"file": path, "line": t.line})
        if i + 1 < n and toks[i + 1].text == "(" and (t.text in interest["functions"] or t.text in interest["macros"]):
            j = _match(toks, i + 1, "(", ")")
            inner = toks[i + 2:j]
            after = toks[j + 1] if j + 1 < n else None
            looks_decl = prev is not None and (prev.kind == "id" and prev.text not in _NOT_DECL and prev.text not in ("else",) or prev.text in ("*",) and i >= 2 and toks[i - 2].kind == "id" and toks[i - 2].text not in _NOT_DECL) \
                and after is not None and after.text in (";", "{", ",", ")")
            if looks_decl and t.text in interest["functions"]:
                d["refs"] -= 1
                continue
            parts = _split_commas(inner, cpp=False)
            argc = 0 if (not inner or [x.text for x in inner] == ["void"]) else len(parts)
            d["calls"].append({"npos": argc, "file": path, "line": t.line})
    return sink
