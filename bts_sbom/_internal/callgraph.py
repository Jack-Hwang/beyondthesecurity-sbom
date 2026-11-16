# vendored from misra_guard/dataflow/callgraph.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
First-class call graph for interprocedural analysis (Coverity-gap closure #2).

The existing taint scanner resolves calls by ad-hoc `re.findall(id\\()` name matching.
A Coverity-class engine needs a real call-graph object: nodes = functions, edges =
call sites (with the argument expressions and the result variable), plus:
  * indirect-call (function-pointer) candidate resolution over ADDRESS-TAKEN functions,
  * nominal C++ class hierarchy and override-aware virtual/member dispatch,
  * strongly-connected-component detection (recursion / mutual recursion),
  * a reverse-topological order so function SUMMARIES can be computed bottom-up.

Self-contained C/C++ parsing (comment/string stripping + brace matching) — no
external toolchain, so it runs everywhere the rest of the offline engine does.
"""
import re
from typing import Any, Dict, List, Optional, Set, Tuple

_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "do", "else",
             "case", "default", "goto", "typedef", "struct", "union", "enum",
             "dynamic_cast", "static_cast", "reinterpret_cast", "const_cast"}
_CALL_RE = re.compile(r"([A-Za-z_]\w*)(\s*<[^;{}()]*>)?\s*\(")
_ADDR_TAKEN_RE = re.compile(r"&\s*([A-Za-z_]\w*)\b")
# virtual-dispatch and function-pointer multi-target analysis
_VIRTUAL_DECL_RE = re.compile(r'\bvirtual\b[^;{(]*?\b([A-Za-z_]\w*)\s*\(')
_FP_ASSIGN_RE = re.compile(r'\b([A-Za-z_]\w*)\s*=\s*&?\s*([A-Za-z_]\w*)\b')


class CallSite:
    __slots__ = ("callee", "args", "lineno", "result", "indirect", "virtual",
                 "receiver", "fp_targets", "dispatch_targets", "template_args",
                 "receiver_adjustment")

    def __init__(self, callee: str, args: List[str], lineno: int,
                 result: Optional[str] = None, indirect: bool = False,
                 virtual: bool = False,
                 fp_targets: Optional[List[str]] = None,
                 receiver: Optional[str] = None, template_args: str = ""):
        self.callee = callee
        self.args = args
        self.lineno = lineno
        self.result = result
        self.indirect = indirect
        self.virtual = virtual            # True when called as ptr->method()/obj.method()
        self.receiver = receiver
        self.fp_targets: List[str] = fp_targets or []  # pre-resolved multi-target fp assignments
        self.dispatch_targets: List[str] = []
        self.template_args = template_args
        self.receiver_adjustment: List[str] = []


class ParsedFunction:
    __slots__ = ("name", "params", "param_types", "owner", "body", "start_line", "calls",
                 "noexcept", "automatic_destructors", "param_decls",
                 "template_args", "constraint", "template_definition")

    def __init__(self, name: str, params: List[str], body: str, start_line: int,
                 param_types: Optional[Dict[str, str]] = None,
                 owner: Optional[str] = None, noexcept: bool = False,
                 param_decls: Optional[Dict[str, str]] = None,
                 template_args: str = "", constraint: str = "",
                 template_definition: bool = False):
        self.name = name
        self.params = params
        self.param_types = param_types or {}
        self.owner = owner
        self.body = body
        self.start_line = start_line
        self.calls: List[CallSite] = []
        self.noexcept = noexcept
        # Original declaration spelling is required by ownership analysis to
        # distinguish shared_ptr by value from a mutable reference and to retain
        # nested STL/smart-pointer type structure that nominal `param_types` drops.
        self.param_decls = param_decls or {}
        self.template_args = template_args
        self.constraint = constraint
        self.template_definition = template_definition
        # (qualified destructor name, declaration line, guaranteed construction).
        self.automatic_destructors: List[Tuple[str, int, bool]] = []


# ── source hygiene ────────────────────────────────────────────────────────────
def strip_noncode(code: str) -> str:
    """Remove comments and blank out string/char literal INNER content, preserving
    newlines (so line numbers are stable) and braces-in-strings can't confuse parsing."""
    out = []
    i, n = 0, len(code)
    while i < n:
        c = code[i]
        two = code[i:i + 2]
        if two == "//":
            while i < n and code[i] != "\n":
                i += 1
        elif two == "/*":
            i += 2
            while i < n and code[i:i + 2] != "*/":
                out.append("\n" if code[i] == "\n" else " ")
                i += 1
            i += 2
        elif c in "\"'":
            quote = c
            out.append(c)
            i += 1
            while i < n and code[i] != quote:
                if code[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                out.append("\n" if code[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(quote)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _match_brace(s: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(s) - 1


def _param_names(param_str: str) -> List[str]:
    param_str = param_str.strip()
    if param_str in ("", "void"):
        return []
    names = []
    for part in _split_top_commas(param_str):
        part = part.strip().rstrip(")")
        # Function-pointer parameter: `void (*callback)(int)`.  The old generic
        # rightmost-identifier rule returned the nested parameter type (`int`),
        # breaking callback propagation through interprocedural points-to analysis.
        fp = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", part)
        if fp:
            names.append(fp.group(1))
            continue
        m = re.search(r"([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*$", part)
        if m and m.group(1) not in _KEYWORDS:
            names.append(m.group(1))
    return names


def _param_types(param_str: str) -> Dict[str, str]:
    """Best-effort map of parameter name to its nominal C++ class/type."""
    out: Dict[str, str] = {}
    ignored = {"const", "volatile", "unsigned", "signed", "long", "short",
               "struct", "class", "typename"}
    for raw_part in _split_top_commas(param_str):
        part = raw_part.split("=", 1)[0].strip().rstrip(")")
        fp = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", part)
        if fp:
            continue
        match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", part)
        if not match:
            continue
        name = match.group(1)
        prefix = part[:match.start()]
        candidates = [token for token in re.findall(r"[A-Za-z_]\w*", prefix)
                      if token not in ignored]
        if candidates:
            out[name] = candidates[-1]
    return out


def _param_decls(param_str: str) -> Dict[str, str]:
    """Map parameter names to their line-normalized declaration spelling."""
    out: Dict[str, str] = {}
    for raw_part in _split_top_commas(param_str):
        part = raw_part.split("=", 1)[0].strip().rstrip(")")
        fp = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", part)
        if fp:
            out[fp.group(1)] = re.sub(r"\s+", " ", part)
            continue
        match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", part)
        if match and match.group(1) not in _KEYWORDS:
            out[match.group(1)] = re.sub(r"\s+", " ", part)
    return out


def _split_top_commas(s: str) -> List[str]:
    parts, depth, cur = [], 0, []
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def _canonical_template(text: str) -> str:
    """Stable spelling for an explicit template-id without evaluating it."""
    if not text:
        return ""
    return re.sub(r"\s+", "", text)


def _builtin_constraint_satisfied(constraint: str, template_args: str) -> Optional[bool]:
    """Evaluate a small, standard-library-only concept subset without a compiler.

    Returns None for dependent/user concepts so callers retain the conservative join.
    This is deliberately not a pretend C++ template instantiator.
    """
    if not constraint or not template_args:
        return None
    actuals = _split_top_commas(template_args.strip("<>"))
    if len(actuals) != 1:
        return None
    actual = re.sub(r"\b(?:const|volatile)\b|[&\s]", "", actuals[0])
    integral = {
        "bool", "char", "signedchar", "unsignedchar", "wchar_t", "char8_t",
        "char16_t", "char32_t", "short", "shortint", "unsignedshort",
        "unsignedshortint", "int", "unsigned", "unsignedint", "long", "longint",
        "unsignedlong", "unsignedlongint", "longlong", "longlongint",
        "unsignedlonglong", "unsignedlonglongint", "size_t", "std::size_t",
        "ptrdiff_t", "std::ptrdiff_t", "int8_t", "uint8_t", "int16_t", "uint16_t",
        "int32_t", "uint32_t", "int64_t", "uint64_t"}
    floating = {"float", "double", "longdouble"}
    signed = integral - {
        "bool", "char", "unsignedchar", "wchar_t", "char8_t", "char16_t",
        "char32_t", "unsignedshort", "unsignedshortint", "unsigned", "unsignedint",
        "unsignedlong", "unsignedlongint", "unsignedlonglong",
        "unsignedlonglongint", "size_t", "std::size_t", "uint8_t", "uint16_t",
        "uint32_t", "uint64_t"}
    unsigned = integral - signed - {"char"}
    normalized = re.sub(r"\s+", "", constraint)
    checks = []
    families = (
        (r"(?:std::)?integral<[^>]+>|(?:std::)?is_integral_v<[^>]+>", actual in integral),
        (r"(?:std::)?floating_point<[^>]+>|(?:std::)?is_floating_point_v<[^>]+>", actual in floating),
        (r"(?:std::)?signed_integral<[^>]+>|(?:std::)?is_signed_v<[^>]+>", actual in signed),
        (r"(?:std::)?unsigned_integral<[^>]+>|(?:std::)?is_unsigned_v<[^>]+>", actual in unsigned),
    )
    for pattern, result in families:
        if re.search(pattern, normalized):
            checks.append(result)
    if not checks:
        return None
    if "||" in normalized:
        return any(checks)
    return all(checks)


def _scan_virtual_methods(code: str) -> Set[str]:
    """Return the set of method names declared `virtual` anywhere in *code*.

    Uses a simple regex over the stripped source; does not require class-body
    brace tracking.  The result is a conservative over-approximation: a name
    that appears as a virtual method in *any* class in the file is recorded."""
    virt: Set[str] = set()
    for m in _VIRTUAL_DECL_RE.finditer(code):
        name = m.group(1)
        if name not in _KEYWORDS:
            virt.add(name)
    return virt


def _scan_cpp_classes(code: str):
    """Return class metadata plus source spans for class bodies.

    The model deliberately records nominal inheritance and virtual/override method
    names only; it does not pretend to instantiate templates or evaluate concepts.
    """
    classes: Dict[str, Dict[str, Any]] = {}
    regions: List[Tuple[int, int, str]] = []
    pattern = re.compile(
        r"\b(?:class|struct)\s+([A-Za-z_]\w*)\s*(final\s*)?"
        r"(?:\:\s*([^\{]+))?\s*\{")
    for match in pattern.finditer(code):
        open_idx = match.end() - 1
        close_idx = _match_brace(code, open_idx)
        body = code[open_idx + 1:close_idx]
        base_text = match.group(3) or ""
        bases = []
        base_edges = []
        for base in _split_top_commas(base_text):
            tokens = [token for token in re.findall(r"[A-Za-z_]\w*", base)
                      if token not in {"public", "protected", "private", "virtual"}]
            if tokens:
                base_name = tokens[-1]
                bases.append(base_name)
                access_match = re.search(r"\b(public|protected|private)\b", base)
                base_edges.append({
                    "name": base_name,
                    "virtual": bool(re.search(r"\bvirtual\b", base)),
                    "access": access_match.group(1) if access_match else "default",
                    "ordinal": len(base_edges),
                })
        virtuals = set(_VIRTUAL_DECL_RE.findall(body))
        virtuals.update(re.findall(
            r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?override\b", body))
        methods = set(re.findall(
            r"(?:~?)([A-Za-z_]\w*)\s*\([^;{}]*\)\s*"
            r"(?:const\s*)?(?:override\s*|final\s*)?(?:=\s*0\s*)?[;{]", body))
        classes[match.group(1)] = {
            "bases": bases,
            "base_edges": base_edges,
            "virtuals": virtuals,
            "methods": methods,
            "final": bool(match.group(2)),
        }
        regions.append((match.start(), close_idx + 1, match.group(1)))
    return classes, regions


def _parse_scope_functions(code: str, start: int, end: int,
                           owner: Optional[str] = None) -> List[ParsedFunction]:
    functions: List[ParsedFunction] = []
    scope = code[start:end]
    i, boundary = 0, 0
    while i < len(scope):
        if scope[i] == "{":
            header = scope[boundary:i]
            callable_header = re.sub(
                r"\btemplate\s*<[^{};]*?>\s*", " ", header, flags=re.S)
            match = re.search(
                r"(?:(?P<qual>(?:[A-Za-z_]\w*(?:\s*<[^(){};]+>)?::)+))?"
                r"(?P<name>~?[A-Za-z_]\w*)(?P<template>\s*<[^(){};]+>)?"
                r"\s*\((?P<params>.*)\)\s*"
                r"(?:const\b\s*)?(?:(?:override|final)\b\s*|"
                r"noexcept(?:\s*\([^)]*\))?\s*)*"
                r"(?P<constraint>requires\s+[^{};]+)?$",
                callable_header, re.S)
            absolute_open = start + i
            absolute_close = _match_brace(code, absolute_open)
            if match and match.group("name") not in _KEYWORDS:
                qualifier = _canonical_template(
                    (match.group("qual") or "").rstrip(":"))
                method_owner = qualifier or owner
                simple_name = match.group("name")
                template_args = _canonical_template(match.group("template") or "")
                callable_name = simple_name + template_args
                full_name = (f"{method_owner}::{callable_name}"
                             if method_owner else callable_name)
                constraint = re.sub(
                    r"\s+", " ", (match.group("constraint") or "").strip())
                if not constraint:
                    # C++20 also permits the requires-clause immediately after the
                    # template parameter list: `template<class T> requires C<T>
                    # int f(T)`. The callable regex deliberately starts at the return
                    # type, so recover the leading clause from the skipped prefix.
                    prefix_constraint = re.search(
                        r"\brequires\s+(.+?)\s+"
                        r"[A-Za-z_:][\w:<>, ]*(?:\s*[*&]\s*)?\b" +
                        re.escape(simple_name) + r"\s*(?:<[^>]+>)?\s*\(",
                        callable_header, re.S)
                    if prefix_constraint:
                        constraint = "requires " + re.sub(
                            r"\s+", " ", prefix_constraint.group(1).strip())
                if constraint:
                    full_name += " " + constraint
                params = match.group("params")
                destructor_default_noexcept = (
                    simple_name.startswith("~")
                    and not re.search(r"\bnoexcept\s*\(\s*(?:false|0)\s*\)", header))
                functions.append(ParsedFunction(
                    full_name, _param_names(params),
                    code[absolute_open + 1:absolute_close],
                    code.count("\n", 0, absolute_open) + 1,
                    param_types=_param_types(params), owner=method_owner,
                    noexcept=_noexcept_guaranteed(header) or destructor_default_noexcept,
                    param_decls=_param_decls(params),
                    template_args=template_args, constraint=constraint,
                    template_definition=bool(re.search(r"\btemplate\s*<", header)),
                ))
            i = absolute_close - start + 1
            boundary = i
            continue
        if scope[i] == ";":
            boundary = i + 1
        i += 1
    return functions


def _scan_fp_multitargets(body: str, defined: Set[str]) -> Dict[str, List[str]]:
    """Return {fp_var: [fn1, fn2, ...]} for function-pointer variables that are
    assigned from two or more distinct known-function targets within *body*.

    This covers the if/switch pattern:
        if (cond) fp = &fn1;
        else       fp = &fn2;
        fp();   ← should resolve to {fn1, fn2}

    Conservative: lhs must NOT itself be a known function (avoids treating
    a direct-assignment `a = b` as a fp assignment)."""
    targets: Dict[str, Set[str]] = {}
    for m in _FP_ASSIGN_RE.finditer(body):
        lhs, rhs = m.group(1), m.group(2)
        if lhs in _KEYWORDS or rhs in _KEYWORDS:
            continue
        if rhs in defined and lhs not in defined:
            targets.setdefault(lhs, set()).add(rhs)
    return {k: sorted(v) for k, v in targets.items() if len(v) >= 2}


def _noexcept_guaranteed(header: str) -> bool:
    """Best-effort evaluation of a function's noexcept specification.

    Bare noexcept and literal true/1 are non-throwing contracts. Literal false/0
    and dependent expressions remain may-throw unless a compiler frontend proves
    them, which is the conservative choice for caller catch analysis.
    """
    match = re.search(r"\bnoexcept(?:\s*\(([^)]*)\))?", header)
    if not match:
        return False
    expression = match.group(1)
    if expression is None:
        return True
    return expression.strip() in {"true", "1"}


def parse_functions(code: str) -> List[ParsedFunction]:
    """Split C/C++ into free functions and qualified inline/out-of-class methods."""
    s = strip_noncode(code)
    _classes, regions = _scan_cpp_classes(s)
    funcs: List[ParsedFunction] = []
    for region_start, region_end, owner in regions:
        open_idx = s.find("{", region_start, region_end)
        if open_idx >= 0:
            funcs.extend(_parse_scope_functions(s, open_idx + 1, region_end - 1, owner))

    # Blank class definitions while preserving offsets/newlines, then parse free and
    # out-of-class definitions at file scope without descending into class bodies.
    masked = list(s)
    for region_start, region_end, _owner in regions:
        for index in range(region_start, region_end):
            if masked[index] != "\n":
                masked[index] = " "
    funcs.extend(_parse_scope_functions("".join(masked), 0, len(masked)))
    return funcs


def _extract_calls(fn: ParsedFunction, defined: Set[str], address_taken: Set[str]) -> None:
    """Populate fn.calls with (callee, args, lineno, result) — direct + indirect."""
    body = fn.body
    for m in _CALL_RE.finditer(body):
        base_name = m.group(1)
        if base_name in _KEYWORDS:
            continue
        template_args = _canonical_template(m.group(2) or "")
        name = base_name + template_args
        # arguments: from the '(' to its matching ')'
        open_paren = m.end() - 1
        depth, j = 0, open_paren
        while j < len(body):
            if body[j] == "(":
                depth += 1
            elif body[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        arg_str = body[open_paren + 1:j]
        args = [a.strip() for a in _split_top_commas(arg_str) if a.strip()]
        lineno = fn.start_line + body.count("\n", 0, m.start())
        # result variable: `lhs = name(...)` on the same statement
        pre = body[max(0, m.start() - 80):m.start()]
        rm = re.search(r"([A-Za-z_]\w*)\s*=\s*$", pre)
        result = rm.group(1) if rm else None
        receiver_match = re.search(r"([A-Za-z_]\w*)\s*(?:->|\.)\s*$", pre)
        receiver = receiver_match.group(1) if receiver_match else None
        # An unqualified call inside a class resolves to a member of that class when
        # such a definition exists in this translation unit.
        qualified = f"{fn.owner}::{name}" if fn.owner else ""
        if not receiver and qualified in defined:
            callee = qualified
        elif name in defined:
            callee = name
        elif template_args and base_name in defined:
            # Primary-template definition is the semantic fallback when no exact
            # explicit specialization is present in this analysis universe.
            callee = base_name
        elif template_args and any(
                candidate.startswith(base_name + " requires ") for candidate in defined):
            callee = base_name
        else:
            callee = name
        indirect = callee not in defined
        member_dispatch = receiver is not None
        fn.calls.append(CallSite(callee, args, lineno, result, indirect,
                                 virtual=member_dispatch, receiver=receiver,
                                 template_args=template_args))


class CallGraph:
    def __init__(self, functions: List[ParsedFunction]):
        self.functions: Dict[str, ParsedFunction] = {f.name: f for f in functions}
        self.points_to = None
        self.virtual_methods: Set[str] = set()   # populated by from_source()
        self.class_model: Dict[str, Dict[str, Any]] = {}
        self.virtual_dispatch: Dict[Tuple[str, str], List[str]] = {}
        self.virtual_dispatch_metrics = {"sites": 0, "resolved_sites": 0,
                                         "exact_dynamic_sites": 0,
                                         "cast_refined_sites": 0,
                                         "unsafe_cast_sites": 0, "targets": 0,
                                         "adjusted_receiver_sites": 0,
                                         "virtual_base_sites": 0,
                                         "ambiguous_base_sites": 0,
                                         "symbolic_adjustment_paths": 0}
        self.template_metrics = {
            "template_definitions": sum(f.template_definition for f in functions),
            "constrained_definitions": sum(bool(f.constraint) for f in functions),
            "template_call_sites": 0,
            "exact_specializations": 0,
            "primary_fallbacks": 0,
            "constraint_joins": 0,
            "constraint_proven_resolutions": 0,
            "constraint_rejections": 0,
            "compiler_proven_resolutions": 0,
        }
        self.compiler_template_resolutions: List[Dict[str, Any]] = []
        self.address_taken: Set[str] = set()
        for f in functions:
            for name in _ADDR_TAKEN_RE.findall(f.body):
                if name in self.functions:
                    self.address_taken.add(name)
        defined = set(self.functions)
        for f in functions:
            _extract_calls(f, defined, self.address_taken)
            for site in f.calls:
                if site.template_args:
                    self.template_metrics["template_call_sites"] += 1
                    exact = site.callee in defined and bool(
                        self.functions.get(site.callee)
                        and self.functions[site.callee].template_args)
                    if exact:
                        self.template_metrics["exact_specializations"] += 1
                    elif site.callee == site.callee.split("<", 1)[0]:
                        self.template_metrics["primary_fallbacks"] += 1
                if any(name.startswith(site.callee + " requires ") for name in defined):
                    self.template_metrics["constraint_joins"] += 1
                if site.template_args:
                    constrained_names = sorted(
                        name for name in defined
                        if name.startswith(site.callee.split("<", 1)[0] + " requires "))
                    verdicts = [
                        _builtin_constraint_satisfied(
                            self.functions[name].constraint, site.template_args)
                        for name in constrained_names]
                    rejected = sum(verdict is False for verdict in verdicts)
                    self.template_metrics["constraint_rejections"] += rejected
                    if any(verdict is True for verdict in verdicts) and all(
                            verdict is not None for verdict in verdicts):
                        self.template_metrics["constraint_proven_resolutions"] += 1
        # Second pass: wire fp multi-target assignments into matching call sites
        for f in functions:
            fp_multi = _scan_fp_multitargets(f.body, defined)
            if fp_multi:
                for site in f.calls:
                    if site.callee in fp_multi:
                        site.fp_targets = list(fp_multi[site.callee])

    @classmethod
    def from_source(cls, code: str) -> "CallGraph":
        cg = cls(parse_functions(code))
        # (vendored note: the platform's compiler-semantics precision tier
        #  (misra_guard.frontend.compiler_semantics) is NOT part of bts-sbom;
        #  compiler-proven template resolutions stay empty here -- honest
        #  absence, recorded in template_metrics via the same fields.)
        cg.compiler_template_resolutions = []
        cg.template_metrics["compiler_proven_resolutions"] = 0
        # __init__ only scans function bodies for &fn_name.  Functions whose
        # address is taken exclusively in global/file scope (e.g. a global
        # initialiser  `static handler_t g_h = &my_fn;`) would therefore be
        # absent from address_taken, causing indirect calls through globally-
        # assigned function pointers to resolve to the empty set.  Scanning
        # the full stripped source fixes the miss without duplicating any entry
        # already added by __init__ (Set semantics deduplicate for free).
        s = strip_noncode(code)
        for name in _ADDR_TAKEN_RE.findall(s):
            if name in cg.functions:
                cg.address_taken.add(name)
        # Populate nominal C++ class hierarchy and override-aware dispatch targets.
        cg.class_model, _regions = _scan_cpp_classes(s)
        cg.virtual_methods = _scan_virtual_methods(s)
        cg._wire_automatic_destructors()
        cg._build_virtual_dispatch()
        # Inclusion-based points-to resolution narrows indirect calls to the actual
        # assignments/callback arguments.  If this optional precision tier fails, the
        # existing address-taken/arity fallback remains sound and conservative.
        try:
            from bts_sbom._internal.points_to import PointsToAnalysis
            cg.points_to = PointsToAnalysis(s, cg.functions.values()).solve()
            for caller, fn in cg.functions.items():
                for site in fn.calls:
                    if site.indirect:
                        precise = cg.points_to.function_targets(caller, site.callee)
                        if precise:
                            site.fp_targets = precise
        except Exception:
            cg.points_to = None
        return cg

    def _wire_automatic_destructors(self) -> None:
        """Add implicit scope-exit destructor edges to the call graph.

        This makes summary order and transitive cache invalidation account for RAII
        calls that have no explicit ``~T()`` token at the call site.
        """
        destructor_by_type = {
            name.rsplit("::~", 1)[0]: name for name in self.functions
            if "::~" in name
        }
        if not destructor_by_type:
            return
        type_alt = "|".join(sorted(map(re.escape, destructor_by_type),
                                   key=len, reverse=True))
        declaration = re.compile(
            rf"\b({type_alt})\s+(?![*&])([A-Za-z_]\w*)"
            rf"\s*(?:\([^;{{}}]*\)|\{{[^;{{}}]*\}})?\s*;", re.M)
        for function in self.functions.values():
            if "::~" in function.name:
                continue
            for match in declaration.finditer(function.body):
                type_name = match.group(1)
                destructor = destructor_by_type[type_name]
                prefix = function.body[:match.start()]
                depth = prefix.count("{") - prefix.count("}")
                line = function.start_line + prefix.count("\n")
                guaranteed = depth == 0
                function.automatic_destructors.append((destructor, line, guaranteed))
                function.calls.append(CallSite(destructor, [], line, indirect=False))

    def _ancestors(self, class_name: str) -> List[str]:
        out: List[str] = []
        queue = list(self.class_model.get(class_name, {}).get("bases", []))
        while queue:
            base = queue.pop(0)
            if base in out:
                continue
            out.append(base)
            queue.extend(self.class_model.get(base, {}).get("bases", []))
        return out

    def _descendants(self, class_name: str) -> List[str]:
        out = []
        for candidate in self.class_model:
            if candidate == class_name or class_name in self._ancestors(candidate):
                out.append(candidate)
        return sorted(out)

    def _inheritance_paths(self, derived: str, base: str):
        """All bounded symbolic derived-to-base paths, including ABI edge facts."""
        if derived == base:
            return [[]]
        paths = []
        stack = [(derived, [], {derived})]
        while stack:
            current, path, seen = stack.pop()
            for edge in self.class_model.get(current, {}).get("base_edges", []):
                target = edge["name"]
                next_path = path + [(current, edge)]
                if target == base:
                    paths.append(next_path)
                elif target not in seen and len(next_path) <= len(self.class_model):
                    stack.append((target, next_path, seen | {target}))
        return paths

    def _receiver_adjustment(self, concrete: str, static_type: str):
        paths = self._inheritance_paths(concrete, static_type)
        if not paths or paths == [[]]:
            return [], False, False
        virtual = any(any(edge["virtual"] for _owner, edge in path) for path in paths)
        # Multiple non-virtual paths denote distinct base subobjects and therefore
        # an ambiguous conversion. Repeated paths through a virtual base coalesce.
        ambiguous = len(paths) > 1 and not virtual
        descriptions = []
        for path in paths:
            requires_adjustment = any(
                edge["virtual"] or int(edge["ordinal"]) > 0
                for _owner, edge in path)
            if not requires_adjustment:
                continue
            pieces = []
            for owner, edge in path:
                marker = "virtual" if edge["virtual"] else f"base#{edge['ordinal']}"
                pieces.append(f"{owner}->{edge['name']}[{marker}]")
            descriptions.append("/".join(pieces))
        return sorted(set(descriptions)), virtual, ambiguous

    def _method_is_virtual(self, class_name: str, method: str) -> bool:
        for candidate in [class_name] + self._ancestors(class_name):
            if method in self.class_model.get(candidate, {}).get("virtuals", set()):
                return True
        return False

    def _implementation(self, class_name: str, method: str) -> Optional[str]:
        for candidate in [class_name] + self._ancestors(class_name):
            qualified = f"{candidate}::{method}"
            if qualified in self.functions:
                return qualified
        return None

    def _receiver_types(self, fn: ParsedFunction):
        static: Dict[str, str] = {
            name: type_name for name, type_name in fn.param_types.items()
            if type_name in self.class_model
        }
        dynamic: Dict[str, Set[str]] = {}
        cast_refined: Set[str] = set()
        unsafe_cast: Set[str] = set()
        if fn.owner in self.class_model:
            static["this"] = fn.owner
            if self.class_model[fn.owner].get("final"):
                dynamic["this"] = {fn.owner}
        if not self.class_model:
            return static, dynamic, cast_refined, unsafe_cast
        class_alt = "|".join(sorted(map(re.escape, self.class_model), key=len, reverse=True))
        objects: Dict[str, str] = {}
        for match in re.finditer(
                rf"\b({class_alt})\s*(\*|&)?\s*([A-Za-z_]\w*)\b", fn.body):
            type_name, indirection, variable = match.groups()
            static[variable] = type_name
            if not indirection:
                objects[variable] = type_name
                dynamic.setdefault(variable, set()).add(type_name)
        for match in re.finditer(
                rf"\b({class_alt})\s*\*\s*([A-Za-z_]\w*)\s*=\s*new\s+({class_alt})\b",
                fn.body):
            base, variable, concrete = match.groups()
            static[variable] = base
            if concrete == base or base in self._ancestors(concrete):
                dynamic.setdefault(variable, set()).add(concrete)
        for match in re.finditer(
                rf"\b({class_alt})\s*\*\s*([A-Za-z_]\w*)\s*=\s*&\s*([A-Za-z_]\w*)\b",
                fn.body):
            base, variable, obj = match.groups()
            static[variable] = base
            concrete = objects.get(obj)
            if concrete and (concrete == base or base in self._ancestors(concrete)):
                dynamic.setdefault(variable, set()).add(concrete)
        safe_cast = re.compile(
            rf"(?:\b(?:{class_alt}|auto)\s*\*?\s*)?\b([A-Za-z_]\w*)\s*=\s*"
            rf"(dynamic_cast|static_cast)\s*<\s*({class_alt})\s*\*\s*>\s*"
            rf"\(\s*([A-Za-z_]\w*)")
        for match in safe_cast.finditer(fn.body):
            variable, _kind, target, source = match.groups()
            source_type = static.get(source)
            common_dynamic = (set(self._descendants(source_type)) &
                              set(self._descendants(target))) if source_type else set()
            compatible = (source_type is None or target == source_type
                          or source_type in self._ancestors(target)
                          or target in self._ancestors(source_type)
                          or bool(common_dynamic))
            if compatible:
                static[variable] = target
                source_dynamic = dynamic.get(source, set())
                refined_dynamic = {
                    concrete for concrete in source_dynamic
                    if concrete == target or target in self._ancestors(concrete)
                }
                if refined_dynamic:
                    dynamic[variable] = refined_dynamic
                else:
                    dynamic.pop(variable, None)
                cast_refined.add(variable)
        c_style_cast = re.compile(
            rf"\b([A-Za-z_]\w*)\s*=\s*\(\s*({class_alt})\s*\*\s*\)\s*"
            rf"([A-Za-z_]\w*)")
        for match in c_style_cast.finditer(fn.body):
            variable, target, source = match.groups()
            source_type = static.get(source)
            common_dynamic = (set(self._descendants(source_type)) &
                              set(self._descendants(target))) if source_type else set()
            if source_type and (target == source_type
                                or source_type in self._ancestors(target)
                                or target in self._ancestors(source_type)
                                or bool(common_dynamic)):
                static[variable] = target
                source_dynamic = dynamic.get(source, set())
                refined_dynamic = {
                    concrete for concrete in source_dynamic
                    if concrete == target or target in self._ancestors(concrete)
                }
                if refined_dynamic:
                    dynamic[variable] = refined_dynamic
                else:
                    dynamic.pop(variable, None)
                cast_refined.add(variable)
        reinterpret = re.compile(
            rf"(?:\b(?:{class_alt}|auto)\s*\*?\s*)?\b([A-Za-z_]\w*)\s*=\s*"
            rf"reinterpret_cast\s*<\s*(?:{class_alt})\s*\*\s*>\s*"
            rf"\(\s*([A-Za-z_]\w*)")
        for match in reinterpret.finditer(fn.body):
            variable, source = match.groups()
            source_type = static.get(source)
            if source_type:
                static[variable] = source_type
            else:
                static.pop(variable, None)
            dynamic.pop(variable, None)
            cast_refined.discard(variable)
            unsafe_cast.add(variable)
        return static, dynamic, cast_refined, unsafe_cast

    def _build_virtual_dispatch(self) -> None:
        aggregate: Dict[Tuple[str, str], Set[str]] = {}
        metrics = {"sites": 0, "resolved_sites": 0,
                   "exact_dynamic_sites": 0, "cast_refined_sites": 0,
                   "unsafe_cast_sites": 0, "targets": 0,
                   "adjusted_receiver_sites": 0, "virtual_base_sites": 0,
                   "ambiguous_base_sites": 0, "symbolic_adjustment_paths": 0}
        for caller, fn in self.functions.items():
            static_types, dynamic_types, cast_refined, unsafe_cast = self._receiver_types(fn)
            for site in fn.calls:
                receiver = getattr(site, "receiver", None)
                if not receiver:
                    continue
                metrics["sites"] += 1
                static_type = static_types.get(receiver)
                concrete_types = dynamic_types.get(receiver, set())
                if concrete_types:
                    candidates = sorted(concrete_types)
                    metrics["exact_dynamic_sites"] += 1
                elif static_type:
                    candidates = (self._descendants(static_type)
                                  if self._method_is_virtual(static_type, site.callee)
                                  else [static_type])
                else:
                    candidates = []
                if receiver in cast_refined:
                    metrics["cast_refined_sites"] += 1
                if receiver in unsafe_cast:
                    metrics["unsafe_cast_sites"] += 1
                adjustments = []
                has_virtual_base = False
                has_ambiguous_base = False
                if static_type:
                    for concrete in candidates:
                        paths, virtual_base, ambiguous_base = self._receiver_adjustment(
                            concrete, static_type)
                        adjustments.extend(paths)
                        has_virtual_base = has_virtual_base or virtual_base
                        has_ambiguous_base = has_ambiguous_base or ambiguous_base
                site.receiver_adjustment = sorted(set(adjustments))
                if site.receiver_adjustment:
                    metrics["adjusted_receiver_sites"] += 1
                    metrics["symbolic_adjustment_paths"] += len(site.receiver_adjustment)
                if has_virtual_base:
                    metrics["virtual_base_sites"] += 1
                if has_ambiguous_base:
                    metrics["ambiguous_base_sites"] += 1
                targets = sorted({implementation for candidate in candidates
                                  if (implementation := self._implementation(
                                      candidate, site.callee)) is not None})
                if targets:
                    site.dispatch_targets = targets
                    aggregate.setdefault((caller, site.callee), set()).update(targets)
                    metrics["resolved_sites"] += 1
                    metrics["targets"] += len(targets)
        self.virtual_dispatch = {key: sorted(value) for key, value in aggregate.items()}
        self.virtual_dispatch_metrics = metrics

    def callees(self, name: str) -> List[CallSite]:
        f = self.functions.get(name)
        return list(f.calls) if f else []

    def resolve(self, site: CallSite) -> List[str]:
        """Direct target if defined; else conservative over-approximation.
        Priority order:
          1. Pre-resolved fp multi-target: fp variable assigned to multiple
             known functions via if/switch branches → all assigned targets.
          2. Virtual method dispatch (ptr->method()): all functions in the
             call graph whose unqualified or qualified name matches the
             virtual method (conservative over-approximation).
          3. Generic indirect call: all address-taken functions of matching arity."""
        template_base = site.callee.split("<", 1)[0]
        exact_template = bool(getattr(site, "template_args", "")) or "<" in site.callee
        compiler_proofs = [
            proof for proof in self.compiler_template_resolutions
            if int(proof.get("call_line", -1)) == int(getattr(site, "lineno", -2))
            and str(proof.get("callee") or "") == template_base]
        if compiler_proofs:
            definition_line = int(compiler_proofs[0]["selected_definition_line"])
            candidates = [name for name, function in self.functions.items()
                          if (name == template_base or
                              name.startswith(template_base + " requires "))]
            if candidates:
                distance = min(abs(self.functions[name].start_line - definition_line)
                               for name in candidates)
                selected = sorted(name for name in candidates
                                  if abs(self.functions[name].start_line -
                                         definition_line) == distance)
                if selected:
                    return [selected[0]]
        constrained_base = template_base if exact_template else site.callee
        constrained = sorted(
            name for name in self.functions
            if name.startswith(constrained_base + " requires "))
        if exact_template and site.callee in self.functions:
            return [site.callee]
        if constrained and exact_template:
            proven, unknown = [], []
            for candidate in constrained:
                verdict = _builtin_constraint_satisfied(
                    self.functions[candidate].constraint,
                    getattr(site, "template_args", "") or
                    ("<" + site.callee.split("<", 1)[1]
                     if "<" in site.callee else ""))
                if verdict is True:
                    proven.append(candidate)
                elif verdict is None:
                    unknown.append(candidate)
            if proven and not unknown:
                return proven
            if proven or unknown:
                return proven + unknown
            if template_base in self.functions:
                return [template_base]
            return []
        if exact_template and template_base in self.functions:
            return [template_base]
        if constrained and "<" not in site.callee:
            candidates = ([site.callee] if site.callee in self.functions else []) + constrained
            return candidates
        if site.callee in self.functions:
            return [site.callee]
        dispatch_targets = getattr(site, "dispatch_targets", None)
        if dispatch_targets:
            return list(dispatch_targets)
        caller = getattr(site, "caller", None)
        if caller:
            resolved_dispatch = self.virtual_dispatch.get((caller, site.callee), [])
            if resolved_dispatch:
                return list(resolved_dispatch)
        # (1) fp variable with multiple known-function assignments
        # Use getattr so that legacy duck-typed _FakeSite callers remain compatible
        fp_targets = getattr(site, "fp_targets", None)
        if fp_targets:
            return list(fp_targets)
        if caller and self.points_to is not None:
            precise = self.points_to.function_targets(caller, site.callee)
            if precise:
                return precise
        # (2) virtual method dispatch via ptr->method()
        if getattr(site, "virtual", False) and site.callee in self.virtual_methods:
            candidates = sorted(
                fn for fn in self.functions
                if fn == site.callee
                or fn.endswith("::" + site.callee)
                or fn.endswith("_" + site.callee)
            )
            if candidates:
                return candidates
        if not site.indirect:
            return []
        # (3) generic function-pointer: all address-taken functions of matching arity
        arity = len(site.args)
        return sorted(fn for fn in self.address_taken
                      if len(self.functions[fn].params) == arity)

    def _unique_callees(self, name: str) -> List[str]:
        """Deduplicated list of resolved callee names for function `name`."""
        seen: Set[str] = set()
        out: List[str] = []
        for site in self.functions[name].calls:
            for tgt in self.resolve(site):
                if tgt not in seen:
                    seen.add(tgt)
                    out.append(tgt)
        return out

    def reverse_topo(self) -> List[str]:
        """Bottom-up order (callees before callers) for summary computation.
        Cycles (recursion) are broken deterministically; the engine re-iterates to a
        fixpoint over SCCs.

        Uses an iterative post-order DFS so that deeply-recursive or mutually-recursive
        call graphs never hit Python's default recursion limit."""
        WHITE, GREY, BLACK = 0, 1, 2
        color = {n: WHITE for n in self.functions}
        visited: Set[str] = set()   # explicit guard against mutual-recursion re-entry
        order: List[str] = []

        for start in self.functions:
            if color[start] != WHITE:
                continue
            # Stack frames: (node, iterator-over-remaining-callees).
            # A node is appended to `order` (post-order) when its iterator is exhausted.
            color[start] = GREY
            visited.add(start)
            stack: List[Tuple[str, Any]] = [
                (start, iter(self._unique_callees(start)))
            ]
            while stack:
                node, children = stack[-1]
                try:
                    child = next(children)
                    if child not in visited and color.get(child) == WHITE:
                        visited.add(child)
                        color[child] = GREY
                        stack.append((child, iter(self._unique_callees(child))))
                    # GREY/visited → back-edge (mutual recursion A→B→A): skip.
                    # BLACK → already ordered: skip.
                except StopIteration:
                    color[node] = BLACK
                    order.append(node)
                    stack.pop()

        return order      # callees-before-callers

    def sccs(self) -> List[List[str]]:
        """Tarjan SCCs — recursion / mutual-recursion clusters.

        Iterative implementation of Tarjan's algorithm to avoid Python's recursion
        limit on programs with deep or mutually-recursive call graphs."""
        index_map: Dict[str, int] = {}
        low: Dict[str, int] = {}
        on_stack: Set[str] = set()
        tarjan_stack: List[str] = []
        result: List[List[str]] = []
        counter = [0]

        for start in self.functions:
            if start in index_map:
                continue

            # Each call-stack frame: (node, iterator-over-successors).
            # After StopIteration we propagate low-link to parent and check SCC root.
            call_stack: List[Tuple[str, Any]] = []

            def _push(v: str) -> None:
                index_map[v] = low[v] = counter[0]
                counter[0] += 1
                tarjan_stack.append(v)
                on_stack.add(v)
                succs = [w for site in self.functions[v].calls
                         for w in self.resolve(site) if w in self.functions]
                call_stack.append((v, iter(succs)))

            _push(start)

            while call_stack:
                v, succs_it = call_stack[-1]
                try:
                    w = next(succs_it)
                    if w not in index_map:
                        # Tree edge: recurse into w.
                        _push(w)
                    elif w in on_stack:
                        # Back edge: update low-link using w's discovery index.
                        low[v] = min(low[v], index_map[w])
                    # Cross edge to a completed SCC: no low-link update.
                except StopIteration:
                    # All successors of v processed; propagate low-link to parent.
                    call_stack.pop()
                    if call_stack:
                        parent = call_stack[-1][0]
                        low[parent] = min(low[parent], low[v])
                    # v is an SCC root when its low-link equals its own discovery index.
                    if low[v] == index_map[v]:
                        comp: List[str] = []
                        while True:
                            w = tarjan_stack.pop()
                            on_stack.discard(w)
                            comp.append(w)
                            if w == v:
                                break
                        result.append(comp)

        return result
