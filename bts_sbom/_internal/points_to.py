# vendored from misra_guard/dataflow/points_to.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""Inclusion-based points-to analysis for C/C++ pointer and callback resolution.

The sound may-points-to tier is deliberately flow-insensitive and monotone: address,
copy, load and store constraints iterate to a fixed point.  A second precision tier
tracks pointer-offset ranges and a sequential final-state view.  Strong updates are
only used there for singleton non-heap objects, so they never erase targets from the
conservative may-alias result used by the call graph.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import DefaultDict, Dict, Iterable, List, Optional, Set, Tuple


_ASSIGN_RE = re.compile(r"(?<![=!<>])=(?!=)")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_CAST_RE = re.compile(r"^\s*\([^()]*(?:\*|\bconst\b|\bvolatile\b)[^()]*\)\s*")


@dataclass
class PointsToResult:
    points: DefaultDict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    copies: List[Tuple[str, str]] = field(default_factory=list)
    offset_adjustments: List[Tuple[str, str, Optional[int]]] = field(default_factory=list)
    offsets: DefaultDict[str, Dict[str, Tuple[Optional[int], Optional[int]]]] = field(
        default_factory=lambda: defaultdict(dict))
    object_extents: Dict[str, int] = field(default_factory=dict)
    union_objects: Set[str] = field(default_factory=set)
    flow_events: List[Dict[str, object]] = field(default_factory=list)
    flow_points: DefaultDict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    flow_memory: DefaultDict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    flow_strong_updates: int = 0
    flow_weak_updates: int = 0
    loads: List[Tuple[str, str, Optional[str], bool]] = field(default_factory=list)
    stores: List[Tuple[str, str, Optional[str], bool]] = field(default_factory=list)
    strong_store_indices: Set[int] = field(default_factory=set)
    final_memory: DefaultDict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    strong_updates: int = 0
    weak_updates: int = 0
    iterations: int = 0
    # Allocation-site heap graph: source abstract object -> field -> target objects.
    # Cyclic SCCs summarize recursive lists/trees/graphs without unbounded unrolling.
    heap_shape_edges: DefaultDict[str, DefaultDict[str, Set[str]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(set)))
    recursive_heap_components: List[Set[str]] = field(default_factory=list)

    def targets(self, symbol: str) -> Set[str]:
        return set(self.points.get(symbol, set()))

    def flow_targets(self, symbol: str) -> Set[str]:
        """Latest sequential state when available, else the conservative may-set."""
        return set(self.flow_points.get(symbol, self.points.get(symbol, set())))

    def aliases(self, left: str, right: str) -> bool:
        return bool(self.targets(left) & self.targets(right))

    def offset_range(self, symbol: str, target: Optional[str] = None
                     ) -> Tuple[Optional[int], Optional[int]]:
        """Return the inclusive element-offset range, or unknown bounds."""
        ranges = self.offsets.get(symbol, {})
        selected = [ranges[target]] if target in ranges else (
            list(ranges.values()) if target is None else [])
        if not selected or any(lo is None or hi is None for lo, hi in selected):
            return None, None
        return min(lo for lo, _hi in selected), max(hi for _lo, hi in selected)

    def must_alias(self, left: str, right: str) -> bool:
        """True only when both symbols denote one identical base and exact offset."""
        left_targets, right_targets = self.targets(left), self.targets(right)
        if len(left_targets) != 1 or left_targets != right_targets:
            return False
        target = next(iter(left_targets))
        left_range = self.offset_range(left, target)
        right_range = self.offset_range(right, target)
        return (left_range[0] is not None and left_range[0] == left_range[1]
                and left_range == right_range)

    def may_overlap(self, left: str, right: str, left_width: int = 1,
                    right_width: int = 1) -> bool:
        """Conservative range-overlap query for pointers sharing a base object."""
        for target in self.targets(left) & self.targets(right):
            llo, lhi = self.offset_range(left, target)
            rlo, rhi = self.offset_range(right, target)
            if None in (llo, lhi, rlo, rhi):
                return True
            if llo <= rhi + max(1, right_width) - 1 and rlo <= lhi + max(1, left_width) - 1:
                return True
        return False

    def final_pointee_targets(self, pointer: str,
                              field_name: Optional[str] = None) -> Set[str]:
        """Targets stored in the sequential final-state view of ``*pointer``."""
        out: Set[str] = set()
        for target in self.targets(pointer):
            key = PointsToAnalysis._memory_key(target, field_name, self.union_objects)
            if key in self.final_memory:
                out.update(self.final_memory[key])
            else:
                out.update(self.points.get(key, set()))
                if field_name is None and target.startswith("object:"):
                    out.update(self.points.get(target[len("object:"):], set()))
        return out

    def flow_pointee_targets(self, pointer: str,
                             field_name: Optional[str] = None) -> Set[str]:
        out: Set[str] = set()
        for target in self.flow_targets(pointer):
            key = PointsToAnalysis._memory_key(target, field_name, self.union_objects)
            out.update(self.flow_memory.get(key, self.final_memory.get(key, set())))
        return out

    def shape_reachable(self, pointer: str, max_depth: int = 16,
                        fields: Optional[Iterable[str]] = None) -> Set[str]:
        """Return abstract objects reachable through heap fields.

        Allocation sites, rather than concrete runtime nodes, are the finite shape
        domain. Cycles therefore converge naturally and ``max_depth`` is only a
        defensive query bound, not an analysis-unrolling limit.
        """
        allowed = set(fields) if fields is not None else None
        roots = self.targets(pointer)
        reached = set(roots)
        frontier = set(roots)
        for _depth in range(max(0, max_depth)):
            following: Set[str] = set()
            for source in frontier:
                for field_name, targets in self.heap_shape_edges.get(source, {}).items():
                    if allowed is None or field_name in allowed:
                        following.update(targets)
            following -= reached
            if not following:
                break
            reached.update(following)
            frontier = following
        return reached

    def is_recursive_shape(self, pointer: str) -> bool:
        reachable = self.shape_reachable(pointer)
        return any(bool(component & reachable)
                   for component in self.recursive_heap_components)

    def function_targets(self, function: str, variable: str) -> List[str]:
        prefix = "function:"
        return sorted(target[len(prefix):] for target in
                      self.points.get(f"{function}::{variable}", set())
                      if target.startswith(prefix))

    def constraint_summary(self) -> Dict[str, int]:
        return {"symbols": len(self.points), "copy": len(self.copies),
                "load": len(self.loads), "store": len(self.stores),
                "offset": len(self.offset_adjustments),
                "strong_updates": self.strong_updates,
                "weak_updates": self.weak_updates,
                "objects_with_extent": len(self.object_extents),
                "union_objects": len(self.union_objects),
                "flow_events": len(self.flow_events),
                "flow_strong_updates": self.flow_strong_updates,
                "flow_weak_updates": self.flow_weak_updates,
                "heap_shape_edges": sum(
                    len(targets) for fields in self.heap_shape_edges.values()
                    for targets in fields.values()),
                "recursive_heap_components": len(self.recursive_heap_components),
                "iterations": self.iterations}


class PointsToAnalysis:
    def __init__(self, code: str, functions: Iterable[object]):
        self.code = code
        self.functions = list(functions)
        self.defined = {str(getattr(fn, "name")) for fn in self.functions}
        self.result = PointsToResult()
        self._locals: Dict[str, Set[str]] = {}
        self._union_types: Set[str] = set(re.findall(
            r"\bunion\s+([A-Za-z_]\w*)\s*\{", code))

    @staticmethod
    def _lhs_name(text: str) -> Optional[str]:
        function_pointer = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", text)
        if function_pointer:
            return function_pointer.group(1)
        names = _IDENT_RE.findall(text)
        return names[-1] if names else None

    @staticmethod
    def _lhs_constraint(text: str) -> Tuple[str, Optional[str], Optional[str], bool]:
        raw = text.strip()
        function_pointer = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", raw)
        if function_pointer:
            return "direct", function_pointer.group(1), None, False
        field = re.search(r"([A-Za-z_]\w*)\s*(->|\.)\s*([A-Za-z_]\w*)\s*$", raw)
        if field:
            return "field", field.group(1), field.group(3), field.group(2) == "."
        deref = re.search(r"\*\s*([A-Za-z_]\w*)\s*$", raw)
        if deref:
            # `int *p` / `Type **slot` are declarations, whereas `*p` is a store.
            # Any declarator/type text before the matched star makes this a direct lhs.
            if raw[:deref.start()].strip():
                return "direct", deref.group(1), None, False
            return "deref", deref.group(1), None, False
        return "direct", PointsToAnalysis._lhs_name(raw), None, False

    @staticmethod
    def _clean_rhs(text: str) -> str:
        rhs = text.strip().rstrip(";").strip()
        while True:
            stripped = _CAST_RE.sub("", rhs, count=1)
            if stripped == rhs:
                return rhs
            rhs = stripped.strip()

    @staticmethod
    def _simple_rhs(text: str) -> Optional[Tuple[str, bool]]:
        rhs = PointsToAnalysis._clean_rhs(text)
        match = re.fullmatch(r"(&)?\s*([A-Za-z_]\w*)", rhs)
        return (match.group(2), bool(match.group(1))) if match else None

    @staticmethod
    def _rhs_memory(text: str) -> Optional[Tuple[str, Optional[str], bool]]:
        rhs = PointsToAnalysis._clean_rhs(text)
        field = re.fullmatch(r"([A-Za-z_]\w*)\s*(->|\.)\s*([A-Za-z_]\w*)", rhs)
        if field:
            return field.group(1), field.group(3), field.group(2) == "."
        deref = re.fullmatch(r"\*\s*([A-Za-z_]\w*)", rhs)
        return (deref.group(1), None, False) if deref else None

    @staticmethod
    def _rhs_pointer_base(text: str) -> Optional[Tuple[str, Optional[int]]]:
        rhs = PointsToAnalysis._clean_rhs(text)
        match = re.fullmatch(r"([A-Za-z_]\w*)\s*([+-])\s*(\d+|[A-Za-z_]\w*)", rhs)
        if not match:
            return None
        delta = None
        if match.group(3).isdigit():
            delta = int(match.group(3)) * (1 if match.group(2) == "+" else -1)
        return match.group(1), delta

    @staticmethod
    def _allocator(text: str) -> Optional[Tuple[str, Optional[int]]]:
        rhs = PointsToAnalysis._clean_rhs(text)
        match = re.match(r"(malloc|realloc)\s*\(\s*(?:[^,]+,\s*)?(\d+)\s*\)", rhs)
        if match:
            return match.group(1), int(match.group(2))
        match = re.match(r"calloc\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)", rhs)
        if match:
            return "calloc", int(match.group(1)) * int(match.group(2))
        match = re.match(r"new\s+[^\[]+\[\s*(\d+)\s*\]", rhs)
        if match:
            return "new[]", int(match.group(1))
        if re.match(r"(?:malloc|calloc|realloc)\s*\(|new\b", rhs):
            name = re.match(r"([A-Za-z_]\w*)", rhs)
            return (name.group(1) if name else "new"), None
        return None

    @staticmethod
    def _statements(body: str) -> Iterable[str]:
        return (statement for statement, _controlled in
                PointsToAnalysis._statements_with_context(body))

    @staticmethod
    def _statements_with_context(body: str) -> Iterable[Tuple[str, bool]]:
        """Yield statements and whether they are governed by branch/loop control."""
        control = re.compile(r"\b(?:if|else|for|while|switch|do)\b")
        stack: List[bool] = []
        current: List[str] = []
        paren_depth = 0
        for char in body:
            if char == "(":
                paren_depth += 1
            elif char == ")":
                paren_depth = max(0, paren_depth - 1)
            if char == "{" and paren_depth == 0:
                header = "".join(current)
                stack.append((stack[-1] if stack else False) or bool(control.search(header)))
                current = []
            elif char == "}" and paren_depth == 0:
                statement = "".join(current).strip()
                if statement:
                    yield statement, (stack[-1] if stack else False)
                current = []
                if stack:
                    stack.pop()
            elif char == ";" and paren_depth == 0:
                statement = "".join(current).strip()
                if statement:
                    governed = (stack[-1] if stack else False) or bool(control.search(statement))
                    yield statement, governed
                current = []
            else:
                current.append(char)
        statement = "".join(current).strip()
        if statement:
            yield statement, (stack[-1] if stack else False) or bool(control.search(statement))

    def _symbol(self, function: str, name: str) -> str:
        if name in self._locals.get(function, set()):
            return f"{function}::{name}"
        return f"global::{name}"

    def _add_target(self, symbol: str, target: str,
                    bounds: Tuple[Optional[int], Optional[int]] = (0, 0)) -> None:
        self.result.points[symbol].add(target)
        self._merge_offset(symbol, target, bounds)

    def _merge_offset(self, symbol: str, target: str,
                      bounds: Tuple[Optional[int], Optional[int]]) -> bool:
        current = self.result.offsets[symbol].get(target)
        if current is None:
            self.result.offsets[symbol][target] = bounds
            return True
        if current == (None, None) or bounds == (None, None):
            joined = (None, None)
        else:
            joined = (min(current[0], bounds[0]), max(current[1], bounds[1]))
        if joined != current:
            self.result.offsets[symbol][target] = joined
            return True
        return False

    def _add_assignment(self, function: str, lhs: str, rhs: str,
                        addressed: bool = False) -> None:
        dst = self._symbol(function, lhs)
        if rhs in self.defined:
            self._add_target(dst, f"function:{rhs}")
        elif addressed:
            self._add_target(dst, f"object:{self._symbol(function, rhs)}")
        else:
            src = self._symbol(function, rhs)
            self.result.copies.append((dst, src))
            self.result.offset_adjustments.append((dst, src, 0))

    def _source_symbol(self, function: str, rhs: str,
                       addressed: bool = False) -> str:
        if rhs in self.defined:
            symbol = f"constant::{rhs}"
            self._add_target(symbol, f"function:{rhs}")
            return symbol
        if addressed:
            symbol = f"address::{function}::{rhs}"
            self._add_target(symbol, f"object:{self._symbol(function, rhs)}")
            return symbol
        return self._symbol(function, rhs)

    @staticmethod
    def _memory_key(target: str, field_name: Optional[str],
                    union_objects: Optional[Set[str]] = None) -> str:
        if field_name and union_objects and target in union_objects:
            field_name = "$union"
        return f"memory:{target}" + (f".{field_name}" if field_name else "")

    def _collect_union_objects(self, function: str, body: str) -> None:
        if not self._union_types:
            return
        alternatives = "|".join(sorted(map(re.escape, self._union_types),
                                         key=len, reverse=True))
        declaration = re.compile(
            rf"\b(?:union\s+)?({alternatives})\s+(?:[*&]\s*)?([A-Za-z_]\w*)\b")
        for match in declaration.finditer(body):
            _type_name, variable = match.groups()
            # Pointer/reference declarations denote another object; only concrete
            # union variables own the overlapping storage cell.
            between = body[match.start():match.end()]
            if "*" in between or "&" in between:
                continue
            self.result.union_objects.add(
                f"object:{self._symbol(function, variable)}")

    @staticmethod
    def _declared_locals(statement: str) -> Set[str]:
        """Best-effort names from a declaration without confusing call expressions."""
        text = statement.strip()
        if not text or "(" in text or "->" in text or "." in text:
            return set()
        match = re.match(
            r"^(?:(?:const|volatile|static|register|extern|mutable)\s+)*"
            r"(?:(?:struct|union|enum|class)\s+)?[A-Za-z_]\w*"
            r"(?:(?:::)[A-Za-z_]\w*)*(?:\s*<[^;{}]+>)?\s+(.+)$", text)
        if not match or match.group(1).lstrip().startswith(
                ("+", "-", "/", "%", "=", "!", "<", ">", "|", "^")):
            return set()
        out: Set[str] = set()
        for declarator in match.group(1).split(","):
            declarator = declarator.split("=", 1)[0].strip()
            name = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^]]*\])?\s*$", declarator)
            if name:
                out.add(name.group(1))
        return out

    def collect(self) -> PointsToResult:
        # First pass establishes each function's local namespace so references to a
        # global callback are not accidentally rewritten as locals.
        for fn in self.functions:
            name = str(getattr(fn, "name"))
            local = set(getattr(fn, "params", []) or [])
            for statement in self._statements(str(getattr(fn, "body", ""))):
                local.update(self._declared_locals(statement))
                parts = _ASSIGN_RE.split(statement, maxsplit=1)
                if len(parts) == 2:
                    kind, lhs, _field, _direct = self._lhs_constraint(parts[0])
                    if lhs and kind == "direct":
                        local.add(lhs)
            self._locals[name] = local
            self._collect_union_objects(name, str(getattr(fn, "body", "")))

        for fn in self.functions:
            caller = str(getattr(fn, "name"))
            for statement_index, (statement, controlled) in enumerate(
                    self._statements_with_context(str(getattr(fn, "body", ""))), start=1):
                parts = _ASSIGN_RE.split(statement, maxsplit=1)
                if len(parts) != 2:
                    continue
                kind, lhs, field_name, direct_object = self._lhs_constraint(parts[0])
                if not lhs:
                    continue
                dst = self._symbol(caller, lhs)
                rhs_memory = self._rhs_memory(parts[1])
                allocator = self._allocator(parts[1])
                pointer_base = self._rhs_pointer_base(parts[1])
                rhs_atom = self._simple_rhs(parts[1])
                if kind == "direct" and allocator:
                    allocator_name, extent = allocator
                    target_name = f"heap:{caller}:{statement_index}:{allocator_name}"
                    self._add_target(dst, target_name)
                    self.result.flow_events.append({
                        "kind": "assign_targets", "function": caller, "dst": dst,
                        "targets": {target_name}, "controlled": controlled})
                    if extent is not None:
                        self.result.object_extents[target_name] = extent
                elif kind == "direct" and rhs_memory:
                    base, rhs_field, rhs_direct = rhs_memory
                    pointer_symbol = self._symbol(caller, base)
                    self.result.loads.append(
                        (dst, pointer_symbol, rhs_field, rhs_direct))
                    self.result.flow_events.append({
                        "kind": "load", "function": caller, "dst": dst, "pointer": pointer_symbol,
                        "field": rhs_field, "direct": rhs_direct,
                        "controlled": controlled})
                elif kind == "direct" and pointer_base:
                    base, delta = pointer_base
                    src = self._symbol(caller, base)
                    self.result.copies.append((dst, src))
                    self.result.offset_adjustments.append((dst, src, delta))
                    self.result.flow_events.append({
                        "kind": "copy", "function": caller, "dst": dst, "src": src,
                        "controlled": controlled})
                elif kind == "direct" and rhs_atom:
                    self._add_assignment(caller, lhs, rhs_atom[0], rhs_atom[1])
                    rhs_name, addressed = rhs_atom
                    if rhs_name in self.defined:
                        self.result.flow_events.append({
                            "kind": "assign_targets", "function": caller, "dst": dst,
                            "targets": {f"function:{rhs_name}"},
                            "controlled": controlled})
                    elif addressed:
                        self.result.flow_events.append({
                            "kind": "assign_targets", "function": caller, "dst": dst,
                            "targets": {f"object:{self._symbol(caller, rhs_name)}"},
                            "controlled": controlled})
                    else:
                        self.result.flow_events.append({
                            "kind": "copy", "function": caller, "dst": dst,
                            "src": self._symbol(caller, rhs_name),
                            "controlled": controlled})
                elif kind in {"deref", "field"} and rhs_atom:
                    src = self._source_symbol(caller, rhs_atom[0], rhs_atom[1])
                    store_index = len(self.result.stores)
                    self.result.stores.append(
                        (self._symbol(caller, lhs), src,
                         field_name if kind == "field" else None, direct_object))
                    self.result.flow_events.append({
                        "kind": "store", "function": caller,
                        "pointer": self._symbol(caller, lhs),
                        "src": src, "field": field_name if kind == "field" else None,
                        "direct": direct_object, "controlled": controlled})
                    if not controlled:
                        self.result.strong_store_indices.add(store_index)

            # Propagate function-pointer actual arguments into direct callee params.
            for site in getattr(fn, "calls", []) or []:
                callee = str(getattr(site, "callee", ""))
                target = next((f for f in self.functions
                               if str(getattr(f, "name")) == callee), None)
                if target is None:
                    continue
                params = list(getattr(target, "params", []) or [])
                for param, expression in zip(params, getattr(site, "args", []) or []):
                    actual_atom = self._simple_rhs(str(expression))
                    if not actual_atom:
                        continue
                    actual, addressed = actual_atom
                    dst = f"{callee}::{param}"
                    if actual in self.defined:
                        self._add_target(dst, f"function:{actual}")
                    elif addressed:
                        self._add_target(dst, f"object:{self._symbol(caller, actual)}")
                    else:
                        src = self._symbol(caller, actual)
                        self.result.copies.append((dst, src))
                        self.result.offset_adjustments.append((dst, src, 0))
        return self.result

    def _propagate(self, dst: str, src: str, delta: Optional[int] = 0) -> bool:
        changed = False
        before = len(self.result.points[dst])
        self.result.points[dst].update(self.result.points.get(src, set()))
        changed |= len(self.result.points[dst]) != before
        for target in self.result.points.get(src, set()):
            lo, hi = self.result.offsets.get(src, {}).get(target, (0, 0))
            if delta is None or lo is None or hi is None:
                adjusted = (None, None)
            else:
                adjusted = (lo + delta, hi + delta)
            changed |= self._merge_offset(dst, target, adjusted)
        return changed

    def _compute_final_memory(self) -> None:
        result = self.result
        result.final_memory.clear()
        result.strong_updates = 0
        result.weak_updates = 0
        for store_index, (pointer, src, field_name, direct_object) in enumerate(result.stores):
            targets = ({f"object:{pointer}"} if direct_object
                       else result.points.get(pointer, set()))
            # An allocation-site may represent many concrete loop/runtime objects.
            # Strong updates are therefore limited to singleton non-heap objects.
            strong = (store_index in result.strong_store_indices and len(targets) == 1
                      and not next(iter(targets), "").startswith("heap:"))
            for target in targets:
                memory = self._memory_key(target, field_name, result.union_objects)
                if strong:
                    result.final_memory[memory] = set(result.points.get(src, set()))
                    result.strong_updates += 1
                else:
                    result.final_memory[memory].update(result.points.get(src, set()))
                    result.weak_updates += 1

    def _compute_flow_state(self) -> None:
        """Sequential precision tier layered under the sound may-points-to result.

        Unconditional local assignments replace the prior local state. Controlled
        assignments join because either branch may execute. Stores replace only a
        singleton non-heap cell; every other store remains weak.
        """
        result = self.result
        result.flow_points.clear()
        result.flow_memory.clear()
        result.flow_strong_updates = 0
        result.flow_weak_updates = 0
        assigned: Set[str] = set()

        def values(symbol: str) -> Set[str]:
            return set(result.flow_points[symbol] if symbol in assigned
                       else result.points.get(symbol, set()))

        def assign(symbol: str, new_values: Set[str], controlled: bool,
                   function: str) -> None:
            local = symbol.startswith(f"{function}::")
            if not controlled and local:
                result.flow_points[symbol] = set(new_values)
                result.flow_strong_updates += 1
            else:
                result.flow_points[symbol].update(new_values)
                result.flow_weak_updates += 1
            assigned.add(symbol)

        for event in result.flow_events:
            kind = str(event.get("kind", ""))
            function = str(event.get("function", ""))
            controlled = bool(event.get("controlled"))
            if kind == "assign_targets":
                assign(str(event["dst"]), set(event.get("targets", set())),
                       controlled, function)
            elif kind == "copy":
                assign(str(event["dst"]), values(str(event["src"])),
                       controlled, function)
            elif kind == "load":
                pointer = str(event["pointer"])
                targets = ({f"object:{pointer}"} if event.get("direct")
                           else values(pointer))
                loaded: Set[str] = set()
                for target in targets:
                    key = self._memory_key(
                        target, event.get("field"), result.union_objects)
                    if key in result.flow_memory:
                        loaded.update(result.flow_memory[key])
                    elif event.get("field") is None and target.startswith("object:"):
                        loaded.update(values(target[len("object:"):]))
                assign(str(event["dst"]), loaded, controlled, function)
            elif kind == "store":
                pointer = str(event["pointer"])
                targets = ({f"object:{pointer}"} if event.get("direct")
                           else values(pointer))
                source_values = values(str(event["src"]))
                strong = (not controlled and len(targets) == 1
                          and not next(iter(targets), "").startswith("heap:"))
                for target in targets:
                    key = self._memory_key(
                        target, event.get("field"), result.union_objects)
                    if strong:
                        result.flow_memory[key] = set(source_values)
                        result.flow_strong_updates += 1
                    else:
                        result.flow_memory[key].update(source_values)
                        result.flow_weak_updates += 1

    def _compute_heap_shapes(self) -> None:
        """Materialize a finite allocation-site shape graph and cyclic SCC summary."""
        result = self.result
        result.heap_shape_edges.clear()
        result.recursive_heap_components.clear()
        for symbol, targets in result.points.items():
            if not symbol.startswith("memory:"):
                continue
            cell = symbol[len("memory:"):]
            field_name = "$cell"
            source = cell
            # Heap allocation-site identifiers contain no '.', so the final suffix
            # is unambiguously the field selected by `_memory_key`.
            if cell.startswith("heap:") and "." in cell:
                source, field_name = cell.rsplit(".", 1)
            if not source.startswith("heap:"):
                continue
            heap_targets = {target for target in targets if target.startswith("heap:")}
            if heap_targets:
                result.heap_shape_edges[source][field_name].update(heap_targets)

        adjacency: Dict[str, Set[str]] = defaultdict(set)
        nodes: Set[str] = set()
        for source, fields in result.heap_shape_edges.items():
            nodes.add(source)
            for targets in fields.values():
                adjacency[source].update(targets)
                nodes.update(targets)

        index = 0
        indices: Dict[str, int] = {}
        lowlink: Dict[str, int] = {}
        stack: List[str] = []
        on_stack: Set[str] = set()

        def visit(node: str) -> None:
            nonlocal index
            indices[node] = index
            lowlink[node] = index
            index += 1
            stack.append(node)
            on_stack.add(node)
            for successor in adjacency.get(node, set()):
                if successor not in indices:
                    visit(successor)
                    lowlink[node] = min(lowlink[node], lowlink[successor])
                elif successor in on_stack:
                    lowlink[node] = min(lowlink[node], indices[successor])
            if lowlink[node] != indices[node]:
                return
            component: Set[str] = set()
            while stack:
                member = stack.pop()
                on_stack.discard(member)
                component.add(member)
                if member == node:
                    break
            if len(component) > 1 or any(member in adjacency.get(member, set())
                                         for member in component):
                result.recursive_heap_components.append(component)

        for node in sorted(nodes):
            if node not in indices:
                visit(node)

    def solve(self, max_iterations: int = 100) -> PointsToResult:
        result = self.collect()
        changed = True
        while changed and result.iterations < max_iterations:
            changed = False
            result.iterations += 1
            for dst, src in result.copies:
                before = len(result.points[dst])
                result.points[dst].update(result.points.get(src, set()))
                changed |= len(result.points[dst]) != before
            for dst, src, delta in result.offset_adjustments:
                for target in result.points.get(src, set()):
                    lo, hi = result.offsets.get(src, {}).get(target, (0, 0))
                    adjusted = ((None, None) if delta is None or lo is None or hi is None
                                else (lo + delta, hi + delta))
                    changed |= self._merge_offset(dst, target, adjusted)
            for pointer, src, field_name, direct_object in result.stores:
                targets = ({f"object:{pointer}"} if direct_object
                           else result.points.get(pointer, set()))
                for target in targets:
                    memory = self._memory_key(target, field_name, result.union_objects)
                    changed |= self._propagate(memory, src, 0)
                    if field_name is None and target.startswith("object:"):
                        cell = target[len("object:"):]
                        changed |= self._propagate(cell, src, 0)
            for dst, pointer, field_name, direct_object in result.loads:
                targets = ({f"object:{pointer}"} if direct_object
                           else result.points.get(pointer, set()))
                for target in targets:
                    changed |= self._propagate(
                        dst, self._memory_key(target, field_name,
                                              result.union_objects), 0)
                    if field_name is None and target.startswith("object:"):
                        changed |= self._propagate(dst, target[len("object:"):], 0)
        self._compute_final_memory()
        self._compute_flow_state()
        self._compute_heap_shapes()
        return result


__all__ = ["PointsToAnalysis", "PointsToResult"]
