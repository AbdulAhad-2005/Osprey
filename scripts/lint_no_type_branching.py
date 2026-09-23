#!/usr/bin/env python3
"""Anti-regression gate — plans/harness/03-earned-finding-pipeline.md Step 7.

The one law: a finding's confidence is a pure function of its evidence,
never its type. This scans the finding-creation, confidence, and
evidence-capability modules for per-type branching — `finding_type ==`,
`.type ==`, a `match`/`switch` on either, or a dict/table keyed by finding
type — and fails if any exists. That is exactly how "HTTP 501 became a
finding" happened (a `no_parser` rule table with a special case per shape);
an invariant defined for every input has no unenumerated case to get wrong,
so nothing in this path may special-case a type, ever.

Uses the AST, not a text grep — a docstring that *mentions* the banned
pattern (to explain the rule, as several of these modules' own module
docstrings do) must never itself trip the gate; grepping raw text would.

The one legitimate use of finding_type/observation.type is *display or
reporting* (grouping a report by category) — that code lives outside the
files this gate scans, never inside them.

Usage: python scripts/lint_no_type_branching.py
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

# The finding-creation / confidence / evidence-capability path. Deliberately
# a short, explicit list, not a glob over all of services/ — report/render
# modules (report_outline.py, markdown_report.py, …) legitimately branch on
# finding_type for *display grouping*, which this gate does not forbid.
_TARGET_FILES = (
    "backend/src/osprey/services/confidence.py",
    "backend/src/osprey/services/finding_pipeline.py",
    "backend/src/osprey/services/exploit_pipeline.py",
)

# Attribute names that mean "what KIND of finding/observation is this" —
# branching on these (not their VALUE-independent presence, their identity)
# is what the law forbids.
_TYPE_ATTRS = frozenset({"finding_type", "type"})


class _Violation:
    def __init__(self, path: str, line: int, detail: str) -> None:
        self.path = path
        self.line = line
        self.detail = detail

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.detail}"


def _is_type_attr(node: ast.expr) -> bool:
    return isinstance(node, ast.Attribute) and node.attr in _TYPE_ATTRS


def _scan_compare(node: ast.Compare, rel: str) -> _Violation | None:
    operands = [node.left, *node.comparators]
    ops_are_equality = all(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops)
    if ops_are_equality and any(_is_type_attr(o) for o in operands):
        return _Violation(rel, node.lineno, "comparison branches on a finding/observation type attribute")
    return None


def _scan_match(node: "ast.Match", rel: str) -> _Violation | None:
    subject = node.subject
    if _is_type_attr(subject) or (isinstance(subject, ast.Name) and subject.id in _TYPE_ATTRS):
        return _Violation(rel, node.lineno, "match statement switches on a finding/observation type")
    return None


def _scan_dict_keyed_by_type_enum(node: ast.Dict, rel: str) -> _Violation | None:
    """A per-vuln-class rule table: a dict literal whose keys are all
    FindingType/ObservationType enum member accesses (FindingType.X: ...)."""
    if len(node.keys) < 2:
        return None
    enum_keys = [
        k for k in node.keys
        if isinstance(k, ast.Attribute)
        and isinstance(k.value, ast.Name)
        and k.value.id in ("FindingType", "ObservationType")
    ]
    if len(enum_keys) == len(node.keys) and enum_keys:
        return _Violation(rel, node.lineno, "dict literal is a per-type rule table keyed by FindingType/ObservationType")
    return None


def lint() -> list[_Violation]:
    violations: list[_Violation] = []
    for rel in _TARGET_FILES:
        path = _ROOT / rel
        if not path.is_file():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                v = _scan_compare(node, rel)
                if v:
                    violations.append(v)
            elif isinstance(node, ast.Dict):
                v = _scan_dict_keyed_by_type_enum(node, rel)
                if v:
                    violations.append(v)
            elif node.__class__.__name__ == "Match":  # ast.Match — py3.10+
                v = _scan_match(node, rel)  # type: ignore[arg-type]
                if v:
                    violations.append(v)
    return violations


def main() -> int:
    violations = lint()
    for v in violations:
        print(f"ERROR {v}")
    if violations:
        print(f"\n{len(violations)} violation(s) of the one law (plans/harness/03-earned-finding-pipeline.md).")
        return 1
    scanned = sum(1 for f in _TARGET_FILES if (_ROOT / f).is_file())
    print(f"OK — {scanned} finding-pipeline module(s) linted clean, no per-type branching.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
