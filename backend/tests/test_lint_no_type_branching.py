"""Wraps scripts/lint_no_type_branching.py (plans/harness/03-earned-finding-
pipeline.md Step 7) so the anti-regression gate runs as part of the normal
test suite, not only as a manual/CI-only script.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))

import lint_no_type_branching as lint_mod  # noqa: E402


def test_finding_pipeline_modules_have_no_per_type_branching():
    violations = lint_mod.lint()
    assert violations == [], "\n".join(str(v) for v in violations)


def test_target_files_actually_exist_and_are_scanned():
    """A gate that silently scans zero files (e.g. after a rename) proves
    nothing — assert the target list still resolves to real files."""
    existing = [f for f in lint_mod._TARGET_FILES if (_ROOT / f).is_file()]
    assert len(existing) == len(lint_mod._TARGET_FILES), (
        f"missing target file(s): {set(lint_mod._TARGET_FILES) - set(existing)}"
    )


def test_gate_detects_a_type_equality_comparison():
    sample = (
        "from osprey.schemas.finding import FindingType\n"
        "def f(finding):\n"
        "    if finding.finding_type == FindingType.VULNERABILITY:\n"
        "        return 'confirmed'\n"
    )
    tree = ast.parse(sample)
    violations = [
        lint_mod._scan_compare(node, "sample.py")
        for node in ast.walk(tree)
        if isinstance(node, ast.Compare)
    ]
    assert any(violations), "gate failed to catch a finding_type == comparison"


def test_gate_detects_a_per_type_rule_table():
    sample = (
        "from osprey.schemas.finding import FindingType\n"
        "_RULES = {FindingType.VULNERABILITY: 'a', FindingType.CREDENTIAL: 'b'}\n"
    )
    tree = ast.parse(sample)
    violations = [
        lint_mod._scan_dict_keyed_by_type_enum(node, "sample.py")
        for node in ast.walk(tree)
        if isinstance(node, ast.Dict)
    ]
    assert any(violations), "gate failed to catch a per-type rule table"


def test_gate_does_not_false_positive_on_docstrings_mentioning_the_rule():
    """The module docstrings in confidence.py/finding_pipeline.py literally
    contain the string "finding_type ==" to explain the rule — the AST-based
    gate must not trip on that, unlike a naive text grep would."""
    sample = '''
"""This module forbids finding_type == anywhere, per the one law."""

def confidence_for(evidence):
    return "hypothesis"
'''
    tree = ast.parse(sample)
    violations = [
        lint_mod._scan_compare(node, "sample.py")
        for node in ast.walk(tree)
        if isinstance(node, ast.Compare)
    ]
    assert not any(violations)
