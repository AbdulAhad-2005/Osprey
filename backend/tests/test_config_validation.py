"""G1 — knowledge-config validators fail loudly with the offending field named,
and the shipped configs pass. This is what makes an operator's own added check
(G2) safe: a malformed edit is rejected at load, not silently ignored."""

from __future__ import annotations

import pytest

from osprey.services.config_loader import read_config
from osprey.services.config_validation import (
    ConfigValidationError,
    validate_expansion,
    validate_tech_dispatch,
)


def test_shipped_tech_dispatch_is_valid():
    validate_tech_dispatch(read_config("tech_dispatch.yaml"))


def test_shipped_expansion_is_valid():
    validate_expansion(read_config("expansion.yaml"))


def test_dispatch_rule_missing_default_tool_fails_loudly():
    bad = {"signals": [{"id": "r1", "match": {"finding_type": "service"}, "dispatch": {"task_id": "x"}}]}
    with pytest.raises(ConfigValidationError, match="default_tool"):
        validate_tech_dispatch(bad)


def test_dispatch_rule_unknown_match_field_fails_loudly():
    bad = {"signals": [{"id": "r1", "match": {"finding_tyype": "service"}, "dispatch": {"default_tool": "nuclei_scan"}}]}
    with pytest.raises(ConfigValidationError, match="unknown match field"):
        validate_tech_dispatch(bad)


def test_duplicate_dispatch_id_fails_loudly():
    bad = {"signals": [
        {"id": "dup", "match": {"finding_type": "url"}, "dispatch": {"default_tool": "a"}},
        {"id": "dup", "match": {"finding_type": "url"}, "dispatch": {"default_tool": "b"}},
    ]}
    with pytest.raises(ConfigValidationError, match="duplicate id"):
        validate_tech_dispatch(bad)


def test_expansion_stage_entry_missing_param_fails_loudly():
    bad = {"web_depth": [{"tool": "katana_crawl"}]}
    with pytest.raises(ConfigValidationError, match="param"):
        validate_expansion(bad)
