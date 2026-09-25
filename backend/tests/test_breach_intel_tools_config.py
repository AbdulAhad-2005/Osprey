"""_breach_intel_tool_entries — config-driven (config/breach_intel_tools.yaml
+ .local.yaml overlay), not a hardcoded tuple, so an operator's own keyed
OSINT tool actually gets run by the mechanical recon pass once added, no
Python edit needed. plans/harness/13 Step 1 (read_config_layered) applied to
plans/harness/14/15's mechanical-flow extension.
"""

from __future__ import annotations

import pytest

from osprey.services import config_loader, surface_expansion


@pytest.fixture(autouse=True)
def _clear_cache_around_each_test():
    # lru_cache'd for the process lifetime by design (config rarely changes
    # mid-run) — tests must clear it on both sides of a CONFIG_DIR
    # monkeypatch, or a tmp_path-scoped result leaks into whichever test
    # (in this file or another) reads the cache next.
    surface_expansion._breach_intel_tool_entries.cache_clear()
    yield
    surface_expansion._breach_intel_tool_entries.cache_clear()


def _reload(tmp_path, monkeypatch):
    monkeypatch.setattr(config_loader, "CONFIG_DIR", tmp_path)
    surface_expansion._breach_intel_tool_entries.cache_clear()


def test_shipped_config_has_the_three_built_in_tools():
    # Real shipped file, not a synthetic one — proves the actual repo config
    # matches what surface_expansion.py dispatches.
    surface_expansion._breach_intel_tool_entries.cache_clear()
    entries = surface_expansion._breach_intel_tool_entries()
    tools = {tool for _env, tool, _param in entries}
    assert {"shodan_search", "intelx_scan", "resecurity_scan"} <= tools


def test_operator_can_add_a_new_entry_without_touching_python(tmp_path, monkeypatch):
    _reload(tmp_path, monkeypatch)
    (tmp_path / "breach_intel_tools.yaml").write_text(
        "tools:\n"
        "  - id: shodan_search\n"
        "    env_var: SHODAN_API_KEY\n"
        "    tool: shodan_search\n"
        "    param: domain\n",
        encoding="utf-8",
    )
    (tmp_path / "breach_intel_tools.local.yaml").write_text(
        "tools:\n"
        "  - id: my_custom_osint\n"
        "    env_var: MY_CUSTOM_OSINT_KEY\n"
        "    tool: my_custom_osint_tool\n"
        "    param: target\n",
        encoding="utf-8",
    )
    entries = surface_expansion._breach_intel_tool_entries()
    tools = {tool for _env, tool, _param in entries}
    assert "shodan_search" in tools
    assert "my_custom_osint_tool" in tools


def test_operator_can_disable_a_built_in_entry(tmp_path, monkeypatch):
    _reload(tmp_path, monkeypatch)
    (tmp_path / "breach_intel_tools.yaml").write_text(
        "tools:\n"
        "  - id: shodan_search\n"
        "    env_var: SHODAN_API_KEY\n"
        "    tool: shodan_search\n"
        "    param: domain\n"
        "  - id: intelx_scan\n"
        "    env_var: INTELX_API_KEY\n"
        "    tool: intelx_scan\n"
        "    param: target\n",
        encoding="utf-8",
    )
    (tmp_path / "breach_intel_tools.local.yaml").write_text(
        "tools:\n"
        "  - id: intelx_scan\n"
        "    disabled: true\n",
        encoding="utf-8",
    )
    entries = surface_expansion._breach_intel_tool_entries()
    tools = {tool for _env, tool, _param in entries}
    assert tools == {"shodan_search"}


def test_malformed_entry_is_skipped_not_fatal(tmp_path, monkeypatch):
    _reload(tmp_path, monkeypatch)
    (tmp_path / "breach_intel_tools.yaml").write_text(
        "tools:\n"
        "  - id: broken\n"
        "    env_var: SOME_KEY\n"
        # missing tool/param -> KeyError, must be skipped not raised
        "  - id: shodan_search\n"
        "    env_var: SHODAN_API_KEY\n"
        "    tool: shodan_search\n"
        "    param: domain\n",
        encoding="utf-8",
    )
    entries = surface_expansion._breach_intel_tool_entries()
    assert entries == (("SHODAN_API_KEY", "shodan_search", "domain"),)
