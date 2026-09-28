"""config/expansion.yaml now reads through read_config_layered too — plans/
harness/13-systematic-vuln-dispatch-and-extensibility.md Step 1 applied
broadly, not just to the new breach_intel_tools.yaml: an operator's own
added step for an EXISTING mechanical section (host_expansion, web_depth,
sister_discovery, …) actually gets appended and run, no Python edit.
"""

from __future__ import annotations

import pytest

from osprey.services import config_loader, surface_expansion


@pytest.fixture(autouse=True)
def _clear_cache_around_each_test():
    surface_expansion.reload_expansion_config()
    yield
    surface_expansion.reload_expansion_config()


def test_shipped_expansion_config_still_loads():
    # Real shipped file — proves the switch to read_config_layered didn't
    # break normal (no .local.yaml present) loading.
    cfg = surface_expansion._expansion_config()
    assert isinstance(cfg.get("host_expansion"), list)
    assert len(cfg["host_expansion"]) > 0


def test_operator_can_append_a_step_to_an_existing_section(tmp_path, monkeypatch):
    monkeypatch.setattr(config_loader, "CONFIG_DIR", tmp_path)
    (tmp_path / "expansion.yaml").write_text(
        "host_expansion:\n"
        "  - tool: httpx_probe\n"
        "    param: target\n",
        encoding="utf-8",
    )
    (tmp_path / "expansion.local.yaml").write_text(
        "host_expansion:\n"
        "  - tool: my_custom_osint_tool\n"
        "    param: target\n",
        encoding="utf-8",
    )
    surface_expansion.reload_expansion_config()
    cfg = surface_expansion._expansion_config()
    tools = {e.get("tool") for e in cfg["host_expansion"]}
    assert "httpx_probe" in tools
    assert "my_custom_osint_tool" in tools
