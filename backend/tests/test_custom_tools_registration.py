"""Operator-defined tools from config/custom_tools.yaml — plans/harness/13-
systematic-vuln-dispatch-and-extensibility.md Step 2. The shipped file's own
template entry is disabled by default (never registers); these tests exercise
the loader directly against synthetic YAML rather than depending on the
shipped file's content.
"""

from __future__ import annotations

from osprey.services.tool_registry import _load_custom_tool_definitions
from osprey.services import config_loader


def test_shipped_custom_tools_template_is_disabled_and_does_not_register():
    # The real config/custom_tools.yaml ships with disabled: true on its only
    # entry — confirms it never silently registers a nonexistent tool.
    defs = _load_custom_tool_definitions()
    assert not any(d.name == "example_custom_tool" for d in defs)


def test_a_valid_custom_entry_registers_as_a_real_tool_definition(tmp_path, monkeypatch):
    monkeypatch.setattr(config_loader, "CONFIG_DIR", tmp_path)
    (tmp_path / "custom_tools.yaml").write_text(
        "tools:\n"
        "  - id: my_custom_scanner\n"
        "    category: webapp\n"
        "    executable: python3\n"
        "    safety_level: active\n"
        "    description: A custom scanner the operator wrote.\n"
        "    tags: [custom]\n"
        "    params:\n"
        "      target:\n"
        "        default: ''\n"
        "        description: Target URL\n",
        encoding="utf-8",
    )
    defs = _load_custom_tool_definitions()
    assert len(defs) == 1
    tool = defs[0]
    assert tool.name == "my_custom_scanner"
    assert tool.executable == "python3"
    assert "custom" in tool.tags
    assert "target" in tool.parameters


def test_disabled_entry_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(config_loader, "CONFIG_DIR", tmp_path)
    (tmp_path / "custom_tools.yaml").write_text(
        "tools:\n"
        "  - id: disabled_one\n"
        "    disabled: true\n"
        "    category: webapp\n"
        "    description: x\n",
        encoding="utf-8",
    )
    assert _load_custom_tool_definitions() == ()


def test_malformed_entry_is_skipped_not_fatal(tmp_path, monkeypatch):
    monkeypatch.setattr(config_loader, "CONFIG_DIR", tmp_path)
    (tmp_path / "custom_tools.yaml").write_text(
        "tools:\n"
        "  - id: ''\n"  # missing real id -> ValueError, must be skipped not raised
        "    category: webapp\n"
        "    description: x\n"
        "  - id: good_one\n"
        "    category: webapp\n"
        "    description: A working entry after a bad one.\n",
        encoding="utf-8",
    )
    defs = _load_custom_tool_definitions()
    assert len(defs) == 1
    assert defs[0].name == "good_one"


def test_local_overlay_disables_a_committed_custom_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(config_loader, "CONFIG_DIR", tmp_path)
    (tmp_path / "custom_tools.yaml").write_text(
        "tools:\n"
        "  - id: shared_tool\n"
        "    category: webapp\n"
        "    description: A tool the team shares.\n",
        encoding="utf-8",
    )
    (tmp_path / "custom_tools.local.yaml").write_text(
        "tools:\n"
        "  - id: shared_tool\n"
        "    disabled: true\n",
        encoding="utf-8",
    )
    assert _load_custom_tool_definitions() == ()
