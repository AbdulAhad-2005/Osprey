"""read_config_layered — plans/harness/13-systematic-vuln-dispatch-and-
extensibility.md Step 1: a per-operator .local.yaml overlay that adds, edits,
or disables entries in a base config file without touching the shipped file.
"""

from __future__ import annotations

from osprey.services import config_loader


def test_no_local_file_returns_base_unchanged(tmp_path, monkeypatch):
    monkeypatch.setattr(config_loader, "CONFIG_DIR", tmp_path)
    (tmp_path / "rules.yaml").write_text("signals:\n  - id: a\n    value: 1\n", encoding="utf-8")
    result = config_loader.read_config_layered("rules.yaml")
    assert result == {"signals": [{"id": "a", "value": 1}]}


def test_local_overlay_appends_new_entry(tmp_path, monkeypatch):
    monkeypatch.setattr(config_loader, "CONFIG_DIR", tmp_path)
    (tmp_path / "rules.yaml").write_text("signals:\n  - id: a\n    value: 1\n", encoding="utf-8")
    (tmp_path / "rules.local.yaml").write_text("signals:\n  - id: b\n    value: 2\n", encoding="utf-8")
    result = config_loader.read_config_layered("rules.yaml")
    ids = [s["id"] for s in result["signals"]]
    assert ids == ["a", "b"]


def test_local_overlay_edits_matching_id(tmp_path, monkeypatch):
    monkeypatch.setattr(config_loader, "CONFIG_DIR", tmp_path)
    (tmp_path / "rules.yaml").write_text("signals:\n  - id: a\n    value: 1\n", encoding="utf-8")
    (tmp_path / "rules.local.yaml").write_text("signals:\n  - id: a\n    value: 99\n", encoding="utf-8")
    result = config_loader.read_config_layered("rules.yaml")
    assert result["signals"] == [{"id": "a", "value": 99}]


def test_local_overlay_disables_matching_id(tmp_path, monkeypatch):
    monkeypatch.setattr(config_loader, "CONFIG_DIR", tmp_path)
    (tmp_path / "rules.yaml").write_text(
        "signals:\n  - id: a\n    value: 1\n  - id: b\n    value: 2\n", encoding="utf-8",
    )
    (tmp_path / "rules.local.yaml").write_text(
        "signals:\n  - id: a\n    disabled: true\n", encoding="utf-8",
    )
    result = config_loader.read_config_layered("rules.yaml")
    ids = [s["id"] for s in result["signals"]]
    assert ids == ["b"]


def test_local_overlay_scalar_key_replaces_outright(tmp_path, monkeypatch):
    monkeypatch.setattr(config_loader, "CONFIG_DIR", tmp_path)
    (tmp_path / "rules.yaml").write_text("phase: recon\nsignals: []\n", encoding="utf-8")
    (tmp_path / "rules.local.yaml").write_text("phase: vuln_web\n", encoding="utf-8")
    result = config_loader.read_config_layered("rules.yaml")
    assert result["phase"] == "vuln_web"


def test_missing_base_file_returns_empty_even_with_local(tmp_path, monkeypatch):
    monkeypatch.setattr(config_loader, "CONFIG_DIR", tmp_path)
    (tmp_path / "rules.local.yaml").write_text("signals:\n  - id: b\n", encoding="utf-8")
    assert config_loader.read_config_layered("rules.yaml") == {}


def test_malformed_local_overlay_falls_back_to_base(tmp_path, monkeypatch):
    monkeypatch.setattr(config_loader, "CONFIG_DIR", tmp_path)
    (tmp_path / "rules.yaml").write_text("signals:\n  - id: a\n", encoding="utf-8")
    (tmp_path / "rules.local.yaml").write_text("not: valid: yaml: [", encoding="utf-8")
    result = config_loader.read_config_layered("rules.yaml")
    assert result == {"signals": [{"id": "a"}]}
