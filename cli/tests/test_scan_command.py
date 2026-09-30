"""/scan previously had no way to force a fresh engagement — it always
silently reused an existing one for the target, with no operator-visible
choice. --fresh closes that gap."""

from __future__ import annotations

from cli.commands.slash import handle_scan


class _FakeClient:
    def __init__(self) -> None:
        self.compile_calls: list[tuple[str, bool]] = []

    def compile_engagement_for_target(self, target: str, force_new: bool = False):
        self.compile_calls.append((target, force_new))
        return {"id": "eng-1", "target": target, "reused": not force_new}


def _patch_runtime(monkeypatch):
    monkeypatch.setattr("cli.commands.slash._run_engine_scan", lambda client, target, **kw: True)
    monkeypatch.setattr("cli.commands.slash._bind_engagement", lambda client, data: None)


def test_scan_without_fresh_reuses_by_default(monkeypatch):
    _patch_runtime(monkeypatch)
    client = _FakeClient()

    handle_scan(["samaa.tv", "--engine"], client)

    assert client.compile_calls == [("samaa.tv", False)]


def test_scan_with_fresh_forces_a_new_engagement(monkeypatch):
    _patch_runtime(monkeypatch)
    client = _FakeClient()

    handle_scan(["samaa.tv", "--engine", "--fresh"], client)

    assert client.compile_calls == [("samaa.tv", True)]


def test_scan_fresh_flag_is_stripped_from_the_target(monkeypatch):
    _patch_runtime(monkeypatch)
    client = _FakeClient()

    handle_scan(["--fresh", "samaa.tv", "--engine"], client)

    assert client.compile_calls == [("samaa.tv", True)]


def test_scan_supervised_with_fresh(monkeypatch):
    _patch_runtime(monkeypatch)
    client = _FakeClient()
    engine_calls: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        "cli.commands.slash._run_engine_scan",
        lambda client, target, **kw: engine_calls.append((target, kw.get("supervised", False))) or True,
    )

    handle_scan(["samaa.tv", "--supervised", "--fresh"], client)

    assert client.compile_calls == [("samaa.tv", True)]
    assert engine_calls == [("samaa.tv", True)]
