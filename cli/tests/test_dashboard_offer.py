"""Binding a target should offer to open the live dashboard — declining
must be a true no-op, and accepting must open the exact backend URL for
that engagement, not a guessed or hardcoded one."""

from __future__ import annotations

from cli.commands import scan_shared


class _FakeClient:
    base_url = "http://localhost:9000"


def test_declining_does_not_open_a_browser(monkeypatch):
    opened = []
    monkeypatch.setattr(scan_shared, "webbrowser", type("W", (), {"open": staticmethod(lambda url: opened.append(url))}))
    monkeypatch.setattr("builtins.input", lambda *_: "n")

    scan_shared._offer_dashboard(_FakeClient(), "eng-123")

    assert opened == []


def test_accepting_opens_the_dashboard_url_for_this_engagement(monkeypatch):
    opened = []
    monkeypatch.setattr(scan_shared, "webbrowser", type("W", (), {"open": staticmethod(lambda url: opened.append(url) or True)}))
    monkeypatch.setattr("builtins.input", lambda *_: "y")

    scan_shared._offer_dashboard(_FakeClient(), "eng-123")

    assert opened == ["http://localhost:9000/api/v1/dashboard/eng-123"]


def test_eof_on_prompt_is_treated_as_decline(monkeypatch):
    opened = []
    monkeypatch.setattr(scan_shared, "webbrowser", type("W", (), {"open": staticmethod(lambda url: opened.append(url))}))

    def _raise(*_):
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise)

    scan_shared._offer_dashboard(_FakeClient(), "eng-123")

    assert opened == []
