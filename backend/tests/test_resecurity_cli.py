"""_resecurity_cli.py (the live HTTP client) + resecurity_scan.py (the mcp-server
wrapper). No unit coverage existed before — only the backend-side JSON parser
(test_creds_parsers.py) was tested, never the actual request/response/error
handling that connects to the account's configured endpoint."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MCP_SERVERS = ROOT / "mcp-servers"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rcli = _load("_test_resecurity_cli", MCP_SERVERS / "osint" / "tools" / "_resecurity_cli.py")


def _wrapper():
    if str(MCP_SERVERS) not in sys.path:
        sys.path.insert(0, str(MCP_SERVERS))
    return _load("_test_resecurity_scan", MCP_SERVERS / "osint" / "tools" / "resecurity_scan.py")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("RESECURITY_API_KEY", "RESECURITY_API_BASE", "RESECURITY_ENDPOINT",
                "RESECURITY_QUERY_PARAM", "RESECURITY_AUTH_HEADER", "RESECURITY_AUTH_SCHEME"):
        monkeypatch.delenv(var, raising=False)


class _CtxResp:
    """Wraps a BytesIO so it supports the `with urlopen(...) as resp:` pattern."""
    def __init__(self, buf):
        self._buf = buf

    def read(self):
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_missing_key_raises_clear_error():
    with pytest.raises(SystemExit, match="RESECURITY_API_KEY is not set"):
        rcli.search("acme.test")


def test_request_uses_configured_base_endpoint_param_and_auth(monkeypatch):
    monkeypatch.setenv("RESECURITY_API_KEY", "k-123")
    monkeypatch.setenv("RESECURITY_API_BASE", "https://custom.example/api")
    monkeypatch.setenv("RESECURITY_ENDPOINT", "/v2/search")
    monkeypatch.setenv("RESECURITY_QUERY_PARAM", "q")
    monkeypatch.setenv("RESECURITY_AUTH_HEADER", "X-Api-Key")
    monkeypatch.setenv("RESECURITY_AUTH_SCHEME", "")
    captured = {}

    def fake_urlopen(req, timeout=45):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.headers)
        return io.BytesIO(b'{"credentials": [], "emails": []}')

    monkeypatch.setattr(rcli, "urlopen", lambda req, timeout=45: _CtxResp(fake_urlopen(req, timeout)))
    rcli.search("acme.test", limit=50)
    assert captured["url"].startswith("https://custom.example/api/v2/search?")
    assert "q=acme.test" in captured["url"]
    assert "per-page=50" in captured["url"]
    # scheme="" means a bare key (no "Bearer " prefix) — see test below for the
    # fix that makes an explicit empty override actually take effect.
    assert captured["headers"].get("X-api-key") == "k-123"  # urllib title-cases header keys


def test_empty_auth_scheme_override_gives_a_bare_key_header(monkeypatch):
    """RESECURITY_AUTH_SCHEME="" is documented as the way to send a bare key
    with no scheme prefix — `_cfg`'s `or default` used to swallow this."""
    monkeypatch.setenv("RESECURITY_API_KEY", "k-123")
    monkeypatch.setenv("RESECURITY_AUTH_SCHEME", "")
    captured = {}

    def fake_urlopen(req, timeout=45):
        captured["headers"] = dict(req.headers)
        return _CtxResp(io.BytesIO(b'{"credentials":[],"emails":[]}'))

    monkeypatch.setattr(rcli, "urlopen", fake_urlopen)
    rcli.search("acme.test")
    assert captured["headers"].get("Authorization") == "k-123"


def test_default_auth_is_real_http_basic_with_key_as_username(monkeypatch):
    """Confirmed live: the server advertises WWW-Authenticate: Basic and accepts
    the API key as the Basic username with an empty password — NOT the literal
    word "Basic" glued onto the raw key."""
    import base64

    monkeypatch.setenv("RESECURITY_API_KEY", "k-123")
    captured = {}

    def fake_urlopen(req, timeout=45):
        captured["headers"] = dict(req.headers)
        return _CtxResp(io.BytesIO(b'{"credentials":[],"emails":[]}'))

    monkeypatch.setattr(rcli, "urlopen", fake_urlopen)
    rcli.search("acme.test")
    expected = "Basic " + base64.b64encode(b"k-123:").decode()
    assert captured["headers"].get("Authorization") == expected


def test_defaults_match_the_confirmed_live_breaches_api(monkeypatch):
    """base/endpoint/query-param/page-size-param all confirmed against the real
    Resecurity Breaches API's own Swagger docs (app.resecurity.com/doc/breaches-
    api) — this pins the no-override "just set the key" path so a future edit
    can't silently drift from what's documented and proven to work."""
    monkeypatch.setenv("RESECURITY_API_KEY", "k")
    captured = {}

    def fake_urlopen(req, timeout=45):
        captured["url"] = req.full_url
        return _CtxResp(io.BytesIO(b"[]"))

    monkeypatch.setattr(rcli, "urlopen", fake_urlopen)
    rcli.search("acme.test", limit=50)
    assert captured["url"] == (
        "https://app.resecurity.com/api/breaches/index?query=acme.test&per-page=50&page=1"
    )


def test_invalid_route_error_names_the_endpoint_and_points_at_env(monkeypatch):
    monkeypatch.setenv("RESECURITY_API_KEY", "k")
    monkeypatch.setenv("RESECURITY_ENDPOINT", "/v1/leaks/search")
    body = (b'{"name":"Not Found","message":"Page not found.","code":0,"status":404,'
            b'"previous":{"name":"Invalid Route","message":"Unable to resolve the request '
            b'\\"v1/leaks/search\\".","code":0}}')

    def fake_urlopen(req, timeout=45):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(body))

    monkeypatch.setattr(rcli, "urlopen", fake_urlopen)
    with pytest.raises(SystemExit) as exc:
        rcli.search("acme.test")
    msg = str(exc.value)
    assert "/v1/leaks/search" in msg
    assert "RESECURITY_ENDPOINT" in msg
    assert "unknown route" in msg.lower()


def test_unauthorized_error_names_the_key_and_auth_vars(monkeypatch):
    monkeypatch.setenv("RESECURITY_API_KEY", "k")

    def fake_urlopen(req, timeout=45):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b'{"error":"invalid key"}'))

    monkeypatch.setattr(rcli, "urlopen", fake_urlopen)
    with pytest.raises(SystemExit) as exc:
        rcli.search("acme.test")
    msg = str(exc.value)
    assert "RESECURITY_API_KEY" in msg
    assert "unauthorized" in msg.lower()


def test_generic_http_error_falls_through_to_plain_message(monkeypatch):
    monkeypatch.setenv("RESECURITY_API_KEY", "k")

    def fake_urlopen(req, timeout=45):
        raise urllib.error.HTTPError(req.full_url, 500, "Server Error", {}, io.BytesIO(b"boom"))

    monkeypatch.setattr(rcli, "urlopen", fake_urlopen)
    with pytest.raises(SystemExit, match="HTTP 500"):
        rcli.search("acme.test")


def test_network_failure_names_the_base(monkeypatch):
    monkeypatch.setenv("RESECURITY_API_KEY", "k")
    monkeypatch.setenv("RESECURITY_API_BASE", "https://dead.example/api")

    def fake_urlopen(req, timeout=45):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(rcli, "urlopen", fake_urlopen)
    with pytest.raises(SystemExit) as exc:
        rcli.search("acme.test")
    assert "dead.example" in str(exc.value)
    assert "RESECURITY_API_BASE" in str(exc.value)


def test_extracts_credentials_and_dedupes(monkeypatch):
    monkeypatch.setenv("RESECURITY_API_KEY", "k")
    payload = {
        "results": [
            {"login": "bob@acme.test", "password": "hunter2", "database": "BigLeak2024"},
            {"login": "bob@acme.test", "password": "hunter2", "database": "BigLeak2024"},  # dup
            {"email": "no-password-here@acme.test"},
        ]
    }

    def fake_urlopen(req, timeout=45):
        return _CtxResp(io.BytesIO(json.dumps(payload).encode()))

    monkeypatch.setattr(rcli, "urlopen", fake_urlopen)
    out = rcli.search("acme.test")
    # A full-email-shaped login is promoted into `email` too (see _extract) —
    # the dedup key is (email or username, password), so the duplicate collapses.
    assert out["credentials"] == [{
        "username": "bob@acme.test", "password": "hunter2", "password_type": "plain",
        "email": "bob@acme.test", "source": "BigLeak2024", "date": "",
    }]
    assert "no-password-here@acme.test" in out["emails"]


def test_extracts_hash_only_credential_with_nested_source_and_date(monkeypatch):
    """The confirmed real shape: no plaintext password, source is a nested
    {name, add_date} dict, not a flat string."""
    payload = [{
        "email": "v@acme.test", "username": "v@acme.test",
        "password": None, "password_hash": "abc123",
        "source": {"name": "BigLeak2024", "add_date": 1618073860},
    }]

    def fake_urlopen(req, timeout=45):
        return _CtxResp(io.BytesIO(json.dumps(payload).encode()))

    monkeypatch.setenv("RESECURITY_API_KEY", "k")
    monkeypatch.setattr(rcli, "urlopen", fake_urlopen)
    out = rcli.search("acme.test")
    assert out["credentials"] == [{
        "username": "v@acme.test", "password": "abc123", "password_type": "hash",
        "email": "v@acme.test", "source": "BigLeak2024", "date": "2021-04-10",
    }]


def test_source_add_date_accepts_the_documented_string_type(monkeypatch):
    """Resecurity's own Swagger schema declares add_date as string($date), even
    though live responses return a bare int — accept both so neither shape
    silently loses the date."""
    payload = [{
        "email": "v@acme.test", "password": "hunter2",
        "source": {"name": "BigLeak2024", "add_date": "1618073860"},
    }]

    def fake_urlopen(req, timeout=45):
        return _CtxResp(io.BytesIO(json.dumps(payload).encode()))

    monkeypatch.setenv("RESECURITY_API_KEY", "k")
    monkeypatch.setattr(rcli, "urlopen", fake_urlopen)
    out = rcli.search("acme.test")
    assert out["credentials"][0]["date"] == "2021-04-10"


def test_non_json_response_falls_back_to_email_scrape(monkeypatch):
    monkeypatch.setenv("RESECURITY_API_KEY", "k")

    def fake_urlopen(req, timeout=45):
        return _CtxResp(io.BytesIO(b"<html>contact leak@acme.test for details</html>"))

    monkeypatch.setattr(rcli, "urlopen", fake_urlopen)
    out = rcli.search("acme.test")
    assert out["emails"] == ["leak@acme.test"]
    assert "warning" in out


def test_limit_is_clamped_to_1_500(monkeypatch):
    monkeypatch.setenv("RESECURITY_API_KEY", "k")
    captured = {}

    def fake_urlopen(req, timeout=45):
        captured["url"] = req.full_url
        return _CtxResp(io.BytesIO(b'{"credentials":[],"emails":[]}'))

    monkeypatch.setattr(rcli, "urlopen", fake_urlopen)
    rcli.search("acme.test", limit=99999)
    assert "per-page=500" in captured["url"]
    rcli.search("acme.test", limit=-5)
    assert "per-page=1" in captured["url"]


# --- resecurity_scan.py wrapper (build_command / parse) ---

def test_wrapper_build_command_requires_target():
    wf = _wrapper()
    with pytest.raises(ValueError):
        wf.build_command(target="")


def test_wrapper_build_command_passes_target_and_limit():
    wf = _wrapper()
    cmd = wf.build_command(target="acme.test", limit=25)
    assert "acme.test" in cmd
    assert "25" in cmd


def test_wrapper_parse_valid_and_invalid_json():
    wf = _wrapper()

    class _R:
        def __init__(self, raw):
            self.raw_stdout = raw

    assert wf.parse(_R('{"credentials": []}')) == {"credentials": []}
    assert wf.parse(_R("not json"))["error"] == "invalid_json"

# _cli_expr's fallback-path quoting is covered generically (all 21 tools
# sharing the pattern, resecurity_scan included) by test_cli_expr_quoting.py.
