"""web_fingerprint tool: build_command shape + the fingerprint matching logic,
including the TLS-verify fallback (appliances serve self-signed certs, so a
verified request must degrade to unverified and flag it rather than fail)."""

from __future__ import annotations

import importlib.util
import io
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MCP_SERVERS = ROOT / "mcp-servers"


def _load():
    if str(MCP_SERVERS) not in sys.path:
        sys.path.insert(0, str(MCP_SERVERS))
    path = MCP_SERVERS / "network" / "tools" / "web_fingerprint.py"
    spec = importlib.util.spec_from_file_location("_test_web_fingerprint", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wf = _load()


class _Resp:
    def __init__(self, body=b"", headers=None, url="https://t.test/", status=200):
        self._b, self.headers, self._u, self.status = body, headers or {}, url, status

    def read(self, n=None):
        return self._b[:n] if n else self._b

    def geturl(self):
        return self._u

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patch(monkeypatch, fn):
    monkeypatch.setattr(urllib.request, "urlopen", fn)


def test_build_command_shape_and_target_alias():
    cmd = wf.build_command(url="https://a.test", timeout="15", verify_tls="false")
    assert "--url" in cmd and "--timeout" in cmd and "--verify-tls false" in cmd
    assert "https://a.test" in cmd
    assert "al.test" in wf.build_command(target="al.test")  # target aliases url


def test_build_command_requires_url():
    import pytest

    with pytest.raises(ValueError):
        wf.build_command(url="")


def test_fingerprint_matches_vendor_and_bounds_confidence(monkeypatch):
    _patch(monkeypatch, lambda req, timeout=10, context=None: _Resp(
        body=b"<title>FortiGate</title> fortigate forticlient /remote/login", url="https://fw.test/"))
    r = wf.fingerprint("https://fw.test", verify_tls=False)
    assert r["best_match"]["vendor"] == "Fortinet"
    assert 0 < r["best_match"]["confidence"] <= 0.99
    assert r["title"] == "FortiGate"
    assert r["tls_verification_failed"] is False


def test_fingerprint_no_match(monkeypatch):
    _patch(monkeypatch, lambda req, timeout=10, context=None: _Resp(body=b"<title>Hi</title>nothing", url="https://x.test/"))
    r = wf.fingerprint("https://x.test", verify_tls=False)
    assert r["best_match"] is None and r["matches"] == []


def test_http_error_page_still_fingerprints(monkeypatch):
    def http403(req, timeout=10, context=None):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {"Server": "SonicWALL"},
                                     io.BytesIO(b"sonicwall sonicos"))
    _patch(monkeypatch, http403)
    r = wf.fingerprint("https://s.test", verify_tls=False)
    assert r["best_match"]["vendor"] == "SonicWall" and r["status"] == 403


def test_tls_verify_failure_falls_back_and_flags(monkeypatch):
    calls = {"n": 0}

    def ssl_then_ok(req, timeout=10, context=None):
        calls["n"] += 1
        if context is None:  # the verified attempt
            raise urllib.error.URLError(ssl.SSLCertVerificationError("self-signed certificate"))
        return _Resp(body=b"mikrotik routeros webfig", url="https://m.test/")

    _patch(monkeypatch, ssl_then_ok)
    r = wf.fingerprint("https://m.test")  # verify_tls defaults True
    assert r["best_match"]["vendor"] == "MikroTik"
    assert r["tls_verification_failed"] is True
    assert calls["n"] == 2  # verified, then one unverified retry


def test_non_cert_connection_error_does_not_fall_back(monkeypatch):
    def refused(req, timeout=10, context=None):
        raise urllib.error.URLError("connection refused")
    _patch(monkeypatch, refused)
    r = wf.fingerprint("https://dead.test")
    assert r.get("error") and r["matches"] == []
