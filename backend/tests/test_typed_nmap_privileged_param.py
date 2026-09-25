"""privileged=/host_timeout= must actually be reachable through the typed
FastMCP nmap tools the LLM calls — the registry/command_builder already
understood these params, but the typed tool signature never exposed them, so
the LLM (using the normal typed-tool calling convention) had no way to
request a privileged scan or override the NSE host-timeout at all."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_MOD_PATH = Path(__file__).resolve().parents[2] / "platform-mcp" / "typed_recon_network.py"


def _load():
    spec = importlib.util.spec_from_file_location("_typed_recon_network_priv_test", _MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_typed = _load()


def test_build_params_carries_privileged_flag():
    params = _typed._build_params(target="10.0.0.5", privileged=True)
    assert params["privileged"] == "true"


def test_build_params_omits_privileged_when_false():
    params = _typed._build_params(target="10.0.0.5", privileged=False)
    assert "privileged" not in params


def test_build_params_carries_host_timeout_override():
    params = _typed._build_params(target="10.0.0.5", host_timeout="none")
    assert params["host_timeout"] == "none"


def test_tool_closure_exposes_privileged_and_host_timeout(monkeypatch):
    """End-to-end through register_typed_recon_network_tools: the registered
    nmap_custom_scan callable must accept privileged=/host_timeout= and pass
    them through to execute()'s params, not just _build_params in isolation."""
    captured = {}

    def fake_execute(name, params, *, additional_args, timeout_seconds, engagement_id):
        captured["name"] = name
        captured["params"] = params
        return "ok"

    class FakeMCP:
        def tool(self, name):
            def _decorator(fn):
                if name == "nmap_custom_scan":
                    captured["handler"] = fn
                return fn
            return _decorator

    _typed.register_typed_recon_network_tools(FakeMCP(), execute=fake_execute)
    handler = captured["handler"]
    handler(target="10.0.0.5", flags="-sS -O", privileged=True, host_timeout="none")
    assert captured["params"]["privileged"] == "true"
    assert captured["params"]["host_timeout"] == "none"
