"""The typed intelx_scan/resecurity_scan tools must actually expose mode= and
limit= — their blurbs document both, but the generic OSINT tool builder didn't
wire either through to execute(), so an LLM could never set them via the typed
tool (only the raw platform_exec JSON path could)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def typed_osint():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location("_test_typed_osint", ROOT / "typed_osint.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_params_includes_mode_and_limit(typed_osint):
    params = typed_osint._build_params(target="acme.test", mode="leaks", limit=50)
    assert params["mode"] == "leaks"
    assert params["limit"] == 50
    assert params["target"] == "acme.test"


def test_build_params_omits_unset_mode_and_limit(typed_osint):
    params = typed_osint._build_params(target="acme.test")
    assert "mode" not in params
    assert "limit" not in params


def test_registered_tool_forwards_mode_and_limit_to_execute(typed_osint):
    calls = []

    def fake_execute(name, params, *, additional_args="", timeout_seconds=0, engagement_id=""):
        calls.append((name, params))
        return "ok"

    class _FakeMCP:
        def tool(self, name):
            def deco(fn):
                setattr(self, name, fn)
                return fn
            return deco

    mcp = _FakeMCP()
    typed_osint.register_typed_osint_tools(mcp, execute=fake_execute)
    mcp.resecurity_scan(target="acme.test", limit=25)
    mcp.intelx_scan(target="acme.test", mode="phonebook")

    by_name = dict(calls)
    assert by_name["resecurity_scan"]["limit"] == 25
    assert by_name["intelx_scan"]["mode"] == "phonebook"
