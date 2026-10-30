"""Tests for unified /model, /models, /config, and /status commands, as well as warning suppression."""

from __future__ import annotations

import os
import warnings
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic_settings import IncompleteFieldDefinitionWarning

from agent_core.llm import ensure_mcp_compatibility
from cli.commands.slash._meta import (
    handle_config,
    handle_help,
    handle_model,
    handle_models,
    handle_status,
)


def test_settings_lifespan_warning_eliminated():
    """Verify that ensure_mcp_compatibility eliminates IncompleteFieldDefinitionWarning for lifespan."""
    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        ensure_mcp_compatibility()
        import mcp.server.fastmcp.server as s
        s.Settings.model_rebuild(_types_namespace={"FastMCP": s.FastMCP})
        from mcp.server.fastmcp import FastMCP
        _ = FastMCP("test-osprey")

    lifespan_warnings = [
        w for w in recorded
        if issubclass(w.category, IncompleteFieldDefinitionWarning) and "lifespan" in str(w.message)
    ]
    assert len(lifespan_warnings) == 0, f"Expected 0 lifespan warnings, got: {lifespan_warnings}"


def test_handle_model_displays_unified_status(monkeypatch):
    """Verify /model displays a single unified status block without duplicating CLI vs Backend models."""
    monkeypatch.setenv("LLM_MODEL", "openrouter/openrouter/free")
    monkeypatch.setenv("LLM_API_KEY", "sk-or-test-key")
    monkeypatch.delenv("LLM_API_BASE", raising=False)

    printed_info: list[str] = []
    monkeypatch.setattr("cli.commands.slash._meta.print_info", lambda msg: printed_info.append(msg))
    monkeypatch.setattr("cli.commands.slash._meta.print_error", lambda msg: pytest.fail(f"Unexpected error: {msg}"))

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "model": "openrouter/openrouter/free",
        "has_api_key": True,
        "has_custom_base": False,
        "max_tokens": 4096,
        "temperature": 0.1,
    }
    mock_client._client.get.return_value = mock_resp

    handle_model([], mock_client)

    output = "\n".join(printed_info)
    assert "Model:        openrouter/openrouter/free (openrouter)" in output
    assert "API Key:      configured" in output
    assert "API Base:     default" in output
    assert "Status:       ready" in output
    assert "Parameters:   max_tokens=4096, temperature=0.1" in output

    # Must NOT have separate CLI driving vs Backend model sections
    assert "CLI driving model:" not in output
    assert "Backend model:" not in output


def test_handle_model_set_command(monkeypatch, tmp_path):
    """Verify /model set updates env, reloads runtime, and updates .env."""
    dotenv_file = tmp_path / ".env"
    dotenv_file.write_text("LLM_MODEL='initial/model'\n", encoding="utf-8")
    monkeypatch.setenv("OSPREY_ENV_FILE", str(dotenv_file))

    reloaded_model = []
    mock_runtime = MagicMock()
    mock_runtime.reload_model.side_effect = lambda: reloaded_model.append(True)
    monkeypatch.setattr("cli.harness.get_runtime", lambda c: mock_runtime)

    successes: list[str] = []
    monkeypatch.setattr("cli.commands.slash._meta.print_success", lambda msg: successes.append(msg))

    mock_client = MagicMock()
    mock_client.base_url = "http://localhost:9000"
    # Mock backend accepting the update
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_client._client.post.return_value = mock_resp

    # Run /model set groq/llama-3.3-70b-versatile gsk_12345 --base https://api.groq.com/openai/v1
    handle_model(
        ["set", "groq/llama-3.3-70b-versatile", "gsk_12345", "--base", "https://api.groq.com/openai/v1"],
        mock_client,
    )

    assert os.environ.get("LLM_MODEL") == "groq/llama-3.3-70b-versatile"
    assert os.environ.get("LLM_API_KEY") == "gsk_12345"
    assert os.environ.get("LLM_API_BASE") == "https://api.groq.com/openai/v1"
    assert len(reloaded_model) == 1
    assert any("Model updated to: groq/llama-3.3-70b-versatile" in s for s in successes)


def test_handle_model_reload_command(monkeypatch, tmp_path):
    """Verify /model reload re-reads .env and triggers model reset."""
    dotenv_file = tmp_path / ".env"
    dotenv_file.write_text("LLM_MODEL='anthropic/claude-3-5-sonnet-20241022'\n", encoding="utf-8")
    monkeypatch.setenv("OSPREY_ENV_FILE", str(dotenv_file))

    reloaded_runtime = []
    mock_runtime = MagicMock()
    mock_runtime.reload_model.side_effect = lambda: reloaded_runtime.append(True)
    monkeypatch.setattr("cli.harness.get_runtime", lambda c: mock_runtime)

    successes: list[str] = []
    monkeypatch.setattr("cli.commands.slash._meta.print_success", lambda msg: successes.append(msg))

    mock_client = MagicMock()
    handle_model(["reload"], mock_client)

    assert len(reloaded_runtime) == 1
    assert any("Reloaded model from .env: anthropic/claude-3-5-sonnet-20241022" in s for s in successes)


def test_handle_models_with_provider_filter(monkeypatch):
    """Verify /models filters models by provider when an argument is provided."""
    mock_client = MagicMock()
    mock_client.list_models.return_value = [
        {"name": "groq/llama-3.3-70b-versatile", "provider": "groq", "description": "Fast Llama", "active": False},
        {"name": "groq/llama-3.1-8b-instant", "provider": "groq", "description": "Instant", "active": False},
        {"name": "openai/gpt-4o", "provider": "openai", "description": "GPT 4o", "active": False},
    ]

    called_kwargs: dict[str, Any] = {}
    def mock_print_models(models, **kwargs):
        called_kwargs.update(kwargs)
        called_kwargs["models"] = models

    monkeypatch.setattr("cli.commands.slash._meta.print_models", mock_print_models)

    handle_models(["groq"], mock_client)
    assert called_kwargs.get("filter_provider") == "groq"
    assert len(called_kwargs.get("models", [])) == 3


def test_handle_models_detects_local_ollama(monkeypatch):
    """Verify /models queries localhost:11434 and discovers locally installed models."""
    mock_client = MagicMock()
    mock_client.list_models.return_value = []

    mock_ollama_resp = MagicMock()
    mock_ollama_resp.status_code = 200
    mock_ollama_resp.json.return_value = {
        "models": [{"name": "qwen2.5:14b"}, {"name": "llama3.1:latest"}]
    }

    monkeypatch.setattr("httpx.get", lambda url, timeout: mock_ollama_resp)

    called_kwargs: dict[str, Any] = {}
    def mock_print_models(models, **kwargs):
        called_kwargs.update(kwargs)

    monkeypatch.setattr("cli.commands.slash._meta.print_models", mock_print_models)

    handle_models([], mock_client)
    assert called_kwargs.get("local_ollama_models") == ["qwen2.5:14b", "llama3.1:latest"]


def test_handle_status_shows_unified_model_line(monkeypatch):
    """Verify /status displays a single unified Model line."""
    monkeypatch.setenv("LLM_MODEL", "groq/llama-3.3-70b-versatile")
    monkeypatch.setenv("LLM_API_KEY", "gsk_test")

    mock_client = MagicMock()
    mock_client.base_url = "http://localhost:9000"
    mock_client.health.return_value = {"status": "ok"}
    mock_client.active_engagement_id = None

    mock_runtime = MagicMock()
    mock_runtime.transcript.detail_mode = "compact"
    mock_runtime.transcript.recent.return_value = []
    monkeypatch.setattr("cli.harness.get_runtime", lambda c: mock_runtime)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"model": "groq/llama-3.3-70b-versatile", "model_active": True, "tools_available": 134}
    mock_client._client.get.return_value = mock_resp

    printed_info: list[str] = []
    monkeypatch.setattr("cli.commands.slash._meta.print_info", lambda msg: printed_info.append(msg))

    handle_status([], mock_client)

    output = "\n".join(printed_info)
    assert "Model:      groq/llama-3.3-70b-versatile (ready)" in output
    assert "CLI driving model:" not in output
    assert "Backend model:" not in output


def test_handle_config_displays_platform_settings_and_redacts_credentials(monkeypatch):
    """Verify /config displays platform settings with database credentials redacted."""
    mock_client = MagicMock()
    mock_client.base_url = "http://localhost:9000"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "environment": "development",
        "database": "postgresql+psycopg://pentest:***@localhost:5432/pentest",
        "model": "openrouter/openrouter/free",
        "has_api_key": True,
        "tool_timeout": 900,
        "request_timeout": 300,
        "max_agent_turns": 30,
        "features": {
            "unrestricted_shell": True,
            "platform_script": True,
            "learned_skills": True,
            "pip_install": True,
            "apt_install": False,
        },
    }
    mock_client._client.get.return_value = mock_resp

    printed_info: list[str] = []
    monkeypatch.setattr("cli.commands.slash._meta.print_info", lambda msg: printed_info.append(msg))

    handle_config([], mock_client)

    output = "\n".join(printed_info)
    assert "Platform Configuration:" in output
    assert "Backend URL:        http://localhost:9000" in output
    assert "Environment:        development" in output
    assert "postgresql+psycopg://pentest:***@localhost:5432/pentest" in output
    assert "Tool Timeout:       900s" in output
    assert "Unrestricted Shell: enabled" in output
    assert "Apt Install:        disabled" in output
    assert "Active Model:         openrouter/openrouter/free (ready)" in output
    # Must NOT have redundant backend model rows
    assert "Backend Model:" not in output
    assert "Backend Custom Base:" not in output


def test_handle_help_no_duplicates_and_includes_missing_commands(monkeypatch):
    """Verify /help contains no duplicate entries (like /cancel) and includes /agent, /profile, /skill."""
    command_dict: dict[str, str] = {}
    def mock_print_command_help(cmds):
        command_dict.update(cmds)

    monkeypatch.setattr("cli.commands.slash._meta.print_command_help", mock_print_command_help)
    monkeypatch.setattr("cli.commands.slash._meta.print_info", lambda msg: None)

    handle_help([], MagicMock())

    # Ensure /cancel appears only once
    cancel_keys = [k for k in command_dict if k.startswith("/cancel")]
    assert len(cancel_keys) == 1, f"Expected 1 /cancel command, found: {cancel_keys}"

    # Ensure /agent, /profile, /skill, /model, /models are present
    assert any("/agent" in k for k in command_dict)
    assert any("/profile" in k for k in command_dict)
    assert any("/skill" in k for k in command_dict)
    assert any("/models" in k for k in command_dict)
    assert any("/model" in k for k in command_dict)
