"""Tests for backend configuration endpoints (/api/v1/config)."""

from __future__ import annotations

from unittest.mock import MagicMock

from osprey.api.v1.endpoints.config import LLMConfigUpdate, get_config, set_llm_config
from osprey.core.config import LLMSettings, Settings


def test_get_config_includes_gui_fields_and_platform_details(monkeypatch):
    """Verify get_config returns GUI-expected fields while adding platform configuration."""
    mock_settings = Settings()
    mock_settings.environment = "development"
    mock_settings.database_url = "postgresql+psycopg://admin:supersecret123@db.internal:5432/pentest_db"
    mock_settings.llm = LLMSettings(
        model="openrouter/openrouter/free",
        api_key="sk-test-key",
        api_base="https://openrouter.ai/api/v1",
        max_tokens=8192,
        temperature=0.2,
        max_agent_turns=40,
        tool_timeout=1200,
        request_timeout=450,
    )
    mock_settings.enable_unrestricted_shell = True
    mock_settings.enable_platform_script = True

    monkeypatch.setattr("osprey.api.v1.endpoints.config.get_settings", lambda: mock_settings)

    res = get_config()

    # GUI backwards-compatibility fields
    assert res["model"] == "openrouter/openrouter/free"
    assert res["has_api_key"] is True
    assert res["has_custom_base"] is True
    assert res["max_tokens"] == 8192
    assert res["temperature"] == 0.2
    assert res["max_agent_turns"] == 40

    # Platform details & credentials redaction
    assert res["environment"] == "development"
    assert "supersecret123" not in res["database"]
    assert "postgresql+psycopg://admin:***@db.internal:5432/pentest_db" == res["database"]
    assert res["tool_timeout"] == 1200
    assert res["request_timeout"] == 450
    assert res["features"]["unrestricted_shell"] is True
    assert res["features"]["platform_script"] is True


def test_set_llm_config_preserves_key_for_same_provider(monkeypatch, tmp_path):
    """Switching between model variants of the same provider must NOT wipe the API key."""
    dotenv = tmp_path / ".env"
    dotenv.write_text("LLM_MODEL='openai/gpt-4o'\nLLM_API_KEY='sk-proj-existing'\n", encoding="utf-8")
    monkeypatch.setenv("OSPREY_ENV_FILE", str(dotenv))

    written_updates: dict[str, str] = {}
    def mock_set_dotenv(updates):
        written_updates.update(updates)

    monkeypatch.setattr("osprey.api.v1.endpoints.config.set_dotenv_values", mock_set_dotenv)
    monkeypatch.setattr("osprey.api.v1.endpoints.config.reload_settings", lambda: None)
    mock_llm_service = MagicMock()
    mock_llm_service.settings.model = "gpt-4o-mini"
    mock_llm_service.settings.api_key = "sk-proj-existing"
    mock_llm_service.settings.api_base = ""
    monkeypatch.setattr("osprey.api.v1.endpoints.config.reload_llm_service", lambda: mock_llm_service)
    monkeypatch.setattr("osprey.api.v1.endpoints.config.llm_configured", lambda: True)
    monkeypatch.setattr("osprey.api.v1.endpoints.config.llm_configured_reason", lambda: "")

    current_settings = Settings()
    current_settings.llm = LLMSettings(model="openai/gpt-4o", api_key="sk-proj-existing")
    monkeypatch.setattr("osprey.api.v1.endpoints.config.get_settings", lambda: current_settings)

    # Change to gpt-4o-mini (bare name, same OpenAI provider)
    payload = LLMConfigUpdate(model="gpt-4o-mini")
    set_llm_config(payload)

    # API key should NOT be wiped in written_updates
    assert written_updates.get("LLM_API_KEY") != ""
    assert written_updates.get("LLM_MODEL") == "gpt-4o-mini"


def test_set_llm_config_clears_credentials_when_switching_providers(monkeypatch, tmp_path):
    """Switching to a different provider must clear previous credentials to prevent sending keys to wrong providers."""
    written_updates: dict[str, str] = {}
    def mock_set_dotenv(updates):
        written_updates.update(updates)

    monkeypatch.setattr("osprey.api.v1.endpoints.config.set_dotenv_values", mock_set_dotenv)
    monkeypatch.setattr("osprey.api.v1.endpoints.config.reload_settings", lambda: None)
    mock_llm_service = MagicMock()
    mock_llm_service.settings.model = "groq/llama-3.3-70b-versatile"
    mock_llm_service.settings.api_key = ""
    mock_llm_service.settings.api_base = ""
    monkeypatch.setattr("osprey.api.v1.endpoints.config.reload_llm_service", lambda: mock_llm_service)
    monkeypatch.setattr("osprey.api.v1.endpoints.config.llm_configured", lambda: False)
    monkeypatch.setattr("osprey.api.v1.endpoints.config.llm_configured_reason", lambda: "Key missing")

    current_settings = Settings()
    current_settings.llm = LLMSettings(model="openai/gpt-4o", api_key="sk-proj-existing")
    monkeypatch.setattr("osprey.api.v1.endpoints.config.get_settings", lambda: current_settings)

    # Switch to Groq without supplying a key yet
    payload = LLMConfigUpdate(model="groq/llama-3.3-70b-versatile")
    set_llm_config(payload)

    assert written_updates.get("LLM_MODEL") == "groq/llama-3.3-70b-versatile"
    assert written_updates.get("LLM_API_KEY") == ""
    assert written_updates.get("LLM_API_BASE") == ""
