from types import SimpleNamespace

import pytest
from dotenv import dotenv_values
from pydantic import ValidationError

from osprey.api.v1.endpoints import config as endpoint
from osprey.core import config


def test_dotenv_round_trip_and_duplicate_definitions(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# preserved\nLLM_API_KEY=old\nLLM_API_KEY=duplicate\nUNRELATED=yes\n")
    monkeypatch.setattr(config, "_DOTENV", str(env))
    value = "a # b'c\\d"
    config.set_dotenv_values({"LLM_API_KEY": value, "LLM_API_BASE": ""})
    assert dotenv_values(env)["LLM_API_KEY"] == value
    assert dotenv_values(env)["UNRELATED"] == "yes"
    assert dotenv_values(env)["LLM_API_BASE"] == ""


@pytest.mark.parametrize("field", ["model", "api_key", "api_base"])
def test_settings_reject_multiline_values(field):
    with pytest.raises(ValidationError):
        endpoint.LLMConfigUpdate(**{field: "value\nANOTHER_SETTING=bad"})


def test_provider_switch_clears_stale_credentials_but_same_provider_keeps(monkeypatch):
    settings = SimpleNamespace(model="openai/old", api_key="old", api_base="https://old.test")
    writes = []
    monkeypatch.setattr(endpoint, "get_settings", lambda: SimpleNamespace(llm=settings))
    monkeypatch.setattr(endpoint, "set_dotenv_values", lambda values: writes.append(values))
    monkeypatch.setattr(endpoint, "reload_settings", lambda: None)
    monkeypatch.setattr(endpoint, "reload_llm_service", lambda: SimpleNamespace(settings=settings))
    monkeypatch.setattr(endpoint, "llm_configured", lambda: True)
    monkeypatch.setattr(endpoint, "llm_configured_reason", lambda: "")
    endpoint.set_llm_config(endpoint.LLMConfigUpdate(model="openai/new"))
    assert writes[-1] == {"LLM_MODEL": "openai/new"}
    endpoint.set_llm_config(endpoint.LLMConfigUpdate(model="ollama/local"))
    assert writes[-1] == {"LLM_MODEL": "ollama/local", "LLM_API_KEY": "", "LLM_API_BASE": ""}
    endpoint.set_llm_config(endpoint.LLMConfigUpdate(model="anthropic/model", api_key="new"))
    assert writes[-1]["LLM_API_KEY"] == "new"
