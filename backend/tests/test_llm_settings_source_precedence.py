"""LLMSettings must prefer a live .env FILE over an already-set process env
var — the reverse of pydantic-settings' default order. In the Docker
deployment, docker-compose's `env_file:`/`environment:` bake LLM_MODEL/
LLM_API_KEY into the container's os.environ once, at `docker compose up`/
`restart`; after that, os.environ is frozen for the container's whole
lifetime while a person editing the project .env expects that edit to take
effect on the next call (get_settings() is deliberately never cached for
exactly this reason). Without the source-order override in
LLMSettings.settings_customise_sources, that fresh env_file read was always
silently shadowed by the stale env var. See
plans/harness/11-operator-trust-and-safety.md Step 2.
"""

from __future__ import annotations

import os

from osprey.core.config import LLMSettings


def test_dotenv_file_wins_over_stale_process_env_var(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("LLM_MODEL=fresh/from-file\nLLM_API_KEY=fresh-key\n", encoding="utf-8")

    # Simulate the Docker case: a process env var baked in at container start,
    # now stale relative to the (live-mounted) file.
    monkeypatch.setenv("LLM_MODEL", "stale/from-container-start")
    monkeypatch.setenv("LLM_API_KEY", "stale-key")

    class _TestLLMSettings(LLMSettings):
        model_config = LLMSettings.model_config.copy()
        model_config["env_file"] = str(env_file)

    settings = _TestLLMSettings()
    assert settings.model == "fresh/from-file"
    assert settings.api_key == "fresh-key"


def test_explicit_kwargs_still_win_over_dotenv_file(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("LLM_MODEL=from-file\n", encoding="utf-8")
    monkeypatch.delenv("LLM_MODEL", raising=False)

    class _TestLLMSettings(LLMSettings):
        model_config = LLMSettings.model_config.copy()
        model_config["env_file"] = str(env_file)

    settings = _TestLLMSettings(model="explicit-kwarg-wins")
    assert settings.model == "explicit-kwarg-wins"


def test_no_dotenv_file_falls_back_to_process_env_var(tmp_path, monkeypatch):
    missing_file = tmp_path / "does-not-exist.env"
    monkeypatch.setenv("LLM_MODEL", "from-env-var")

    class _TestLLMSettings(LLMSettings):
        model_config = LLMSettings.model_config.copy()
        model_config["env_file"] = str(missing_file)

    settings = _TestLLMSettings()
    assert settings.model == "from-env-var"
