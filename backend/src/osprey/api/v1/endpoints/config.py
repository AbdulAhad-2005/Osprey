"""Configuration management endpoints."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field, field_validator

from osprey.core.config import get_settings, reload_settings, set_dotenv_values
from osprey.services.llm_service import (
    _provider_of,
    llm_configured,
    llm_configured_reason,
    reload_llm_service,
)
from osprey.services.tool_registry import reload_tool_availability

router = APIRouter()


class LLMConfigUpdate(BaseModel):
    """Settings surface payload — any user picks a provider + pastes a key.

    The LiteLLM core is provider-agnostic (Claude / DeepSeek / GPT / Groq / local
    Ollama), so this is all a front-end needs to send to switch brains.
    """

    model: str | None = Field(default=None, description="LiteLLM model id, e.g. groq/llama-3.1-8b-instant")
    api_key: str | None = Field(default=None, description="Provider API key (omit/empty for local models)")
    api_base: str | None = Field(default=None, description="Custom base URL (proxies / local Ollama)")

    @field_validator("model", "api_key", "api_base")
    @classmethod
    def single_line(cls, value: str | None) -> str | None:
        if value is not None and any(c in value for c in ("\r", "\n", "\x00")):
            raise ValueError("Settings must contain a single line")
        return value

    @field_validator("model")
    @classmethod
    def model_not_blank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("A model id is required")
        return value


@router.get("/", summary="Show current platform & LLM config")
def get_config() -> dict:
    """Return platform and LLM configuration (safe, credentials redacted)."""
    settings = get_settings()
    llm = settings.llm

    # Redact sensitive credentials in database URL
    db_repr = settings.database_url
    if "@" in db_repr and "://" in db_repr:
        prefix, rest = db_repr.split("://", 1)
        user_pass, host_part = rest.split("@", 1)
        user = user_pass.split(":", 1)[0]
        db_repr = f"{prefix}://{user}:***@{host_part}"

    return {
        "environment": settings.environment,
        "database": db_repr,
        "model": llm.model,
        "has_api_key": bool(llm.api_key),
        "has_custom_base": bool(llm.api_base),
        "max_tokens": llm.max_tokens,
        "temperature": llm.temperature,
        "request_timeout": llm.request_timeout,
        "max_agent_turns": llm.max_agent_turns,
        "tool_timeout": llm.tool_timeout,
        "features": {
            "unrestricted_shell": settings.enable_unrestricted_shell,
            "platform_script": settings.enable_platform_script,
            "learned_skills": settings.enable_learned_skills,
            "pip_install": settings.enable_script_pip_install,
            "apt_install": settings.enable_script_apt_install,
            "slim_skills": settings.slim_context_skills,
        },
    }


@router.post("/llm", summary="Set the LLM provider/key (Settings surface)")
def set_llm_config(update: LLMConfigUpdate) -> dict:
    """Persist provider + key to .env and hot-reload the LLM service.

    This is the storage behind a Settings page: pick a provider/model, paste a
    key. Nothing here is multi-tenant — it configures the single local instance.
    """
    env_updates: dict[str, str] = {}
    current = get_settings().llm
    current_provider = _provider_of(current.model)
    new_provider = _provider_of(update.model) if update.model is not None else current_provider
    provider_changed = update.model is not None and bool(new_provider) and (new_provider != current_provider)
    # Never send one provider's saved credential to a different provider.
    if provider_changed:
        env_updates.update(LLM_API_KEY="", LLM_API_BASE="")
    if update.model is not None:
        env_updates["LLM_MODEL"] = update.model.strip()
    if update.api_key is not None:
        env_updates["LLM_API_KEY"] = update.api_key.strip()
    if update.api_base is not None:
        env_updates["LLM_API_BASE"] = update.api_base.strip()
    if env_updates:
        set_dotenv_values(env_updates)
    reload_settings()
    llm = reload_llm_service()
    return {
        "status": "updated",
        "model": llm.settings.model,
        "has_api_key": bool(llm.settings.api_key),
        "has_custom_base": bool(llm.settings.api_base),
        "usable": llm_configured(),
        "reason": llm_configured_reason(),
    }


@router.post("/reload", summary="Reload config from .env")
def config_reload() -> dict:
    """Re-read .env and recreate the LLM service.

    Call this after changing LLM_MODEL, LLM_API_KEY, etc. in .env — or after
    starting/stopping the Kali tools container, since tool availability is
    also cached for the backend's process lifetime and has no other refresh
    path (see `tool_registry.reload_tool_availability`).
    """
    reload_settings()
    llm = reload_llm_service()
    reload_tool_availability()
    settings = llm.settings
    return {
        "status": "reloaded",
        "model": settings.model,
        "has_api_key": bool(settings.api_key),
        "max_tokens": settings.max_tokens,
        "temperature": settings.temperature,
    }
