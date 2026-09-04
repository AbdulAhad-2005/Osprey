from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# Resolve .env relative to this file (config.py), not CWD, so it works
# regardless of where the backend process is started from.
_HERE = Path(__file__).resolve().parent


def _find_dotenv() -> str:
    """Walk up from this file to find the project root .env."""
    current = _HERE
    for _ in range(10):
        candidate = current / ".env"
        if candidate.is_file():
            return str(candidate)
        current = current.parent
    return str(_HERE / ".env")


_DOTENV = _find_dotenv()


def set_dotenv_values(updates: dict[str, str]) -> str:
    """Persist key=value pairs into the project .env (create/update in place).

    Local-first, single-user: the person running the platform sets their own LLM
    key here (via the Settings surface). Returns the .env path written. Empty
    values are written as empty (explicit unset), not skipped.
    """
    path = Path(_DOTENV)
    lines: list[str] = []
    if path.is_file():
        lines = path.read_text(encoding="utf-8").splitlines()
    remaining = dict(updates)
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in remaining:
                out.append(f"{key}={remaining.pop(key)}")
                continue
        out.append(line)
    for key, value in remaining.items():
        out.append(f"{key}={value}")
    path.write_text("\n".join(out).rstrip("\n") + "\n", encoding="utf-8")
    return str(path)


class LLMSettings(BaseSettings):
    """LLM provider configuration.

    Supported models follow the LiteLLM format:
      - groq/compound-mini, groq/llama-3.1-8b-instant (free)
      - deepseek/deepseek-chat (very cheap)
      - openai/gpt-4o
      - anthropic/claude-sonnet-4-20250514
      - gemini/gemini-3.5-flash (recommended)
      - ollama/llama3.1 (local, free)

    Full provider list: https://docs.litellm.ai/docs/providers
    """

    model_config = SettingsConfigDict(env_prefix="LLM_", env_file=_DOTENV, env_file_encoding="utf-8", extra="ignore")

    model: str = Field(default="<model-provider>/<model-name>", description="LiteLLM model identifier")
    api_key: str = Field(default="", description="API key for the LLM provider")
    api_base: str = Field(default="", description="Custom API base URL (for proxies, local models, etc.)")
    max_tokens: int = Field(default=4096, ge=1, le=128000, description="Max tokens per response")
    temperature: float = Field(default=0.1, ge=0.0, le=2.0, description="Sampling temperature")
    request_timeout: int = Field(default=300, ge=10, le=600, description="Request timeout in seconds")
    max_retries: int = Field(default=3, ge=0, le=10, description="Max retries on transient errors")
    max_agent_turns: int = Field(default=30, ge=1, le=200, description="Max LLM turns per agent run")
    tool_timeout: int = Field(
        default=900,
        ge=60,
        le=3600,
        description="Max seconds per tool run (nmap, amass, gau, etc.)",
    )


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_DOTENV, env_file_encoding="utf-8", extra="ignore")

    environment: str = "development"
    database_url: str = "postgresql+psycopg://pentest:pentest@localhost:5432/pentest"
    temporal_address: str = "localhost:7233"
    llm: LLMSettings = Field(default_factory=LLMSettings)

    # Prefer OpenCode MCP path; built-in LiteLLM agent is optional/legacy.
    enable_builtin_agent: bool = Field(
        default=False,
        description="Enable POST /api/v1/agent/chat LiteLLM commander (off by default)",
    )
    # Condensed skills in commander context (overview + shared only).
    slim_context_skills: bool = Field(
        default=True,
        description="Load phase-overview + shared skills instead of full skill dump",
    )
    # Learned-skills tier: let the LLM PROPOSE a new operator-local skill (gated by
    # human approval, stored git-ignored in skills/learned/). On by default.
    enable_learned_skills: bool = Field(
        default=True,
        description="Enable platform_propose_skill + the operator-approved learned-skills tier",
    )
    # Write→run scripts (python/bash) inside Kali.
    enable_platform_script: bool = Field(
        default=True,
        description="Enable POST /api/v1/mcp/script for adaptive script execution",
    )
    enable_script_pip_install: bool = Field(
        default=True,
        description="Allow gated pip install --user for script dependencies",
    )
    enable_script_apt_install: bool = Field(
        default=True,
        description="Allow gated apt-get install from a small allowlist",
    )
    # Unrestricted raw bash for platform_shell (loops, ;, &&, $(), redirects) —
    # same capability as a raw shell, executed inside the Kali
    # container as mcpuser. Set false to fall back to the allowlisted argv mode.
    enable_unrestricted_shell: bool = Field(
        default=True,
        description="platform_shell runs raw bash -c (no allowlist/metachar ban)",
    )


# Not cached — always reads .env fresh so config changes are picked up
# immediately without needing to restart the backend.
def get_settings() -> Settings:
    return Settings()


def reload_settings() -> Settings:
    return get_settings()
