"""The CLI's own model client — the CLI supplies the brain now.

A thin wrapper around `litellm` (the same multi-provider calling library the
backend depends on, used here as a plain third-party library — not shared
application logic, no import of backend code). Reads `LLM_MODEL`/
`LLM_API_KEY`/`LLM_API_BASE` from the CLI's own process environment
(loaded via `python-dotenv` in `cli/main.py`, same convention already used
for `API_BASE_URL`) — independent of whatever the backend's own `.env` has
configured, so the CLI is never depending on a key it doesn't control.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

# litellm's own `_logging.py` defaults LITELLM_LOG to "DEBUG" when unset —
# read once, at that module's import time, so this must be set before the
# first `import litellm` anywhere in the process (the lazy import in
# complete() below is the first one, and this module always loads before
# complete() can be called). Set here, not swallowed by redirecting output
# elsewhere, and setdefault so an operator who explicitly wants
# LITELLM_LOG=DEBUG for troubleshooting still gets it.
os.environ.setdefault("LITELLM_LOG", "WARNING")


class LLMNotConfiguredError(RuntimeError):
    pass


@dataclass
class CLIModelConfig:
    model: str
    api_key: str
    api_base: str = ""

    @classmethod
    def from_env(cls) -> "CLIModelConfig":
        model = (os.getenv("LLM_MODEL") or "").strip()
        api_key = (os.getenv("LLM_API_KEY") or "").strip()
        api_base = (os.getenv("LLM_API_BASE") or "").strip()
        if not model or not api_key:
            raise LLMNotConfiguredError(
                "No driving model configured for this CLI. Set LLM_MODEL and "
                "LLM_API_KEY in your own .env (any LiteLLM-supported provider — "
                "OpenAI, Anthropic, Gemini, Groq, DeepSeek, Ollama, ...). This is "
                "independent of the backend's own .env."
            )
        return cls(model=model, api_key=api_key, api_base=api_base)


def friendly_llm_error(exc: Exception) -> str:
    """One clean line for a failed model call — a provider outage, a rate
    limit, or a bad key should never surface as a raw traceback; the CLI's
    whole session shouldn't die because one turn's completion call failed."""
    import litellm

    if isinstance(exc, litellm.RateLimitError):
        return (
            "Rate limited by your LLM provider. Wait for it to reset, or "
            "switch LLM_MODEL/LLM_API_KEY in your .env to a different "
            "provider/model, then try again."
        )
    if isinstance(exc, litellm.AuthenticationError):
        return "Authentication failed — check LLM_API_KEY in your .env."
    if isinstance(exc, (litellm.APIConnectionError, litellm.Timeout)):
        return f"Could not reach the LLM provider ({exc.__class__.__name__}). Check your connection and try again."
    if isinstance(exc, litellm.BadRequestError):
        return f"The provider rejected the request: {exc}"
    return f"LLM request failed ({exc.__class__.__name__}): {exc}"


async def complete(
    *,
    config: CLIModelConfig,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    temperature: float = 0.2,
    max_tokens: int = 4096,
) -> dict[str, Any]:
    """One chat-completion call with tool-calling. Returns the raw litellm
    response dict (OpenAI-shaped: choices[0].message.{content,tool_calls})."""
    import litellm
    from litellm._logging import _disable_debugging

    # The LITELLM_LOG env var (set on import, above) only lowers the level
    # some of litellm's logging goes through — its own verbose/router/proxy
    # loggers run a separate internal logging-worker path that ignores that
    # level, so the level alone still let "LiteLLM completion() model=..."
    # and worker-flush chatter through. This is litellm's own documented
    # disable switch for exactly those loggers — a real off switch, not a
    # broader level tweak that happened not to cover this case.
    litellm.suppress_debug_info = True
    _disable_debugging()

    kwargs: dict[str, Any] = {
        "model": config.model,
        "api_key": config.api_key,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "timeout": 120,
    }
    if config.api_base:
        kwargs["api_base"] = config.api_base
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"

    response = await litellm.acompletion(**kwargs)
    return response.model_dump() if hasattr(response, "model_dump") else dict(response)
