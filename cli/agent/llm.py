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

import asyncio
import os
from dataclasses import dataclass
from typing import Any

# Retry schedule for transient provider-side errors in complete() below —
# 3 attempts total (2 retries), short backoff since these resolve in seconds
# or not at all; a longer wait wouldn't suit an interactive turn.
_TRANSIENT_RETRY_ATTEMPTS = 2
_TRANSIENT_RETRY_BACKOFF_SECONDS = (2, 4)

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
    # 0 (default, unset) = send every registered tool's full schema every
    # turn, exactly as this CLI has always worked — fine for any model/
    # provider with normal context and per-minute-token room, which is most
    # of them. Set LLM_TOOL_SCHEMA_BUDGET_TOKENS in .env only when a
    # SPECIFIC provider's free-tier token-per-minute cap is smaller than the
    # full tool catalog (Groq's 8K TPM on some models, for instance) — see
    # cli/agent/tools.py's get_tool_schemas() for what actually changes:
    # fewer tools sent directly, none of them made unreachable.
    tool_schema_budget_tokens: int = 0

    @classmethod
    def from_env(cls) -> "CLIModelConfig":
        model = (os.getenv("LLM_MODEL") or "").strip()
        api_key = (os.getenv("LLM_API_KEY") or "").strip()
        api_base = (os.getenv("LLM_API_BASE") or "").strip()
        budget_raw = (os.getenv("LLM_TOOL_SCHEMA_BUDGET_TOKENS") or "").strip()
        try:
            tool_schema_budget_tokens = int(budget_raw) if budget_raw else 0
        except ValueError:
            tool_schema_budget_tokens = 0
        if not model or not api_key:
            raise LLMNotConfiguredError(
                "No driving model configured for this CLI. Set LLM_MODEL and "
                "LLM_API_KEY in your own .env (any LiteLLM-supported provider — "
                "OpenAI, Anthropic, Gemini, Groq, DeepSeek, Ollama, ...). This is "
                "independent of the backend's own .env."
            )
        return cls(
            model=model,
            api_key=api_key,
            api_base=api_base,
            tool_schema_budget_tokens=tool_schema_budget_tokens,
        )


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
    if isinstance(exc, (litellm.ServiceUnavailableError, litellm.InternalServerError)):
        return (
            f"Your LLM provider is temporarily overloaded ({exc.__class__.__name__}) — "
            f"already retried {_TRANSIENT_RETRY_ATTEMPTS} times with backoff and it's "
            "still down. Wait a bit and try again, or switch LLM_MODEL in your .env "
            "to a different provider/model."
        )
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

    # Provider-side infrastructure hiccups (a 503 "high demand, try again
    # later", a transient 5xx, a dropped connection) are not the same class
    # of failure as a bad key or a rejected request — those two genuinely
    # need the operator to do something; these resolve themselves in
    # seconds. Retrying automatically here means "the model is briefly
    # overloaded" doesn't end the whole turn — only RateLimitError/
    # AuthenticationError/BadRequestError (unretryable — a delay changes
    # nothing) reach the caller on the first attempt.
    transient = (
        litellm.ServiceUnavailableError,
        litellm.InternalServerError,
        litellm.Timeout,
        litellm.APIConnectionError,
    )
    for attempt in range(_TRANSIENT_RETRY_ATTEMPTS + 1):
        try:
            response = await litellm.acompletion(**kwargs)
            return response.model_dump() if hasattr(response, "model_dump") else dict(response)
        except transient:
            if attempt == _TRANSIENT_RETRY_ATTEMPTS:
                raise
            await asyncio.sleep(_TRANSIENT_RETRY_BACKOFF_SECONDS[attempt])
    raise AssertionError("unreachable")  # loop always returns or raises
