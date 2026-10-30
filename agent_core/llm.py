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
import re
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


def ensure_mcp_compatibility() -> None:
    """Ensure backward-compatibility between mcp 1.x and newer third-party libraries (e.g. litellm).

    LiteLLM experimental MCP integrations import CacheableResult from mcp.types, which was
    only introduced in mcp 2.x. Providing a compatible dummy class on mcp.types allows
    these imports to succeed cleanly without requiring an invasive library fork or breaking mcp 1.x pins.
    """
    try:
        import mcp.types as _mcp_types

        if not hasattr(_mcp_types, "CacheableResult"):
            class CacheableResult:
                """Backward compatibility shim for mcp < 2.0 when newer litellm expects CacheableResult."""

            _mcp_types.CacheableResult = CacheableResult
    except (ImportError, AttributeError):
        pass


# Apply compatibility shim as soon as agent_core.llm is loaded.
ensure_mcp_compatibility()


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
    # agent_core/tools.py's get_tool_schemas() for what actually changes:
    # fewer tools sent directly, none of them made unreachable.
    tool_schema_budget_tokens: int = 0

    @classmethod
    def from_env(cls) -> CLIModelConfig:
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


_EXCEPTION_PREFIX_RE = re.compile(
    r"^(?:(?:[a-zA-Z_]\w*\.)*(?:APIConnectionError|Timeout|BadRequestError|RateLimitError|AuthenticationError|ServiceUnavailableError|InternalServerError|[A-Za-z_]+Exception|[A-Za-z_]+Error)):\s*",
    re.IGNORECASE,
)


def _clean_error_message(text: str) -> str:
    """Strip redundant exception class and provider wrapper prefixes (e.g. 'OpenrouterException - ')."""
    cleaned = text.strip()
    while True:
        # Strip provider prefixes e.g. "OpenrouterException - "
        cleaned = re.sub(r"^[A-Za-z_]+Exception\s*-\s*", "", cleaned).strip()
        new_cleaned = _EXCEPTION_PREFIX_RE.sub("", cleaned).strip()
        if new_cleaned == cleaned:
            break
        cleaned = new_cleaned
    return cleaned


def _extract_root_cause(exc: Exception) -> tuple[Exception, str]:
    """Traverse __cause__, __context__, and attributes like original_exception
    to find the true underlying root exception and a clean detail string."""
    current: Exception = exc
    visited: set[int] = set()
    chain: list[Exception] = []
    while current and id(current) not in visited:
        visited.add(id(current))
        chain.append(current)
        nxt = current.__cause__ or current.__context__
        if not nxt and hasattr(current, "original_exception") and isinstance(current.original_exception, Exception):
            nxt = current.original_exception
        if not nxt and hasattr(current, "original_error") and isinstance(current.original_error, Exception):
            nxt = current.original_error
        current = nxt

    root = chain[-1] if chain else exc
    # Prefer the deepest non-empty message in the chain
    for candidate in reversed(chain):
        msg = str(candidate).strip()
        if msg:
            return root, _clean_error_message(msg)
    return root, _clean_error_message(str(exc))


def _is_internal_runtime_error(exc: Exception, detail: str = "") -> bool:
    """Detect whether an exception (possibly masked by LiteLLM inside APIConnectionError)
    is actually an internal Python/library error (e.g. import failure, type error, missing attribute)
    rather than a real network/provider connectivity issue."""
    root, clean_detail = _extract_root_cause(exc)
    if isinstance(
        root,
        (ImportError, ModuleNotFoundError, AttributeError, TypeError, NameError, SyntaxError, KeyError, IndexError),
    ):
        return True

    text = f"{exc} {detail} {clean_detail}".lower()
    patterns = (
        "cannot import name",
        "no module named",
        "importerror",
        "modulenotfounderror",
        "attributeerror",
        "typeerror",
        "nameerror",
        "syntaxerror",
        "traceback (most recent call last)",
    )
    return any(p in text for p in patterns)


def friendly_llm_error(exc: Exception) -> str:
    """One clean line for a failed model call — a provider outage, a rate
    limit, or a bad key should never surface as a raw traceback; the CLI's
    whole session shouldn't die because one turn's completion call failed.

    Inspects exception chaining and underlying causes so that internal runtime
    errors wrapped by LiteLLM (e.g. ImportErrors masked as APIConnectionError)
    are surfaced truthfully rather than falsely attributed to network drops.
    """
    import litellm

    root, detail = _extract_root_cause(exc)

    # 1. Internal code / library / runtime error (even if wrapped as APIConnectionError by litellm)
    if _is_internal_runtime_error(exc, detail):
        root_cls = root.__class__.__name__ if root is not exc else "RuntimeError"
        return f"LLM client runtime error ({root_cls}): {detail}"

    # 2. Rate limit
    if isinstance(exc, litellm.RateLimitError) or isinstance(root, litellm.RateLimitError):
        msg = detail or str(exc).strip()
        return (
            f"Rate limited by your LLM provider ({msg}). Wait for it to reset, or "
            "switch LLM_MODEL/LLM_API_KEY in your .env to a different "
            "provider/model, then try again."
        )

    # 3. Authentication
    if isinstance(exc, litellm.AuthenticationError) or isinstance(root, litellm.AuthenticationError):
        msg = f": {detail}" if detail else ""
        return f"Authentication failed — check LLM_API_KEY in your .env{msg}."

    # 4. Service unavailable / internal server error (transient overload)
    if isinstance(exc, (litellm.ServiceUnavailableError, litellm.InternalServerError)) or isinstance(
        root, (litellm.ServiceUnavailableError, litellm.InternalServerError)
    ):
        return (
            f"Your LLM provider is temporarily overloaded ({exc.__class__.__name__}: {detail or 'service unavailable'}) — "
            f"already retried {_TRANSIENT_RETRY_ATTEMPTS} times with backoff and it's "
            "still down. Wait a bit and try again, or switch LLM_MODEL in your .env "
            "to a different provider/model."
        )

    # 5. Network connectivity / Timeout
    if isinstance(exc, litellm.Timeout) or isinstance(root, litellm.Timeout):
        timeout_msg = f": {detail}" if detail else ""
        return f"LLM provider request timed out{timeout_msg}. Check your connection and try again."

    if isinstance(exc, litellm.APIConnectionError) or isinstance(root, litellm.APIConnectionError):
        conn_msg = f": {detail}" if detail else ""
        return f"Could not reach the LLM provider ({exc.__class__.__name__}){conn_msg}. Check your connection and try again."

    # 6. Bad request (prompt formatting, parameter validation, etc.)
    if isinstance(exc, litellm.BadRequestError) or isinstance(root, litellm.BadRequestError):
        return f"The provider rejected the request ({exc.__class__.__name__}): {detail or exc}"

    # 7. Fallback for unmapped exceptions
    return f"LLM request failed ({exc.__class__.__name__}): {detail or exc}"


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

    litellm.suppress_debug_info = True
    # Drop unknown or unsupported params before sending to provider APIs
    litellm.drop_params = True
    litellm.modify_params = True
    _disable_debugging()

    kwargs: dict[str, Any] = {
        "model": config.model,
        "api_key": config.api_key,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "timeout": 120,
        # Bypass LiteLLM's experimental internal MCP proxy / catalog handler.
        # Osprey manages its own tool execution via EmbeddedToolGateway and
        # supplies standard OpenAI tool schemas directly to the provider.
        "_skip_mcp_handler": True,
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
        except transient as exc:
            # Never retry internal runtime errors that LiteLLM wrapped into APIConnectionError
            if _is_internal_runtime_error(exc, str(exc)):
                raise
            if attempt == _TRANSIENT_RETRY_ATTEMPTS:
                raise
            await asyncio.sleep(_TRANSIENT_RETRY_BACKOFF_SECONDS[attempt])
    raise AssertionError("unreachable")  # loop always returns or raises
