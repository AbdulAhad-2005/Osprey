"""Tests for LLM compatibility shims, exception unwrapping, and error diagnostics."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import litellm
import mcp.types
import pytest

from agent_core.llm import (
    CLIModelConfig,
    _clean_error_message,
    _is_internal_runtime_error,
    complete,
    ensure_mcp_compatibility,
    friendly_llm_error,
)


def _run(coro):
    return asyncio.run(coro)


def test_clean_error_message_strips_nested_prefixes():
    """Verify that _clean_error_message cleanly strips provider and exception class prefixes."""
    raw = "OpenrouterException - litellm.exceptions.APIConnectionError: cannot import name 'CacheableResult' from 'mcp.types'"
    assert _clean_error_message(raw) == "cannot import name 'CacheableResult' from 'mcp.types'"

    raw2 = "GeminiException: RateLimitError: 429 Resource has been exhausted"
    assert _clean_error_message(raw2) == "429 Resource has been exhausted"

    raw3 = "Connection refused to 127.0.0.1:11434"
    assert _clean_error_message(raw3) == "Connection refused to 127.0.0.1:11434"


def test_ensure_mcp_compatibility():
    """Verify that CacheableResult exists on mcp.types and can be imported cleanly."""
    ensure_mcp_compatibility()
    assert hasattr(mcp.types, "CacheableResult")
    from mcp.types import CacheableResult

    assert CacheableResult is not None


def test_is_internal_runtime_error_detects_import_and_code_errors():
    """Internal code/library errors should be identified as internal runtime errors."""
    imp_err = ImportError("cannot import name 'CacheableResult' from 'mcp.types'")
    assert _is_internal_runtime_error(imp_err)

    wrapped = litellm.APIConnectionError(
        message="OpenrouterException - cannot import name 'CacheableResult' from 'mcp.types'",
        model="openrouter/auto",
        llm_provider="openrouter",
    )
    assert _is_internal_runtime_error(wrapped, str(wrapped))

    # Chained exception
    try:
        try:
            raise ModuleNotFoundError("No module named 'something_missing'")
        except ModuleNotFoundError as e:
            raise litellm.APIConnectionError(
                message="Connection error",
                model="openrouter/auto",
                llm_provider="openrouter",
            ) from e
    except litellm.APIConnectionError as chained:
        assert _is_internal_runtime_error(chained, str(chained))

    # Real network error should NOT be flagged as internal error
    real_conn_err = litellm.APIConnectionError(
        message="Connection refused to http://127.0.0.1:11434",
        model="ollama/llama3",
        llm_provider="ollama",
    )
    assert not _is_internal_runtime_error(real_conn_err, str(real_conn_err))


def test_friendly_llm_error_surfaces_actual_error_for_masked_api_connection_error():
    """When litellm wraps an ImportError into APIConnectionError, friendly_llm_error
    must NOT lie and claim 'Could not reach the LLM provider'. It must report the actual error."""
    # 1. Message containing import error
    masked_exc = litellm.APIConnectionError(
        message="OpenrouterException - cannot import name 'CacheableResult' from 'mcp.types'",
        model="openrouter/auto",
        llm_provider="openrouter",
    )
    msg = friendly_llm_error(masked_exc)
    assert "LLM client runtime error" in msg
    assert "cannot import name 'CacheableResult' from 'mcp.types'" in msg
    assert "Could not reach the LLM provider" not in msg

    # 2. Chained cause
    try:
        try:
            raise AttributeError("'NoneType' object has no attribute 'catalog'")
        except AttributeError as inner:
            raise litellm.APIConnectionError(
                message="Unexpected error",
                model="gpt-4o",
                llm_provider="openai",
            ) from inner
    except litellm.APIConnectionError as chained_exc:
        msg2 = friendly_llm_error(chained_exc)
        assert "LLM client runtime error (AttributeError)" in msg2
        assert "'NoneType' object has no attribute 'catalog'" in msg2
        assert "Could not reach the LLM provider" not in msg2


def test_friendly_llm_error_surfaces_detail_for_real_connection_errors():
    """For genuine connection errors, friendly_llm_error provides the exact failure detail."""
    real_exc = litellm.APIConnectionError(
        message="Connection refused: [Errno 111] Connect call failed ('127.0.0.1', 11434)",
        model="ollama/llama3",
        llm_provider="ollama",
    )
    msg = friendly_llm_error(real_exc)
    assert "Could not reach the LLM provider (APIConnectionError)" in msg
    assert "Connection refused" in msg
    assert "Check your connection and try again" in msg


def test_friendly_llm_error_surfaces_detail_for_other_errors():
    """Verify Timeout, RateLimit, Authentication, and BadRequest preserve detailed messages."""
    timeout_exc = litellm.Timeout(
        message="Client network timeout after 120.0s",
        model="groq/llama-3.3-70b",
        llm_provider="groq",
    )
    t_msg = friendly_llm_error(timeout_exc)
    assert "LLM provider request timed out: Client network timeout after 120.0s" in t_msg

    auth_exc = litellm.AuthenticationError(
        message="Incorrect API key provided: sk-invalid",
        model="gpt-4o",
        llm_provider="openai",
    )
    a_msg = friendly_llm_error(auth_exc)
    assert "Authentication failed" in a_msg
    assert "Incorrect API key provided" in a_msg

    bad_req = litellm.BadRequestError(
        message="Invalid model parameter: temperature must be between 0 and 2",
        model="gpt-4o",
        llm_provider="openai",
    )
    b_msg = friendly_llm_error(bad_req)
    assert "The provider rejected the request (BadRequestError)" in b_msg
    assert "temperature must be between 0 and 2" in b_msg


def test_complete_passes_skip_mcp_handler_and_configures_litellm():
    """Verify that complete() passes _skip_mcp_handler=True, skip_mcp_handler=True,
    and sets litellm.drop_params = True."""
    config = CLIModelConfig(model="openai/gpt-4o", api_key="sk-test")
    captured_kwargs = {}

    async def fake_acompletion(**kwargs):
        captured_kwargs.update(kwargs)
        return {"choices": [{"message": {"content": "ok"}}]}

    with patch("litellm.acompletion", new=fake_acompletion):
        res = _run(
            complete(
                config=config,
                messages=[{"role": "user", "content": "hello"}],
                tools=[{"type": "function", "function": {"name": "test"}}],
            )
        )

    assert res["choices"][0]["message"]["content"] == "ok"
    assert captured_kwargs.get("_skip_mcp_handler") is True
    assert litellm.drop_params is True


def test_complete_does_not_retry_masked_internal_errors():
    """Internal runtime errors masked as APIConnectionError should fail immediately without retries."""
    config = CLIModelConfig(model="openrouter/auto", api_key="sk-test")
    call_count = 0

    async def failing_acompletion(**kwargs):
        nonlocal call_count
        call_count += 1
        raise litellm.APIConnectionError(
            message="OpenrouterException - cannot import name 'CacheableResult' from 'mcp.types'",
            model="openrouter/auto",
            llm_provider="openrouter",
        )

    with patch("litellm.acompletion", new=failing_acompletion), pytest.raises(litellm.APIConnectionError):
        _run(
            complete(
                config=config,
                messages=[{"role": "user", "content": "hello"}],
            )
        )

    # Must NOT have retried — exactly 1 attempt
    assert call_count == 1
