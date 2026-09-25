"""Regression test: a registered parser that finds nothing structured in a
particular run's output must get the same LLM structural-extraction recovery
chance as a tool with no parser registered at all — previously only the
no-parser case tried it, so every tool WITH a parser (the majority of the
catalog) skipped straight to a raw placeholder observation on every empty
parse. Renamed from the old dynamic_fallback-era test after Plan 02 replaced
Finding-minting LLM structuring with structural-only observation extraction
(``observation_engine.extract``) — see
plans/harness/02-evidence-and-observation-layer.md.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.parsers import registry


def _extracted_observation(tool_name: str) -> Observation:
    return Observation(
        type=ObservationType.TECHNOLOGY,
        title="LLM-extracted observation",
        source_tool=tool_name,
        details={"title": "LLM-extracted observation"},
    )


@pytest.fixture(autouse=True)
def _clean_registry():
    # Isolate from whatever real parsers ensure_parsers_loaded() registered
    # elsewhere in the test session.
    saved = dict(registry._OUTPUT_PARSERS)
    yield
    registry._OUTPUT_PARSERS.clear()
    registry._OUTPUT_PARSERS.update(saved)


def test_registered_parser_returning_empty_still_tries_llm_extraction():
    """The actual regression: some_tool HAS a parser, but it finds nothing in
    this stdout — that must not skip the LLM structural-extraction fallback."""
    registry._OUTPUT_PARSERS["some_tool"] = lambda stdout, **kw: []

    with patch(
        "osprey.services.parsers.observation_engine.extract",
        new=AsyncMock(return_value=[_extracted_observation("some_tool")]),
    ) as mock_extract:
        import asyncio
        result = asyncio.run(registry.parse_tool_output("some_tool", "some raw output"))

    mock_extract.assert_awaited_once()
    assert len(result) == 1
    assert result[0].details.get("title") == "LLM-extracted observation"


def test_registered_parser_returning_empty_falls_back_to_raw_when_llm_unavailable():
    registry._OUTPUT_PARSERS["some_tool"] = lambda stdout, **kw: []

    with patch(
        "osprey.services.parsers.observation_engine.extract", new=AsyncMock(return_value=[])
    ):
        import asyncio
        result = asyncio.run(registry.parse_tool_output("some_tool", "some raw output"))

    assert len(result) == 1
    assert result[0].type == ObservationType.RAW


def test_registered_parser_that_finds_something_never_calls_llm():
    """A parser that DID extract real observations must short-circuit — no
    wasted LLM call when there's nothing to recover."""
    real_observation = Observation(
        type=ObservationType.HOST, target="real.example.com", source_tool="some_tool",
        details={"hostname": "real.example.com"},
    )
    registry._OUTPUT_PARSERS["some_tool"] = lambda stdout, **kw: [real_observation]

    with patch(
        "osprey.services.parsers.observation_engine.extract", new=AsyncMock()
    ) as mock_extract:
        import asyncio
        result = asyncio.run(registry.parse_tool_output("some_tool", "some raw output"))

    mock_extract.assert_not_awaited()
    assert result == [real_observation]


def test_no_parser_registered_still_tries_llm_extraction_as_before():
    with patch(
        "osprey.services.parsers.observation_engine.extract",
        new=AsyncMock(return_value=[_extracted_observation("unregistered_tool")]),
    ) as mock_extract:
        import asyncio
        result = asyncio.run(registry.parse_tool_output("unregistered_tool", "some raw output"))

    mock_extract.assert_awaited_once()
    assert len(result) == 1
