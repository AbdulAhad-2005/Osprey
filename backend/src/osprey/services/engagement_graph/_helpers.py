"""Engagement graph — Postgres-backed, strictly scoped per engagement.

Same subdomain/IP labels on different engagements never share nodes or edges.
Composite PK is (engagement_id, node_id) where node_id = asset_type:label.

Since plans/harness/05-world-model-and-attack-paths.md Step 1, ``ingest_observation``
is the primary builder — every node/edge it creates cites the ``observation_id``(s)
that assert it, and confidence is recomputed fresh from the *current* evidence
set on every ingest (never ratcheted from a remembered prior value), so it can
fall as well as rise once Plan 06's decay model or Step 2a's conflict handling
feeds back into it. ``ingest_finding`` still exists, but only to stamp a filed
Finding's link to the graph node(s) its own observation_ids already built —
it mints no new structure itself.

Disclosed exception: ``ensure_node`` / ``operator_link`` / ``operator_link_many``
(behind ``platform_graph_link``/``platform_graph_link_many``) still let an
operator/LLM assert a node or edge with no observation_id — these predate the
evidence law and migrating them is a separately-scoped follow-up (same gap as
``operator_memory.record_think``/``platform_record_finding``). Every
*deterministic* edge this module builds itself always cites evidence.
"""

from __future__ import annotations

import logging
import re

import orjson

from osprey.schemas.engagement_graph import (
    AssetType,
    ConflictingValue,
)

logger = logging.getLogger(__name__)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _node_id(asset_type: AssetType, label: str) -> str:
    """Local node key within an engagement (engagement_id is a separate PK part)."""
    return f"{asset_type.value}:{label.lower()}"


def _encode_meta(meta: dict) -> str:
    return orjson.dumps(meta).decode()


def _decode_meta(raw: str) -> dict:
    if not raw:
        return {}
    try:
        data = orjson.loads(raw)
        return data if isinstance(data, dict) else {}
    except (orjson.JSONDecodeError, TypeError, ValueError):
        return {}


def _decode_list(raw: str) -> list[str]:
    if not raw:
        return []
    try:
        data = orjson.loads(raw)
        return [str(x) for x in data] if isinstance(data, list) else []
    except (orjson.JSONDecodeError, TypeError, ValueError):
        return []


def _decode_conflicts(raw: str) -> dict[str, list[ConflictingValue]]:
    if not raw:
        return {}
    try:
        data = orjson.loads(raw)
    except (orjson.JSONDecodeError, TypeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, list[ConflictingValue]] = {}
    for slot, entries in data.items():
        if isinstance(entries, list):
            out[str(slot)] = [ConflictingValue.model_validate(e) for e in entries if isinstance(e, dict)]
    return out


def _node_confidence(source_tool_count: int) -> str:
    """The same evidence law as ``services.confidence.confidence_for``, applied
    to a graph node: a fact only one tool ever reported stays a hypothesis;
    two or more independent tools agreeing earns "likely". There is no
    "confirmed" tier for a graph fact — nothing here is a reproduction."""
    return "likely" if source_tool_count >= 2 else "hypothesis"


