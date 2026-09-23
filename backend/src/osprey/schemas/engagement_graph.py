"""Engagement graph — cross-asset pivot + Tool_architecture memory plane."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AssetType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    HOST = "host"
    IP = "ip"
    URL = "url"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    # ── Passive OSINT identity entities ──
    EMAIL = "email"
    USERNAME = "username"
    PERSON = "person"
    PHONE = "phone"
    SOCIAL_ACCOUNT = "social_account"
    ORGANIZATION = "organization"
    DOCUMENT = "document"
    # ── Downstream (exploit / post-exploit) entity ──
    CREDENTIAL = "credential"
    SECRET = "secret"


class ConflictingValue(BaseModel):
    """One disputed value for a node's slot (e.g. service@443) — plans/harness/
    05-world-model-and-attack-paths.md Step 2a: kept, never silently
    overwritten, when two observations disagree."""

    value: str
    observation_id: str = ""
    source_tool: str = ""


class AssetNode(BaseModel):
    id: str
    asset_type: AssetType
    label: str
    engagement_id: str = ""
    run_id: str = ""
    source_tool: str = ""
    confidence: str = "likely"
    # Every observation_id that asserts this node — the evidence backing
    # (Step 1). Empty only for the disclosed operator-asserted exception
    # (ensure_node/operator_link — see engagement_graph.py's module docstring).
    observation_ids: list[str] = Field(default_factory=list)
    source_tools: list[str] = Field(default_factory=list)
    # slot name -> disputed values, when observations disagree (Step 2a).
    conflicts: dict[str, list[ConflictingValue]] = Field(default_factory=dict)
    # Nested metadata is allowed: banners, TLS cert chains, response bodies, OS
    # guesses, etc. live on the node instead of being flattened away.
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None


class AssetEdge(BaseModel):
    source_id: str
    target_id: str
    relationship: str
    engagement_id: str = ""
    run_id: str = ""
    source_tool: str = ""
    observation_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphSummary(BaseModel):
    engagement_id: str
    run_id: str = ""
    node_count: int
    edge_count: int
    subdomains: list[str] = Field(default_factory=list)
    live_hosts: list[str] = Field(default_factory=list)
    open_ports: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    pivot_hints: list[str] = Field(default_factory=list)


class SiblingHostResponse(BaseModel):
    reference: str
    ip: str
    siblings: list[str]
    hint: str
