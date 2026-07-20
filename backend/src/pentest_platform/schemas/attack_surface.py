"""Attack-surface tree — condensed view of seed → sisters → hosts → IPs → ports.

Built best-effort from graph + findings. Incomplete/unstructured data is fine —
missing branches stay empty rather than inventing assets.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HostSurface(BaseModel):
    host: str
    ips: list[str] = Field(default_factory=list)
    ports: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    cf: bool | None = None
    tags: list[str] = Field(default_factory=list)
    notes: str = ""


class DomainBranch(BaseModel):
    domain: str
    role: str = "seed"  # seed | sister | related | orphan
    subdomains: list[HostSurface] = Field(default_factory=list)
    direct: HostSurface | None = None  # the apex itself if probed
    incomplete: bool = Field(
        default=False,
        description="True when we have the domain but little structured host data.",
    )


class AttackSurfaceStats(BaseModel):
    sisters: int = 0
    subdomains: int = 0
    unique_ips: int = 0
    open_ports: int = 0
    services: int = 0
    orphan_hosts: int = 0


class AttackSurfaceTree(BaseModel):
    engagement_id: str
    seed: str
    sisters: list[DomainBranch] = Field(default_factory=list)
    seed_branch: DomainBranch | None = None
    orphans: list[HostSurface] = Field(
        default_factory=list,
        description="Hosts not clearly under seed/sisters — may be unstructured leftovers.",
    )
    stats: AttackSurfaceStats = Field(default_factory=AttackSurfaceStats)
    advisory: bool = True
    note: str = (
        "Best-effort tree from structured graph/findings. "
        "Missing branches often mean unparsed output, not absence of work."
    )
    truncated: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)
