"""Per-IP network surface state (M5) — soft ports_known vs services_known."""

from __future__ import annotations

from pydantic import BaseModel, Field


class IpNetworkState(BaseModel):
    ip: str
    hosts: list[str] = Field(default_factory=list)
    ports: list[str] = Field(default_factory=list, description="Discovered port numbers/labels")
    services: list[str] = Field(default_factory=list)
    ports_known: bool = False
    services_known: bool = False
    advisory: bool = True
    notes: str = ""


class HostNetworkState(BaseModel):
    """Same shape as IpNetworkState but keyed by host/subdomain node directly —
    doesn't depend on a resolves_to->IP edge existing. The dominant recon flow
    (subfinder -> httpx_probe -> nmap-by-hostname) never creates an IP node
    unless dnsx_resolve also ran, so IP-only completeness tracking can report
    "0 gaps" when it really means "0 IP nodes exist to check"."""

    host: str
    ports: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    ports_known: bool = False
    services_known: bool = False
    notes: str = ""


class NetworkSurfaceSummary(BaseModel):
    engagement_id: str
    ips: list[IpNetworkState] = Field(default_factory=list)
    unscanned_ips: int = 0
    ports_without_services: int = 0
    hosts: list[HostNetworkState] = Field(default_factory=list)
    unscanned_hosts: int = 0
    hosts_ports_without_services: int = 0
    advisory: bool = True
    note: str = (
        "Per-IP network granularity from structured graph/findings. "
        "Missing service data often means unparsed nmap output, not that version scan was skipped. "
        "hosts/unscanned_hosts is the same view keyed by host node directly — check both; "
        "a host can show port/service coverage here even when its IP was never resolved."
    )
