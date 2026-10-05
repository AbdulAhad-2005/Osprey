"""Plan 19 — no-wasted-work guard: infrastructure learned from DNS records must
not be treated as a scannable target asset.

The operator's geo.tv complaint included "naabu on domain names / the CDN's own
nameservers". Verified against current code (2026-09-30): an NS-target host
(e.g. a Cloudflare nameserver learned from a dnsx NS record) is created in the
graph with ``metadata['role'] = 'ns_target'`` but is NOT offered for active work,
because it has no ``resolves_to`` edge and isn't a resolve-eligible node type —
so it never enters ``probe_nodes``/``profile_nodes``. That correct behaviour is
pinned here as a permanent regression guard: a future change to node selection
must not start offering scans against DNS-byproduct infrastructure.

(The exact path by which the old geo.tv run scanned nameservers could not be
reproduced from an NS record — it was most likely a nameserver surfaced as a
SUBDOMAIN by crt_sh/subfinder, then resolved and probed like any real asset.
That is a scope/ownership question, not a node-classification bug, and is left
to the scope policy of Phase 3 rather than fixed speculatively here.)
"""
from __future__ import annotations

import asyncio

from osprey.schemas.benchmark import Recording, ToolCallRecord
from osprey.services.benchmark.flow_replay import offered_after_ingest

_TARGET = "flowtest.example"


def _seed_with_nameserver() -> Recording:
    """dnsx resolves the seed to an IP and declares a Cloudflare nameserver
    (NS record) — real dnsx -resp shape ('host [TYPE] [VALUE]')."""
    return Recording(
        name="guard-ns-not-profiled",
        target=_TARGET,
        synthetic=True,
        calls=[
            ToolCallRecord(
                tool_name="dnsx_resolve",
                target=_TARGET,
                command="dnsx -resp",
                stdout=(
                    f"{_TARGET} [A] [93.184.216.34]\n"
                    f"{_TARGET} [NS] [ns1.cloudflare.com]\n"
                    f"{_TARGET} [NS] [ns2.cloudflare.com]\n"
                ),
                returncode=0,
                success=True,
                stdout_source="none",
            )
        ],
    )


def test_nameserver_from_ns_record_is_not_offered_for_active_work():
    """A host learned only as an NS-record target (role=ns_target) is
    infrastructure, not a target — it must never be offered for probing/
    port-scanning/web-profiling."""
    trace = asyncio.run(offered_after_ingest(_seed_with_nameserver()))
    ns_offered = [entry for entry in trace.offered if "cloudflare.com" in entry]
    assert ns_offered == [], f"nameserver infrastructure offered for work: {ns_offered}"
