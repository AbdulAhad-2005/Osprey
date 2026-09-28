"""Peer-anomaly detection — plans/harness/14-pentester-intelligence.md Step 1.

A senior tester doesn't need a rule that says "check for X on this kind of
site" to get suspicious — they notice that *this one* host among several
identical siblings behaves differently: slower, running an older version of
the same product. That's statistical surprise relative to peers, not
knowledge of a specific vuln class — a genuinely different, much narrower
thing than the bespoke signal-vocabulary/chaining-engine shape rejected in
the 2026-09-16 harness-unification decision (see plans/harness/13's "Why").

Deterministic, no LLM, no new data collection — everything here reads facts
already recorded by ordinary tool runs (``Evidence.duration_ms``, TECHNOLOGY
observations' ``name``/``version``). Peers are grouped by registrable apex,
the same grouping ``surface_expansion.py::_owned_apexes`` already uses — not
reinvented here.

Deliberately does NOT flag on HTTP status/response-shape yet:
``httpx_probe``'s own observations don't record a clean status_code field
(only unstructured ``raw`` text) — verified, not assumed. Worth adding once a
parser actually captures it structurally; guessing a key that silently
matches nothing would be worse than not shipping it.
"""

from __future__ import annotations

import statistics
from collections import defaultdict

from osprey.schemas.observation import ObservationType
from osprey.services.evidence_store import get_evidence_store
from osprey.services.observation_store import get_observation_store
from osprey.services.target_utils import registrable_apex

# A peer group needs at least this many members before "outlier" means
# anything — flagging one host as an outlier against one sibling is a coin
# flip, not a signal.
_MIN_PEER_GROUP = 3
# A run taking more than this many times the peer median duration for the
# SAME tool is worth a second look (a slower backend path, a different app
# behind the same-looking hostname — could be nothing, but it's cheap to ask).
_TIMING_OUTLIER_RATIO = 3.0


def _tag(kind: str) -> list[str]:
    return ["anomaly", kind]


def _timing_anomalies(engagement_id: str) -> list["Observation"]:
    from osprey.schemas.observation import Observation

    evidence = get_evidence_store().list_for_engagement(engagement_id, limit=5000)
    # (tool_name, apex) -> [(target, duration_ms), ...]
    groups: dict[tuple[str, str], list[tuple[str, int]]] = defaultdict(list)
    for e in evidence:
        if not e.tool_name or not e.target or not e.duration_ms:
            continue
        apex = registrable_apex(e.target)
        if not apex:
            continue
        groups[(e.tool_name, apex)].append((e.target, e.duration_ms))

    out: list[Observation] = []
    for (tool_name, apex), pairs in groups.items():
        if len(pairs) < _MIN_PEER_GROUP:
            continue
        durations = [d for _, d in pairs]
        median = statistics.median(durations)
        if median <= 0:
            continue
        for target, duration in pairs:
            if duration >= median * _TIMING_OUTLIER_RATIO:
                out.append(
                    Observation(
                        engagement_id=engagement_id,
                        type=ObservationType.SCANNER_SIGNAL,
                        target=target,
                        source_tool="anomaly_detection",
                        details={
                            "title": f"{target} took {duration}ms on {tool_name} vs. peer median "
                            f"{median:.0f}ms ({apex} peer group, n={len(pairs)})",
                            "claimed_severity": "none",
                            "kind": "timing_outlier",
                            "peer_group": apex,
                            "tool_name": tool_name,
                            "this_value_ms": duration,
                            "peer_median_ms": median,
                            "peer_count": len(pairs),
                        },
                        tags=_tag("timing_outlier"),
                    )
                )
    return out


def _version_anomalies(engagement_id: str) -> list["Observation"]:
    from osprey.schemas.observation import Observation

    tech_obs = get_observation_store().list_by_type(engagement_id, ObservationType.TECHNOLOGY)
    # product name -> apex -> [(target, version), ...]
    groups: dict[str, dict[str, list[tuple[str, str]]]] = defaultdict(lambda: defaultdict(list))
    for o in tech_obs:
        name = str(o.details.get("name") or "").strip().lower()
        version = str(o.details.get("version") or "").strip()
        if not name or not version:
            continue
        apex = registrable_apex(o.target) or ""
        if not apex:
            continue
        groups[name][apex].append((o.target, version))

    out: list[Observation] = []
    for name, by_apex in groups.items():
        for apex, pairs in by_apex.items():
            if len(pairs) < _MIN_PEER_GROUP:
                continue
            versions = [v for _, v in pairs]
            counts: dict[str, int] = defaultdict(int)
            for v in versions:
                counts[v] += 1
            majority_version, majority_count = max(counts.items(), key=lambda kv: kv[1])
            # Only flag when there IS a real majority (not every peer running a
            # distinct version, which just means version isn't a stable signal
            # for this product) and a minority genuinely differs from it.
            if majority_count < max(2, len(pairs) - 1):
                continue
            for target, version in pairs:
                if version != majority_version:
                    out.append(
                        Observation(
                            engagement_id=engagement_id,
                            type=ObservationType.SCANNER_SIGNAL,
                            target=target,
                            source_tool="anomaly_detection",
                            details={
                                "title": f"{target} runs {name} {version}, "
                                f"{majority_count}/{len(pairs)} peers run {majority_version} ({apex})",
                                "claimed_severity": "none",
                                "kind": "version_drift",
                                "peer_group": apex,
                                "technology": name,
                                "this_value": version,
                                "peer_majority_value": majority_version,
                                "peer_count": len(pairs),
                            },
                            tags=_tag("version_drift"),
                        )
                    )
    return out


def detect_peer_anomalies(engagement_id: str, *, persist: bool = True) -> list["Observation"]:
    """Deterministic, best-effort — each signal type is isolated so one
    failing never blocks the other, matching the rest of this codebase's
    "one failure never aborts the pass" discipline.

    Persists via ``ObservationStore.record_many`` by default — its own
    signature-based dedup means calling this repeatedly (once per recon
    pass) never creates duplicate rows, it just increments occurrence_count
    on a re-detected anomaly, same as any other observation source.
    """
    eid = (engagement_id or "").strip()
    if not eid:
        return []
    out: list = []
    for fn in (_timing_anomalies, _version_anomalies):
        try:
            out.extend(fn(eid))
        except Exception:  # noqa: BLE001
            import logging

            logging.getLogger(__name__).debug(
                "anomaly detection signal %s failed for %s (non-fatal)", fn.__name__, eid, exc_info=True,
            )
    if persist and out:
        try:
            result = get_observation_store().record_many(out)
            return result.observations
        except Exception:  # noqa: BLE001
            import logging

            logging.getLogger(__name__).debug(
                "anomaly detection persist failed for %s (non-fatal)", eid, exc_info=True,
            )
            return out
    return out
