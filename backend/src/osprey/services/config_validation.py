"""Loud, field-naming validation for the operator-editable knowledge configs
(G1). A malformed rule must fail with the offending field named — never a
silent no-op that makes the engine behave as if the config were empty. Runs at
load time (so a bad hot-reloaded edit is rejected) and in CI.

Scoped to the two files an operator edits to grow the engine's procedural
intelligence: the dispatch rules (``tech_dispatch.yaml``) and the recon stage
map (``expansion.yaml``). Other catalogs are validated structurally by their
own consumers; these two get an explicit schema because they are the
"add your own check" surface (G2)."""

from __future__ import annotations

from typing import Any


class ConfigValidationError(ValueError):
    """A knowledge-config file is malformed. The message names the file and the
    offending field so an operator can fix it without reading the loader."""


_DISPATCH_MATCH_KEYS = frozenset({
    "finding_type", "missing_finding_type", "has_tag", "metadata_key",
    "metadata_contains", "metadata_contains_any", "metadata_value",
    "min_count", "max_count", "scope", "graph_query", "has_live_hosts",
    "min_siblings", "phases_complete",
})


def validate_tech_dispatch(data: dict[str, Any]) -> dict[str, Any]:
    """Validate a tech_dispatch.yaml mapping. Returns it unchanged when valid."""
    signals = data.get("signals")
    if signals is None:
        return data  # an empty/absent signals list is legal (defaults apply)
    if not isinstance(signals, list):
        raise ConfigValidationError("tech_dispatch.yaml: 'signals' must be a list")

    seen_ids: set[str] = set()
    for i, rule in enumerate(signals):
        where = f"tech_dispatch.yaml signal #{i}"
        if not isinstance(rule, dict):
            raise ConfigValidationError(f"{where}: each signal must be a mapping")
        rid = rule.get("id")
        if not rid or not isinstance(rid, str):
            raise ConfigValidationError(f"{where}: missing or non-string 'id'")
        if rid in seen_ids:
            raise ConfigValidationError(f"{where}: duplicate id {rid!r}")
        seen_ids.add(rid)

        match = rule.get("match")
        if not isinstance(match, dict) or not match:
            raise ConfigValidationError(f"signal {rid!r}: 'match' must be a non-empty mapping")
        unknown = set(match) - _DISPATCH_MATCH_KEYS
        if unknown:
            raise ConfigValidationError(
                f"signal {rid!r}: unknown match field(s) {sorted(unknown)} "
                f"(known: {sorted(_DISPATCH_MATCH_KEYS)})"
            )

        dispatch = rule.get("dispatch")
        if not isinstance(dispatch, dict) or not dispatch:
            raise ConfigValidationError(f"signal {rid!r}: 'dispatch' must be a non-empty mapping")
        if not dispatch.get("default_tool"):
            raise ConfigValidationError(f"signal {rid!r}: dispatch.default_tool is required")
        params_from = dispatch.get("params_from")
        if params_from is not None and not isinstance(params_from, dict):
            raise ConfigValidationError(f"signal {rid!r}: dispatch.params_from must be a mapping")
        if match.get("scope") not in (None, "per_match"):
            raise ConfigValidationError(f"signal {rid!r}: match.scope must be 'per_match' when set")
    return data


def validate_expansion(data: dict[str, Any]) -> dict[str, Any]:
    """Validate expansion.yaml stage entries ({tool, param}). Returns unchanged
    when valid. Non-stage top-level keys (batch, phases, flags) are left to
    their consumer."""
    _NON_STAGE = {"batch", "phases", "work_sisters"}
    for stage, entries in data.items():
        if stage in _NON_STAGE or not isinstance(entries, list):
            continue
        for j, entry in enumerate(entries):
            where = f"expansion.yaml stage {stage!r} entry #{j}"
            if not isinstance(entry, dict):
                raise ConfigValidationError(f"{where}: must be a mapping like {{tool: ..., param: ...}}")
            if not entry.get("tool"):
                raise ConfigValidationError(f"{where}: missing 'tool'")
            if not entry.get("param"):
                raise ConfigValidationError(f"{where}: missing 'param' (the field that carries the asset label)")
    return data
