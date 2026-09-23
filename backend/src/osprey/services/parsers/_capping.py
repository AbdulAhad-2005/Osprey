"""Shared cap-with-accounting helper for parsers that turn many raw items
(URLs, script matches, endpoints, ...) into Observation rows.

Tool output can contain far more items than are useful as individual rows
(tens of thousands of URLs, hundreds of NSE matches). Capping is fine;
silently dropping the remainder is not — every caller that truncates a list
must account for what it excluded via a durable Observation, not just a
display string that may never be shown. This is the one implementation for
that pattern; parsers should not hand-roll their own cap logic.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TypeVar

from osprey.schemas.observation import Observation, ObservationType

T = TypeVar("T")


def make_accounting_observation(
    *,
    tool_name: str,
    item_label: str,
    kept: int,
    total: int,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> Observation:
    """A durable Observation recording what a cap excluded, so it's never just gone."""
    excluded = total - kept
    return Observation(
        engagement_id=engagement_id,
        run_id=run_id,
        type=ObservationType.RAW,
        target=target,
        source_tool=tool_name,
        details={
            "kind": "capped_accounting",
            "item_label": item_label,
            "total_count": total,
            "stored_count": kept,
            "excluded_count": excluded,
        },
        tags=["capped", "accounting"],
    )


def cap_with_accounting(
    items: Sequence[T],
    *,
    max_items: int,
    render: Callable[[T], Observation],
    tool_name: str,
    item_label: str,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """Render up to max_items via `render`, appending one accounting Observation
    covering anything beyond the cap. Never truncates without a trace."""
    total = len(items)
    kept_items = list(items)[:max_items]
    observations = [render(item) for item in kept_items]
    if total > len(kept_items):
        observations.append(
            make_accounting_observation(
                tool_name=tool_name,
                item_label=item_label,
                kept=len(kept_items),
                total=total,
                engagement_id=engagement_id,
                run_id=run_id,
                target=target,
            )
        )
    return observations
