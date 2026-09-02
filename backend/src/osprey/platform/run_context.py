"""Per-run state shared across all phases and agents."""



from __future__ import annotations



import json

from dataclasses import dataclass, field

from typing import Any





@dataclass

class RunAssistState:

    """Tracks tool outcomes and run-level memory for any phase."""



    failure_counts: dict[str, int] = field(default_factory=dict)

    tools_attempted: dict[str, int] = field(default_factory=dict)

    successful_tools: set[str] = field(default_factory=set)

    phases_completed: list[str] = field(default_factory=list)

    skip_categories: set[str] = field(default_factory=set)





def tool_call_signature(

    tool_name: str,

    tool_args: dict[str, Any],

    *,

    additional_args: str = "",

) -> str:

    normalized = {k: v for k, v in sorted(tool_args.items()) if v is not None}

    payload = {

        "tool": tool_name,

        "args": normalized,

        "additional_args": additional_args.strip(),

    }

    return json.dumps(payload, sort_keys=True, default=str)





def note_failure(*, signature: str, state: RunAssistState) -> None:

    state.failure_counts[signature] = state.failure_counts.get(signature, 0) + 1





def note_tool_outcome(

    *,

    tool_name: str,

    success: bool,

    state: RunAssistState,

    skip_category: str | None = None,

) -> None:

    state.tools_attempted[tool_name] = state.tools_attempted.get(tool_name, 0) + 1

    if success:

        state.successful_tools.add(tool_name)

    if skip_category and not success:

        state.skip_categories.add(skip_category)





def repeat_failure_warning(*, signature: str, state: RunAssistState) -> str:

    prior = state.failure_counts.get(signature, 0)

    if prior < 1:

        return ""

    return (

        f"REPEAT WARNING: This exact tool+arguments already failed {prior} time(s) earlier in this run. "

        "Do not retry unchanged — change approach, target, or flags, or explain why the check does not apply."

    )

