# Integration Contract — Platform Kernel ↔ Multi-Agent Layer

This document defines the **stable surfaces** between execution/platform work (you) and LLM orchestration work (friend). Both sides should code against these APIs — not against recon/network-specific internals.

## Philosophy

- **Assist the LLM, don't script it** — YAML, skills, and hints are suggestions; governance blocks unsafe execution only.
- **One pipeline for all phases** — adaptation, parsing, and handoff live in `platform/`; new phases register parsers/hints instead of forking agent logic.
- **Failures are platform events** — timeout, privilege, wrong target shape, repeat calls → same `enrich_tool_result()` path for every tool.

---

## 1. Tool execution

```python
from pentest_platform.services.tool_execution import execute_tool_request
from pentest_platform.schemas.tools import ToolExecutionRequest

response = await execute_tool_request(
    ToolExecutionRequest(
        tool_name="nmap_syn_scan",
        params={"target": "45.33.32.156"},
        additional_args="-sT -Pn --top-ports 1000",
        engagement_id=engagement_id,
        run_id=run_id,
        record_findings=True,
        use_recovery=False,  # Commander path: deterministic only
    )
)
```

**Returns:** `ToolExecutionResponse` with `success`, `stdout`, `stderr`, `command`, `timed_out`, `error`.

---

## 2. Result adaptation (all agents)

After every tool run, pass raw output through the kernel:

```python
from pentest_platform.platform.adaptation import AdaptationContext, enrich_tool_result
from pentest_platform.platform.run_context import RunAssistState, tool_call_signature

signature = tool_call_signature(tool_name, params, additional_args=additional_args)
enriched = enrich_tool_result(
    base_text,  # SUCCESS/FAILED + STDOUT/STDERR
    AdaptationContext(
        tool_response=response,
        assist_state=assist_state,
        signature=signature,
        engagement_id=engagement_id,
        run_id=run_id,
        target=target,
        run_phase=phase,
        params=params,
    ),
)
```

**Adds (when applicable):** parsed digest, repeat-failure warning, cross-cutting hints, escalation/dispatch suggestions, findings snapshot.

---

## 3. Phase handoff

```python
from pentest_platform.platform import build_phase_handoff, handoff_to_prompt

packet = build_phase_handoff(
    from_phase="recon",
    to_phase="network",
    engagement_id=engagement_id,
    run_id=run_id,
    target=target,
    resolved_ip=resolved_ip,
)
prompt_block = handoff_to_prompt(packet)
# or: packet.to_prompt()
```

**HTTP:** `GET /api/v1/findings/structured?engagement_id=&run_id=&target=&from_phase=recon`

**Schema:** `StructuredFindingsExport`, `PhaseHandoff` in `schemas/agent_run.py`.

---

## 4. Situational context (context-dependent flow)

The LLM should not brute-force the tool catalog. Before each turn and after each tool run, build a brief from evidence:

```python
from pentest_platform.platform import build_situational_brief

brief = build_situational_brief(
    engagement_id=engagement_id,
    run_id=run_id,
    target=target,
    resolved_ip=resolved_ip,
    phase=phase,
    assist_state=assist_state,
    user_goal=user_message,
)
```

**`RunAssistState` tracks:** `successful_tools`, `tools_attempted`, `failure_counts`, `skip_categories` (e.g. SMB after enum4linux failure).

Inject `brief` into the system prompt; `enrich_tool_result()` appends an updated brief after each tool run.

---

## 5. Parser registration (new phases)

Do **not** edit `adaptation.py` for a new phase. Register in a phase module:

```python
from pentest_platform.services.parsers.registry import (
    register_output_parser,
    register_output_digester,
)

register_output_parser("nikto_scan", parse_nikto)
register_output_digester("nikto_scan", lambda stdout: digest_nikto(stdout))
```

Import the module from `services/parsers/__init__.py` so it self-registers.

---

## 6. Hint registration (new failure modes)

```python
from pentest_platform.platform.hint_providers import HintContext, register_hint_provider

def _hints_waf(ctx: HintContext) -> list[str]:
    if "403" in ctx.stdout and ctx.phase == "webapp":
        return ["HINT: Possible WAF — try different User-Agent or path normalization."]
    return []

register_hint_provider(_hints_waf, priority=35)
```

---

## 7. Tools exposed to LLM per phase

```python
from pentest_platform.services.tool_discovery import get_agent_tools, get_tools_for_llm_phase

tools = get_tools_for_llm_phase("network")  # friend should use this in phase agents
```

---

## 8. SSE events (agent chat)

`POST /api/v1/agent/chat/stream` emits:

| Event | Purpose |
|-------|---------|
| `run_start` | phase, target, run_id, model |
| `status` | LLM thinking |
| `tool_start` / `tool_end` | tool name, success, preview |
| `assistant` | final text |
| `done` | full `AgentResponse` payload |
| `error` | unrecoverable loop error |

Friend's Commander should wrap phase agents and emit `phase_start` / `phase_end` using the same transport.

---

## Branch split

| Owner | Branch | Owns |
|-------|--------|------|
| Platform / execution | `feature/execution-hardening` | `platform/`, `tool_execution`, parsers registry, YAML matrices |
| Multi-agent LLM | `feature/multi-agent` | `orchestrator.py`, `commander_agent.py`, `phase_agent.py`, skills wiring |

Merge when: structured findings endpoint works, `enrich_tool_result` is the only post-tool path, and handoff prompt renders from real session data.
