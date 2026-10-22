import asyncio
from types import SimpleNamespace
import pytest

from osprey.schemas.engagement import EngagementCreateRequest
from osprey.services.engagement_store import get_engagement_store
from osprey.services.chat_transcript import append_event, page_events, restore_history
from osprey.services import foreground_chat as chat


def engagement():
    return get_engagement_store().create(EngagementCreateRequest(target="resume.test"))


def test_restart_restores_tool_protocol_and_repairs_partial_batches():
    eid = engagement().id
    append_event(eid, "old", "run_start", {"prompt": "Original objective and scope"})
    append_event(eid, "old", "assistant", {"content": "Inspect evidence"})
    for call in ("fast", "slow"):
        append_event(eid, "old", "tool_start", {"tool_call_id": call, "tool_name": "platform_context", "arguments": "{}"})
    append_event(eid, "old", "tool_end", {"tool_call_id": "fast", "result": "Recorded proof"})
    append_event(eid, "old", "assistant", {"source": "worker-1", "content": "Independent worker history"})
    append_event(eid, "new", "run_start", {"prompt": "continue"})
    history = restore_history(eid, exclude_run="new")
    assert [message["role"] for message in history] == ["user", "assistant", "tool", "tool"]
    assert history[1]["content"] == "Inspect evidence"
    assert history[2]["content"] == "Recorded proof"
    assert "interrupted" in history[3]["content"]
    assert {call["id"] for call in history[1]["tool_calls"]} == {"fast", "slow"}
    assert chat.run_state(eid)["resumable"]


def test_large_restored_result_has_real_scoped_retrieval():
    from osprey.services.artifacts import read_artifact_slice

    eid = engagement().id
    append_event(eid, "run", "run_start", {"prompt": "Inspect"})
    append_event(eid, "run", "tool_start", {"tool_name": "platform_context", "tool_call_id": "x"})
    full = "head" + "x" * 25000 + "tail"
    event = append_event(eid, "run", "tool_end", {"tool_call_id": "x", "result": full})
    restored = restore_history(eid)[-1]["content"]
    assert f"chat-event:{event['id']}" in restored and len(restored) < len(full)
    result = asyncio.run(read_artifact_slice(eid, f"chat-event:{event['id']}", limit=40000))
    assert result["content"] == full
    other = asyncio.run(read_artifact_slice(engagement().id, f"chat-event:{event['id']}"))
    assert not other["ok"]


def test_empty_and_limited_runs_are_resumable_not_completed():
    eid = engagement().id
    append_event(eid, "run", "done", {"content": "(stopped: reached the turn limit for this prompt)"})
    assert chat.run_state(eid)["reason"] == "turn_limit"
    append_event(eid, "run2", "done", {"content": ""})
    assert chat.run_state(eid)["reason"] == "empty_response"
    append_event(eid, "run3", "done", {"content": "Summary", "reason": "completed"})
    assert chat.run_state(eid)["state"] == "completed"
    assert chat.run_state(eid)["resumable"]  # A finished turn is not a completed engagement.


def test_failed_admission_cannot_leave_an_orphan_user_message(monkeypatch):
    from sqlalchemy.orm import Session
    from osprey.services.chat_transcript import admit_input
    from osprey.services.conversation_store import get_history

    eid = engagement().id
    def fail_commit(self):
        raise RuntimeError("storage failed")
    with monkeypatch.context() as patch:
        patch.setattr(Session, "commit", fail_commit)
        with pytest.raises(RuntimeError, match="storage failed"):
            admit_input(eid, "run", "Do not lose or duplicate this input", "request")
    assert get_history(eid) == []
    assert page_events(eid) == []


def test_bulk_dns_input_wins_over_scalar_seed_and_summary_reports_partial_methods():
    import json
    from osprey.services.agent_arg_normalizer import normalize_agent_tool_args
    from osprey.services.parsers.registry import digest_tool_output, ensure_parsers_loaded

    hosts = "one.example.test\ntwo.example.test"
    params, _ = normalize_agent_tool_args("dnsx_resolve", {"target": "example.test", "input_data": hosts})
    assert params["target"] == hosts
    ensure_parsers_loaded()
    output = json.dumps({"unified_stack": [{"name": "PHP", "version": "7.1.33"}],
                         "methods": {"wappalyzer": {"error": "No module named Wappalyzer"}}})
    digest = digest_tool_output("tech_stack_analyze", output)
    assert "PHP 7.1.33" in digest and "Partial coverage" in digest
    assert len(digest_tool_output("unknown", ("x" * 10000 + "\n") * 4)) < 1000


def test_admission_redirect_settles_old_run_and_records_each_input_once(monkeypatch):
    from agent_core.loop import Event
    import agent_core.context

    eid = engagement().id

    async def scenario():
        entered = asyncio.Event()

        class Runner:
            async def run(self, prompt, **kwargs):
                if prompt == "first":
                    entered.set()
                    await asyncio.Event().wait()
                yield Event("assistant_text", {"content": "Second instruction completed"})
                yield Event("done", {"content": "Second instruction completed", "reason": "completed"})

        async def system(*args, **kwargs):
            return "test system"

        session = SimpleNamespace(runner=Runner(), gateway=SimpleNamespace(call=None), lock=asyncio.Lock())
        monkeypatch.setattr(chat, "_get_session", lambda *args: session)
        monkeypatch.setattr(chat, "resolve_model_config", lambda: object())
        monkeypatch.setattr(chat, "llm_configured", lambda: True)
        monkeypatch.setattr(agent_core.context, "build_system_prompt", system)
        first = await chat.start_chat(eid, "first", request_id="input-one")
        await asyncio.wait_for(entered.wait(), 2)
        assert await chat.start_chat(eid, "first", request_id="input-one") == first
        second = await chat.start_chat(eid, "second", interrupt=True)
        assert first["run_id"] != second["run_id"]
        await chat._active_runs[eid]
        events = page_events(eid)
        assert [event["data"]["prompt"] for event in events if event["event"] == "run_start"] == ["first", "second"]
        terminal = [event for event in events if event["event"] == "done"]
        assert [event["data"]["reason"] for event in terminal] == ["paused", "completed"]
        assert not chat.run_active(eid)

    asyncio.run(scenario())
