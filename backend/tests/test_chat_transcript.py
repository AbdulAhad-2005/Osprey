"""Disconnect/reconnect must retain ordered tool activity, not just final text."""
import asyncio
from types import SimpleNamespace

from osprey.schemas.engagement import EngagementCreateRequest
from osprey.services.engagement_store import get_engagement_store
from osprey.services.chat_transcript import append_event, page_events
from osprey.services import event_bus, foreground_chat


def test_transcript_cursor_is_engagement_scoped():
    store = get_engagement_store()
    a = store.create(EngagementCreateRequest(target="transcript-a.test"))
    b = store.create(EngagementCreateRequest(target="transcript-b.test"))
    first = append_event(a.id, "run", "run_start", {"prompt":"hello"})
    append_event(b.id, "other", "assistant", {"content":"private to b"})
    last = append_event(a.id, "run", "tool_end", {"tool_call_id":"call", "result":"retained output"})
    assert [event["id"] for event in page_events(a.id)] == [first["id"], last["id"]]
    assert page_events(a.id, first["id"])[0]["data"]["result"] == "retained output"


def test_disconnected_run_saves_tool_arguments_and_results(monkeypatch):
    from agent_core.loop import Event
    import agent_core.context

    engagement = get_engagement_store().create(EngagementCreateRequest(target="transcript-disconnect.test"))
    class Runner:
        async def run(self, prompt, **kwargs):
            yield Event("thinking", {"content":"I will inspect the recorded context."})
            yield Event("tool_start", {"tool_name":"platform_context", "arguments":'{"full":true}', "tool_call_id":"ctx"})
            await asyncio.sleep(0)
            yield Event("tool_end", {"tool_name":"platform_context", "result":"recorded context", "tool_call_id":"ctx", "success":True})
            yield Event("assistant_text", {"content":"Assessment context restored."})
            yield Event("done", {"content":"Assessment context restored."})
    async def system(*args, **kwargs):
        return "test"
    session = SimpleNamespace(runner=Runner(), gateway=SimpleNamespace(call=None), lock=asyncio.Lock())
    monkeypatch.setattr(foreground_chat, "_get_session", lambda *args: session)
    monkeypatch.setattr(agent_core.context, "build_system_prompt", system)
    asyncio.run(foreground_chat._drive_run(engagement.id, "Review context", None))
    # A new reader, with no in-memory bus history, still receives the full run.
    event_bus.clear_history(engagement.id)
    events = page_events(engagement.id)
    assert [event["event"] for event in events] == ["run_start", "assistant", "tool_start", "tool_end", "assistant", "done"]
    assert events[2]["data"]["arguments"] == '{"full":true}'
    assert events[3]["data"]["result"] == "recorded context"


def test_zero_replay_does_not_replay_prior_done():
    event_bus.publish("transcript-replay", "done", {})
    assert event_bus.history("transcript-replay", limit=0) == []


def test_legacy_boundary_uses_message_id_not_second_precision_timestamp():
    from osprey.services.conversation_store import append_message, get_history
    engagement = get_engagement_store().create(EngagementCreateRequest(target="transcript-boundary.test"))
    append_message(engagement.id, "user", "old prompt")
    append_message(engagement.id, "assistant", "old answer")
    boundary = append_message(engagement.id, "user", "journal prompt")
    append_event(engagement.id, "run", "run_start", {"prompt": "journal prompt", "message_id": boundary})
    history = get_history(engagement.id, before_id=boundary)
    assert [message["content"] for message in history] == ["old prompt", "old answer"]


def test_storage_failure_still_terminates_connected_clients(monkeypatch):
    import osprey.services.chat_transcript as journal

    def unavailable(*args, **kwargs):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(foreground_chat, "_get_session", unavailable)
    monkeypatch.setattr(journal, "append_event", unavailable)
    eid = "transcript-storage-failure"
    asyncio.run(foreground_chat._drive_run(eid, "hello", None))
    assert [record["event"] for record in event_bus.history(eid)] == ["error", "done"]
