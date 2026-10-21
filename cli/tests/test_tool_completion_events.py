"""Fast calls must finish visibly without waiting for a slower sibling."""
import asyncio

from agent_core import loop
from agent_core.llm import CLIModelConfig


class Gateway:
    engagement_id = "events-test"

    def schemas(self, **kwargs):
        return []

    async def call(self, *args):
        return "recorded findings"


def test_tool_end_arrives_before_slow_sibling_and_cancellation_cleans_up():
    async def scenario():
        release = asyncio.Event()
        cancelled = asyncio.Event()
        runner = loop.Runner(config=CLIModelConfig(model="test/model", api_key="test"), api_base_url="", tool_gateway=Gateway())

        async def manage(*args):
            if False:
                yield

        async def completion(*args):
            yield loop.Event("llm_result", {"response": {"choices": [{"message": {"content": "Inspect both", "tool_calls": [
                {"id": name, "function": {"name": name, "arguments": "{}"}} for name in ("fast", "slow")
            ]}}]}})

        async def dispatch(name, *args, **kwargs):
            if name == "slow":
                try:
                    await release.wait()
                finally:
                    cancelled.set()
            return "ok"

        runner._manage_context = manage
        runner._complete_with_feedback = completion
        runner._dispatch_tool = dispatch
        events = []
        fast_visible = asyncio.Event()

        async def consume():
            async for event in runner.run("inspect"):
                events.append(event)
                if event.type == "tool_end" and event.data["tool_call_id"] == "fast":
                    fast_visible.set()

        task = asyncio.create_task(consume())
        await asyncio.wait_for(fast_visible.wait(), 2)
        assert not release.is_set()
        assert not any(e.type == "tool_end" and e.data["tool_call_id"] == "slow" for e in events)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert cancelled.is_set()
        assert {m.get("tool_call_id") for m in runner.messages if m["role"] == "tool"} == {"fast", "slow"}

    asyncio.run(scenario())


def test_worker_tool_ids_cannot_collide_with_parent_or_sibling():
    event = loop.Event("tool_start", {"tool_call_id": "call1", "tool_name": "platform_context"})
    assert loop._tag_worker_event(1, event).data["tool_call_id"] == "worker-1:call1"
    assert loop._tag_worker_event(2, event).data["tool_call_id"] == "worker-2:call1"
    assert event.data["tool_call_id"] == "call1"
