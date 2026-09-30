from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from cli.agent.loop import Runner

if TYPE_CHECKING:
    from cli.harness.runtime import HarnessRuntime


class WorkerManager:
    """Creates native CLI workers under the parent runtime.

    Workers share the runtime's capability gateway and engagement identity but
    keep independent Runner histories.  They cannot recursively spawn more
    workers; supervision stays at one harness layer.
    """

    def __init__(self, runtime: "HarnessRuntime") -> None:
        self.runtime = runtime

    def create(
        self,
        *,
        config: Any,
        engagement_id: str,
        target: str,
        tool_filter: Callable[[str], bool] | None,
        agent_prompt: str,
    ) -> Runner:
        return Runner(
            config=config,
            api_base_url=self.runtime.base_url,
            engagement_id=engagement_id,
            target=target,
            allow_spawn=False,
            tool_filter=tool_filter,
            agent_prompt=agent_prompt,
            tool_gateway=self.runtime.tool_gateway,
            worker_factory=self.create,
        )
