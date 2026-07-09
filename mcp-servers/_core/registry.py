"""Tool registry — maps category -> tool modules for FastMCP server assembly."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class RegisteredTool:
    name: str
    category: str
    description: str
    handler: Callable[..., dict[str, Any]]
    parameters_schema: dict[str, Any] = field(default_factory=dict)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}

    def register(self, tool: RegisteredTool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[RegisteredTool]:
        return self._tools.get(name)

    def list_tools(self, category: Optional[str] = None) -> list[RegisteredTool]:
        tools = list(self._tools.values())
        if category:
            tools = [t for t in tools if t.category == category]
        return sorted(tools, key=lambda t: t.name)

    def names(self, category: Optional[str] = None) -> list[str]:
        return [t.name for t in self.list_tools(category)]


GLOBAL_REGISTRY = ToolRegistry()
