"""Osprey CLI's own local agent runtime.

This package makes the interactive CLI a real agent host — like Claude
Code's own CLI — instead of a thin remote control over a backend-hosted
LLM. The CLI supplies the brain (its own configured model/key, see
``llm.py``); the backend supplies tools, memory, and the conductor signal
through the exact same surface an external MCP harness (OpenCode, Claude
Desktop) already uses (``tools.py`` imports ``platform-mcp/server.py``
directly — one tool layer, not a second one).
"""
