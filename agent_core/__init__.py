"""Osprey's transport-agnostic agent core — the one ReAct loop.

This package holds Osprey's single reasoning loop (``loop.Runner``) and the
pieces it needs: the embedded tool gateway (``tools``), the LLM client
(``llm``), system-prompt assembly (``context``), context compaction
(``compaction``), and prompt-defined flows (``flows``). It depends on neither
the CLI UX nor the backend package — only a third-party LLM library and the
platform-mcp tool schemas — so all three drivers import it as peers:

- the interactive CLI (``cli.harness``) drives it with the operator's own key;
- the backend runs it headlessly for scoped sub-agent jobs
  (``osprey.services.agent_runner``) and for the GUI's foreground operator chat
  (``osprey.services.foreground_chat``);
- an external MCP harness drives the same tools over the gateway.

It used to live under ``cli/agent/``; the backend importing a loop out of the
*client* package was an inverted dependency, so it was lifted here where no
side "owns" it.
"""
