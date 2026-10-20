# Osprey GUI

A Next.js operator console for the Osprey capability backend — a live chat with
proper tool-call rendering, an interactive exploitation gate, and (next
milestones) attack-surface visualizations and standards-aligned reporting.

It is a **pure client** of the existing FastAPI backend. It adds no business
logic of its own: the chat runs Osprey's one ReAct loop (`cli.agent.loop.Runner`)
in the backend foreground and streams its events here; every data view reads the
same REST surface the CLI and MCP gateway already use.

## Architecture (how it plugs in)

```
┌────────────┐     SSE (POST /api/v1/agent/chat)      ┌──────────────────────────┐
│  Browser   │  ◀────────────────────────────────────  │  FastAPI backend          │
│ (this app) │     REST (/api/v1/… reads)              │  • foreground_chat ─► one │
│            │  ────────────────────────────────────▶  │    Runner per engagement  │
└────────────┘     POST /agent/question/{id}/answer    │  • event_bus / stores     │
                                                        └──────────────────────────┘
```

- **Chat** → `POST /api/v1/agent/chat` streams `thinking` / `tool_start` /
  `tool_end` / `question` / `assistant` / `done` as Server-Sent Events.
- **Interactive questions** → the agent's `ask_operator` tool emits a `question`
  event; the UI renders option chips; `POST /api/v1/agent/question/{id}/answer`
  resumes the same open stream. A `gate` question can flip the engagement's
  Rules-of-Engagement (exploitation).
- **Everything else** reads existing endpoints (engagements, findings,
  observations, graph, reasoning, …).

## Run (local dev)

Prerequisites: the Osprey backend running (default `http://localhost:9000`) and,
for a real chat, `LLM_MODEL` + `LLM_API_KEY` set in the backend's `.env`.

```bash
cd gui
npm install
cp .env.example .env.local        # optional; defaults to localhost:9000
npm run dev                        # http://localhost:3100
```

Then open http://localhost:3100.

- **Demo mode** (toggle in the chat top bar) replays a scripted run — tool
  cards, findings, and the exploitation gate — with **no backend or LLM key**,
  so you can see the interface immediately.
- Without a configured model, a real chat returns a clear "set LLM_MODEL…"
  message instead of failing.

## Build / check

```bash
npm run build        # production build
npm run typecheck    # tsc --noEmit
```

## Layout

```
src/
  app/                      # routes: / (launch), /engagement/[id] (workspace)
  components/
    brand/                  # OspreyMark (geometric osprey), wordmark, lockup
    shell/                  # WorkspaceProvider, Sidebar, TopBar, AppShell
    chat/                   # ChatView, TurnView, ToolCallCard, QuestionPrompt, …
  hooks/useChat.ts          # streaming + interactive-answer engine
  lib/                      # api client, SSE parser, event→turn reducer, types
```
