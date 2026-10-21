# Osprey GUI

A Next.js operator console for the Osprey capability backend — a live chat with
durable tool-call transcripts, interactive operator questions, attack-surface
inventory, focused relationship graphs, and evidence-aware reporting.

It is a **pure client** of the existing FastAPI backend. It adds no business
logic of its own: the chat runs Osprey's shared ReAct loop (`agent_core.loop.Runner`)
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

- **Chat** → `POST /stream/chat` (a Next streaming Route Handler that proxies the
  backend's `POST /api/v1/agent/chat`) streams public assistant messages, tool
  arguments/results, operator questions, and terminal events. `/api/*` and
  `/stream/*` share one streaming proxy; canonical backend redirects are followed
  server-side so a browser never escapes to another origin.
- **Refresh/reconnect** → `/api/v1/agent/chat-events/{id}?after=<cursor>` pages a
  durable ordered journal, then long-polls while the run is active. The backend
  owns the run independently of the browser connection. A browser refresh does
  not restart the run or duplicate its tools. A backend process restart stops
  execution, but saved transcript events remain. Older text-only conversations
  are retained; historical tool cards that were never saved cannot be recovered.
- **Interactive questions** → the agent's `ask_operator` tool emits a `question`
  event; the UI renders option chips; `POST /api/v1/agent/question/{id}/answer`
  resumes the same open stream. A `gate` question can flip the engagement's
  Rules-of-Engagement (exploitation).
- **Everything else** reads existing endpoints (engagements, findings,
  observations, graph, reasoning, …).
- **Graph** starts with an exhaustive category overview. Drill into searchable
  members and direct/two-hop connections, or open the full detailed topology.
  Fullscreen, back navigation, relationship filtering and original evidence
  inspection support large engagements. Graph risk links to recorded findings;
  arrow directions retain their stored meaning. JSON export and explicit limits
  remain available. Category counts are stored records, not unique machines.
- **Findings** separates conclusions, scanner signals and legacy review records,
  with evidence inspection and navigation to affected graph targets.
- **Evidence** pages and searches the original observation/finding stores,
  including execution notes and legacy rows omitted from vulnerability totals.
  Inventory/finding/graph inspection retrieves complete source records on demand.
- **Background jobs** in Chat have their own progress, results and cancellation.
  Stopping the chat driver does not cancel independent jobs.

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

Development output is `.next-dev`; production build/start use `.next`. A normal
`npm run build` can therefore run without overwriting the open dev server's
manifests. `OSPREY_NEXT_DIST` explicitly overrides this for isolated testing;
do not point two concurrently running processes at the same override directory.

- **Demo mode** (toggle in the chat top bar) replays a scripted run — tool
  cards and assistant messages — with **no LLM key or live execution**,
  so you can see the interface immediately.
- **Settings** (⚙ in the sidebar footer) picks the LLM provider/model and stores
  an API key — no `.env` editing. Configuration checks are not provider connectivity
  tests. A saved key/custom base is retained when omitted; changing providers
  clears both unless replacements are supplied. Changes apply on the next idle
  turn, not halfway through an active run. Keys are not returned to the browser.
- **No prompt needed:** after a target binds, **Start autonomous recon** (or a
  suggestion chip) kicks off a recon-first plan that pauses before anything
  intrusive.
- Without a usable model, a real chat returns a clear error pointing at Settings
  instead of hanging.

## Build / check

```bash
npm run build        # production build
npm run typecheck    # tsc --noEmit
npx vitest run       # transcript reducer, SSE framing, graph projections
```

The backend applies migration `0024_chat_events` on startup. Run the updated
backend together with the updated GUI. See [GUI review](../docs/GUI_REVIEW.md)
for architecture, verified defects, test scope, and limitations.

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
