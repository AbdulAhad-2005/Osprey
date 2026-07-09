# Autonomous AI Penetration Testing Platform
## Technical Implementation Report

**Modified Date:** 9 July, 2026  
**Repository:** AI-Pentesting-Tool  

---

## 1. Executive Summary

This project implements an autonomous AI-driven penetration testing platform that orchestrates security tools through a structured pipeline: **Governance → Tool Execution → Audit Logging**. The platform is built as a FastAPI backend with 90 security tools organized across 10 category-based MCP (Model Context Protocol) servers, a typed tool registry with safety classifications, a scope-enforcement governance engine, and an immutable audit log.

---

## 2. What Was Implemented (Current State)

### 2.1 Tool Registry — 90 Tools Across 10 Categories

| Category | Tools | Examples | Safety Levels |
|----------|-------|----------|---------------|
| Recon | 9 | subfinder, amass, httpx, gau, waybackurls | All PASSIVE |
| Network | 15 | nmap (3 variants), rustscan, masscan, smbmap, enum4linux-ng | ACTIVE + 3 custom nmap |
| Web/Webapp | 22 | ffuf, gobuster, sqlmap, nikto, katana, dalfox, wpscan | ACTIVE (sqlmap = GATED) |
| Vulnerability | 2 | nuclei, jaeles | ACTIVE |
| Cloud | 12 | prowler, trivy, kube-hunter, checkov, docker-bench | ACTIVE (pacu = GATED) |
| Credentials | 3 | hydra, hashcat, john | All GATED |
| Exploitation | 3 | metasploit, msfvenom, pwntools | All GATED |
| API Testing | 3 | api_fuzzer, graphql_scanner, api_schema_analyzer | All ACTIVE |
| Binary Analysis | 15 | gdb, ghidra, radare2, angr, checksec, ropgadget | Mixed |
| Forensics | 6 | exiftool, foremost, steghide, volatility | Mixed |

Each tool definition includes: name, category, executable binary, safety level (PASSIVE/ACTIVE/GATED), description, tags, install hint, MCP server mapping, and typed parameter schema.

### 2.2 Governance Engine

A pre-execution check that runs before every tool call:

1. **Safety level check** — GATED tools require `allow_exploitation=True` in the engagement's Rules of Engagement
2. **Category allow/block list** — Engagement can block specific categories (e.g., "no credential attacks")
3. **Target scope enforcement** — Supports CIDR ranges (`10.0.0.0/24`), exact matches, wildcard domains (`*.example.com`), and substring matching
4. **Time window constraints** — Tools only execute within allowed UTC time windows

### 2.3 Audit Log

Every tool execution (approved or denied) is recorded with:
- Tool name, target, engagement ID
- Command executed, success/failure, return code
- Duration, governance decision and reason
- Recovery actions, error details

Thread-safe, append-only, bounded to 10,000 entries (production: Postgres).

### 2.4 Engagement System

Engagements define the scope and rules for a pentest:
- In-scope targets (CIDR, domains, IPs)
- Out-of-scope exclusions
- Allowed/blocked technique categories
- Exploitation permission toggle
- Human approval gate toggle
- Time window restrictions

### 2.5 MCP Client

An async subprocess manager that spawns FastMCP server processes (`mcp-servers/<category>/server.py`) on first use and communicates via JSON-RPC over stdio. Each category runs as an independent process.

### 2.6 API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/tools/` | GET | List all 90 tools, filter by category |
| `/api/v1/tools/catalog` | GET | Summary stats (installed/missing/by-category) |
| `/api/v1/tools/by-server/{server}` | GET | Tools per MCP server |
| `/api/v1/tools/{name}` | GET | Single tool lookup |
| `/api/v1/mcp/execute` | POST | Execute tool (governance → MCP → audit) |
| `/api/v1/engagements/` | GET/POST | List and create engagements |
| `/api/v1/engagements/{id}` | GET/DELETE | Get or delete engagement |
| `/api/v1/audit/` | GET | Query audit log |

### 2.7 Test Coverage

- **17 pytest unit tests** — catalog, engagements, governance denial, audit logging
- **144 integration tests** — full pipeline verification (tool registry, API, governance, MCP server discovery, audit)

---

## 3. Architecture

### 3.1 System Architecture (4 Planes)

```
┌─────────────────────────────────────────────────────────────┐
│  PLANNING & REASONING PLANE                                 │
│  Orchestrator · Task-tree planner · Cost-aware scheduler    │
│  Reflection/self-critique loop · LLM-agnostic (BYO model)   │
│  [PLANNED — not yet implemented]                            │
└───────────────┬─────────────────────────────────────────────┘
                │  structured tool calls (MCP)
┌───────────────▼─────────────────────────────────────────────┐
│  GOVERNANCE PLANE                          [IMPLEMENTED]     │
│  Scope engine · Safety level enforcement                     │
│  Authorization ledger · Audit log                            │
└───────────────┬─────────────────────────────────────────────┘
                │
┌───────────────▼────────────────────────────────────────────┐
│  EXECUTION PLANE                         [IMPLEMENTED]      │
│  MCP servers (10 category servers, 90 tools)                │
│  Safe subprocess executor (shell=False)                     │
│  Error recovery · Caching · Tool alternatives               │
└───────────────┬────────────────────────────────────────────┘
                │
┌───────────────▼──────────────────────────────────────────────┐
│  MEMORY & STATE PLANE                                        │
│  Engagement graph · Vector recall                            │
│  Durable workflow engine (Temporal) · Session resume         │
│  [PLANNED — not yet implemented]                             │
└──────────────────────────────────────────────────────────────┘
```

### 3.2 Backend Structure

```
backend/
  src/pentest_platform/
    main.py                          # FastAPI app entrypoint
    core/config.py                   # pydantic-settings config
    schemas/
      tools.py                       # ToolDefinition, ToolCategory, ToolSafetyLevel, MCPServerCategory
      engagement.py                  # Engagement, RulesOfEngagement, ScopeConfig
      audit.py                       # AuditAction, AuditLogEntry
    services/
      tool_registry.py               # 90-tool registry with lookup/filter/availability
      mcp_client.py                  # Async MCP server subprocess manager
      governance.py                  # Pre-execution scope + safety checks
      audit_log.py                   # Immutable action log
      engagement_store.py            # In-memory engagement CRUD
    api/v1/
      endpoints/
        tools.py                     # Tool catalog API
        mcp.py                       # Tool execution pipeline
        engagements.py               # Engagement CRUD
        audit.py                     # Audit log query
        health.py, models.py, agent.py  # Existing stubs
      router.py                      # Route registration
  tests/
    test_tools.py                    # 17 unit tests
    test_full_tool_feature.py        # 144 integration checks
    test_health.py                   # Health endpoint tests
```

### 3.3 Execution Flow

```
Client → POST /api/v1/mcp/execute
  → Tool Registry lookup (name → ToolDefinition)
  → Governance Engine check:
      ├── Safety level vs RoE
      ├── Category allow/block
      ├── Target scope (CIDR/wildcard/exact)
      └── Time window
  → If denied → 403 + audit record
  → If approved → MCP Client call_tool():
      ├── Resolve MCP server (category → server.py)
      ├── Spawn subprocess if not running
      ├── Send JSON-RPC request via stdio
      └── Parse response
  → Audit Log record
  → Return ToolExecutionResponse
```

---

## 4. Comparative Analysis: What Was Borrowed

### 4.1 From HexStrike AI

| Aspect | HexStrike Approach | Our Adoption |
|--------|-------------------|--------------|
| Tool coverage | 150+ tools via Flask HTTP | **Borrowed**: All 90 real CLI tools harvested into MCP servers |
| Error recovery | `IntelligentErrorHandler` — classify error → retry/adjust/switch/escalate | **Borrowed**: Full error handler lifted into `mcp-servers/_core/error_handler.py` (693 lines) |
| Tool alternatives | Map of fallback tools per category | **Borrowed**: 30+ tool alternative chains in `_core/error_handler.py` |
| Parameter auto-adjustment | `ParameterOptimizer` adjusts flags on timeout/rate-limit | **Borrowed**: Per-tool parameter adjustment rules |
| Graceful degradation | Fallback chains (nmap→rustscan→masscan→ping) | **Borrowed**: 5 degradation paths for different operation types |

**What we did NOT borrow:**
- `shell=True` subprocess execution → We use `shell=False` with argument lists (security hardening)
- Monolithic Flask server → We split into 10 independent FastMCP category servers
- No governance/authorization checks → We added a full governance plane

### 4.2 From Shannon

| Aspect | Shannon Approach | Our Adoption |
|--------|-----------------|--------------|
| Temporal workflows | Crash-proof durable workflows with retry/recovery | **Planned**: Will adopt for multi-hour engagements |
| Confirmed/unconfirmed findings | Only reports findings with working PoC evidence | **Planned**: Will adopt for finding validation |
| Collector MCP pattern | One-shot Zod-validated tool calls, deterministic rendering | **Planned**: Will adopt for structured agent output |
| Scope locking | Engagement scope locked on first run, can't change mid-scan | **Adopted**: Our scope config is immutable per engagement |
| Git checkpoint/rollback | Every agent gets pre-execution commit, rollback on failure | **Planned**: Will adopt for agent state management |

**What we did NOT borrow:**
- Claude-only SDK dependency → Our architecture is LLM-agnostic
- Hardcoded 5 vulnerability classes → Our tool registry is extensible
- TypeScript-only codebase → Our stack is Python-native

### 4.3 From Strix

| Aspect | Strix Approach | Our Adoption |
|--------|---------------|--------------|
| Skills system | Markdown knowledge files injected into agent prompts | **Planned**: Will create `skills/` directory with vulnerability playbooks |
| Two-tier model | Tools = actions, Skills = knowledge | **Planned**: Skills teach agents how to use tools effectively |
| Scan modes | Quick/Standard/Deep modes via skill files | **Planned**: Will adopt for configurable scan intensity |
| Agent spawning pattern | Reactive (spawn based on discoveries, not all at once) | **Planned**: Will adopt for multi-agent orchestration |
| Sandbox isolation | All agent execution in Docker containers | **Planned**: Will adopt for tool execution isolation |

**What we did NOT borrow:**
- OpenAI Agents SDK dependency → Our MCP client is SDK-agnostic
- Skills as prompt-only (no execution) → Our tools have real execution via MCP servers

### 4.4 From Our Architecture Blueprint

| Blueprint Requirement | Implementation Status |
|----------------------|----------------------|
| Governance plane (scope engine, audit log) | **DONE** — `services/governance.py`, `services/audit_log.py` |
| Tool abstraction via MCP (category-based servers) | **DONE** — 10 MCP servers, 90 tools |
| Typed tool registry (categories, safety, tags) | **DONE** — `schemas/tools.py`, `services/tool_registry.py` |
| Engagement system with RoE | **DONE** — `schemas/engagement.py`, `services/engagement_store.py` |
| Memory & State plane (engagement graph) | **PLANNED** — Postgres + NetworkX |
| Planning & Reasoning plane (Planner/Critic) | **PLANNED** — LiteLLM + agent loop |
| Durable workflow engine (Temporal) | **PLANNED** — Will integrate for crash recovery |
| Reporting engine | **PLANNED** — Structured finding schema |

---

## 5. Technology Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Backend API | FastAPI (Python 3.12+) | Already scaffolded, async-native |
| Data validation | Pydantic v2 | Type-safe schemas, auto-generated API docs |
| Configuration | pydantic-settings | Environment variable management |
| Tool execution | MCP servers (FastMCP) | Standard protocol, community support |
| Database (planned) | PostgreSQL 16 + SQLAlchemy 2.0 | Already in docker-compose |
| Workflow (planned) | Temporal | Crash recovery, long-running engagements |
| Model abstraction (planned) | LiteLLM | One call signature across Claude/GPT/Gemini/Ollama |
| Sandboxing (planned) | Docker SDK for Python | Ephemeral containers per tool run |
| Testing | pytest + httpx | Already working, 17 unit + 144 integration tests |

---

## 6. Current Dev Environment

### What Works Now (Windows + Docker Compose)

```
docker-compose.yml
  ├── postgres:16-alpine     ← Database (running)
  └── backend                 ← FastAPI app (running on port 9000)
```

The backend runs inside Docker. The 90-tool registry, governance engine, audit log, and engagement system are fully functional and tested.

### What's Missing: Security Tool Binaries

The MCP servers (`mcp-servers/`) wrap CLI tools like `nmap`, `nuclei`, `subfinder`, `ffuf`, etc. These are Linux binaries not available on Windows. The tool registry correctly reports them as `installed: false` via `shutil.which()`.

**Current state:** Governance, audit, engagement, and catalog features work perfectly. Actual tool execution returns clean "binary not found" errors.

---

## 7. Plan: Running Security Tools (Kali Docker Container)

### Recommended Approach: Dedicated Kali Tools Container

The cleanest solution is a dedicated Docker container based on Kali Linux that has all security tools pre-installed. The backend spawns MCP server processes that run inside this container.

### Architecture

```
┌──────────────────────────────────────────────────┐
│  Docker Compose                                   │
│                                                   │
│  ┌──────────────┐  ┌───────────────────────────┐ │
│  │ postgres:16   │  │ kali-tools                │ │
│  │ (database)    │  │ (90 security binaries)    │ │
│  └──────────────┘  │ MCP servers run here       │ │
│                     └───────────────────────────┘ │
│  ┌──────────────────────────────────────────────┐ │
│  │ backend                                       │ │
│  │ (FastAPI + MCP client spawns processes        │ │
│  │  inside kali-tools via docker exec)           │ │
│  └──────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
```

### Implementation Steps

**Step 1: Create `kali-tools/Dockerfile`**
```dockerfile
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Recon
    amass subfinder httpx waybackurls hakrawler dnsenum fierce gau anew \
    # Network
    nmap rustscan masscan enum4linux enum4linux-ng smbmap netexec \
    responder rpcclient arp-scan nbtscan autorecon \
    # Web
    gobuster feroxbuster dirsearch dirb wfuzz ffuf sqlmap nikto \
    zaproxy katana dalfox xsser wpscan wafw00f dotdotpwn \
    arjun paramspider x8 qsreplace uro \
    # Vulnerability
    nuclei jaeles \
    # Cloud
    prowler trivy kube-hunter kube-bench checkov terrascan \
    docker-bench-security \
    # Credentials
    hydra hashcat john \
    # Exploitation
    metasploit-framework msfvenom \
    # API
    curl \
    # Binary
    gdb checksec strings xxd objdump binwalk radare2 \
    # Forensics
    exiftool foremost steghide hashpump volatility \
    # Utilities
    python3 python3-pip curl wget git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for MCP server execution
RUN useradd -m -s /bin/bash mcpuser
USER mcpuser
WORKDIR /home/mcpuser

# MCP servers will be mounted here
VOLUME ["/home/mcpuser/mcp-servers"]
```

**Step 2: Update `docker-compose.yml`**
```yaml
services:
  postgres:
    image: postgres:16-alpine
    # ... (existing config)

  kali-tools:
    build:
      context: ./kali-tools
    container_name: ai-pentest-kali
    volumes:
      - ./mcp-servers:/home/mcpuser/mcp-servers
    stdin_open: true
    tty: true
    # No ports needed — backend connects via docker exec
    healthcheck:
      test: ["CMD", "which", "nmap"]
      interval: 30s
      timeout: 5s
      retries: 3

  backend:
    build:
      context: ./backend
    env_file:
      - .env
    environment:
      DATABASE_URL: ${DATABASE_URL:-postgresql+psycopg://pentest:pentest@postgres:5432/pentest}
      KALI_CONTAINER: ai-pentest-kali
    volumes:
      - ./backend:/app
      - /var/run/docker.sock:/var/run/docker.sock  # For docker exec
    ports:
      - "9000:9000"
    depends_on:
      postgres:
        condition: service_healthy
      kali-tools:
        condition: service_healthy
```

**Step 3: Update `services/mcp_client.py`**

Replace direct subprocess spawning with `docker exec` into the kali-tools container:

```python
async def ensure_server(self, server: MCPServerCategory) -> str:
    """Ensure MCP server is available inside kali-tools container."""
    # Use docker exec to run the MCP server script
    # The MCP client sends JSON-RPC via stdin/stdout
    container = os.getenv("KALI_CONTAINER", "ai-pentest-kali")
    script = f"/home/mcpuser/mcp-servers/{server.value}/server.py"
    # docker exec -i ai-pentest-kali python3 /home/mcpuser/mcp-servers/recon/server.py
```

**Step 4: Update `backend/Dockerfile`**

Add Docker CLI to the backend container so it can run `docker exec`:

```dockerfile
# Add Docker CLI for kali-tools communication
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev docker.io \
    && rm -rf /var/lib/apt/lists/*
```

### Alternative: Kali WSL2 (Simpler for Dev)

If you prefer not to use Docker for Kali:

1. Enable WSL2 on Windows
2. Install Kali Linux from Microsoft Store
3. Install tools inside Kali: `sudo apt install kali-tools-top10`
4. The backend (running in Docker or Windows) calls tools via WSL:

```python
# In mcp_client.py, for Windows dev:
import subprocess
result = subprocess.run(
    ["wsl", "-d", "kali-linux", "--", "nmap", "-sV", target],
    capture_output=True, text=True
)
```

### Comparison

| Approach | Pros | Cons |
|----------|------|------|
| **Kali Docker container** | Reproducible, isolated, matches production | More complex docker-compose, needs Docker socket mount |
| **Kali WSL2** | Simple, fast, native Windows integration | Windows-only, manual tool updates, not reproducible |
| **Tool-by-tool Docker** | Fine-grained control | N containers to manage, overkill |

**Recommendation:** Start with **Kali WSL2** for fast local dev, then move to the **Kali Docker container** for production/reproducibility. The backend code change is minimal (just the MCP client's `ensure_server` method).

---

## 8. Testing Summary

### How to Run Tests

```bash
# Unit tests (17 tests, ~6 seconds)
cd backend
python -m pytest tests/ -v

# Full integration test (144 checks, ~8 seconds)
cd backend
python tests/test_full_tool_feature.py
```

### Test Coverage

| Area | Tests | Status |
|------|-------|--------|
| Tool catalog (90 tools) | 100+ checks | All passing |
| Tool lookup/filter | 9 checks | All passing |
| API endpoints (catalog) | 8 checks | All passing |
| Engagement CRUD | 7 checks | All passing |
| Governance (scope/safety) | 10 checks | All passing |
| Audit log | 3 checks | All passing |
| MCP server discovery | 10 checks | All passing |
| **Total** | **144 + 17 = 161** | **All passing** |

---

## 9. What's Next (Planned Work)

| Priority | Feature | Dependencies | Estimated Effort |
|----------|---------|-------------|-----------------|
| 1 | Kali Docker container setup | Docker | 1 day |
| 2 | Wire MCP client to Kali container | Kali container | 1 day |
| 3 | Real tool execution end-to-end | Kali container + MCP client | 2 days |
| 4 | Per-tool `parse()` functions (not stubs) | Real tool output | 3 days |
| 5 | Skills system (markdown knowledge files) | None | 2 days |
| 6 | Planner/Critic agent loop | LiteLLM integration | 1 week |
| 7 | Engagement graph (Postgres + NetworkX) | Postgres schema | 3 days |
| 8 | Temporal workflow integration | Temporal server | 1 week |
| 9 | Exploitation module with impact-tiered gates | Governance + Skills | 1 week |
| 10 | Reporting engine | Finding schema + graph | 3 days |

---

## 10. Key Files Reference

| File | Purpose |
|------|---------|
| `backend/src/pentest_platform/schemas/tools.py` | Tool definitions, categories, safety levels, MCP server mapping |
| `backend/src/pentest_platform/services/tool_registry.py` | 90-tool registry with lookup and availability check |
| `backend/src/pentest_platform/services/mcp_client.py` | Async MCP server subprocess manager |
| `backend/src/pentest_platform/services/governance.py` | Pre-execution scope and safety enforcement |
| `backend/src/pentest_platform/services/audit_log.py` | Immutable action audit trail |
| `backend/src/pentest_platform/services/engagement_store.py` | Engagement CRUD storage |
| `backend/src/pentest_platform/api/v1/endpoints/mcp.py` | Tool execution pipeline endpoint |
| `backend/tests/test_full_tool_feature.py` | 144-check integration test suite |
| `mcp-servers/_core/` | Shared execution infrastructure (executor, error handler, cache, runner) |
| `mcp-servers/*/server.py` | 10 category-based FastMCP servers |

---

## 11. Appendix: Tool-to-MCP-Server Mapping

| MCP Server | Script Location | Tool Count |
|------------|----------------|------------|
| recon-mcp | `mcp-servers/recon/server.py` | 9 |
| network-mcp | `mcp-servers/network/server.py` | 15 |
| web-mcp | `mcp-servers/web/server.py` | 22 |
| vuln-mcp | `mcp-servers/vuln/server.py` | 2 |
| cloud-mcp | `mcp-servers/cloud/server.py` | 12 |
| creds-mcp | `mcp-servers/creds/server.py` | 3 |
| exploit-mcp | `mcp-servers/exploit/server.py` | 3 |
| api-mcp | `mcp-servers/api/server.py` | 3 |
| binary-mcp | `mcp-servers/binary/server.py` | 15 |
| forensics-mcp | `mcp-servers/forensics/server.py` | 6 |
| **Total** | | **90** |

---

*This document is a living report. Update as new features are implemented.*
