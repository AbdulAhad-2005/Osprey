#!/usr/bin/env bash
# ==============================================================================
# Osprey - Guided Interactive Setup & Onboarding Wizard (Linux / macOS / Kali / WSL)
# ==============================================================================
#
# Walks through:
#   [1/5] Tool execution & infrastructure mode (Full Docker / Lean / Hybrid / Local)
#   [2/5] Tool environment initialization & scanner checks
#   [3/5] Usage mode selection (Built-in CLI, AI Harness via MCP, or Both)
#   [4/5] Model configuration (LiteLLM provider presets & API key)
#   [5/5] Optional OSINT API keys & automatic AI harness MCP configuration
#
# Usage: bash scripts/install.sh
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

# ── Styling & output helpers ──────────────────────────────────────────────────
if [ -t 1 ]; then
  C_BOLD=$'\033[1m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'
  C_CYAN=$'\033[36m'; C_DARK=$'\033[90m'; C_RESET=$'\033[0m'
else
  C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_CYAN=""; C_DARK=""; C_RESET=""
fi

write_header() {
  local title="$1"
  printf '\n%s┌─────────────────────────────────────────────────────────────┐%s\n' "${C_CYAN}" "${C_RESET}"
  printf '%s│  %-58s │%s\n' "${C_CYAN}" "$title" "${C_RESET}"
  printf '%s└─────────────────────────────────────────────────────────────┘%s\n' "${C_CYAN}" "${C_RESET}"
}

info()    { printf '\n%s==>%s %s\n' "${C_CYAN}" "${C_RESET}" "$*"; }
ok()      { printf '%s  [OK]%s %s\n' "${C_GREEN}" "${C_RESET}" "$*"; }
warn()    { printf '%s  [!] %s %s\n' "${C_YELLOW}" "${C_RESET}" "$*"; }
fail()    { printf '%s  [X] %s %s\n' "${C_RED}" "${C_RESET}" "$*"; }
muted()   { printf '%s       %s%s\n' "${C_DARK}" "$*" "${C_RESET}"; }
ask()     { printf '%s%s%s ' "${C_BOLD}" "$*" "${C_RESET}"; }

# ── .env upsert helper ────────────────────────────────────────────────────────
env_set() {
  local key="$1" value="$2" file="${3:-.env}"
  local tmp; tmp="$(mktemp 2>/dev/null || mktemp -t 'osprey_env')"
  local found=0
  if [ -f "$file" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      case "$line" in
        "$key="*) printf '%s=%s\n' "$key" "$value" >> "$tmp"; found=1 ;;
        *) printf '%s\n' "$line" >> "$tmp" ;;
      esac
    done < "$file"
  fi
  if [ "$found" -eq 0 ]; then
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
  fi
  mv "$tmp" "$file"
}

env_get() {
  local key="$1" default="${2:-}" file="${3:-.env}"
  if [ ! -f "$file" ]; then printf '%s' "$default"; return; fi
  local val; val="$(grep -E "^${key}=" "$file" | tail -n1 | cut -d'=' -f2-)"
  printf '%s' "${val:-$default}"
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    fail "docker is not installed or not in PATH. Please install Docker Engine / Desktop first."
    return 1
  fi
  if ! docker info >/dev/null 2>&1; then
    fail "docker is installed but the daemon is unreachable (is Docker running?)."
    return 1
  fi
  return 0
}

wait_for_backend() {
  local url="http://localhost:9000/health" tries=60
  printf '%s  Waiting for backend at %s ' "${C_CYAN}" "$url"
  for _ in $(seq 1 "$tries"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      printf '\n'
      ok "Backend is healthy and listening on http://localhost:9000"
      return 0
    fi
    printf '%s.' "${C_DARK}"
    sleep 1
  done
  printf '\n'
  warn "Backend did not respond within ${tries}s. It may still be starting."
  warn "Inspect logs with:  docker compose logs -f backend"
  return 1
}

resolve_python_path() {
  if [ -f "$ROOT_DIR/.venv/bin/python" ]; then
    printf '%s' "$ROOT_DIR/.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    command -v python3
  else
    printf 'python3'
  fi
}

# ── Banner ────────────────────────────────────────────────────────────────────
clear 2>/dev/null || true
printf '%s' "${C_RED}"
cat << 'BANNER'
   ____  _____ _____  _____  ________   __
  / __ \/ ___// __ \/ __ \/ ____/\ \ / /
 / / / /\__ \/ /_/ / /_/ / __/    \ V /  
/ /_/ /___/ / ____/ _, _/ /___     / /   
\____//____/_/   /_/ |_/_____/    /_/    
Autonomous AI Offensive Security Platform
BANNER
printf '%s\n' "${C_RESET}"

muted "Welcome to the Osprey setup wizard. Press Ctrl+C anytime to exit."
muted "Re-running this wizard is always safe and preserves existing work."

# ── Ensure .env exists ────────────────────────────────────────────────────────
if [ ! -f .env ]; then
  cp .env.example .env
  ok "Initialized .env from .env.example"
else
  ok "Found existing .env (will update only selected keys)"
fi

# ==============================================================================
# [1/5] Execution & Tool Runtime Selection
# ==============================================================================
write_header "[1/5] How should Osprey & security tools run?"

printf '%s  1) Full Docker (Recommended)%s\n' "${C_BOLD}" "${C_RESET}"
muted "All-in-one: Postgres DB, Backend API & 90+ Kali tools in Docker."
muted "Zero tool installation required on your host system."

printf '%s  2) Lean Docker (Custom Tools Container)%s\n' "${C_BOLD}" "${C_RESET}"
muted "Postgres & Backend in Docker; tools executed via your own existing container."

printf '%s  3) Hybrid (Docker Postgres + Local Scanners)%s\n' "${C_BOLD}" "${C_RESET}"
muted "Postgres runs in Docker; Backend and security scanners run on this machine."

printf '%s  4) Fully Local, No Docker (Self-contained / SQLite)%s\n' "${C_BOLD}" "${C_RESET}"
muted "Backend and tools run on this machine with local SQLite database (no Docker required)."

printf '%s  0) Manual Setup%s\n' "${C_BOLD}" "${C_RESET}"
muted "Keep .env as-is; I will start services manually."

ask "Select execution mode [1]:"; read -r runtime_choice
runtime_choice="${runtime_choice:-1}"

case "$runtime_choice" in
  1)
    require_docker || exit 1
    write_header "Full Docker: Kali Image Source"
    printf '%s  1) Pull prebuilt Kali image from Docker Hub (Fast, ~2-5 min, Recommended)%s\n' "${C_BOLD}" "${C_RESET}"
    muted "Image: ospreytools/osprey-kali:latest (prebuilt with all 90+ tools)"
    printf '%s  2) Build Kali image from source (Slow, ~40-60 min, needs ~16GB disk)%s\n' "${C_BOLD}" "${C_RESET}"
    muted "Compiles all tools locally via kali-tools/Dockerfile"

    ask "Select image source [1]:"; read -r img_choice
    img_choice="${img_choice:-1}"

    env_set "KALI_CONTAINER" "osprey-kali"
    env_set "DATABASE_URL" "postgresql+psycopg://pentest:pentest@postgres:5432/pentest"

    if [ "$img_choice" = "2" ]; then
      info "Building Kali image from source and starting stack..."
      warn "This build compiles heavy tools and may take 40-60 minutes on cold runs."
      if docker compose --profile kali -f docker-compose.yml -f docker-compose.build.yml up -d --build; then
        ok "Docker stack started (built from source)."
        wait_for_backend || true
      else
        fail "Build/compose failed. Ensure Docker has adequate disk space (~16GB free)."
        exit 1
      fi
    else
      env_set "OSPREY_KALI_IMAGE" "ospreytools/osprey-kali:latest"
      info "Pulling prebuilt image (ospreytools/osprey-kali:latest) & launching stack..."
      if docker compose --profile kali up -d; then
        ok "Docker stack started."
        wait_for_backend || true
      else
        fail "docker compose failed. Please check the error output above."
        exit 1
      fi
    fi
    ;;

  2)
    require_docker || exit 1
    current_cont="$(env_get "KALI_CONTAINER" "my-kali-container")"
    ask "Enter the name of your running tools container [$current_cont]:"; read -r tools_cont
    tools_cont="${tools_cont:-$current_cont}"
    if [ -z "$tools_cont" ]; then fail "Container name cannot be empty."; exit 1; fi

    env_set "KALI_CONTAINER" "$tools_cont"
    env_set "DATABASE_URL" "postgresql+psycopg://pentest:pentest@postgres:5432/pentest"

    info "Starting Postgres + Backend in Docker (targeting container '$tools_cont')..."
    if docker compose up -d; then
      ok "Stack started. Tools will be executed into '$tools_cont'."
      wait_for_backend || true
    else
      fail "docker compose failed."; exit 1
    fi
    ;;

  3)
    require_docker || exit 1
    env_set "DATABASE_URL" "postgresql+psycopg://pentest:pentest@localhost:5432/pentest"
    env_set "KALI_CONTAINER" ""

    info "Starting Postgres database container..."
    if docker compose up -d postgres; then
      ok "Postgres container is active on localhost:5432"
    else
      fail "Failed to start Postgres container."; exit 1
    fi

    info "Setting up local Python virtual environment for backend & tools..."
    bash "$SCRIPT_DIR/setup.sh"
    ;;

  4)
    env_set "DATABASE_URL" "sqlite:///./pentest.db"
    env_set "KALI_CONTAINER" ""

    info "Configured SQLite local database (pentest.db)."
    info "Setting up local Python virtual environment..."
    bash "$SCRIPT_DIR/setup.sh"
    ;;

  0)
    ok "Manual mode selected. Preserved current .env."
    ;;

  *)
    fail "Unrecognized option '$runtime_choice'."
    exit 1
    ;;
esac

# ==============================================================================
# [2/5] Tool Environment Detection (For Local/Hybrid Modes)
# ==============================================================================
if [ "$runtime_choice" = "3" ] || [ "$runtime_choice" = "4" ]; then
  write_header "[2/5] Host Tool Availability & Scanner Detection"
  printf '%sScanning for native security tools on your PATH...%s\n' "${C_CYAN}" "${C_RESET}"

  tools_to_check="nmap whois amass subfinder httpx naabu dnsx tlsx katana nuclei ffuf searchsploit"
  missing_tools=()

  tool_present() {
    case "$1" in
      httpx) command -v httpx-toolkit >/dev/null 2>&1 || command -v httpx >/dev/null 2>&1 ;;
      *) command -v "$1" >/dev/null 2>&1 ;;
    esac
  }

  for t in $tools_to_check; do
    if tool_present "$t"; then
      printf '%s  [✓] %-14s : Found%s\n' "${C_GREEN}" "$t" "${C_RESET}"
    else
      printf '%s  [!] %-14s : Missing%s\n' "${C_YELLOW}" "$t" "${C_RESET}"
      missing_tools+=("$t")
    fi
  done

  if [ "${#missing_tools[@]}" -eq 0 ]; then
    ok "All primary security scanners are present on this host!"
  else
    printf '\n'
    warn "${#missing_tools[@]} tool(s) are missing on your host machine."
    muted "Osprey will gracefully adapt and use whichever tools are installed."

    SUDO=""
    if [ "$(id -u 2>/dev/null || echo 1000)" != "0" ] && command -v sudo >/dev/null 2>&1; then
      SUDO="sudo"
    fi

    ask "Attempt automatic installation of missing tools? [Y/n]:"; read -r install_ans
    install_ans="${install_ans:-y}"

    if [ "$install_ans" = "y" ] || [ "$install_ans" = "Y" ]; then
      for mt in "${missing_tools[@]}"; do
        info "Installing $mt..."
        case "$mt" in
          nmap|whois|amass|ffuf)
            if command -v apt-get >/dev/null 2>&1; then
              $SUDO apt-get update -qq && $SUDO apt-get install -y "$mt" || warn "apt-get install $mt failed"
            elif command -v brew >/dev/null 2>&1; then
              brew install "$mt" || warn "brew install $mt failed"
            fi
            ;;
          subfinder|httpx|naabu|dnsx|tlsx|katana|nuclei)
            if command -v go >/dev/null 2>&1; then
              go install "github.com/projectdiscovery/${mt}/cmd/${mt}@latest" 2>/dev/null || \
              go install "github.com/projectdiscovery/${mt}/v2/cmd/${mt}@latest" 2>/dev/null || \
              go install "github.com/projectdiscovery/${mt}/v3/cmd/${mt}@latest" 2>/dev/null || warn "go install $mt failed"
            elif command -v brew >/dev/null 2>&1; then
              brew install "projectdiscovery/tap/$mt" 2>/dev/null || brew install "$mt" || warn "brew install $mt failed"
            fi
            ;;
          searchsploit)
            if command -v apt-get >/dev/null 2>&1; then
              $SUDO apt-get update -qq && $SUDO apt-get install -y exploitdb || warn "apt-get install exploitdb failed"
            elif command -v brew >/dev/null 2>&1; then
              brew install exploitdb || warn "brew install exploitdb failed"
            fi
            ;;
        esac
      done
    fi
  fi
fi

# ==============================================================================
# [3/5] Usage Mode Selection
# ==============================================================================
write_header "[3/5] How do you plan to use Osprey?"

printf '%s  1) Both Built-in CLI & AI Harness (MCP) (Recommended - complete access)%s\n' "${C_BOLD}" "${C_RESET}"
muted "Use our native CLI (osprey) AND connect AI clients like Claude, Cursor, OpenCode."

printf '%s  2) Built-in CLI only%s\n' "${C_BOLD}" "${C_RESET}"
muted "Drive tests directly via the interactive terminal interface (osprey / python -m cli)."

printf '%s  3) AI Harness via MCP only%s\n' "${C_BOLD}" "${C_RESET}"
muted "Control Osprey exclusively from Claude Desktop, Cursor, OpenCode, Windsurf, or ChatGPT."

ask "Select usage mode [1]:"; read -r usage_choice
usage_choice="${usage_choice:-1}"

needs_cli_llm=0
if [ "$usage_choice" = "1" ] || [ "$usage_choice" = "2" ]; then
  needs_cli_llm=1
fi

# ==============================================================================
# [4/5] LLM Configuration
# ==============================================================================
write_header "[4/5] LLM Provider Configuration"

if [ "$needs_cli_llm" -eq 1 ]; then
  printf '%sThe Osprey CLI uses LiteLLM to drive its autonomous agent loop.%s\n' "${C_BOLD}" "${C_RESET}"
  printf '%sSelect your LLM provider preset or enter a custom identifier:%s\n' "${C_CYAN}" "${C_RESET}"
  echo "  1) Anthropic    : anthropic/claude-sonnet-5"
  echo "  2) OpenAI       : openai/gpt-4o"
  echo "  3) Google Gemini: gemini/gemini-2.5-flash"
  echo "  4) OpenRouter   : openrouter/anthropic/claude-sonnet-5"
  echo "  5) Groq         : groq/llama-3.3-70b-versatile"
  echo "  6) Local Ollama : ollama/llama3.3"
  echo "  7) Custom model identifier"
  echo "  0) Skip (configure in .env manually later)"

  ask "Choose provider preset [1]:"; read -r preset
  preset="${preset:-1}"

  chosen_model=""
  case "$preset" in
    1) chosen_model="anthropic/claude-sonnet-5" ;;
    2) chosen_model="openai/gpt-4o" ;;
    3) chosen_model="gemini/gemini-2.5-flash" ;;
    4) chosen_model="openrouter/anthropic/claude-sonnet-5" ;;
    5) chosen_model="groq/llama-3.3-70b-versatile" ;;
    6) chosen_model="ollama/llama3.3" ;;
    7) ask "Enter LiteLLM model identifier (e.g. openai/gpt-4o):"; read -r chosen_model ;;
    0) warn "Skipped LLM configuration. Configure LLM_MODEL in .env before running CLI." ;;
  esac

  if [ -n "$chosen_model" ]; then
    env_set "LLM_MODEL" "$chosen_model"
    ok "Saved LLM_MODEL=$chosen_model"

    case "$chosen_model" in
      ollama/*) ;;
      *)
        ask "Enter API key for $chosen_model [Enter to skip]:"; read -rs plain_key; printf '\n'
        if [ -n "$plain_key" ]; then
          env_set "LLM_API_KEY" "$plain_key"
          ok "Saved LLM_API_KEY to .env"
        else
          warn "Key skipped. Remember to populate LLM_API_KEY in .env."
        fi
        ;;
    esac
  fi
else
  printf '%sIn MCP mode, your AI harness (Claude, Cursor, OpenCode, etc.) supplies its own LLM.%s\n' "${C_GREEN}" "${C_RESET}"
  muted "Osprey CLI agent config is not required for MCP operation."
fi

# ==============================================================================
# [5/5] Optional OSINT API Keys & MCP Harness Auto-Configuration
# ==============================================================================
write_header "[5/5] Optional OSINT API Keys & MCP Integration"

ask "Configure optional OSINT API keys (Shodan, IntelX)? [y/N]:"; read -r opt_keys
opt_keys="${opt_keys:-n}"
if [ "$opt_keys" = "y" ] || [ "$opt_keys" = "Y" ]; then
  ask "Shodan API Key [Enter to skip]:"; read -r shodan_key
  [ -n "$shodan_key" ] && env_set "SHODAN_API_KEY" "$shodan_key" && ok "Saved SHODAN_API_KEY"

  ask "IntelX API Key [Enter to skip]:"; read -r intelx_key
  [ -n "$intelx_key" ] && env_set "INTELX_API_KEY" "$intelx_key" && ok "Saved INTELX_API_KEY"
fi

# ── Generate reference mcp-config.json ────────────────────────────────────────
python_exe="$(resolve_python_path)"
server_script="$ROOT_DIR/platform-mcp/server.py"

cat > "$ROOT_DIR/mcp-config.json" << EOF
{
  "claude_desktop": {
    "mcpServers": {
      "osprey": {
        "command": "$python_exe",
        "args": ["$server_script"],
        "cwd": "$ROOT_DIR",
        "env": {
          "PENTEST_API_BASE": "http://localhost:9000",
          "PENTEST_QUICK_TIMEOUT": "30",
          "PENTEST_HTTP_TIMEOUT": "900"
        }
      }
    }
  },
  "cursor": {
    "mcpServers": {
      "osprey": {
        "command": "$python_exe",
        "args": ["$server_script"],
        "env": {
          "PENTEST_API_BASE": "http://localhost:9000",
          "PENTEST_QUICK_TIMEOUT": "60",
          "PENTEST_HTTP_TIMEOUT": "900"
        }
      }
    }
  },
  "opencode": {
    "mcp": {
      "osprey": {
        "type": "local",
        "command": ["$python_exe", "$server_script"],
        "cwd": "$ROOT_DIR",
        "environment": {
          "PENTEST_API_BASE": "http://localhost:9000",
          "PENTEST_QUICK_TIMEOUT": "60"
        },
        "enabled": true,
        "timeout": 960000
      }
    }
  }
}
EOF
ok "Generated reference MCP config: mcp-config.json"

# ── Detect and configure AI harnesses ─────────────────────────────────────────
info "Scanning for installed AI harnesses on your system..."

detected_configs=()

# 1. Claude Desktop (macOS / Linux)
if [ -d "$HOME/Library/Application Support/Claude" ]; then
  detected_configs+=("Claude Desktop:$HOME/Library/Application Support/Claude/claude_desktop_config.json:claude")
elif [ -d "$HOME/.config/Claude" ]; then
  detected_configs+=("Claude Desktop:$HOME/.config/Claude/claude_desktop_config.json:claude")
fi

# 2. Cursor
if [ -d "$HOME/.cursor" ]; then
  detected_configs+=("Cursor (Global):$HOME/.cursor/mcp.json:cursor")
fi
detected_configs+=("Cursor (Workspace .cursor/mcp.json):$ROOT_DIR/.cursor/mcp.json:cursor")

# 3. OpenCode
if [ -d "$HOME/.config/opencode" ]; then
  opencode_cfg="$HOME/.config/opencode/opencode.json"
  if [ -f "$HOME/.config/opencode/opencode.jsonc" ]; then
    opencode_cfg="$HOME/.config/opencode/opencode.jsonc"
  fi
  detected_configs+=("OpenCode:$opencode_cfg:opencode")
fi

# 4. Windsurf
if [ -d "$HOME/.codeium/windsurf" ]; then
  detected_configs+=("Windsurf:$HOME/.codeium/windsurf/mcp_config.json:cursor")
fi

if [ "${#detected_configs[@]}" -gt 0 ]; then
  printf '%sFound detected AI harnesses:%s\n' "${C_GREEN}" "${C_RESET}"
  for entry in "${detected_configs[@]}"; do
    h_name="$(echo "$entry" | cut -d: -f1)"
    h_path="$(echo "$entry" | cut -d: -f2)"
    echo "  - $h_name at $h_path"
  done

  ask "Automatically configure Osprey MCP in detected harnesses? [Y/n]:"; read -r auto_mcp
  auto_mcp="${auto_mcp:-y}"

  if [ "$auto_mcp" = "y" ] || [ "$auto_mcp" = "Y" ]; then
    for entry in "${detected_configs[@]}"; do
      h_name="$(echo "$entry" | cut -d: -f1)"
      h_path="$(echo "$entry" | cut -d: -f2)"
      h_type="$(echo "$entry" | cut -d: -f3)"

      mkdir -p "$(dirname "$h_path")"
      if [ -f "$h_path" ]; then
        bak="$h_path.bak_$(date +%Y%m%d%H%M%S)"
        cp "$h_path" "$bak"
        muted "Created backup: $bak"
      fi

      # Safely inject/merge using Python
      python3 -c "
import json, os, sys

path = '$h_path'
h_type = '$h_type'
py_exe = '$python_exe'
srv = '$server_script'
root = '$ROOT_DIR'

data = {}
if os.path.exists(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            lines = [l for l in f if not l.strip().startswith('//')]
            data = json.loads(''.join(lines))
    except Exception:
        data = {}

if h_type == 'opencode':
    if 'mcp' not in data or not isinstance(data['mcp'], dict):
        data['mcp'] = {}
    data['mcp']['osprey'] = {
        'type': 'local',
        'command': [py_exe, srv],
        'cwd': root,
        'environment': {'PENTEST_API_BASE': 'http://localhost:9000', 'PENTEST_QUICK_TIMEOUT': '60'},
        'enabled': True,
        'timeout': 960000
    }
elif h_type == 'cursor':
    if 'mcpServers' not in data or not isinstance(data['mcpServers'], dict):
        data['mcpServers'] = {}
    data['mcpServers']['osprey'] = {
        'command': py_exe,
        'args': [srv],
        'env': {'PENTEST_API_BASE': 'http://localhost:9000', 'PENTEST_QUICK_TIMEOUT': '60', 'PENTEST_HTTP_TIMEOUT': '900'}
    }
else:
    if 'mcpServers' not in data or not isinstance(data['mcpServers'], dict):
        data['mcpServers'] = {}
    data['mcpServers']['osprey'] = {
        'command': py_exe,
        'args': [srv],
        'cwd': root,
        'env': {'PENTEST_API_BASE': 'http://localhost:9000', 'PENTEST_QUICK_TIMEOUT': '60', 'PENTEST_HTTP_TIMEOUT': '900'}
    }

with open(path, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2)
" 2>/dev/null && ok "Configured Osprey MCP in $h_name" || warn "Could not write $h_name config. See mcp-config.json for manual setup."
    done
  fi
else
  muted "No pre-existing harness config directories detected automatically."
  muted "Reference mcp-config.json was created for quick manual setup."
fi

# ==============================================================================
# Setup Complete - Summary & Next Steps
# ==============================================================================
write_header "Setup Complete! Next Steps"

case "$runtime_choice" in
  1|2)
    printf '%s  * Backend Status: Running inside Docker at http://localhost:9000%s\n' "${C_GREEN}" "${C_RESET}"
    muted "Inspect logs anytime : docker compose logs -f backend"
    ;;
  3|4)
    printf '%s  * Backend Status: Configured for local execution%s\n' "${C_YELLOW}" "${C_RESET}"
    echo "    Start backend       : source .venv/bin/activate"
    echo "                          uvicorn osprey.main:app --host 0.0.0.0 --port 9000"
    ;;
esac

if [ "$needs_cli_llm" -eq 1 ]; then
  printf '\n%s  * Running the Osprey CLI:%s\n' "${C_CYAN}" "${C_RESET}"
  echo "    source .venv/bin/activate"
  echo "    osprey                          # Interactive Commander CLI"
  echo "    osprey scan example.com         # Direct scan entry point"
fi

printf '\n%s  * AI Harness (MCP):%s\n' "${C_CYAN}" "${C_RESET}"
echo "    Osprey MCP is ready to be launched via:"
muted "$python_exe $server_script"
muted "See mcp-config.json for copy-pasteable JSON configs."

printf '\n%sHappy hunting!%s\n\n' "${C_GREEN}" "${C_RESET}"
