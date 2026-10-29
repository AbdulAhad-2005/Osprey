#!/usr/bin/env bash
# ==============================================================================
# Osprey - Guided Interactive Setup & Onboarding Wizard (Linux / macOS / Kali / WSL)
# ==============================================================================
#
# Walks through:
#   [1/5] Tool execution & infrastructure mode (Full Docker / Lean Docker / Fully Local)
#   [2/5] Tool environment initialization & scanner checks
#   [3/5] Usage mode selection (Built-in CLI, AI Harness via MCP, or Both)
#   [4/5] Model configuration (LiteLLM provider presets & API key)
#   [5/5] Optional OSINT API keys & automatic AI harness MCP configuration
#
# Usage: bash scripts/install.sh
# ==============================================================================
set -uo pipefail

BRAND="${OSPREY_APP_NAME:-${BRAND}}"

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

# Every docker/docker-compose call in this script goes through $DOCKER_CMD so
# it's set in exactly one place. require_docker() fills it in: plain "docker"
# normally, or "sudo docker" on Linux boxes where the current user isn't in
# the `docker` group yet (the daemon then needs root) — the #1 reason people
# end up manually prefixing every docker command, including ones THIS script
# prints for them to copy-paste later (the password-mismatch fix command,
# "inspect logs", etc.), with sudo themselves.
DOCKER_CMD="docker"
require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    fail "docker is not installed or not in PATH. Please install Docker Engine / Desktop first."
    return 1
  fi
  if docker info >/dev/null 2>&1; then
    DOCKER_CMD="docker"
    return 0
  fi
  # The "needs sudo because you're not in the docker group" situation is a
  # Linux-only concept (Docker Desktop on macOS/Windows has no such group, and
  # manages its own permissions) — gate the sudo retry on that, so this never
  # fires on Windows under Git Bash/MSYS, where `sudo` may exist as Windows
  # 11's own (unrelated, UAC-based) sudo.exe and could hang or misbehave.
  if [ "$(uname -s 2>/dev/null)" = "Linux" ] && command -v sudo >/dev/null 2>&1; then
    if sudo -n docker info >/dev/null 2>&1; then
      DOCKER_CMD="sudo docker"
      return 0
    fi
    warn "docker needs sudo on this system (you're not in the 'docker' group yet)."
    muted "Checking with sudo — you may be prompted for your password..."
    if sudo docker info >/dev/null 2>&1; then
      DOCKER_CMD="sudo docker"
      muted "Using 'sudo docker' for the rest of this run."
      muted "Fix this permanently (no more sudo needed) with:"
      muted "    sudo usermod -aG docker \$USER   # then log out and back in"
      return 0
    fi
  fi
  fail "docker is installed but the daemon is unreachable (is Docker running? do you need sudo?)."
  return 1
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
  local backend_log=""
  if command -v docker >/dev/null 2>&1; then
    backend_log="$($DOCKER_CMD compose logs backend 2>/dev/null | tail -n 80)"
  fi
  if printf '%s' "$backend_log" | grep -qiE "password authentication failed|PasswordError|OperationalError.*password"; then
    # Most common first-run failure: an existing Postgres volume was initialized
    # with a different password than DATABASE_URL now uses (e.g. an old .env that
    # still had the <db-password> placeholder). The password baked into the volume
    # can't be changed by env vars — the volume must be reset.
    fail "Database password mismatch: the Postgres volume was created with a different password."
    muted "Reset the database volume (this DELETES local DB data) and re-run the wizard:"
    muted "    $DOCKER_CMD compose down -v  &&  bash scripts/install.sh"
  elif printf '%s' "$backend_log" | grep -qiE "could not connect to server|connection refused|could not translate host name|OperationalError"; then
    # A stale .env from an earlier manual edit (wrong host/port in DATABASE_URL)
    # is the other common cause — this wizard always writes a consistent
    # DATABASE_URL for Docker modes, so this means something outside the wizard
    # edited it since.
    fail "The backend can't reach Postgres — DATABASE_URL in .env looks stale or wrong."
    muted "Fix: let the wizard rewrite it — re-run  bash scripts/install.sh  and pick"
    muted "option 1 or 2 again (it always sets a consistent, working DATABASE_URL)."
  else
    warn "Inspect logs with:  $DOCKER_CMD compose logs -f backend"
  fi
  return 1
}

# A venv's python lives at .venv/bin/python on Linux/macOS/WSL, but at
# .venv/Scripts/python.exe when it was created by a native Windows Python —
# which happens even when THIS script runs under Git Bash on Windows, since
# `python -m venv` lays itself out by OS, not by which shell ran it. Checking
# only the Unix path here used to make the generated mcp-config.json (and the
# MCP deps install below) silently fall back to a bare system `python3` that
# never has mcp/httpx installed — the exact ModuleNotFoundError this exists
# to prevent.
venv_python_path() {
  if [ -f "$ROOT_DIR/.venv/bin/python" ]; then
    printf '%s' "$ROOT_DIR/.venv/bin/python"
  elif [ -f "$ROOT_DIR/.venv/Scripts/python.exe" ]; then
    printf '%s' "$ROOT_DIR/.venv/Scripts/python.exe"
  fi
}

resolve_python_path() {
  local vp; vp="$(venv_python_path)"
  if [ -n "$vp" ]; then
    printf '%s' "$vp"
  elif command -v python3 >/dev/null 2>&1; then
    command -v python3
  else
    printf 'python3'
  fi
}

# The Osprey MCP server is a small local stdio bridge to the backend's HTTP API —
# it needs its own Python deps (mcp, httpx) regardless of how the backend runs.
# In Docker-only setups no .venv is ever created, so the MCP config would point at
# a system Python without those deps and the harness launch dies with
# "ModuleNotFoundError: No module named 'httpx'". Ensure a .venv that HAS the deps
# so resolve_python_path returns a usable interpreter for the MCP command.
# Set by ensure_mcp_python() so the final "Setup Complete!" summary can call
# this out prominently instead of a warning scrolling off 100+ lines earlier —
# a setup that silently can't actually launch MCP should never just say
# "Setup Complete!" without a flag the operator will actually see.
MCP_DEPS_OK=1
CLI_DEPS_OK=1
GUI_DEPS_OK=1

ensure_cli_python() {
  local py; py="$(venv_python_path)"
  if [ -z "$py" ]; then
    if ! command -v python3 >/dev/null 2>&1; then
      warn "python3 not found — cannot install the ${BRAND} CLI. Install Python 3.12+, then re-run."
      CLI_DEPS_OK=0
      return 1
    fi
    info "Preparing a local Python environment for the ${BRAND} CLI..."
    python3 -m venv "$ROOT_DIR/.venv" || {
      warn "Could not create .venv; the CLI is not installed."
      CLI_DEPS_OK=0
      return 1
    }
    py="$(venv_python_path)"
  fi
  "$py" -m pip install --upgrade pip --quiet >/dev/null 2>&1 || true
  local pip_err=""
  if pip_err="$("$py" -m pip install --quiet -e "$ROOT_DIR/agent_core" -e "$ROOT_DIR/cli" 2>&1)"; then
    ok "${BRAND} CLI installed into .venv (osprey command ready after activation)."
  else
    warn "Failed to install the ${BRAND} CLI."
    muted "$pip_err"
    muted "Retry:  \"$py\" -m pip install -e ./agent_core -e ./cli"
    CLI_DEPS_OK=0
  fi
}

ensure_mcp_python() {
  local py; py="$(venv_python_path)"
  if [ -n "$py" ] && "$py" -c "import httpx, mcp" >/dev/null 2>&1; then
    return 0  # already usable
  fi
  info "Preparing a local Python environment for the ${BRAND} MCP bridge..."
  if [ -z "$py" ]; then
    if command -v python3 >/dev/null 2>&1; then
      python3 -m venv "$ROOT_DIR/.venv" || { warn "Could not create .venv; MCP may fail to launch."; MCP_DEPS_OK=0; return 1; }
      py="$(venv_python_path)"
    else
      warn "python3 not found — cannot prepare the MCP environment. Install Python 3, then re-run."
      MCP_DEPS_OK=0
      return 1
    fi
  fi
  "$py" -m pip install --upgrade pip --quiet >/dev/null 2>&1 || true
  local pip_err=""
  if pip_err="$("$py" -m pip install --quiet -r "$ROOT_DIR/platform-mcp/requirements.txt" 2>&1)"; then
    ok "MCP bridge dependencies installed into .venv (mcp, httpx)."
  elif printf '%s' "$pip_err" | grep -qiE "NameResolutionError|Failed to resolve|Temporary failure in name resolution|Network is unreachable"; then
    # Not a bug to chase — no DNS/network reachable from here right now. Say
    # that plainly instead of dumping pip's retry/traceback noise, and give
    # the one command to run once connectivity is back.
    warn "No internet connection from here — couldn't download MCP deps (mcp, httpx)."
    muted "Once you're back online, run:  \"$py\" -m pip install -r platform-mcp/requirements.txt"
    MCP_DEPS_OK=0
  else
    warn "Failed to install MCP deps into .venv; the harness launch may fail."
    muted "Retry:  \"$py\" -m pip install -r platform-mcp/requirements.txt"
    MCP_DEPS_OK=0
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

muted "Welcome to the ${BRAND} setup wizard. Press Ctrl+C anytime to exit."
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
write_header "[1/5] How should ${BRAND} & security tools run?"

printf '%s  1) Full Docker (Recommended)%s\n' "${C_BOLD}" "${C_RESET}"
muted "All-in-one: Postgres DB, Backend API & 90+ Kali tools in Docker."
muted "Zero tool installation required on your host system."

printf '%s  2) Lean Docker (Custom Tools Container)%s\n' "${C_BOLD}" "${C_RESET}"
muted "Postgres & Backend in Docker; tools executed via your own existing container."

printf '%s  3) Fully Local, No Docker (Self-contained / SQLite)%s\n' "${C_BOLD}" "${C_RESET}"
muted "Backend and tools run on this machine with a local SQLite database — no Docker, no Postgres."

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
    # Keep the Postgres password and the DATABASE_URL password in lock-step —
    # a stale .env may still carry the <db-password> placeholder, which would
    # make the DB init with one password and the backend connect with another
    # (503 Service Unavailable on first start).
    env_set "POSTGRES_PASSWORD" "pentest"
    env_set "DATABASE_URL" "postgresql+psycopg://pentest:pentest@postgres:5432/pentest"

    if [ "$img_choice" = "2" ]; then
      info "Building Kali image from source and starting stack..."
      warn "This build compiles heavy tools and may take 40-60 minutes on cold runs."
      if $DOCKER_CMD compose --profile kali -f docker-compose.yml -f docker-compose.build.yml up -d --build; then
        ok "Docker stack started (built from source)."
        wait_for_backend || true
      else
        fail "Build/compose failed. Ensure Docker has adequate disk space (~16GB free)."
        exit 1
      fi
    else
      env_set "OSPREY_KALI_IMAGE" "ospreytools/osprey-kali:latest"
      info "Pulling prebuilt image (ospreytools/osprey-kali:latest) & launching stack..."
      if $DOCKER_CMD compose --profile kali up -d; then
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
    env_set "POSTGRES_PASSWORD" "pentest"
    env_set "DATABASE_URL" "postgresql+psycopg://pentest:pentest@postgres:5432/pentest"

    info "Starting Postgres + Backend in Docker (targeting container '$tools_cont')..."
    if $DOCKER_CMD compose up -d; then
      ok "Stack started. Tools will be executed into '$tools_cont'."
      wait_for_backend || true
    else
      fail "docker compose failed."; exit 1
    fi
    ;;

  3)
    env_set "DATABASE_URL" "sqlite:///./pentest.db"
    env_set "KALI_CONTAINER" ""

    info "Configured SQLite local database (pentest.db) — nothing else to connect."
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
# [2/5] Tool Environment Detection (For the Fully Local mode)
# ==============================================================================
if [ "$runtime_choice" = "3" ]; then
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
    muted "${BRAND} will gracefully adapt and use whichever tools are installed."

    SUDO=""
    if [ "$(id -u 2>/dev/null || echo 1000)" != "0" ] && command -v sudo >/dev/null 2>&1; then
      SUDO="sudo"
    fi

    ask "Attempt automatic installation of missing tools? [Y/n]:"; read -r install_ans
    install_ans="${install_ans:-y}"

    if [ "$install_ans" = "y" ] || [ "$install_ans" = "Y" ]; then
      if printf '%s\n' "${missing_tools[@]}" | grep -qE '^(subfinder|httpx|naabu|dnsx|tlsx|katana|nuclei)$' &&
         ! command -v go >/dev/null 2>&1 && ! command -v brew >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
          info "Installing Go, required for ProjectDiscovery tools..."
          if $SUDO apt-get update -qq && $SUDO apt-get install -y golang-go; then
            hash -r 2>/dev/null || true
          else
            warn "Could not install Go; ProjectDiscovery tools cannot be installed automatically."
          fi
        else
          warn "Go is not installed and no supported package manager was found."
          muted "Install Go manually, then re-run this wizard to install ProjectDiscovery tools."
        fi
      fi

      go_bin=""
      if command -v go >/dev/null 2>&1; then
        go_bin="$(go env GOBIN 2>/dev/null || true)"
        if [ -z "$go_bin" ]; then
          go_bin="$(go env GOPATH 2>/dev/null || true)/bin"
        fi
        if [ -n "$go_bin" ]; then
          mkdir -p "$go_bin"
          export PATH="$go_bin:$PATH"
          path_marker="# Osprey: Go-installed security tools"
          path_export="export PATH=\"$go_bin:\$PATH\""
          # Kali commonly starts zsh for interactive terminals; bash's
          # profiles are not read there. Keep all supported user shells in
          # sync so a new terminal can resolve the binaries.
          for shell_profile in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
            if { [ -f "$shell_profile" ] || touch "$shell_profile" 2>/dev/null; } &&
               [ -w "$shell_profile" ] && ! grep -Fq "$path_marker" "$shell_profile"; then
              printf '\n%s\n%s\n' "$path_marker" "$path_export" >> "$shell_profile"
              muted "Added $go_bin to PATH in $shell_profile"
            fi
          done
        fi
      fi

      for mt in "${missing_tools[@]}"; do
        info "Installing $mt..."
        case "$mt" in
          nmap|whois|amass|ffuf)
            if command -v apt-get >/dev/null 2>&1; then
              $SUDO apt-get update -qq && $SUDO apt-get install -y "$mt" || warn "apt-get install $mt failed"
            elif command -v brew >/dev/null 2>&1; then
              brew install "$mt" || warn "brew install $mt failed"
            else
              warn "No supported package manager found for $mt; it was not installed."
            fi
            ;;
          subfinder|httpx|naabu|dnsx|tlsx|katana|nuclei)
            if command -v go >/dev/null 2>&1; then
              if go install "github.com/projectdiscovery/${mt}/cmd/${mt}@latest" 2>/dev/null ||
                 go install "github.com/projectdiscovery/${mt}/v2/cmd/${mt}@latest" 2>/dev/null ||
                 go install "github.com/projectdiscovery/${mt}/v3/cmd/${mt}@latest" 2>/dev/null; then
                if command -v "$mt" >/dev/null 2>&1; then
                  ok "$mt installed and available on PATH."
                else
                  warn "$mt was downloaded, but its Go bin directory is not available in this shell."
                  muted "Open a new shell (or run: export PATH=\"$go_bin:\$PATH\") and re-run the tool check."
                fi
              else
                warn "go install $mt failed; it was not installed."
              fi
            elif command -v brew >/dev/null 2>&1; then
              if brew install "projectdiscovery/tap/$mt" 2>/dev/null || brew install "$mt" 2>/dev/null; then
                command -v "$mt" >/dev/null 2>&1 && ok "$mt installed and available on PATH." ||
                  warn "$mt installation finished, but it is not available on PATH."
              else
                warn "brew install $mt failed; it was not installed."
              fi
            else
              warn "Go/Homebrew is unavailable; $mt was not installed."
            fi
            ;;
          searchsploit)
            if command -v apt-get >/dev/null 2>&1; then
              $SUDO apt-get update -qq && $SUDO apt-get install -y exploitdb || warn "apt-get install exploitdb failed"
            elif command -v brew >/dev/null 2>&1; then
              brew install exploitdb || warn "brew install exploitdb failed"
            else
              warn "No supported package manager found for searchsploit; it was not installed."
            fi
            ;;
        esac
      done

      remaining_tools=()
      for mt in "${missing_tools[@]}"; do
        if ! tool_present "$mt"; then
          remaining_tools+=("$mt")
        fi
      done
      if [ "${#remaining_tools[@]}" -eq 0 ]; then
        ok "All requested host tools are now available on PATH."
      else
        warn "Still unavailable after installation attempt: ${remaining_tools[*]}"
        muted "Re-run the wizard after fixing the package manager, Go, or PATH."
      fi
    fi
  fi
fi

# ==============================================================================
# [3/5] Usage Mode Selection
# ==============================================================================
write_header "[3/5] How do you plan to use ${BRAND}?"

printf '%s  1) Both Built-in CLI & AI Harness (MCP) (Recommended - complete access)%s\n' "${C_BOLD}" "${C_RESET}"
muted "Use our native CLI (osprey) AND connect AI clients like Claude, Cursor, OpenCode."

printf '%s  2) Built-in CLI only%s\n' "${C_BOLD}" "${C_RESET}"
muted "Drive tests directly via the interactive terminal interface (osprey / python -m cli)."

printf '%s  3) AI Harness via MCP only%s\n' "${C_BOLD}" "${C_RESET}"
muted "Control ${BRAND} exclusively from Claude Desktop, Cursor, OpenCode, Windsurf, or ChatGPT."

printf '%s  4) Operator Console GUI only%s\n' "${C_BOLD}" "${C_RESET}"
muted "Use the web dashboard at http://localhost:3100 (requires Node.js 18.18+)."

ask "Select usage mode [1]:"; read -r usage_choice
usage_choice="${usage_choice:-1}"
case "$usage_choice" in
  1|2|3|4) ;;
  *) fail "Unrecognized option '$usage_choice'."; exit 1 ;;
esac

needs_cli_llm=0
if [ "$usage_choice" = "1" ] || [ "$usage_choice" = "2" ]; then
  needs_cli_llm=1
fi
wants_mcp=0
if [ "$usage_choice" = "1" ] || [ "$usage_choice" = "3" ]; then
  wants_mcp=1
fi
wants_gui=0
if [ "$usage_choice" = "4" ]; then
  wants_gui=1
fi

# ==============================================================================
# [4/5] LLM Configuration
# ==============================================================================
write_header "[4/5] LLM Provider Configuration"

if [ "$needs_cli_llm" -eq 1 ]; then
  printf "%sThe ${BRAND} CLI uses LiteLLM to drive its autonomous agent loop.%s\n" "${C_BOLD}" "${C_RESET}"
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
  muted "${BRAND} CLI agent config is not required for MCP operation."
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
# Make sure the interpreter we're about to hand the harness actually has the MCP
# deps (mcp, httpx) — otherwise the harness shows "Osprey MCP failed to start".
# Only bother (network calls, time) if the operator actually said they want MCP;
# the config file itself is still generated either way, as a free reference for
# later — it just isn't backed by an installed environment yet in that case.
if [ "$wants_mcp" -eq 1 ]; then
  if [ "$needs_cli_llm" -eq 1 ]; then
    ensure_cli_python
  else
    ensure_mcp_python
  fi
fi

if [ "$needs_cli_llm" -eq 1 ] && [ "$wants_mcp" -eq 0 ]; then
  ensure_cli_python
fi

if [ "$wants_gui" -eq 1 ]; then
  if command -v npm >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
    gui_node_version="$(node -p 'process.versions.node' 2>/dev/null || true)"
    gui_node_major="${gui_node_version%%.*}"
    gui_node_minor="${gui_node_version#*.}"; gui_node_minor="${gui_node_minor%%.*}"
    if [ -n "$gui_node_version" ] && { [ "$gui_node_major" -gt 18 ] || { [ "$gui_node_major" -eq 18 ] && [ "$gui_node_minor" -ge 18 ]; }; }; then
      info "Installing Operator Console dependencies..."
      if (cd "$ROOT_DIR/gui" && npm install); then
        ok "Operator Console dependencies installed."
      else
        warn "GUI dependency installation failed. Retry with: cd gui && npm install"
        GUI_DEPS_OK=0
      fi
    else
      warn "Node.js $gui_node_version is too old. Install Node.js 18.18+ and retry: cd gui && npm install"
      GUI_DEPS_OK=0
    fi
  else
    warn "Node.js/npm not found. Install Node.js 18.18+, then run: cd gui && npm install"
    GUI_DEPS_OK=0
  fi
fi
python_exe="$(resolve_python_path)"
server_script="$ROOT_DIR/platform-mcp/server.py"
# White-label hook (default "osprey" is a no-op): a downstream build sets
# OSPREY_MCP_SERVER_NAME to rebrand the generated/auto-written MCP config
# key name — matches platform-mcp/server.py's own FastMCP(...) name.
mcp_server_name="${OSPREY_MCP_SERVER_NAME:-osprey}"

cat > "$ROOT_DIR/mcp-config.json" << EOF
{
  "claude_desktop": {
    "mcpServers": {
      "$mcp_server_name": {
        "command": "$python_exe",
        "args": ["$server_script"],
        "cwd": "$ROOT_DIR",
        "env": {
          "OSPREY_MCP_SERVER_NAME": "$mcp_server_name",
          "PENTEST_API_BASE": "http://localhost:9000",
          "PENTEST_QUICK_TIMEOUT": "30",
          "PENTEST_HTTP_TIMEOUT": "900"
        }
      }
    }
  },
  "cursor": {
    "mcpServers": {
      "$mcp_server_name": {
        "command": "$python_exe",
        "args": ["$server_script"],
        "env": {
          "OSPREY_MCP_SERVER_NAME": "$mcp_server_name",
          "PENTEST_API_BASE": "http://localhost:9000",
          "PENTEST_QUICK_TIMEOUT": "60",
          "PENTEST_HTTP_TIMEOUT": "900"
        }
      }
    }
  },
  "opencode": {
    "mcp": {
      "$mcp_server_name": {
        "type": "local",
        "command": ["$python_exe", "$server_script"],
        "cwd": "$ROOT_DIR",
        "environment": {
          "OSPREY_MCP_SERVER_NAME": "$mcp_server_name",
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
if [ "$wants_mcp" -eq 1 ]; then
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

  ask "Automatically configure ${BRAND} MCP in detected harnesses? [Y/n]:"; read -r auto_mcp
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
mcp_name = '$mcp_server_name'

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
    data['mcp'][mcp_name] = {
        'type': 'local',
        'command': [py_exe, srv],
        'cwd': root,
        'environment': {'OSPREY_MCP_SERVER_NAME': mcp_name, 'PENTEST_API_BASE': 'http://localhost:9000', 'PENTEST_QUICK_TIMEOUT': '60'},
        'enabled': True,
        'timeout': 960000
    }
elif h_type == 'cursor':
    if 'mcpServers' not in data or not isinstance(data['mcpServers'], dict):
        data['mcpServers'] = {}
    data['mcpServers'][mcp_name] = {
        'command': py_exe,
        'args': [srv],
        'env': {'OSPREY_MCP_SERVER_NAME': mcp_name, 'PENTEST_API_BASE': 'http://localhost:9000', 'PENTEST_QUICK_TIMEOUT': '60', 'PENTEST_HTTP_TIMEOUT': '900'}
    }
else:
    if 'mcpServers' not in data or not isinstance(data['mcpServers'], dict):
        data['mcpServers'] = {}
    data['mcpServers'][mcp_name] = {
        'command': py_exe,
        'args': [srv],
        'cwd': root,
        'env': {'OSPREY_MCP_SERVER_NAME': mcp_name, 'PENTEST_API_BASE': 'http://localhost:9000', 'PENTEST_QUICK_TIMEOUT': '60', 'PENTEST_HTTP_TIMEOUT': '900'}
    }

with open(path, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2)
" 2>/dev/null && ok "Configured ${BRAND} MCP in $h_name" || warn "Could not write $h_name config. See mcp-config.json for manual setup."
    done
  fi
else
  muted "No pre-existing harness config directories detected automatically."
  muted "Reference mcp-config.json was created for quick manual setup."
fi
else
  muted "Skipped AI harness auto-configuration (MCP was not selected)."
fi

# ==============================================================================
# Setup Complete - Summary & Next Steps
# ==============================================================================
write_header "Setup Complete! Next Steps"

case "$runtime_choice" in
  1|2)
    printf '%s  * Backend Status: Running inside Docker at http://localhost:9000%s\n' "${C_GREEN}" "${C_RESET}"
    muted "Inspect logs anytime : $DOCKER_CMD compose logs -f backend"
    muted "Stop it              : $DOCKER_CMD compose down"
    ;;
  3)
    printf '%s  * Backend Status: Configured for local execution (not started yet)%s\n' "${C_YELLOW}" "${C_RESET}"
    echo "    Start it now        : bash scripts/serve.sh"
    muted "(leave that running; open a new terminal for the CLI/GUI)"
    ;;
esac

if [ "$needs_cli_llm" -eq 1 ]; then
  printf "\n%s  * Running the ${BRAND} CLI:%s\n" "${C_CYAN}" "${C_RESET}"
  if [ "$CLI_DEPS_OK" -eq 1 ]; then
    echo "    source .venv/bin/activate     # optional; makes the 'osprey' command available"
    echo "    osprey                          # Interactive Commander CLI"
    echo "    osprey scan example.com         # Direct scan entry point"
    muted "Or run directly without activation:  \"$python_exe\" -m cli"
  else
    fail "CLI installation did NOT complete — the 'osprey' command is not ready."
  fi
fi

if [ "$wants_mcp" -eq 1 ]; then
  printf '\n%s  * AI Harness (MCP):%s\n' "${C_CYAN}" "${C_RESET}"
  if [ "$MCP_DEPS_OK" -eq 1 ]; then
    echo "    ${BRAND} MCP is ready to be launched via:"
    muted "$python_exe $server_script"
    muted "See mcp-config.json for copy-pasteable JSON configs."
  else
    fail "MCP bridge dependencies did NOT install — your AI harness (Claude/Cursor/"
    fail "OpenCode/etc.) will NOT be able to launch ${BRAND}'s MCP server until you fix this."
    muted "mcp-config.json was still generated and is otherwise correct — once you"
    muted "have internet access, finish the install with:"
    muted "    \"$python_exe\" -m pip install -r platform-mcp/requirements.txt"
  fi

  if [ "$wants_gui" -eq 1 ]; then
    printf '\n%s  * Operator Console GUI:%s\n' "${C_CYAN}" "${C_RESET}"
    if [ "$GUI_DEPS_OK" -eq 1 ]; then
      echo "    cd gui && npm run dev             # http://localhost:3100"
    else
      fail "GUI dependencies did NOT install. Install Node.js 18.18+ and run: cd gui && npm install"
    fi
  fi
else
  printf '\n%s  * AI Harness (MCP):%s not configured (you chose CLI only). A reference\n' "${C_CYAN}" "${C_RESET}"
  muted "mcp-config.json was still generated if you want it later."
fi

printf '\n%sHappy hunting!%s\n\n' "${C_GREEN}" "${C_RESET}"
