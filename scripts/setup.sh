#!/usr/bin/env bash
# One virtualenv at the repo root for the backend + CLI (+ native tool wrappers).
# Replaces the old per-package venvs. Run from the repo root:  bash scripts/setup.sh
# Pass --gui to also install the Operator Console (gui/) web dashboard deps.
set -euo pipefail

cd "$(dirname "$0")/.."

WITH_GUI=0
for arg in "$@"; do
  case "$arg" in
    --gui) WITH_GUI=1 ;;
    *) echo "Unknown option: $arg (supported: --gui)"; exit 1 ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is not installed or not on PATH. Install Python 3.12+ and re-run." >&2
  exit 1
fi

# A venv's python lives at .venv/bin/python on Linux/macOS/WSL, but at
# .venv/Scripts/python.exe when it was created by a native Windows Python —
# which happens even when THIS script is invoked from Git Bash on Windows,
# since `python -m venv` lays itself out by OS, not by which shell ran it.
# This checks/returns whichever one actually exists.
venv_python() {
  if [ -x ".venv/bin/python" ]; then
    printf '%s' ".venv/bin/python"
  elif [ -x ".venv/Scripts/python.exe" ]; then
    printf '%s' ".venv/Scripts/python.exe"
  fi
}

# `python3 -m venv` fails with no venv on offer when the distro ships python3
# without the venv/ensurepip stdlib module split into its own package — this is
# the DEFAULT on Debian/Ubuntu/Kali, so it's the #1 reason this script fails on
# a fresh machine. Detect that specific failure, install the matching package,
# and retry once, instead of just dying on `set -e` with a raw traceback.
ensure_venv() {
  if [ -n "$(venv_python)" ]; then
    return 0  # already created (e.g. re-running setup.sh, or set up via a .ps1)
  fi

  local venv_err=""
  if venv_err="$(python3 -m venv .venv 2>&1)"; then
    return 0
  fi
  printf '%s\n' "$venv_err" >&2
  rm -rf .venv  # a failed attempt can leave a partial dir that confuses a retry

  if command -v apt-get >/dev/null 2>&1; then
    echo
    echo "==> python3 -m venv failed. On Debian/Ubuntu/Kali this almost always means"
    echo "    the 'python3-venv' system package isn't installed (python3 ships without"
    echo "    venv/ensurepip by default on these distros)."

    local py_minor pkgs
    py_minor="$(python3 -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo "")"
    if [ -n "$py_minor" ]; then
      pkgs=("python3.${py_minor}-venv" "python3-venv")
    else
      pkgs=("python3-venv")
    fi

    local SUDO=""
    if [ "$(id -u 2>/dev/null || echo 1000)" != "0" ] && command -v sudo >/dev/null 2>&1; then
      SUDO="sudo"
    fi

    echo "    Attempting to install it automatically: ${SUDO:+$SUDO }apt-get install -y ${pkgs[*]}"
    if $SUDO apt-get update -qq 2>/dev/null && $SUDO apt-get install -y "${pkgs[@]}" 2>/dev/null; then
      echo "    Installed. Retrying..."
      if python3 -m venv .venv; then
        echo "    Virtual environment created."
        return 0
      fi
    fi
  fi

  echo
  echo "Could not create a Python virtual environment automatically." >&2
  echo "Install the venv module yourself, then re-run this script:" >&2
  echo "  Debian / Ubuntu / Kali : sudo apt-get install -y python3-venv" >&2
  echo "  Fedora / RHEL          : sudo dnf install -y python3-virtualenv" >&2
  echo "  Arch / Manjaro         : sudo pacman -S python-virtualenv" >&2
  echo "  macOS (Homebrew)       : brew install python   # includes venv" >&2
  exit 1
}

ensure_venv
PY="$(venv_python)"
if [ -z "$PY" ]; then
  echo "Virtual environment creation reported success but no python was found" >&2
  echo "at .venv/bin/python or .venv/Scripts/python.exe — this shouldn't happen." >&2
  exit 1
fi

# Invoke pip/python through the venv's own executable rather than `source
# .venv/bin/activate` — that activate script only exists on the Unix layout,
# so sourcing it unconditionally breaks the moment the venv was Windows-made
# (same root cause as the bug above, one step later). Calling "$PY" -m pip
# directly works identically on both layouts and needs no activation at all.
"$PY" -m pip install --upgrade pip

# Backend (with dev extras: pytest, ruff, httpx) + CLI, both editable.
"$PY" -m pip install -e ./agent_core -e "./backend[dev]" -e ./cli

# Native tool-wrapper deps — only needed if you run tools on the host instead of
# the Kali container. Safe to install regardless.
"$PY" -m pip install -r mcp-servers/requirements.txt

# Operator Console (web dashboard) — optional, needs Node.js.
if [ "$WITH_GUI" -eq 1 ]; then
  echo
  if command -v npm >/dev/null 2>&1; then
    echo "Installing Operator Console (gui/) dependencies..."
    ( cd gui && npm install )
    echo "GUI ready. Start it with:  cd gui && npm run dev   # http://localhost:3100"
  else
    echo "Skipping GUI: Node.js/npm not found on PATH. Install Node 18.18+ from https://nodejs.org, then: cd gui && npm install && npm run dev"
  fi
fi

echo
echo "Setup complete."
echo "Start the backend  : bash scripts/serve.sh"
echo "Run the Osprey CLI : \"$PY\" -m cli    # or activate the venv first and run: osprey"
[ "$WITH_GUI" -eq 1 ] && echo "The Operator Console (web GUI) runs from gui/ — see above."
