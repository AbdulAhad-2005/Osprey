# Shared by install.sh and setup.sh — not standalone, source it after ROOT_DIR
# is set: `. "$ROOT_DIR/scripts/lib_local_python.sh"`
#
# Resolves a Python interpreter to create the local .venv with, transparently
# matching whatever Python version a downstream build's precompiled PyArmor
# runtime needs (e.g. Ababeel) — regardless of what `python3` already
# resolves to on this machine, and without the user needing to know or care
# what their Python version is. A plain-source checkout (Osprey) has no
# pyarmor_runtime_* marker at the repo root, so this is a complete no-op
# there: resolve_local_venv_python just returns `python3`, same as before
# this file existed.
#
# Why this exists: PyArmor's compiled runtime extension is hard-linked to the
# exact Python version that ran `pyarmor gen` — there is no cross-version
# fallback, and the failure mode on a mismatch is a cryptic ImportError
# ("undefined symbol: ..."), not a clear version message. The maintainer-side
# release build (see release_ababeel.py) always targets one fixed version to
# match backend/Dockerfile, so a local venv needs that same version,
# whatever's already on the user's PATH — this finds or provisions it rather
# than making that the user's problem to solve by hand.
PYARMOR_TARGET_PYTHON="3.12"

_pyarmor_marker_present() {
  ls "$ROOT_DIR"/pyarmor_runtime_* >/dev/null 2>&1
}

_python_reports_version() {
  # $1: a single command (no args); $2: wanted "X.Y"
  local out
  out="$("$1" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)" || return 1
  [ "$out" = "$2" ]
}

# Prints the chosen interpreter's path on stdout; returns non-zero (nothing
# printed) if none could be found or provisioned. Uses plain stderr messages
# (not this caller's own colored helpers) so it works the same regardless of
# which script sources it.
resolve_local_venv_python() {
  if ! _pyarmor_marker_present; then
    if command -v python3 >/dev/null 2>&1; then
      command -v python3
      return 0
    fi
    echo "  [!] python3 not found. Install Python 3.12+, then re-run." >&2
    return 1
  fi

  if command -v python3 >/dev/null 2>&1 && _python_reports_version python3 "$PYARMOR_TARGET_PYTHON"; then
    command -v python3
    return 0
  fi
  if command -v "python${PYARMOR_TARGET_PYTHON}" >/dev/null 2>&1; then
    command -v "python${PYARMOR_TARGET_PYTHON}"
    return 0
  fi

  local host_minor
  host_minor="$(python3 -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo "?")"
  echo "  [!] This build's precompiled runtime needs Python ${PYARMOR_TARGET_PYTHON} specifically" >&2
  echo "      (this machine's python3 is 3.${host_minor}) — fetching an isolated one with 'uv'," >&2
  echo "      which touches nothing system-wide and needs no sudo." >&2

  if ! command -v uv >/dev/null 2>&1; then
    printf "      Install uv now to get Python %s? [Y/n]: " "$PYARMOR_TARGET_PYTHON" >&2
    read -r install_uv_ans || install_uv_ans="n"
    case "$install_uv_ans" in
      ""|y|Y) ;;
      *) return 1 ;;
    esac
    curl -LsSf https://astral.sh/uv/install.sh 2>/dev/null | sh >&2 2>&1 || true
    export PATH="$HOME/.local/bin:$PATH"
  fi
  if ! command -v uv >/dev/null 2>&1; then
    echo "      Could not install uv automatically. Install Python ${PYARMOR_TARGET_PYTHON} yourself" >&2
    echo "      (e.g. 'uv python install ${PYARMOR_TARGET_PYTHON}' once uv is on PATH, or via your OS" >&2
    echo "      package manager / pyenv), then re-run this wizard." >&2
    return 1
  fi

  local found
  found="$(uv python find "$PYARMOR_TARGET_PYTHON" 2>/dev/null || true)"
  if [ -z "$found" ]; then
    echo "      Fetching Python ${PYARMOR_TARGET_PYTHON} via uv (one-time download) ..." >&2
    uv python install "$PYARMOR_TARGET_PYTHON" >&2 2>&1 || true
    found="$(uv python find "$PYARMOR_TARGET_PYTHON" 2>/dev/null || true)"
  fi
  if [ -n "$found" ] && _python_reports_version "$found" "$PYARMOR_TARGET_PYTHON"; then
    printf '%s' "$found"
    return 0
  fi
  echo "      Still couldn't get Python ${PYARMOR_TARGET_PYTHON} working via uv. Install it yourself," >&2
  echo "      then re-run this wizard." >&2
  return 1
}

# True if an EXISTING venv's own python is wrong for this build (needs
# recreating), independent of whether it was just created or already existed
# — a gate that only runs at venv-creation time misses a stale venv left
# over from before this file existed, or from a previous Python on this host.
local_venv_python_is_wrong() {
  local py="$1"
  [ -n "$py" ] || return 1
  _pyarmor_marker_present || return 1
  ! _python_reports_version "$py" "$PYARMOR_TARGET_PYTHON"
}
