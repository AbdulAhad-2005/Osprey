#!/usr/bin/env bash
# Osprey one-line bootstrap installer (Linux / macOS / WSL / Kali).
#
#   curl -fsSL https://raw.githubusercontent.com/AbdulAhad-2005/osprey/main/scripts/get.sh | bash
#
# This script has NO repo checked out yet (that's the whole point) — it clones
# (or downloads) one, then hands off to the real interactive wizard,
# scripts/install.sh, which is kept in one place and does the actual work.
#
# Env overrides: OSPREY_DIR (clone target, default ./osprey), OSPREY_REF
# (branch/tag, default main).
set -uo pipefail

REPO_OWNER="AbdulAhad-2005"
REPO_NAME="osprey"
REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
REF="${OSPREY_REF:-main}"
DIR="${OSPREY_DIR:-osprey}"

if [ -t 1 ]; then
  C_BOLD=$'\033[1m'; C_CYAN=$'\033[36m'; C_RED=$'\033[31m'; C_RESET=$'\033[0m'
else
  C_BOLD=""; C_CYAN=""; C_RED=""; C_RESET=""
fi
info() { printf '%s==>%s %s\n' "${C_CYAN}" "${C_RESET}" "$*"; }
fail() { printf '%s[x]%s %s\n' "${C_RED}" "${C_RESET}" "$*" >&2; }

printf '%s' "${C_BOLD}"
cat << 'BANNER'
   ____  _____ _____  _____  ________   __
  / __ \/ ___// __ \/ __ \/ ____/\ \ / /
 / / / /\__ \/ /_/ / /_/ / __/    \ V /
/ /_/ /___/ / ____/ _, _/ /___     / /
\____//____/_/   /_/ |_/_____/    /_/
BANNER
printf '%s\n' "${C_RESET}"

# Already inside a checkout (e.g. someone ran this from the repo itself, or a
# previous run left it set up)? Don't re-clone — just hand off.
if [ -f "./scripts/install.sh" ] && [ -f "./docker-compose.yml" ]; then
  info "Already inside an Osprey checkout — skipping clone."
  DIR="."
elif [ -d "$DIR/.git" ]; then
  info "Found an existing checkout at ./$DIR — updating it instead of re-cloning."
  git -C "$DIR" fetch --depth 1 origin "$REF" && git -C "$DIR" reset --hard "origin/$REF"
elif command -v git >/dev/null 2>&1; then
  info "Cloning ${REPO_OWNER}/${REPO_NAME} (branch: $REF) into ./$DIR ..."
  if ! git clone --depth 1 --branch "$REF" "$REPO_URL" "$DIR"; then
    fail "git clone failed. Check your network / the repo URL and try again."
    exit 1
  fi
elif command -v curl >/dev/null 2>&1 && command -v tar >/dev/null 2>&1; then
  # No git — fall back to a plain tarball download+extract so this still works
  # on a bare-minimum machine (curl + tar are present on virtually everything).
  info "git not found — downloading the ${REF} tarball instead..."
  TARBALL_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REF}.tar.gz"
  TMP="$(mktemp -d)"
  if ! curl -fsSL "$TARBALL_URL" -o "$TMP/osprey.tar.gz"; then
    fail "Download failed (tried $TARBALL_URL). Install git and try again, or download"
    fail "the repo manually from https://github.com/${REPO_OWNER}/${REPO_NAME}"
    exit 1
  fi
  mkdir -p "$DIR"
  tar -xzf "$TMP/osprey.tar.gz" -C "$DIR" --strip-components=1
  rm -rf "$TMP"
else
  fail "Need either 'git', or 'curl'+'tar', to fetch Osprey. Install one and re-run."
  exit 1
fi

cd "$DIR"
info "Handing off to the setup wizard (scripts/install.sh)..."
echo

# The classic "curl | bash" gotcha: when this script's own stdin is the pipe
# from curl, that pipe is exhausted by the time we get here — any `read` in
# install.sh below would silently get EOF (empty answers) instead of asking
# the terminal. Reopen stdin from the controlling TTY before handing off, so
# the wizard's prompts work normally. If there's no TTY (e.g. CI), fall back
# to running as-is; install.sh's defaults still produce a sane setup.
if [ -e /dev/tty ]; then
  exec bash scripts/install.sh < /dev/tty
else
  exec bash scripts/install.sh
fi
