#!/usr/bin/env bash
# Prints the current kalilinux/kali-rolling amd64 digest, for deliberately
# refreshing KALI_BASE_DIGEST in kali-tools/Dockerfile.
#
# kali-rolling has no versioned tags -- only a floating "latest" pointer that
# silently re-resolves to whatever Kali ships today. kali-tools/Dockerfile
# pins to a specific digest instead, so builds are reproducible until someone
# deliberately takes a new snapshot. Run this script when you WANT that
# (e.g. to pick up a newer nmap, or because an upstream package fixed a bug
# that's blocking a build) -- never wire it into CI to run automatically.
#
# Usage:
#   scripts/pin-kali-base.sh                 # print the digest
#   scripts/pin-kali-base.sh --apply          # print it AND patch the Dockerfile
set -euo pipefail

DIGEST="$(curl -fsSL "https://registry.hub.docker.com/v2/repositories/kalilinux/kali-rolling/tags/latest" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(next(i['digest'] for i in d['images'] if i['architecture']=='amd64'))")"

echo "Current kalilinux/kali-rolling amd64 digest: $DIGEST"

if [[ "${1:-}" == "--apply" ]]; then
  cd "$(dirname "$0")/.."
  sed -i.bak -E "s/^ARG KALI_BASE_DIGEST=sha256:[0-9a-f]+/ARG KALI_BASE_DIGEST=${DIGEST}/" kali-tools/Dockerfile
  rm -f kali-tools/Dockerfile.bak
  echo "Patched kali-tools/Dockerfile. Review the diff, then rebuild:"
  echo "  docker compose --profile kali up --build"
fi
