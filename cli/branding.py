from __future__ import annotations

import os

# White-label brand for the CLI. Defaults to "Osprey"; a downstream build
# (e.g. the private Ababeel overlay) sets these env vars to rebrand every
# banner/help string without forking any module — same pattern as the GUI's
# NEXT_PUBLIC_BRAND_NAME (gui/src/lib/brand.ts). This only changes DISPLAY
# text: the actually-installed console-script names still come from
# cli/pyproject.toml's [project.scripts] (osprey/pentest) — a downstream
# distribution that wants a real `ababeel` command installs its own thin
# wrapper/entry point that execs this same cli.main:main.
APP_NAME = os.environ.get("OSPREY_APP_NAME", "Osprey")
APP_TAGLINE = os.environ.get("OSPREY_APP_TAGLINE", "AI security operator")
CLI_COMMAND = os.environ.get("OSPREY_CLI_COMMAND", "osprey")
LEGACY_CLI_COMMAND = os.environ.get("OSPREY_LEGACY_CLI_COMMAND", "pentest")

