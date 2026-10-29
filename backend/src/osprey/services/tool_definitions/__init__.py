"""Tool-definition data for the registry, split out of tool_registry.py.

Each category module holds its <CAT>_TOOLS tuple; the registry imports these
and assembles ALL_TOOL_DEFINITIONS. Pure data — no availability/logic here."""

from __future__ import annotations

from osprey.services.tool_definitions._builders import _COMMON_PARAMS, _p, _t
from osprey.services.tool_definitions.recon import RECON_TOOLS
from osprey.services.tool_definitions.osint import OSINT_TOOLS
from osprey.services.tool_definitions.network import NETWORK_TOOLS
from osprey.services.tool_definitions.web import WEB_TOOLS
from osprey.services.tool_definitions.vuln import VULN_TOOLS
from osprey.services.tool_definitions.cloud import CLOUD_TOOLS
from osprey.services.tool_definitions.creds import CREDS_TOOLS
from osprey.services.tool_definitions.exploit import EXPLOIT_TOOLS
from osprey.services.tool_definitions.api import API_TOOLS
from osprey.services.tool_definitions.binary import BINARY_TOOLS
from osprey.services.tool_definitions.forensics import FORENSICS_TOOLS

__all__ = [
    "_t",
    "_p",
    "_COMMON_PARAMS",
    "RECON_TOOLS",
    "OSINT_TOOLS",
    "NETWORK_TOOLS",
    "WEB_TOOLS",
    "VULN_TOOLS",
    "CLOUD_TOOLS",
    "CREDS_TOOLS",
    "EXPLOIT_TOOLS",
    "API_TOOLS",
    "BINARY_TOOLS",
    "FORENSICS_TOOLS",
]
