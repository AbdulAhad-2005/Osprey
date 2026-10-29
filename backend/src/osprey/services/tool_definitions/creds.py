"""CREDS_TOOLS — tool catalog definitions."""

from __future__ import annotations

from osprey.schemas.tools import ToolCategory, ToolDefinition, ToolSafetyLevel
from osprey.services.tool_definitions._builders import _COMMON_PARAMS, _p, _t


# ---- CREDS (3 tools) ------------------------------------------------------

CREDS_TOOLS: list[ToolDefinition] = [
    _t("hydra_attack", ToolCategory.CREDS, "hydra", ToolSafetyLevel.GATED,
       "Password brute force attacking.",
       ["brute-force", "credentials", "passwords"],
       {"target": _p("", "Target IP/hostname"), "service": _p("", "Service (ssh/http/ftp/etc)"),
        "username": _p("", "Username or username file"),
        "password_file": _p("", "Password wordlist"),
        "threads": _p("", "Parallel connections (-t); default 4 is brute-force-polite"),
        **_COMMON_PARAMS}),
    _t("hashcat_crack", ToolCategory.CREDS, "hashcat", ToolSafetyLevel.GATED,
       "Advanced password cracking (GPU).",
       ["cracking", "passwords", "hashes"],
       {"hash_file": _p("", "File containing hashes"),
        "hash_type": _p("", "Hash type (e.g. 0=MD5, 1000=NTLM)"),
        "wordlist": _p("/usr/share/wordlists/rockyou.txt", "Wordlist"),
        **_COMMON_PARAMS}),
    _t("john_crack", ToolCategory.CREDS, "john", ToolSafetyLevel.GATED,
       "Password cracking via John the Ripper.",
       ["cracking", "passwords", "hashes"],
       {"hash_file": _p("", "File containing hashes"),
        "wordlist": _p("/usr/share/wordlists/rockyou.txt", "Wordlist"),
        "format": _p("", "Hash format"), **_COMMON_PARAMS}),
]
