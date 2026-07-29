"""Register typed FastMCP tools for the passive-OSINT catalog entries.

Same backend execute path as platform_exec, but with explicit OSINT parameters
(email / username / phone / name / url) so the Commander LLM does not have to
reverse-engineer params_json. All tools are passive — public sources only.
"""

from __future__ import annotations

from typing import Any, Callable

TYPED_OSINT_TOOLS: tuple[str, ...] = (
    "web_contact_harvest",
    "theharvester",
    "metagoofil",
    "dnstwist",
    "sherlock",
    "maigret",
    "social_analyzer",
    "holehe",
    "phoneinfoga",
    "email_permute",
)

_TOOL_BLURBS: dict[str, str] = {
    "web_contact_harvest": (
        "PASSIVE SEED — crawl the target site (url=/domain=) and extract emails, "
        "phones, social profile links (+handles) and person names. Start here, then "
        "pivot each name/email/username it returns."
    ),
    "theharvester": "Harvest emails, names, subdomains and hosts from public sources (domain=).",
    "metagoofil": "Discover public documents for a domain (domain=); run exiftool_extract on them for author/GPS.",
    "dnstwist": "Registered typosquat / look-alike domains (domain=).",
    "sherlock": "Fast username search across 400+ sites (username= or target=).",
    "maigret": "Deep username search across 3000+ sites, extracts profile data (username=).",
    "social_analyzer": "Confidence-rated social presence for a username (username=).",
    "holehe": "Which sites have an account for an email — existence only, no breach data (email=).",
    "phoneinfoga": "Passive phone-number OSINT: carrier/country/footprint (phone=, E.164).",
    "email_permute": "Name (name=) + domain= → likely corporate email candidates (+MX). Feed results to holehe.",
}


def _build_params(
    *,
    domain: str = "",
    url: str = "",
    target: str = "",
    email: str = "",
    username: str = "",
    phone: str = "",
    name: str = "",
    input_data: str = "",
    additional_args: str = "",
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for key, val in (
        ("domain", domain),
        ("url", url),
        ("target", target),
        ("email", email),
        ("username", username),
        ("phone", phone),
        ("name", name),
        ("input_data", input_data),
        ("additional_args", additional_args),
    ):
        if str(val).strip():
            params[key] = str(val).strip()
    return params


def register_typed_osint_tools(mcp: Any, *, execute: Callable[..., str]) -> int:
    """Register one FastMCP tool per OSINT catalog name."""
    count = 0
    for tool_name in TYPED_OSINT_TOOLS:
        blurb = _TOOL_BLURBS.get(tool_name, f"Passive OSINT tool {tool_name}.")

        def _make(name: str, doc: str) -> Callable[..., str]:
            def _tool(
                domain: str = "",
                url: str = "",
                target: str = "",
                email: str = "",
                username: str = "",
                phone: str = "",
                name_arg: str = "",
                input_data: str = "",
                additional_args: str = "",
                timeout_seconds: int = 300,
            ) -> str:
                params = _build_params(
                    domain=domain,
                    url=url,
                    target=target,
                    email=email,
                    username=username,
                    phone=phone,
                    name=name_arg,
                    input_data=input_data,
                    additional_args="",
                )
                return execute(
                    name,
                    params,
                    additional_args=(additional_args or "").strip(),
                    timeout_seconds=timeout_seconds,
                )

            _tool.__name__ = name
            _tool.__doc__ = (
                f"{doc}\n\n"
                "PASSIVE OSINT — public sources only. Typed tool; prefer over "
                "platform_exec JSON. Aliases domain|url|target|email|username|phone|"
                "name_arg are accepted. Escape hatch: platform_shell / platform_script."
            )
            return _tool

        handler = _make(tool_name, blurb)
        mcp.tool(name=tool_name)(handler)
        count += 1
    return count
