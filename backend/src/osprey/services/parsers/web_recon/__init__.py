"""Web-recon tool-output parsers, split by concern into _shared/content/params/crawl/posture.

Re-exports every name the flat web_recon.py exposed and runs _register()
on import, so osprey.services.parsers.web_recon is unchanged for callers."""

from __future__ import annotations

from osprey.services.parsers.web_recon._shared import (  # noqa: F401
    _INTERESTING_PATH,
    _host_of,
    _is_interesting,
    _content_hit,
)
from osprey.services.parsers.web_recon.content import (  # noqa: F401
    parse_feroxbuster,
    parse_ffuf,
    _GOBUSTER_RE,
    _GOBUSTER_DNS_RE,
    _GOBUSTER_DNS_IP_RE,
    parse_gobuster,
    _dir_text_fallback,
    _content_digest,
)
from osprey.services.parsers.web_recon.params import (  # noqa: F401
    _ARJUN_FOUND_RE,
    _ensure_param_in_url,
    _param_observation,
    parse_arjun,
    _X8_FOUND_RE,
    _X8_PARAM_TOKEN_RE,
    parse_x8,
    extract_parameters_from_urls,
)
from osprey.services.parsers.web_recon.crawl import (  # noqa: F401
    parse_katana,
    parse_js_recon,
    parse_app_recon,
    _js_digest,
    _app_digest,
)
from osprey.services.parsers.web_recon.posture import (  # noqa: F401
    parse_email_security,
    parse_well_known,
    parse_tech_stack,
    _ANSI_RE,
    _WAF_BEHIND_RE,
    _WAF_PLACEHOLDER_NAMES,
    parse_wafw00f,
    _tech_stack_digest,
)

__all__ = [
    "_INTERESTING_PATH",
    "_host_of",
    "_is_interesting",
    "_content_hit",
    "parse_feroxbuster",
    "parse_ffuf",
    "_GOBUSTER_RE",
    "_GOBUSTER_DNS_RE",
    "_GOBUSTER_DNS_IP_RE",
    "parse_gobuster",
    "_dir_text_fallback",
    "_ARJUN_FOUND_RE",
    "_ensure_param_in_url",
    "_param_observation",
    "parse_arjun",
    "_X8_FOUND_RE",
    "_X8_PARAM_TOKEN_RE",
    "parse_x8",
    "extract_parameters_from_urls",
    "parse_katana",
    "parse_js_recon",
    "parse_app_recon",
    "parse_email_security",
    "parse_well_known",
    "parse_tech_stack",
    "_ANSI_RE",
    "_WAF_BEHIND_RE",
    "_WAF_PLACEHOLDER_NAMES",
    "parse_wafw00f",
    "_content_digest",
    "_js_digest",
    "_app_digest",
    "_tech_stack_digest",
]


def _register() -> None:
    from osprey.services.parsers.registry import (
        register_output_digester,
        register_output_parser,
    )

    register_output_parser("feroxbuster_scan", parse_feroxbuster)
    register_output_digester("feroxbuster_scan", _content_digest("feroxbuster"))
    register_output_parser("ffuf_scan", parse_ffuf)
    register_output_digester("ffuf_scan", _content_digest("ffuf"))
    register_output_parser("gobuster_scan", parse_gobuster)
    register_output_digester("gobuster_scan", _content_digest("gobuster"))
    register_output_parser("arjun_scan", parse_arjun)
    register_output_parser("arjun_parameter_discovery", parse_arjun)
    register_output_parser("x8_parameter_discovery", parse_x8)
    register_output_parser("katana_crawl", parse_katana)
    register_output_parser("js_recon", parse_js_recon)
    register_output_digester("js_recon", _js_digest)
    register_output_parser("app_recon", parse_app_recon)
    register_output_digester("app_recon", _app_digest)
    register_output_parser("email_security_probe", parse_email_security)
    register_output_parser("well_known_probe", parse_well_known)
    register_output_parser("tech_stack_analyze", parse_tech_stack)
    register_output_digester("tech_stack_analyze", _tech_stack_digest)
    register_output_parser("wafw00f_scan", parse_wafw00f)


_register()
