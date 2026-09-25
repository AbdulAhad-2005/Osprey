"""Unquoted-interpolation sweep (Fix 3) — the 7 priority wrappers.

param_validator.py blocks classic shell metacharacters (;|&`$()<>) in param
values before a wrapper ever builds its command, but not spaces (word-
splitting), quote characters, or glob characters. These wrappers run via
`bash -c` inside the Kali container (a real shell), so an unquoted value
containing any of those is a live correctness/safety gap — this asserts the
7 highest-priority wrappers now shlex-quote user-controlled values.
"""

from __future__ import annotations

from osprey.services.command_builder import build_command_for_tool

_TRICKY = "foo bar's *"  # space + embedded quote + glob char


def test_sqlmap_quotes_url_and_data():
    cmd = build_command_for_tool("sqlmap_scan", {"url": _TRICKY, "data": _TRICKY})
    assert "sqlmap -u 'foo bar'\"'\"'s *' --batch" in cmd
    assert f"--data='foo bar'\"'\"'s *'" in cmd


def test_nuclei_quotes_target_severity_tags_template():
    cmd = build_command_for_tool(
        "nuclei_scan",
        {"target": _TRICKY, "severity": _TRICKY, "tags": _TRICKY, "template": _TRICKY},
    )
    for flag in ("-u", "-severity", "-tags", "-t"):
        assert f"{flag} 'foo bar'\"'\"'s *'" in cmd


def test_gobuster_quotes_url_and_mode():
    cmd = build_command_for_tool("gobuster_scan", {"url": _TRICKY, "mode": _TRICKY})
    assert "gobuster 'foo bar'\"'\"'s *' -u 'foo bar'\"'\"'s *' -w" in cmd


def test_gobuster_dns_mode_quotes_domain():
    cmd = build_command_for_tool(
        "gobuster_scan", {"url": "evil.com; touch pwned", "mode": "dns"}
    )
    # semicolon would already be blocked by param_validator upstream in the
    # real request path; build_command_for_tool itself has no such gate, so
    # this directly proves the builder's own quoting holds regardless.
    assert "--domain 'evil.com; touch pwned'" in cmd


def test_hydra_quotes_all_identity_params():
    cmd = build_command_for_tool(
        "hydra_attack",
        {
            "target": _TRICKY,
            "service": _TRICKY,
            "username": _TRICKY,
            "username_file": _TRICKY,
            "password": _TRICKY,
            "password_file": _TRICKY,
        },
    )
    quoted = "'foo bar'\"'\"'s *'"
    for flag in ("-l", "-L", "-p", "-P"):
        assert f"{flag} {quoted}" in cmd
    assert cmd.strip().endswith(f"{quoted} {quoted}")


def test_nikto_quotes_target():
    cmd = build_command_for_tool("nikto_scan", {"target": _TRICKY})
    assert f"nikto -h 'foo bar'\"'\"'s *'" == cmd


def test_wafw00f_quotes_target():
    cmd = build_command_for_tool("wafw00f_scan", {"target": _TRICKY})
    assert f"wafw00f 'foo bar'\"'\"'s *'" == cmd


def test_feroxbuster_quotes_url_and_explicit_wordlist():
    cmd = build_command_for_tool(
        "feroxbuster_scan", {"url": _TRICKY, "wordlist": _TRICKY}
    )
    quoted = "'foo bar'\"'\"'s *'"
    assert f"-u {quoted}" in cmd
    assert f"-w {quoted}" in cmd


def test_feroxbuster_falls_back_to_internal_wordlist_expr_unquoted():
    # The internal $([ -f ... ] && echo ... || echo ...) fallback is a shell
    # expression, not user input — it must NOT be quoted (that would break
    # the substitution and pass the literal string as a filename).
    cmd = build_command_for_tool("feroxbuster_scan", {"url": "example.com"})
    assert "-w $(" in cmd
