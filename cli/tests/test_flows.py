"""Tests for prompt-customizable flows (Markdown agents/commands)."""

from __future__ import annotations

from cli.agent import flows


def test_parse_frontmatter_extracts_meta_and_body():
    text = "---\ndescription: Recon mode\ndeny_tools: metasploit_*, hydra_*\n---\nBody line one.\nBody line two."
    meta, body = flows._parse_frontmatter(text)
    assert meta["description"] == "Recon mode"
    assert meta["deny_tools"] == "metasploit_*, hydra_*"
    assert body == "Body line one.\nBody line two."


def test_parse_frontmatter_no_frontmatter():
    meta, body = flows._parse_frontmatter("just a body, no frontmatter")
    assert meta == {}
    assert body == "just a body, no frontmatter"


def test_tool_allowed_deny_takes_precedence():
    a = flows.Agent(name="recon", deny_tools=["metasploit_*", "hydra_*", "sqlmap_*"])
    assert a.tool_allowed("subfinder_scan") is True
    assert a.tool_allowed("metasploit_run") is False
    assert a.tool_allowed("hydra_attack") is False


def test_tool_allowed_allowlist_restricts():
    a = flows.Agent(name="passive", allow_tools=["subfinder_scan", "httpx_*"])
    assert a.tool_allowed("subfinder_scan") is True
    assert a.tool_allowed("httpx_probe") is True
    assert a.tool_allowed("nmap_syn_scan") is False


def test_tool_allowed_default_allows_all():
    assert flows.Agent(name="default").tool_allowed("anything_at_all") is True


def test_deny_beats_allow():
    a = flows.Agent(name="x", allow_tools=["*"], deny_tools=["metasploit_*"])
    assert a.tool_allowed("nuclei_scan") is True
    assert a.tool_allowed("metasploit_run") is False


def test_expand_command_arguments_and_positional():
    assert flows.expand_command("scan $ARGUMENTS now", ["a", "b"]) == "scan a b now"
    assert flows.expand_command("first=$1 second=$2", ["x", "y"]) == "first=x second=y"


def test_expand_command_does_not_clobber_double_digit():
    args = [f"v{i}" for i in range(1, 11)]  # $1..$10
    out = flows.expand_command("$10 $1", args)
    assert out == "v10 v1"


def test_load_agents_reads_project_dir(monkeypatch, tmp_path):
    agents_dir = tmp_path / ".osprey" / "agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "recon.md").write_text(
        "---\ndescription: Read-only recon\ndeny_tools: metasploit_*, hydra_*\n---\n"
        "Stay in recon. Do not exploit.",
        encoding="utf-8",
    )
    # load_agents resolves `.osprey/agents` relative to cwd — run from tmp_path.
    monkeypatch.chdir(tmp_path)
    agents = flows.load_agents()
    assert "recon" in agents
    a = agents["recon"]
    assert a.description == "Read-only recon"
    assert a.deny_tools == ["metasploit_*", "hydra_*"]
    assert "Do not exploit" in a.prompt
    assert a.tool_allowed("subfinder_scan") and not a.tool_allowed("metasploit_run")
