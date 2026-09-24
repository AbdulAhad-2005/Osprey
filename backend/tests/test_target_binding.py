"""Target binding accepts anything scannable — domain, IP, IPv6, CIDR, host:port,
URL — and only a genuinely ambiguous bare label asks for clarification. Port is
carried as scope, never baked into the engagement key.
"""

from __future__ import annotations

import pytest
from osprey.services.session_context import _bindable_target, normalize_target
from osprey.services.target_analysis import analyze_target, classify_target


@pytest.mark.parametrize("raw,kind,key,port", [
    ("example.com", "domain", "example.com", None),
    ("1.2.3.4", "ip", "1.2.3.4", None),
    ("1.2.3.4:8080", "host_port", "1.2.3.4", 8080),
    ("example.com:8443", "host_port", "example.com", 8443),
    ("10.0.0.0/24", "cidr", "10.0.0.0/24", None),
    ("2001:db8::1", "ipv6", "2001:db8::1", None),
    ("[::1]:8080", "ipv6", "::1", 8080),
    ("https://app.example.com:8443/login", "url", "app.example.com", 8443),
    ("http://1.2.3.4/", "ip", "1.2.3.4", None),
    ("scan example.com please", "domain", "example.com", None),
    ("osprey scan example.com", "domain", "example.com", None),
])
def test_classify_target(raw, kind, key, port):
    spec = classify_target(raw)
    assert spec.kind == kind
    assert spec.engagement_target == key
    assert spec.port == port
    assert spec.bindable is True


@pytest.mark.parametrize("raw", ["zong", "", "not a target!!"])
def test_classify_non_bindable(raw):
    assert classify_target(raw).bindable is False


def test_analyze_target_ip_is_ready_not_clarification():
    a = analyze_target("1.2.3.4", probe_dns=False)
    assert a.status == "ready"
    assert a.needs_clarification is False
    assert a.ready_domain == "1.2.3.4"
    assert a.target_kind == "ip"
    assert "subdomain" in a.agent_instruction.lower()  # guidance to skip subdomain enum


def test_analyze_target_host_port_carries_scope():
    a = analyze_target("1.2.3.4:8080", probe_dns=False)
    assert a.status == "ready"
    assert a.ready_domain == "1.2.3.4"  # key = bare host, no port
    assert a.scope_port == 8080
    assert "8080" in a.scope


def test_analyze_target_cidr_ready():
    a = analyze_target("10.0.0.0/24", probe_dns=False)
    assert a.status == "ready" and a.target_kind == "cidr"
    assert a.ready_domain == "10.0.0.0/24"


def test_analyze_target_bare_label_still_clarifies():
    a = analyze_target("zong", probe_dns=False)
    assert a.status == "ambiguous"
    assert a.needs_clarification is True


def test_session_normalize_key_is_bare_host_and_preserves_cidr():
    assert normalize_target("1.2.3.4:8080") == "1.2.3.4"
    assert normalize_target("example.com:8443") == "example.com"
    assert normalize_target("10.0.0.0/24") == "10.0.0.0/24"  # mask NOT stripped
    assert _bindable_target("1.2.3.4") is True
    assert _bindable_target("zong") is False
