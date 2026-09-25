"""Reverse-DNS PTR ingestion: provider auto-PTR names that just re-encode their
own IP must not inflate the subdomain surface (they drove a recon-reopen storm
of hundreds of non-existent hosts). They are kept as DNS_RECORD evidence; only
genuine PTR hostnames become SUBDOMAIN seeds.
"""

from __future__ import annotations

from osprey.schemas.observation import ObservationType
from osprey.services.parsers.recon_network import (
    _is_ptr_ip_placeholder,
    parse_dnsx_reverse,
)


def test_ip_placeholder_detection():
    assert _is_ptr_ip_placeholder("115-186-143-17.nadra.gov.pk", "115.186.143.17") is True
    assert _is_ptr_ip_placeholder("115.186.143.17.nadra.gov.pk", "115.186.143.17") is True
    assert _is_ptr_ip_placeholder("mail.nadra.gov.pk", "115.186.143.5") is False
    # A hostname whose label merely starts with a number is not a placeholder.
    assert _is_ptr_ip_placeholder("2fa.example.com", "10.0.0.9") is False


def test_placeholder_ptr_is_dns_record_not_subdomain():
    out = parse_dnsx_reverse(
        "115.186.143.17 [PTR] [115-186-143-17.nadra.gov.pk]\n"
        "115.186.143.5 [PTR] [mail.nadra.gov.pk]"
    )
    subs = [o for o in out if o.type == ObservationType.SUBDOMAIN]
    dns = [o for o in out if o.type == ObservationType.DNS_RECORD]
    assert [o.details["hostname"] for o in subs] == ["mail.nadra.gov.pk"]
    assert len(dns) == 1
    assert dns[0].details["hostname"] == "115-186-143-17.nadra.gov.pk"
    assert "ip_placeholder" in dns[0].tags
