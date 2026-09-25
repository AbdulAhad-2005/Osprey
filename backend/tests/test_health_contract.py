from __future__ import annotations

from osprey.contract import API_CONTRACT_VERSION, APP_VERSION, CAPABILITIES
from osprey.services.startup_readiness import mark_ready, snapshot


def test_health_exposes_machine_readable_compatibility_contract() -> None:
    mark_ready()

    payload = snapshot("test")

    assert payload["version"] == APP_VERSION
    assert payload["api_contract_version"] == API_CONTRACT_VERSION
    assert payload["capabilities"] == list(CAPABILITIES)
    assert "engagement_pinning" in payload["capabilities"]
