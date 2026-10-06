"""parse_app_recon: app_recon JSON -> observations.

The app-recon worker emits the same JSON contract js_recon does plus app
metadata; the parser must turn it into the right typed observations — backend
hostnames as SUBDOMAIN seeds (so the engagement resolves/probes them like any
discovered name), endpoints/secrets/cloud like js_recon, platform as a
TECHNOLOGY fact, and declared posture as SCANNER_SIGNAL facts (never verdicts).
"""

from __future__ import annotations

import json

from osprey.schemas.observation import ObservationType
from osprey.services.parsers.web_recon import parse_app_recon


def _apk_payload() -> str:
    return json.dumps({
        "target": "/work/app.apk",
        "app_type": "apk",
        "platform": "android",
        "package": "com.example.app",
        "version": "1.2.3",
        "endpoints": ["/api/v2/users", "https://api.example.com/v1/login"],
        "endpoint_count": 2,
        "hosts": ["api.example.com", "backend.corp.example.com"],
        "secrets": [
            {"type": "aws_access_key_id", "match": "AKIA...", "secret": "AKIA1234567890ABCDEF",
             "high_signal": True, "source": "classes.dex"},
        ],
        "cloud_assets": [{"type": "s3_bucket_url", "bucket": "mybucket",
                          "match": "mybucket.s3.amazonaws.com"}],
        "permissions": ["android.permission.INTERNET", "android.permission.CAMERA"],
        "dangerous_permissions": ["android.permission.CAMERA"],
        "cleartext_traffic": True,
        "url_schemes": ["myapp"],
        "components": ["com.example.app.MainActivity"],
    })


def _obs(payload: str):
    return parse_app_recon(payload, engagement_id="e1", run_id="r1", target="example.com")


def test_backend_hosts_become_subdomain_seeds():
    obs = _obs(_apk_payload())
    subs = [o for o in obs if o.type == ObservationType.SUBDOMAIN]
    names = {o.details.get("hostname") for o in subs}
    assert names == {"api.example.com", "backend.corp.example.com"}
    # Same shape subfinder uses: hostname in details, engagement target as target,
    # so the graph ingests them as resolvable seeds.
    for o in subs:
        assert o.target == "example.com"
        assert o.source_tool == "app_recon"
        assert "app-backend" in o.tags


def test_endpoints_secrets_cloud_platform():
    obs = _obs(_apk_payload())
    eps = [o for o in obs if o.type == ObservationType.ENDPOINT]
    # 2 real endpoints + 1 cloud asset (also ENDPOINT-typed, js_recon convention)
    endpoint_vals = {o.details.get("endpoint") for o in eps if "endpoint" in o.details}
    assert "/api/v2/users" in endpoint_vals
    assert any("injection_point_candidate" in o.tags for o in eps)
    cloud = [o for o in eps if "cloud-asset" in o.tags]
    assert cloud and cloud[0].details.get("bucket") == "mybucket"

    secrets = [o for o in obs if o.type == ObservationType.SECRET]
    assert len(secrets) == 1
    assert secrets[0].details["secret_type"] == "aws_access_key_id"
    assert "verify_validity" in secrets[0].tags  # high_signal

    tech = [o for o in obs if o.type == ObservationType.TECHNOLOGY]
    assert tech and tech[0].details.get("platform") == "android"
    assert tech[0].details.get("package") == "com.example.app"


def test_posture_signals_are_scanner_signals_not_verdicts():
    obs = _obs(_apk_payload())
    sigs = {o.details.get("signal") for o in obs if o.type == ObservationType.SCANNER_SIGNAL}
    assert "cleartext_traffic_permitted" in sigs
    assert "dangerous_permissions" in sigs
    assert "custom_url_schemes" in sigs
    # Posture facts must never be emitted as findings/verdicts — only signals.
    assert all(
        o.type == ObservationType.SCANNER_SIGNAL
        for o in obs
        if "app-posture" in o.tags
    )


def test_ios_ats_and_schemes():
    payload = json.dumps({
        "target": "/work/app.ipa", "app_type": "ipa", "platform": "ios",
        "bundle_id": "com.example.ios", "version": "4.0",
        "endpoints": [], "hosts": [], "secrets": [], "cloud_assets": [],
        "url_schemes": ["myapp", "fbauth2"], "ats_arbitrary_loads": True,
    })
    obs = parse_app_recon(payload, engagement_id="e1", run_id="r1", target="example.com")
    sigs = {o.details.get("signal") for o in obs if o.type == ObservationType.SCANNER_SIGNAL}
    assert "ios_ats_arbitrary_loads" in sigs
    assert "custom_url_schemes" in sigs
    tech = [o for o in obs if o.type == ObservationType.TECHNOLOGY]
    assert tech and tech[0].details.get("bundle_id") == "com.example.ios"


def test_empty_and_error_inputs_yield_nothing():
    assert parse_app_recon("not json") == []
    assert parse_app_recon(json.dumps({"error": "provide --app-path or --url"})) == []
    assert parse_app_recon(json.dumps([])) == []
    assert parse_app_recon("") == []


def test_cleartext_false_emits_no_signal():
    payload = json.dumps({
        "app_type": "apk", "platform": "android",
        "endpoints": [], "hosts": [], "secrets": [], "cloud_assets": [],
        "cleartext_traffic": None, "dangerous_permissions": [],
    })
    obs = parse_app_recon(payload, engagement_id="e1", run_id="r1", target="x")
    sigs = [o for o in obs if o.type == ObservationType.SCANNER_SIGNAL]
    assert sigs == []
