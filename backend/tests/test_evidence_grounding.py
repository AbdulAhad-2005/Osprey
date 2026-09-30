"""Unit tests for evidence_grounding.py — plans/harness/12-deterministic-
evidence-verification.md Step 1. Pure-function checks against Observation/
Evidence, no DB/network.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.evidence_grounding import ground_claim


def _obs(details: dict | None = None, evidence_id: str = "") -> Observation:
    return Observation(
        type=ObservationType.SCANNER_SIGNAL,
        target="x.test",
        source_tool="sqlmap_scan",
        details=details or {},
        evidence_id=evidence_id,
    )


def test_rejects_claim_too_short_to_ground():
    obs = _obs({"snippet": "some real tool output here that is long enough to matter"})
    ok, reason = ground_claim("it worked", obs)
    assert not ok
    assert "too short" in reason


def test_rejects_when_no_raw_text_available_at_all():
    obs = _obs({})
    ok, reason = ground_claim("this is a sufficiently long fabricated claim text", obs)
    assert not ok
    assert "no recorded raw tool output" in reason


def test_accepts_claim_grounded_in_observation_details_snippet():
    real_output = "sqlmap identified the following injection point: id=1 AND SLEEP(5) -- boolean-based blind"
    obs = _obs({"snippet": real_output})
    claim = f"Confirmed: {real_output}"
    ok, reason = ground_claim(claim, obs)
    assert ok, reason


def test_rejects_claim_that_paraphrases_without_quoting():
    real_output = "sqlmap identified the following injection point: id=1 AND SLEEP(5) -- boolean-based blind"
    obs = _obs({"snippet": real_output})
    claim = "I ran a totally different test and confirmed the site is vulnerable to attack"
    ok, reason = ground_claim(claim, obs)
    assert not ok
    assert "doesn't contain any excerpt" in reason


def test_accepts_claim_grounded_via_evidence_store_raw_excerpt():
    obs = _obs({}, evidence_id="ev123")
    fake_evidence = MagicMock()
    fake_evidence.raw_excerpt = "HTTP/1.1 500 Internal Server Error — stack trace leaked DB credentials inline"
    with patch("osprey.services.evidence_grounding.get_evidence_store") as mock_store:
        mock_store.return_value.get.return_value = fake_evidence
        claim = "Server returned: stack trace leaked DB credentials inline in the response body"
        ok, reason = ground_claim(claim, obs)
    assert ok, reason


def test_case_and_whitespace_insensitive_matching():
    real_output = "Vulnerable parameter:   'username'   \n  reflected XSS confirmed via <script>alert(1)</script>"
    obs = _obs({"snippet": real_output})
    claim = "REFLECTED XSS CONFIRMED VIA <SCRIPT>ALERT(1)</SCRIPT> — filed as high severity"
    ok, reason = ground_claim(claim, obs)
    assert ok, reason
