"""`osprey benchmark ...` one-shot subcommand — proves the replay/benchmark
harness (plans/harness/01-...) is drivable from the CLI, not just the REST
API directly (architectural invariant I in plans/harness/README.md).

Mocks at the APIClient boundary (thin HTTP wrappers) rather than spinning up
a live backend — the backend-side logic has its own full test suite
(backend/tests/test_benchmark_harness.py).
"""

from __future__ import annotations

import argparse
from unittest.mock import MagicMock

from cli.main import _run_benchmark_noninteractive


def _args(**kw) -> argparse.Namespace:
    base = {
        "benchmark_command": None,
        "engagement_id": None,
        "name": None,
        "target": None,
        "fixture": None,
        "baseline": None,
        "candidate": None,
    }
    base.update(kw)
    return argparse.Namespace(**base)


def test_list_calls_client_and_prints_fixtures(monkeypatch, capsys):
    client = MagicMock()
    client.benchmark_list_fixtures.return_value = {"fixtures": ["synthetic-web-recon-mixed"]}
    monkeypatch.setattr("cli.main.APIClient", lambda base_url: client)

    rc = _run_benchmark_noninteractive(_args(benchmark_command="list"))

    assert rc == 0
    client.benchmark_list_fixtures.assert_called_once()
    assert "synthetic-web-recon-mixed" in capsys.readouterr().out


def test_install_builtin_calls_client(monkeypatch, capsys):
    client = MagicMock()
    client.benchmark_install_builtin_fixtures.return_value = {
        "installed": ["synthetic-web-recon-mixed", "synthetic-repeat-scan-redundancy"]
    }
    monkeypatch.setattr("cli.main.APIClient", lambda base_url: client)

    rc = _run_benchmark_noninteractive(_args(benchmark_command="install-builtin"))

    assert rc == 0
    client.benchmark_install_builtin_fixtures.assert_called_once()


def test_record_requires_engagement_id_and_name(monkeypatch, capsys):
    client = MagicMock()
    monkeypatch.setattr("cli.main.APIClient", lambda base_url: client)

    rc = _run_benchmark_noninteractive(_args(benchmark_command="record"))

    assert rc == 2
    client.benchmark_record.assert_not_called()
    assert "Usage" in capsys.readouterr().out


def test_record_passes_through_args(monkeypatch):
    client = MagicMock()
    client.benchmark_record.return_value = {
        "name": "prod-run", "path": "/x/prod-run.jsonl", "calls_recorded": 5,
        "degraded_fidelity_calls": 0,
    }
    monkeypatch.setattr("cli.main.APIClient", lambda base_url: client)

    rc = _run_benchmark_noninteractive(
        _args(benchmark_command="record", engagement_id="eng123", name="prod-run", target="x.test")
    )

    assert rc == 0
    client.benchmark_record.assert_called_once_with(
        engagement_id="eng123", name="prod-run", target="x.test"
    )


def test_run_prints_scorecard(monkeypatch, capsys):
    client = MagicMock()
    client.benchmark_run.return_value = {
        "run_id": "abc123",
        "fixture_name": "synthetic-web-recon-mixed",
        "mode": "deterministic",
        "false_positive_rate": 0.25,
        "validated_finding_count": 3,
        "confirmed_without_proof_count": 1,
        "attack_surface_coverage": 1,
        "redundant_action_count": 0,
        "missed_known_vuln_count": 0,
        "time_to_first_validated_finding_seconds": None,
        "notes": [],
    }
    monkeypatch.setattr("cli.main.APIClient", lambda base_url: client)

    rc = _run_benchmark_noninteractive(_args(benchmark_command="run", fixture="synthetic-web-recon-mixed"))

    assert rc == 0
    client.benchmark_run.assert_called_once_with("synthetic-web-recon-mixed")
    out = capsys.readouterr().out
    assert "false_positive_rate [deterministic]: 0.25" in out
    assert "time_to_first_validated_finding_seconds [llm-dependent]: unmeasured" in out


def test_diff_prints_deltas(monkeypatch, capsys):
    client = MagicMock()
    client.benchmark_diff.return_value = {
        "baseline_run_id": "run1",
        "candidate_run_id": "run2",
        "deltas": {
            "false_positive_rate": {"baseline": 0.5, "candidate": 0.0, "delta": -0.5},
        },
    }
    monkeypatch.setattr("cli.main.APIClient", lambda base_url: client)

    rc = _run_benchmark_noninteractive(_args(benchmark_command="diff", baseline="run1", candidate="run2"))

    assert rc == 0
    client.benchmark_diff.assert_called_once_with("run1", "run2")
    assert "delta=-0.5" in capsys.readouterr().out
