"""``/finding fp`` + ``/fp`` — plans/harness/04-learning-fp-cache.md Step 3+4.

Mocks at the APIClient boundary — the backend-side logic has its own test
suite (backend/tests/test_finding_pipeline.py, test_fp_cache.py).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from cli.commands.slash import handle_finding, handle_fp


def _http_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "http://x/y")
    response = httpx.Response(status_code, request=request)
    return httpx.HTTPStatusError("boom", request=request, response=response)


def test_finding_fp_usage_with_no_args(capsys):
    client = MagicMock()
    handle_finding([], client)
    client.mark_finding_fp.assert_not_called()
    assert "Usage" in capsys.readouterr().out


def test_finding_fp_marks_and_prints_pattern(capsys):
    client = MagicMock()
    client.mark_finding_fp.return_value = {
        "pattern": {"id": "p1", "target_glob": "host-a.test", "title_contains": "501 Not Implemented"},
        "retracted_finding_id": "f1",
    }
    handle_finding(["fp", "f1", "known", "noise"], client)
    client.mark_finding_fp.assert_called_once_with("f1", reason="known noise", target_glob="")
    out = capsys.readouterr().out
    assert "Retracted finding f1" in out
    # Console wrapping may split the title text across lines — check the
    # normalized (whitespace-collapsed) output instead of an exact substring.
    assert "501 Not Implemented" in " ".join(out.split())


def test_finding_fp_with_explicit_scope_flag(capsys):
    client = MagicMock()
    client.mark_finding_fp.return_value = {
        "pattern": {"id": "p1", "target_glob": "*", "title_contains": "scanner self-banner"},
        "retracted_finding_id": "f1",
    }
    handle_finding(["fp", "f1", "--scope", "*", "always", "noise"], client)
    client.mark_finding_fp.assert_called_once_with("f1", reason="always noise", target_glob="*")


def test_finding_fp_404_prints_error(capsys):
    client = MagicMock()
    client.mark_finding_fp.side_effect = _http_error(404)
    handle_finding(["fp", "does-not-exist"], client)
    assert "No finding with id" in capsys.readouterr().out


def test_fp_list_empty(capsys):
    client = MagicMock()
    client.list_fp_patterns.return_value = {"patterns": [], "total": 0}
    handle_fp(["list"], client)
    assert "No FP-cache patterns yet" in capsys.readouterr().out


def test_fp_list_shows_patterns(capsys):
    client = MagicMock()
    client.list_fp_patterns.return_value = {
        "patterns": [
            {"id": "p1", "target_glob": "*", "finding_type": "vulnerability",
             "title_contains": "501 Not Implemented", "reason": "scanner noise"},
        ],
        "total": 1,
    }
    handle_fp([], client)  # default sub == "list"
    out = capsys.readouterr().out
    assert "p1" in out
    assert "501 Not Implemented" in out


def test_fp_remove_calls_client(capsys):
    client = MagicMock()
    handle_fp(["remove", "p1"], client)
    client.remove_fp_pattern.assert_called_once_with("p1")
    assert "Removed pattern p1" in capsys.readouterr().out


def test_fp_remove_404(capsys):
    client = MagicMock()
    client.remove_fp_pattern.side_effect = _http_error(404)
    handle_fp(["remove", "does-not-exist"], client)
    assert "No FP pattern with id" in capsys.readouterr().out
