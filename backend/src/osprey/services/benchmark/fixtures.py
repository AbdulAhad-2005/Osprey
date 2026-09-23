"""Fixture (recording + optional labels) storage, and the built-in synthetic
fixtures plans/harness/01-replay-benchmark-harness.md Step 4 asks for.

Synthetic fixtures are hand-authored so replay needs no live Kali/tool at
all — every byte of "tool output" is written here, in the exact shape the
*current, real* parser it targets expects (verified against that parser's
source, not guessed), so replaying one exercises real production parsing
code and produces a real, checkable result.
"""

from __future__ import annotations

from pathlib import Path

from osprey.schemas.benchmark import (
    FixtureLabels,
    NoiseLabel,
    PlantedVuln,
    Recording,
    ToolCallRecord,
)
from osprey.services.benchmark.recorder import RECORDINGS_DIR, save_recording

_LABELS_SUFFIX = ".labels.json"


def load_labels(name: str, *, directory: Path | None = None) -> FixtureLabels | None:
    in_dir = directory or RECORDINGS_DIR
    path = in_dir / f"{name}{_LABELS_SUFFIX}"
    if not path.is_file():
        return None
    return FixtureLabels.model_validate_json(path.read_text(encoding="utf-8"))


def save_labels(labels: FixtureLabels, *, directory: Path | None = None) -> Path:
    out_dir = directory or RECORDINGS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{labels.fixture_name}{_LABELS_SUFFIX}"
    path.write_text(labels.model_dump_json(indent=2), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Built-in synthetic fixtures
# --------------------------------------------------------------------------

def _fixture_web_recon_mixed() -> tuple[Recording, FixtureLabels]:
    """One genuine planted vuln (an explicit script FINDING marker — the
    documented, exact format freeform_probe.py's `_FINDING_MARKER_RE`
    parses) plus one verified-real false-positive trap: a bare `URL status`
    line with a 501 status. `_ERROR_STATUSES` in freeform_probe.py (checked
    against the live source) does not include "501", so this line is
    promoted straight to a CONFIRMED URL finding today with zero
    corroboration — the exact "HTTP 501 became a finding" failure class this
    whole harness program exists to kill. This fixture is a real,
    reproducible instance of it, not a hypothetical.
    """
    target = "bench-target.test"
    stdout = (
        "FINDING|confirmed|critical|technology|Outdated OpenSSH 7.2 (CVE-2016-6210)"
        "|nmap banner grab on port 22: SSH-2.0-OpenSSH_7.2p2 Ubuntu, matches "
        "CVE-2016-6210 (user enumeration via authentication timing)\n"
        "https://internal-api.bench-target.test/legacy-status 501 Not Implemented\n"
    )
    recording = Recording(
        name="synthetic-web-recon-mixed",
        target=target,
        synthetic=True,
        calls=[
            ToolCallRecord(
                tool_name="script:probe",
                target=target,
                command="platform_script probe.py",
                stdout=stdout,
                returncode=0,
                success=True,
                stdout_source="none",  # hand-authored, not captured from a real run
            )
        ],
    )
    labels = FixtureLabels(
        fixture_name=recording.name,
        noise=[
            NoiseLabel(
                tool_name="script:probe",
                title_contains="internal-api.bench-target.test/legacy-status",
                reason=(
                    "Bare HTTP 501 with no corroboration — freeform_probe.py's "
                    "_ERROR_STATUSES omits 501, so this is promoted to a CONFIRMED "
                    "URL finding by the current pipeline with zero real evidence."
                ),
            )
        ],
        planted_vulns=[
            PlantedVuln(
                tool_name="script:probe",
                target=target,
                title_contains="CVE-2016-6210",
                description="Explicit FINDING marker naming a real, versioned OpenSSH CVE.",
            )
        ],
    )
    return recording, labels


def _fixture_repeat_scan_redundancy() -> tuple[Recording, FixtureLabels]:
    """No noise, no planted vuln — exists purely to make
    `redundant_action_count` computable: the same (tool, target) recorded
    three times, only the first of which should count as non-redundant."""
    target = "bench-repeat.test"
    call = ToolCallRecord(
        tool_name="script:probe",
        target=target,
        command="platform_script probe.py",
        stdout="FINDING|likely|info|observation|Probe ran|no new information this pass\n",
        returncode=0,
        success=True,
        stdout_source="none",
    )
    recording = Recording(
        name="synthetic-repeat-scan-redundancy",
        target=target,
        synthetic=True,
        calls=[call, call.model_copy(), call.model_copy()],
    )
    labels = FixtureLabels(fixture_name=recording.name)
    return recording, labels


_BUILTIN_FIXTURES = (
    _fixture_web_recon_mixed,
    _fixture_repeat_scan_redundancy,
)


def install_builtin_fixtures(*, directory: Path | None = None) -> list[str]:
    """Write every built-in synthetic fixture to disk (idempotent — re-running
    just overwrites with the same content). Returns the fixture names."""
    names = []
    for builder in _BUILTIN_FIXTURES:
        recording, labels = builder()
        save_recording(recording, directory=directory)
        save_labels(labels, directory=directory)
        names.append(recording.name)
    return names
