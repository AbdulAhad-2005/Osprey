# Replay & benchmark corpus

See `plans/harness/01-replay-benchmark-harness.md`. Record → replay → score.

- `recordings/<name>.jsonl` — a fixture's ordered tool-call sequence (header
  line + one `ToolCallRecord` per line). `synthetic-*` fixtures are
  hand-authored (no live Kali/tool needed to replay them); a real recording
  (via `osprey benchmark record --engagement-id ID --name NAME`) captures a
  live/recent engagement instead — do that soon after the engagement while
  the backend's in-process audit log and Kali connection are still live (both
  are process-lifetime only today, not yet durable across restarts).
- `recordings/<name>.labels.json` — optional ground truth for a fixture
  (`FixtureLabels`): planted noise (known-not-real signals) and planted vulns
  (known-real ones), so `false_positive_rate`/`confirmed_without_proof_count`/
  `missed_known_vuln_count` are computable against a known answer, not guessed.
- `results/<run_id>.json` — a saved `Scorecard` from `osprey benchmark run`.
  `results/baseline-<fixture-name>.json` are the pinned reference scorecards
  every later plan (02+ onward) diffs against — do not overwrite them
  silently; a real pipeline change should produce a new run_id and a
  deliberate `osprey benchmark diff --baseline baseline-<name> --candidate <new>`.

Real recordings may contain live engagement data — review before committing
one; synthetic fixtures never do (they're just text this repo already ships).

## CLI

```bash
osprey benchmark install-builtin              # write the synthetic fixtures to disk
osprey benchmark list                         # list available fixtures
osprey benchmark record --engagement-id ID --name NAME [--target T]
osprey benchmark run --fixture NAME           # replay + score, prints the scorecard
osprey benchmark diff --baseline ID --candidate ID
```

Deterministic by default (no live LLM in the replayed ingestion path, even if
the replaying process happens to have an LLM key configured) — see
`replay_recording`'s `live_llm` parameter and the plan's "Determinism scope".
