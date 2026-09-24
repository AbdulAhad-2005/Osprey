"""Durable execution audit behavior."""

from __future__ import annotations

from osprey.schemas.audit import AuditAction
from osprey.services.audit_log import AuditLog


def test_audit_entries_persist_across_store_instances() -> None:
    engagement_id = "audit-durable"
    first = AuditLog()
    entry = first.record(
        AuditAction(
            tool_name="nmap_service_scan",
            target="192.0.2.10",
            engagement_id=engagement_id,
            run_id="run-audit",
            command="nmap -sV 192.0.2.10",
            success=True,
            returncode=0,
            duration_seconds=1.25,
            metadata={
                "params": {"target": "192.0.2.10"},
                "cache_key": "cache-123",
                "artifacts": {"stdout_path": "/tmp/nmap.out"},
            },
        )
    )

    restored = AuditLog().query(engagement_id=engagement_id)

    assert [item.id for item in restored] == [entry.id]
    assert restored[0].action.run_id == "run-audit"
    assert restored[0].action.command == "nmap -sV 192.0.2.10"
    assert restored[0].action.metadata["cache_key"] == "cache-123"
    assert restored[0].action.metadata["artifacts"]["stdout_path"] == "/tmp/nmap.out"
