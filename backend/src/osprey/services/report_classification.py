"""Presentation classification for current conclusions and legacy fact rows.

No stored finding, confidence, parser result, or evidence is modified here.
"""
from osprey.schemas.finding import is_conclusion_type


def is_security_finding(finding) -> bool:
    tags = set(finding.tags or [])
    return is_conclusion_type(finding.finding_type) and not tags.intersection(
        {"raw_output", "unparsed", "tool_error", "execution_error"}
    )


def partition_findings(findings):
    conclusions, supporting = [], []
    for finding in findings:
        (conclusions if is_security_finding(finding) else supporting).append(finding)
    return conclusions, supporting
