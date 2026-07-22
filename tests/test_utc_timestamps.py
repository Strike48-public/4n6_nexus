"""Regression tests: timestamps are timezone-aware UTC, not naive utcnow().

datetime.utcnow() is deprecated (Python 3.12) and returns a NAIVE datetime,
which is a forensic hazard — an ISO string without an offset is ambiguous. The
engine's convention (CLAUDE.md: "Always output in UTC") is now enforced with
timezone-aware datetimes. These tests pin that so a regression to utcnow()
(naive) is caught.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

pytestmark = pytest.mark.unit


def _write_draft_findings(path):
    """Write a findings.json with one draft finding in the on-disk envelope."""
    path.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "finding_id": "f1",
                        "finding": {"title": "t", "severity": "high"},
                        "approval": None,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                ]
            }
        )
    )


class TestApprovalManagerTimestamps:
    def test_approve_sets_timezone_aware_timestamp(self, tmp_path):
        from sift_find_evil.approval.manager import ApprovalManager

        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)
        mgr = ApprovalManager(findings_path=findings_path)
        mgr.approve(["f1"], reviewer="analyst", reason="looks real")

        approved = mgr.load_findings()
        ts = approved[0].approval.timestamp
        # Timezone-aware UTC, not a naive utcnow() value.
        assert ts.tzinfo is not None
        assert ts.utcoffset() == timezone.utc.utcoffset(None)

    def test_audit_timestamp_isoformat_carries_offset(self, tmp_path):
        from sift_find_evil.approval.manager import ApprovalManager

        findings_path = tmp_path / "findings.json"
        audit_path = tmp_path / "audit.jsonl"
        _write_draft_findings(findings_path)
        mgr = ApprovalManager(findings_path=findings_path, audit_path=audit_path)
        mgr.approve(["f1"], reviewer="analyst", reason="looks real")

        line = audit_path.read_text().splitlines()[0]
        ts = json.loads(line)["timestamp"]
        # A timezone-aware isoformat ends with an explicit UTC offset.
        assert ts.endswith("+00:00")


class TestCaseManagerTimestamps:
    def test_case_created_at_is_timezone_aware(self, tmp_path):
        from sift_find_evil.case.manager import CaseManager

        mgr = CaseManager(case_root=tmp_path)
        case = mgr.create_case(
            case_id="INC-2026-001",
            name="test-case",
            examiner="analyst",
            description="d",
        )
        assert case.created_at.tzinfo is not None
        assert case.created_at.utcoffset() == timezone.utc.utcoffset(None)


class TestMcpClientTimestamps:
    def test_last_failure_time_is_timezone_aware_on_failure(self, tmp_path):
        from sift_find_evil.mcp.client import MCPClient

        client = MCPClient()
        # A tool that does not exist makes execution fail, stamping
        # last_failure_time. The exact exception is irrelevant.
        with pytest.raises(Exception):  # noqa: B017 - failure path stamps the time
            client.execute_tool(
                "definitely-not-a-real-tool-xyz",
                ["definitely-not-a-real-tool-xyz", "-r", "x"],
            )
        assert client.last_failure_time is not None
        assert client.last_failure_time.tzinfo is not None
