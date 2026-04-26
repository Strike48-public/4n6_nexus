"""Manager for handling finding approvals and rejections."""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .models import ApprovalMetadata, ApprovalStatus, FindingWithApproval


class ApprovalManager:
    """Manages finding approval workflow and persistence."""

    def __init__(self, findings_path: Path, audit_path: Optional[Path] = None):
        """Initialize approval manager.

        Args:
            findings_path: Path to findings.json file
            audit_path: Optional path to audit.jsonl file for approval logging
        """
        self.findings_path = findings_path
        self.audit_path = audit_path or findings_path.parent / "audit.jsonl"

    def load_findings(self) -> List[FindingWithApproval]:
        """Load findings from JSON file."""
        if not self.findings_path.exists():
            return []

        with open(self.findings_path, "r") as f:
            data = json.load(f)

        return [
            FindingWithApproval.from_dict(item) for item in data.get("findings", [])
        ]

    def save_findings(self, findings: List[FindingWithApproval]) -> None:
        """Save findings to JSON file."""
        data = {
            "findings": [f.to_dict() for f in findings],
            "summary": {
                "total": len(findings),
                "draft": sum(1 for f in findings if f.is_draft()),
                "approved": sum(1 for f in findings if f.is_approved()),
                "rejected": sum(1 for f in findings if f.is_rejected()),
            },
        }

        with open(self.findings_path, "w") as f:
            json.dump(data, f, indent=2)

    def approve(
        self,
        finding_ids: List[str],
        reviewer: str,
        reason: Optional[str] = None,
    ) -> int:
        """Approve findings.

        Args:
            finding_ids: List of finding IDs to approve
            reviewer: Name of reviewer approving findings
            reason: Optional approval reason

        Returns:
            Number of findings approved
        """
        findings = self.load_findings()
        approved_count = 0

        for finding in findings:
            if finding.finding_id in finding_ids:
                # Generate signature hash
                finding_json = json.dumps(finding.finding, sort_keys=True)
                signature = hashlib.sha256(
                    f"{finding_json}:{reviewer}:{datetime.utcnow().isoformat()}".encode()
                ).hexdigest()

                finding.approval = ApprovalMetadata(
                    status=ApprovalStatus.APPROVED,
                    reviewer=reviewer,
                    timestamp=datetime.utcnow(),
                    reason=reason,
                    signature_hash=signature[:16],  # First 16 chars for brevity
                )
                approved_count += 1

                self._log_audit("approve", finding, reviewer, reason)

        if approved_count > 0:
            self.save_findings(findings)

        return approved_count

    def reject(
        self,
        finding_ids: List[str],
        reviewer: str,
        reason: str,
    ) -> int:
        """Reject findings.

        Args:
            finding_ids: List of finding IDs to reject
            reviewer: Name of reviewer rejecting findings
            reason: Required rejection reason

        Returns:
            Number of findings rejected
        """
        findings = self.load_findings()
        rejected_count = 0

        for finding in findings:
            if finding.finding_id in finding_ids:
                finding.approval = ApprovalMetadata(
                    status=ApprovalStatus.REJECTED,
                    reviewer=reviewer,
                    timestamp=datetime.utcnow(),
                    reason=reason,
                )
                rejected_count += 1

                self._log_audit("reject", finding, reviewer, reason)

        if rejected_count > 0:
            self.save_findings(findings)

        return rejected_count

    def get_by_status(self, status: ApprovalStatus) -> List[FindingWithApproval]:
        """Get findings filtered by approval status."""
        findings = self.load_findings()
        return [f for f in findings if f.status == status]

    def _log_audit(
        self,
        action: str,
        finding: FindingWithApproval,
        reviewer: str,
        reason: Optional[str],
    ) -> None:
        """Log approval/rejection action to audit trail."""
        if not self.audit_path:
            return

        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "finding_id": finding.finding_id,
            "finding_title": finding.finding.get("title", "Unknown"),
            "reviewer": reviewer,
            "reason": reason,
            "signature_hash": (
                finding.approval.signature_hash if finding.approval else None
            ),
        }

        # Append to audit log (JSONL format)
        with open(self.audit_path, "a") as f:
            f.write(json.dumps(audit_entry) + "\n")
