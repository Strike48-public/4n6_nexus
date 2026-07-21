"""Manager for handling finding approvals and rejections."""

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

from ..canonical import canonical_bytes
from .models import ApprovalMetadata, ApprovalStatus, FindingWithApproval

# Environment variable holding the HMAC signing key for approval signatures.
# When unset/empty, approvals are recorded UNSIGNED rather than carrying a
# forgeable keyless hash (see SFE-jlce).
APPROVAL_HMAC_KEY_ENV = "SFE_APPROVAL_HMAC_KEY"


def _resolve_key(secret_key: Optional[Union[bytes, str]]) -> Optional[bytes]:
    """Resolve the effective signing key from an explicit arg or the env var.

    An explicit ``secret_key`` wins; otherwise the ``SFE_APPROVAL_HMAC_KEY``
    environment variable is consulted. An empty string (arg or env) is treated
    as "no key configured" -> signatures are omitted rather than faked, since
    an empty HMAC key is cryptographically meaningless.
    """
    raw: Optional[Union[bytes, str]] = secret_key
    if raw is None:
        raw = os.environ.get(APPROVAL_HMAC_KEY_ENV)
    if not raw:
        return None
    return raw if isinstance(raw, bytes) else raw.encode()


def _canonical_message(
    finding_id: str,
    finding: dict,
    status: str,
    reviewer: str,
    reason: Optional[str],
    timestamp_iso: str,
) -> bytes:
    """Serialize an approval decision to canonical, UTF-8 JSON bytes.

    Key order is normalized (``sort_keys=True``) and whitespace stripped so the
    byte sequence is reproducible across processes.
    Every field that defines the decision is bound: the finding identity and
    content, the status, the reviewer, the reason, and the STORED timestamp.
    Editing any of them, or copying a signature onto a different finding,
    changes this message and therefore fails verification.
    """
    payload = {
        "finding_id": finding_id,
        "finding": finding,
        "status": status,
        "reviewer": reviewer,
        "reason": reason,
        "timestamp": timestamp_iso,
    }
    # Shared canonical serializer (byte-identical here since the payload is all
    # strings; default=str is a harmless superset over the previous inline form).
    return canonical_bytes(payload)


class ApprovalManager:
    """Manages finding approval workflow and persistence."""

    def __init__(
        self,
        findings_path: Path,
        audit_path: Optional[Path] = None,
        secret_key: Optional[Union[bytes, str]] = None,
    ):
        """Initialize approval manager.

        Args:
            findings_path: Path to findings.json file
            audit_path: Optional path to audit.jsonl file for approval logging
            secret_key: Optional HMAC signing key for approval signatures. When
                omitted, falls back to the ``SFE_APPROVAL_HMAC_KEY`` environment
                variable; when neither is set, approvals are recorded unsigned.
        """
        self.findings_path = findings_path
        self.audit_path = audit_path or findings_path.parent / "audit.jsonl"
        self._secret_key = _resolve_key(secret_key)

    @property
    def has_signing_key(self) -> bool:
        """Whether a signing/verification key is configured."""
        return self._secret_key is not None

    def _sign(
        self,
        finding_id: str,
        finding: dict,
        status: ApprovalStatus,
        reviewer: str,
        reason: Optional[str],
        timestamp: datetime,
    ) -> Optional[str]:
        """Compute the HMAC-SHA256 signature for a decision, or None if unkeyed.

        The signature is computed over the exact ``timestamp`` that will be
        persisted, so verification can reproduce it byte-for-byte from disk.
        """
        if self._secret_key is None:
            return None
        message = _canonical_message(
            finding_id,
            finding,
            status.value,
            reviewer,
            reason,
            timestamp.isoformat(),
        )
        return hmac.new(self._secret_key, message, hashlib.sha256).hexdigest()

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
                # Sign over the SAME timestamp we persist, so verify() can
                # reproduce the HMAC from disk. Unkeyed managers sign None.
                timestamp = datetime.now(timezone.utc)
                signature = self._sign(
                    finding.finding_id,
                    finding.finding,
                    ApprovalStatus.APPROVED,
                    reviewer,
                    reason,
                    timestamp,
                )

                finding.approval = ApprovalMetadata(
                    status=ApprovalStatus.APPROVED,
                    reviewer=reviewer,
                    timestamp=timestamp,
                    reason=reason,
                    signature_hash=signature,
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
                timestamp = datetime.now(timezone.utc)
                signature = self._sign(
                    finding.finding_id,
                    finding.finding,
                    ApprovalStatus.REJECTED,
                    reviewer,
                    reason,
                    timestamp,
                )

                finding.approval = ApprovalMetadata(
                    status=ApprovalStatus.REJECTED,
                    reviewer=reviewer,
                    timestamp=timestamp,
                    reason=reason,
                    signature_hash=signature,
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

    def verify(self) -> dict:
        """Re-verify approval signatures against the persisted decisions.

        Recomputes the HMAC over each signed finding's stored content and
        metadata and compares it in constant time to the stored signature.
        Detects post-approval tampering with the finding body, status,
        reviewer, reason, or timestamp, and signatures copied between findings.

        Returns:
            A results dict with counts (total/verified/tampered/unsigned) and a
            per-finding ``details`` list, or ``{"error": ...}`` if no signing
            key is configured (verification is impossible without it).
        """
        # Only decided (approved/rejected) findings carry signatures; drafts
        # are not signed and are not part of the integrity surface.
        decided = [f for f in self.load_findings() if not f.is_draft()]

        if self._secret_key is None:
            # Distinguish "never configured signing" from "there are signed
            # findings but the key is gone" — the latter is a possible key
            # loss / downgrade and must not be mistaken for unsigned data.
            signed = sum(
                1
                for f in decided
                if f.approval and f.approval.signature_hash is not None
            )
            if signed:
                return {
                    "error": (
                        f"Found {signed} signed finding(s) but no signing key "
                        f"configured ({APPROVAL_HMAC_KEY_ENV}); integrity "
                        "cannot be verified (possible key loss or downgrade)."
                    )
                }
            return {
                "error": (
                    "No signing key configured; set "
                    f"{APPROVAL_HMAC_KEY_ENV} to verify approval signatures."
                )
            }

        results: dict = {
            "total": len(decided),
            "verified": 0,
            "tampered": 0,
            "unsigned": 0,
            "details": [],
        }

        for finding in decided:
            approval = finding.approval
            if approval is None or approval.signature_hash is None:
                results["unsigned"] += 1
                results["details"].append(
                    {"finding_id": finding.finding_id, "status": "UNSIGNED"}
                )
                continue

            expected = self._sign(
                finding.finding_id,
                finding.finding,
                approval.status,
                approval.reviewer,
                approval.reason,
                approval.timestamp,
            )

            # A crafted signature_hash (non-hex / non-ASCII / wrong length)
            # cannot match a real HMAC hex digest and would make
            # hmac.compare_digest raise on non-ASCII input; treat it as tamper.
            stored = approval.signature_hash
            well_formed = len(stored) == 64 and all(
                c in "0123456789abcdef" for c in stored
            )

            if (
                well_formed
                and expected is not None
                and hmac.compare_digest(expected, stored)
            ):
                results["verified"] += 1
                results["details"].append(
                    {"finding_id": finding.finding_id, "status": "VERIFIED"}
                )
            else:
                results["tampered"] += 1
                results["details"].append(
                    {"finding_id": finding.finding_id, "status": "TAMPERED"}
                )

        results["failed"] = results["tampered"]
        return results

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
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
