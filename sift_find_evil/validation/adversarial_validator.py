"""Adversarial validator that critically examines CRITICAL findings.

Systematically challenges findings to catch errors in reasoning, evidence,
or confidence scoring before they reach the user.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ValidationCheck:
    """Result of a single validation check."""

    check_name: str
    issues: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Check passed if no issues found."""
        return len(self.issues) == 0


@dataclass
class ValidationReport:
    """Complete validation report for a finding."""

    finding_title: str
    checks: list[ValidationCheck]
    validation_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def passed(self) -> bool:
        """Validation passed (no critical issues)."""
        return len(self.critical_issues) == 0

    @property
    def critical_issues(self) -> list[str]:
        """Issues that invalidate the finding (must fix)."""
        critical_check_names = {
            "evidence_completeness",
            "reasoning_logic",
            "hash_format",
        }
        issues = []
        for check in self.checks:
            if check.check_name in critical_check_names:
                issues.extend(check.issues)
        return issues

    @property
    def warnings(self) -> list[str]:
        """Issues that weaken but don't invalidate finding."""
        warning_check_names = {
            "confidence_justification",
            "alternative_explanations",
            "temporal_consistency",
        }
        warnings = []
        for check in self.checks:
            if check.check_name in warning_check_names:
                warnings.extend(check.issues)
        return warnings

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON output."""
        return {
            "finding_title": self.finding_title,
            "passed": self.passed,
            "critical_issues": self.critical_issues,
            "warnings": self.warnings,
            "checks": [
                {
                    "name": check.check_name,
                    "passed": check.passed,
                    "issues": check.issues,
                }
                for check in self.checks
            ],
            "validation_timestamp": self.validation_timestamp.isoformat(),
        }


class AdversarialValidator:
    """Systematically challenge CRITICAL findings to catch errors.

    Runs 6 validation checks on each CRITICAL finding:
    1. Evidence completeness
    2. Reasoning logic
    3. Confidence justification
    4. Alternative explanations
    5. Temporal consistency
    6. Hash format

    Usage:
        validator = AdversarialValidator()
        report = validator.validate(finding)
        if report.critical_issues:
            logger.warning(f"Finding failed: {report.critical_issues}")
    """

    def validate(self, finding) -> ValidationReport:
        """Run all validation checks on a finding.

        Args:
            finding: Finding object from engine

        Returns:
            ValidationReport with pass/fail and issues
        """
        checks = [
            self._check_evidence_completeness(finding),
            self._check_reasoning_logic(finding),
            self._check_confidence_justification(finding),
            self._check_alternative_explanations(finding),
            self._check_temporal_consistency(finding),
            self._check_hash_format(finding),
        ]

        return ValidationReport(
            finding_title=finding.title if hasattr(finding, "title") else str(finding),
            checks=checks,
        )

    def _check_evidence_completeness(self, finding) -> ValidationCheck:
        """Ensure all claims have supporting evidence."""
        issues = []

        # Get evidence dict
        evidence = {}
        if hasattr(finding, "evidence"):
            evidence = finding.evidence or {}

        # Get reasoning chain
        reasoning_text = ""
        if hasattr(finding, "reasoning_chain"):
            reasoning_text = " ".join(finding.reasoning_chain or [])

        # Check hash claims have full hashes
        if "hash" in reasoning_text.lower() or "sha-256" in reasoning_text.lower():
            hash_keys = [k for k in evidence.keys() if "sha256" in k.lower() or "hash" in k.lower()]
            if not hash_keys:
                issues.append("Reasoning mentions hash but evidence lacks hash field")

        # Check timestamp claims have timestamps
        if "saved at" in reasoning_text.lower() or "modified" in reasoning_text.lower():
            time_keys = [k for k in evidence.keys() if "time" in k.lower() or "modified" in k.lower()]
            if not time_keys:
                issues.append("Reasoning mentions timestamps but evidence lacks timestamp fields")

        # Check file path claims have file paths
        if "file" in reasoning_text.lower() and "path" in reasoning_text.lower():
            path_keys = [k for k in evidence.keys() if "path" in k.lower() or "file" in k.lower()]
            if not path_keys:
                issues.append("Reasoning mentions file path but evidence lacks path field")

        return ValidationCheck("evidence_completeness", issues)

    def _check_reasoning_logic(self, finding) -> ValidationCheck:
        """Identify logical fallacies or unsupported leaps."""
        issues = []

        # Get evidence
        evidence = {}
        if hasattr(finding, "evidence"):
            evidence = finding.evidence or {}

        # Check temporal causality for exfiltration claims
        category = getattr(finding, "category", None)
        if category and str(category) == "data_exfiltration":
            # For exfiltration, always check causality if we have both timestamps
            file_time_str = evidence.get("file_modified")
            email_time_str = evidence.get("email_sent")

            if file_time_str and email_time_str:
                try:
                    # Parse timestamps
                    file_time = datetime.fromisoformat(file_time_str.replace("Z", "+00:00"))
                    email_time = datetime.fromisoformat(email_time_str.replace("Z", "+00:00"))

                    if file_time >= email_time:
                        issues.append(
                            f"Causality violation: file modified {file_time_str} "
                            f"at or after email sent {email_time_str}"
                        )
                except (ValueError, AttributeError):
                    pass

        return ValidationCheck("reasoning_logic", issues)

    def _check_confidence_justification(self, finding) -> ValidationCheck:
        """Challenge confidence scores that may be overconfident."""
        issues = []

        confidence = getattr(finding, "confidence", 0.0)
        evidence = {}
        if hasattr(finding, "evidence"):
            evidence = finding.evidence or {}

        category = getattr(finding, "category", None)

        if category and str(category) == "data_exfiltration":
            # Check time delta alignment with graduated confidence
            time_delta = evidence.get("time_delta_seconds")

            if time_delta is not None:
                # Validate confidence matches time delta threshold
                if confidence >= 0.95 and time_delta > 60:
                    issues.append(
                        f"Confidence 0.95 with {time_delta}s delta may be too high. "
                        f"Time windows >60s suggest 0.90 more appropriate."
                    )
                elif confidence >= 0.90 and time_delta > 180:
                    issues.append(
                        f"Confidence 0.90 with {time_delta}s delta may be too high. "
                        f"Time windows >180s suggest 0.85 more appropriate."
                    )

        return ValidationCheck("confidence_justification", issues)

    def _check_alternative_explanations(self, finding) -> ValidationCheck:
        """Ensure competing hypotheses were considered."""
        issues = []

        category = getattr(finding, "category", None)
        evidence = {}
        if hasattr(finding, "evidence"):
            evidence = finding.evidence or {}

        if category and str(category) == "data_exfiltration":
            # Check if backup software possibility was addressed
            reasoning_text = ""
            if hasattr(finding, "reasoning_chain"):
                reasoning_text = " ".join(finding.reasoning_chain or []).lower()

            if "backup" not in reasoning_text and "sync" not in reasoning_text:
                # High time delta + no mention of backup = missed alternative
                time_delta = evidence.get("time_delta_seconds", 0)
                if time_delta > 120:
                    issues.append(
                        "Alternative explanation not addressed: automated backup "
                        "software could explain >2min delay. Consider mentioning why "
                        "this was ruled out."
                    )

        return ValidationCheck("alternative_explanations", issues)

    def _check_temporal_consistency(self, finding) -> ValidationCheck:
        """Verify timestamps are internally consistent."""
        issues = []

        evidence = {}
        if hasattr(finding, "evidence"):
            evidence = finding.evidence or {}

        # Collect all timestamp strings
        timestamps = []
        for key, value in evidence.items():
            if any(word in key.lower() for word in ["time", "modified", "created", "sent", "accessed"]):
                if isinstance(value, str):
                    try:
                        # Try to parse ISO format (handle both aware and naive)
                        value_cleaned = value.replace("Z", "+00:00")
                        dt = datetime.fromisoformat(value_cleaned)
                        timestamps.append((key, dt))
                    except (ValueError, AttributeError):
                        # If ISO parsing fails, try without timezone handling
                        try:
                            dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
                            timestamps.append((key, dt))
                        except (ValueError, AttributeError):
                            pass

        # Check timezone consistency
        if len(timestamps) >= 2:
            aware_status = [dt.tzinfo is not None for _, dt in timestamps]
            if not (all(aware_status) or not any(aware_status)):
                issues.append(
                    "Mixed timezone-aware and naive timestamps detected. "
                    "All timestamps should be consistently timezone-aware or naive."
                )

        return ValidationCheck("temporal_consistency", issues)

    def _check_hash_format(self, finding) -> ValidationCheck:
        """Validate cryptographic hash formats."""
        issues = []

        evidence = {}
        if hasattr(finding, "evidence"):
            evidence = finding.evidence or {}

        # Check all hash fields
        for key, value in evidence.items():
            if "sha256" in key.lower() or "sha-256" in key.lower():
                if not isinstance(value, str):
                    issues.append(f"{key} should be string, got {type(value).__name__}")
                    continue

                # SHA-256 must be exactly 64 hex characters
                if not re.match(r"^[a-f0-9]{64}$", value):
                    issues.append(
                        f"Invalid SHA-256 format in {key}: '{value}' "
                        f"(expected 64 lowercase hex characters)"
                    )

            elif "md5" in key.lower():
                if not isinstance(value, str):
                    issues.append(f"{key} should be string, got {type(value).__name__}")
                    continue

                # MD5 must be exactly 32 hex characters
                if not re.match(r"^[a-f0-9]{32}$", value):
                    issues.append(
                        f"Invalid MD5 format in {key}: '{value}' "
                        f"(expected 32 lowercase hex characters)"
                    )

        return ValidationCheck("hash_format", issues)
