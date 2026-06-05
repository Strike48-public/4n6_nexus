"""Report generator for forensic investigations."""

import json
from datetime import datetime
from pathlib import Path

from ..approval import ApprovalManager, ApprovalStatus
from ..case import CaseManager
from .models import Report, ReportFormat


class ReportGenerator:
    """Generate investigation reports in multiple formats."""

    def __init__(self, case_manager: CaseManager):
        """Initialize report generator.

        Args:
            case_manager: CaseManager instance
        """
        self.case_manager = case_manager

    def generate(
        self,
        case_id: str,
        output_path: Path,
        format: ReportFormat = ReportFormat.MARKDOWN,
        approved_only: bool = True,
    ) -> None:
        """Generate investigation report.

        Args:
            case_id: Case identifier
            output_path: Path to write report
            format: Report format (MARKDOWN, HTML, PDF)
            approved_only: Only include approved findings
        """
        # Load case
        case = self.case_manager.load_case(case_id)
        case_dir = self.case_manager.case_root / case_id

        # Load evidence
        evidence_path = case_dir / "evidence.json"
        evidence = []
        if evidence_path.exists():
            with open(evidence_path, "r") as f:
                evidence = json.load(f).get("evidence", [])

        # Load findings
        findings_path = case_dir / "findings.json"
        findings = []
        if findings_path.exists():
            approval_manager = ApprovalManager(findings_path)
            all_findings = approval_manager.load_findings()

            if approved_only:
                findings = [
                    f for f in all_findings if f.status == ApprovalStatus.APPROVED
                ]
            else:
                findings = all_findings

        # Extract IOCs
        iocs = self._extract_iocs(findings)

        # Build report
        report = Report(
            case_id=case.case_id,
            case_name=case.name,
            examiner=case.examiner,
            created_at=datetime.utcnow(),
            findings=[f.to_dict() for f in findings],
            evidence=evidence,
            iocs=iocs,
            executive_summary=self._generate_executive_summary(findings),
            recommendations=self._generate_recommendations(findings),
            case_description=case.description,
        )

        # Generate report in requested format
        if format == ReportFormat.MARKDOWN:
            content = self._generate_markdown(report, case)
        elif format == ReportFormat.HTML:
            content = self._generate_html(report, case)
        elif format == ReportFormat.PDF:
            raise NotImplementedError("PDF generation not yet implemented")
        else:
            raise ValueError(f"Unsupported format: {format}")

        # Write report
        with open(output_path, "w") as f:
            f.write(content)

    def _extract_iocs(self, findings) -> dict:
        """Extract IOCs from findings.

        Args:
            findings: List of FindingWithApproval objects

        Returns:
            Dictionary with IOC lists (ips, domains, file_hashes, processes)
        """
        iocs = {
            "ips": set(),
            "domains": set(),
            "file_hashes": set(),
            "processes": set(),
        }

        for finding in findings:
            evidence = finding.finding.get("evidence", {})

            # Extract IPs
            if "ip" in evidence:
                iocs["ips"].add(evidence["ip"])
            if "ips" in evidence:
                iocs["ips"].update(evidence["ips"])

            # Extract domains
            if "domain" in evidence:
                iocs["domains"].add(evidence["domain"])
            if "domains" in evidence:
                iocs["domains"].update(evidence["domains"])

            # Extract file hashes
            if "sha256" in evidence:
                iocs["file_hashes"].add(evidence["sha256"])
            if "md5" in evidence:
                iocs["file_hashes"].add(evidence["md5"])
            if "hashes" in evidence:
                iocs["file_hashes"].update(evidence["hashes"])

            # Extract processes
            if "process" in evidence:
                iocs["processes"].add(evidence["process"])
            if "processes" in evidence:
                iocs["processes"].update(evidence["processes"])

        # Convert sets to sorted lists
        return {
            "ips": sorted(iocs["ips"]),
            "domains": sorted(iocs["domains"]),
            "file_hashes": sorted(iocs["file_hashes"]),
            "processes": sorted(iocs["processes"]),
        }

    def _generate_executive_summary(self, findings) -> str:
        """Generate executive summary.

        Args:
            findings: List of FindingWithApproval objects

        Returns:
            Executive summary text
        """
        if not findings:
            return "No suspicious findings detected. All artifacts are consistent with expected behavior."

        total = len(findings)
        critical = sum(1 for f in findings if f.finding.get("severity") == "critical")
        high = sum(1 for f in findings if f.finding.get("severity") == "high")
        medium = sum(1 for f in findings if f.finding.get("severity") == "medium")

        summary = f"Detected {total} suspicious finding(s) during analysis. "

        if critical:
            summary += f"{critical} CRITICAL, "
        if high:
            summary += f"{high} HIGH, "
        if medium:
            summary += f"{medium} MEDIUM severity. "

        summary += (
            "All findings have been reviewed and approved for inclusion in this report."
        )

        return summary

    def _generate_recommendations(self, findings) -> list[str]:
        """Generate recommendations based on findings.

        Args:
            findings: List of FindingWithApproval objects

        Returns:
            List of recommendation strings
        """
        recommendations = []

        critical_count = sum(
            1 for f in findings if f.finding.get("severity") == "critical"
        )
        if critical_count > 0:
            recommendations.append(
                "Immediate incident response: Isolate affected systems and contain threat."
            )
            recommendations.append(
                "Conduct comprehensive forensic analysis of all systems."
            )

        high_count = sum(1 for f in findings if f.finding.get("severity") == "high")
        if high_count > 0:
            recommendations.append(
                "Review and harden security controls to prevent recurrence."
            )
            recommendations.append("Implement enhanced monitoring for detected IOCs.")

        if not findings:
            recommendations.append(
                "Continue monitoring systems for suspicious activity."
            )
            recommendations.append("Review and update detection rules periodically.")

        return recommendations

    def _generate_markdown(self, report: Report, case) -> str:
        """Generate Markdown report.

        Args:
            report: Report object
            case: Case object

        Returns:
            Markdown report content
        """
        lines = []

        # Header
        lines.append("# Forensic Investigation Report")
        lines.append(f"## Case: {report.case_name}")
        lines.append("")

        # Case metadata
        lines.append("## Case Metadata")
        lines.append("")
        lines.append(f"- **Case ID:** {report.case_id}")
        lines.append(f"- **Examiner:** {report.examiner}")
        lines.append(f"- **Created:** {case.created_at.isoformat()}")
        lines.append(f"- **Report Generated:** {report.created_at.isoformat()}")
        lines.append(f"- **Status:** {case.status.value}")
        if report.case_description:
            lines.append(f"- **Description:** {report.case_description}")
        lines.append("")

        # Executive summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(report.executive_summary or "No summary available.")
        lines.append("")

        # Visual summary (Mermaid — GitHub renders these natively)
        visual = self._visual_summary(report, case)
        if visual:
            lines.append(visual)
            lines.append("")

        # Evidence summary
        lines.append("## Evidence Summary")
        lines.append("")
        if report.evidence:
            lines.append(f"Total evidence files: {len(report.evidence)}")
            lines.append("")
            lines.append("| File | SHA-256 Hash | Size |")
            lines.append("|------|--------------|------|")
            for item in report.evidence:
                file_path = item.get("file_path", "Unknown")
                sha256 = item.get("sha256_hash", "N/A")[:16] + "..."
                size = item.get("file_size", 0)
                size_mb = size / (1024 * 1024) if size else 0
                lines.append(
                    f"| {Path(file_path).name} | {sha256} | {size_mb:.2f} MB |"
                )
            lines.append("")
        else:
            lines.append("No evidence files registered.")
            lines.append("")

        # Findings
        lines.append("## Findings")
        lines.append("")
        if report.findings:
            lines.append(
                f"Total findings: {len(report.findings)} (approved only, sorted by severity)"
            )
            lines.append("")

            # Group by severity
            for severity in ["critical", "high", "medium", "low"]:
                severity_findings = [
                    f
                    for f in report.findings
                    if f.get("finding", {}).get("severity") == severity
                ]
                if not severity_findings:
                    continue

                lines.append(
                    f"### {severity.upper()} Severity ({len(severity_findings)})"
                )
                lines.append("")

                for idx, item in enumerate(severity_findings, 1):
                    finding = item.get("finding", {})
                    finding_id = item.get("finding_id", "Unknown")
                    title = finding.get("title", "Unknown")
                    description = finding.get(
                        "description", "No description available."
                    )
                    confidence = finding.get("confidence", 0.0)

                    lines.append(f"#### [{finding_id}] {title}")
                    lines.append("")
                    lines.append(f"**Confidence:** {confidence:.2f}")
                    lines.append("")
                    lines.append(description)
                    lines.append("")
        else:
            lines.append("No findings to report.")
            lines.append("")

        # IOC summary
        lines.append("## Indicators of Compromise (IOCs)")
        lines.append("")
        if any(report.iocs.values()):
            if report.iocs["ips"]:
                lines.append(f"### IP Addresses ({len(report.iocs['ips'])})")
                lines.append("")
                for ip in report.iocs["ips"]:
                    lines.append(f"- {ip}")
                lines.append("")

            if report.iocs["domains"]:
                lines.append(f"### Domains ({len(report.iocs['domains'])})")
                lines.append("")
                for domain in report.iocs["domains"]:
                    lines.append(f"- {domain}")
                lines.append("")

            if report.iocs["file_hashes"]:
                lines.append(f"### File Hashes ({len(report.iocs['file_hashes'])})")
                lines.append("")
                for hash_val in report.iocs["file_hashes"]:
                    lines.append(f"- {hash_val}")
                lines.append("")

            if report.iocs["processes"]:
                lines.append(f"### Processes ({len(report.iocs['processes'])})")
                lines.append("")
                for process in report.iocs["processes"]:
                    lines.append(f"- {process}")
                lines.append("")
        else:
            lines.append("No IOCs extracted from findings.")
            lines.append("")

        # Recommendations
        lines.append("## Recommendations")
        lines.append("")
        if report.recommendations:
            for idx, rec in enumerate(report.recommendations, 1):
                lines.append(f"{idx}. {rec}")
            lines.append("")
        else:
            lines.append("No recommendations available.")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append(
            f"*This report was generated automatically by SIFT Find Evil on {report.created_at.isoformat()}*"
        )

        return "\n".join(lines)

    def _visual_summary(self, report: Report, case) -> str:
        """Build the Mermaid 'Visual Summary' section, or '' if nothing to show.

        Two diagrams: a finding flow (from report.findings) and, when the case
        has an audit log, an A2A sequence diagram reconstructed from it. Failures
        to read/parse the audit log degrade gracefully to just the finding flow —
        a report must never fail to generate because a diagram couldn't be built.
        """
        from .mermaid import mermaid_a2a_sequence, mermaid_finding_flow

        blocks: list[str] = []

        if report.findings:
            # Reduce the approval-shaped finding dicts to the flat rows the
            # diagram expects (id, label, verdict, confidence transition).
            rows = [self._finding_flow_row(item) for item in report.findings]
            blocks.append("### Findings and verifier verdicts")
            blocks.append("")
            blocks.append(mermaid_finding_flow(rows))

        a2a = self._read_audit_entries(case)
        if a2a:
            blocks.append("")
            blocks.append("### Agent-to-agent investigation flow")
            blocks.append("")
            blocks.append(mermaid_a2a_sequence(a2a))

        if not blocks:
            return ""
        return "## Visual Summary\n\n" + "\n".join(blocks)

    @staticmethod
    def _finding_flow_row(item: dict) -> dict:
        """Flatten an approval-shaped finding dict into a diagram row."""
        finding = item.get("finding", {}) if "finding" in item else item
        return {
            "finding_id": item.get("finding_id") or finding.get("finding_id"),
            "label": finding.get("title") or item.get("label"),
            "verdict": finding.get("verdict") or item.get("verdict") or "reported",
            "confidence_before": item.get("confidence_before"),
            "confidence_after": item.get("confidence_after"),
            "confidence": finding.get("confidence"),
        }

    def _read_audit_entries(self, case) -> list[dict]:
        """Best-effort load of the case's A2A audit log (empty list on any issue)."""
        try:
            audit_path = self.case_manager.case_root / case.case_id / "audit.jsonl"
            if not audit_path.is_file():
                return []
            entries = []
            for line in audit_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
            return entries
        except (OSError, ValueError):
            return []

    def _generate_html(self, report: Report, case) -> str:
        """Generate HTML report.

        Args:
            report: Report object
            case: Case object

        Returns:
            HTML report content
        """
        # Simple HTML wrapper around Markdown content
        markdown_content = self._generate_markdown(report, case)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{report.case_name} - Forensic Investigation Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 900px;
            margin: 50px auto;
            padding: 20px;
            line-height: 1.6;
        }}
        h1, h2, h3, h4 {{
            color: #333;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        code {{
            background-color: #f4f4f4;
            padding: 2px 4px;
            border-radius: 3px;
        }}
        pre {{
            background-color: #f4f4f4;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
"""

        # Convert Markdown tables to HTML
        for line in markdown_content.split("\n"):
            if line.startswith("|"):
                # Simple table row conversion
                html += f"    {line}\n"
            elif line.startswith("#"):
                # Headers
                level = line.count("#", 0, 6)
                text = line.lstrip("#").strip()
                html += f"    <h{level}>{text}</h{level}>\n"
            elif line.strip():
                html += f"    <p>{line}</p>\n"
            else:
                html += "\n"

        html += """</body>
</html>
"""
        return html
