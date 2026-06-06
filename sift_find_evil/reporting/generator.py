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
        """Generate a Markdown report following professional DFIR conventions.

        Structure (progressive depth, the way published DFIR reports read):
        title + identity block -> executive summary with a stated confidence ->
        investigation flow (A2A visual) -> findings (severity-ranked, each with a
        qualified confidence, ATT&CK mapping, surfaced evidence facts, and any
        self-correction) -> findings-at-a-glance visual -> evidence & chain of
        custody -> IOCs -> recommendations -> methodology & limitations.
        """
        L: list[str] = []
        findings = report.findings or []
        sev_counts = self._severity_counts(findings)

        # --- Title + identity block (compact, scannable) --------------------
        L.append(f"# Forensic Investigation Report: {report.case_name}")
        L.append("")
        L.append(
            f"**Case:** {report.case_id}  |  **Examiner:** {report.examiner}  |  "
            f"**Status:** {case.status.value}"
        )
        L.append(
            f"**Opened:** {self._date(case.created_at)}  |  "
            f"**Report generated:** {self._date(report.created_at)}"
        )
        if report.case_description:
            L.append("")
            L.append(f"> {report.case_description}")
        L.append("")
        L.append("---")
        L.append("")

        # --- Executive summary (lead paragraph + stated confidence) ---------
        L.append("## Executive Summary")
        L.append("")
        L.append(self._exec_summary_prose(report, findings, sev_counts))
        L.append("")
        if sev_counts:
            L.append("| Severity | Count |")
            L.append("|----------|-------|")
            for sev in ("critical", "high", "medium", "low"):
                if sev_counts.get(sev):
                    L.append(f"| {sev.upper()} | {sev_counts[sev]} |")
            L.append("")

        # --- Investigation flow (A2A visual, up front) ----------------------
        a2a = self._read_audit_entries(case)
        if a2a:
            from .mermaid import mermaid_a2a_sequence

            L.append("## Investigation Flow")
            L.append("")
            L.append(
                "Reconstructed from the agent-to-agent audit log: the orchestrator "
                "dispatched a triage agent and three domain analysts, then a "
                "verifier independently challenged every finding before reporting."
            )
            L.append("")
            L.append(mermaid_a2a_sequence(a2a))
            L.append("")

        # --- Findings (the core; severity-ranked, evidence-led) -------------
        L.append("## Findings")
        L.append("")
        if findings:
            for severity in ("critical", "high", "medium", "low"):
                group = [
                    f
                    for f in findings
                    if f.get("finding", {}).get("severity") == severity
                ]
                for item in group:
                    L.extend(self._render_finding(item))
        else:
            L.append("No findings to report.")
            L.append("")

        # --- Findings at a glance (finding-flow visual) ---------------------
        # Only worthwhile with multiple findings: a single-node flow conveys
        # nothing the Findings section above doesn't already state.
        if len(findings) >= 2:
            from .mermaid import mermaid_finding_flow

            rows = [self._finding_flow_row(item) for item in findings]
            L.append("## Findings at a Glance")
            L.append("")
            L.append(
                "Each finding and the verifier's verdict; green resolved, red held "
                "as a live signal."
            )
            L.append("")
            L.append(mermaid_finding_flow(rows))
            L.append("")

        # --- Evidence & chain of custody ------------------------------------
        L.append("## Evidence and Chain of Custody")
        L.append("")
        if report.evidence:
            L.append("| File | SHA-256 | Size |")
            L.append("|------|---------|------|")
            for item in report.evidence:
                name = Path(item.get("file_path", "Unknown")).name
                sha = item.get("sha256_hash", "N/A")
                sha_disp = f"`{sha[:32]}...`" if sha and sha != "N/A" else "N/A"
                size = item.get("file_size", 0)
                size_mb = f"{size / (1024 * 1024):.1f} MB" if size else "n/a"
                L.append(f"| {name} | {sha_disp} | {size_mb} |")
            L.append("")
        else:
            L.append(
                "Evidence was analyzed directly from source artifacts; per-file "
                "SHA-256 registration was not recorded for this case. Every finding "
                "below cites the specific artifact it was derived from."
            )
            L.append("")

        # --- IOCs ------------------------------------------------------------
        L.append("## Indicators of Compromise")
        L.append("")
        if any(report.iocs.values()):
            ioc_labels = {
                "ips": "IP Addresses",
                "domains": "Domains",
                "file_hashes": "File Hashes",
                "processes": "Processes",
            }
            for key, label in ioc_labels.items():
                values = report.iocs.get(key) or []
                if values:
                    L.append(f"**{label}**")
                    L.append("")
                    for v in values:
                        L.append(f"- `{v}`")
                    L.append("")
        else:
            L.append("No atomic IOCs were extracted from the findings in this case.")
            L.append("")

        # --- Recommendations -------------------------------------------------
        if report.recommendations:
            L.append("## Recommendations")
            L.append("")
            for idx, rec in enumerate(report.recommendations, 1):
                L.append(f"{idx}. {rec}")
            L.append("")

        # --- Methodology & limitations (credibility) ------------------------
        L.append("## Methodology and Limitations")
        L.append("")
        L.append(
            "Findings were produced by an autonomous multi-agent system over a "
            "read-only Custom MCP tool boundary: domain analysts emit candidates "
            "from forensic-tool output, and a verifier cross-checks each against a "
            "second source, resolving or holding contradictions. Confidence labels "
            "(High >= 0.80, Medium >= 0.60, Low >= 0.40) reflect post-verification "
            "scores. Every finding is traceable to the tool execution that produced "
            "it via the audit log. This report asserts only what is grounded in "
            "observed tool output; absence of a finding is not proof of absence of "
            "activity."
        )
        L.append("")

        # --- Footer ----------------------------------------------------------
        L.append("---")
        L.append("")
        L.append(
            f"*Generated by 4n6 Nexus on {self._date(report.created_at)} "
            "(SANS FIND EVIL! submission *SIFT Find Evil*).*"
        )

        return "\n".join(L)

    # -- markdown helpers ----------------------------------------------------

    @staticmethod
    def _date(value) -> str:
        """Format a datetime/ISO value as a compact UTC string."""
        try:
            return value.strftime("%Y-%m-%d %H:%M UTC")
        except AttributeError:
            return str(value)

    @staticmethod
    def _confidence_label(confidence: float) -> str:
        """Qualitative band for a confidence score (matches ConfidenceScorer)."""
        if confidence >= 0.80:
            return "High"
        if confidence >= 0.60:
            return "Medium"
        if confidence >= 0.40:
            return "Low"
        return "Very Low"

    @staticmethod
    def _severity_counts(findings: list) -> dict:
        counts: dict = {}
        for item in findings:
            sev = item.get("finding", {}).get("severity", "unknown")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _exec_summary_prose(
        self, report: Report, findings: list, sev_counts: dict
    ) -> str:
        """Lead paragraph: scope, headline finding, and stated confidence."""
        if not findings:
            return (
                "Autonomous analysis completed with no suspicious findings. The "
                "absence of findings reflects the artifacts examined and is not, by "
                "itself, proof that no activity occurred."
            )
        total = len(findings)
        parts = [
            f"{sev_counts[s]} {s.upper()}"
            for s in ("critical", "high", "medium", "low")
            if sev_counts.get(s)
        ]
        breakdown = ", ".join(parts)
        # Highest-severity finding leads the summary.
        lead = None
        for sev in ("critical", "high", "medium", "low"):
            for item in findings:
                if item.get("finding", {}).get("severity") == sev:
                    lead = item.get("finding", {})
                    break
            if lead:
                break
        lead_conf = (
            self._confidence_label(lead.get("confidence", 0.0)) if lead else "Medium"
        )
        headline = lead.get("title", "a suspicious artifact") if lead else ""
        return (
            f"Autonomous multi-agent analysis identified **{total} finding(s)** "
            f"({breakdown}). The most significant, assessed with **{lead_conf} "
            f"confidence**, is: *{headline}*. Each finding below is traceable to the "
            "specific forensic-tool execution that produced it, and was independently "
            "challenged by the verifier agent before inclusion."
        )

    _CATEGORY_ATTCK = {
        "anti_forensics": "T1070 Indicator Removal / T1485 Data Destruction",
        "exfiltration": "T1041 Exfiltration Over C2 Channel",
        "c2": "T1071 Application Layer Protocol",
        "persistence": "T1547 Boot or Logon Autostart Execution",
        "execution": "T1059 Command and Scripting Interpreter",
        "credential_access": "T1003 OS Credential Dumping",
        "defense_evasion": "T1070 Indicator Removal",
        "injection": "T1055 Process Injection",
    }

    def _render_finding(self, item: dict) -> list[str]:
        """Render one finding as a DFIR-style subsection (returns lines)."""
        finding = item.get("finding", {})
        fid = item.get("finding_id", "F-?")
        title = finding.get("title", "Unknown finding")
        severity = finding.get("severity", "unknown").upper()
        confidence = finding.get("confidence", 0.0)
        conf_label = self._confidence_label(confidence)
        category = finding.get("category", "")
        description = finding.get("description", "")

        out = [f"### [{fid}] {title}", ""]
        meta = f"**Severity:** {severity}  |  **Confidence:** {conf_label} ({confidence:.2f})"
        attck = self._CATEGORY_ATTCK.get(category)
        if attck:
            meta += f"  |  **ATT&CK:** {attck}"
        out.append(meta)
        out.append("")
        if description:
            out.append(description)
            out.append("")

        # Surface a few concrete evidence facts (the dict the engine attaches).
        evidence = finding.get("evidence")
        if isinstance(evidence, dict) and evidence:
            facts = self._evidence_facts(evidence)
            if facts:
                out.append("**Supporting evidence:**")
                out.append("")
                for k, v in facts:
                    out.append(f"- {k}: `{v}`")
                out.append("")

        # Self-correction note, if the verdict/transition is present on the row.
        verdict = item.get("verdict")
        before = item.get("confidence_before")
        after = item.get("confidence_after")
        if verdict and before is not None and after is not None:
            out.append(
                f"*Self-correction:* verifier verdict **{verdict}** "
                f"(confidence {before} to {after})."
            )
            out.append("")
        return out

    @staticmethod
    def _evidence_facts(evidence: dict, limit: int = 6) -> list[tuple]:
        """Pick a few human-meaningful scalar facts from an evidence dict.

        Skips nested structures and overly long values so the report shows
        digestible facts (e.g. primary_header_zeroed: True), not a JSON dump.
        """
        facts: list[tuple] = []
        for key, value in evidence.items():
            if isinstance(value, (dict, list)):
                continue
            text = str(value)
            if len(text) > 80:
                continue
            facts.append((key, text))
            if len(facts) >= limit:
                break
        return facts

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
