"""YaraDetector — turn YARA rule matches into Findings.

Bridges ``YaraScanner`` (the yara-python wrapper) to the case-agnostic
``Finding`` taxonomy. One Finding per (rule, file) hit, capped to the top-N
most confident matches per file so a noisy community ruleset cannot bury the
investigator in duplicates.

Confidence model
----------------
- Rule ``severity`` meta drives the base confidence:
  ``high = 0.90``, ``medium = 0.70``, ``low = 0.50``.
- Bonuses (additive, cap at 0.95):
  - ``+0.05`` if the rule carries a ``family`` meta field (named malware
    family is a stronger signal than a generic indicator-of-compromise).
  - ``+0.05`` if the rule carries an ``mitre_attack`` meta field (explicit
    technique mapping means the rule author believes the match maps to an
    active TTP, not an artifact).
- Missing severity defaults to ``medium`` — documented in tests so drift is
  caught rather than silently tolerated.

Evidence payload
----------------
Findings carry the full rule metadata plus match offsets so reviewers can pivot
straight to the bytes that fired the rule. Matching-string byte payloads are
truncated to a safe length to avoid ballooning JSON reports.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ..findings import FindingCategory
from ..findings import Finding
from ..yara_scan.scanner import DirectoryScanResult, YaraMatch, YaraScanner

# Severity → base confidence. Values tuned so HIGH fires the default 0.85
# confidence gate used elsewhere, MEDIUM sits just below, and LOW makes the
# reviewer actively accept the match instead of auto-escalating.
_SEVERITY_BASE_CONFIDENCE: dict[str, float] = {
    "high": 0.90,
    "medium": 0.70,
    "low": 0.50,
}

_DEFAULT_SEVERITY = "medium"
_CONFIDENCE_CAP = 0.95
_FAMILY_BONUS = 0.05
_MITRE_BONUS = 0.05

# Cap matching-string payload at this many bytes per instance so a 10MB rule
# hit does not inflate Finding.evidence into unshippable JSON.
_MAX_STRING_PREVIEW_BYTES = 64
# Cap the number of string instances captured per finding so a single
# noisy rule firing on a 100MB file with thousands of $a matches does
# not balloon the evidence dict into a megabyte of JSON. Reviewers can
# see the full count via evidence["match_count"] and pivot to the file.
_MAX_STRING_INSTANCES_PER_FINDING = 50
_DEFAULT_MAX_FINDINGS_PER_FILE = 10

# Cap the number of skipped-file paths embedded in the ANALYSIS_GAP finding's
# evidence. On a real disk image thousands of files can be unreadable/oversized;
# the exact COUNT is always reported, but only a bounded sample of paths is
# carried so the finding's JSON stays shippable (same spirit as the per-finding
# string-instance cap above).
_MAX_SKIP_SAMPLE = 50


class YaraDetector:
    """Convert YARA scanner matches into MALWARE_CLASSIFICATION findings.

    The detector never touches yara-python directly; it consumes the immutable
    ``YaraMatch`` / ``YaraString`` dataclasses produced by ``YaraScanner``.
    That boundary lets us swap the underlying scanner (yara-x, libyara-rs)
    without rewriting confidence logic.
    """

    def __init__(
        self,
        *,
        scanner: YaraScanner,
        max_findings_per_file: int = _DEFAULT_MAX_FINDINGS_PER_FILE,
        min_confidence: float = 0.0,
    ):
        if max_findings_per_file <= 0:
            raise ValueError("max_findings_per_file must be positive")
        if not 0.0 <= min_confidence <= 1.0:
            raise ValueError("min_confidence must be between 0.0 and 1.0")
        self._scanner = scanner
        self._max_findings_per_file = max_findings_per_file
        # Opt-in quality floor: drop matches below this confidence. Defaults to
        # 0.0 (no floor) so existing callers and scenarios are unaffected. Lets
        # a deployment suppress broad, low-severity community-rule hits without
        # rewriting confidence logic. (SFE-box)
        self._min_confidence = min_confidence

    def analyze_file(self, target: Path) -> list[Finding]:
        """Scan one file and return its findings (highest-confidence first)."""
        matches = self._scanner.scan_file(target)
        return self._rank_and_cap(self._match_to_finding(m) for m in matches)

    def analyze_directory(
        self,
        root: Path,
        *,
        recursive: bool = True,
    ) -> list[Finding]:
        """Scan every file under ``root`` and flatten findings across files.

        Each file is independently capped at ``max_findings_per_file`` so one
        noisy file cannot crowd out hits in other files. The returned list is
        not sorted across files — callers that care about global ranking can
        re-sort by confidence.

        When the underlying scan skipped any file — unreadable (OSError on real
        evidence: locked SQLite, corrupt clusters, permission denied) or
        oversized (exceeds ``max_file_size``) — a single ANALYSIS_GAP
        diagnostic Finding is appended so an empty match set is never mistaken
        for "directory clean". This mirrors the memory detector's list-walk
        gap: the skip signal appears IN the findings output rather than only in
        WARNING logs, which are fragile (rotation, ``/dev/null`` in pipelines)
        and absent from a structured scan report (SFE-fuk).
        """
        result = self._scanner.scan_directory_details(root, recursive=recursive)
        findings: list[Finding] = []
        for _path, matches in result.matches.items():
            if not matches:
                continue
            findings.extend(
                self._rank_and_cap(self._match_to_finding(m) for m in matches)
            )
        gap = self._skip_gap_finding(root, result)
        if gap is not None:
            findings.append(gap)
        return findings

    def _skip_gap_finding(
        self, root: Path, result: DirectoryScanResult
    ) -> Finding | None:
        """Build one ANALYSIS_GAP Finding when files were skipped, else None.

        The exact skip counts are always reported; the embedded path lists are
        capped at ``_MAX_SKIP_SAMPLE`` so the evidence stays shippable on real
        images that can skip thousands of files.
        """
        oversized = result.oversized
        unreadable = result.unreadable
        skipped = len(oversized) + len(unreadable)
        if skipped == 0:
            return None

        oversized_sample = [str(p) for p in oversized[:_MAX_SKIP_SAMPLE]]
        unreadable_sample = [str(p) for p in unreadable[:_MAX_SKIP_SAMPLE]]
        truncated = (
            len(oversized) > _MAX_SKIP_SAMPLE or len(unreadable) > _MAX_SKIP_SAMPLE
        )

        reasons: list[str] = []
        if unreadable:
            reasons.append(
                f"{len(unreadable)} unreadable (I/O error, permission, or "
                "corrupt cluster)"
            )
        if oversized:
            reasons.append(f"{len(oversized)} exceeded the per-file size cap")

        return Finding(
            title=(
                f"YARA scan coverage gap: {skipped} file(s) under "
                f"{root.name or root} were not scanned"
            ),
            description=(
                f"{skipped} file(s) were skipped during the directory scan "
                f"({'; '.join(reasons)}) and therefore never matched against "
                "the ruleset. An empty or partial match set for this directory "
                "must NOT be read as 'no malware present' — the skipped files "
                "were not examined at all. Re-scan the skipped paths "
                "individually (raising max_file_size for oversized blobs, or "
                "resolving the I/O/permission error for unreadable ones) before "
                "concluding the directory is clean."
            ),
            finding_type="diagnostic",
            severity="info",
            category=FindingCategory.ANALYSIS_GAP,
            evidence={
                "scan_root": str(root),
                "skipped_count": skipped,
                "oversized_count": len(oversized),
                "unreadable_count": len(unreadable),
                "oversized_sample": oversized_sample,
                "unreadable_sample": unreadable_sample,
                "sample_truncated": truncated,
            },
            confidence=0.90,
            confidence_label="High",
            reasoning_chain=[
                f"Directory scan of {root} skipped {skipped} file(s): "
                + "; ".join(reasons)
                + ".",
                "Skipped files were never scanned, so their contents are "
                "unknown — not confirmed benign.",
                "This is an evidence-reliability gap, not attacker behavior: it "
                "bounds what the scan observed so an empty match set is not "
                "mistaken for a clean directory.",
            ],
            artifact_sources=["yara"],
        )

    def _rank_and_cap(self, findings_iter: Iterable[Finding]) -> list[Finding]:
        floored = (f for f in findings_iter if f.confidence >= self._min_confidence)
        ranked = sorted(floored, key=lambda f: f.confidence, reverse=True)
        return ranked[: self._max_findings_per_file]

    def _match_to_finding(self, match: YaraMatch) -> Finding:
        severity = _severity_from_meta(match.meta)
        base = _SEVERITY_BASE_CONFIDENCE[severity]
        bonuses = _confidence_bonuses(match.meta)
        confidence = min(_CONFIDENCE_CAP, base + bonuses)

        strings_to_capture = match.strings[:_MAX_STRING_INSTANCES_PER_FINDING]
        matching_strings = [
            {
                "identifier": s.identifier,
                "offset": s.offset,
                "preview_hex": s.data[:_MAX_STRING_PREVIEW_BYTES].hex(),
                "preview_len": min(len(s.data), _MAX_STRING_PREVIEW_BYTES),
                "truncated": len(s.data) > _MAX_STRING_PREVIEW_BYTES,
            }
            for s in strings_to_capture
        ]

        mitre = match.meta.get("mitre_attack")
        mitre_list = (
            [mitre] if isinstance(mitre, str) else (list(mitre) if mitre else [])
        )

        description = match.meta.get("description", f"YARA rule {match.rule} matched.")
        family = match.meta.get("family")

        return Finding(
            title=f"YARA match: {match.rule} on {match.source_file.name}",
            description=(
                f"{description} File: {match.source_file}. "
                f"Rule severity: {severity}."
                + (f" Family: {family}." if family else "")
            ),
            finding_type="indicator",
            severity=severity,
            category=FindingCategory.MALWARE_CLASSIFICATION,
            evidence={
                "rule": match.rule,
                "namespace": match.namespace,
                "source_file": str(match.source_file),
                "rule_meta": dict(match.meta),
                "tags": list(match.tags),
                "mitre_attack": mitre_list,
                "family": family,
                "matching_strings": matching_strings,
                "match_count": len(match.strings),
                "instances_captured": len(matching_strings),
                "instances_truncated": (
                    len(match.strings) > _MAX_STRING_INSTANCES_PER_FINDING
                ),
            },
            confidence=confidence,
            confidence_label=_confidence_label(confidence),
            reasoning_chain=[
                f"Rule '{match.rule}' fired on {match.source_file.name}.",
                f"Rule severity meta = '{severity}' → base confidence {base:.2f}.",
            ]
            + (
                [
                    f"Confidence bonuses applied: +{bonuses:.2f} "
                    f"(capped at {_CONFIDENCE_CAP})."
                ]
                if bonuses > 0
                else []
            ),
            artifact_sources=["yara"],
        )


def _severity_from_meta(meta: dict) -> str:
    raw = meta.get("severity")
    if not isinstance(raw, str):
        return _DEFAULT_SEVERITY
    lowered = raw.strip().lower()
    if lowered in _SEVERITY_BASE_CONFIDENCE:
        return lowered
    return _DEFAULT_SEVERITY


def _confidence_bonuses(meta: dict) -> float:
    bonus = 0.0
    if meta.get("family"):
        bonus += _FAMILY_BONUS
    if meta.get("mitre_attack"):
        bonus += _MITRE_BONUS
    return bonus


def _confidence_label(confidence: float) -> str:
    if confidence >= 0.85:
        return "High"
    if confidence >= 0.60:
        return "Medium"
    return "Low"


__all__ = ["YaraDetector"]
