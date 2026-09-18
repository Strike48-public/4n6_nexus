"""Misattribution guard: a real-but-wrong-finding anchor must be FALSIFIED.

SFE-fsno (verification 3->4). The blob-wide falsifier caught an anchor ABSENT
from all evidence, but was blind to the more common failure: a REAL-BUT-
MISATTRIBUTED anchor - a PID/IP that genuinely appears in the corpus, but in a
DIFFERENT finding's record. Because both live in the concatenated blob, the old
check passed it.

Per-finding provenance fixes this: each finding re-derives its anchors against
the SPECIFIC tool-output record that produced it (``evidence["source_span"]``),
not the whole-corpus blob.

The mutation guard is explicit here: ``_harden`` re-derives against per-finding
spans (the fix) and FALSIFIES the misattribution; ``_harden_blobwide`` re-derives
against the concatenated blob (the reverted behavior) and lets it SURVIVE. If a
future edit collapses the per-finding span back to the blob, the first assertion
goes green-when-it-should-be-red and this test fails.
"""

from __future__ import annotations

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.hardening import harden_findings

KEY = b"k" * 32
IMAGE = "a" * 64


def _mem_finding(pid: int, process: str, source_span: str) -> Finding:
    """A single-source memory finding asserting ``pid``, produced by source_span."""
    return Finding(
        title=f"Suspicious command line: PID {pid} ({process})",
        description=f"cmdline shows PID {pid} ({process})",
        finding_type="behavior",
        severity="medium",
        category=FindingCategory.PERSISTENCE,
        evidence={"pid": pid, "process": process, "source_span": source_span},
        confidence=0.6,
        reasoning_chain=[f"PID {pid} invoked {process}"],
        artifact_sources=["memory"],
    )


def _evidence_texts_per_finding(findings: list[Finding]) -> dict[str, str]:
    """Map each finding to ITS OWN provenance span (the fix)."""
    return {f.title: f.evidence["source_span"] for f in findings}


def _evidence_texts_blobwide(findings: list[Finding]) -> dict[str, str]:
    """Map every finding to the concatenated corpus blob (reverted behavior)."""
    blob = "\n".join(f.evidence["source_span"] for f in findings)
    return {f.title: blob for f in findings}


def _status(findings, evidence_texts, title):
    report = harden_findings(
        findings,
        image_sha256=IMAGE,
        receipt_key=KEY,
        evidence_texts=evidence_texts,
    )
    for item in report.hardened:
        if item["finding"]["title"] == title:
            return item["adversarial"]["falsifier_status"]
    raise AssertionError(f"no hardened finding titled {title!r}")


def _misattributed_case():
    """Finding A asserts PID 3120 but its OWN record is the PID-7412 record.

    3120 is real (finding B's record), so it exists in the corpus blob - the
    misattribution the old check could not see.
    """
    record_a = "cmdline: PID 7412 rootkit.exe"  # A's true producing record
    record_b = "cmdline: PID 3120 svchost.exe"  # B's record; contains 3120
    finding_a = _mem_finding(3120, "svchost.exe", source_span=record_a)
    finding_b = _mem_finding(7412, "rootkit.exe", source_span=record_b)
    # Give them distinct titles even though A's asserted pid clashes with B's.
    finding_a.title = "A: assert PID 3120 (misattributed)"
    finding_b.title = "B: assert PID 7412 (misattributed)"
    return finding_a, finding_b


def test_misattributed_anchor_is_falsified_by_per_finding_provenance() -> None:
    a, b = _misattributed_case()
    findings = [a, b]
    status = _status(findings, _evidence_texts_per_finding(findings), a.title)
    assert status == "falsified", (
        "per-finding provenance must FALSIFY a finding whose asserted PID is "
        "absent from its OWN producing record (even though the PID is real "
        "elsewhere in the corpus)"
    )


def test_blobwide_check_misses_the_misattribution_mutation_guard() -> None:
    # MUTATION GUARD: reverting to the whole-corpus blob lets the misattributed
    # anchor SURVIVE - the exact blind spot the fix closes. If per-finding
    # provenance ever collapses back to the blob, the test above flips to green
    # incorrectly; this test documents/locks the contrast.
    a, b = _misattributed_case()
    findings = [a, b]
    status = _status(findings, _evidence_texts_blobwide(findings), a.title)
    assert status == "survived", (
        "the reverted blob-wide behavior is expected to MISS the misattribution "
        "(PID 3120 appears in finding B's record within the blob)"
    )


def test_correctly_attributed_anchor_still_survives() -> None:
    # F1-safety at the unit level: a finding whose asserted PID IS in its own
    # record must still SURVIVE under per-finding provenance.
    f = _mem_finding(
        5580, "powershell.exe", source_span="cmdline: PID 5580 powershell.exe"
    )
    status = _status([f], _evidence_texts_per_finding([f]), f.title)
    assert status == "survived"


# --- end-to-end via the real detector (source_span emitted, not hand-built) ---


def _real_detector_findings():
    """Two real cmdline findings, each carrying the source_span it was built from."""
    from sift_find_evil.detectors.memory_detector import MemoryDetector
    from sift_find_evil.memory.volatility_runner import CommandLineRow

    rows = [
        CommandLineRow(
            pid=5580,
            process="powershell.exe",
            args="powershell.exe -WindowStyle Hidden -EncodedCommand ZQBjAGgAbwA=",
            raw_row={"PID": 5580, "Process": "powershell.exe", "Args": "hidden enc"},
        ),
        CommandLineRow(
            pid=7412,
            process="cmd.exe",
            args="cmd.exe /c whoami -NoProfile -enc ZQBjAGgAbwA=",
            raw_row={"PID": 7412, "Process": "cmd.exe", "Args": "enc"},
        ),
    ]
    findings = MemoryDetector().analyze(cmdline=rows)
    # Keep only the anchored (pid-bearing) cmdline findings.
    return [f for f in findings if f.evidence.get("pid") in (5580, 7412)]


def test_end_to_end_real_detector_span_catches_misattribution() -> None:
    # Build findings through the REAL detector so source_span is emitted by the
    # production code, then MISATTRIBUTE: rewrite finding-5580 to assert PID 7412
    # (which is real, but belongs to the OTHER record). Per-finding provenance
    # must FALSIFY it because 7412 is absent from finding-5580's own span.
    findings = _real_detector_findings()
    victim = next(f for f in findings if f.evidence["pid"] == 5580)
    assert victim.evidence.get("source_span"), "detector must emit source_span"
    # 7412 is not in the 5580 record's span -> misattribution.
    assert "7412" not in victim.evidence["source_span"]
    victim.evidence["pid"] = 7412  # assert a real-but-foreign anchor

    per_finding = _status(findings, _evidence_texts_per_finding(findings), victim.title)
    assert per_finding == "falsified"

    # Mutation guard: the blob (both records concatenated) DOES contain 7412, so
    # the reverted whole-corpus behavior would MISS it.
    blobwide = _status(findings, _evidence_texts_blobwide(findings), victim.title)
    assert blobwide == "survived"
