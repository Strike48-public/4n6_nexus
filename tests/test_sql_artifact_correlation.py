"""SFE-fx8o: DuckDB entity-keyed cross-artifact correlation.

The two existing correlators do NOT express "one canonical entity corroborated
by N distinct artifact sources":

  - ``sql_timeline.py`` is memory-only (only ``memory_detector`` emits ``timeline``
    rows) and does a pairwise time-window self-join on a string ``actor``.
  - ``cross_source.py`` detects ABSENCE (ghost/phantom/uninstalled) - the opposite
    polarity from corroboration.

This layer loads canonicalized findings into DuckDB keyed on ``canonical_entity``
(the SFE-1fkn join key) and surfaces entities evidenced by >=2 distinct artifact
sources - e.g. a process whose image appears in memory AND has a timestomped MFT
record AND an outbound C2 flow. It is additive HardeningReport metadata: it never
adds, drops, or reweights a finding, so F1 is provably unaffected.

DuckDB is an OPTIONAL dependency: absent it, the layer no-ops (returns []), so the
zero-dep install path stays green. CI installs duckdb so the real path is
exercised, not silently skipped.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import sift_find_evil.correlation.sql_artifact as sa
from sift_find_evil.correlation.sql_artifact import (
    ArtifactCorroboration,
    correlate_artifacts,
)
from sift_find_evil.findings import Finding, FindingCategory

_REPO_ROOT = Path(__file__).resolve().parent.parent

duckdb = pytest.importorskip("duckdb")


def _finding(
    title: str,
    *,
    evidence: dict,
    sources: list[str],
    category: FindingCategory = FindingCategory.EXECUTION,
) -> Finding:
    return Finding(
        title=title,
        description="d",
        finding_type="behavior",
        severity="high",
        category=category,
        evidence=evidence,
        artifact_sources=list(sources),
    )


# --- core capability: N-way entity join across artifact sources ------------


def test_same_entity_across_two_sources_is_corroborated() -> None:
    findings = [
        _finding("mft", evidence={"executable": "evil.exe"}, sources=["MFT"]),
        _finding("mem", evidence={"process": "evil.exe"}, sources=["memory"]),
    ]
    result = correlate_artifacts(findings)
    assert len(result) == 1
    corr = result[0]
    assert isinstance(corr, ArtifactCorroboration)
    assert corr.entity_kind == "process"
    assert corr.entity_value == "evil.exe"
    assert corr.sources == ("MFT", "memory")
    assert corr.source_count == 2


def test_single_source_entity_is_not_corroborated() -> None:
    findings = [_finding("mft", evidence={"executable": "evil.exe"}, sources=["MFT"])]
    assert correlate_artifacts(findings) == []


def test_one_finding_carrying_multiple_sources_corroborates() -> None:
    # Matches the real corpus shape: a single ransomware finding whose
    # artifact_sources is ['EventLog','MFT','Prefetch'].
    findings = [
        _finding(
            "ransom",
            evidence={"executable": "ransom.exe"},
            sources=["EventLog", "MFT", "Prefetch"],
        )
    ]
    result = correlate_artifacts(findings)
    assert len(result) == 1
    assert result[0].sources == ("EventLog", "MFT", "Prefetch")
    assert result[0].source_count == 3


def test_distinct_entities_do_not_merge() -> None:
    findings = [
        _finding("a1", evidence={"executable": "evil.exe"}, sources=["MFT"]),
        _finding("a2", evidence={"process": "evil.exe"}, sources=["memory"]),
        _finding("b1", evidence={"executable": "benign.exe"}, sources=["MFT"]),
        _finding("b2", evidence={"process": "benign.exe"}, sources=["memory"]),
    ]
    result = correlate_artifacts(findings)
    values = {c.entity_value for c in result}
    assert values == {"evil.exe", "benign.exe"}
    assert len(result) == 2


def test_hash_entity_corroborates_across_sources() -> None:
    # The join key is canonical_entity, so a shared hash unifies across sources
    # even when the process names differ (hash > name in identity priority).
    sha = "a" * 64
    findings = [
        _finding("y", evidence={"sha256": sha}, sources=["yara"]),
        _finding("v", evidence={"sha256": sha.upper()}, sources=["virustotal"]),
    ]
    result = correlate_artifacts(findings)
    assert len(result) == 1
    assert result[0].entity_kind == "hash"
    assert result[0].sources == ("virustotal", "yara")


def test_categories_are_collected_across_the_corroborating_findings() -> None:
    findings = [
        _finding(
            "ts",
            evidence={"executable": "evil.exe"},
            sources=["MFT"],
            category=FindingCategory.TIMELINE_TAMPERING,
        ),
        _finding(
            "inj",
            evidence={"process": "evil.exe"},
            sources=["memory"],
            category=FindingCategory.PROCESS_INJECTION,
        ),
    ]
    result = correlate_artifacts(findings)
    assert len(result) == 1
    assert result[0].categories == (
        FindingCategory.PROCESS_INJECTION.value,
        FindingCategory.TIMELINE_TAMPERING.value,
    )


def test_output_is_deterministic_regardless_of_input_order() -> None:
    a = _finding("a", evidence={"executable": "evil.exe"}, sources=["memory"])
    b = _finding("b", evidence={"process": "evil.exe"}, sources=["MFT"])
    forward = correlate_artifacts([a, b])
    backward = correlate_artifacts([b, a])
    assert forward == backward
    # sources sorted, so order-independent
    assert forward[0].sources == ("MFT", "memory")


def test_findings_without_a_canonical_entity_are_skipped() -> None:
    # No structured entity (no hash/ip/relationship/name) -> no join key.
    findings = [
        _finding("n1", evidence={"note": "nothing structured"}, sources=["MFT"]),
        _finding("n2", evidence={"note": "still nothing"}, sources=["memory"]),
    ]
    assert correlate_artifacts(findings) == []


def test_blank_sources_do_not_count_toward_corroboration() -> None:
    # Two findings on one entity but only ONE non-blank source between them must
    # not corroborate on a shared blank.
    findings = [
        _finding("a", evidence={"executable": "evil.exe"}, sources=["MFT"]),
        _finding("b", evidence={"process": "evil.exe"}, sources=[""]),
    ]
    assert correlate_artifacts(findings) == []


def test_empty_input_returns_empty() -> None:
    assert correlate_artifacts([]) == []


# --- dict input shape (Finding.to_dict), not just Finding objects ----------


def test_dict_input_with_sources_corroborates_like_a_finding_object() -> None:
    # A caller may hand us Finding.to_dict() output. canonical_entity already
    # reads dicts; the source/category reads must too, or a dict would be
    # silently treated as sourceless. Two dicts on one entity from distinct
    # sources MUST corroborate.
    findings = [
        {
            "title": "a",
            "evidence": {"executable": "evil.exe"},
            "artifact_sources": ["MFT"],
            "category": "execution",
        },
        {
            "title": "b",
            "evidence": {"process": "evil.exe"},
            "artifact_sources": ["memory"],
            "category": "process_injection",
        },
    ]
    result = correlate_artifacts(findings)
    assert len(result) == 1
    assert result[0].sources == ("MFT", "memory")
    assert result[0].categories == ("execution", "process_injection")


def test_dict_input_missing_artifact_sources_key_is_skipped() -> None:
    # A dict that omits artifact_sources entirely must fall through to [] (no
    # sources -> no rows), never raise, and never corroborate on the absence.
    findings = [
        {"title": "a", "evidence": {"executable": "evil.exe"}},  # no artifact_sources
        {
            "title": "b",
            "evidence": {"process": "evil.exe"},
            "artifact_sources": ["memory"],
        },
    ]
    assert correlate_artifacts(findings) == []


# --- graceful degradation: no-op when DuckDB is unavailable ----------------


def test_no_op_when_duckdb_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    # MUTATION GUARD for the optional-dep contract: with duckdb removed, the layer
    # must return [] (never raise), so the zero-dep install path stays green.
    monkeypatch.setattr(sa, "duckdb", None)
    findings = [
        _finding("mft", evidence={"executable": "evil.exe"}, sources=["MFT"]),
        _finding("mem", evidence={"process": "evil.exe"}, sources=["memory"]),
    ]
    assert correlate_artifacts(findings) == []
