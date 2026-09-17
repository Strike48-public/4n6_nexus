"""Reusable correlation assembly + entity pivot (SFE-fibx.10 slice 1a).

``build_correlation`` was lifted verbatim out of ``harden_findings`` so the live
path can run correlation on demand; ``entity_pivot`` is the new "show everything
entity X touched" query. These tests pin:

  1. correlation is assembled correctly (entity corroboration across sources,
     timeline edges) -- on the SAME dict shape ``analyze`` returns, since the
     sidecar ``pivot`` method passes finding dicts, not Finding objects;
  2. ``harden_findings`` still delegates to the shared unit (the refactor did not
     fork the logic);
  3. the pivot returns every finding for an entity, its cross-source
     corroboration, and only the timeline edges the entity actually participates
     in -- empty (never fabricated) when the entity has no timeline evidence.
"""

from __future__ import annotations

import pytest

from sift_find_evil.correlation.assemble import (
    CorrelationResult,
    build_correlation,
    entity_pivot,
)
from sift_find_evil.findings.dedup import canonical_entity, canonicalize_name


def _finding(
    title: str,
    evidence: dict,
    sources: list[str],
    category: str = "execution",
    timeline: dict | None = None,
) -> dict:
    """A finding in the serialized (``Finding.to_dict``) shape the sidecar sees."""
    ev = dict(evidence)
    if timeline is not None:
        ev["timeline"] = timeline
    return {
        "title": title,
        # Keys Finding.from_dict requires (data[...]); harmless for the dict path.
        "description": title,
        "type": "test",
        "severity": "high",
        "detected_at": "2026-01-01T12:00:00+00:00",
        "category": category,
        "evidence": ev,
        "artifact_sources": list(sources),
    }


def _timeline(ts: str, source: str, actor: str) -> dict:
    return {"ts": ts, "source": source, "actor": actor, "target": "", "type": "exec"}


def test_build_correlation_corroborates_entity_across_distinct_sources() -> None:
    """Two findings on the SAME process entity from DIFFERENT artifact sources
    corroborate (>=2 distinct sources) -- the entity-keyed cross-source join."""
    findings = [
        _finding("MFT sighting", {"executable": "evil.exe"}, ["mft"]),
        _finding("Prefetch sighting", {"executable": "evil.exe"}, ["prefetch"]),
    ]
    result = build_correlation(findings)

    assert isinstance(result, CorrelationResult)
    evil = [
        c
        for c in result.corroborations
        if c["entity_value"] == canonicalize_name("evil.exe")
    ]
    assert (
        len(evil) == 1
    ), "the shared process entity should corroborate across mft+prefetch"
    assert set(evil[0]["sources"]) == {"mft", "prefetch"}
    assert evil[0]["source_count"] == 2


def test_build_correlation_matches_harden_findings_output() -> None:
    """``harden_findings`` must delegate correlation to the shared unit, not a
    forked copy: its report fields equal ``build_correlation`` over the same
    findings. Mutation: reverting harden to a divergent inline computation, or
    breaking the extraction, turns this red."""
    from sift_find_evil.findings.finding import Finding

    raw = [
        _finding("MFT sighting", {"executable": "evil.exe"}, ["mft"]),
        _finding("Prefetch sighting", {"executable": "evil.exe"}, ["prefetch"]),
    ]
    findings = [Finding.from_dict(d) for d in raw]

    from sift_find_evil.hardening import harden_findings

    # image_sha256 / receipt_key feed the receipt+anchor chain, not correlation;
    # dummy values suffice to reach the correlation fields under test.
    report = harden_findings(findings, image_sha256="0" * 64, receipt_key=b"k" * 32)
    shared = build_correlation(findings)

    assert report.correlations == shared.correlations
    assert report.co_occurrences == shared.co_occurrences
    assert report.corroborations == shared.corroborations


def test_entity_pivot_returns_every_finding_for_the_entity() -> None:
    """The authoritative pivot answer: all findings whose canonical_entity is X,
    and none belonging to a different entity."""
    findings = [
        _finding("A", {"executable": "evil.exe"}, ["mft"]),
        _finding("B", {"executable": "evil.exe"}, ["prefetch"]),
        _finding("C", {"executable": "benign.exe"}, ["mft"]),
    ]
    ref = canonical_entity(findings[0])
    assert ref is not None

    pivot = entity_pivot(findings, ref)

    titles = {f["title"] for f in pivot.findings}
    assert titles == {"A", "B"}, "pivot must include exactly the entity's findings"
    assert pivot.entity == {"kind": ref.kind, "value": ref.value}
    # Two distinct sources -> the cross-source corroboration is attached.
    assert pivot.corroboration is not None
    assert pivot.corroboration["source_count"] == 2


def test_entity_pivot_works_on_finding_objects_too() -> None:
    """Both shapes: the CLI/harden path passes Finding objects, the sidecar passes
    dicts. The pivot must behave identically on objects."""
    from sift_find_evil.findings.finding import Finding

    findings = [
        Finding.from_dict(_finding("A", {"executable": "evil.exe"}, ["mft"])),
        Finding.from_dict(_finding("C", {"executable": "benign.exe"}, ["mft"])),
    ]
    ref = canonical_entity(findings[0])

    pivot = entity_pivot(findings, ref)
    assert {f["title"] for f in pivot.findings} == {"A"}


def test_entity_pivot_links_timeline_edges_the_entity_participates_in() -> None:
    """When the entity appears as a timeline actor, its correlation edges surface."""
    findings = [
        _finding(
            "mem",
            {"executable": "evil.exe"},
            ["memory"],
            timeline=_timeline("2026-01-01 12:00:00", "memory", "evil.exe"),
        ),
        _finding(
            "disk",
            {"executable": "evil.exe"},
            ["mft"],
            timeline=_timeline("2026-01-01 12:00:02", "disk", "evil.exe"),
        ),
    ]
    ref = canonical_entity(findings[0])

    pivot = entity_pivot(findings, ref)
    assert pivot.timeline, "the entity's own timeline events should surface"
    assert (
        pivot.correlations
    ), "a cross-source timeline edge on this actor should surface"


def test_entity_pivot_disk_only_entity_has_empty_timeline_not_fabricated() -> None:
    """Honest gap: an entity with NO timeline evidence gets empty timeline/edges,
    never a fabricated one -- while still returning its findings + corroboration."""
    findings = [
        _finding("A", {"executable": "evil.exe"}, ["mft"]),
        _finding("B", {"executable": "evil.exe"}, ["prefetch"]),
    ]
    ref = canonical_entity(findings[0])

    pivot = entity_pivot(findings, ref)
    assert pivot.findings, "findings are still returned for a disk-only entity"
    assert pivot.timeline == []
    assert pivot.correlations == []


def test_entity_pivot_reuses_precomputed_correlation() -> None:
    """Passing a precomputed CorrelationResult must be USED, not recomputed --
    so the ``pivot`` method can correlate once and slice per entity. An empty
    precomputed result yields no corroboration even though the findings would
    corroborate if recomputed."""
    findings = [
        _finding("A", {"executable": "evil.exe"}, ["mft"]),
        _finding("B", {"executable": "evil.exe"}, ["prefetch"]),
    ]
    ref = canonical_entity(findings[0])
    empty = CorrelationResult(correlations=[], co_occurrences=[], corroborations=[])

    pivot = entity_pivot(findings, ref, correlation=empty)
    assert pivot.corroboration is None, "precomputed correlation must not be recomputed"
    assert pivot.correlations == []
    # findings are independent of the correlation arg, so they're still returned.
    assert {f["title"] for f in pivot.findings} == {"A", "B"}


def test_build_correlation_tolerates_a_non_dict_evidence_finding() -> None:
    """A malformed finding whose ``evidence`` is not a dict is skipped, not raised
    -- so one bad finding from the pivot JSON-RPC boundary cannot error the whole
    request. The well-formed finding alongside it still correlates."""
    findings = [
        {
            "title": "bad",
            "category": "execution",
            "evidence": "not-a-dict",
            "artifact_sources": ["mft"],
        },
        _finding("A", {"executable": "evil.exe"}, ["mft"]),
        _finding("B", {"executable": "evil.exe"}, ["prefetch"]),
    ]
    result = build_correlation(findings)  # must not raise
    assert any(c["source_count"] == 2 for c in result.corroborations)


@pytest.mark.parametrize("bad_actor", ["", "   "])
def test_build_correlation_no_edges_without_timeline(bad_actor: str) -> None:
    """A finding with no usable timeline contributes no timeline edges (guards the
    opportunistic-correlation contract: correlation is never required)."""
    findings = [_finding("A", {"executable": "evil.exe"}, ["mft"])]
    result = build_correlation(findings)
    assert result.correlations == []
    assert result.co_occurrences == []


# --- Entity attribute rollup (SFE-fbic) ------------------------------------
#
# entity_pivot attaches a read-only per-entity forensic profile aggregated over
# the entity's own findings + timeline events: distinct hashes, first/last-seen
# (from forensic timeline ts, NOT the volatile detected_at), paths, other
# forensic timestamps, finding categories, and MITRE technique ids. Pure
# aggregation -- it never adds/drops/rescores a finding.


def test_entity_pivot_rolls_up_distinct_hashes_by_kind() -> None:
    """Hashes are collected across the entity's findings, grouped by algorithm,
    distinct and lowercased. A hash on a DIFFERENT entity must not leak in.
    Mutation: dropping the hash rollup, or not deduping, turns this red."""
    findings = [
        _finding(
            "A",
            {"executable": "evil.exe", "sha256": "AB" * 32, "md5": "cd" * 16},
            ["mft"],
        ),
        # Same entity, same sha256 (must dedupe) + a distinct imphash.
        _finding(
            "B",
            {"executable": "evil.exe", "sha256": "ab" * 32, "imphash": "ef" * 16},
            ["prefetch"],
        ),
        # Different entity -- its hash must NOT appear in evil.exe's rollup.
        _finding("C", {"executable": "benign.exe", "sha256": "99" * 32}, ["mft"]),
    ]
    ref = canonical_entity(findings[0])

    attrs = entity_pivot(findings, ref).attributes

    assert attrs["hashes"]["sha256"] == ["ab" * 32], "distinct + lowercased"
    assert attrs["hashes"]["md5"] == ["cd" * 16]
    assert attrs["hashes"]["imphash"] == ["ef" * 16]
    assert "99" * 32 not in attrs["hashes"]["sha256"], "other entity's hash leaked"


def test_entity_pivot_first_last_seen_from_forensic_timeline() -> None:
    """first_seen/last_seen bound the entity's forensic timeline ts (min/max),
    NOT the volatile detected_at. Mutation: using detected_at, or not taking
    min/max, turns this red."""
    findings = [
        _finding(
            "later",
            {"executable": "evil.exe"},
            ["mft"],
            timeline=_timeline("2026-01-01 12:00:05", "disk", "evil.exe"),
        ),
        _finding(
            "earlier",
            {"executable": "evil.exe"},
            ["memory"],
            timeline=_timeline("2026-01-01 12:00:01", "memory", "evil.exe"),
        ),
    ]
    ref = canonical_entity(findings[0])

    attrs = entity_pivot(findings, ref).attributes

    assert attrs["first_seen"] == "2026-01-01 12:00:01"
    assert attrs["last_seen"] == "2026-01-01 12:00:05"
    # detected_at is 2026-01-01T12:00:00 for both fixtures -- it must not be the
    # source, or first_seen would be that value.
    assert attrs["first_seen"] != "2026-01-01T12:00:00+00:00"


def test_entity_pivot_first_last_seen_chronological_across_ts_formats() -> None:
    """Regression: first/last-seen must order by the real instant, not by ASCII.
    A space-separated ts and an ISO 'T' ts of the same entity render different
    separators; a plain string sort (space < 'T') would reverse them. The EARLIER
    instant (08:00) must be first_seen even though it uses the 'T' separator that
    sorts AFTER a space lexically."""
    findings = [
        _finding(
            "space-later",
            {"executable": "evil.exe"},
            ["mft"],
            timeline=_timeline("2026-01-01 20:00:00", "disk", "evil.exe"),
        ),
        _finding(
            "iso-earlier",
            {"executable": "evil.exe"},
            ["memory"],
            timeline=_timeline("2026-01-01T08:00:00", "memory", "evil.exe"),
        ),
    ]
    ref = canonical_entity(findings[0])

    attrs = entity_pivot(findings, ref).attributes

    assert attrs["first_seen"] == "2026-01-01T08:00:00", "earlier instant wins"
    assert attrs["last_seen"] == "2026-01-01 20:00:00"


def test_entity_pivot_collects_paths_categories_techniques_timestamps() -> None:
    """Paths, forensic timestamps, categories and MITRE ids roll up distinct and
    sorted across the entity's findings."""
    findings = [
        _finding(
            "exec",
            {
                "executable": "evil.exe",
                "path": "C:\\Users\\v\\evil.exe",
                "last_run": "2026-01-01 11:59:00",
            },
            ["prefetch"],
            category="execution",
        ),
    ]
    findings[0]["techniques"] = ["T1055"]
    findings.append(
        _finding(
            "stomp",
            {
                "executable": "evil.exe",
                "target_path": "C:\\Windows\\evil.exe",
                "si_time": "2026-01-01 10:00:00",
            },
            ["mft"],
            category="anti_forensics",
        )
    )
    findings[1]["techniques"] = ["T1070.006"]
    ref = canonical_entity(findings[0])

    attrs = entity_pivot(findings, ref).attributes

    assert attrs["paths"] == ["C:\\Users\\v\\evil.exe", "C:\\Windows\\evil.exe"]
    assert attrs["categories"] == ["anti_forensics", "execution"]
    assert attrs["techniques"] == ["T1055", "T1070.006"]
    assert attrs["timestamps"]["last_run"] == ["2026-01-01 11:59:00"]
    assert attrs["timestamps"]["si_time"] == ["2026-01-01 10:00:00"]


def test_entity_pivot_attributes_empty_when_absent_not_fabricated() -> None:
    """Honest gaps: an entity whose findings carry no hashes/paths/timeline gets
    empty rollups (categories still present -- every finding has one), never a
    fabricated value."""
    findings = [_finding("A", {"executable": "evil.exe"}, ["mft"])]
    ref = canonical_entity(findings[0])

    attrs = entity_pivot(findings, ref).attributes

    assert attrs["hashes"] == {}
    assert attrs["first_seen"] is None and attrs["last_seen"] is None
    assert attrs["paths"] == []
    assert attrs["timestamps"] == {}
    assert attrs["techniques"] == []
    assert attrs["categories"] == ["execution"]


def test_entity_pivot_to_dict_carries_attributes() -> None:
    """The attribute rollup rides the serialized envelope the sidecar returns, so
    the Rust facade/GUI can read it. Mutation: dropping attributes from to_dict
    turns this red."""
    findings = [
        _finding("A", {"executable": "evil.exe", "md5": "ab" * 16}, ["mft"]),
    ]
    ref = canonical_entity(findings[0])

    payload = entity_pivot(findings, ref).to_dict()

    assert "attributes" in payload
    assert payload["attributes"]["hashes"]["md5"] == ["ab" * 16]
