"""Reusable cross-artifact correlation assembly + entity pivot (SFE-fibx.10).

The correlation substrate (:mod:`.sql_timeline`, :mod:`.sql_artifact`) was
assembled inline inside :func:`sift_find_evil.hardening.harden_findings`, so it
was reachable only from the CLI ``analyze --harden`` path -- never from the live
connector/GUI, which runs ``lite_harden`` (correlation deliberately omitted for
latency). This module lifts that assembly into a standalone, read-only unit so
the live path can run it on demand (the ``pivot`` sidecar method) without the
receipts/anchor cost, and adds :func:`entity_pivot` -- "show everything entity X
touched".

Everything here is READ-ONLY over the findings: it never adds, drops, renames, or
re-scores a finding, so detection accuracy (F1) is provably unaffected -- the same
guarantee ``harden_findings`` gives. All functions accept either ``Finding``
objects or the dicts they serialize to (``canonical_entity`` /
``correlate_artifacts`` read either shape), so the sidecar can pass the same
finding dicts ``analyze`` already returns without reconstructing objects.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Optional

from ..findings.dedup import EntityRef, _scalar, canonical_entity, canonicalize_name
from .sql_artifact import correlate_artifacts
from .sql_timeline import correlate_timeline, find_co_occurrences

logger = logging.getLogger(__name__)


# A trailing ALPHABETIC timezone word on a timeline timestamp that SQLite
# ``julianday()`` cannot parse. Volatility renders create-times as e.g.
# ``"2026-04-22 10:05:10.000000 UTC"``; the `` UTC`` tail makes julianday() return
# NULL, so the correlation window predicate never matches and a real correlation
# is silently dropped. Empirically (SQLite): julianday() natively parses bare
# timestamps, a trailing ``Z``, and COLON-SEPARATED numeric offsets (``+00:00``,
# ``+05:30``); it returns NULL for alphabetic zone words (UTC/GMT/PDT/EST/...) and
# for COMPACT offsets like ``-0700``. So we strip a trailing alphabetic zone word
# plus a trailing ``Z``. Numeric offsets are preserved automatically because the
# regex matches only alphabetic words: a colon-separated offset parses natively,
# and a compact offset (which julianday() rejects) is left to trip the
# not-parseable warning below rather than be silently mangled. Timeline events are
# already normalized to UTC upstream, so an alphabetic tag carries no offset we
# lose by dropping it. We match any alphabetic word (not a hard-coded set that
# drifts as new artifact sources appear), but warn when the stripped word is not a
# RECOGNIZED zone -- so removing a stray non-timezone token (which could yield a
# subtly-wrong instant that still parses) is observable rather than silent.
_TZ_WORD_SUFFIX = re.compile(r"\s+([A-Za-z]{2,5})$")
_Z_SUFFIX = re.compile(r"Z$")

# Recognized alphabetic timezone abbreviations. Stripping one of these is the
# expected, silent case; stripping any OTHER trailing word warns (see above).
_KNOWN_TZ_ABBREVS = frozenset(
    {
        "UTC",
        "GMT",
        "Z",
        "EST",
        "EDT",
        "CST",
        "CDT",
        "MST",
        "MDT",
        "PST",
        "PDT",
        "BST",
        "CET",
        "CEST",
        "EET",
        "EEST",
        "WET",
        "JST",
        "IST",
        "AEST",
        "AEDT",
        "AWST",
        "NZST",
        "NZDT",
    }
)


def _julianday_parseable(ts: str) -> bool:
    """True iff SQLite ``julianday()`` yields a non-NULL value for ``ts``.

    Used only to decide whether to warn: a normalized ts that still will not
    parse would be dropped to NULL by the correlator (a silent false negative),
    so we surface it as a log signal instead.
    """
    con = sqlite3.connect(":memory:")
    try:
        return con.execute("SELECT julianday(?)", (ts,)).fetchone()[0] is not None
    finally:
        con.close()


def _normalize_ts(ts: str) -> str:
    """Strip a trailing timezone tag so SQLite ``julianday()`` can parse the ts.

    Strips a trailing alphabetic zone word (`` UTC``/`` PDT``/...) or a trailing
    ``Z``; numeric offsets are preserved because julianday() parses them and
    stripping would shift the instant. If the normalized form STILL will not
    parse (e.g. a compact ``-0700`` offset from some future artifact source), the
    ts is returned unchanged but a warning is logged, so the resulting NULL drop
    in the time-window self-join is observable rather than silent.
    """
    text = ts.strip()
    word_match = _TZ_WORD_SUFFIX.search(text)
    if word_match:
        word = word_match.group(1)
        if word.upper() not in _KNOWN_TZ_ABBREVS:
            # Best-effort strip, but flag it: a stray non-timezone token could
            # leave a remainder that still parses to a subtly-wrong instant.
            logger.warning(
                "timeline ts %r has trailing word %r that is not a recognized "
                "timezone; stripping it anyway -- verify this artifact source.",
                ts,
                word,
            )
        normalized = _TZ_WORD_SUFFIX.sub("", text)
    else:
        normalized = _Z_SUFFIX.sub("", text)
    normalized = normalized.strip()
    if normalized and not _julianday_parseable(normalized):
        logger.warning(
            "timeline ts %r normalized to %r is not julianday-parseable; the "
            "time-window correlation self-join will drop it (NULL). Extend "
            "_normalize_ts if this artifact source is expected.",
            ts,
            normalized,
        )
    return normalized


def _finding_evidence(finding: Any) -> dict:
    """The finding's ``evidence`` mapping, from either a dict or a Finding object.

    Mirrors the both-shapes access ``canonical_entity`` uses, so this module runs
    identically on the objects ``harden_findings`` passes and the dicts the
    sidecar passes. For an object this is exactly the prior
    ``getattr(finding, "evidence", None) or {}``.
    """
    if isinstance(finding, dict):
        ev = finding.get("evidence")
    else:
        ev = getattr(finding, "evidence", None)
    # Guarantee a mapping. On the real paths ``evidence`` is always a dict, so this
    # is a no-op there; it only matters at the ``pivot`` JSON-RPC boundary, where a
    # malformed client finding could carry a non-dict ``evidence`` -- returning it
    # as-is would make the caller's ``.get("timeline")`` raise (an internal error
    # for the whole request) instead of that one bad finding being skipped.
    return ev if isinstance(ev, dict) else {}


def _timeline_events(findings: list[Any]) -> list[dict]:
    """Extract normalized timeline events from findings that carry them.

    A finding opts into cross-artifact correlation by putting a ``timeline``
    dict (ts/source/actor/target/type) in its evidence. Findings without one are
    simply skipped, so correlation is opportunistic and never required.

    Two normalizations make the SQL correlator actually fire on real evidence:
    the ``ts`` is stripped of an unparseable timezone tag (:func:`_normalize_ts`),
    and the ``actor`` is canonicalized (:func:`canonicalize_name`) so a
    memory-truncated ``_EPROCESS`` name and its full disk/path form join as one
    actor instead of two distinct strings.
    """
    events: list[dict] = []
    for finding in findings:
        timeline = _finding_evidence(finding).get("timeline")
        if not isinstance(timeline, dict):
            continue
        if not timeline.get("ts") or not timeline.get("source"):
            continue
        events.append(
            {
                "ts": _normalize_ts(str(timeline.get("ts"))),
                "source": str(timeline.get("source")),
                "actor": canonicalize_name(str(timeline.get("actor", ""))),
                "target": str(timeline.get("target", "")),
                "type": str(timeline.get("type", "")),
                "raw": str(timeline.get("raw", "")),
            }
        )
    return events


@dataclass(frozen=True)
class CorrelationResult:
    """The read-only cross-artifact correlation over a finding set.

    Field shapes match the ``HardeningReport`` fields they used to be computed
    inline for, so ``harden_findings`` can delegate here without changing its
    output:

    - ``correlations``: pairwise time-window edges ``[{a, b, relation}]``.
    - ``co_occurrences``: same-actor multi-behavior overlaps (corroborating).
    - ``corroborations``: entity-keyed N-way join (entities evidenced by >=2
      distinct artifact sources); empty when DuckDB is unavailable.
    """

    correlations: list[dict]
    co_occurrences: list[dict]
    corroborations: list[dict]

    def to_dict(self) -> dict:
        return {
            "correlations": self.correlations,
            "co_occurrences": self.co_occurrences,
            "corroborations": self.corroborations,
        }


def build_correlation(findings: list[Any]) -> CorrelationResult:
    """Assemble all cross-artifact correlation over ``findings`` (read-only).

    Extracted verbatim from ``harden_findings`` so both the CLI harden report and
    the live/session path compute correlation identically. Never mutates or
    re-scores a finding.
    """
    events = _timeline_events(findings)
    correlations = [
        {"a": c.a, "b": c.b, "relation": c.relation} for c in correlate_timeline(events)
    ]
    co_occurrences = find_co_occurrences(events)
    corroborations = [c.to_dict() for c in correlate_artifacts(findings)]
    return CorrelationResult(
        correlations=correlations,
        co_occurrences=co_occurrences,
        corroborations=corroborations,
    )


def _as_finding_dict(finding: Any) -> dict:
    """Serialize a finding to a dict, passing an already-dict finding through."""
    if isinstance(finding, dict):
        return finding
    return finding.to_dict()


def _event_touches(event: dict, value: str) -> bool:
    """True iff a normalized timeline event names ``value`` as actor or target.

    The event ``actor`` is already canonicalized by :func:`_timeline_events`, and
    a ``process``/``relationship`` :class:`EntityRef` value is canonicalized the
    same way, so they compare directly. For ``ip``/``hash`` entities the timeline
    actor is a process name and will simply not match -- honest empty, not wrong.
    """
    return event.get("actor") == value or event.get("target") == value


# --- Per-entity forensic attribute rollup (SFE-fbic) -----------------------
#
# Evidence is free-form per detector, so these are CURATED key sets: the rollup
# surfaces an attribute only when a finding actually carries one of these keys,
# and stays empty (an honest gap) otherwise -- it never fabricates a value.
# Hashes are grouped by algorithm; paths and forensic timestamps are collected
# distinct. First/last-seen come from the entity's timeline ts (a real forensic
# instant), never the volatile ``detected_at`` (wall-clock at analysis time).
_ATTR_HASH_KEYS = ("md5", "sha1", "sha256", "imphash")
_ATTR_PATH_KEYS = ("path", "target_path", "file_path", "full_path", "image")
_ATTR_TIME_KEYS = (
    "create_time",
    "modified",
    "accessed",
    "last_write_time",
    "opened_time",
    "si_time",
    "fn_time",
    "command_time",
    "last_run",
    "run_time",
    "execution_time",
    "first_run",
)
# Legacy evidence keys carrying MITRE ids before the first-class ``techniques``
# field (mirrors ``Finding._LEGACY_MITRE_KEYS``); used only as a fallback for a
# finding dict that predates the migration. First present key wins.
_ATTR_MITRE_KEYS = ("mitre_attack", "mitre_technique", "mitre")


def _all_scalars(value: Any) -> list[str]:
    """Every usable identity string in ``value`` (scalar, or each list element).

    Unlike :func:`sift_find_evil.findings.dedup._scalar` (first usable only), this
    collects ALL elements so a multi-valued evidence field (e.g. several paths)
    contributes each. Empty/whitespace/mapping values yield nothing.
    """
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            out.extend(_all_scalars(item))
        return out
    got = _scalar(value)
    return [got] if got else []


def _distinct_ordered(values: Iterable[str]) -> list[str]:
    """Distinct values, sorted for a deterministic rollup (order-independent)."""
    return sorted(set(values))


def _collect_flat(matched: list[dict], keys: tuple[str, ...]) -> list[str]:
    """Distinct scalar values across ``keys`` in the entity's findings, sorted."""
    return _distinct_ordered(
        value
        for finding in matched
        for key in keys
        for value in _all_scalars(_finding_evidence(finding).get(key))
    )


def _collect_grouped(matched: list[dict], keys: tuple[str, ...]) -> dict:
    """Map each present key to the distinct scalar values seen for it.

    A key with no usable value in any finding is omitted entirely, so an empty
    group never appears (the render can treat presence as "we have this").
    """
    grouped: dict[str, list[str]] = {}
    for finding in matched:
        evidence = _finding_evidence(finding)
        for key in keys:
            found = _all_scalars(evidence.get(key))
            if found:
                grouped.setdefault(key, []).extend(found)
    return {k: _distinct_ordered(v) for k, v in grouped.items() if v}


def _collect_hashes(matched: list[dict]) -> dict:
    """Distinct hashes grouped by algorithm, lowercased (hex is case-insensitive)."""
    grouped: dict[str, list[str]] = {}
    for finding in matched:
        evidence = _finding_evidence(finding)
        for key in _ATTR_HASH_KEYS:
            found = [h.lower() for h in _all_scalars(evidence.get(key))]
            if found:
                grouped.setdefault(key, []).extend(found)
    return {k: _distinct_ordered(v) for k, v in grouped.items() if v}


def _collect_categories(matched: list[dict]) -> list[str]:
    """Distinct finding-category labels across the entity's findings."""
    cats: list[str] = []
    for finding in matched:
        category = finding.get("category")
        value = getattr(category, "value", category)
        if value is not None:
            cats.append(str(value))
    return _distinct_ordered(c for c in cats if c)


def _collect_techniques(matched: list[dict]) -> list[str]:
    """Distinct MITRE technique ids, first-class ``techniques`` then legacy keys.

    Mirrors ``Finding.mitre_techniques`` for the serialized dict shape the pivot
    operates on: the first-class field wins; otherwise the first present legacy
    evidence key (scalar or list) is used, so a not-yet-migrated finding still
    contributes.
    """
    techs: list[str] = []
    for finding in matched:
        values = finding.get("techniques") or []
        if not values:
            evidence = _finding_evidence(finding)
            for key in _ATTR_MITRE_KEYS:
                legacy = evidence.get(key)
                if legacy is None or legacy == "":
                    continue
                values = list(legacy) if isinstance(legacy, (list, tuple)) else [legacy]
                break
        techs.extend(str(t).strip() for t in values)
    return _distinct_ordered(t for t in techs if t)


@dataclass(frozen=True)
class EntityAttributes:
    """A read-only forensic profile aggregated over one entity's findings.

    Pure aggregation: it reads the entity's findings + timeline events and never
    adds, drops, or re-scores a finding, so detection accuracy is unaffected.
    Every field is an honest gap (empty) when the entity's evidence carries none
    of the curated keys -- the rollup never fabricates an attribute.
    """

    hashes: dict  # {algorithm: [distinct hash, ...]}, only present algorithms
    first_seen: Optional[str]  # earliest forensic timeline ts, or None
    last_seen: Optional[str]  # latest forensic timeline ts, or None
    paths: list[str]  # distinct file paths
    timestamps: dict  # {key: [distinct ts, ...]} of other forensic time fields
    categories: list[str]  # distinct finding categories
    techniques: list[str]  # distinct MITRE ATT&CK technique ids

    def to_dict(self) -> dict:
        return {
            "hashes": self.hashes,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "paths": self.paths,
            "timestamps": self.timestamps,
            "categories": self.categories,
            "techniques": self.techniques,
        }


def _ts_sort_key(ts: str) -> tuple:
    """A CHRONOLOGICAL sort key for a timeline ts, robust to format variance.

    Different artifact sources render the same instant differently -- e.g. a
    space separator (Volatility: ``"2026-04-22 10:05:10"``) vs an ISO ``T``
    (``"2026-04-22T10:05:10"``). A plain string sort orders those by ASCII
    (space < ``T``), which reverses the real order, so the activity window would
    show the wrong first/last-seen for a cross-source entity. We instead sort by
    the PARSED instant (:meth:`datetime.fromisoformat`, which accepts both
    separators plus fractional seconds/offsets on 3.11+). The leading ``0``/``1``
    keeps parseable timestamps ordered among themselves and unparseable ones after
    them (compared lexically), so datetime is never compared against str.
    """
    try:
        return (0, datetime.fromisoformat(ts))
    except ValueError:
        return (1, ts)


def _build_entity_attributes(
    matched: list[dict], events: list[dict]
) -> EntityAttributes:
    """Assemble the per-entity attribute rollup from its findings + timeline.

    ``matched`` are the entity's findings (already serialized dicts); ``events``
    are the entity's own timeline events (already normalized by
    :func:`_timeline_events`), used only to bound first/last-seen.
    """
    tss = sorted((ev["ts"] for ev in events if ev.get("ts")), key=_ts_sort_key)
    first_seen = tss[0] if tss else None
    last_seen = tss[-1] if tss else None
    return EntityAttributes(
        hashes=_collect_hashes(matched),
        first_seen=first_seen,
        last_seen=last_seen,
        paths=_collect_flat(matched, _ATTR_PATH_KEYS),
        timestamps=_collect_grouped(matched, _ATTR_TIME_KEYS),
        categories=_collect_categories(matched),
        techniques=_collect_techniques(matched),
    )


@dataclass(frozen=True)
class EntityPivot:
    """Everything a single entity touched, across findings and correlation.

    ``findings`` is the authoritative answer (every finding whose
    ``canonical_entity`` is this entity). ``corroboration`` is the entity's
    cross-source join row (>=2 distinct artifact sources) when one exists.
    ``timeline`` and ``correlations`` are best-effort: they link only when the
    entity participates as a timeline ``actor``/``target`` (populated today mainly
    by memory findings), so they may be empty for an entity with no timeline
    evidence -- an honest gap, never a fabricated edge.
    """

    entity: dict  # {"kind", "value"}
    findings: list[dict]
    corroboration: Optional[dict]
    timeline: list[dict]
    correlations: list[dict]
    attributes: dict  # forensic rollup (see EntityAttributes.to_dict)

    def to_dict(self) -> dict:
        return {
            "entity": self.entity,
            "findings": self.findings,
            "corroboration": self.corroboration,
            "timeline": self.timeline,
            "correlations": self.correlations,
            "attributes": self.attributes,
        }


def entity_pivot(
    findings: list[Any],
    entity_ref: EntityRef,
    correlation: Optional[CorrelationResult] = None,
) -> EntityPivot:
    """Gather everything ``entity_ref`` touched across ``findings``.

    Args:
        findings: Finding objects or their serialized dicts.
        entity_ref: The canonical entity to pivot on (kind + value).
        correlation: A pre-computed :class:`CorrelationResult` to reuse (so a
            caller running the full correlation once, e.g. the ``pivot`` method,
            does not recompute it here). Computed on demand when ``None``.

    Returns:
        An :class:`EntityPivot`; ``findings`` is exact, the rest best-effort.
    """
    corr = correlation if correlation is not None else build_correlation(findings)

    matched = [
        _as_finding_dict(f) for f in findings if canonical_entity(f) == entity_ref
    ]

    corroboration = next(
        (
            c
            for c in corr.corroborations
            if c.get("entity_kind") == entity_ref.kind
            and c.get("entity_value") == entity_ref.value
        ),
        None,
    )

    value = entity_ref.value
    events = [ev for ev in _timeline_events(findings) if _event_touches(ev, value)]
    edges = [
        e
        for e in corr.correlations
        if _event_touches(e.get("a", {}), value)
        or _event_touches(e.get("b", {}), value)
    ]

    return EntityPivot(
        entity={"kind": entity_ref.kind, "value": entity_ref.value},
        findings=matched,
        corroboration=corroboration,
        timeline=events,
        correlations=edges,
        attributes=_build_entity_attributes(matched, events).to_dict(),
    )
