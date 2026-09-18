"""DuckDB entity-keyed cross-artifact correlation (SFE-fx8o).

Answers a question no single-source detector can express: **which canonical
entity is corroborated by N distinct artifact sources?** - e.g. a process whose
image appears in memory (malfind) AND has a timestomped MFT record AND an
outbound C2 flow. This is the correlation-4 shape the 4-tier field ships via
DuckDB SQL; it is distinct from the two existing correlators:

  - :mod:`.sql_timeline` (stdlib sqlite3): memory-only, pairwise time-window
    self-join on a string ``actor`` - not entity-keyed, not N-way.
  - :mod:`.cross_source`: detects ABSENCE (ghost/phantom/uninstalled) - the
    opposite polarity from corroboration.

Design:
- Join key is :func:`~sift_find_evil.findings.dedup.canonical_entity` (the
  SFE-1fkn / dedup key: ``EntityRef(kind, value)``), so hash/ip/relationship/
  process entities all unify across tools by the SAME rule dedup already uses.
- Each (entity, source) pair is a row; a corroboration is an entity GROUP with
  ``COUNT(DISTINCT source) >= 2``. Blank sources never count.
- Output is additive HardeningReport metadata over TRUE artifacts; it never adds,
  drops, or reweights a finding, so F1 is provably unaffected.

Security / determinism posture:
- All built-in SQL is static and parameter-free (no user/LLM string reaches it);
  the reject-to-record guard for any future user rule stays in
  :func:`.sql_timeline.validate_rule_string`.
- The DuckDB connection is in-memory only (never persisted) and results are
  fully ordered, so a run is reproducible.

DuckDB is an OPTIONAL dependency. When it is not installed, :func:`correlate_artifacts`
returns ``[]`` (never raises), so the zero-dependency install path stays green;
CI installs duckdb so the real path is exercised rather than silently skipped.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Tuple

try:  # optional dependency - see module docstring
    import duckdb
except ImportError:  # pragma: no cover - exercised via monkeypatch in tests
    duckdb = None  # type: ignore[assignment]

from ..findings.dedup import canonical_entity

# Minimum distinct artifact sources for an entity to count as corroborated.
_CORROBORATION_MIN = 2


@dataclass(frozen=True)
class ArtifactCorroboration:
    """One canonical entity evidenced by >=2 distinct artifact sources.

    Attributes:
        entity_kind: The :class:`~sift_find_evil.findings.dedup.EntityRef` kind
            ("hash", "ip", "relationship", "process").
        entity_value: The normalized entity identity string.
        sources: The distinct artifact sources that evidenced the entity, sorted.
        categories: The distinct finding categories across the corroborating
            findings, sorted.
        finding_titles: The titles of the corroborating findings, sorted.
    """

    entity_kind: str
    entity_value: str
    sources: Tuple[str, ...]
    categories: Tuple[str, ...]
    finding_titles: Tuple[str, ...]

    @property
    def source_count(self) -> int:
        """Number of distinct artifact sources corroborating this entity."""
        return len(self.sources)

    def to_dict(self) -> dict:
        """Serialize for the HardeningReport / JSON report."""
        return {
            "entity_kind": self.entity_kind,
            "entity_value": self.entity_value,
            "sources": list(self.sources),
            "source_count": self.source_count,
            "categories": list(self.categories),
            "finding_titles": list(self.finding_titles),
        }


def _field(finding: Any, name: str) -> Any:
    """Read ``name`` from a Finding-like object OR the dict it serializes to.

    ``canonical_entity`` already supports both shapes; this keeps the source/
    category/title reads consistent so a dict input (``Finding.to_dict()``) is
    not silently treated as having no artifact sources. A dict is read by key,
    anything else by attribute (``getattr`` never sees a dict's keys).
    """
    if isinstance(finding, dict):
        return finding.get(name)
    return getattr(finding, name, None)


def _entity_source_rows(findings: List[Any]) -> List[Tuple[str, str, str, str, str]]:
    """Flatten findings into (kind, value, source, category, title) rows.

    One row per (finding, non-blank artifact source). A finding with no canonical
    entity, or with only blank sources, contributes no rows - so it can never
    corroborate on a shared blank. Accepts both Finding objects and the dicts
    they serialize to (:meth:`Finding.to_dict`).
    """
    rows: List[Tuple[str, str, str, str, str]] = []
    for finding in findings:
        entity = canonical_entity(finding)
        if entity is None:
            continue
        # A Finding carries a FindingCategory enum (.value); a serialized dict
        # carries the already-stringified category. Handle both.
        raw_category = _field(finding, "category")
        category = getattr(raw_category, "value", None) or (
            str(raw_category) if raw_category else ""
        )
        title = str(_field(finding, "title") or "")
        sources = _field(finding, "artifact_sources") or []
        for source in sources:
            text = str(source).strip()
            if not text:
                continue
            rows.append((entity.kind, entity.value, text, category, title))
    return rows


def correlate_artifacts(findings: List[Any]) -> List[ArtifactCorroboration]:
    """Correlate findings by canonical entity across distinct artifact sources.

    Loads (entity, source) rows into an in-memory DuckDB table and groups by
    entity, keeping only entities evidenced by ``>=_CORROBORATION_MIN`` distinct
    sources. Inputs are never mutated.

    Args:
        findings: :class:`~sift_find_evil.findings.finding.Finding` objects (or the
            dicts they serialize to). ``canonical_entity`` reads either shape.

    Returns:
        A deterministically ordered list of :class:`ArtifactCorroboration`. Empty
        when there is nothing to correlate OR when DuckDB is unavailable.
    """
    if duckdb is None:
        return []

    rows = _entity_source_rows(findings)
    if not rows:
        return []

    conn = duckdb.connect(":memory:")
    try:
        conn.execute(
            "CREATE TABLE ev ("
            "kind VARCHAR, value VARCHAR, source VARCHAR, "
            "category VARCHAR, title VARCHAR)"
        )
        conn.executemany(
            "INSERT INTO ev (kind, value, source, category, title) "
            "VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        # Static, parameter-free aggregation (only the numeric threshold is bound):
        # entity groups evidenced by >=2 distinct sources. list_sort keeps the
        # arrays order-independent so the result is reproducible regardless of
        # input order; the outer ORDER BY fixes the row order across runs.
        result = conn.execute(
            "SELECT kind, value, "
            "list_sort(list(DISTINCT source)) AS sources, "
            "list_sort(list(DISTINCT category)) AS categories, "
            "list_sort(list(DISTINCT title)) AS titles "
            "FROM ev "
            "GROUP BY kind, value "
            "HAVING COUNT(DISTINCT source) >= ? "
            "ORDER BY kind, value",
            (_CORROBORATION_MIN,),
        ).fetchall()
    finally:
        conn.close()

    return [
        ArtifactCorroboration(
            entity_kind=kind,
            entity_value=value,
            sources=tuple(sources),
            categories=tuple(c for c in categories if c),
            finding_titles=tuple(titles),
        )
        for (kind, value, sources, categories, titles) in result
    ]
