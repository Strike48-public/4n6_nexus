"""Entity canonicalization + cross-source finding dedup .

A single canonical identity for the subject of a finding, so equivalent findings
from different sources collapse to ONE entity: a disk MFT record for
``crypt_engine.exe`` and a memory ``_EPROCESS`` truncated to ``crypt_engine.ex``
name the SAME process. Two DISTINCT identities serve two distinct purposes:

  * :func:`canonical_entity` - a CATEGORY-AGNOSTIC entity key. ENABLES same-actor
    cross-source correlation (SFE-1fkn): the correlation join keys on this, so a
    subject seen across disk + memory + network is one candidate regardless of
    what each source concluded about it.
  * :func:`fingerprint` - a CATEGORY-AWARE dedup key. :func:`dedupe_findings`
    keeps the first finding per fingerprint. Because the category is part of the
    key, two genuinely different behaviors on ONE entity (an injection AND a
    timestomp on the same binary) both survive; only true restatements collapse.
    In DFIR the dangerous direction is dropping a real finding, so dedup errs
    toward keeping.

Both are pure, deterministic, read-only OVERLAYS. Nothing here runs on the
detection scoring path (findings still score off ``evidence['executable']`` in
the harness), so F1 is unaffected.

Entity identity priority (most to least specific), mirroring how detectors
populate ``evidence``:

  1. a cryptographic hash (``sha256`` > ``md5`` > ``hash`` / ``imphash``)
  2. an IP address (``dst_ip`` > ``foreign_addr`` > ``src_ip`` > ``remote_ip``
     > ``ip``)
  3. a relationship pair (``parent`` -> ``child``) - kept as an ORDERED pair so a
     spawn edge is never reduced to a single subject (which would collide with
     unrelated findings about the parent)
  4. a process / file name (``executable`` > ``process`` > ``image`` >
     ``path`` > ``target_path``), canonicalized by :func:`canonicalize_name`

An entity value that is empty after trimming (a whitespace-only hash/IP) is
skipped and the next identity kind is tried, so a blank field never becomes a
garbage key that merges unrelated findings.

Volatile fields (timestamps, ``source_tools``) never enter the identity, so two
observations of the same entity at different times still collapse. ``pid`` is
deliberately excluded: a memory finding carries a pid and a disk finding does
not, and the join must survive that asymmetry.

### Why the truncation length is 14, not 15

``_EPROCESS.ImageFileName`` is a ``UCHAR[15]`` buffer, so a long process name is
stored truncated to 15 bytes. The sibling cross-source correlator
(``correlation/cross_source.py``) clips to 15 (``_EPROCESS_NAME_LEN``) and then
does a FUZZY prefix match at runtime. This module needs a HASHABLE equality key
instead, so it clips to **14** - one shorter, at the truncation boundary.
Clipping to 14 collapses BOTH truncation shapes to one key: the full 15-byte
form (``crypt_engine.ex`` from a 16-char name) and the null-terminator-lost
14-byte form.

The exact relationship this module guarantees against the correlator is narrow
and testable: ``canonicalize_name(x)`` equals ``normalize_eprocess_name(x)``
clipped to 14, and the two clip lengths differ by exactly 1. A test pins both
(the shared basename/lowercase contract and the 1-char offset) so the forms
cannot silently drift. This does NOT claim general agreement with the
correlator's fuzzy matcher: two 15+ char names sharing a 14-char prefix collapse
to one key here (intended, for the truncation goal) while the correlator's
prefix matcher may keep them distinct.
"""

from __future__ import annotations

import ntpath
from dataclasses import dataclass
from typing import Any, Iterable, Optional

# Hashable dedup key equality clips a process/file basename to this length. See
# the module docstring ("Why the truncation length is 14, not 15"): 14 is the
# EPROCESS truncation boundary, so both the 15-byte-buffer form and the
# null-terminator-lost form collapse to one key.
_NAME_CLIP_LEN = 14

# Evidence keys that name each entity kind, in descending specificity. The first
# present, non-empty (after trimming) key of each group wins.
_HASH_KEYS = ("sha256", "md5", "hash", "imphash")
_IP_KEYS = ("dst_ip", "foreign_addr", "src_ip", "remote_ip", "ip")
_NAME_KEYS = ("executable", "process", "image", "path", "target_path")


@dataclass(frozen=True)
class EntityRef:
    """A canonical entity identity: a ``kind`` and its normalized ``value``.

    Frozen and hashable so it can key a dict/set directly (used by the SFE-1fkn
    correlation join and, wrapped in a :class:`FindingFingerprint`, by
    :func:`dedupe_findings`).

    Attributes:
        kind: One of ``"hash"``, ``"ip"``, ``"relationship"``, ``"process"``,
            or ``"title"`` (the fallback).
        value: The normalized identity string for that kind.
    """

    kind: str
    value: str


@dataclass(frozen=True)
class FindingFingerprint:
    """A dedup identity: an entity/title :class:`EntityRef` plus the category.

    Only findings sharing BOTH the same canonical identity AND the same category
    collapse under :func:`dedupe_findings`, so two different behaviors on one
    entity (e.g. an injection and a timestomp on the same binary) both survive.
    The category-agnostic entity join used for correlation is
    :func:`canonical_entity`, not this.

    Attributes:
        identity: The finding's entity ref, or a ``"title"`` ref when the finding
            names no structured entity.
        category: The finding's category value (a string).
    """

    identity: EntityRef
    category: str


def canonicalize_name(name: str) -> str:
    """Canonicalize a process/file name to a comparable key.

    Takes the basename (after normalizing ``/`` and ``\\Device\\HarddiskVolumeN``
    forms to Windows separators), lowercases it, and clips to the EPROCESS
    truncation boundary (:data:`_NAME_CLIP_LEN`) so a full disk name and its
    truncated memory form produce the same key.

    Args:
        name: A raw process name or file path from finding evidence.

    Returns:
        The canonical lowercased, clipped basename. Empty string for empty input.
    """
    if not name:
        return ""
    # Normalize forward slashes to Windows separators so ntpath.basename works on
    # both "/tmp/evil.sh" and "\\Device\\HarddiskVolume2\\...\\evil.exe". The
    # \Device\HarddiskVolumeN prefix is just leading path components, so taking
    # the basename drops it without a dedicated strip step.
    base = ntpath.basename(name.strip().replace("/", "\\"))
    return base.lower()[:_NAME_CLIP_LEN]


def _get_field(finding: Any, name: str) -> Any:
    """Read ``name`` from a Finding-like object OR a plain dict.

    Findings are sometimes serialized to plain dicts (``Finding.to_dict``), so a
    caller may hand us either shape. A dict is read by key, anything else by
    attribute. Returning the wrong thing here would silently collapse distinct
    findings, so both shapes are supported explicitly rather than via ``getattr``
    (which never sees a dict's keys).
    """
    if isinstance(finding, dict):
        return finding.get(name)
    return getattr(finding, name, None)


def _scalar(value: Any) -> Optional[str]:
    """Coerce an evidence value to a trimmed identity string, or None if unusable.

    Absent, empty, and whitespace-only values are None. A list/tuple contributes
    its first usable element (a single-element ``dst_ip`` list must join with the
    scalar form), never its Python ``repr``. Mappings are rejected: there is no
    meaningful single-entity string for a dict-valued field.
    """
    if value is None or isinstance(value, dict):
        return None
    if isinstance(value, (list, tuple)):
        for item in value:
            got = _scalar(item)
            if got:
                return got
        return None
    text = str(value).strip()
    return text or None


def _first_present(evidence: dict, keys: Iterable[str]) -> Optional[str]:
    """Return the first value among ``keys`` that yields a usable scalar.

    A whitespace-only, empty, or container-only value is treated as absent so a
    blank or structurally-wrong field never becomes a key. The returned string is
    already trimmed.
    """
    for key in keys:
        got = _scalar(evidence.get(key))
        if got:
            return got
    return None


def canonical_entity(finding: Any) -> Optional[EntityRef]:
    """Derive the canonical entity a finding is ABOUT, or None if it has none.

    Applies the identity priority documented in the module docstring
    (hash > ip > relationship > process/file name), skipping any candidate that
    is empty after trimming. ``pid`` is intentionally ignored so the cross-source
    join survives a memory-vs-disk pid asymmetry. Category-agnostic by design:
    this is the correlation join key.

    Args:
        finding: A :class:`~sift_find_evil.findings.finding.Finding`, or the plain
            dict it serializes to (:meth:`Finding.to_dict`). The ``evidence``
            mapping is read from either shape.

    Returns:
        An :class:`EntityRef`, or ``None`` when no structured entity is present.
    """
    evidence = _get_field(finding, "evidence")
    if not isinstance(evidence, dict):
        return None

    digest = _first_present(evidence, _HASH_KEYS)
    if digest:
        return EntityRef("hash", digest.lower())

    ip = _first_present(evidence, _IP_KEYS)
    if ip:
        # Lowercased so IPv6 (hex, case-insensitive) unifies across tools that
        # emit different casing; harmless for IPv4.
        return EntityRef("ip", ip.lower())

    parent = _scalar(evidence.get("parent"))
    child = _scalar(evidence.get("child"))
    if parent and child:
        canon_parent = canonicalize_name(parent)
        canon_child = canonicalize_name(child)
        # Ordered pair: parent->child is directional, and a relationship is never
        # reduced to a single subject. Both ends must canonicalize non-empty, or a
        # degenerate ">" key would merge unrelated pairs.
        if canon_parent and canon_child:
            return EntityRef("relationship", f"{canon_parent}>{canon_child}")

    name = _first_present(evidence, _NAME_KEYS)
    if name:
        canon = canonicalize_name(name)
        if canon:
            return EntityRef("process", canon)

    return None


def _normalize_title(title: str) -> str:
    """Collapse internal/edge whitespace and lowercase a title for fallback keys."""
    return " ".join(title.split()).lower()


def fingerprint(finding: Any) -> FindingFingerprint:
    """Return a category-aware dedup identity for a finding.

    Combines :func:`canonical_entity` (or a ``"title"`` ref when the finding names
    no structured entity) with the finding's category, so :func:`dedupe_findings`
    collapses only true restatements and preserves distinct behaviors on one
    entity. For the category-agnostic entity join used by correlation, call
    :func:`canonical_entity` directly.

    Args:
        finding: A :class:`~sift_find_evil.findings.finding.Finding`, or the plain
            dict it serializes to. ``evidence``, ``title`` and ``category`` are
            read from either shape.

    Returns:
        A :class:`FindingFingerprint` that is equal for equivalent findings of the
        same category.
    """
    entity = canonical_entity(finding)
    if entity is None:
        entity = EntityRef(
            "title", _normalize_title(str(_get_field(finding, "title") or ""))
        )

    category = _get_field(finding, "category")
    # A dict-serialized finding stores the category as a plain string; a live
    # Finding stores a FindingCategory enum whose .value is that string.
    cat_value = getattr(category, "value", category)
    return FindingFingerprint(identity=entity, category=str(cat_value))


def dedupe_findings(findings: list) -> list:
    """Return findings with duplicate restatements collapsed, order preserved.

    Keeps the FIRST finding for each :func:`fingerprint` and drops every later
    finding with the same (entity, category) identity. Two findings about the
    same entity but with different categories both survive. The input list is
    never mutated.

    Args:
        findings: Findings in emission order.

    Returns:
        A new list containing the first finding per fingerprint, in the order
        those first occurrences appeared.
    """
    seen: set[FindingFingerprint] = set()
    out: list = []
    for finding in findings:
        key = fingerprint(finding)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out
