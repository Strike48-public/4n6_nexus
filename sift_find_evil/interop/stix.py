"""STIX 2.1 bundle export from findings (SFE-b0om).

A PURE, deterministic, read-only exporter turning findings into a STIX 2.1
bundle so they can be ingested by a TIP/SOAR without hand-translation. Nothing
here runs on the detection path, so F1 is unaffected.

The bundle carries, per finding:

  * one **Indicator** SDO per extracted IOC (a STIX pattern over the IP/hash),
  * one **attack-pattern** SDO per MITRE technique the guardrail CONFIRMED
    (grounded by a real finding, never an LLM guess -- see
    :func:`sift_find_evil.reporting.mitre_guardrail.confirmed_matrix`),
  * a **relationship** (``indicates``) linking each of a finding's indicators to
    each technique THAT SAME finding confirmed -- never a bundle-wide cross
    product, so an exfil IP is never said to "indicate" a persistence technique
    that came from a different finding, and
  * for a finding that yields NEITHER an IOC NOR a confirmed technique, a
    **file SCO + Observed-Data** built from the finding's subject name (so an
    IOC-less detection such as a timestomp on a local file is still represented),
    or, when the finding names no subject, a minimal custom
    **x-4n6nexus-finding** SDO. Either way the finding is represented in STIX
    rather than silently vanishing -- keeping STIX in parity with the OCSF/Wazuh
    exporters, which emit an event per finding.

Indicators, attack-patterns and their SCOs are DEDUPLICATED across findings by
their deterministic id, so two findings citing the same IP yield one indicator.

### Deterministic ids (documented deviation from the spec's SHOULD)

STIX 2.1 says SDOs SHOULD use a random UUIDv4. We instead give every object a
deterministic **UUIDv5** over the STIX namespace + its defining content, because
the issue requires idempotent re-ingest: re-running the engine on the same
evidence must yield the SAME ids so a TIP dedupes rather than duplicates. This is
a deliberate, tested choice -- do not "correct" it back to uuid4. Only the bundle
id is uuid4, since a bundle is a transient envelope, not a deduplicated entity.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from ..reporting.mitre_guardrail import confirmed_matrix
from .iocs import IocSet, finding_iocs

# STIX 2.1 namespace for deterministic UUIDv5 ids (OASIS spec, SCO id rules).
_STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
_SPEC_VERSION = "2.1"

# Internal category -> STIX indicator-types vocabulary. Attacker-behavior
# categories are malicious-activity; a meta finding about the analysis itself
# (ANALYSIS_GAP) or an unclassified one is anomalous-activity, never asserted as
# malicious. A finding whose category is not listed defaults to malicious-activity
# (every current attack category IS malicious).
_ANOMALOUS_CATEGORIES = {"analysis_gap", "unknown"}


def _now_stix() -> str:
    """RFC3339 UTC timestamp with a trailing ``Z`` (STIX timestamp format)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _det_id(stix_type: str, *parts: str) -> str:
    """A deterministic ``<type>--<uuidv5>`` id over the STIX namespace + parts."""
    name = "|".join([stix_type, *parts])
    return f"{stix_type}--{uuid.uuid5(_STIX_NAMESPACE, name)}"


def _get(finding: Any, key: str, default: Any) -> Any:
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


def _category_value(finding: Any) -> str:
    """The finding's category as a lowercase string (enum or plain str)."""
    category = _get(finding, "category", "unknown")
    return str(getattr(category, "value", category)).lower()


def _confidence_0_100(finding: Any) -> "int | None":
    """The finding's 0-1 confidence scaled to the STIX 0-100 integer, or None."""
    confidence = _get(finding, "confidence", None)
    if isinstance(confidence, (int, float)):
        return int(round(float(confidence) * 100))
    return None


def _indicator(
    pattern: str,
    name: str,
    ts: str,
    *,
    indicator_types: list[str],
    confidence: "int | None",
) -> dict:
    """Build one Indicator SDO with a deterministic (idempotent) id."""
    obj = {
        "type": "indicator",
        "spec_version": _SPEC_VERSION,
        "id": _det_id("indicator", pattern),
        "created": ts,
        "modified": ts,
        "name": name,
        "indicator_types": indicator_types,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ts,
    }
    if confidence is not None:
        obj["confidence"] = confidence
    return obj


def _ioc_patterns(iocs: IocSet) -> list[tuple[str, str]]:
    """Yield ``(pattern, name)`` for every IOC in an :class:`IocSet`.

    One place builds STIX patterns, reused for every finding, so the same IOC
    always derives the same pattern (and thus the same deterministic id).
    """
    out: list[tuple[str, str]] = []
    for value in iocs.sha256:
        out.append((f"[file:hashes.'SHA-256' = '{value}']", f"file {value}"))
    for value in iocs.md5:
        out.append((f"[file:hashes.MD5 = '{value}']", f"file {value}"))
    for value in iocs.ipv4:
        out.append((f"[ipv4-addr:value = '{value}']", f"ipv4 {value}"))
    for value in iocs.ipv6:
        out.append((f"[ipv6-addr:value = '{value}']", f"ipv6 {value}"))
    for value in iocs.domains:
        out.append((f"[domain-name:value = '{value}']", f"domain {value}"))
    return out


def _indicator_types_for(category: str) -> list[str]:
    """Map a finding category to the STIX indicator-types vocabulary."""
    if category in _ANOMALOUS_CATEGORIES:
        return ["anomalous-activity"]
    return ["malicious-activity"]


def _attack_pattern(entry: dict, ts: str) -> dict:
    """Build one attack-pattern SDO from a confirmed-technique entry."""
    technique_id = str(entry["technique_id"])
    name = str(entry.get("name") or technique_id)
    return {
        "type": "attack-pattern",
        "spec_version": _SPEC_VERSION,
        "id": _det_id("attack-pattern", technique_id),
        "created": ts,
        "modified": ts,
        "name": name,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": (
                    "https://attack.mitre.org/techniques/"
                    + technique_id.replace(".", "/")
                ),
            }
        ],
    }


def _relationship(source_ref: str, target_ref: str, ts: str) -> dict:
    """An ``indicates`` relationship SRO with a deterministic id."""
    return {
        "type": "relationship",
        "spec_version": _SPEC_VERSION,
        "id": _det_id("relationship", "indicates", source_ref, target_ref),
        "created": ts,
        "modified": ts,
        "relationship_type": "indicates",
        "source_ref": source_ref,
        "target_ref": target_ref,
    }


def _subject_name(finding: Any) -> "str | None":
    """The full process/file basename a finding is about, for a file SCO, or None.

    Reuses dedup's name-key PRIORITY (``executable`` > ``process`` > ... ) so the
    SCO names the same subject field the correlation join keys on -- but takes the
    UNTRUNCATED basename, not :func:`canonical_entity`'s value: that helper clips
    to 14 chars for EPROCESS memory matching, which would mislabel a disk file SCO
    (``ransom_note.ex`` instead of ``ransom_note.exe``). A file SCO wants the real
    name.
    """
    import ntpath

    from ..findings.dedup import _NAME_KEYS, _first_present

    evidence = _get(finding, "evidence", None)
    if not isinstance(evidence, dict):
        return None
    raw = _first_present(evidence, _NAME_KEYS)
    if not raw:
        return None
    return ntpath.basename(raw.strip().replace("/", "\\")) or None


def _file_observation(finding: Any, ts: str) -> list[dict]:
    """A file SCO + Observed-Data for an IOC-less finding that names a subject.

    Returns the two objects (SCO first) so a STIX consumer sees the file the
    finding is about even though it carries no atomic IOC. Empty list when the
    finding names no file subject (the caller falls back to a custom SDO).
    """
    name = _subject_name(finding)
    if not name:
        return []
    file_id = _det_id("file", name)
    file_sco = {
        "type": "file",
        "spec_version": _SPEC_VERSION,
        "id": file_id,
        "name": name,
    }
    observed = {
        "type": "observed-data",
        "spec_version": _SPEC_VERSION,
        "id": _det_id("observed-data", name),
        "created": ts,
        "modified": ts,
        "first_observed": ts,
        "last_observed": ts,
        "number_observed": 1,
        "object_refs": [file_id],
    }
    return [file_sco, observed]


def _custom_finding_sdo(finding: Any, ts: str) -> dict:
    """A minimal custom SDO for a finding with no IOC, technique, or subject.

    A last-resort representation so NO finding vanishes from STIX. Uses a custom
    ``x-4n6nexus-finding`` type (the STIX-sanctioned mechanism for content the
    core vocabulary doesn't cover) rather than mislabelling it as an indicator.
    """
    title = str(_get(finding, "title", "") or "Untitled finding")
    category = _category_value(finding)
    obj = {
        "type": "x-4n6nexus-finding",
        "spec_version": _SPEC_VERSION,
        "id": _det_id("x-4n6nexus-finding", title, category),
        "created": ts,
        "modified": ts,
        "name": title,
        "description": str(_get(finding, "description", "") or ""),
        "category": category,
    }
    confidence = _confidence_0_100(finding)
    if confidence is not None:
        obj["confidence"] = confidence
    return obj


def _finding_dict(finding: Any) -> dict:
    """Coerce a finding to the dict shape the MITRE guardrail consumes."""
    if isinstance(finding, dict):
        return finding
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    return {"title": _get(finding, "title", ""), "evidence": {}}  # pragma: no cover


def build_stix_bundle(findings: Iterable[Any], *, timestamp: str | None = None) -> dict:
    """Build a STIX 2.1 bundle from ``findings``.

    Args:
        findings: Findings (:class:`~sift_find_evil.findings.finding.Finding` or
            their ``to_dict`` mappings).
        timestamp: Optional fixed STIX timestamp (for deterministic tests). When
            omitted, the current UTC time is used. The timestamp does NOT enter
            any object id, so ids are stable regardless of when the bundle is built.

    Returns:
        A STIX 2.1 bundle dict: ``{type:"bundle", id, objects:[...]}``. Each
        object (not the bundle) carries ``spec_version:"2.1"``. Each finding's
        indicators link ONLY to the techniques that same finding confirmed
        (never a bundle-wide cross product); an IOC-less, technique-less finding
        is represented by a Note. An empty findings list yields a valid bundle
        with an empty ``objects`` list.
    """
    findings = list(findings)
    ts = timestamp or _now_stix()

    # Deduplicated object maps keyed by deterministic id, so two findings citing
    # the same IOC/technique share one object but ids stay stable across runs.
    objects: dict[str, dict] = {}
    relationship_pairs: set[tuple[str, str]] = set()

    for finding in findings:
        finding_dict = _finding_dict(finding)
        category = _category_value(finding)
        indicator_types = _indicator_types_for(category)
        confidence = _confidence_0_100(finding)

        # This finding's own indicators (deduped globally, but tracked locally so
        # relationships stay within the finding).
        local_indicator_ids: list[str] = []
        for pattern, name in _ioc_patterns(finding_iocs(finding)):
            indicator = _indicator(
                pattern,
                name,
                ts,
                indicator_types=indicator_types,
                confidence=confidence,
            )
            objects.setdefault(indicator["id"], indicator)
            local_indicator_ids.append(indicator["id"])

        # This finding's own confirmed techniques.
        local_attack_ids: list[str] = []
        for entry in confirmed_matrix([finding_dict]).confirmed:
            attack = _attack_pattern(entry, ts)
            objects.setdefault(attack["id"], attack)
            local_attack_ids.append(attack["id"])

        # Per-finding join ONLY: this finding's IOCs indicate this finding's
        # techniques -- never another finding's.
        for indicator_id in local_indicator_ids:
            for attack_id in local_attack_ids:
                relationship_pairs.add((indicator_id, attack_id))

        # A finding with neither an IOC nor a technique still gets represented,
        # so STIX stays in parity with OCSF/Wazuh: a file SCO + Observed-Data when
        # it names a subject, else a minimal custom SDO.
        if not local_indicator_ids and not local_attack_ids:
            observation = _file_observation(finding, ts)
            if observation:
                for obj in observation:
                    objects.setdefault(obj["id"], obj)
            else:
                sdo = _custom_finding_sdo(finding, ts)
                objects.setdefault(sdo["id"], sdo)

    # Sorted so bundle object order is deterministic regardless of set iteration.
    for source_ref, target_ref in sorted(relationship_pairs):
        rel = _relationship(source_ref, target_ref, ts)
        objects.setdefault(rel["id"], rel)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": list(objects.values()),
    }
