"""Tests for the entity fingerprint / cross-source dedup .

A canonical entity key collapses equivalent findings across sources to ONE
identity: a disk MFT record for ``crypt_engine.exe`` and a memory ``_EPROCESS``
truncated to ``crypt_engine.ex`` are the SAME process. This is the enabler for
same-actor cross-source correlation (SFE-1fkn) and cuts double-counting.

Each behavior has an inverse/negative control, and the truncation-length choice
(14, the EPROCESS boundary) is guarded so it cannot silently drift.
"""

from __future__ import annotations

from sift_find_evil.correlation.cross_source import (
    _EPROCESS_NAME_LEN,
    normalize_eprocess_name,
)
from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.findings.dedup import (
    _NAME_CLIP_LEN,
    EntityRef,
    canonical_entity,
    canonicalize_name,
    dedupe_findings,
    fingerprint,
)


def _finding(
    *,
    title: str = "t",
    category: FindingCategory = FindingCategory.EXECUTION,
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        title=title,
        description="d",
        finding_type="indicator",
        severity="high",
        category=category,
        evidence=evidence or {},
    )


# --- canonicalize_name -----------------------------------------------------


def test_canonicalize_name_takes_basename_lowers_and_clips_to_14() -> None:
    # A full disk path collapses to the lowercased 14-char basename.
    assert canonicalize_name(r"C:\Users\alice\Crypt_Engine.exe") == "crypt_engine.e"


def test_canonicalize_name_strips_device_harddiskvolume_prefix() -> None:
    dev = r"\Device\HarddiskVolume2\Users\alice\crypt_engine.exe"
    win = r"C:\Users\alice\crypt_engine.exe"
    # Both physical-volume and drive-letter forms canonicalize identically.
    assert canonicalize_name(dev) == canonicalize_name(win) == "crypt_engine.e"


def test_canonicalize_name_handles_forward_slashes() -> None:
    assert canonicalize_name("/tmp/EVIL.sh") == "evil.sh"


def test_eprocess_truncation_forms_collapse_to_one_key() -> None:
    # 15-byte-buffer truncation ("crypt_engine.ex") and the full disk name
    # ("crypt_engine.exe", 16 chars) must map to the SAME 14-char canonical key.
    mem_truncated = "crypt_engine.ex"  # what Volatility surfaces
    disk_full = "crypt_engine.exe"
    assert canonicalize_name(mem_truncated) == canonicalize_name(disk_full)


def test_null_terminator_lost_form_also_collapses() -> None:
    # The other truncation shape: the trailing char is lost to a null terminator,
    # so memory shows a 14-char name. Clipping to 14 still collapses it with disk.
    assert canonicalize_name("iCloudDrive.ex") == canonicalize_name(
        r"C:\Program Files\iCloudDrive.exe"
    )


def test_distinct_binaries_do_not_collapse() -> None:
    # Negative control: two genuinely different short names stay distinct.
    assert canonicalize_name("evil.exe") != canonicalize_name("calc.exe")


# --- canonical_entity ------------------------------------------------------


def test_canonical_entity_prefers_hash_over_ip_and_process() -> None:
    f = _finding(
        evidence={"sha256": "ABC123", "dst_ip": "203.0.113.66", "process": "x.exe"}
    )
    assert canonical_entity(f) == EntityRef("hash", "abc123")


def test_canonical_entity_prefers_ip_over_process() -> None:
    f = _finding(evidence={"foreign_addr": "203.0.113.66", "process": "x.exe"})
    assert canonical_entity(f) == EntityRef("ip", "203.0.113.66")


def test_canonical_entity_process_from_executable_path() -> None:
    f = _finding(evidence={"executable": r"C:\Users\a\Crypt_Engine.exe"})
    assert canonical_entity(f) == EntityRef("process", "crypt_engine.e")


def test_canonical_entity_ignores_pid_so_it_joins_across_sources() -> None:
    # A memory process finding (has pid) and a disk finding (no pid) for the same
    # image must produce the SAME entity: pid must NOT be part of the identity or
    # the cross-source join in SFE-1fkn cannot fire.
    mem = _finding(evidence={"process": "crypt_engine.ex", "pid": 4321})
    disk = _finding(evidence={"path": r"\Device\HarddiskVolume2\a\crypt_engine.exe"})
    assert canonical_entity(mem) == canonical_entity(disk)
    assert canonical_entity(mem) == EntityRef("process", "crypt_engine.e")


def test_canonical_entity_none_when_no_structured_entity() -> None:
    assert canonical_entity(_finding(evidence={"note": "nothing structured"})) is None


# --- fingerprint -----------------------------------------------------------


def test_canonical_entity_collapses_same_actor_across_sources_and_categories() -> None:
    # The correlation join key (category-AGNOSTIC): a memory injection finding and
    # a disk timestomp finding about the same binary are the SAME actor entity,
    # even though their categories differ. This is what SFE-1fkn joins on.
    mem = _finding(
        title="Injected process crypt_engine.ex",
        category=FindingCategory.PROCESS_INJECTION,
        evidence={"process": "crypt_engine.ex", "pid": 4321},
    )
    disk = _finding(
        title="Timestomped binary crypt_engine.exe",
        category=FindingCategory.ANTI_FORENSICS,
        evidence={"path": r"\Device\HarddiskVolume2\a\crypt_engine.exe"},
    )
    assert canonical_entity(mem) == canonical_entity(disk)


def test_fingerprint_collapses_same_entity_same_category_across_sources() -> None:
    # The dedup key (category-AWARE): two restatements of the SAME finding about
    # one binary (same category, memory-truncated vs disk-full name) collapse.
    mem = _finding(
        category=FindingCategory.PROCESS_INJECTION,
        evidence={"process": "crypt_engine.ex", "pid": 4321},
    )
    disk = _finding(
        category=FindingCategory.PROCESS_INJECTION,
        evidence={"path": r"\Device\HarddiskVolume2\a\crypt_engine.exe"},
    )
    assert fingerprint(mem) == fingerprint(disk)


def test_fingerprint_excludes_volatile_fields() -> None:
    # Timestamps and source-tool lists must not enter the fingerprint, or two
    # observations of the same entity at different times would not collapse.
    a = _finding(
        evidence={
            "process": "evil.exe",
            "first_seen": "2026-01-01T00:00:00Z",
            "source_tools": ["pslist"],
        }
    )
    b = _finding(
        evidence={
            "process": "evil.exe",
            "first_seen": "2026-06-06T12:00:00Z",
            "source_tools": ["psscan", "malfind"],
        }
    )
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_relationship_finding_keys_on_ordered_pair() -> None:
    # A parent->child relationship's identity is the PAIR; it is never reduced to
    # a single subject (which would collide with unrelated findings about parent).
    rel = _finding(
        category=FindingCategory.EXECUTION,
        evidence={"parent": "services.exe", "child": "cmd.exe"},
    )
    single_parent = _finding(
        category=FindingCategory.EXECUTION, evidence={"process": "services.exe"}
    )
    assert fingerprint(rel) != fingerprint(single_parent)


def test_fingerprint_relationship_direction_matters() -> None:
    ab = _finding(evidence={"parent": "a.exe", "child": "b.exe"})
    ba = _finding(evidence={"parent": "b.exe", "child": "a.exe"})
    # parent->child is directional: A spawns B is not the same as B spawns A.
    assert fingerprint(ab) != fingerprint(ba)


def test_fingerprint_falls_back_to_category_and_title() -> None:
    a = _finding(title="Suspicious PowerShell", category=FindingCategory.EXECUTION)
    b = _finding(title="suspicious powershell  ", category=FindingCategory.EXECUTION)
    # No structured entity: title (normalized) + category is the identity.
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_distinct_entities_stay_distinct() -> None:
    a = _finding(evidence={"dst_ip": "203.0.113.66"})
    b = _finding(evidence={"dst_ip": "8.8.8.8"})
    assert fingerprint(a) != fingerprint(b)


# --- empty / malformed entity fields ---------------------------------------


def test_whitespace_only_hash_is_skipped_not_used_as_key() -> None:
    # A blank hash must NOT become EntityRef("hash", "") and merge unrelated
    # findings; the entity falls through to the next identity kind (here, none).
    a = _finding(evidence={"sha256": "   ", "note": "x"})
    b = _finding(evidence={"sha256": "\t\n", "note": "y"})
    assert canonical_entity(a) is None
    assert canonical_entity(b) is None


def test_whitespace_hash_falls_through_to_process_name() -> None:
    f = _finding(evidence={"sha256": "  ", "process": "evil.exe"})
    assert canonical_entity(f) == EntityRef("process", "evil.exe")


def test_blank_entities_do_not_merge_distinct_findings() -> None:
    # Negative control for the whitespace-key bug: two findings with blank IPs but
    # different real subjects must stay distinct, not collapse to one ip key.
    a = _finding(
        category=FindingCategory.EXECUTION,
        evidence={"dst_ip": " ", "process": "a.exe"},
    )
    b = _finding(
        category=FindingCategory.EXECUTION,
        evidence={"dst_ip": " ", "process": "b.exe"},
    )
    assert fingerprint(a) != fingerprint(b)
    assert len(dedupe_findings([a, b])) == 2


def test_ipv6_identity_is_case_insensitive() -> None:
    # IPv6 is hex and case-insensitive; differing casing from two tools must
    # unify or the same-actor join misses the match.
    upper = _finding(evidence={"dst_ip": "FE80::1"})
    lower = _finding(evidence={"dst_ip": "fe80::1"})
    assert canonical_entity(upper) == canonical_entity(lower)


def test_list_valued_field_joins_with_its_scalar_form() -> None:
    # A single-element dst_ip list must produce the SAME entity as the scalar,
    # not a Python-repr key like "['203.0.113.66']" that defeats the join.
    scalar = _finding(evidence={"dst_ip": "203.0.113.66"})
    listed = _finding(evidence={"dst_ip": ["203.0.113.66"]})
    assert canonical_entity(listed) == canonical_entity(scalar)
    assert canonical_entity(listed) == EntityRef("ip", "203.0.113.66")


def test_mapping_valued_field_is_skipped_not_repr_keyed() -> None:
    # A dict-valued identity field has no meaningful single-entity string; it must
    # fall through, not become str(dict).
    f = _finding(evidence={"sha256": {"weird": "shape"}, "process": "evil.exe"})
    assert canonical_entity(f) == EntityRef("process", "evil.exe")


def test_relationship_needs_both_ends_non_empty_after_canonicalize() -> None:
    # Both parent and child must canonicalize to non-empty, or a degenerate ">"
    # key would merge unrelated findings.
    degenerate = _finding(evidence={"parent": "///", "child": "\\"})
    assert canonical_entity(degenerate) is None


# --- dict-serialized findings (Finding.to_dict shape) ----------------------


def test_canonical_entity_reads_plain_dict_finding() -> None:
    # Findings are serialized to plain dicts (Finding.to_dict); the entity must be
    # read from the dict's "evidence" KEY, not a (nonexistent) attribute.
    d = {"evidence": {"process": "crypt_engine.ex"}, "title": "t", "category": "x"}
    assert canonical_entity(d) == EntityRef("process", "crypt_engine.e")


def test_dict_and_object_findings_share_one_identity() -> None:
    # The Finding object and its to_dict() form must fingerprint identically, so
    # deduping a mix (or a post-serialization list) does not silently drop either.
    obj = _finding(category=FindingCategory.EXECUTION, evidence={"process": "evil.exe"})
    as_dict = obj.to_dict()
    assert fingerprint(obj) == fingerprint(as_dict)


def test_dedupe_does_not_collapse_distinct_dict_findings() -> None:
    # Regression for the "plain dict -> all merge" trap: distinct dict findings
    # must stay distinct (getattr would have returned None for every one).
    a = {"evidence": {"process": "a.exe"}, "title": "a", "category": "execution"}
    b = {"evidence": {"process": "b.exe"}, "title": "b", "category": "execution"}
    assert len(dedupe_findings([a, b])) == 2


# --- dedupe_findings -------------------------------------------------------


def test_dedupe_keeps_first_occurrence_and_preserves_order() -> None:
    f1 = _finding(title="first", evidence={"process": "crypt_engine.ex"})
    f2 = _finding(title="second", evidence={"dst_ip": "203.0.113.66"})
    f3 = _finding(  # duplicate of f1 by entity (disk form of the same image)
        title="third",
        evidence={"path": r"C:\a\crypt_engine.exe"},
    )
    out = dedupe_findings([f1, f2, f3])
    assert [f.title for f in out] == ["first", "second"]


def test_dedupe_empty_is_empty() -> None:
    assert dedupe_findings([]) == []


def test_dedupe_does_not_mutate_input() -> None:
    findings = [_finding(evidence={"process": "a.exe"})]
    dedupe_findings(findings)
    assert len(findings) == 1


def test_dedupe_preserves_distinct_categories_on_same_entity() -> None:
    # A real DFIR case: one binary is BOTH injected and timestomped. Both findings
    # must survive dedup; collapsing them by entity alone would silently drop a
    # real finding (the dangerous direction).
    injection = _finding(
        title="injected",
        category=FindingCategory.PROCESS_INJECTION,
        evidence={"process": "crypt_engine.exe"},
    )
    timestomp = _finding(
        title="timestomped",
        category=FindingCategory.ANTI_FORENSICS,
        evidence={"process": "crypt_engine.exe"},
    )
    out = dedupe_findings([injection, timestomp])
    assert [f.title for f in out] == ["injected", "timestomped"]


# --- consistency guard: must not drift from the correlator ------------------


def test_shares_basename_lowercase_contract_with_correlator() -> None:
    # This module's key must be exactly the correlator's normalized name clipped
    # to our length, across a range of shapes (paths, slashes, case, truncation).
    # If someone changes the basename/lowercase contract in either module without
    # the other, this fails. (This does NOT claim agreement with the correlator's
    # fuzzy prefix matcher for 15+ char names -- only the normalizer contract.)
    for raw in [
        r"C:\Users\alice\Crypt_Engine.exe",
        r"\Device\HarddiskVolume2\a\crypt_engine.exe",
        "/tmp/EVIL.sh",
        "crypt_engine.ex",
        "AaBbCcDdEeFfGgHhIi.exe",  # long enough to exercise the clip
    ]:
        assert canonicalize_name(raw) == normalize_eprocess_name(raw)[:_NAME_CLIP_LEN]


def test_clip_lengths_differ_by_exactly_one() -> None:
    # The whole "14 collapses both truncation shapes" argument rests on our clip
    # being exactly one shorter than the correlator's EPROCESS buffer length. Pin
    # it: if either constant moves independently, this fails loudly.
    assert _EPROCESS_NAME_LEN - _NAME_CLIP_LEN == 1


def test_names_differing_only_past_the_clip_do_collapse_here() -> None:
    # Documents (not laments) the intended over-collapse: two 15+ char names that
    # first differ at position 15 share our 14-char key. This is the price of a
    # hashable truncation-safe key and is expected for the SFE-1fkn join.
    a = "abcdefghijklmnOPQ.exe"
    b = "abcdefghijklmnXYZ.exe"
    assert canonicalize_name(a) == canonicalize_name(b) == "abcdefghijklmn"


# --- mutation guards --------------------------------------------------------


def test_mutation_guard_clip_length_must_collapse_truncation() -> None:
    # Guards the _NAME_CLIP_LEN=14 choice: if it drifts to 15 (or 16), the disk
    # form "crypt_engine.exe" (16 chars) and memory form "crypt_engine.ex" (15)
    # would NO LONGER collapse, silently breaking the cross-source join.
    assert canonicalize_name("crypt_engine.exe") == canonicalize_name("crypt_engine.ex")
    # And the collapsed key is exactly the 14-char boundary form.
    assert canonicalize_name("crypt_engine.exe") == "crypt_engine.e"


def test_mutation_guard_pid_excluded_from_identity() -> None:
    # Guards the "ignore pid" rule: if pid were folded into the identity, the
    # memory finding (pid present) and disk finding (pid absent) for one image
    # would get different fingerprints and the SFE-1fkn join would never fire.
    with_pid = _finding(evidence={"process": "evil.exe", "pid": 1234})
    without_pid = _finding(evidence={"process": "evil.exe"})
    assert fingerprint(with_pid) == fingerprint(without_pid)
