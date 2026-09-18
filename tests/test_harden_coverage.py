"""Coverage audit for the shipping harden path (SFE-fibx.5 PR-B).

The pre-existing ``assess_coverage`` distinguishes "looked and found nothing"
from "could not look" -- but that trichotomy is inert on the harden path, where
evidence arrives ALREADY PARSED (supplying an artifact class == the detector for
it ran), so nothing is ever "present but unevaluated" and its gap axis is
vacuously empty. This module computes the two coverage signals that ARE honest
and non-vacuous on that path:

  * ``uncited``: artifact classes that were supplied+parsed but that NO finding
    cites -- the real blind-spot detector ("we parsed the registry and drew no
    conclusion from it").
  * ``not_examined``: high/critical catalog classes whose evidence was not
    supplied this run -- so their silence is honestly not a clean bill of health.
"""

from __future__ import annotations

from sift_find_evil.coverage.harden_coverage import (
    COARSE_CLASSES,
    finding_supplied_class,
    harden_coverage,
    normalize_source,
)


class _Finding:
    """Minimal duck-typed finding: only ``artifact_sources`` is consulted."""

    def __init__(self, artifact_sources: list[str]):
        self.artifact_sources = list(artifact_sources)


# ---------------------------------------------------------------------------
# normalize_source: finding artifact-source token -> coarse supplied class
# ---------------------------------------------------------------------------


def test_normalize_disk_family_tokens():
    for token in ("$MFT", "MFT", "EventLog", "evtx", "disk", "disk_image"):
        assert normalize_source(token) == "disk", token


def test_normalize_usn_token_is_disk():
    assert normalize_source("$UsnJrnl:$J") == "disk"


def test_normalize_network_registry_memory_lnk_pst_yara():
    assert normalize_source("pcap") == "network"
    assert normalize_source("registry") == "registry"
    assert normalize_source("memory") == "memory"
    assert normalize_source("lnk_jumplist") == "lnk_jumplist"
    assert normalize_source("PST") == "pst"
    assert normalize_source("yara") == "yara"
    assert normalize_source("sigma_scan") == "yara"


def test_normalize_browser_history_is_network():
    # Regression: webmail/cloud-exfil findings stamp artifact_sources=
    # ["browser_history"] as their SOLE source when there is no pcap/mft
    # corroboration. If this did not normalize to network, a --browser-history
    # run whose only network finding is browser-only would report network as a
    # FALSE blind-spot (declared supplied, but never cite-able).
    assert normalize_source("browser_history") == "network"


def test_normalize_is_case_insensitive():
    assert normalize_source("mft") == "disk"
    assert normalize_source("Pcap") == "network"


def test_normalize_unknown_token_returns_none():
    # A token with no coarse mapping (e.g. a dynamic node id) contributes no
    # class rather than being force-fit into a wrong bucket.
    assert normalize_source("node-42") is None
    assert normalize_source("") is None


def test_every_coarse_class_is_a_known_class():
    # Every value normalize_source can emit must be in COARSE_CLASSES.
    for token in ("$MFT", "pcap", "registry", "memory", "lnk_jumplist", "PST", "yara"):
        assert normalize_source(token) in COARSE_CLASSES


# ---------------------------------------------------------------------------
# finding_supplied_class: a finding's coarse classes
# ---------------------------------------------------------------------------


def test_finding_with_multiple_sources_maps_all():
    f = _Finding(["MFT", "PST"])
    assert finding_supplied_class(f) == frozenset({"disk", "pst"})


def test_finding_with_no_sources_is_empty():
    assert finding_supplied_class(_Finding([])) == frozenset()


def test_finding_drops_unmappable_source():
    f = _Finding(["memory", "node-7"])
    assert finding_supplied_class(f) == frozenset({"memory"})


# ---------------------------------------------------------------------------
# harden_coverage: the two honest signals
# ---------------------------------------------------------------------------


def test_supplied_class_cited_by_a_finding_is_not_uncited():
    findings = [_Finding(["registry"]), _Finding(["memory"])]
    cov = harden_coverage(findings, supplied_classes={"registry", "memory"})
    assert cov.uncited == ()


def test_supplied_but_uncited_class_is_flagged():
    # registry was supplied+parsed, but no finding cites it -> a blind spot.
    findings = [_Finding(["memory"])]
    cov = harden_coverage(findings, supplied_classes={"registry", "memory"})
    assert cov.uncited == ("registry",)


def test_uncited_is_sorted_and_deduped():
    cov = harden_coverage([], supplied_classes={"registry", "network", "disk"})
    assert cov.uncited == ("disk", "network", "registry")


def test_not_examined_lists_high_critical_unsupplied_classes():
    # Only disk supplied. memory + registry (critical/high catalog classes) were
    # not examined this run, so their silence is not a clean result.
    cov = harden_coverage([_Finding(["MFT"])], supplied_classes={"disk"})
    assert "memory" in cov.not_examined
    assert "registry" in cov.not_examined
    # disk WAS supplied, so it is never in not_examined.
    assert "disk" not in cov.not_examined


def test_not_examined_excludes_supplied_classes():
    cov = harden_coverage(
        [_Finding(["memory"])],
        supplied_classes={"disk", "memory", "registry", "network"},
    )
    assert cov.not_examined == ()


def test_empty_supplied_is_honest_not_vacuous():
    # No evidence supplied at all: nothing uncited (nothing to cite), but every
    # high/critical class is not_examined -- the opposite of a vacuous clean pass.
    cov = harden_coverage([], supplied_classes=set())
    assert cov.uncited == ()
    assert cov.not_examined  # non-empty: we did not look at anything important


def test_supplied_classes_none_does_not_crash():
    # The signature is None-tolerant: a direct caller passing None (or omitting
    # the arg) must not crash. None behaves like an empty declared set.
    cov = harden_coverage([_Finding(["MFT"])])
    assert cov == harden_coverage([_Finding(["MFT"])], supplied_classes=set())


def test_supplied_classes_outside_the_vocabulary_are_ignored():
    # A caller passing an unknown/garbage class must not have it leak into
    # `supplied` (and thus never be reported uncited): only COARSE_CLASSES count.
    cov = harden_coverage(
        [_Finding(["memory"])],
        supplied_classes={"memory", "not_a_real_class", "DISK"},
    )
    assert cov.supplied == ("memory",)
    assert "not_a_real_class" not in cov.uncited
    assert "DISK" not in cov.uncited


def test_to_dict_is_serializable():
    cov = harden_coverage([_Finding(["MFT"])], supplied_classes={"disk", "registry"})
    d = cov.to_dict()
    assert set(d) == {"uncited", "not_examined", "supplied"}
    assert d["uncited"] == ["registry"]
    assert d["supplied"] == ["disk", "registry"]
    assert isinstance(d["not_examined"], list)


def test_coverage_is_read_only_over_findings():
    findings = [_Finding(["registry"])]
    before = [list(f.artifact_sources) for f in findings]
    harden_coverage(findings, supplied_classes={"registry"})
    after = [list(f.artifact_sources) for f in findings]
    assert before == after


def test_coverage_is_deterministic():
    findings = [_Finding(["memory"]), _Finding(["MFT"])]
    supplied = {"disk", "memory", "registry"}
    assert (
        harden_coverage(findings, supplied_classes=supplied).to_dict()
        == harden_coverage(findings, supplied_classes=supplied).to_dict()
    )


def test_result_is_frozen():
    import pytest

    cov = harden_coverage([], supplied_classes={"disk"})
    with pytest.raises((AttributeError, TypeError)):
        cov.uncited = ()  # type: ignore[misc]


# ---------------------------------------------------------------------------
# drift guards: keep the three maps consistent with the rest of the engine
# ---------------------------------------------------------------------------


def test_every_cli_declared_supplied_class_is_citeable():
    """Every coarse class the CLI can DECLARE supplied must be CITE-ABLE.

    The bug this guards: if the CLI declares a run supplied class X (via
    _ARG_TO_COVERAGE_CLASS) but no artifact_sources token normalizes to X (via
    _SOURCE_TO_COARSE), then X is ALWAYS uncited -- a permanent false blind spot,
    the exact browser_history->network defect this test was added for. The
    citeable set (values of _SOURCE_TO_COARSE) must therefore cover every class
    the CLI can declare (values of _ARG_TO_COVERAGE_CLASS).
    """
    from sift_find_evil.cli import _ARG_TO_COVERAGE_CLASS
    from sift_find_evil.coverage.harden_coverage import _SOURCE_TO_COARSE

    declarable = set(_ARG_TO_COVERAGE_CLASS.values())
    citeable = set(_SOURCE_TO_COARSE.values())
    missing = declarable - citeable
    assert not missing, (
        f"CLI can declare {missing} supplied, but no artifact_sources token "
        f"normalizes to it -> permanent false blind spot(s)"
    )


def test_catalog_to_coarse_covers_every_catalog_class():
    """Every ARTIFACT_CATALOG class must roll up into a coarse class.

    A catalog class missing from _CATALOG_TO_COARSE silently drops out of the
    not_examined signal, weakening the "we didn't look here" honesty check. Fails
    loudly so the map stays in lockstep with the catalog.
    """
    from sift_find_evil.coverage.audit import ARTIFACT_CATALOG
    from sift_find_evil.coverage.harden_coverage import _CATALOG_TO_COARSE

    missing = set(ARTIFACT_CATALOG) - set(_CATALOG_TO_COARSE)
    assert not missing, f"catalog classes missing from _CATALOG_TO_COARSE: {missing}"


def test_browser_history_only_finding_does_not_falsely_flag_network_uncited():
    """End-to-end of the regression: a browser-only network finding cites network.

    Mirrors a webmail-exfil finding with no pcap/mft corroboration. With network
    declared supplied, network must NOT appear uncited.
    """
    finding = _Finding(["browser_history"])
    cov = harden_coverage([finding], supplied_classes={"network"})
    assert cov.uncited == ()
