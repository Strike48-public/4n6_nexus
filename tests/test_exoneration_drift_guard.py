"""Drift-guard for the exonerating-resolution discriminator (SFE-h53w).

The hypothesis ledger logs a SUPPORTS->REFUTES self-correction only when a
finding's engine resolution EXONERATES it (clears the subject) rather than
CONFIRMS it. Historically that discrimination lived in a hard-coded frozenset
(``_EXONERATING_RESOLUTION_METHODS``) in ``orchestration.py``, decoupled from
the three ``Resolution`` construction sites in the engine. If the engine later
added or renamed an exonerating method, the frozenset would silently fall out of
sync and the ledger would stop logging that self-correction -- a false positive
the machinery exists to eliminate, with no test failure.

The fix co-locates the classification: every ``Resolution`` carries an
``is_exonerating`` flag set at its construction site, and the ledger reads that
flag. These tests pin the drift-proof contract: it is the FLAG, not the method
NAME, that drives exoneration.

RED-first: before the flag existed, ``_exonerating_resolution`` keyed on the
method name via the frozenset, so a flag-vs-name disagreement resolved the wrong
way (and constructing a ``Resolution`` with ``is_exonerating`` raised TypeError).
"""

from __future__ import annotations

from types import SimpleNamespace

from sift_find_evil.orchestration import InvestigationOrchestrator
from sift_find_evil.self_correction.confidence_scorer import Resolution


def _finding_with(resolution: Resolution) -> SimpleNamespace:
    """A minimal finding stub carrying a single resolution."""
    return SimpleNamespace(resolutions=[resolution])


def test_flag_true_exonerates_even_for_an_unknown_future_method() -> None:
    """A NEW exonerating method the frozenset never knew still exonerates.

    This is the drift the frozenset design missed: an engine that later emits a
    fresh benign-downgrade method under a name not in the hard-coded set would
    silently stop logging the elimination. Keying on the co-located flag makes
    the method name irrelevant, so a future exonerating resolution self-declares.
    """
    res = Resolution(
        contradiction_type="c2_no_dns",
        resolution_method="some_future_benign_downgrade",  # not in any set
        confidence_recovery=0.30,
        evidence={"note": "future benign infra rule"},
        is_exonerating=True,
    )
    result = InvestigationOrchestrator._exonerating_resolution(_finding_with(res))
    assert result is not None, "an is_exonerating=True resolution must exonerate"
    method, note = result
    assert method == "some_future_benign_downgrade"
    assert note == "future benign infra rule"


def test_flag_false_does_not_exonerate_even_for_the_benign_ip_method_name() -> None:
    """The historical benign-IP method name alone must NOT exonerate.

    Proves the discriminator no longer keys on the method string: a confirming
    resolution that happens to reuse a name is not treated as an elimination.
    """
    res = Resolution(
        contradiction_type="c2_no_dns",
        resolution_method="known_benign_direct_ip_infrastructure",
        confidence_recovery=0.30,
        evidence={"note": "not actually clearing the subject"},
        is_exonerating=False,
    )
    result = InvestigationOrchestrator._exonerating_resolution(_finding_with(res))
    assert result is None, "a non-exonerating resolution must not eliminate"


def test_confirming_resolutions_are_not_exonerating() -> None:
    """The two confirming methods carry is_exonerating=False by construction."""
    for method in ("psscan_confirms_unlinked_process", "event_log_confirms_prefetch"):
        res = Resolution(
            contradiction_type="x",
            resolution_method=method,
            confidence_recovery=0.30,
            evidence={},
            is_exonerating=False,
        )
        assert (
            InvestigationOrchestrator._exonerating_resolution(_finding_with(res))
            is None
        )


def test_no_resolutions_returns_none() -> None:
    assert InvestigationOrchestrator._exonerating_resolution(SimpleNamespace()) is None
