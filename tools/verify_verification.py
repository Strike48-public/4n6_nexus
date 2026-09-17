#!/usr/bin/env python3
"""Standalone offline verifier for 4n6 Nexus adversarial-verification verdicts.

Third companion to ``tools/verify_receipts.py`` (finding receipts + run anchor) and
``tools/verify_chain.py`` (the audit hash-chain). This one independently re-derives
the ADVERSARIAL VERIFICATION tier: for every finding in a hardening / orchestrator
report it re-runs

  * the LLM-free ENTAILMENT challenge - does each identity anchor the finding
    asserts (an IP, a PID) actually appear, on a token boundary, in the raw
    evidence span the detector consumed? - reproducing the falsifier's status, and
  * the deterministic ADJUDICATOR ladder over (falsifier status, corroboration
    count), reproducing the recorded outcome.

It then confirms the verdict it re-derives matches the ``outcome`` / ``falsifier_
status`` the engine recorded. A recorded ``sustained``/``survived`` whose evidence
span does not actually contain the asserted anchor is caught: re-derivation yields
``falsified`` and the recorded verdict is flagged as not reproducible.

Like the other two verifiers it is DELIBERATELY self-contained: it imports nothing
from ``sift_find_evil`` and re-implements the token-boundary entailment match and
the adjudication rules from the Python standard library. That is what lets a third
party (a court, an auditor, a downstream consumer) re-run the verification tier with
no engine and no live model - the exact bar the field's verification "5"s clear via
"LLM-free entailment + replay". If this reader and the engine's writer ever disagree
about the entailment or adjudication contract, a pristine report fails here (drift
detection).

The re-derivation inputs it consumes are recorded by ``sift_find_evil/hardening.py``
``_adversarial_ruling`` into each finding's ``adversarial`` block:

    "adversarial": {
        "outcome": "sustained",              # the recorded adjudication
        "falsifier_status": "survived",      # the recorded challenge result
        "falsifier_family": "entailment-rederivation",
        "architectural_distance": 1.0,
        "anchors": [{"path": "dst_ip", "expected": "10.0.0.9", "kind": "ipv4"}],
        "evidence_span": "outbound to 10.0.0.9 seen",  # None on the null-falsifier
        "corroboration": 2
    }

Two levels of guarantee, reported honestly per finding:
  * INDEPENDENT: ``evidence_span`` present -> both the falsifier status AND the
    outcome are re-derived from evidence + rules (the strong claim).
  * ADJUDICATION-CONSISTENT: ``evidence_span`` is None (the engine's null-falsifier
    fallback, when a finding asserts no re-derivable anchor or no raw evidence was
    threaded) -> the status cannot be reproduced from evidence, so the outcome is
    re-checked against the recorded status + corroboration via the ladder.
    Independence is NOT claimed for these. Crucially, the null falsifier ALWAYS
    SURVIVES (it is unconditional), so a non-``survived`` status on this path is a
    shape the engine never emits and is REJECTED - closing a suppression vector
    where a forged ``falsified`` + ``evidence_span=None`` would dodge the entailment
    check to dismiss a genuine finding.

Usage:
    python3 tools/verify_verification.py <report.json>
    # Reads findings from either a hardening report ("hardened") or a live
    # orchestrator report ("case_findings").

Exit codes (semantic):
    0  every recorded verdict is reproducible (or the report has no findings)
    1  a recorded verdict does not follow from its recorded inputs (tamper/drift)
    2  file error (missing file, bad JSON, wrong shape)

Contracts this file MUST mirror (kept in sync by the round-trip tests in
tests/test_verify_verification_tool.py, which harden real findings and re-verify):
    entailment  -> sift_find_evil/findings/entailment.py
    adjudicator -> sift_find_evil/self_correction/adversarial.py (RulesAdjudicator)
"""

from __future__ import annotations

import json
import re
import sys

# --- entailment contract (mirror of sift_find_evil/findings/entailment.py) ------

# A generic token shorter than this matches too much noise to be evidence.
_GENERIC_MIN_LENGTH = 4

# Per-kind continuation character class: a match is only accepted when it is not
# preceded or followed by one of these (a token boundary appropriate to the kind).
_BOUNDARY_CLASSES = {
    "pid": r"0-9",
    "hash": r"0-9a-fA-F",
    "ipv4": r"0-9.",
    "ipv6": r"0-9a-fA-F:",
    "filename": r"A-Za-z0-9_",
    "generic": r"A-Za-z0-9_",
}
_DEFAULT_BOUNDARY_CLASS = r"A-Za-z0-9_"

# --- adjudicator contract (mirror of RulesAdjudicator, in the hardening path) ---
# In sift_find_evil/hardening.py the adversarial pass always runs with
# analyst_verdict="confirmed" (affirmative) and remand_count=0, so the reachable
# ladder is exactly: FALSIFIED->dismissed; INCONCLUSIVE->remanded;
# SURVIVED & corroboration>=2 -> sustained; SURVIVED & corroboration<2 -> remanded.
_MIN_CORROBORATION = 2

_SURVIVED = "survived"
_FALSIFIED = "falsified"
_INCONCLUSIVE = "inconclusive"


def _appears_on_boundary(expected: str, kind: str, observed_text: str) -> bool:
    """True iff ``expected`` occurs on a token boundary for its kind in the text."""
    if not expected or not observed_text:
        return False
    cls = _BOUNDARY_CLASSES.get(kind, _DEFAULT_BOUNDARY_CLASS)
    pattern = rf"(?<![{cls}]){re.escape(expected)}(?![{cls}])"
    return re.search(pattern, observed_text) is not None


def _value_matched(expected: str, kind: str, observed_text: str) -> bool:
    """Re-derive whether a single asserted value is accepted as support."""
    observed = _appears_on_boundary(expected, kind, observed_text)
    if kind == "generic" and len(expected) < _GENERIC_MIN_LENGTH:
        return False
    return observed


def _rederive_falsifier_status(anchors: list, evidence_span: str) -> str:
    """Reproduce EntailmentFalsifier.challenge over the recorded anchors + span.

    No anchors -> INCONCLUSIVE (nothing checkable); all anchors matched -> SURVIVED;
    otherwise FALSIFIED (an asserted identity anchor is not entailed by evidence).
    """
    if not anchors:
        return _INCONCLUSIVE
    all_supported = all(
        _value_matched(
            str(a.get("expected", "")),
            str(a.get("kind", "generic")),
            evidence_span,
        )
        for a in anchors
    )
    return _SURVIVED if all_supported else _FALSIFIED


def _rederive_outcome(falsifier_status: str, corroboration: int) -> str:
    """Reproduce RulesAdjudicator.adjudicate for the hardening path.

    (analyst_verdict is always affirmative and remand_count 0 there, so the
    'not affirmative' and 'remand budget exhausted' branches are unreachable.)
    """
    if falsifier_status == _FALSIFIED:
        return "dismissed"
    if falsifier_status == _INCONCLUSIVE:
        return "remanded"
    # SURVIVED from here.
    if corroboration >= _MIN_CORROBORATION:
        return "sustained"
    return "remanded"


def _findings_section(report: dict) -> list:
    """Return the findings list from either report shape (hardened|case_findings)."""
    if isinstance(report.get("hardened"), list):
        return report["hardened"]
    if isinstance(report.get("case_findings"), list):
        return report["case_findings"]
    return []


def verify(path: str) -> tuple[int, str]:
    """Return (exit_code, human_message) for the report at ``path``."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    except FileNotFoundError:
        return (2, f"file error: {path} not found")
    except (OSError, ValueError) as exc:
        return (2, f"file error: {exc}")

    if not isinstance(report, dict):
        return (2, "file error: report is not a JSON object")

    entries = _findings_section(report)
    if not entries:
        return (0, "OK: report has no findings; nothing to verify")

    independent = 0
    adjudication_only = 0
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return (1, f"BROKEN at finding {index}: entry is not an object")
        adv = entry.get("adversarial")
        if not isinstance(adv, dict):
            return (
                1,
                f"BROKEN at finding {index}: missing 'adversarial' block "
                "(re-derivation inputs absent - cannot verify independently)",
            )

        recorded_outcome = adv.get("outcome")
        recorded_status = adv.get("falsifier_status")
        anchors = adv.get("anchors")
        evidence_span = adv.get("evidence_span")
        corroboration = adv.get("corroboration")

        if not isinstance(anchors, list) or not isinstance(corroboration, int):
            return (
                1,
                f"BROKEN at finding {index}: re-derivation inputs are malformed "
                "(anchors must be a list and corroboration an int)",
            )

        if evidence_span is not None:
            # INDEPENDENT: reproduce the falsifier status from evidence, then the
            # outcome from the ladder. Both must match what was recorded.
            if not isinstance(evidence_span, str):
                return (
                    1,
                    f"BROKEN at finding {index}: evidence_span must be a string "
                    "when present",
                )
            derived_status = _rederive_falsifier_status(anchors, evidence_span)
            if derived_status != recorded_status:
                asserted = ", ".join(str(a.get("expected", "")) for a in anchors)
                return (
                    1,
                    f"BROKEN at finding {index}: recorded falsifier_status "
                    f"'{recorded_status}' does not reproduce from the evidence span "
                    f"(re-derived '{derived_status}'; anchors: {asserted}). The "
                    "recorded verdict is not reproducible from its evidence.",
                )
            derived_outcome = _rederive_outcome(derived_status, corroboration)
            independent += 1
        else:
            # ADJUDICATION-CONSISTENT: evidence_span is None only on the engine's
            # null-falsifier fallback (a finding with no re-derivable anchor, or no
            # raw evidence threaded). That falsifier ALWAYS returns SURVIVED - it is
            # unconditional - so the ONLY falsifier_status the engine can record on
            # this path is 'survived'. A recorded 'falsified'/'inconclusive' with no
            # span is therefore a shape the engine never produces: a tamper signature
            # (e.g. an attacker forging 'falsified' + evidence_span=None to SUPPRESS
            # a genuine finding while dodging the entailment check). Reject it, so the
            # null path cannot be turned into a suppression vector.
            if recorded_status != _SURVIVED:
                return (
                    1,
                    f"BROKEN at finding {index}: falsifier_status "
                    f"'{recorded_status}' recorded with no evidence_span. The "
                    "null-falsifier path always SURVIVES; a non-survived status "
                    "with no span is a shape the engine never emits (a forged "
                    "verdict dodging the entailment check).",
                )
            # SURVIVED confirmed: re-check the ladder produced the recorded outcome.
            derived_outcome = _rederive_outcome(recorded_status, corroboration)
            adjudication_only += 1

        if derived_outcome != recorded_outcome:
            return (
                1,
                f"BROKEN at finding {index}: recorded outcome '{recorded_outcome}' "
                f"does not match the re-derived adjudication '{derived_outcome}' "
                f"(falsifier_status '{recorded_status}', corroboration "
                f"{corroboration}). Verdict/inputs mismatch.",
            )

    total = independent + adjudication_only
    return (
        0,
        f"OK: {total} verdict(s) reproducible - {independent} independently "
        f"re-derived from evidence, {adjudication_only} adjudication-consistent "
        "(null-falsifier, no independent anchor). No live model, no engine.",
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: verify_verification.py <report.json>", file=sys.stderr)
        return 2
    code, message = verify(argv[1])
    stream = sys.stdout if code == 0 else sys.stderr
    print(message, file=stream)
    if code != 0:
        # Echo to stdout too so callers capturing stdout see the reason.
        print(message)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
