"""Falsifiable competing-hypothesis ledger with logged self-correction (SFE-udkk).

Gallery idea #33, built independently by four FIND EVIL! competitors (VERDICT,
Camel, SIFT-MIND, LinuxIR Agent) -- a strong signal that an explicit hypothesis
structure is how a trustworthy DFIR agent shows its work.

The structure:

  * The lead registers 2-5 *falsifiable* hypotheses, each naming the artifact
    that would confirm or kill it. A hypothesis with no named falsifier is
    rejected -- an unfalsifiable claim is not a hypothesis.
  * Findings attach to a hypothesis with a ``Verdict`` (SUPPORTS / REFUTES /
    INCONCLUSIVE / RETRACTED) and MUST cite the tool execution they came from.
  * The ONLY way to change a finding's verdict is :meth:`HypothesisLedger.revise_finding`,
    which appends a ``SelfCorrection{sequence, from, to, reason, trigger_exec_id}``.

Why this shape makes self-correction *unforgeable*: the ``Hypothesis``,
``AttachedFinding``, and ``SelfCorrection`` records are all frozen, and the
ledger's stores are private. There is no assignment path that flips a verdict
without going through ``revise_finding`` and thereby logging a correction. So a
verdict flip that is NOT accompanied by a logged ``SelfCorrection`` cannot occur
-- retractions and contradictions become log-backed, replay-able proof of
self-correction that feeds the report's candidate-elimination trail.

Hypothesis *status* is always DERIVED from the live verdicts, never stored, so it
cannot drift from the findings. A single live REFUTES dominates a hypothesis into
RETRACTED (an eliminated candidate) even if SUPPORTS findings also exist -- the
contradiction hard-block is automatic. Withdraw the refutation (revise it to
RETRACTED) and the candidate reopens, fully log-backed.

Pure and deterministic: no wall-clock, no ambient state, atomic persistence
(tmp-file then ``os.replace``). Mirrors the sibling primitives
(``loop_control.LoopBreaker``, ``judge_cache.JudgeCache``) so an entire
investigation's reasoning replays bit-identically offline.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union

# Schema version stamped into persisted ledgers. Bump when the on-disk shape
# changes so an old file (a different contract) can never be silently misread.
_SCHEMA_VERSION = "v1"


class Verdict(str, Enum):
    """A finding's bearing on the hypothesis it is attached to."""

    SUPPORTS = "supports"  # evidence for the hypothesis
    REFUTES = "refutes"  # evidence against -- eliminates the candidate
    INCONCLUSIVE = "inconclusive"  # attached but does not move the needle
    RETRACTED = "retracted"  # withdrawn; no longer bears on status


class HypothesisStatus(str, Enum):
    """Derived state of a hypothesis, computed from its live verdicts."""

    OPEN = "open"  # no live SUPPORTS and no live REFUTES
    CONFIRMED = "confirmed"  # a live SUPPORTS and no live REFUTES
    RETRACTED = "retracted"  # a live REFUTES dominates -> eliminated candidate


@dataclass(frozen=True)
class SelfCorrection:
    """One logged verdict transition -- the unforgeable proof of self-correction.

    Appended only by :meth:`HypothesisLedger.revise_finding`. ``sequence`` is a
    1-based, ledger-global ordinal so the full correction trail across every
    finding has a stable total order for the report.
    """

    sequence: int
    finding_id: str
    from_verdict: Verdict
    to_verdict: Verdict
    reason: str
    trigger_exec_id: str

    def to_dict(self) -> dict:
        return {
            "sequence": self.sequence,
            "finding_id": self.finding_id,
            "from_verdict": self.from_verdict.value,
            "to_verdict": self.to_verdict.value,
            "reason": self.reason,
            "trigger_exec_id": self.trigger_exec_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SelfCorrection":
        return cls(
            sequence=int(data["sequence"]),
            finding_id=str(data["finding_id"]),
            from_verdict=Verdict(data["from_verdict"]),
            to_verdict=Verdict(data["to_verdict"]),
            reason=str(data["reason"]),
            trigger_exec_id=str(data["trigger_exec_id"]),
        )


@dataclass(frozen=True)
class Hypothesis:
    """A falsifiable claim under investigation.

    ``falsifier`` names the artifact/observation that would kill the hypothesis;
    it is required, because an unfalsifiable claim is not a hypothesis.
    """

    id: str
    statement: str
    falsifier: str

    def to_dict(self) -> dict:
        return {"id": self.id, "statement": self.statement, "falsifier": self.falsifier}

    @classmethod
    def from_dict(cls, data: dict) -> "Hypothesis":
        return cls(
            id=str(data["id"]),
            statement=str(data["statement"]),
            falsifier=str(data["falsifier"]),
        )


@dataclass(frozen=True)
class AttachedFinding:
    """A finding bound to a hypothesis, carrying its current verdict + trail.

    Frozen: the verdict is only ever changed by :meth:`HypothesisLedger.revise_finding`
    producing a NEW record (via ``dataclasses.replace``) with an appended
    ``SelfCorrection``. There is no in-place mutation path.
    """

    id: str
    hypothesis_id: str
    summary: str
    verdict: Verdict
    source_exec_id: str
    corrections: tuple[SelfCorrection, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "hypothesis_id": self.hypothesis_id,
            "summary": self.summary,
            "verdict": self.verdict.value,
            "source_exec_id": self.source_exec_id,
            "corrections": [c.to_dict() for c in self.corrections],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AttachedFinding":
        return cls(
            id=str(data["id"]),
            hypothesis_id=str(data["hypothesis_id"]),
            summary=str(data["summary"]),
            verdict=Verdict(data["verdict"]),
            source_exec_id=str(data["source_exec_id"]),
            corrections=tuple(
                SelfCorrection.from_dict(c) for c in data.get("corrections", [])
            ),
        )


class HypothesisLedger:
    """The append-and-revise ledger: sole mutation path for hypothesis verdicts.

    Usage::

        ledger = HypothesisLedger()
        h = ledger.add_hypothesis(statement="...", falsifier="...")
        f = ledger.add_finding(h.id, summary="...", verdict=Verdict.SUPPORTS,
                               source_exec_id="mftecmd-001")
        # later, on re-reading the evidence:
        ledger.revise_finding(f.id, new_verdict=Verdict.RETRACTED,
                              reason="renames predate the incident window",
                              trigger_exec_id="mftecmd-002")
    """

    def __init__(self) -> None:
        self._hypotheses: dict[str, Hypothesis] = {}
        self._findings: dict[str, AttachedFinding] = {}
        self._correction_count = 0

    # -- registration --------------------------------------------------------

    def add_hypothesis(self, statement: str, falsifier: str) -> Hypothesis:
        """Register a falsifiable hypothesis and return it.

        Raises:
            ValueError: if ``statement`` or ``falsifier`` is empty/whitespace. A
                hypothesis with no named falsifier is not falsifiable.
        """
        if not statement or not statement.strip():
            raise ValueError("hypothesis statement must be non-empty")
        if not falsifier or not falsifier.strip():
            raise ValueError(
                "hypothesis requires a falsifier (the artifact that would kill it)"
            )
        hyp_id = f"H-{len(self._hypotheses) + 1:03d}"
        hyp = Hypothesis(id=hyp_id, statement=statement, falsifier=falsifier)
        self._hypotheses[hyp_id] = hyp
        return hyp

    def add_finding(
        self,
        hypothesis_id: str,
        summary: str,
        verdict: Verdict,
        source_exec_id: str,
    ) -> AttachedFinding:
        """Attach a finding to a hypothesis with an initial verdict.

        The initial verdict is the first assertion, NOT a self-correction, so it
        does not append a ``SelfCorrection``.

        Raises:
            KeyError: if ``hypothesis_id`` is unknown.
            ValueError: if ``source_exec_id`` is empty -- a finding must cite the
                tool execution it came from.
        """
        if hypothesis_id not in self._hypotheses:
            raise KeyError(f"unknown hypothesis {hypothesis_id!r}")
        if not source_exec_id or not source_exec_id.strip():
            raise ValueError("finding must cite a source_exec_id")
        finding_id = f"F-{len(self._findings) + 1:03d}"
        finding = AttachedFinding(
            id=finding_id,
            hypothesis_id=hypothesis_id,
            summary=summary,
            verdict=verdict,
            source_exec_id=source_exec_id,
        )
        self._findings[finding_id] = finding
        return finding

    # -- the sole mutation path ---------------------------------------------

    def revise_finding(
        self,
        finding_id: str,
        new_verdict: Verdict,
        reason: str,
        trigger_exec_id: str,
    ) -> AttachedFinding:
        """Change a finding's verdict, appending a logged ``SelfCorrection``.

        This is the ONLY way a verdict changes. It returns the new frozen record.

        Raises:
            KeyError: if ``finding_id`` is unknown.
            ValueError: if the new verdict equals the current one (a no-op is not
                a correction), or ``reason`` / ``trigger_exec_id`` is empty (a
                self-correction must be grounded and explained).
        """
        current = self._findings.get(finding_id)
        if current is None:
            raise KeyError(f"unknown finding {finding_id!r}")
        if new_verdict is current.verdict:
            raise ValueError(
                f"revise is a no-op: finding {finding_id} is already {new_verdict.value}"
            )
        if not reason or not reason.strip():
            raise ValueError("a self-correction requires a reason")
        if not trigger_exec_id or not trigger_exec_id.strip():
            raise ValueError("a self-correction requires a trigger_exec_id")

        self._correction_count += 1
        correction = SelfCorrection(
            sequence=self._correction_count,
            finding_id=finding_id,
            from_verdict=current.verdict,
            to_verdict=new_verdict,
            reason=reason,
            trigger_exec_id=trigger_exec_id,
        )
        revised = replace(
            current,
            verdict=new_verdict,
            corrections=current.corrections + (correction,),
        )
        self._findings[finding_id] = revised
        return revised

    # -- reads ---------------------------------------------------------------

    def get_hypothesis(self, hypothesis_id: str) -> Hypothesis:
        """Return a registered hypothesis or raise ``KeyError``."""
        if hypothesis_id not in self._hypotheses:
            raise KeyError(f"unknown hypothesis {hypothesis_id!r}")
        return self._hypotheses[hypothesis_id]

    def findings_for(self, hypothesis_id: str) -> tuple[AttachedFinding, ...]:
        """All findings attached to a hypothesis, in attachment order."""
        if hypothesis_id not in self._hypotheses:
            raise KeyError(f"unknown hypothesis {hypothesis_id!r}")
        return tuple(
            f for f in self._findings.values() if f.hypothesis_id == hypothesis_id
        )

    def status_of(self, hypothesis_id: str) -> HypothesisStatus:
        """Derive a hypothesis's status from its live (non-RETRACTED) verdicts.

        A live REFUTES dominates -> RETRACTED. Else a live SUPPORTS -> CONFIRMED.
        Else OPEN. Status is never stored, so it cannot drift from the findings.

        Raises:
            KeyError: if ``hypothesis_id`` is unknown.
        """
        if hypothesis_id not in self._hypotheses:
            raise KeyError(f"unknown hypothesis {hypothesis_id!r}")
        verdicts = {f.verdict for f in self.findings_for(hypothesis_id)}
        if Verdict.REFUTES in verdicts:
            return HypothesisStatus.RETRACTED
        if Verdict.SUPPORTS in verdicts:
            return HypothesisStatus.CONFIRMED
        return HypothesisStatus.OPEN

    def _by_status(self, want: HypothesisStatus) -> tuple[Hypothesis, ...]:
        return tuple(
            h for h in self._hypotheses.values() if self.status_of(h.id) is want
        )

    def confirmed(self) -> tuple[Hypothesis, ...]:
        """Every hypothesis currently CONFIRMED."""
        return self._by_status(HypothesisStatus.CONFIRMED)

    def retracted(self) -> tuple[Hypothesis, ...]:
        """Every hypothesis currently RETRACTED (eliminated candidate)."""
        return self._by_status(HypothesisStatus.RETRACTED)

    def open_hypotheses(self) -> tuple[Hypothesis, ...]:
        """Every hypothesis still OPEN (neither supported nor refuted yet)."""
        return self._by_status(HypothesisStatus.OPEN)

    def self_correction_count(self) -> int:
        """Total logged verdict transitions across all findings."""
        return self._correction_count

    def correction_trail(self) -> tuple[SelfCorrection, ...]:
        """Every logged self-correction, in global sequence order."""
        trail = [c for f in self._findings.values() for c in f.corrections]
        return tuple(sorted(trail, key=lambda c: c.sequence))

    def report_summary(self) -> dict:
        """A JSON-serializable candidate-elimination summary for the report."""
        return {
            "hypothesis_count": len(self._hypotheses),
            "finding_count": len(self._findings),
            "self_correction_count": self._correction_count,
            "confirmed": [h.to_dict() for h in self.confirmed()],
            "retracted": [h.to_dict() for h in self.retracted()],
            "open": [h.to_dict() for h in self.open_hypotheses()],
            "correction_trail": [c.to_dict() for c in self.correction_trail()],
        }

    # -- persistence ---------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "schema_version": _SCHEMA_VERSION,
            "correction_count": self._correction_count,
            "hypotheses": [h.to_dict() for h in self._hypotheses.values()],
            "findings": [f.to_dict() for f in self._findings.values()],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HypothesisLedger":
        ledger = cls()
        ledger._hypotheses = {
            h["id"]: Hypothesis.from_dict(h) for h in data.get("hypotheses", [])
        }
        ledger._findings = {
            f["id"]: AttachedFinding.from_dict(f) for f in data.get("findings", [])
        }
        ledger._correction_count = int(data.get("correction_count", 0))
        return ledger

    def save(self, path: Optional[Union[str, Path]] = None) -> None:
        """Persist the ledger to ``path`` atomically (temp file then replace).

        Raises:
            ValueError: if no path is given.
        """
        if path is None:
            raise ValueError("save requires a path")
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_text(
            json.dumps(self.to_dict(), sort_keys=True, indent=2), encoding="utf-8"
        )
        os.replace(tmp, target)

    @classmethod
    def load(cls, path: Union[str, Path]) -> "HypothesisLedger":
        """Load a ledger from a JSON file written by :meth:`save`."""
        with Path(path).open(encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))


# -- shared builder (one candidate-elimination overlay for every path) --------


def subject_label(finding: Any) -> Optional[str]:
    """Best-effort human label for a finding's primary artifact, across domains.

    Precedence: ``executable -> process -> dst_ip -> foreign_addr -> owner``; the
    first non-empty evidence key wins. ``foreign_addr`` groups a network finding
    surfaced from memory (netscan) with its disk/pcap twin.

    One investigative SUBJECT per label, so a subject seen across domains (e.g.
    ``crypt_engine.exe`` in both a disk timeline and memory) is a single
    competing candidate rather than duplicated hypotheses.
    """
    ev = getattr(finding, "evidence", {}) or {}
    return (
        ev.get("executable")
        or ev.get("process")
        or ev.get("dst_ip")
        or ev.get("foreign_addr")
        or ev.get("owner")
    )


def exonerating_resolution(finding: Any) -> Optional[tuple[str, str]]:
    """Return an exonerating resolution's ``(method, note)`` or None.

    Only a resolution the engine itself CLASSIFIED as exonerating (its co-located
    ``is_exonerating`` flag, SFE-h53w) clears a subject; a confirming resolution
    returns None (no elimination). Keying on the flag rather than a hard-coded
    method-name set means a new or renamed exonerating method self-declares at its
    construction site and cannot drift out of sync with this discriminator. The
    note is drawn from the resolution's own evidence so the logged self-correction
    reason is grounded in the engine's real output.
    """
    for res in getattr(finding, "resolutions", None) or []:
        if getattr(res, "is_exonerating", False):
            method = getattr(res, "resolution_method", "") or ""
            evidence = getattr(res, "evidence", None) or {}
            return method, str(evidence.get("note", "subject cleared"))
    return None


def build_hypothesis_ledger(items: list[tuple[Any, str]]) -> "HypothesisLedger":
    """Overlay a falsifiable-hypothesis ledger onto emitted findings (SFE-n69x).

    Read-only overlay: it never touches the scored findings, so F1 is unchanged.
    One falsifiable hypothesis is registered per investigative SUBJECT
    (:func:`subject_label`); each finding attaches as SUPPORTS, citing the tool
    execution that produced it. The ONLY verdict changes are genuine eliminations:
    a finding whose engine resolution EXONERATES it (:func:`exonerating_resolution`)
    is revised SUPPORTS -> REFUTES through ``ledger.revise_finding``, so the
    elimination is a logged, unforgeable ``SelfCorrection`` citing that resolution.

    Args:
        items: ``(finding, source_exec_id)`` pairs. ``source_exec_id`` must be a
            non-empty citation (the ledger requires it); a caller with no tool id
            passes the finding's own id as the fallback, keeping the overlay total.
    """
    ledger = HypothesisLedger()
    hypotheses: dict[str, Hypothesis] = {}
    for finding, source_exec_id in items:
        subject = subject_label(finding) or source_exec_id
        hyp = hypotheses.get(subject)
        if hyp is None:
            hyp = ledger.add_hypothesis(
                statement=f"{subject} is attacker-controlled / malicious",
                falsifier=(
                    "an artifact or resolution showing the subject is benign "
                    "(e.g. known-benign infrastructure, legitimate signer)"
                ),
            )
            hypotheses[subject] = hyp
        attached = ledger.add_finding(
            hyp.id,
            summary=subject,
            verdict=Verdict.SUPPORTS,
            source_exec_id=source_exec_id,
        )
        exoneration = exonerating_resolution(finding)
        if exoneration is not None:
            method, note = exoneration
            ledger.revise_finding(
                attached.id,
                new_verdict=Verdict.REFUTES,
                reason=f"{method}: {note}",
                trigger_exec_id=source_exec_id,
            )
    return ledger
