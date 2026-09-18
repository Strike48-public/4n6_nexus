"""Typed reasoning-event stream for the live connector/GUI analyze path.

The scored detection path and the ``analyze --harden`` custody path are
untouched by this module. This is the event source for the live reasoning
stream (SFE-pobj): as the connector's ``make_analyze_fn`` pipeline runs, it
calls an injected ``emit_event`` callback at each meaningful step (a detector
starts/finishes, a finding is added, a self-correction contradiction is seen, a
severity clamp adjusts confidence, subjects are risk-ranked, analysis is done).
The sidecar server forwards these as JSON-RPC ``event`` notifications and the
Rust UI fans them to an SSE stream.

Design constraints:

- **No-op by default.** When no listener is attached, the pipeline passes
  ``emit_event=None`` and the whole seam is a zero-cost no-op, so the returned
  ``{findings, summary}`` envelope is byte-identical to the pre-instrumentation
  path. This is the guarantee that F1 and every existing caller are unaffected.
- **The adapter stays decoupled.** Callers emit with a bare
  ``emit_event(event_type, **summary)`` signature; they never construct a
  :class:`ReasoningEvent` or know about ``run_id``/``seq``/``ts``. The
  :class:`ReasoningEventEmitter` owns that stamping so ids stay monotonic and
  the shape is consistent across every emit site.
- **Additive, unhashed.** Events are ephemeral progress notifications, not part
  of the tamper-evident audit chain, so they carry no ``prev_hash``/``entry_hash``
  and are plain-JSON serialized.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

# Reasoning-event type vocabulary. Kept as module constants (not a bare-string
# free-for-all) so the emit sites, the tests, and the Rust/UI consumers share
# one source of truth for the wire vocabulary.
EVENT_DETECTOR_STARTED = "detector_started"
EVENT_DETECTOR_FINISHED = "detector_finished"
EVENT_FINDING_ADDED = "finding_added"
EVENT_CONTRADICTION_DETECTED = "contradiction_detected"
EVENT_CONFIDENCE_ADJUSTED = "confidence_adjusted"
EVENT_SUBJECT_RISK_RANKED = "subject_risk_ranked"
EVENT_DONE = "done"

EVENT_TYPES = frozenset(
    {
        EVENT_DETECTOR_STARTED,
        EVENT_DETECTOR_FINISHED,
        EVENT_FINDING_ADDED,
        EVENT_CONTRADICTION_DETECTED,
        EVENT_CONFIDENCE_ADJUSTED,
        EVENT_SUBJECT_RISK_RANKED,
        EVENT_DONE,
    }
)

# The callback the analyze pipeline invokes: ``emit_event(event_type, **summary)``.
# ``None`` means "no listener" and is treated as a no-op by callers.
EmitFn = Callable[..., None]


@dataclass(frozen=True)
class ReasoningEvent:
    """One structured step in the live reasoning stream.

    ``run_id`` groups every event of a single analysis; ``seq`` is a per-run
    monotonic counter (0-based) that doubles as the SSE ``Last-Event-ID`` handle
    for the deferred resume work (SFE-q2nx). ``summary`` is the free-form typed
    payload for the event (e.g. ``{"detector": "registry"}``).
    """

    type: str
    run_id: str
    seq: int
    ts: str
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to the wire shape carried by the JSON-RPC ``event`` notification."""
        return {
            "type": self.type,
            "run_id": self.run_id,
            "seq": self.seq,
            "ts": self.ts,
            "summary": self.summary,
        }


class ReasoningEventEmitter:
    """Stamps and dispatches :class:`ReasoningEvent`s for one analysis run.

    Holds the run identity and the monotonic sequence counter so emit sites can
    stay ignorant of both. Each :meth:`emit` allocates the next ``seq``, stamps a
    tz-aware UTC timestamp, builds the immutable event, hands it to ``sink``, and
    returns it (handy for tests and for the sink to inspect).

    The emitter is used from a single synchronous analysis call (the sidecar runs
    one ``analyze`` at a time, inline), so the plain counter needs no locking.
    """

    def __init__(self, run_id: str, sink: Callable[[ReasoningEvent], None]):
        self.run_id = run_id
        self._sink = sink
        self._next_seq = 0

    def emit(self, event_type: str, **summary) -> ReasoningEvent:
        """Allocate a seq, stamp, build, dispatch, and return the event.

        Raises ``ValueError`` on an unknown ``event_type`` so a typo at an emit
        site fails loudly in tests rather than shipping an off-vocabulary event
        the UI silently drops.
        """
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown reasoning event type: {event_type!r}")
        event = ReasoningEvent(
            type=event_type,
            run_id=self.run_id,
            seq=self._next_seq,
            ts=datetime.now(timezone.utc).isoformat(),
            summary=dict(summary),
        )
        self._next_seq += 1
        self._sink(event)
        return event


def resolve_emit(emit_event: Optional[EmitFn]) -> EmitFn:
    """Return ``emit_event`` or a no-op when no listener is attached.

    Centralizes the "``None`` means no-op" contract so every pipeline site can
    call ``emit(...)`` unconditionally without a ``None`` guard, and the no-op
    path stays a single well-tested function.
    """
    if emit_event is not None:
        return emit_event
    return _noop_emit


def _noop_emit(*_args, **_kwargs) -> None:
    """The zero-cost default when nothing is listening to the stream."""
    return None
