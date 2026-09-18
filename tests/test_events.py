"""Unit tests for the reasoning-event stream primitives (sift_find_evil.events).

Pure/Tier-1: no engine, no fixtures. Covers the event dataclass wire shape, the
emitter's monotonic-seq + stamping contract, the unknown-type guard, and the
no-op default that keeps the un-instrumented path zero-cost.
"""

import pytest

from sift_find_evil.events import (
    EVENT_DETECTOR_STARTED,
    EVENT_DONE,
    EVENT_FINDING_ADDED,
    ReasoningEvent,
    ReasoningEventEmitter,
    resolve_emit,
)


class TestReasoningEvent:
    def test_to_dict_wire_shape(self):
        event = ReasoningEvent(
            type=EVENT_FINDING_ADDED,
            run_id="run-1",
            seq=3,
            ts="2026-08-13T00:00:00+00:00",
            summary={"title": "evil.exe", "severity": "high"},
        )
        assert event.to_dict() == {
            "type": "finding_added",
            "run_id": "run-1",
            "seq": 3,
            "ts": "2026-08-13T00:00:00+00:00",
            "summary": {"title": "evil.exe", "severity": "high"},
        }

    def test_event_is_frozen(self):
        event = ReasoningEvent(type=EVENT_DONE, run_id="r", seq=0, ts="t", summary={})
        with pytest.raises(Exception):
            event.type = "mutated"  # type: ignore[misc]


class TestReasoningEventEmitter:
    def test_emit_allocates_monotonic_seq_from_zero(self):
        sink: list[ReasoningEvent] = []
        emitter = ReasoningEventEmitter(run_id="run-x", sink=sink.append)

        emitter.emit(EVENT_DETECTOR_STARTED, detector="registry")
        emitter.emit(EVENT_DETECTOR_STARTED, detector="network")
        emitter.emit(EVENT_DONE)

        assert [e.seq for e in sink] == [0, 1, 2]
        assert all(e.run_id == "run-x" for e in sink)

    def test_emit_stamps_and_carries_summary(self):
        sink: list[ReasoningEvent] = []
        emitter = ReasoningEventEmitter(run_id="run-y", sink=sink.append)

        returned = emitter.emit(EVENT_FINDING_ADDED, title="t", severity="high")

        assert returned is sink[0]
        assert returned.summary == {"title": "t", "severity": "high"}
        # ts is a non-empty ISO-8601 UTC stamp (tz-aware -> carries an offset).
        assert returned.ts and ("+00:00" in returned.ts or returned.ts.endswith("Z"))

    def test_summary_is_copied_not_aliased(self):
        # A caller reusing/mutating its kwargs dict must not retroactively change
        # an already-emitted event. emit(**summary) binds a fresh dict, and the
        # emitter copies it, so this holds structurally; assert it explicitly.
        sink: list[ReasoningEvent] = []
        emitter = ReasoningEventEmitter(run_id="r", sink=sink.append)
        payload = {"detector": "memory"}
        emitter.emit(EVENT_DETECTOR_STARTED, **payload)
        payload["detector"] = "mutated"
        assert sink[0].summary == {"detector": "memory"}

    def test_unknown_event_type_raises(self):
        emitter = ReasoningEventEmitter(run_id="r", sink=lambda _e: None)
        with pytest.raises(ValueError, match="unknown reasoning event type"):
            emitter.emit("not_a_real_event", foo="bar")


class TestResolveEmit:
    def test_none_resolves_to_noop_callable(self):
        emit = resolve_emit(None)
        # Callable, accepts the (event_type, **summary) shape, returns None.
        assert emit("finding_added", title="t") is None

    def test_passes_through_a_real_callback(self):
        seen: list[tuple] = []

        def cb(event_type, **summary):
            seen.append((event_type, summary))

        emit = resolve_emit(cb)
        emit("done")
        assert seen == [("done", {})]
