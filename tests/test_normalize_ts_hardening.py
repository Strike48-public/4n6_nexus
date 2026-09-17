"""Harden _normalize_ts against non-UTC timezone suffixes (SFE-z366).

The timeline correlator hands each event's ``ts`` to SQLite ``julianday()`` to
compute a time-window self-join. ``julianday()`` returns NULL for a timestamp
carrying a trailing ALPHABETIC timezone word (e.g. ``" PDT"``, ``" EST"``), so
the window predicate silently never matches and a real cross-artifact
correlation is dropped -- a false negative with no crash.

The original ``_normalize_ts`` stripped only a hard-coded ``(" UTC", " GMT",
"Z")`` list, so any OTHER alphabetic zone word slipped through. This generalizes
the strip to any trailing zone word and logs a warning when the result STILL
will not parse, so a future artifact source with an exotic tail surfaces as a
visible signal instead of a silent drop.

Empirically (verified against SQLite, 2026-07-26): julianday() natively parses
bare timestamps, ``Z``, and NUMERIC offsets (``+00:00``, ``+05:30``); it returns
NULL for alphabetic zone words and for compact offsets like ``-0700``. So the
realistic gap this closes is alphabetic zone words beyond UTC/GMT.

RED-first: before the change, ``_normalize_ts("... PDT")`` returned the string
with the `` PDT`` tail intact, which julianday() then read as NULL.
"""

from __future__ import annotations

import sqlite3

import pytest

from sift_find_evil.correlation.assemble import _normalize_ts

_BASE = "2026-04-22 10:05:10.000000"


def _julianday_parses(ts: str) -> bool:
    """True iff SQLite julianday() yields a non-NULL value for ``ts``."""
    con = sqlite3.connect(":memory:")
    try:
        return con.execute("SELECT julianday(?)", (ts,)).fetchone()[0] is not None
    finally:
        con.close()


# -- the regression: alphabetic zone words other than UTC/GMT ---------------


@pytest.mark.parametrize("zone", ["PDT", "PST", "EST", "EDT", "CET", "BST"])
def test_strips_arbitrary_alphabetic_timezone_word(zone: str) -> None:
    normalized = _normalize_ts(f"{_BASE} {zone}")
    assert normalized == _BASE, f"{zone!r} tail was not stripped"
    # ...and the stripped form is one julianday() can actually parse.
    assert _julianday_parses(normalized)


def test_previously_handled_suffixes_still_strip() -> None:
    # Regression guard: the original UTC/GMT/Z cases must keep working.
    assert _normalize_ts(f"{_BASE} UTC") == _BASE
    assert _normalize_ts(f"{_BASE} GMT") == _BASE
    assert _normalize_ts("2026-04-22T10:05:10Z") == "2026-04-22T10:05:10"


def test_bare_timestamp_is_untouched() -> None:
    assert _normalize_ts(_BASE) == _BASE


def test_numeric_offset_is_preserved_because_julianday_parses_it() -> None:
    # julianday() handles numeric offsets natively, so we must NOT strip them
    # (stripping would change the instant). Verify both that we leave them and
    # that they parse.
    for ts in (f"{_BASE}+00:00", f"{_BASE} +05:30", "2026-04-22T10:05:10.5+05:30"):
        out = _normalize_ts(ts)
        assert _julianday_parses(out), f"offset ts {ts!r} -> {out!r} did not parse"


def test_unparseable_tail_is_logged_not_silently_dropped(caplog) -> None:
    """A tail we cannot rescue must WARN, so a future FN is visible.

    ``-0700`` (compact offset, no colon) is a real shape julianday() rejects and
    our zone-word strip does not fix. It must still be returned (no crash) but a
    warning must fire so the silent-NULL drop becomes an observable signal.
    """
    weird = f"{_BASE}-0700"
    with caplog.at_level("WARNING"):
        out = _normalize_ts(weird)
    assert not _julianday_parses(out), "test premise: this tail should not parse"
    assert any(
        "julianday" in rec.message or "normaliz" in rec.message.lower()
        for rec in caplog.records
    ), "an unparseable normalized ts must log a warning"


def test_stripping_an_unknown_trailing_word_warns(caplog) -> None:
    """A trailing 2-5 letter word that is NOT a known zone must WARN when stripped.

    Post-PR finding: the regex strips ANY trailing alphabetic word, so a
    non-timezone token (e.g. a stray ``May``) would be silently removed and, if
    the remainder happens to parse, produce a subtly-wrong instant with no signal.
    Stripping an UNRECOGNIZED word must log a warning so that silent corruption is
    observable, even though the result parses.
    """
    ts = f"{_BASE} May"  # 'May' is a 3-letter word, not a timezone
    with caplog.at_level("WARNING"):
        out = _normalize_ts(ts)
    assert out == _BASE, "the trailing word is still stripped (best-effort)"
    assert _julianday_parses(out), "test premise: the stripped remainder parses"
    assert any(
        "May" in rec.message and "timezone" in rec.message.lower()
        for rec in caplog.records
    ), "stripping an unknown trailing word must warn about the unrecognized zone"


def test_stripping_a_known_timezone_word_does_not_warn(caplog) -> None:
    """Stripping a recognized zone (UTC/PDT/...) is silent -- the common case."""
    with caplog.at_level("WARNING"):
        out = _normalize_ts(f"{_BASE} PDT")
    assert out == _BASE
    assert caplog.records == [], "a known timezone strip must not warn"
