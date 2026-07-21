#!/usr/bin/env python3
"""Standalone offline verifier for the 4n6 Nexus tamper-evident audit chain.

Gallery idea #5. This script is DELIBERATELY self-contained: it imports nothing
from ``sift_find_evil`` and re-implements canonicalization + hashing from the
Python standard library alone. That gives two properties the in-product
verifier cannot:

  * Independent verification (Daubert): a third party can prove the integrity of
    an audit log without trusting - or even installing - our engine.
  * Drift detection: if the product's writer and this reader ever disagree about
    canonicalization, a pristine log fails here, surfacing the drift.

Usage:
    python3 tools/verify_chain.py <audit.jsonl>

Exit codes (semantic):
    0  chain valid (or empty)
    1  chain invalid  (prints the failing entry index and reason)
    2  file error     (missing / unreadable)

The chain rule (must match sift_find_evil/audit/models.compute_entry_hash):
    GENESIS  = "0" * 64
    body     = the entry dict with "entry_hash" removed (includes "prev_hash")
    canonical= json.dumps(body, sort_keys=True, separators=(",",":"), default=str)
    entry_hash = sha256(canonical.encode("utf-8")).hexdigest()
    entry[0].prev_hash == GENESIS; entry[i].prev_hash == entry[i-1].entry_hash
"""

import hashlib
import json
import sys

GENESIS_HASH = "0" * 64


def _canonical(body_without_hash: dict) -> str:
    return json.dumps(
        body_without_hash, sort_keys=True, separators=(",", ":"), default=str
    )


def _entry_hash(body_without_hash: dict) -> str:
    return hashlib.sha256(_canonical(body_without_hash).encode("utf-8")).hexdigest()


def verify(path: str) -> tuple[int, str]:
    """Return (exit_code, human_message) for the log at ``path``."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_lines = f.readlines()
    except FileNotFoundError:
        return (2, f"file error: {path} not found")
    except OSError as exc:
        return (2, f"file error: {exc}")

    expected_prev = GENESIS_HASH
    index = 0
    for raw in raw_lines:
        line = raw.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except ValueError:
            return (1, f"BROKEN at entry {index}: malformed JSON")

        stored = data.get("entry_hash")
        if stored is None:
            return (
                1,
                f"BROKEN at entry {index}: missing entry_hash "
                "(unchained/legacy entry)",
            )
        if data.get("prev_hash") != expected_prev:
            return (
                1,
                f"BROKEN at entry {index}: prev_hash link mismatch "
                "(deletion, reordering, or truncation)",
            )
        body = {k: v for k, v in data.items() if k != "entry_hash"}
        if _entry_hash(body) != stored:
            return (
                1,
                f"BROKEN at entry {index}: entry_hash content mismatch "
                "(in-line edit)",
            )
        expected_prev = stored
        index += 1

    return (0, f"OK: {index} entr{'y' if index == 1 else 'ies'} verified, chain intact")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: verify_chain.py <audit.jsonl>", file=sys.stderr)
        return 2
    code, message = verify(argv[1])
    stream = sys.stdout if code == 0 else sys.stderr
    print(message, file=stream)
    # Always echo the message to stdout too so callers capturing stdout (tests,
    # pipelines) see the failing index regardless of stream.
    if code != 0:
        print(message)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
