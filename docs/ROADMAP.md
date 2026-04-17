# Roadmap

Tracked work beyond what is currently merged on `main`. Written as structured entries so any session (human or agent) can pick up from here without losing context. Beads is unavailable on this SIFT install (binary built without CGO), so this file is the durable source of truth.

Entries use this shape:

```
### <PREFIX>-<N>: <title>
- Status: open | in_progress | blocked | done
- Type: feature | task | bug
- Priority: P0..P4
- Depends on: <ids>
- Why: <the load-bearing reason>
- Acceptance: <what "done" looks like, testable>
```

---

## Feature: Email-based exfiltration detection (SFE-F1)

**Status:** open
**Priority:** P1
**Why:** The M57-Jean case (see `docs/real_examples/nps-2008-jean/findings.md`) was solved manually because the engine's current artifact model is MFT + Prefetch + EventLog, tuned for process-execution contradictions. File-save-then-email exfiltration sits outside that model, so the engine produced 856 MEDIUM-severity noise findings and missed the only finding that mattered (hash-identical `m57biz.xls` attachment 44 s after Desktop save). Without this feature the engine cannot pass the Jean case autonomously, which is the headline demo for the hackathon.

**Acceptance:** Re-running `sift_find_evil analyze` against the Jean image produces a finding titled approximately "m57biz.xls exfiltrated via email" with confidence >= 0.90, severity CRITICAL, and a reasoning chain that cites both the on-disk SHA-256 and the matching PST attachment SHA-256. The finding surfaces without any case-specific flags or hints.

### SFE-1: Promote PST parser to first-class artifact source

- Status: open
- Type: task
- Priority: P1
- Depends on: none
- Why: The Jean story is only tellable because `scripts/parse_jean_pst.py` exists. That script is one-off; the engine needs a stable parser that emits a frozen dataclass the detector can consume, with attachment-level hash extraction as a required field.
- Acceptance:
  - `sift_find_evil/parsers/pst_parser.py` exports `PstParser.parse_file(path) -> list[EmailMessage]`.
  - `EmailMessage` is `@dataclass(frozen=True)` with fields: `folder`, `submit_time`, `delivery_time`, `sender_name`, `sender_email`, `subject`, `transport_headers`, `body_preview`, and `attachments: tuple[Attachment, ...]` where `Attachment` carries `name`, `size`, `sha256`.
  - The attachment SHA-256 is computed via streaming read; no attachment bytes live in memory at once beyond a 64 KB window.
  - Unit tests cover: empty PST, message without attachments, message with one attachment, message whose attachment hash is verified against a known-content fixture.
  - Integration-lite test parses the Jean PST (skipped if not extracted) and asserts the "RE: Please send me the information now" reply has exactly one attachment with SHA-256 `34456b5f714dc9d8dd23c742d54c3f5f582ecb042bc1c4d3042b88203863779f`.

### SFE-2: Plumb a content-reader through the engine

- Status: open
- Type: task
- Priority: P1
- Depends on: SFE-1
- Why: Matching an email attachment to a file on disk requires the SHA-256 of the on-disk file. The current MFT parser reads CSV metadata only, which is correct for the process-execution detectors but insufficient here. The engine needs an optional content-reader so hash-level correlation is available without making CSV-only workflows slower or more fragile.
- Acceptance:
  - `sift_find_evil/parsers/mft_parser.py` gains an optional `content_reader: Callable[[MftEntry], bytes] | None` field on parsed rows, populated only when a reader is supplied.
  - `SelfCorrectionEngine.analyze()` accepts `content_reader=None`; when None, existing behavior is unchanged.
  - A helper `sift_find_evil/parsers/image_content_reader.py` reads file bytes from an E01 via pyewf+pytsk3, identified by MFT entry number, with a 4 MB streaming window.
  - Unit test: a fake MFT entry plus a fake content reader produces the expected SHA-256 through the engine's content-resolution path.

### SFE-3: Add `EXFIL_CORRELATION` contradiction type and detector

- Status: open
- Type: task
- Priority: P1
- Depends on: SFE-1, SFE-2
- Why: The new signal needs a home in the same detection/scoring pipeline the existing detectors use so findings appear in the same output shape, ranked alongside everything else.
- Acceptance:
  - `ContradictionType.EXFIL_CORRELATION` added to `sift_find_evil/self_correction/contradiction_detector.py`.
  - `ContradictionDetector.detect_save_then_exfil(mft_entries, emails, content_reader, window_seconds=300)` returns a list of `Contradiction` objects, one per matched (file, email) pair.
  - Matching is hash-based: for each email attachment, find MFT entries whose content-hash equals the attachment hash AND whose `$STANDARD_INFORMATION.created` is within `window_seconds` before the email's `submit_time`. Fall back to `(filename, size)` match only when no content reader is supplied, and mark the confidence lower in that fallback path.
  - `ConfidenceScorer` scores the new type starting at 0.95 for hash match, 0.65 for size+name fallback, with standard deductions for missing context (no recipient in headers, etc.).
  - Unit tests: hash match inside window, hash match outside window (no finding), size+name fallback, and header analysis flag for the external-recipient case.

### SFE-4: CLI wiring and documentation

- Status: open
- Type: task
- Priority: P2
- Depends on: SFE-3
- Why: The feature only counts if it runs end-to-end from `sift_find_evil analyze`. The CLI currently takes CSV paths; it needs to accept a PST path and optionally an image path for the content reader.
- Acceptance:
  - `sift_find_evil analyze` accepts `--pst PATH` and `--image PATH` flags, both optional.
  - With `--pst` only: size+name fallback correlation runs.
  - With `--pst --image`: hash-level correlation runs.
  - `docs/CLI_USAGE.md` updated.
  - `--help` output documents the new flags.

### SFE-5: Re-run Jean case as acceptance test

- Status: open
- Type: task
- Priority: P1
- Depends on: SFE-4
- Why: This is the real acceptance test. The feature lands when the engine, invoked with no case-specific hints, produces the finding that the manual pass produced. If the finding's confidence is below 0.90 we go back and tune the scorer, not the test.
- Acceptance:
  - Re-running the engine against the Jean artifacts produces exactly one finding with:
    - title matching "exfil" or "exfiltration"
    - severity CRITICAL
    - confidence >= 0.90
    - evidence field containing both the on-disk SHA-256 and the PST attachment SHA-256 (equal)
    - evidence field containing the 44 s save-to-send delta
    - reasoning chain mentioning the `tuckgorge@gmail.com` header anomaly
  - The finding is captured in `docs/real_examples/nps-2008-jean/engine_pass.md` with the raw JSON output, so future regressions are visible.
  - If the finding drops below 0.90 or the title/severity don't match, the task is not done — we iterate on scoring, not on the acceptance bar.

### SFE-6 (optional): Extend the adversarial validator as a standing check

- Status: open
- Type: task
- Priority: P3
- Depends on: SFE-5
- Why: The validator pass on Jean caught three real errors in the first analyst draft. It was valuable enough that it's worth trying to automate it as a post-engine review step, where every CRITICAL finding gets a structured "attack each claim" pass before being reported.
- Acceptance: design doc only at this stage; implementation would be a separate feature.
