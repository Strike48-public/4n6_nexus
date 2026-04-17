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

## Index

One line per entry, grep-friendly. `grep "Status: open" docs/ROADMAP.md` lists ready work. Keep this index in sync with the entry bodies below.

- SFE-F1 | Feature | P1 | Status: open    | Depends on: -                  | Email-based exfiltration detection
- SFE-1  | Task    | P1 | Status: open    | Depends on: -                  | Promote PST parser to first-class artifact source
- SFE-2  | Task    | P1 | Status: open    | Depends on: SFE-1              | Plumb a content-reader through the engine
- SFE-3  | Task    | P1 | Status: open    | Depends on: SFE-1, SFE-2, SFE-7| Add EXFIL_CORRELATION contradiction type and detector
- SFE-4  | Task    | P2 | Status: open    | Depends on: SFE-3              | CLI wiring and documentation
- SFE-5  | Task    | P1 | Status: open    | Depends on: SFE-4              | Re-run Jean case as acceptance test (case-agnostic)
- SFE-6  | Task    | P3 | Status: open    | Depends on: SFE-5              | Automate adversarial validator as post-engine check
- SFE-7  | Task    | P1 | Status: done    | Depends on: -                  | Establish case-agnostic finding category taxonomy

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
- Depends on: SFE-1, SFE-2, SFE-7
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

### SFE-5: Re-run Jean case as acceptance test (case-agnostic criteria)

- Status: open
- Type: task
- Priority: P1
- Depends on: SFE-4
- Why: This is the real acceptance test. In production we get arbitrary disk images without knowing the case type, so the acceptance bar must be *artifact-centric*, not title-centric. A detector that only fires when the analyst already suspected exfiltration is useless. The bar is: given Jean's artifacts and no case-specific hints, does the engine surface the hash-identity correlation as a ranked finding?
- Acceptance (all artifact-centric, no case-string matching):
  - At least one finding is produced with:
    - `category == data_exfiltration` (from the fixed category taxonomy — see SFE-7)
    - `severity == CRITICAL`
    - `confidence >= 0.90`
    - evidence field contains two independent SHA-256 values that are byte-equal (cross-artifact hash correlation)
    - evidence field contains a save-to-send delta under 300 s
    - reasoning chain cites at least two independent artifact sources (e.g. MFT + PST)
  - The finding ranks in the top 5 by confidence, so an analyst reading the output lands on it without searching.
  - The raw JSON is captured in `docs/real_examples/nps-2008-jean/engine_pass.md` for regression visibility.
  - If confidence drops below 0.90 or the finding is not in the top 5, we iterate on scoring, not on the acceptance bar.
  - No acceptance criterion references the strings "Jean", "m57biz", "exfil", or "tuckgorge". The test must pass for any image exhibiting the same pattern.

### SFE-7: Establish a case-agnostic finding category taxonomy

- Status: done
- Type: task
- Priority: P1
- Depends on: none (should land before SFE-3 so EXFIL_CORRELATION can tag findings correctly)
- Why: SFE-5's acceptance criteria reference `category == data_exfiltration`. For that to be testable, the engine needs a fixed, documented category vocabulary so every detector tags its findings consistently. Without this, "category" becomes a free-text field and acceptance tests devolve back into string matching.
- Acceptance:
  - `sift_find_evil/findings/categories.py` exports a `FindingCategory` `StrEnum` with at least: `data_exfiltration`, `timeline_tampering`, `process_injection`, `credential_theft`, `persistence`, `lateral_movement`, `anti_forensics`, `unknown`.
  - Every existing detector is audited and its findings tagged with the correct category (or `unknown` if none applies).
  - `Finding` dataclass gains `category: FindingCategory` as a required field.
  - `EXFIL_CORRELATION` (SFE-3) tags its findings `data_exfiltration`.
  - Docs: `docs/DETECTION_TAXONOMY.md` lists each category, what it means, and which detectors populate it.
  - Unit test: a detector cannot emit a `Finding` without a category (type system enforces it).

### SFE-6 (optional): Extend the adversarial validator as a standing check

- Status: open
- Type: task
- Priority: P3
- Depends on: SFE-5
- Why: The validator pass on Jean caught three real errors in the first analyst draft. It was valuable enough that it's worth trying to automate it as a post-engine review step, where every CRITICAL finding gets a structured "attack each claim" pass before being reported.
- Acceptance: design doc only at this stage; implementation would be a separate feature.

---

## Why this file and not beads

Beads is the intended tracker (see `~/.claude/CLAUDE.md` root guidance). The beads binary shipped on this SIFT install (`bd 0.52.0`) was built without CGO support, so `bd init` fails with a dolt error and there is no JSONL-only fallback on this version. Rebuilding beads from source with `CGO_ENABLED=1` is a yak-shave that provides no value over a structured markdown file.

Migration trigger: when a CGO-enabled `bd` is installed (or when a future release adds real `--no-db` JSONL mode), migrate these entries into beads issues preserving id prefix (`SFE-`), dependency edges, priority, and status. Delete the corresponding entries from this file as they land in beads, and update the index above. Until then, this file is the durable source of truth and every edit lands in git alongside the code it describes.
