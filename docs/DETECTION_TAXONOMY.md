# Detection Taxonomy

Every finding the engine emits carries a `category` drawn from the fixed
vocabulary defined in `sift_find_evil/findings/categories.py`. The category is
chosen by the artifact signatures that fired, not by the analyst's prior belief
about what the image contains. That keeps acceptance tests artifact-centric:
callers can assert `category == "data_exfiltration"` for any image that
exhibits the pattern, regardless of whether the case is the Jean exercise,
ransomware staging, or IP theft.

## Categories

| Category | Meaning | Populated by |
|---|---|---|
| `data_exfiltration` | Evidence that sensitive data left the system. | `EXFIL_CORRELATION` detector (planned, SFE-3). |
| `timeline_tampering` | Artifact timestamps have been manipulated or are inconsistent across artifacts. | `SelfCorrectionEngine` for `CAUSALITY_VIOLATION`, `TIMESTOMPING`, `TEMPORAL_MISMATCH` contradictions. |
| `process_injection` | Code running inside a process that did not load it. | None yet. |
| `credential_theft` | Access to authentication material. | None yet. |
| `persistence` | A mechanism was installed to survive reboot. | None yet. |
| `lateral_movement` | Movement between hosts in the environment. | None yet. |
| `anti_forensics` | Active efforts to hide activity from an investigator. | `wipe_detector` (primary-GPT-wiped-but-secondary-intact pattern). `SelfCorrectionEngine` for `MISSING_ARTIFACT` contradictions. |
| `unknown` | Escape hatch for findings that do not yet map to a named category. Use sparingly. | Engine fallback when contradictions span categories without precedence. |

## Precedence when a finding spans categories

`engine._pick_category` currently prefers `anti_forensics` over
`timeline_tampering` when both are represented. The rationale: a missing
artifact (anti-forensics) is a more load-bearing claim than an SI/FN skew
(timeline-tampering), so the finding should surface under the stronger label.
Add a precedence row here whenever a new category joins the engine mapping.

## Adding a new category

Changing the vocabulary is a deliberate act.

1. Add the enum member to `sift_find_evil/findings/categories.py` with a
   docstring describing what qualifies.
2. Add a row to the table above with the detectors that populate it.
3. If the category can coexist with others on the same finding, update
   precedence above and the corresponding mapping in
   `sift_find_evil/self_correction/engine.py`.
4. Extend `tests/test_finding_categories.py` so the vocabulary is protected by
   a test that fails if the value is removed.

Prefer mapping new signals onto existing categories unless the signal is
genuinely outside all of them. A sprawling taxonomy makes acceptance tests
harder to write, not easier.

## Anti-pattern: title-based classification

Do not write acceptance tests or downstream logic that greps finding titles for
keywords. Titles are human-readable strings that drift over time. The category
enum is the stable contract. If a test says `assert "exfil" in title`, it is
assuming the case type in advance, which defeats the purpose of running the
engine against an unknown image.
