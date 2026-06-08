# SFE-qad: Memory FP Candidate Validation Against Real Evidence

Date: 2026-06-06 (UTC)
Validator: real-evidence run on DFIR workstation
Volatility: Volatility 3 Framework 2.27.0 (mise python 3.12.2)

## Evidence

Source: SANS SRL-2018 Compromised Enterprise Network memory captures
(bundled under the SRL-2015 corpus on TESLADRIVE).

| Image | Acquisition md5 | Verified |
|-------|-----------------|----------|
| base-wkstn-01-memory.img (3 GiB) | `7586e0cd75e9c6a5ea97c3c74ebf391b` | YES (matches dc3dd acquisition log) |
| base-wkstn-05-memory.img (3 GiB) | (extracted from .7z) | n/a |

Both are **benign baseline** workstation captures (pre-compromise), each with a
browser running (firefox.exe / RdrCEF.exe present in psscan) plus McAfee AV and
Office - exactly the JIT-host + enterprise-noise surface the FP candidates target.

## Corpus-wide Volatility caveat

`windows.pslist` (active-process linked-list walk) returns **0 rows** on every
SRL-2018 image tested, while `windows.psscan` (pool-tag scan) returns a full
process set (wkstn-01: 131 rows / 66 procs; wkstn-05: 96 rows). `windows.info`
reports garbage `KeNumberProcessors 0` and `Major/Minor 52281.24963`, indicating
a symbol/KDBG mismatch for these 2018 VMware captures under Vol3 2.27.0. Plugins
that walk the active list (pslist, cmdline, malfind) cannot be exercised on this
corpus; pool-scan plugins (psscan, netscan) work normally.

## Candidate verdicts

### Candidate #1 - malfind RWX "Unbacked RWX" (memory_detector._analyze_malfind)

Status: **NOT REPRODUCIBLE on this corpus; code-inspection verdict (non-issue) upheld.**

`windows.malfind` returned 0 rows on both wkstn-01 and wkstn-05. malfind iterates
the active-process list, which does not walk on this corpus (see caveat), so the
JIT-host FP test (does a signed browser's legitimate RWX JIT region get flagged?)
could not be run against this evidence. No regression introduced. The detector
already (a) flags only RWX VADs, (b) names the JIT FP surface (V8/SpiderMonkey/
.NET CLR) in the finding text, (c) caps confidence at Medium (0.70) and instructs
triage. Re-test requires a memory image whose active-process list traverses under
the installed Vol3 build, with a running browser. Tracked for that follow-up.

### Candidate #2 - LOLBAS-over-network (0.55 medium)

Status: **REFUTED on real evidence.**

`windows.netscan` returned 148 rows on wkstn-01. Zero were LOLBAS-owned
(powershell/cmd/rundll32/etc.). The "enterprise PSRemoting/GPO flood" concern did
not materialize on a real enterprise baseline. No change required.

## NEW false positive discovered and FIXED (TDD)

Feeding the real wkstn-01 netscan (148 rows) through `MemoryDetector` produced
**16 high-severity "Unowned network socket" (T1014 rootkit) findings on a clean
baseline**. Breakdown of the 18 unowned sockets:

- 16 CLOSED  -> 14 fired (non-loopback) as false T1014 highs
- 2 ESTABLISHED -> genuine, correctly flagged

Root cause: the unowned-socket branch (`_classify_netscan_row`) fired **before**
the half-dead/CLOSED state filter that already guards owned sockets. A CLOSED /
half-dead unowned socket is a torn-down connection netscan carved from freed pool
memory (the owning PID was naturally reclaimed), not a hidden live socket.

Fix: apply the same inactive-TCP-state filter to the unowned-socket branch.
Extracted the duplicated state set to module constant `_INACTIVE_TCP_STATES`.

Result on real evidence: **16 -> 2 findings** (only the genuine ESTABLISHED
unowned sockets remain). ESTABLISHED unowned sockets still fire (no
over-correction).

Tests added (TDD, RED->GREEN):
- `test_netscan_unowned_closed_socket_skipped`
- `test_netscan_unowned_established_socket_still_fires`

## Quality gates (post-fix)

- 1299 tests pass
- 100% coverage maintained (fail_under=100)
- scenario harness F1=1.00 across all 14 scenarios (scenario 12 memory: 27 TP / 0 FP / 0 FN)
- ruff check + format clean
