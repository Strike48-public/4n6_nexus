# SFE-07g: Real-Evidence FP Sweep Results

Date: 2026-06-07 (UTC)
Method: in-process pyewf + pytsk3 (NO mount, NO sudo) via analysis/sweep_driver.py;
Volatility 3 2.27.0 for memory.

## Approach: no mounting required

Disk images are opened in-process with pyewf + pytsk3, which reads the NTFS
filesystem directly from the .E01 (and split .E0n sets) without ewfmount/FUSE
or root. The driver auto-detects the Windows volume (largest data partition),
falls back to a bare-filesystem read when there is no partition table, extracts
$MFT, runs mftecmd, and runs the detectors. ewfmount (sudo) remains available as
a fallback for tools that require a real path, but was not needed for this sweep.

## Disk images swept (MFT timestomping FP audit)

| Image | Source | MFT entries | Timestomping findings | Verdict |
|-------|--------|-------------|-----------------------|---------|
| Narcos-CCleaner.E01 | insider_threat_2022 | 155,452 | 0 | True negative (clean) |
| LoneWolf.E01-E09 | ransomware_2021 | 184,910 | 0 | True negative (clean) |
| alison_ws.E01 | blue_team_challenge | n/a | n/a | OUT OF SCOPE: ext4/Linux image, not Windows NTFS (no $MFT) |

340,362 real MFT entries processed with zero timestomping false positives. The
$SI/$FN detector did not over-fire on large real datasets.

## Memory image swept (LoneWolf memdump.mem, 17 GB) — major result

LoneWolf is a **second, independent image confirming the SFE-10f list-walk
failure** first seen on SRL-2018: windows.info reports KeNumberProcessors=0,
windows.pslist returns 0 rows, while windows.psscan returns 216 and
windows.netscan 426. The active-process list did not traverse under Vol3 2.27.0.

Feeding the raw plugin output through MemoryDetector:

| Stage | Findings | Notes |
|-------|----------|-------|
| Pre-fix projection | ~447 | ~160 false hidden-process T1014 highs + 287 unowned CLOSED-socket FPs + 12 unowned-ESTABLISHED FPs |
| After SFE-qad (CLOSED-socket filter) | (287 removed) | 273 CLOSED + 14 CLOSE_WAIT unowned sockets filtered |
| After SFE-10f (list-walk diagnostic + cascade suppression) | (160 removed) | hidden-process cascade suppressed; 1 honest ANALYSIS_GAP emitted |
| After SFE-4n7 (unowned-socket suppression under list-walk failure) | (12 removed) | 12 benign-cloud T1014 FPs (443 / 5228 FCM / 5222 XMPP) removed |
| **Final** | **1** | a single ANALYSIS_GAP diagnostic telling the analyst the process layer is unreliable |

Net: **~447 false findings -> 1 honest diagnostic** on a real ransomware memory
image, across three composing fixes — all validated on independent evidence.

## New bug found and fixed this sweep: SFE-4n7

The unowned-socket branch inferred "pid=None + no owner => maliciously unlinked
=> T1014 rootkit". Under list-walk failure that inference is unsound: netscan
could not carve the owner object, not because a process was hidden. On LoneWolf
this fired 12 high-severity T1014 findings against benign cloud sockets.

Fix: when the list-walk-failure diagnostic fires, suppress the unowned-socket
sub-branch of netscan. Owner-resolved netscan findings (exfil / lateral movement
with a real owner) still surface — netscan resolves its own owners independently
of the broken process list. TDD: 3 new tests; the superseded SFE-10f
"does_not_suppress_netscan" test was retargeted to an owner-resolved example.

## Quality gates

- 1311 tests pass
- 100% coverage maintained (fail_under=100)
- scenario harness F1=1.00 across all 14 scenarios
- ruff check + format clean

## Follow-ups

- blue_team alison_ws is ext4/Linux — a candidate for a future Linux disk
  detector, out of scope for the Windows NTFS sweep.
- LoneWolf memory list-walk failure is the same Vol3 2.27.0 condition as
  SRL-2018; an empirical malfind RWX re-test (SFE-dtz) still needs an image
  whose active-process list traverses.
