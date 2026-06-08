# SFE-e3g: SRL-2015 Multi-Host APT Corpus Sweep

Date: 2026-06-07 (UTC)
Method: in-process pyewf + pytsk3 (no mount, no sudo) via analysis/sweep_driver.py;
mftecmd for $MFT, python-registry for Run-key hives.
Corpus: SANS SRL-2015 Compromised Enterprise Network (7 Windows C-drive E01s).

## Hosts swept

| Host | Role | MFT entries | Run-key values | Timestomp findings | Run-key findings |
|------|------|-------------|----------------|--------------------|------------------|
| base-dc-cdrive | Domain Controller | 236,778 | 2 | 0 | 0 |
| base-file-cdrive | File Server | 149,432 | 2 | 0 | 0 |
| base-rd-01-cdrive | RD Server 01 | 303,352 | 16 | 0 | 2 (Low) |
| base-rd-02-cdrive | RD Server 02 | 303,815 | 17 | 0 | 0 (after fix) |
| base-wkstn-01-c-drive | Workstation 01 (mhill) | 301,363 | 21 | 0 | 0 (after fix) |
| base-wkstn-05-cdrive | Workstation 05 | 170,008 | 10 | 0 | 0 |
| dmz-ftp-cdrive | DMZ FTP Server | 283,778 | 1 | 0 | 0 |
| **TOTAL** | | **1,748,526** | **69** | **0** | **2** |

1.75M real MFT entries and 69 Run-key values processed across a full enterprise
intrusion corpus, no mounting required (these are single-volume C-drive images;
pyewf+pytsk3 read NTFS directly, with the driver's bare-filesystem fallback).

## New FP found and fixed: SFE-9rj (OneDrive RunOnce cleanup)

The Run-key sweep flagged 8 entries; critical review showed 6 were false
positives — the legitimate Microsoft OneDrive updater's RunOnce cleanup
commands on rd-02 (rsydow-a) and wkstn-01 (mhill):

    cmd.exe /q /c rmdir /s /q "...\AppData\Local\Microsoft\OneDrive\19.232.1124.0008\amd64"
    cmd.exe /q /c del   /q "...\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe"

These fired on the lone "cmd.exe is a LOLBAS host" reason and were scored
Medium. OneDrive AppData paths were already in _BENIGN_AUTOSTART_PATH_FRAGMENTS,
but the existing suppression only covered PATH-ONLY reasons, not the LOLBAS
reason. A self-contained `cmd /c del|rmdir` cleanup launches no payload, so it
is benign updater behavior, not persistence.

Fix (TDD): _is_benign_vendor_cleanup suppresses a lone-LOLBAS-reason RunOnce
when the command is a pure cmd /c del|rmdir of a known-good vendor path, with
no command chaining (&&/|/&/;) and no payload launch. Guard tests prove a
cleanup outside a vendor path, a chained command, and a payload-launching cmd
all still fire — an attacker cannot cloak execution as "cleanup".

Result on real corpus: flagged Run keys 8 -> 2.

## Remaining 2 findings (not FPs — acceptable Low leads)

rd-01 (tdungan): Dashlane password manager autostart from AppData\Roaming\
Dashlane, scored Low (path-only, single reason). Dashlane is not on the vendor
allowlist, so it correctly surfaces as a low-confidence lead rather than being
silently trusted. This is the designed behavior for an unrecognized
user-writable autostart, not a defect.

## Forensic notes (cross-host context for future deep-dive)

User accounts observed across hosts include tier-separated admin accounts
(administrator.shieldbase domain admin, cbarton-a, rsydow-a) and standard users
(mhill, tdungan, spsql) — the SANS scenario's Avengers-themed enterprise. The
rd-01/rd-02 Administrator NTUSER.DAT hives failed to parse ("Invalid REGF ID" —
corrupt/locked), gracefully skipped. A full APT attack-chain reconstruction
(lateral movement, persistence timeline, exfil) across these hosts remains a
larger post-submission effort; this sweep covered the FP-hardening pass on the
timestomping + Run-key persistence surface.

## Quality gates

- 1317 tests pass
- 100% coverage maintained (fail_under=100)
- scenario harness F1=1.00 across all 14 scenarios
- ruff check + format clean
