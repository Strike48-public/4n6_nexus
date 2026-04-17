# Test Scenarios

Five synthetic scenarios for evaluating the self-correction engine.

Each scenario includes three CSV artifacts (`mft.csv`, `prefetch.csv`, `evtx.csv`) shaped like MFTECmd, PECmd, and EvtxECmd output.

## Scenario 1: Clean Baseline (`01_clean_baseline/`)

Legitimate activity with no contradictions.
- chrome.exe, firefox.exe, notepad.exe, calc.exe
- All MFT timestamps align with Prefetch and Event Log evidence.

Expected findings: 0.

## Scenario 2: Ransomware Attack Chain (`02_ransomware/`)

Three causality violations plus a shadow copy deletion indicator.
- ransom_note.exe: modified 10:45 but executed 10:30 (15 min gap)
- crypt_engine.exe: modified 11:00 but executed 10:45 (15 min gap)
- persist.exe: modified 11:30 but executed 11:15 (15 min gap)
- cmd.exe invoked `vssadmin delete shadows /all`

Expected findings: 3 causality violations (all resolved by Event ID 4688).

## Scenario 3: Timestomping (`03_timestomping/`)

Three files with `$SI` timestamps backdated years before `$FN` timestamps.
- backdoor.exe: $SI=2020-01-15, $FN=2025-03-15
- stolen_creds.dll: $SI=2021-06-10, $FN=2025-03-15
- keylogger.exe: $SI=2022-03-01, $FN=2025-03-15
- svchost.exe is aligned (legitimate control).

Expected findings: timestomping on executables with matching Prefetch (backdoor.exe, keylogger.exe). DLL is not currently checked because the engine pivots on Prefetch executables.

## Scenario 4: Edge Cases (`04_edge_cases/`)

Boundary conditions for tolerance and null handling.
- just_under_tolerance.exe: 4 min delta (below 5 min tolerance - no finding)
- just_over_tolerance.exe: 6 min delta (above tolerance - finding)
- null_timestamps.exe: Windows epoch timestamps (skipped as null)
- future_timestamp.exe: Modified in 2099 (causality violation)

Expected findings: 2 (just_over_tolerance.exe, future_timestamp.exe).

## Scenario 5: Missing Prefetch (`05_missing_prefetch/`)

Insider threat pattern where attacker deletes Prefetch.
- data_exfil.exe: MFT and Event Log only (no Prefetch)
- zip_tool.exe: MFT and Event Log only (no Prefetch)
- cleaner.exe: ran `--wipe-prefetch` in Event Log
- explorer.exe: normal baseline.

Expected findings: 3 missing-artifact findings.
