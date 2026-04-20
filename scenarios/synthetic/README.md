# Synthetic Scenarios

Deterministic CSV fixtures for unit-style regression of the self-correction engine. Tracked in git, used by the automated harness and CI.

Each scenario lives in its own directory and includes `mft.csv`, `prefetch.csv`, and `evtx.csv` shaped like MFTECmd, PECmd, and EvtxECmd output. A `scenario.yaml` manifest provides ground truth for the test harness.

## Scenarios

### 01_clean_baseline
Legitimate activity with no contradictions. Expected findings: 0.

- chrome.exe, firefox.exe, notepad.exe, calc.exe
- All MFT timestamps align with Prefetch and Event Log evidence

### 02_ransomware
Three causality violations plus a shadow copy deletion indicator. Expected findings: 3 causality violations (all resolved by Event ID 4688).

- ransom_note.exe: modified 10:45 but executed 10:30 (15 min gap)
- crypt_engine.exe: modified 11:00 but executed 10:45 (15 min gap)
- persist.exe: modified 11:30 but executed 11:15 (15 min gap)
- cmd.exe invoked `vssadmin delete shadows /all`

### 03_timestomping
Three files with `$SI` timestamps backdated years before `$FN`. Expected findings: 2 (executables with matching Prefetch).

- backdoor.exe: $SI=2020-01-15, $FN=2025-03-15
- stolen_creds.dll: $SI=2021-06-10, $FN=2025-03-15 (not detected - engine pivots on PF executables)
- keylogger.exe: $SI=2022-03-01, $FN=2025-03-15
- svchost.exe aligned (legitimate control)

### 04_edge_cases
Boundary conditions for tolerance and null handling. Expected findings: 2.

- just_under_tolerance.exe: 4 min delta (below 5 min tolerance - no finding)
- just_over_tolerance.exe: 6 min delta (above tolerance - finding)
- null_timestamps.exe: Windows epoch (skipped as null)
- future_timestamp.exe: modified 2099 (causality violation)

### 05_missing_prefetch
Insider threat where attacker deletes Prefetch. Expected findings: 3.

- data_exfil.exe: MFT + Event Log only (no PF)
- zip_tool.exe: MFT + Event Log only (no PF)
- cleaner.exe: ran `--wipe-prefetch` in Event Log
- explorer.exe: normal baseline

### 06_webmail_exfiltration
Webmail-based data exfiltration detection (browser history). Adds `browser_history.csv` alongside the standard triple.

### 08_persistence_run_keys
Persistence via HKCU Run key launching `powershell.exe -enc` against `beacon.ps1`. Adds `run_keys.csv`, `amcache.csv`, `bam.csv`. Expected findings: 2 (Run key persistence + attacker-writable-path execution of `beacon.exe`). Exercises the LOLBAS-aware payload-basename extraction in `RegistryDetector`.

### 09_shimcache_only
Attacker wiped Prefetch; only Shimcache still records staging binaries. Adds `shimcache.csv`. Expected findings: 2 (`stage1.exe` in ProgramData, double-extension `report.pdf.exe` in Users\Public). Includes a System32 cmd.exe row as control.

### 10_timestomping_with_bam
Dual-detector scenario. `backdoor.exe` is timestomped ($SI vs $FN) and caught by the SelfCorrectionEngine timestomping pathway; `ldr.exe` runs from `C:\Users\Public\Downloads` and is caught by `RegistryDetector` via BAM + attacker-writable-path heuristic. Adds `bam.csv`.

## Adding a Scenario

1. Create `scenarios/synthetic/NN_<name>/`
2. Add CSVs: `mft.csv`, `prefetch.csv`, `evtx.csv` (+ optional parsers)
   - Registry fixtures: `shimcache.csv`, `amcache.csv`, `bam.csv`, `userassist.csv`, `run_keys.csv`
3. Add `scenario.yaml` manifest (see `../_schemas/scenario.yaml`)
4. Tests are picked up automatically via the `scenarios/**/scenario.yaml` glob
