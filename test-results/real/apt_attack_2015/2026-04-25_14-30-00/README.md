# APT Attack 2015 - Test Run: 2026-04-25 14:30:00

## Overview

Analysis of SANS SRL-2015 APT enterprise compromise scenario with enhanced detection engine.

## Test Configuration

- **Detection Engine Version**: Post-enhancement (attack pattern detection + Event Log correlation)
- **Evidence Source**: SANS SRL-2015 Compromised Enterprise Network
- **Systems Analyzed**: 6 of 7 (DMZ FTP, Domain Controller, File Server, Workstation 01, RD-01, RD-02, Workstation 05)
- **Duration**: 10 minutes 12 seconds
- **MFT Entries Processed**: 1,576,722
- **Event Log Entries Processed**: ~216,093

## Key Enhancements in This Run

1. **Scaled Confidence Scoring by Execution Frequency**
   - 6+ executions: INFO severity (system service pattern)
   - 2-5 executions: LOW severity with -0.08 confidence penalty
   - 1 execution: LOW severity with -0.10 confidence penalty

2. **Command Line Attack Pattern Detection**
   - 40+ attack signatures across 7 MITRE ATT&CK categories
   - Pattern matching on Event ID 4688 command lines
   - Technique-specific confidence scores (0.80-0.95)

3. **Event Log JSON Payload Parsing**
   - Fixed parser to extract NewProcessName and CommandLine from JSON
   - Previously relied on Maps-extracted PayloadData fields (incomplete)

## Results Summary

### Critical Findings

- **NTDS.dit Extraction** (Domain Controller) - 0.95 confidence
- **PsExec Lateral Movement** (DMZ FTP) - 0.95 confidence
- **Volume Shadow Copy Abuse** (3 systems) - 0.85 confidence
- **Scheduled Task Persistence** (DMZ FTP) - 0.80 confidence

### Files in This Directory

- `ENHANCEMENTS_COMPLETE.md` - Detailed enhancement specifications
- `dmz_ftp_results.md` - DMZ FTP server analysis (71 CRITICAL, 3 HIGH findings)
- `MULTI_SYSTEM_ANALYSIS.md` - 6-system enterprise analysis with attack chain reconstruction

## Next Steps

- Investigate workstation analysis failures (4 systems failed during detection phase)
- Optimize pattern matching for large Event Log sets
- Create cross-system correlation timeline report
