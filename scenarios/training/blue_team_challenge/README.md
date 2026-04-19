# Blue Team IR Challenge (2019)

**Source:** DFIR.training
**Size:** ~10 GB
**Format:** E01 disk image + memory dump
**OS:** Windows 10

## Scenario

Compromised Windows 10 workstation with lateral movement indicators.

## Investigation Focus

- Memory forensics (process analysis)
- Timeline analysis across disk and memory
- Lateral movement artifact collection
- Persistence mechanism identification

## Files Needed

Download from https://www.dfir.training/downloads/test-images:
- compromised_system.E01
- memory_dump.raw (or similar)

## Analysis Steps

1. Run Volatility 3 against memory dump
2. Mount and analyze disk image
3. Correlate memory and disk artifacts
4. Build comprehensive timeline
5. Identify initial access and persistence

## Expected Time

6-8 hours for complete investigation
