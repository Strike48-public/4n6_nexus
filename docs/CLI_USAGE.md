# CLI Usage Guide

## Overview

The SIFT Find Evil CLI provides an interface to the autonomous self-correction engine for analyzing Windows forensic artifacts.

## Installation

```bash
# Clone repository
git clone https://github.com/Strike48-public/4n6_nexus.git
cd sift_find_evil

# Install core dependencies (add `-r requirements-forensic.txt` for real
# evidence: E01/raw images, PST, memory dumps)
pip install -r requirements.txt
```

## Commands

### Demo Mode

Run a demonstration with synthetic test data showing the self-correction engine in action.

```bash
python -m sift_find_evil demo
```

**What it does:**
- Loads synthetic MFT, Prefetch, and Event Log data
- Detects causality violation in malware.exe (modified 15 min after execution)
- Resolves contradiction using Event ID 4688 tiebreaker
- Displays finding with reasoning chain and confidence calculation

**Optional flags:**
- `--output FILE` or `-o FILE` - Write findings to JSON file

**Example:**
```bash
python -m sift_find_evil demo --output demo_results.json
```

### Analyze Mode

Analyze real forensic artifacts (MFTECmd, PECmd, EvtxECmd CSV output).

```bash
python -m sift_find_evil analyze \
  --mft /path/to/mft.csv \
  --prefetch /path/to/prefetch.csv \
  --evtx /path/to/evtx.csv
```

**Required arguments:**
- `--mft FILE` or `-m FILE` - Path to MFT CSV file (MFTECmd output)
- `--prefetch FILE` or `-p FILE` - Path to Prefetch CSV file (PECmd output)
- `--evtx FILE` or `-e FILE` - Path to Event Log CSV file (EvtxECmd output)

**Optional flags:**
- `--pst FILE` - Path to PST file for email exfiltration detection (optional)
- `--image FILE` or `-i FILE` - Path to disk image (.E01 or .dd) for wipe detection and/or content reading (optional)
- `--output FILE` or `-o FILE` - Write findings to JSON file

**Example:**
```bash
python -m sift_find_evil analyze \
  --mft evidence/mft_output.csv \
  --prefetch evidence/prefetch_output.csv \
  --evtx evidence/evtx_output.csv \
  --output findings.json
```

**Example with email exfiltration detection:**
```bash
python -m sift_find_evil analyze \
  --mft evidence/mft_output.csv \
  --prefetch evidence/prefetch_output.csv \
  --evtx evidence/evtx_output.csv \
  --pst evidence/user.pst \
  --image evidence/disk.E01 \
  --output findings.json
```

When `--pst` and `--image` are provided together:
- PST parser extracts email messages with attachment metadata and SHA-256 hashes
- Image content reader computes on-disk file hashes from the disk image
- Exfiltration detector correlates file-save-then-email patterns within a 5-minute window
- Hash-based matching provides cryptographic proof (confidence 0.95)
- Size+name fallback matching used when content reader unavailable (confidence 0.65)

## Output Format

### Console Output

The CLI displays:

1. **Banner** - Tool identification
2. **Loading Progress** - Artifact parsing status
3. **Analysis Progress** - Self-correction engine status
4. **Findings** - Detailed findings with:
   - Title and severity
   - Confidence score and label
   - Description
   - Contradictions detected
   - Resolutions applied
   - Reasoning chain (step-by-step logic)
   - Evidence collected
5. **Summary** - Statistics and validation

### JSON Output

When using `--output`, findings are written in structured JSON format:

```json
{
  "findings": [
    {
      "title": "Suspicious Activity: malware.exe",
      "description": "...",
      "type": "indicator",
      "severity": "high",
      "confidence": 0.75,
      "confidence_label": "Medium",
      "reasoning_chain": [...],
      "contradictions": [...],
      "resolutions": [...],
      "confidence_calculation": {...},
      "evidence": {...}
    }
  ],
  "summary": {
    "total_findings": 1,
    "mft_entries": 3,
    "prefetch_entries": 3,
    "event_log_entries": 5
  }
}
```

## Understanding Findings

### Severity Levels

- **CRITICAL** - Immediate threat, confirmed malicious activity
- **HIGH** - Strong indicators of compromise
- **MEDIUM** - Suspicious activity worth investigation
- **LOW** - Minor anomalies
- **INFO** - Informational findings

### Confidence Scores

Confidence scores range from 0.0 to 1.0:

- **0.80-1.0 (High)** - Strong evidence, cross-validated
- **0.60-0.79 (Medium)** - Moderate evidence, some contradictions resolved
- **0.40-0.59 (Low)** - Weak evidence or unresolved contradictions
- **0.0-0.39 (Very Low)** - Minimal evidence, multiple contradictions

### Contradiction Types

1. **Causality Violation** - File modified after execution (impossible)
2. **Timestomping** - $STANDARD_INFORMATION vs $FILE_NAME mismatch
3. **Missing Artifact** - Executable exists but no Prefetch evidence
4. **Temporal Mismatch** - Prefetch time doesn't match Event Log
5. **Exfil Correlation** - File saved then emailed within a short time window

### Resolutions

- **event_log_confirms_prefetch** - Event ID 4688 validates Prefetch execution time
- Resolutions increase confidence by showing cross-validation

## Preparing Evidence Files

### Using SIFT Workstation Tools

**1. Extract MFT:**
```bash
dotnet /opt/zimmermantools/MFTECmd/MFTECmd.dll \
  -f /mnt/evidence/C/\$MFT \
  --csv /cases/output \
  --csvf mft_output.csv
```

**2. Process Prefetch:**
```bash
dotnet /opt/zimmermantools/PECmd/PECmd.dll \
  -d /mnt/evidence/C/Windows/Prefetch \
  --csv /cases/output \
  --csvf prefetch_output.csv
```

**3. Parse Event Logs:**
```bash
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -d /mnt/evidence/C/Windows/System32/winevt/Logs \
  --csv /cases/output \
  --csvf evtx_output.csv
```

**4. Extract PST file (optional, for email exfiltration detection):**
```bash
# Mount disk image
sudo ewfmount /evidence/disk.E01 /mnt/ewf
sudo mount -o ro,loop,offset=$((2048*512)) /mnt/ewf/ewf1 /mnt/evidence

# Locate PST file
find /mnt/evidence -name "*.pst"

# Copy PST to working directory
cp /mnt/evidence/Users/Alice/AppData/Local/Microsoft/Outlook/archive.pst /cases/output/
```

Then run analysis:
```bash
python -m sift_find_evil analyze \
  --mft /cases/output/mft_output.csv \
  --prefetch /cases/output/prefetch_output.csv \
  --evtx /cases/output/evtx_output.csv \
  --pst /cases/output/archive.pst \
  --image /evidence/disk.E01 \
  --output /cases/findings.json
```

## Interpreting Results

### Example Finding

```
[Finding 1] Suspicious Activity: malware.exe
  Severity: HIGH
  Confidence: 0.75 (Medium)
  
  Contradictions Detected: 1
    1. causality_violation (high)
       Impact: -0.50
       File modified at 14:40 but executed at 14:25
  
  Resolutions Applied: 1
    1. event_log_confirms_prefetch
       Recovery: +0.30
  
  Reasoning Chain:
    1. Found 3 artifact types (MFT, Prefetch, EventLog)
    2. Initial confidence: 0.95
    3. Detected causality violation (impact: -0.50)
    4. Event Log confirms Prefetch time (recovery: +0.30)
    5. Final confidence: 0.75
```

**Interpretation:**
- **High severity** suggests strong indicators of compromise
- **Causality violation** indicates timestamp manipulation (file cannot be modified after execution)
- **Event Log resolution** confirms the true execution time, increasing confidence
- **Final confidence 0.75** means moderate certainty after self-correction

### Actionable Next Steps

1. **Review the executable** - Analyze malware.exe with additional tools (YARA, VirusTotal)
2. **Check persistence mechanisms** - Look for registry keys, scheduled tasks, services
3. **Timeline analysis** - Use Plaso to build full timeline around 14:25-14:40 timeframe
4. **Network activity** - Check for C2 communications around execution time
5. **File system analysis** - Look for related files created/modified in same timeframe

## Troubleshooting

### Error: File not found

Ensure paths are correct and files exist:
```bash
ls -l /path/to/mft.csv
```

### Error: No findings detected

Possible reasons:
- All artifacts are consistent (legitimate system activity)
- CSV files are empty or malformed
- Timestamps are all NULL/epoch values

### Error: Module not found

Ensure you're in the correct directory:
```bash
cd /path/to/sift_find_evil
python -m sift_find_evil demo
```

### Low confidence scores

Low confidence can indicate:
- Contradictions without resolutions (no Event Log evidence)
- Limited artifact diversity (only 1-2 sources)
- Genuine uncertainty in timeline reconstruction

## Advanced Usage

### Scripting

Run analysis in scripts:

```bash
#!/bin/bash
for case in /cases/*/; do
  echo "Analyzing $case"
  python -m sift_find_evil analyze \
    --mft "$case/mft.csv" \
    --prefetch "$case/prefetch.csv" \
    --evtx "$case/evtx.csv" \
    --output "$case/findings.json"
done
```

### Batch Processing

Process multiple cases:

```python
import subprocess
import json
from pathlib import Path

cases = Path('/cases').glob('case_*/')

for case_dir in cases:
    result = subprocess.run([
        'python', '-m', 'sift_find_evil', 'analyze',
        '--mft', str(case_dir / 'mft.csv'),
        '--prefetch', str(case_dir / 'prefetch.csv'),
        '--evtx', str(case_dir / 'evtx.csv'),
        '--output', str(case_dir / 'findings.json')
    ], capture_output=True)
    
    if result.returncode == 0:
        print(f"✓ {case_dir.name}")
    else:
        print(f"✗ {case_dir.name}: {result.stderr}")
```

## Further Reading

- [Timestamp Formats](TIMESTAMP_FORMATS.md) - Understanding Windows timestamp precision
- [Tool Specifications](../tools/) - MFTECmd, PECmd, EvtxECmd output formats
- [Test Data](../scenarios/synthetic/README.md) - Understanding synthetic test scenarios

## Support

Report issues: https://github.com/Strike48-public/4n6_nexus/issues
