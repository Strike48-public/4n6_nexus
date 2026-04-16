# Protocol SIFT Tool Inventory

**Date:** 2026-04-16  
**Purpose:** Complete mapping of forensic tools for self-correction implementation  
**Source:** Protocol SIFT skill files analysis

---

## Tools for Cross-Artifact Validation (MVP Star Feature)

These are the tools we'll use to implement timestamp contradiction detection and resolution.

### MFT Analysis

**Tool:** MFTECmd  
**Location:** `/opt/zimmermantools/MFTECmd.dll`  
**Invocation:**
```bash
dotnet /opt/zimmermantools/MFTECmd.dll \
  -f ./exports/mft/$MFT \
  --csv ./exports/mft/ \
  --csvf mft_parsed.csv
```

**Output Format:** CSV with columns:
- `EntryNumber` - MFT record number
- `FileName` - File name
- `ParentPath` - Directory path
- `Created0x10` - $STANDARD_INFORMATION creation time
- `Created0x30` - $FILE_NAME creation time
- `Modified0x10` - $STANDARD_INFORMATION modification time
- `Modified0x30` - $FILE_NAME modification time
- `Accessed0x10` - $STANDARD_INFORMATION access time
- `Accessed0x30` - $FILE_NAME access time
- `Changed0x10` - $STANDARD_INFORMATION change time

**Timestamp Format:** ISO 8601 (UTC)  
**Our Usage:** Extract file modification timestamps (both $SI and $FN attributes)

**Key Finding for Self-Correction:**
- $STANDARD_INFORMATION timestamps can be tampered (SetFileTime API)
- $FILE_NAME timestamps are harder to modify (require MFT record edit)
- Contradiction between 0x10 and 0x30 timestamps = timestomping indicator

---

### Prefetch Analysis

**Tool:** PECmd  
**Location:** `/opt/zimmermantools/PECmd.dll`  
**Invocation:**
```bash
dotnet /opt/zimmermantools/PECmd.dll \
  -d ./exports/prefetch/ \
  --csv ./exports/prefetch/ \
  --csvf prefetch_parsed.csv
```

**Output Format:** CSV with columns:
- `SourceFilename` - Prefetch file name (e.g., `MALWARE.EXE-ABCD1234.pf`)
- `Executable` - Executable that was run
- `LastRunTime` - Most recent execution time
- `RunCount` - Number of times executed
- `PreviousRunTime0` through `PreviousRunTime6` - Last 7 additional run times
- `FilesLoaded` - DLLs and files accessed during execution
- `VolumeName` - Drive volume where executable was located
- `VolumeSerialNumber` - Volume serial number

**Timestamp Format:** ISO 8601 (UTC)  
**Our Usage:** Extract last run time for executables

**Key Finding for Self-Correction:**
- Prefetch confirms EXECUTION (not just presence on disk)
- Contains up to 8 execution timestamps
- If executable exists in MFT but NOT in Prefetch, it may not have run

---

### Event Log Analysis

**Tool:** EvtxECmd  
**Location:** `/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll`  
**Invocation:**
```bash
# Parse with Maps for structured field extraction
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -d ./exports/evtx/ \
  --csv ./exports/evtx/parsed/ \
  --maps /opt/zimmermantools/EvtxeCmd/Maps/

# Filter to process creation events only
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -d ./exports/evtx/ \
  --inc 4688 \
  --csv ./exports/evtx/parsed/ \
  --csvf process_creation.csv
```

**Output Format:** CSV with columns (Event ID 4688 - Process Creation):
- `TimeCreated` - Event timestamp
- `EventId` - 4688
- `RecordId` - Event record number
- `PayloadData1` - New Process Name (full path)
- `PayloadData2` - Token Elevation Type
- `PayloadData3` - Process ID
- `PayloadData4` - Creator Process Name
- `PayloadData5` - Creator Process ID
- `PayloadData6` - Command Line (if enabled)
- `Computer` - Host name
- `UserId` - Account that ran the process

**Timestamp Format:** ISO 8601 (UTC)  
**Our Usage:** Use Event ID 4688 as tiebreaker when MFT and Prefetch timestamps conflict

**Key Event IDs for Validation:**
| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| 4688 | Process created | Tiebreaker for execution time |
| 4689 | Process exited | Validates process runtime |
| 4663 | File accessed | Validates file access time |
| 4656 | File handle opened | Validates file open time |
| 4660 | File deleted | Validates deletion time |

---

### Timeline Generation (Super-Timeline)

**Tool:** Plaso log2timeline.py  
**Location:** System PATH (`log2timeline.py`)  
**Invocation:**
```bash
# Generate super-timeline from disk image
log2timeline.py --storage-file ./analysis/case.plaso /mnt/ewf/ewf1

# Export to CSV
psort.py -o l2tcsv -w ./exports/timeline.csv ./analysis/case.plaso
```

**Output Format:** CSV with columns:
- `date` - Timestamp (YYYY-MM-DD HH:MM:SS UTC)
- `timestamp_desc` - What the timestamp represents (Modified, Accessed, Created, etc.)
- `source` - Artifact source (FILE, LOG, WEBHIST, etc.)
- `source_long` - Detailed source description
- `message` - Event description
- `parser` - Parser that extracted this artifact
- `display_name` - File or artifact name
- `filename` - Full path

**Timestamp Format:** ISO 8601 (UTC)  
**Our Usage:** Merge all artifact timestamps into one timeline for correlation

**Supported Sources:**
- FILE - MFT, $J, filesystem metadata
- LOG - Windows Event Logs (EVTX)
- PE - Prefetch files
- REG - Registry artifacts
- WEBHIST - Browser history
- And 100+ other parsers

---

## Self-Correction Implementation Plan

### Phase 1: Single-Source Timestamp Extraction

**MFT Timestamps:**
```python
import pandas as pd

def extract_mft_timestamps(mft_csv_path):
    df = pd.read_csv(mft_csv_path)
    
    # Return list of file findings with timestamps
    findings = []
    for _, row in df.iterrows():
        findings.append({
            'source': 'MFT',
            'file_path': f"{row['ParentPath']}\\{row['FileName']}",
            'mft_entry': row['EntryNumber'],
            'modified_si': pd.to_datetime(row['Modified0x10']),
            'modified_fn': pd.to_datetime(row['Modified0x30']),
            'created_si': pd.to_datetime(row['Created0x10']),
            'created_fn': pd.to_datetime(row['Created0x30']),
        })
    return findings
```

**Prefetch Timestamps:**
```python
def extract_prefetch_timestamps(prefetch_csv_path):
    df = pd.read_csv(prefetch_csv_path)
    
    findings = []
    for _, row in df.iterrows():
        findings.append({
            'source': 'Prefetch',
            'executable': row['Executable'],
            'last_run': pd.to_datetime(row['LastRunTime']),
            'run_count': row['RunCount'],
            'previous_runs': [
                pd.to_datetime(row[f'PreviousRunTime{i}'])
                for i in range(7)
                if pd.notna(row.get(f'PreviousRunTime{i}'))
            ]
        })
    return findings
```

**Event Log Timestamps:**
```python
def extract_event_log_process_creation(evtx_csv_path):
    df = pd.read_csv(evtx_csv_path)
    
    # Filter to Event ID 4688 (process creation)
    process_events = df[df['EventId'] == 4688]
    
    findings = []
    for _, row in process_events.iterrows():
        findings.append({
            'source': 'EventLog_4688',
            'timestamp': pd.to_datetime(row['TimeCreated']),
            'process_name': row['PayloadData1'],
            'command_line': row.get('PayloadData6', ''),
            'parent_process': row['PayloadData4'],
            'user': row['UserId']
        })
    return findings
```

---

### Phase 2: Cross-Artifact Correlation

**Find Matching Artifacts:**
```python
def correlate_file_to_prefetch(file_path, mft_findings, prefetch_findings):
    # Extract executable name from file path
    file_name = file_path.split('\\')[-1]
    
    # Find matching Prefetch entry
    for pf in prefetch_findings:
        if pf['executable'].lower() == file_name.lower():
            return pf
    
    return None

def correlate_prefetch_to_event_log(executable, prefetch_last_run, event_log_findings, tolerance_seconds=5):
    # Find Event ID 4688 within tolerance window of Prefetch last run time
    matches = []
    for event in event_log_findings:
        if executable.lower() in event['process_name'].lower():
            time_diff = abs((event['timestamp'] - prefetch_last_run).total_seconds())
            if time_diff <= tolerance_seconds:
                matches.append(event)
    
    return matches
```

---

### Phase 3: Contradiction Detection

**Timestamp Causality Violation:**
```python
def detect_timestamp_contradiction(mft_finding, prefetch_finding, tolerance_minutes=5):
    """
    Detect causality violations: file modified AFTER it was executed
    
    MFT says file.exe was modified at 10:05 AM
    Prefetch says file.exe ran at 10:00 AM
    
    This is impossible - you cannot run a file before it exists/was modified.
    """
    file_modified_time = mft_finding['modified_si']
    prefetch_last_run = prefetch_finding['last_run']
    
    # Check if file was "modified" AFTER it ran
    time_diff = (file_modified_time - prefetch_last_run).total_seconds() / 60.0
    
    if time_diff > tolerance_minutes:
        return {
            'type': 'timestamp_causality_violation',
            'severity': 'high',
            'description': f"File {mft_finding['file_path']} modified at {file_modified_time} but ran at {prefetch_last_run}",
            'mft_time': file_modified_time,
            'prefetch_time': prefetch_last_run,
            'time_delta_minutes': time_diff,
            'confidence_impact': -0.45  # Degrade confidence by 45%
        }
    
    return None
```

**Timestomping Detection:**
```python
def detect_timestomping(mft_finding):
    """
    Detect timestamp manipulation by comparing $STANDARD_INFORMATION vs $FILE_NAME
    
    $SI timestamps can be modified with SetFileTime API
    $FN timestamps require MFT record modification (harder to tamper)
    """
    si_modified = mft_finding['modified_si']
    fn_modified = mft_finding['modified_fn']
    
    # If $SI time is EARLIER than $FN time, timestomping likely occurred
    time_diff = (si_modified - fn_modified).total_seconds()
    
    if time_diff < -60:  # More than 1 minute discrepancy
        return {
            'type': 'timestomping_detected',
            'severity': 'critical',
            'description': f"$SI timestamp ({si_modified}) is earlier than $FN timestamp ({fn_modified})",
            'file_path': mft_finding['file_path'],
            'si_time': si_modified,
            'fn_time': fn_modified,
            'confidence_impact': -0.60  # Major confidence hit
        }
    
    return None
```

---

### Phase 4: Self-Correction Resolution

**Tiebreaker via Event Logs:**
```python
def resolve_contradiction_via_event_logs(contradiction, event_log_findings):
    """
    When MFT and Prefetch disagree, use Event ID 4688 as ground truth
    """
    file_path = contradiction['file_path']
    prefetch_time = contradiction['prefetch_time']
    
    # Search Event Logs for process creation within ±5 minutes of Prefetch time
    tolerance = timedelta(minutes=5)
    matching_events = []
    
    for event in event_log_findings:
        if file_path.lower() in event['process_name'].lower():
            time_diff = abs(event['timestamp'] - prefetch_time)
            if time_diff <= tolerance:
                matching_events.append(event)
    
    if matching_events:
        # Event Log confirms execution time - trust Prefetch over MFT
        resolution = {
            'resolution': 'event_log_confirms_prefetch',
            'ground_truth_time': matching_events[0]['timestamp'],
            'confidence_recovery': +0.30,  # Recover some confidence
            'reasoning': f"Event ID 4688 confirms execution at {matching_events[0]['timestamp']}, aligning with Prefetch"
        }
        return resolution
    else:
        # No Event Log confirmation - flag as uncertain
        resolution = {
            'resolution': 'uncertain_no_event_log',
            'confidence_recovery': 0,
            'reasoning': 'No Event ID 4688 found to confirm execution time'
        }
        return resolution
```

---

### Phase 5: Confidence Scoring

**Confidence Calculation:**
```python
class Finding:
    def __init__(self, description, evidence, confidence=0.85):
        self.description = description
        self.evidence = evidence
        self.confidence = confidence
        self.contradictions = []
        self.resolutions = []
    
    def detect_contradictions(self, other_findings):
        # Run all contradiction detection logic
        # Append to self.contradictions
        pass
    
    def apply_resolution(self, resolution):
        self.resolutions.append(resolution)
        self.confidence += resolution['confidence_recovery']
        self.confidence = max(0.0, min(1.0, self.confidence))  # Clamp to [0, 1]
    
    def to_dict(self):
        return {
            'description': self.description,
            'confidence': round(self.confidence, 2),
            'evidence': self.evidence,
            'contradictions': [c['description'] for c in self.contradictions],
            'resolutions': [r['reasoning'] for r in self.resolutions]
        }
```

---

## Timestamp Format Standards

All timestamps in Protocol SIFT outputs use **ISO 8601 format in UTC:**

```
2025-03-15T14:23:45.123456Z
```

**Parsing in Python:**
```python
from dateutil import parser
import pytz

def parse_timestamp(timestamp_str):
    """Parse any ISO 8601 timestamp to UTC datetime"""
    dt = parser.isoparse(timestamp_str)
    
    # Ensure UTC
    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt)
    else:
        dt = dt.astimezone(pytz.utc)
    
    return dt
```

---

## Tool Output Locations

Following Protocol SIFT conventions:

| Tool | Output Location | File Pattern |
|------|-----------------|--------------|
| MFTECmd | `./exports/mft/` | `mft_parsed.csv` |
| PECmd | `./exports/prefetch/` | `prefetch_parsed.csv` |
| EvtxECmd | `./exports/evtx/parsed/` | `*.csv` (one per log) |
| log2timeline | `./analysis/` | `case.plaso` |
| psort | `./exports/` | `timeline.csv` |
| AppCompatCacheParser | `./exports/shimcache/` | `shimcache.csv` |
| AmcacheParser | `./exports/amcache/` | `amcache.csv` |
| RECmd | `./exports/registry/` | `*_batch.csv` |
| SBECmd | `./exports/shellbags/` | `*.csv` |

---

## Tool Performance Considerations

**Speed Rankings (Fastest → Slowest):**

1. **MFTECmd** - Very fast (<1 min for 100GB disk)
2. **PECmd** - Fast (seconds for typical Prefetch dir)
3. **EvtxECmd** - Fast to Medium (depends on log size)
4. **log2timeline** - SLOW (30+ min for 100GB disk with all parsers)

**Optimization Strategy:**
- Always run MFTECmd, PECmd, EvtxECmd first (fast, targeted)
- Only run log2timeline if super-timeline is explicitly needed
- For MVP demo, we can skip log2timeline and just use direct tool outputs

---

## Next Steps for Implementation

### Validation Phase 2-3 (This Week):
1. Execute MFTECmd on test MFT
2. Execute PECmd on test Prefetch files
3. Execute EvtxECmd on test Event Logs
4. Parse outputs with pandas
5. Implement correlation logic

### Validation Phase 4 (Next Week):
1. Create synthetic contradictions (modify CSV test data)
2. Implement contradiction detection
3. Implement resolution via tiebreaker
4. Log full reasoning chain
5. Measure confidence before/after

---

## Reference Documentation

- **EZ Tools Documentation:** https://ericzimmerman.github.io/
- **MFTECmd Guide:** https://github.com/EricZimmerman/MFTECmd
- **Sleuth Kit Book:** http://www.sleuthkit.org/sleuthkit/docs.php
- **Plaso Documentation:** https://plaso.readthedocs.io/

---

*Last Updated: 2026-04-16*
