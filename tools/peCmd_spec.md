# PECmd Tool Specification

**Tool:** PECmd (Eric Zimmerman)  
**Purpose:** Parse Windows Prefetch files  
**Location:** `/opt/zimmermantools/PECmd.dll`

---

## Invocation

```bash
dotnet /opt/zimmermantools/PECmd.dll \
  -d ./exports/prefetch/ \
  --csv ./exports/prefetch/ \
  --csvf prefetch_parsed.csv
```

---

## CSV Output Format

**Columns:**
- `SourceFilename` - Prefetch file name (e.g., `MALWARE.EXE-ABCD1234.pf`)
- `SourceCreated` - Prefetch file creation time
- `SourceModified` - Prefetch file modification time
- `SourceAccessed` - Prefetch file access time
- `Executable` - Executable name that was run
- `Hash` - Prefetch hash (path-based)
- `Size` - Executable size in bytes
- `Version` - Prefetch format version (Win7/Win8/Win10)
- `RunCount` - Number of times executed
- `LastRunTime` - Most recent execution timestamp
- `PreviousRunTime0` - 2nd most recent execution
- `PreviousRunTime1` - 3rd most recent
- `PreviousRunTime2` - 4th most recent
- `PreviousRunTime3` - 5th most recent
- `PreviousRunTime4` - 6th most recent
- `PreviousRunTime5` - 7th most recent
- `PreviousRunTime6` - 8th most recent (oldest)
- `Volume0Name` - Drive volume label
- `Volume0Serial` - Volume serial number
- `Volume0Created` - Volume creation time
- `Volume1Name` - Second volume (if multi-volume)
- `Directories` - Count of directories accessed
- `FilesLoaded` - List of DLLs and files loaded
- `DirectoriesLoaded` - List of directories accessed

---

## Timestamp Format

**Format:** ISO 8601 with fractional seconds, UTC  
**Example:** `2025-03-15T14:23:45.1234567Z` (7-digit precision)

**Null/Empty:** Empty string or not present

---

## Critical Timestamps for Validation

### Execution Timestamps

**LastRunTime:**
- Most recent execution of the program
- This is the primary execution timestamp

**PreviousRunTime0-6:**
- Up to 7 additional execution timestamps
- Ordered from newest (0) to oldest (6)
- Windows stores up to 8 total execution times

### Validation Rules

1. **Prefetch confirms EXECUTION** (not just file presence)
2. **LastRunTime should be AFTER file creation** (from MFT)
3. **LastRunTime should MATCH Event ID 4688** (within tolerance)

---

## Example CSV Row

```csv
SourceFilename,Executable,LastRunTime,RunCount,PreviousRunTime0,FilesLoaded
MALWARE.EXE-ABCD1234.pf,MALWARE.EXE,2025-03-15T14:25:00.1234567Z,3,2025-03-15T10:00:00.0000000Z,"C:\WINDOWS\SYSTEM32\KERNEL32.DLL,C:\WINDOWS\SYSTEM32\NTDLL.DLL"
```

**Interpretation:**
- Executable: malware.exe
- Last run: 2:25 PM (most recent)
- Previous run: 10:00 AM
- Run count: 3 times total
- Loaded system DLLs

---

## Parsing Requirements

1. **Extract executable name** (strip .pf extension and hash)
2. **Parse all run times** (LastRunTime + PreviousRunTime0-6)
3. **Handle empty previous runs** (not all 8 slots may be filled)
4. **Extract loaded files** (for DLL analysis)

---

## Cross-Artifact Validation

**Compare with MFT:**
- If MFT shows file modified AFTER LastRunTime = suspicious
- Prefetch LastRunTime should be >= MFT Created time

**Compare with Event Logs:**
- Event ID 4688 should match LastRunTime (±5 seconds)
- If no Event ID 4688 found = potential log tampering

---

*Reference: docs/PROTOCOL_SIFT_TOOL_INVENTORY.md*
