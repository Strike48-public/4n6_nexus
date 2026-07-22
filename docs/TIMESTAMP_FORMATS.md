# Timestamp Formats Reference

**Date:** 2026-04-16  
**Purpose:** Comprehensive reference for parsing timestamps from forensic tools  
**Critical for:** Cross-artifact validation timestamp comparison

---

## Why This Matters

Cross-artifact validation requires comparing timestamps from different tools. Each tool may output timestamps in different formats, timezones, or precisions. **Wrong timestamp parsing = false contradictions = broken self-correction.**

---

## Tool Output Formats

### MFTECmd

**Format:** ISO 8601 with microseconds, UTC  
**Example:** `2025-03-15T14:23:45.123456Z`

**Parsing:**
```python
from dateutil import parser

timestamp_str = "2025-03-15T14:23:45.123456Z"
dt = parser.isoparse(timestamp_str)
# dt is timezone-aware datetime in UTC
```

**CSV Column Names:**
- `Created0x10` - $STANDARD_INFORMATION creation time
- `Created0x30` - $FILE_NAME creation time
- `Modified0x10` - $STANDARD_INFORMATION modification time
- `Modified0x30` - $FILE_NAME modification time
- `Accessed0x10` - $STANDARD_INFORMATION access time
- `Accessed0x30` - $FILE_NAME access time
- `Changed0x10` - $STANDARD_INFORMATION MFT change time

**Special Cases:**
- Null timestamps: `1601-01-01T00:00:00.0000000Z` (Windows epoch)
- Zero timestamp means "not set" (ignore in comparisons)

---

### PECmd

**Format:** ISO 8601 with fractional seconds, UTC  
**Example:** `2025-03-15T14:23:45.1234567Z` (7 digits)

**Parsing:**
```python
from dateutil import parser

timestamp_str = "2025-03-15T14:23:45.1234567Z"
dt = parser.isoparse(timestamp_str)
# Handles variable precision automatically
```

**CSV Column Names:**
- `LastRunTime` - Most recent execution
- `PreviousRunTime0` through `PreviousRunTime6` - Last 7 additional runs
- `SourceCreated` - Prefetch file creation time
- `SourceModified` - Prefetch file modification time

**Special Cases:**
- Prefetch files store up to 8 run times total
- If `PreviousRunTimeN` is empty, no Nth previous run exists
- Prefetch timestamps are based on FILETIME (100-nanosecond intervals since 1601)

---

### EvtxECmd

**Format:** ISO 8601 with fractional seconds, UTC (when using --maps)  
**Example:** `2025-03-15T14:23:45.1234567Z`

**Without --maps:** US format with local timezone  
**Example:** `3/15/2025 2:23:45 PM`

**Parsing (with --maps - recommended):**
```python
from dateutil import parser

timestamp_str = "2025-03-15T14:23:45.1234567Z"
dt = parser.isoparse(timestamp_str)
```

**Parsing (without --maps - fallback):**
```python
from datetime import datetime
import pytz

timestamp_str = "3/15/2025 2:23:45 PM"
dt_naive = datetime.strptime(timestamp_str, "%m/%d/%Y %I:%M:%S %p")

# CRITICAL: Determine timezone from System event log or case metadata
# Assume UTC if unknown (safest for international cases)
dt = pytz.utc.localize(dt_naive)
```

**CSV Column Names:**
- `TimeCreated` - Event timestamp
- `PayloadData1` through `PayloadDataN` - Varies by Event ID

**Special Cases:**
- Always use `--maps` flag to get ISO 8601 output
- Without maps, timezone is ambiguous (local to evidence machine)
- Event ID 4688 includes process creation time in `TimeCreated`

---

### Plaso (log2timeline / psort)

**Format:** `YYYY-MM-DD HH:MM:SS UTC` (psort -o l2tcsv)  
**Example:** `2025-03-15 14:23:45 UTC`

**Parsing:**
```python
from datetime import datetime
import pytz

timestamp_str = "2025-03-15 14:23:45 UTC"
dt_naive = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S %Z")
dt = pytz.utc.localize(dt_naive)
```

**Alternative Format:** ISO 8601 (if using `--output_time_zone UTC`)  
**Example:** `2025-03-15T14:23:45+00:00`

**CSV Column Names:**
- `date` - Timestamp
- `timestamp_desc` - What this timestamp represents (Modified, Accessed, etc.)
- `source` - Artifact type (FILE, LOG, PE, etc.)
- `message` - Event description

**Special Cases:**
- Plaso normalizes all timestamps to UTC
- Multiple timestamp types per artifact (MACB = Modified, Accessed, Changed, Birth)
- `timestamp_desc` field tells you which timestamp this is

---

### AppCompatCacheParser (Shimcache)

**Format:** ISO 8601 with microseconds, UTC  
**Example:** `2025-03-15T14:23:45.123456Z`

**Parsing:** Same as MFTECmd (ISO 8601)

**CSV Column Names:**
- `LastModifiedTimeUTC` - File last modified time
- `CacheEntryPosition` - Order in cache

**Special Cases:**
- Shimcache timestamps on Win8+ are NOT execution times (just file existence)
- Shimcache on Win7 shows last EXECUTION time
- Check OS version in SYSTEM registry before interpreting

---

### AmcacheParser

**Format:** ISO 8601 with fractional seconds, UTC  
**Example:** `2025-03-15T14:23:45.1234567Z`

**Parsing:** Same as PECmd (ISO 8601)

**CSV Column Names:**
- `FileKeyLastWriteTimestamp` - Registry key last write time
- `LinkDate` - PE binary link/compile timestamp
- `Created` - First time binary was executed (Win10+)

**Special Cases:**
- `LinkDate` can be forged by attacker (PE header manipulation)
- `Created` is more reliable (comes from registry activity)

---

## Timestamp Precision Comparison

| Tool | Precision | Notes |
|------|-----------|-------|
| MFTECmd | 100ns (FILETIME) | Windows native precision |
| PECmd | 100ns (FILETIME) | Same as MFT |
| EvtxECmd | 100ns (FILETIME) | Event Log native format |
| Plaso | 1 microsecond | Normalized by Plaso |
| Shimcache | 100ns (FILETIME) | From registry FILETIME |
| Amcache | 100ns (FILETIME) | From registry FILETIME |

**For Comparison:**
- Truncate to **1 second precision** when comparing across tools
- Reason: Filesystem metadata vs execution logs may have slight timing skew
- If difference is <1 second, consider them equivalent

---

## Tolerance Windows for Contradiction Detection

| Comparison | Tolerance | Rationale |
|------------|-----------|-----------|
| MFT vs Prefetch | 5 minutes | Prefetch updates on close, MFT on write |
| Prefetch vs Event Log | 5 seconds | Event 4688 logs start, Prefetch logs completion |
| MFT $SI vs $FN | 1 minute | Legitimately can differ during moves |
| Shimcache vs MFT | 10 minutes | Cache writes batched |

**Golden Rule:** If timestamps agree within tolerance, NO contradiction.

---

## Timezone Handling

### Protocol SIFT Default: UTC

All Protocol SIFT tools output UTC by default when possible.

**Verification:**
```python
def verify_utc(dt):
    """Check if datetime is UTC-aware"""
    return dt.tzinfo is not None and dt.tzinfo == pytz.utc
```

### Converting Local to UTC

If you encounter a local timestamp (from evidence without UTC conversion):

```python
from datetime import datetime
import pytz

# Evidence machine was in US/Eastern timezone
local_tz = pytz.timezone('US/Eastern')
timestamp_str = "2025-03-15 10:23:45"  # Local time

# Parse as naive datetime
dt_naive = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

# Localize to evidence timezone
dt_local = local_tz.localize(dt_naive)

# Convert to UTC
dt_utc = dt_local.astimezone(pytz.utc)
```

**Critical:** Always determine evidence machine timezone from:
1. SYSTEM registry `TimeZoneInformation` key
2. Event Log header metadata
3. Case documentation

---

## Null/Invalid Timestamp Handling

### Windows Epoch: `1601-01-01T00:00:00Z`

This is the Windows FILETIME epoch. In NTFS, it means "timestamp not set."

```python
WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=pytz.utc)

def is_null_timestamp(dt):
    """Check if timestamp is Windows epoch (null)"""
    return dt == WINDOWS_EPOCH
```

### Unix Epoch: `1970-01-01T00:00:00Z`

Sometimes seen in Plaso output for artifacts without timestamps.

```python
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=pytz.utc)

def is_unix_epoch(dt):
    """Check if timestamp is Unix epoch"""
    return dt == UNIX_EPOCH
```

### Handling in Comparison

```python
def compare_timestamps(dt1, dt2, tolerance_seconds=300):
    """
    Compare two timestamps with tolerance window.
    Returns 0 if within tolerance, -1 if dt1 < dt2, +1 if dt1 > dt2.
    Returns None if either timestamp is null.
    """
    if is_null_timestamp(dt1) or is_null_timestamp(dt2):
        return None
    
    if is_unix_epoch(dt1) or is_unix_epoch(dt2):
        return None
    
    diff = (dt1 - dt2).total_seconds()
    
    if abs(diff) <= tolerance_seconds:
        return 0  # Equivalent
    elif diff < 0:
        return -1  # dt1 is earlier
    else:
        return +1  # dt1 is later
```

---

## Common Parsing Errors

### Error 1: Timezone-Naive Datetime Comparison

**Wrong:**
```python
dt1 = datetime.strptime("2025-03-15 14:23:45", "%Y-%m-%d %H:%M:%S")
dt2 = datetime.strptime("2025-03-15 14:23:45", "%Y-%m-%d %H:%M:%S")
diff = dt1 - dt2  # Works, but DANGEROUS if timezones differ
```

**Correct:**
```python
dt1 = pytz.utc.localize(datetime.strptime("2025-03-15 14:23:45", "%Y-%m-%d %H:%M:%S"))
dt2 = pytz.utc.localize(datetime.strptime("2025-03-15 14:23:45", "%Y-%m-%d %H:%M:%S"))
diff = dt1 - dt2  # Safe
```

### Error 2: Mixing Local and UTC

**Wrong:**
```python
mft_time = parser.isoparse("2025-03-15T14:23:45Z")  # UTC
event_time = datetime.strptime("3/15/2025 10:23:45 AM", "%m/%d/%Y %I:%M:%S %p")  # Local (naive)
diff = mft_time - event_time  # TypeError: can't subtract offset-naive and offset-aware datetimes
```

**Correct:**
```python
mft_time = parser.isoparse("2025-03-15T14:23:45Z")  # UTC
event_time_naive = datetime.strptime("3/15/2025 10:23:45 AM", "%m/%d/%Y %I:%M:%S %p")
event_time = pytz.timezone('US/Eastern').localize(event_time_naive).astimezone(pytz.utc)
diff = mft_time - event_time  # Safe
```

### Error 3: Ignoring Microseconds

**Wrong:**
```python
# Truncating to seconds loses precision
dt = datetime.strptime("2025-03-15T14:23:45.123456Z", "%Y-%m-%dT%H:%M:%SZ")
# Result: microseconds discarded
```

**Correct:**
```python
# Use dateutil.parser - handles any ISO 8601 format
dt = parser.isoparse("2025-03-15T14:23:45.123456Z")
# Result: microseconds preserved
```

---

## Reference Implementation

```python
from datetime import datetime, timedelta
from dateutil import parser
import pytz

class TimestampComparator:
    """
    Utility class for comparing timestamps from forensic tools
    with tolerance windows and null handling.
    """
    
    WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=pytz.utc)
    UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=pytz.utc)
    
    def __init__(self, default_tolerance_seconds=300):
        self.default_tolerance = default_tolerance_seconds
    
    def parse_iso8601(self, timestamp_str):
        """Parse any ISO 8601 timestamp to UTC datetime"""
        dt = parser.isoparse(timestamp_str)
        
        # Ensure UTC
        if dt.tzinfo is None:
            dt = pytz.utc.localize(dt)
        else:
            dt = dt.astimezone(pytz.utc)
        
        return dt
    
    def is_null(self, dt):
        """Check if timestamp is null/epoch"""
        return dt == self.WINDOWS_EPOCH or dt == self.UNIX_EPOCH
    
    def compare(self, dt1, dt2, tolerance_seconds=None):
        """
        Compare two timestamps.
        Returns:
            None: One or both timestamps are null
            0: Timestamps within tolerance (equivalent)
            -1: dt1 is earlier than dt2 (beyond tolerance)
            +1: dt1 is later than dt2 (beyond tolerance)
        """
        if self.is_null(dt1) or self.is_null(dt2):
            return None
        
        tolerance = tolerance_seconds or self.default_tolerance
        diff = (dt1 - dt2).total_seconds()
        
        if abs(diff) <= tolerance:
            return 0
        elif diff < 0:
            return -1
        else:
            return +1
    
    def detect_causality_violation(self, file_modified, process_executed, tolerance_seconds=300):
        """
        Detect if file was modified AFTER it was executed.
        
        Args:
            file_modified: datetime from MFT $SI or $FN
            process_executed: datetime from Prefetch or Event Log
            tolerance_seconds: grace period for timing skew
        
        Returns:
            dict with violation details, or None if no violation
        """
        comparison = self.compare(file_modified, process_executed, tolerance_seconds)
        
        if comparison is None:
            return None  # Cannot determine (null timestamp)
        
        if comparison > 0:
            # file_modified > process_executed = VIOLATION
            time_delta = (file_modified - process_executed).total_seconds()
            return {
                'type': 'causality_violation',
                'description': f"File modified at {file_modified} but executed at {process_executed}",
                'time_delta_seconds': time_delta,
                'severity': 'high' if time_delta > 600 else 'medium'
            }
        
        return None  # No violation
```

---

## Testing Timestamp Parsing

```python
# Unit test examples
def test_mft_timestamp_parsing():
    ts = "2025-03-15T14:23:45.123456Z"
    dt = parser.isoparse(ts)
    assert dt.year == 2025
    assert dt.month == 3
    assert dt.day == 15
    assert dt.hour == 14
    assert dt.minute == 23
    assert dt.second == 45
    assert dt.microsecond == 123456
    assert dt.tzinfo == pytz.utc

def test_windows_epoch_detection():
    ts = "1601-01-01T00:00:00.0000000Z"
    dt = parser.isoparse(ts)
    comparator = TimestampComparator()
    assert comparator.is_null(dt) == True

def test_causality_violation():
    comparator = TimestampComparator()
    
    file_modified = parser.isoparse("2025-03-15T14:30:00Z")
    process_executed = parser.isoparse("2025-03-15T14:25:00Z")
    
    violation = comparator.detect_causality_violation(file_modified, process_executed)
    assert violation is not None
    assert violation['type'] == 'causality_violation'
    assert violation['time_delta_seconds'] == 300
```

---

## Summary

| Aspect | Guideline |
|--------|-----------|
| **Default Timezone** | Always UTC |
| **Parsing Library** | Use `dateutil.parser.isoparse()` |
| **Comparison Tolerance** | 5 minutes (300 seconds) |
| **Null Detection** | Check for 1601-01-01 (Windows epoch) |
| **Precision** | Truncate to 1 second for cross-tool comparison |

---

*Last Updated: 2026-04-16*
