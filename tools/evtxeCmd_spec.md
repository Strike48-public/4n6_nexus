# EvtxECmd Tool Specification

**Tool:** EvtxECmd (Eric Zimmerman)  
**Purpose:** Parse Windows Event Logs (.evtx)  
**Location:** `/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll`

---

## Invocation

```bash
# Parse all logs with Maps for structured output
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -d ./exports/evtx/ \
  --csv ./exports/evtx/parsed/ \
  --maps /opt/zimmermantools/EvtxeCmd/Maps/

# Filter to specific Event IDs (process creation)
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -d ./exports/evtx/ \
  --inc 4688 \
  --csv ./exports/evtx/parsed/ \
  --csvf process_creation.csv
```

---

## CSV Output Format (with --maps)

**Common Columns:**
- `TimeCreated` - Event timestamp (UTC)
- `EventId` - Event ID number
- `RecordId` - Event record number
- `Level` - Severity (Information, Warning, Error, Critical)
- `Channel` - Log file (Security, System, Application, etc.)
- `Computer` - Hostname
- `UserId` - SID or account name
- `MapDescription` - Human-readable description
- `ChunkNumber` - Log chunk number
- `Payload` - Raw XML if Maps parsing failed

**Event-Specific Columns (via Maps):**
- `PayloadData1` through `PayloadData6` - Structured fields
  - Content varies by Event ID
  - Maps extract meaningful fields from XML

---

## Timestamp Format

**Format:** ISO 8601 with fractional seconds, UTC (when using --maps)  
**Example:** `2025-03-15T14:23:45.1234567Z`

**Without --maps:** US format with local timezone  
**Example:** `3/15/2025 2:23:45 PM` (AVOID - always use --maps)

---

## Critical Event IDs for Validation

### Event ID 4688 - Process Creation

**Purpose:** Confirms process execution  
**Log:** Security.evtx

**PayloadData Fields:**
- `PayloadData1` - New Process Name (full path)
- `PayloadData2` - Token Elevation Type
- `PayloadData3` - Process ID
- `PayloadData4` - Creator Process Name
- `PayloadData5` - Creator Process ID
- `PayloadData6` - Command Line (if audit policy enabled)

**Example Row:**
```csv
TimeCreated,EventId,PayloadData1,PayloadData6
2025-03-15T14:25:03.1234567Z,4688,C:\Users\victim\AppData\Local\Temp\malware.exe,"malware.exe --payload"
```

### Event ID 4689 - Process Termination

**Purpose:** Validates process runtime  
**PayloadData1:** Process name that exited

### Event ID 4663 - Object Access

**Purpose:** File access validation  
**PayloadData1:** Object name (file path)  
**PayloadData2:** Access mask

---

## Parsing Requirements for Validation

1. **Filter to Event ID 4688** for process creation
2. **Extract TimeCreated** (execution timestamp)
3. **Extract PayloadData1** (process path)
4. **Extract PayloadData6** (command line if available)
5. **Match executable name** from path

---

## Cross-Artifact Validation

### As Tiebreaker for MFT vs Prefetch

**Scenario:** MFT and Prefetch timestamps conflict

**Resolution:**
1. Query Event ID 4688 for the executable
2. Find events within ±5 minutes of Prefetch time
3. Event Log timestamp = ground truth
4. If Event Log matches Prefetch, trust Prefetch
5. If Event Log absent, flag as uncertain

**Example:**
```
MFT Modified: 10:05 AM
Prefetch LastRun: 10:00 AM
Event 4688: 10:00:03 AM

Resolution: Event Log confirms Prefetch (10:00 AM) is correct.
MFT timestamp likely reflects file update AFTER execution.
```

---

## Other Useful Event IDs

### Authentication
- **4624** - Successful logon
- **4625** - Failed logon
- **4672** - Special privileges assigned (admin)

### Account Management
- **4720** - User account created
- **4726** - User account deleted
- **4728** - Member added to security group

### System
- **7045** - Service installed
- **7040** - Service start type changed

---

## Parsing Requirements

1. **Always use --maps flag** for structured output
2. **Filter by Event ID** to reduce output size
3. **Handle missing PayloadData** (not all events have all fields)
4. **Match by executable name** (case-insensitive)

---

*Reference: docs/PROTOCOL_SIFT_TOOL_INVENTORY.md*
