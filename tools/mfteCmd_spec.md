# MFTECmd Tool Specification

**Tool:** MFTECmd (Eric Zimmerman)  
**Purpose:** Parse NTFS Master File Table ($MFT)  
**Location:** `/opt/zimmermantools/MFTECmd.dll`

---

## Invocation

```bash
dotnet /opt/zimmermantools/MFTECmd.dll \
  -f ./exports/mft/$MFT \
  --csv ./exports/mft/ \
  --csvf mft_parsed.csv
```

---

## CSV Output Format

**Columns:**
- `EntryNumber` - MFT record number (integer)
- `SequenceNumber` - MFT sequence number
- `InUse` - Boolean (True/False)
- `ParentEntryNumber` - Parent directory MFT entry
- `ParentSequenceNumber` - Parent sequence number
- `ParentPath` - Full parent directory path
- `FileName` - File name
- `Extension` - File extension
- `FileSize` - Size in bytes
- `ReferenceCount` - Hard link count
- `ReparseTarget` - Symlink/junction target
- `IsDirectory` - Boolean
- `HasAds` - Has Alternate Data Streams
- `IsAds` - Is an ADS
- `SI_LtModified` - $STANDARD_INFORMATION last modified (UTC)
- `SI_LtAccess` - $STANDARD_INFORMATION last access (UTC)
- `SI_LtMftModified` - $STANDARD_INFORMATION MFT change (UTC)
- `SI_LtCreated` - $STANDARD_INFORMATION creation (UTC)
- `FN_LtModified` - $FILE_NAME last modified (UTC)
- `FN_LtAccess` - $FILE_NAME last access (UTC)
- `FN_LtMftModified` - $FILE_NAME MFT change (UTC)
- `FN_LtCreated` - $FILE_NAME creation (UTC)
- `SI_Flags` - $SI file attributes
- `FN_Flags` - $FN file attributes
- `ObjectID` - GUID if present
- `Created0x10` - Alias for SI_LtCreated
- `Created0x30` - Alias for FN_LtCreated
- `Modified0x10` - Alias for SI_LtModified
- `Modified0x30` - Alias for FN_LtModified

---

## Timestamp Format

**Format:** ISO 8601 with microseconds, UTC  
**Example:** `2025-03-15T14:23:45.123456Z`

**Null Timestamp:** `1601-01-01T00:00:00.0000000Z` (Windows epoch)

---

## Critical Timestamps for Validation

### $STANDARD_INFORMATION (0x10) vs $FILE_NAME (0x30)

**$STANDARD_INFORMATION:**
- `Created0x10` / `SI_LtCreated`
- `Modified0x10` / `SI_LtModified`
- Can be modified by SetFileTime API
- **Easier to tamper**

**$FILE_NAME:**
- `Created0x30` / `FN_LtCreated`
- `Modified0x30` / `FN_LtModified`
- Updated by MFT operations
- **Harder to tamper** (requires MFT record modification)

**Timestomping Detection:**
If `SI_LtModified < FN_LtModified`, file was likely timestomped.

---

## Example CSV Row

```csv
EntryNumber,FileName,ParentPath,Created0x10,Created0x30,Modified0x10,Modified0x30
12345,malware.exe,C:\Users\victim\AppData\Local\Temp,2025-03-15T10:00:00.0000000Z,2025-03-15T14:00:00.0000000Z,2025-03-15T10:05:00.0000000Z,2025-03-15T14:05:00.0000000Z
```

**Interpretation:**
- File created according to $SI: 10:00 AM
- File created according to $FN: 2:00 PM
- This is suspicious - $SI earlier than $FN suggests tampering

---

## Parsing Requirements

1. **Parse all timestamp columns** (8 total: 4 from $SI, 4 from $FN)
2. **Detect null timestamps** (1601-01-01)
3. **Compare $SI vs $FN** for timestomping
4. **Extract full file path** (ParentPath + FileName)

---

*Reference: docs/PROTOCOL_SIFT_TOOL_INVENTORY.md*
