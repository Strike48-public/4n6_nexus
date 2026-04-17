# Synthetic Test Data

**Purpose:** Test cross-artifact validation with known contradictions

---

## Test Scenario: Ransomware Attack

This synthetic dataset simulates a ransomware attack with intentional timestamp manipulation.

### Files Included

1. **synthetic_mft.csv** - Master File Table entries
2. **synthetic_prefetch.csv** - Windows Prefetch execution evidence
3. **synthetic_evtx.csv** - Security Event Logs (Event ID 4688)

---

## Planted Contradiction: malware.exe

### Timeline of Events (Ground Truth)

**Actual execution sequence:**
1. **09:55:03 AM** - First execution (Event ID 4688 confirms)
2. **10:00:03 AM** - Second execution (Event ID 4688 confirms)
3. **14:25:03 PM** - Third execution (Event ID 4688 confirms, Prefetch LastRunTime)

### Observed Evidence

#### MFT Timestamps (Entry 12345)
- **$SI Created:** 09:55:00 AM (legitimate)
- **$SI Modified:** **14:30:00 PM** (SUSPICIOUS - after last execution!)
- **$FN Created:** 14:00:00 PM
- **$FN Modified:** 14:05:00 PM

#### Prefetch Timestamps
- **LastRunTime:** 14:25:00 PM (last execution)
- **PreviousRunTime0:** 10:00:00 AM
- **PreviousRunTime1:** 09:55:03 AM (first execution)
- **RunCount:** 3

#### Event ID 4688 (Process Creation)
- **14:25:03 PM** - Latest execution
- **10:00:03 AM** - Second execution
- **09:55:03 AM** - First execution

---

## Expected Contradictions

### Contradiction 1: Causality Violation

**MFT $SI Modified (14:30 PM) > Prefetch LastRunTime (14:25 PM)**

This violates causality - the file was modified **5 minutes AFTER** it was executed.

**Analysis:**
- Attacker ran malware at 14:25 PM
- Attacker then modified MFT $SI timestamp to 14:30 PM (timestomping attempt)
- But Prefetch and Event Logs preserve the true execution time

**Self-Correction Expected:**
1. Detect contradiction: MFT modified > Prefetch last run
2. Query Event ID 4688 for tiebreaker
3. Find execution at 14:25:03 PM (matches Prefetch within 3 seconds)
4. Resolution: Trust Prefetch + Event Log, flag MFT $SI as tampered
5. Confidence recovery: +0.30 (Event Log confirms ground truth)

### Contradiction 2: Timestomping ($SI vs $FN)

**MFT $SI Modified (14:30 PM) > $FN Modified (14:05 PM)**

Wait, this is **backwards** - normally timestomping makes $SI **earlier** than $FN.

**Actually, let me check the logic:**
- $SI can be modified with SetFileTime API
- $FN requires MFT record modification
- If attacker only used SetFileTime, $FN stays original

**This case:**
- $FN Modified: 14:05 PM (original, harder to fake)
- $SI Modified: 14:30 PM (modified by attacker)

This suggests the file's **real** modification time was around 14:05 PM, but attacker pushed $SI forward to 14:30 PM.

Actually, the typical timestomping pattern is $SI **earlier** than $FN. Let me reconsider the scenario.

**Revised understanding:**
The attacker may have:
1. Created malware.exe around 14:00-14:05 PM
2. Executed it at 14:25 PM
3. Attempted to modify timestamps to 14:30 PM but only changed $SI

This is still suspicious because the file shouldn't be modified after execution.

---

## Legitimate Files (No Contradictions)

### legitapp.exe
- **MFT Modified:** 10:00 AM (March 10)
- **Prefetch LastRun:** 08:00 AM (March 15)
- **Event 4688:** 08:00:05 AM (March 15)

All timestamps align - file was created weeks ago, executed recently.

### notepad.exe
- **MFT Modified:** 01/01/2024 (system file)
- **Prefetch LastRun:** 13:00 PM (March 15)
- **Event 4688:** 13:00:00 PM (March 15)

System file with normal usage pattern.

---

## Validation Test Cases

### Test Case 1: Detect Causality Violation
```python
mft_parser = MFTParser()
prefetch_parser = PrefetchParser()
comparator = TimestampComparator()

mft_entries = mft_parser.parse_csv('synthetic_mft.csv')
prefetch_entries = prefetch_parser.parse_csv('synthetic_prefetch.csv')

malware_mft = mft_parser.find_by_filename(mft_entries, 'malware.exe')[0]
malware_prefetch = prefetch_parser.find_by_executable(prefetch_entries, 'MALWARE.EXE')[0]

violation = comparator.detect_causality_violation(
    malware_mft.si_modified,  # 14:30 PM
    malware_prefetch.last_run_time  # 14:25 PM
)

assert violation is not None
assert violation['type'] == 'causality_violation'
assert violation['severity'] == 'medium'  # 5 minutes delta
```

### Test Case 2: Resolve via Event Log Tiebreaker
```python
evtx_parser = EventLogParser()
evtx_entries = evtx_parser.parse_csv('synthetic_evtx.csv', filter_event_ids=[4688])

resolution = evtx_parser.resolve_contradiction(
    executable_name='malware.exe',
    prefetch_time=malware_prefetch.last_run_time,
    mft_time=malware_mft.si_modified,
    entries=evtx_entries
)

assert resolution['resolution'] == 'event_log_confirms_prefetch'
assert resolution['confidence_recovery'] == 0.30
assert 'Event ID 4688 confirms execution at' in resolution['reasoning']
```

### Test Case 3: No False Positives on Legitimate Files
```python
legit_mft = mft_parser.find_by_filename(mft_entries, 'legitapp.exe')[0]
legit_prefetch = prefetch_parser.find_by_executable(prefetch_entries, 'LEGITAPP.EXE')[0]

violation = comparator.detect_causality_violation(
    legit_mft.si_modified,
    legit_prefetch.last_run_time
)

assert violation is None  # No contradiction for legitimate file
```

---

## Ground Truth Summary

| File | Real Creation | Real Execution | Tampering |
|------|---------------|----------------|-----------|
| malware.exe | ~14:00-14:05 PM | 09:55 AM, 10:00 AM, 14:25 PM | Yes - $SI timestamp pushed to 14:30 PM |
| legitapp.exe | March 10, 10:00 AM | March 15, 08:00 AM | No |
| notepad.exe | 2024-01-01 | March 15, 13:00 PM | No |

---

*This synthetic data is designed to test the self-correction engine's ability to:*
1. *Detect causality violations*
2. *Use Event Logs as tiebreaker*
3. *Avoid false positives on legitimate files*
4. *Calculate confidence adjustments correctly*
