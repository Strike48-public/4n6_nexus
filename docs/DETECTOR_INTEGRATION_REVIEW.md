# Detector Integration Review

## Overview

This document provides a code review checklist for the integrated progress tracking system with real detector implementations.

**Status:** Ready for Review  
**Date:** 2026-05-19  
**Integration Scope:** YARA, Memory, Registry detectors with progress tracking

---

## Integration Summary

### Integrated Detectors

| Detector | Status | Progress Tracking | Findings Mapping | Notes |
|----------|--------|-------------------|------------------|-------|
| **YaraDetector** | ✅ Integrated | ✅ Enabled | ✅ Mapped | Scans all files, confidence-based severity |
| **MemoryDetector** | ✅ Integrated | ✅ Enabled | ✅ Mapped | Uses JSON fixtures, multiple plugin support |
| **RegistryDetector** | ✅ Integrated | ✅ Enabled | ✅ Mapped | Parses CSV artifacts (shimcache, amcache, bam, userassist, run_keys) |

### Key Changes

1. **analysis_runner.py**:
   - Added imports: `YaraDetector`, `MemoryDetector`, `RegistryDetector`, `YaraScanner`, `json`
   - Replaced simulated phases with real detector integration
   - Added `_map_finding_severity()` helper method
   - Integrated error handling for missing evidence/fixtures

2. **YARA Integration** (`_phase_yara_scan`):
   - Initializes `YaraScanner` from rules directory
   - Scans all files matching patterns: `*.exe`, `*.dll`, `*.sys`, `*.bin`, `*`
   - Maps `Finding` severity to `FindingSeverity` enum
   - Reports progress per file scanned

3. **Memory Integration** (`_phase_memory_analysis`):
   - Searches for `memory_fixtures/*.json` files
   - Parses JSON fixtures into Volatility plugin row objects
   - Supports: `pslist`, `psscan`, `malfind`, `cmdline`, `netscan`
   - Maps findings from detector to progress tracker

4. **Registry Integration** (`_phase_persistence_detection`):
   - Uses `RegistryParser` to parse CSV artifacts
   - Supports: shimcache, amcache, bam, userassist, run_keys
   - Collects all entries before running detector analysis
   - Maps findings from detector to progress tracker

---

## Code Review Checklist

### Phase 1: YARA Integration Review

- [ ] **File Discovery**
  - [ ] Verify pattern matching works: `**/*.exe`, `**/*.dll`, `**/*.sys`, `**/*.bin`, `**/*`
  - [ ] Test with empty evidence directory
  - [ ] Test with evidence containing only non-executable files
  - [ ] Test with deeply nested directory structures

- [ ] **Scanner Initialization**
  - [ ] Verify rules directory path resolution: `Path(__file__).parent.parent / "rules" / "yara" / "community" / "signature-base"`
  - [ ] Test fallback when rules directory doesn't exist
  - [ ] Test with empty rules directory
  - [ ] Test with malformed YARA rules

- [ ] **Detector Analysis**
  - [ ] Verify `analyze_file()` returns `Finding` objects
  - [ ] Test severity mapping: `critical`, `high`, `medium`, `low`, `info`
  - [ ] Verify findings include correct metadata (file path, rule name, etc.)
  - [ ] Test with files that trigger multiple YARA rules

- [ ] **Progress Reporting**
  - [ ] Verify `start_phase()` called with correct item count
  - [ ] Verify `increment_progress()` called per file
  - [ ] Verify `complete_phase()` called after all files
  - [ ] Test progress percentage calculation with 0 files, 1 file, 1000+ files

- [ ] **Error Handling**
  - [ ] Verify exception handling per file doesn't crash entire phase
  - [ ] Verify activity log captures scan errors
  - [ ] Verify phase completes even if some files fail
  - [ ] Test with permission-denied files

### Phase 2: Memory Integration Review

- [ ] **Fixture Discovery**
  - [ ] Verify `memory_fixtures/*.json` pattern matching
  - [ ] Test with missing memory_fixtures directory
  - [ ] Test with empty memory_fixtures directory
  - [ ] Test with malformed JSON fixtures

- [ ] **Fixture Parsing**
  - [ ] Verify JSON structure matches expected plugin outputs
  - [ ] Verify row object instantiation: `ProcessRow`, `InjectionRow`, `CommandLineRow`, `NetworkRow`
  - [ ] Test with partial fixture data (missing plugins)
  - [ ] Test with extra fields in fixtures (forward compatibility)

- [ ] **Detector Analysis**
  - [ ] Verify `analyze()` accepts optional plugin parameters
  - [ ] Verify findings cover: hidden processes, RWX memory, suspicious cmdlines, network activity
  - [ ] Test severity mapping for memory findings
  - [ ] Verify MITRE ATT&CK techniques mapped correctly

- [ ] **Progress Reporting**
  - [ ] Verify `start_phase()` called with fixture count
  - [ ] Verify `increment_progress()` called per fixture
  - [ ] Verify `complete_phase()` called after all fixtures
  - [ ] Test with 0 fixtures, 1 fixture, 10+ fixtures

- [ ] **Error Handling**
  - [ ] Verify exception handling per fixture doesn't crash phase
  - [ ] Verify activity log captures parse errors
  - [ ] Verify phase completes even if some fixtures fail
  - [ ] Test with invalid fixture structure

### Phase 3: Registry Integration Review

- [ ] **Fixture Discovery**
  - [ ] Verify CSV pattern matching for: `shimcache.csv`, `amcache.csv`, `bam.csv`, `userassist.csv`, `run_keys.csv`
  - [ ] Test with missing CSV files
  - [ ] Test with empty CSV files
  - [ ] Test with malformed CSV files

- [ ] **Parser Integration**
  - [ ] Verify `RegistryParser` instantiation
  - [ ] Verify method calls: `parse_shimcache_csv()`, `parse_amcache_csv()`, etc.
  - [ ] Test CSV format compatibility with RegRipper exports
  - [ ] Test timestamp parsing (various formats)

- [ ] **Entry Aggregation**
  - [ ] Verify all entries collected before detector analysis
  - [ ] Verify empty lists handled correctly (None vs empty list)
  - [ ] Test with multiple CSV files of same type
  - [ ] Test with mixed artifact types

- [ ] **Detector Analysis**
  - [ ] Verify `analyze()` accepts all artifact types
  - [ ] Verify findings cover: Run keys, suspicious execution paths, double-extensions
  - [ ] Test severity mapping for registry findings
  - [ ] Verify MITRE ATT&CK techniques mapped correctly

- [ ] **Progress Reporting**
  - [ ] Verify `start_phase()` called with total CSV file count
  - [ ] Verify `increment_progress()` called per CSV file
  - [ ] Verify `complete_phase()` called after all files
  - [ ] Test with 0 files, 1 file per type, multiple files per type

- [ ] **Error Handling**
  - [ ] Verify exception handling per CSV doesn't crash phase
  - [ ] Verify activity log captures parse errors
  - [ ] Verify phase completes even if some CSVs fail
  - [ ] Test with permission-denied files

### Phase 4: Severity Mapping Review

- [ ] **Helper Method**
  - [ ] Verify `_map_finding_severity()` maps all severity strings
  - [ ] Test case-insensitivity: `"CRITICAL"`, `"critical"`, `"Critical"`
  - [ ] Test unknown severity defaults to `MEDIUM`
  - [ ] Verify enum mapping: `critical` → `FindingSeverity.CRITICAL`, etc.

### Phase 5: Error Recovery & Graceful Degradation

- [ ] **Missing Evidence Path**
  - [ ] Verify each phase skips gracefully when `evidence_path` is None
  - [ ] Verify each phase skips gracefully when `evidence_path` doesn't exist
  - [ ] Verify activity log explains why phase was skipped

- [ ] **Missing Detectors/Dependencies**
  - [ ] Test with missing YARA rules directory
  - [ ] Test with missing memory fixtures
  - [ ] Test with missing registry CSVs
  - [ ] Verify fallback messages are clear

- [ ] **Partial Failures**
  - [ ] Verify one bad file doesn't stop entire YARA scan
  - [ ] Verify one bad fixture doesn't stop memory analysis
  - [ ] Verify one bad CSV doesn't stop registry analysis
  - [ ] Verify findings from successful items are preserved

### Phase 6: Integration Testing

- [ ] **End-to-End Workflows**
  - [ ] Run quick analysis with all detectors enabled
  - [ ] Run full analysis with all detectors enabled
  - [ ] Run memory analysis mode
  - [ ] Verify findings appear in progress panel
  - [ ] Verify activity log shows detector operations

- [ ] **UI Integration**
  - [ ] Verify progress bar updates during detector phases
  - [ ] Verify findings counter increments correctly
  - [ ] Verify activity feed shows detector-specific messages
  - [ ] Verify phase indicators update correctly
  - [ ] Test with rapid detector findings (burst scenarios)

- [ ] **Real Scenario Testing**
  - [ ] Run against `scenarios/synthetic/02_ransomware/`
  - [ ] Run against `scenarios/synthetic/11_yara_malware/`
  - [ ] Run against `scenarios/synthetic/12_memory_intrusion/`
  - [ ] Verify F1 scores remain at 1.00

### Phase 7: Performance Review

- [ ] **YARA Scanning Performance**
  - [ ] Measure time per file (should be <100ms for typical files)
  - [ ] Test with 1000+ files
  - [ ] Verify progress updates don't slow scan
  - [ ] Check memory usage during large scans

- [ ] **Memory Analysis Performance**
  - [ ] Measure fixture parse time (should be <50ms per fixture)
  - [ ] Test with large JSON fixtures (>1MB)
  - [ ] Verify async sleep (0.001s) doesn't accumulate delays
  - [ ] Check memory usage during analysis

- [ ] **Registry Analysis Performance**
  - [ ] Measure CSV parse time (should be <100ms per CSV)
  - [ ] Test with large CSV files (10,000+ rows)
  - [ ] Verify entry aggregation doesn't cause memory spike
  - [ ] Check detector analysis time with large entry sets

### Phase 8: Code Quality

- [ ] **Imports**
  - [ ] All imports resolve correctly
  - [ ] No circular dependencies
  - [ ] Unused imports removed
  - [ ] Standard library, third-party, local imports ordered

- [ ] **Type Annotations**
  - [ ] All method signatures have type hints
  - [ ] Return types specified
  - [ ] Optional types used correctly
  - [ ] No type: ignore comments without justification

- [ ] **Error Messages**
  - [ ] Activity log messages are clear and actionable
  - [ ] Error messages include context (file name, line number, etc.)
  - [ ] No sensitive data logged (file contents, passwords, etc.)

- [ ] **Code Duplication**
  - [ ] No duplicated error handling patterns
  - [ ] Helper methods used where appropriate
  - [ ] Consistent patterns across detector integrations

---

## Testing Validation

### Unit Tests Needed

1. **test_analysis_runner_yara_integration.py**
   - Mock YaraScanner and YaraDetector
   - Test file discovery patterns
   - Test severity mapping
   - Test error handling per file

2. **test_analysis_runner_memory_integration.py**
   - Mock MemoryDetector
   - Test fixture discovery and parsing
   - Test severity mapping
   - Test error handling per fixture

3. **test_analysis_runner_registry_integration.py**
   - Mock RegistryParser and RegistryDetector
   - Test CSV discovery and parsing
   - Test entry aggregation
   - Test severity mapping
   - Test error handling per CSV

4. **test_severity_mapping.py**
   - Test all severity string cases
   - Test unknown severity defaults
   - Test case-insensitivity

### Integration Tests Needed

1. **test_real_detector_workflow.py**
   - Test full analysis against synthetic scenarios
   - Verify findings match ground truth
   - Verify progress tracking updates correctly
   - Verify F1 scores remain at 1.00

### Current Test Coverage

Run to verify:
```bash
pytest tests/ --cov=sift_find_evil/analysis_runner --cov-report=term-missing
```

**Target:** 80%+ coverage on `analysis_runner.py`

---

## Known Issues & Limitations

### Current Limitations

1. **YARA Rules Path**
   - Hardcoded to `rules/yara/community/signature-base/`
   - Fails if rules are in different location
   - **Mitigation:** Add configuration for rules path

2. **Memory Fixtures Format**
   - Expects specific JSON structure
   - No schema validation
   - **Mitigation:** Add JSON schema validation

3. **Registry CSV Format**
   - Expects specific column names
   - Sensitive to format variations
   - **Mitigation:** Add format detection/normalization

4. **Error Recovery**
   - Phase completes even if all files fail
   - No distinction between "no evidence" and "all failed"
   - **Mitigation:** Add failure counters and thresholds

### Future Enhancements

1. **Detector Configuration**
   - Allow disabling specific detectors
   - Confidence threshold tuning
   - Custom detector plugins

2. **Progress Checkpointing**
   - Save progress mid-analysis
   - Resume from checkpoint
   - Export/import progress state

3. **Parallel Detector Execution**
   - Run independent detectors concurrently
   - Pool file scanning for YARA
   - Async fixture processing for memory

4. **Real-Time Detector Streaming**
   - Stream findings as they're discovered
   - Don't wait for phase completion
   - Update UI immediately on findings

---

## Sign-Off

- [ ] Code review completed
- [ ] All integrations tested
- [ ] Unit tests written (80%+ coverage)
- [ ] Integration tests passing
- [ ] F1 scores validated (1.00)
- [ ] Documentation updated
- [ ] Ready for merge

**Reviewer:** _____________  
**Date:** _____________  
**Status:** PENDING REVIEW

---

**Last Updated:** 2026-05-19  
**Integration Status:** COMPLETE  
**Priority:** HIGH
