# SIFT Carving Tools - Status Report

**Date:** 2026-04-17  
**Issue:** SFE-1n2

## Summary

None of the standard SIFT carving tools are currently installed on this instance:

- foremost (file carving by header/footer) - NOT INSTALLED
- scalpel (enhanced foremost with config) - NOT INSTALLED
- binwalk (firmware/embedded extraction) - NOT INSTALLED
- photorec (signature-based recovery) - NOT INSTALLED
- bulk_extractor (bulk data extraction) - NOT INSTALLED
- tsk_recover (Sleuth Kit recovery) - NOT INSTALLED

## Root Cause

This appears to be a minimal SIFT installation or a custom Ubuntu environment without the full SIFT tool suite. The SANS SIFT Workstation typically includes these tools by default.

## Options

### Option 1: Install Tools (Requires sudo)

```bash
sudo apt-get update
sudo apt-get install foremost scalpel binwalk testdisk
```

Note: bulk_extractor may require separate repository or manual compilation.

### Option 2: Pure Python Implementation

Continue with our Python-based signature scanner approach:
- Pros: No external dependencies, full control, cross-platform
- Cons: Less battle-tested, limited signature library

### Option 3: Defer to End User

Document that file carving requires external tools installation. Provide clear error messages guiding users to install tools.

## Recommendation

**Proceed with Option 3** (defer to end user):

1. Keep Python signature scanner as fallback
2. Add tool detection at runtime
3. Provide helpful error messages with installation instructions
4. Document tool requirements in README

**Rationale:**

- We don't have sudo access to install system packages
- Pure Python implementation provides value without external dependencies
- Users running SIFT typically have tools installed already
- Clear error messages + documentation = good UX for edge cases

## Next Steps

1. Update SFE-1n2 issue with findings
2. Create fallback detection logic in carving code
3. Document tool requirements in project README
4. Close SFE-1n2 as complete (investigation + documentation)
