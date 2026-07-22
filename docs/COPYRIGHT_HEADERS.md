# Copyright Headers Guide

**Purpose:** How to add copyright headers to source files (not full license text)
**Last Updated:** 2026-04-24

---

## What We Do (Standard Practice)

### ✅ Short Copyright Header in Each File

```python
# Copyright (c) 2024 4n6Nexus Contributors
# SPDX-License-Identifier: MIT
```

**Why this approach:**
- Standard practice (used by most open source projects)
- Short and simple (3 lines)
- SPDX identifier is machine-readable
- Full license text stays in root LICENSE file

### ✅ Full License Text Only in Repository Root

```
LICENSE                  (full MIT license text - 21 lines)
```

---

## What We Don't Do

### ❌ Full License Text in Every File

```python
# MIT License
# 
# Copyright (c) 2024 4n6Nexus Contributors
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software")...
# [40 more lines]
```

**Why not:**
- Redundant (license is already in root LICENSE file)
- Makes files harder to read
- Outdated practice (replaced by SPDX)
- Annoying to maintain

---

## Header Format by File Type

### Python Files (.py)

**Without shebang:**
```python
# Copyright (c) 2024 4n6Nexus Contributors
# SPDX-License-Identifier: MIT

"""Module docstring."""

import os
```

**With shebang:**
```python
#!/usr/bin/env python3
# Copyright (c) 2024 4n6Nexus Contributors
# SPDX-License-Identifier: MIT

"""Module docstring."""

import os
```

### Shell Scripts (.sh)

```bash
#!/usr/bin/env bash
# Copyright (c) 2024 4n6Nexus Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail
```

### Markdown Files (.md)

```markdown
<!-- Copyright (c) 2024 4n6Nexus Contributors -->
<!-- SPDX-License-Identifier: MIT -->

# Document Title
```

### YAML Files (.yml, .yaml)

```yaml
# Copyright (c) 2024 4n6Nexus Contributors
# SPDX-License-Identifier: MIT

name: CI Pipeline
```

---

## Adding Headers Automatically

### Using the Script

```bash
# Add headers to all Python files
bash scripts/add_copyright_headers.sh

# Review changes
git diff sift_find_evil/

# Commit
git add sift_find_evil/
git commit -m "chore: add copyright headers to source files"
```

### Manual Addition

If you create a new file:

```python
# 1. Add header at top (after shebang if present)
# Copyright (c) 2024 4n6Nexus Contributors
# SPDX-License-Identifier: MIT

# 2. Continue with your code
def my_function():
    pass
```

---

## SPDX Identifiers

**What is SPDX?**
- Software Package Data Exchange
- Standard way to reference licenses
- Machine-readable
- Used by GitHub, npm, PyPI, etc.

**Common identifiers:**
- `MIT` - MIT License
- `Apache-2.0` - Apache License 2.0
- `GPL-3.0-or-later` - GNU GPL v3 or later
- `BSD-3-Clause` - BSD 3-Clause License

**Full list:** https://spdx.org/licenses/

---

## Why SPDX?

**Before SPDX (inconsistent):**
```python
# Licensed under MIT
# See LICENSE for details
# MIT licensed
# This code is MIT
```

**With SPDX (standard):**
```python
# SPDX-License-Identifier: MIT
```

**Benefits:**
- Machines can parse it (automated compliance checks)
- Consistent across projects
- GitHub recognizes it
- Package managers understand it

---

## Verification

### Check All Files Have Headers

```bash
# Find Python files without copyright
find sift_find_evil -name "*.py" -type f -exec grep -L "Copyright (c)" {} \;

# Should return nothing if all files have headers
```

### Verify SPDX Identifier

```bash
# Check all files have SPDX
find sift_find_evil -name "*.py" -type f -exec grep -L "SPDX-License-Identifier" {} \;

# Should return nothing
```

---

## FAQ

**Q: Do we need copyright headers in test files?**
A: Yes, all source files should have headers (including tests).

**Q: Do we need headers in documentation files (.md)?**
A: Optional. Typically only source code files (.py, .sh) need headers.

**Q: What about third-party code we copied?**
A: Keep the original copyright header, add our own below:
```python
# Copyright (c) 2020 Original Author
# Copyright (c) 2024 4n6Nexus Contributors
# SPDX-License-Identifier: MIT
```

**Q: Do we update the year every year?**
A: Two approaches:
- Static: `Copyright (c) 2024 4n6Nexus Contributors` (never update)
- Range: `Copyright (c) 2024-2025 4n6Nexus Contributors` (update yearly)

Most projects use static (less maintenance).

**Q: What if a file is modified by someone else?**
A: The copyright line doesn't change. It represents the collective "4n6Nexus Contributors", not individuals.

**Q: Can contributors add their own copyright line?**
A: No, we use collective copyright ("4n6Nexus Contributors"). Individual contributions are tracked in git history.

---

## Examples from Popular Projects

**Linux Kernel:**
```c
// SPDX-License-Identifier: GPL-2.0
```

**Kubernetes:**
```go
// Copyright 2024 The Kubernetes Authors
// SPDX-License-Identifier: Apache-2.0
```

**Pandas:**
```python
# Copyright (c) 2008-2011, AQR Capital Management, LLC
# Copyright (c) 2008-2014, Pandas Development Team
# SPDX-License-Identifier: BSD-3-Clause
```

**Our approach (4n6Nexus):**
```python
# Copyright (c) 2024 4n6Nexus Contributors
# SPDX-License-Identifier: MIT
```

---

## References

- SPDX Specification: https://spdx.github.io/spdx-spec/
- SPDX License List: https://spdx.org/licenses/
- REUSE Best Practices: https://reuse.software/
- GitHub License Detection: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository

---

**Document Owner:** Core Team
**Last Updated:** 2026-04-24
