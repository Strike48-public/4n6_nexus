# Community YARA Rulesets

This directory vendors third-party YARA rulesets as git submodules so the
detection engine can load them alongside the in-repo seed rules under
`rules/yara/seed/`. The submodules remain on their upstream history; we
never modify vendored rule content in this repo.

## Vendored Sources

| Submodule | Upstream | License | Content |
|---|---|---|---|
| `yara-rules/` | https://github.com/Yara-Rules/rules | GPL-2.0 | Community-curated malware, packer, webshell, exploit, and capability rules |
| `signature-base/` | https://github.com/Neo23x0/signature-base | [Detection Rule License (DRL) 1.1](signature-base/LICENSE) | Neo23x0 / THOR APT, CVE, web, and threat-hunting rules |

Both licenses permit redistribution of the rules themselves. Do not copy
rule content into other directories - keep the submodule boundary intact
so license headers, attribution, and update history stay attached to the
rules.

## Loading the Rules

The scanner compiles every `*.yar` and `*.yara` file found under the
listed directories. Broken rule files are recorded and skipped (see
`scanner.compile_errors`) so a single bad file in a community ruleset
cannot take the whole scanner offline.

```python
from pathlib import Path
from sift_find_evil.yara_scan.scanner import YaraScanner

scanner = YaraScanner.compile_from_directories([
    Path("rules/yara/seed"),
    Path("rules/yara/community/yara-rules"),
    Path("rules/yara/community/signature-base/yara"),
])

print(scanner.rule_count, "rules compiled")
print(len(scanner.compile_errors), "rule file(s) skipped")
```

Each source directory contributes a namespace prefix derived from its
folder name so rule identifiers from different sources cannot collide
silently.

## Update Cadence

Pull community submodules quarterly to pick up new coverage without
introducing too much churn. The seed ruleset is the stable contract;
community rules drift and some upstream commits introduce regressions
that only surface at compile time, so pin updates to a deliberate cycle.

```bash
# Refresh all vendored community rulesets
git submodule update --remote rules/yara/community/yara-rules
git submodule update --remote rules/yara/community/signature-base
git add rules/yara/community/yara-rules rules/yara/community/signature-base
git commit -m "chore(yara): refresh community rulesets ($(date -u +%Y-%m-%d))"
```

After a refresh, rerun the CIRCL triage pass (`scripts/scan_circl_yara.py`)
and any other integration scenarios before merging. Record the number of
compile errors and the rule_count delta in the commit body; a large
regression in either number is a signal to investigate upstream before
rolling the submodule forward.

## Initial Clone

New clones of this repository need the submodules initialized:

```bash
git clone --recurse-submodules <repo-url>
# or, if already cloned:
git submodule update --init --recursive
```

Without this step, `rules/yara/community/yara-rules/` and
`rules/yara/community/signature-base/` will be empty directories and the
scanner will raise `FileNotFoundError`.

## Out of Scope

- False-positive tuning per ruleset. That work lives in its own ticket
  once we measure the community rules against the CIRCL case and the
  synthetic scenarios.
- Rule authorship. Do not add hand-written rules here; author them in
  `rules/yara/seed/` instead so they stay under our own attribution and
  licensing.
