# Pre-Flight Checklist: Repository Split & Competition Submission

**Purpose:** Ensure we're fully prepared before executing the repository split and competition submission
**Owner:** Core Team
**Date:** 2026-04-24

---

## 📋 Documentation Review

### Strategy Documents (Internal)

- [ ] **PRODUCT_TIERS.md** - All team members have read and approved
  - [ ] Feature split is clear (Community vs Enterprise)
  - [ ] Rationale makes sense
  - [ ] No disagreements on what goes where
  - [ ] Pricing strategy approved

- [ ] **OPEN_SOURCE_STRATEGY.md** - Business model approved
  - [ ] Competitive positioning clear
  - [ ] Risk mitigation acceptable
  - [ ] File split mapping reviewed
  - [ ] Timeline realistic

- [ ] **REPOSITORY_MANAGEMENT.md** - Technical approach approved
  - [ ] Repository structure understood
  - [ ] Maintenance workflow clear
  - [ ] Security considerations addressed
  - [ ] Scripts reviewed (when created)

- [ ] **DOCUMENTATION_INDEX.md** - All docs accounted for
  - [ ] No missing documents
  - [ ] Cross-references correct
  - [ ] Approval process understood

### Public-Facing Documents

- [ ] **README_COMMUNITY.md** - Ready for public release
  - [ ] No internal strategy leaked
  - [ ] SANS attribution correct
  - [ ] 4n6Nexus branding consistent
  - [ ] All placeholders identified (video URL, repo URLs)
  - [ ] Feature descriptions accurate
  - [ ] Contributing guidelines clear

- [ ] **ARCHITECTURE_DIAGRAM.md** - Competition requirement
  - [ ] Diagrams render correctly (Mermaid)
  - [ ] Component descriptions accurate
  - [ ] Technology stack current
  - [ ] No proprietary details leaked

- [ ] **VOICEOVER_SCRIPT_REVISED.txt** - Demo video narration
  - [ ] 4n6Nexus branding (not "SIFT Find Evil" or "Veritas")
  - [ ] SANS attribution included
  - [ ] Jargon removed/explained
  - [ ] Timing reasonable (~4:30-5:00)
  - [ ] Pronunciation guidance clear

- [ ] **VIDEO_RECORDING_GUIDE.md** - Recording instructions
  - [ ] Hardware requirements clear
  - [ ] Software setup documented
  - [ ] Recording options explained (AI vs live)
  - [ ] Post-production steps complete
  - [ ] Upload instructions ready

- [ ] **TERMINAL_RECORDING_COMMANDS.sh** - Demo commands
  - [ ] Commands tested and work
  - [ ] Evidence paths correct
  - [ ] Output matches expectations
  - [ ] Timing reasonable for video

---

## 🔍 Code Review

### Community Edition Files (What Will Be Open Sourced)

- [ ] **MCP Safety Layer** (`sift_find_evil/mcp/`)
  - [ ] No secrets or credentials
  - [ ] No enterprise-specific logic
  - [ ] Comments appropriate for public
  - [ ] Code quality high (will be scrutinized)

- [ ] **Self-Correction Engine** (`sift_find_evil/self_correction/`)
  - [ ] Core innovation visible
  - [ ] No proprietary algorithms leaked
  - [ ] Well-documented for contributors

- [ ] **Basic Detectors** (5 detectors)
  - [ ] timestomping.py - Ready for public
  - [ ] suspicious_ext.py - Ready for public
  - [ ] hidden_files.py - Ready for public
  - [ ] file_size.py - Ready for public
  - [ ] timeline.py - Ready for public
  - [ ] No advanced detection logic included

- [ ] **Parsers** (`sift_find_evil/parsers/`)
  - [ ] MFT parser wrapper clean
  - [ ] CSV parsing utilities generic
  - [ ] No proprietary parsing logic

- [ ] **CLI** (`sift_find_evil/cli.py`)
  - [ ] Basic commands only (no enterprise features)
  - [ ] Help text appropriate
  - [ ] Error messages clear

- [ ] **Tests** (`tests/scenario_harness.py` + 5 scenarios)
  - [ ] Test framework complete
  - [ ] 5 synthetic scenarios work
  - [ ] Ground truth data correct
  - [ ] F1=1.00 results reproducible

### Enterprise Edition Files (What Stays Private)

- [ ] **Memory Forensics** (`sift_find_evil/detectors/memory/`)
  - [ ] NOT in community file list
  - [ ] Scripts won't copy these files
  - [ ] .gitignore prevents accidental inclusion

- [ ] **Advanced Correlation** (`sift_find_evil/correlation/advanced/`)
  - [ ] NOT in community file list
  - [ ] Proprietary logic protected

- [ ] **Web UI** (`sift_find_evil/web_ui/`)
  - [ ] NOT in community file list
  - [ ] Enterprise-only feature

- [ ] **Integrations** (`sift_find_evil/integrations/`)
  - [ ] NOT in community file list
  - [ ] SIEM/ticketing code protected

- [ ] **Enterprise Features** (`sift_find_evil/enterprise/`)
  - [ ] NOT in community file list
  - [ ] RBAC, SSO, reporting protected

---

## 🔒 Security Audit

### Secrets & Credentials

- [ ] **No hardcoded secrets** in community files
  - [ ] No API keys
  - [ ] No passwords
  - [ ] No tokens
  - [ ] No internal URLs/IPs
  - [ ] No customer information

- [ ] **.gitignore** comprehensive
  - [ ] Python cache files excluded
  - [ ] Virtual environments excluded
  - [ ] Case data excluded (`.E01`, `.raw`, `.dd`, `.mem`)
  - [ ] Audit logs excluded (`audit.jsonl`)
  - [ ] IDE files excluded (`.vscode/`, `.idea/`)

### Proprietary Information

- [ ] **No internal strategy docs** in community repo
  - [ ] OPEN_SOURCE_STRATEGY.md stays private
  - [ ] PRODUCT_TIERS.md stays private
  - [ ] REPOSITORY_MANAGEMENT.md stays private
  - [ ] PRE_FLIGHT_CHECKLIST.md (this file) stays private

- [ ] **No customer/case information**
  - [ ] No real case data
  - [ ] No customer names
  - [ ] No proprietary evidence

- [ ] **No enterprise implementation details**
  - [ ] No advanced detector algorithms
  - [ ] No correlation heuristics
  - [ ] No ML model details

### Attribution & Licensing

- [ ] **SANS attribution** correct everywhere
  - [ ] "Built on SANS's SIFT Workstation and MCP protocol" in README
  - [ ] Acknowledgments section includes SANS
  - [ ] No claims we created SIFT or MCP

- [ ] **MIT License** correct
  - [ ] LICENSE file has correct year (2024)
  - [ ] Copyright holder: "4n6Nexus Contributors"
  - [ ] All community files have MIT license

- [ ] **No copyright violations**
  - [ ] No copied code without attribution
  - [ ] No proprietary tool output included
  - [ ] Evidence sources properly attributed

---

## 🧪 Testing

### Functional Testing

- [ ] **Community code works standalone**
  - [ ] Clean installation from scratch (`pip install -e .`)
  - [ ] All dependencies install correctly
  - [ ] CLI commands work (`4n6nexus --help`)
  - [ ] Basic analysis runs (`4n6nexus analyze --case-id test`)

- [ ] **Test suite passes**
  - [ ] All tests pass (`pytest tests/`)
  - [ ] F1=1.00 on all scenarios
  - [ ] No test failures
  - [ ] Coverage acceptable (>80%)

- [ ] **Demo workflow works**
  - [ ] Evidence mounts read-only
  - [ ] MCP tools execute successfully
  - [ ] Findings generated correctly
  - [ ] Self-correction examples present
  - [ ] Audit log captures everything

### Documentation Testing

- [ ] **README renders correctly**
  - [ ] Logo banner displays on GitHub
  - [ ] Mermaid diagrams render
  - [ ] Badges show correct status
  - [ ] Links work (no 404s)
  - [ ] Code blocks formatted correctly

- [ ] **Installation guide works**
  - [ ] Followed step-by-step on clean VM
  - [ ] All commands work
  - [ ] No missing dependencies
  - [ ] Troubleshooting section helps

- [ ] **CLI reference accurate**
  - [ ] All commands documented
  - [ ] Examples work
  - [ ] Help text matches docs

---

## 🎯 Competition Requirements

### Required Deliverables

- [x] **Architecture Diagram**
  - [x] Mermaid diagram in ARCHITECTURE_DIAGRAM.md
  - [x] System components clear
  - [x] Data flow shown
  - [x] Self-correction flow illustrated

- [x] **Accuracy Report**
  - [x] F1=1.00 achieved
  - [x] 12/12 scenarios pass
  - [x] Precision and recall both 1.00
  - [x] Results reproducible

- [x] **Execution Logs**
  - [x] Sample audit.jsonl available
  - [x] SHA-256 hashes present
  - [x] Timestamps in UTC
  - [x] Tool invocations logged

- [x] **Evidence Samples**
  - [x] Reference to publicly available evidence
  - [x] insider_threat_2022 corpus documented
  - [x] Evidence source attributed

- [x] **Documentation**
  - [x] README comprehensive
  - [x] Installation guide complete
  - [x] Architecture documented
  - [x] Usage examples provided

- [x] **Source Code**
  - [x] Will be in public GitHub repo
  - [x] Community edition complete
  - [x] All tests pass

- [x] **License**
  - [x] MIT License included
  - [x] License headers in files (optional but good)
  - [x] Third-party licenses documented

- [ ] **Demo Video** - **BLOCKER** (only remaining item)
  - [ ] <5 minutes length
  - [ ] Shows real execution
  - [ ] Demonstrates self-correction
  - [ ] F1=1.00 results visible
  - [ ] Uploaded to YouTube/Vimeo

### Judging Criteria Alignment

- [ ] **Autonomous Execution Quality**
  - [ ] MCP safety layer demonstrated
  - [ ] No human intervention required
  - [ ] Error handling robust

- [ ] **IR Accuracy**
  - [ ] F1=1.00 proven
  - [ ] No false positives
  - [ ] No false negatives
  - [ ] Self-correction examples shown

- [ ] **Breadth & Depth**
  - [ ] Multiple detector types (5 basic)
  - [ ] Cross-artifact correlation shown
  - [ ] Real evidence processed (155K entries)

- [ ] **Constraint Implementation**
  - [ ] Architectural (not prompt-based)
  - [ ] Code-enforced safety
  - [ ] Contradiction detection in code

- [ ] **Audit Trail Quality**
  - [ ] Complete chain of custody
  - [ ] SHA-256 hashes
  - [ ] Reproducible from logs

- [ ] **Usability & Documentation**
  - [ ] Clear installation (<15 minutes)
  - [ ] Comprehensive README
  - [ ] Example usage shown

---

## 🚀 Pre-Execution Tasks

### Before Running Scripts

- [ ] **Backup current repo**
  - [ ] Full git commit (no uncommitted changes)
  - [ ] Tag current state (`git tag pre-split`)
  - [ ] Push to remote backup
  - [ ] Verify backup complete

- [ ] **Test scripts in dry-run**
  - [ ] Review script output (don't execute yet)
  - [ ] Verify file paths correct
  - [ ] Check for unintended copies

- [ ] **Environment ready**
  - [ ] Python 3.11+ installed
  - [ ] Git configured correctly
  - [ ] GitHub CLI installed (`gh`)
  - [ ] Sufficient disk space (>5 GB)

### Team Alignment

- [ ] **All team members on same page**
  - [ ] Everyone has read key docs
  - [ ] No outstanding objections
  - [ ] Roles assigned (who does what)
  - [ ] Timeline agreed upon

- [ ] **Communication plan**
  - [ ] How to report progress
  - [ ] Who to notify when done
  - [ ] What to do if issues arise

---

## 📝 Post-Execution Validation

### After Creating Community Repo

- [ ] **Repository structure correct**
  - [ ] Only intended files present
  - [ ] No enterprise code leaked
  - [ ] LICENSE file correct
  - [ ] .gitignore comprehensive

- [ ] **Clean installation works**
  - [ ] `pip install -e .` succeeds
  - [ ] All dependencies install
  - [ ] CLI commands work
  - [ ] Tests pass

- [ ] **GitHub looks good**
  - [ ] README renders correctly
  - [ ] Logo banner displays
  - [ ] Mermaid diagrams render
  - [ ] No broken links

### After Renaming Enterprise Repo

- [ ] **Enterprise repo still works**
  - [ ] All tests pass
  - [ ] Git remote URL correct
  - [ ] CI/CD still runs (if configured)
  - [ ] No broken references

- [ ] **Clear separation**
  - [ ] Community repo is public
  - [ ] Enterprise repo is private
  - [ ] No confusion about what's what

---

## 🎬 Demo Video Checklist

### Pre-Recording

- [ ] **Equipment ready**
  - [ ] SIFT VM running
  - [ ] Evidence accessible
  - [ ] Recording software installed (OBS/FFmpeg)
  - [ ] Microphone tested (if Option B)

- [ ] **Script ready**
  - [ ] VOICEOVER_SCRIPT_REVISED.txt reviewed
  - [ ] TERMINAL_RECORDING_COMMANDS.sh tested
  - [ ] Timing rehearsed

- [ ] **AI voiceover ready** (if Option A)
  - [ ] Chatterbox installed on RTX 4090 system
  - [ ] Audio segments generated
  - [ ] Quality verified

### Recording

- [ ] **Terminal readable**
  - [ ] Font size increased (16pt+)
  - [ ] High contrast colors
  - [ ] No distractions (notifications off)

- [ ] **Commands execute cleanly**
  - [ ] No errors
  - [ ] Output displays long enough (2-3 seconds)
  - [ ] Self-correction example visible

- [ ] **Timing good**
  - [ ] <5 minutes total
  - [ ] Not rushed
  - [ ] Pauses between sections

### Post-Production

- [ ] **Video quality**
  - [ ] 1920x1080 minimum resolution
  - [ ] 30fps minimum frame rate
  - [ ] H.264 codec (MP4)
  - [ ] Terminal text readable

- [ ] **Audio quality**
  - [ ] Clearly audible
  - [ ] No background noise
  - [ ] Consistent volume
  - [ ] No clipping/distortion

- [ ] **Title cards**
  - [ ] Intro card (2 seconds)
    ```
    4n6Nexus
    Autonomous DFIR with Architectural Self-Correction
    FIND EVIL! Hackathon 2026
    ```
  - [ ] Outro card (2 seconds)
    ```
    github.com/4n6nexus/4n6nexus
    MIT License
    ```

- [ ] **Final export**
  - [ ] H.264, 1080p, 30fps
  - [ ] File size <500MB
  - [ ] Plays in all browsers
  - [ ] Uploaded to YouTube/Vimeo

---

## 🏁 Final Submission Checklist

### Devpost Form

- [ ] **Basic Information**
  - [ ] Project name: 4n6Nexus
  - [ ] Tagline: Autonomous DFIR with Architectural Self-Correction
  - [ ] Description: (copy from README_COMMUNITY.md)

- [ ] **Links**
  - [ ] Demo video URL: (YouTube/Vimeo link)
  - [ ] GitHub repo: https://github.com/4n6nexus/4n6nexus
  - [ ] Website: (optional - 4n6nexus.dev if launched)

- [ ] **Deliverables**
  - [ ] Architecture diagram: (link to ARCHITECTURE_DIAGRAM.md in repo)
  - [ ] Accuracy report: (link to accuracy_report.json in repo)
  - [ ] Execution logs: (link to sample audit.jsonl in repo)
  - [ ] Evidence reference: (link to docs explaining insider_threat_2022)
  - [ ] Documentation: (link to README.md in repo)
  - [ ] Source code: (GitHub repo link)
  - [ ] License: (link to LICENSE in repo)

- [ ] **Team Members**
  - [ ] All team members listed
  - [ ] Roles assigned (optional)

### Pre-Submission Review

- [ ] **Everything works**
  - [ ] Video plays on Devpost
  - [ ] All links resolve (no 404s)
  - [ ] GitHub repo is public
  - [ ] Documentation is complete

- [ ] **Quality check**
  - [ ] No typos in submission text
  - [ ] Professional appearance
  - [ ] Clear value proposition
  - [ ] Competition requirements met

- [ ] **Legal check**
  - [ ] SANS attribution correct
  - [ ] MIT License applied
  - [ ] No copyright violations
  - [ ] No proprietary info leaked

### Submit!

- [ ] **Submission complete**
  - [ ] Form submitted before deadline (June 15, 2026)
  - [ ] Confirmation email received
  - [ ] Submission visible on Devpost
  - [ ] Team notified

---

## ⚠️ Red Flags - Stop If You See These

**STOP and review before proceeding if:**

- ❌ Enterprise code appears in community repository
- ❌ Secrets or credentials found in any public file
- ❌ Tests fail in community edition clean installation
- ❌ SANS attribution missing or incorrect
- ❌ MIT License missing or incorrect
- ❌ Customer/case information visible anywhere
- ❌ Advanced detector algorithms leaked to community
- ❌ Demo video shows sensitive information
- ❌ Any team member has unresolved objections

**If you see a red flag:**
1. STOP immediately
2. Document the issue
3. Fix before proceeding
4. Re-run relevant checklist sections

---

## ✅ Sign-Off

**When all items are checked, obtain sign-off from:**

- [ ] **Technical Lead** - Code quality, architecture, testing
- [ ] **Security Lead** - No leaks, proper attribution, secrets scan
- [ ] **Product Lead** - Feature split correct, positioning clear
- [ ] **Legal/Compliance** - Licensing, attribution, no violations

**Signatures:**

- Technical Lead: _________________ Date: _______
- Security Lead: _________________ Date: _______
- Product Lead: _________________ Date: _______
- Legal/Compliance: _________________ Date: _______

---

## 📞 Emergency Contacts

**If something goes wrong during execution:**

- Technical issues: [Name] - [Contact]
- Security concerns: [Name] - [Contact]
- Legal questions: [Name] - [Contact]

**Rollback procedure:**
```bash
# If community repo has issues, delete it
rm -rf ../4n6nexus

# If enterprise rename has issues, restore from backup
git tag pre-split  # Find the backup tag
git reset --hard pre-split

# Restore remote URL if changed
git remote set-url origin <original-url>
```

---

**Document Owner:** Core Team
**Last Updated:** 2026-04-24
**Status:** Ready for execution after team sign-off
