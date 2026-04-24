# 4n6Nexus Documentation Index

**Purpose:** This document provides a complete map of all internal documentation for the 4n6Nexus project.
**Audience:** Internal team members
**Last Updated:** 2026-04-24

---

## 📋 Quick Reference

| Document | Purpose | When to Read |
|----------|---------|--------------|
| [PRODUCT_TIERS.md](#product-tiers) | Defines Community vs Enterprise features | Before any product decisions |
| [OPEN_SOURCE_STRATEGY.md](#open-source-strategy) | Business strategy for open source vs proprietary | Strategic planning |
| [REPOSITORY_MANAGEMENT.md](#repository-management) | How to manage split repositories | Before creating community repo |
| [README_COMMUNITY.md](#readme-community) | Public-facing Community Edition README | Before releasing to public |
| [ARCHITECTURE_DIAGRAM.md](#architecture-diagram) | System architecture (Mermaid diagrams) | Understanding system design |
| [VOICEOVER_SCRIPT_REVISED.txt](#voiceover-script) | Demo video narration (4n6Nexus branded) | Before recording demo |
| [VIDEO_RECORDING_GUIDE.md](#video-recording-guide) | Complete video recording instructions | When recording demo |
| [EVIDENCE_COMPATIBILITY.md](#evidence-compatibility) | What evidence can be analyzed (Windows/Linux/macOS) | When planning tests or answering capability questions |
| [COPYRIGHT_HEADERS.md](#copyright-headers) | How to add copyright headers (not full license) | When creating new files |

---

## 📚 Document Descriptions

### PRODUCT_TIERS.md

**Path:** `docs/PRODUCT_TIERS.md`
**Status:** ✅ Approved
**Owner:** Core Team

**What It Defines:**
- Exact feature split between Community and Enterprise editions
- Rationale for each feature placement
- Pricing strategy
- Competitive positioning
- Upgrade path from Community to Enterprise

**Key Sections:**
- Edition comparison (Community vs Enterprise)
- Feature allocation rationale (why each feature is where it is)
- Pricing strategy (free vs custom pricing)
- Risk mitigation (forking, competitors, free riders)
- Decision log (key decisions with dates and rationale)

**When to Reference:**
- Making any product feature decisions
- Sales conversations (what's included in Enterprise)
- Community contributions (does this belong in Community or Enterprise?)
- Roadmap planning (prioritizing features)

---

### OPEN_SOURCE_STRATEGY.md

**Path:** `docs/OPEN_SOURCE_STRATEGY.md`
**Status:** ✅ Approved for team review
**Owner:** Core Team

**What It Defines:**
- Overall open source business model
- Community Edition scope (what goes open source)
- Enterprise Edition scope (what stays proprietary)
- Competition submission strategy
- Monetization path
- File-level implementation plan

**Key Sections:**
- Community Edition (open source components)
- Proprietary features (hold back for Enterprise)
- Competition strategy (what judges will see)
- Competitive advantages preserved
- Monetization path (free → Enterprise)
- File split mapping (current path → new path)
- Risk assessment (technical and business risks)

**When to Reference:**
- Before creating community repository
- When evaluating community contributions
- Strategic business planning
- Investor/partner discussions

---

### REPOSITORY_MANAGEMENT.md

**Path:** `docs/REPOSITORY_MANAGEMENT.md`
**Status:** ✅ Documented, scripts ready to create
**Owner:** Core Team

**What It Defines:**
- How to split current repo into Community and Enterprise
- Repository structure and relationships
- File split mapping (what goes where)
- Automation scripts (create community repo, rename enterprise repo)
- Maintenance workflows (syncing bug fixes, backporting PRs)
- Security considerations (preventing leaks)

**Key Sections:**
- Current state vs target state
- Repository structure (Community public, Enterprise private)
- File split mapping (detailed table of what goes where)
- Implementation plan (4 phases)
- Split scripts (bash automation)
- Maintenance workflow (how to sync changes)
- Security considerations (preventing leaks)

**When to Reference:**
- Before creating community repository
- When syncing bug fixes between repos
- When contributor adds feature (where does it belong?)
- Setting up CI/CD for each repo

---

### README_COMMUNITY.md

**Path:** `docs/README_COMMUNITY.md`
**Status:** ✅ Ready for public release (after competition video recorded)
**Owner:** Core Team

**What It Is:**
- The public-facing README for the Community Edition repository
- Will become `README.md` in `4n6nexus/4n6nexus` repo

**What It Contains:**
- Hero banner (logo_banner.svg)
- Badges (CI, license, F1 score, competition submission)
- Elevator pitch (autonomous DFIR with self-correction)
- Competition achievement box (F1=1.00, 12/12 scenarios)
- Architecture diagrams (Mermaid)
- Self-correction example (actual JSON)
- Quick start (3 installation paths)
- Usage examples (CLI commands)
- Detection capabilities table
- Evidence integrity & chain of custody
- Test results (accuracy report summary)
- Roadmap (Community vs Enterprise comparison)
- Contributing guidelines
- Security & responsible use
- Acknowledgments (SANS, FIND EVIL!, evidence sources)

**When to Reference:**
- Before creating community repository
- When updating public documentation
- When writing blog posts or marketing materials
- Onboarding new contributors

**Placeholders to Update Before Publishing:**
- YouTube video ID (once demo video is recorded)
- Repository URLs (once GitHub repo is created)
- Email addresses (if you want specific contact emails)
- Social media handles (Twitter, LinkedIn)

---

### ARCHITECTURE_DIAGRAM.md

**Path:** `docs/ARCHITECTURE_DIAGRAM.md`
**Status:** ✅ Complete
**Owner:** Core Team

**What It Contains:**
- System architecture diagram (Mermaid)
- Data flow sequence diagram (Mermaid)
- Self-correction flow chart (Mermaid)
- Component descriptions
- Technology stack

**Why It's Important:**
- Competition requirement (architecture diagram)
- Helps new team members understand system design
- Reference for contributors (where does new code go?)
- Public documentation (will be in community repo)

**When to Reference:**
- Explaining system design to new team members
- Planning new features (which component?)
- Code reviews (does this fit the architecture?)
- Competition submission (required deliverable)

---

### VOICEOVER_SCRIPT_REVISED.txt

**Path:** `docs/VOICEOVER_SCRIPT_REVISED.txt`
**Status:** ✅ Revised with 4n6Nexus branding + SANS attribution
**Owner:** Core Team

**What It Contains:**
- Complete narration for 5-minute demo video
- 6 segments matching video timing
- Jargon removed (timestomping → timestamp manipulation)
- SANS attribution added ("Built on SANS's SIFT Workstation and MCP protocol, we added...")
- 4n6Nexus branding (was "Veritas", then "SIFT Find Evil")
- Pronunciation guidance for Chatterbox TTS
- Word count and timing estimates (~670 words, ~4:20-5:00)

**Key Changes from Original:**
- Project name: "SIFT Find Evil" → "4n6Nexus"
- Attribution: "Our solution combines..." → "Built on SANS's SIFT Workstation and MCP protocol, we added..."
- Jargon: "Timestomping" → "timestamp manipulation"
- Jargon: "Prefetch artifact" → "Windows execution trace"
- Jargon: "MFT $STANDARD_INFORMATION vs $FILE_NAME" → "Windows stores two timestamps for each file"
- Jargon: "SHA-256 hashing" → "cryptographic fingerprinting"

**When to Reference:**
- Recording AI voiceover with Chatterbox (on RTX 4090 system)
- Recording live narration (your voice)
- Writing marketing copy (same messaging)

---

### VIDEO_RECORDING_GUIDE.md

**Path:** `docs/VIDEO_RECORDING_GUIDE.md`
**Status:** ✅ Complete
**Owner:** Core Team

**What It Contains:**
- Complete instructions for recording demo video
- Option A: AI voiceover (Chatterbox TTS on RTX 4090)
- Option B: Live narration (your voice)
- Pre-recording checklist (hardware, software, test run)
- Recording process (OBS Studio or FFmpeg)
- Post-production editing (combining video + audio)
- Title cards (intro/outro)
- Upload instructions (YouTube/Vimeo)
- Troubleshooting common issues

**When to Reference:**
- Before recording demo video
- When setting up recording equipment
- When editing video
- When troubleshooting recording issues

---

### TERMINAL_RECORDING_COMMANDS.sh

**Path:** `docs/TERMINAL_RECORDING_COMMANDS.sh`
**Status:** ✅ Complete
**Owner:** Core Team

**What It Is:**
- Executable bash script with all commands for demo video
- Segment-by-segment commands matching video timing
- Pre-recording setup (VM start, SSH test, font scaling)
- Evidence mounting workflow (E01 → partition → NTFS mount)
- MCP execution demonstration
- Self-correction example display
- Post-recording cleanup

**When to Reference:**
- Recording terminal session for demo video
- Testing demo workflow before recording
- Troubleshooting evidence mounting

---

### VIDEO_STORYBOARD.md

**Path:** `docs/VIDEO_STORYBOARD.md`
**Status:** ✅ Complete (not in this conversation, but may exist)
**Owner:** Core Team

**What It Contains:**
- Frame-by-frame description of what viewers will see
- ASCII art representations of title cards
- Terminal output examples
- JSON finding examples
- Audit log display format
- Split-screen layout specification

**When to Reference:**
- Planning video recording
- Understanding visual flow of demo
- Designing title cards

---

## 🎯 Competition Submission Checklist

Reference this before submitting to FIND EVIL! Hackathon:

**Required Deliverables:**
- [ ] Demo video (<5 minutes) - **BLOCKER** (only remaining item)
- [x] Architecture diagram (ARCHITECTURE_DIAGRAM.md)
- [x] Accuracy report (accuracy_report.json - F1=1.00)
- [x] Execution logs (cases/*/audit.jsonl)
- [x] Evidence samples (reference to publicly available evidence)
- [x] Documentation (README_COMMUNITY.md, ARCHITECTURE_DIAGRAM.md)
- [x] Source code (will be in 4n6nexus/4n6nexus public repo)
- [x] License (MIT License)

**Pre-Submission Tasks:**
- [ ] Record demo video
- [ ] Create 4n6nexus/4n6nexus public repository
- [ ] Push community code to public repo
- [ ] Verify clean installation from public repo
- [ ] Test all documented workflows
- [ ] Upload video to YouTube/Vimeo
- [ ] Update README_COMMUNITY.md with video URL
- [ ] Submit to Devpost

---

## 🔄 Workflow: From Documentation to Execution

### Phase 1: Review & Alignment (Current Phase)

**Goal:** Ensure all documentation is complete, consistent, and approved by team

**Tasks:**
1. ✅ Create PRODUCT_TIERS.md (defines what goes where)
2. ✅ Update OPEN_SOURCE_STRATEGY.md (two tiers, not three)
3. ✅ Update README_COMMUNITY.md (two tiers, not three)
4. ✅ Create DOCUMENTATION_INDEX.md (this file)
5. ⏳ Team review (get approval on all strategy docs)

**Approval Criteria:**
- [ ] Core team has read PRODUCT_TIERS.md and agrees on feature split
- [ ] Core team has read OPEN_SOURCE_STRATEGY.md and agrees on business model
- [ ] Core team has read REPOSITORY_MANAGEMENT.md and understands workflow
- [ ] Any concerns or objections have been addressed

### Phase 2: Create Automation Scripts

**Goal:** Automate the repository split process

**Tasks:**
1. Create `scripts/create_community_repo.sh` (copies files to new repo)
2. Create `scripts/rename_enterprise_repo.sh` (renames current repo)
3. Test scripts in dry-run mode (don't actually create repos yet)
4. Review script output (ensure correct files are copied)

**Validation:**
- [ ] Scripts copy exactly the files specified in REPOSITORY_MANAGEMENT.md
- [ ] Scripts generate correct LICENSE, .gitignore, pyproject.toml
- [ ] Scripts commit with appropriate messages
- [ ] Scripts provide clear next-step instructions

### Phase 3: Execute Repository Split

**Goal:** Create public community repository

**Tasks:**
1. Run `bash scripts/create_community_repo.sh`
2. Review generated repository (cd ../4n6nexus)
3. Test installation (pip install -e .)
4. Run tests (pytest tests/)
5. Create GitHub repository: `4n6nexus/4n6nexus`
6. Push to GitHub
7. Verify GitHub repo looks correct (README, badges, files)

**Validation:**
- [ ] Community repo has only intended files (no enterprise code)
- [ ] Tests pass in clean installation
- [ ] README renders correctly on GitHub
- [ ] Logo banner displays correctly
- [ ] No secrets or credentials leaked

### Phase 4: Rename Enterprise Repository

**Goal:** Clarify current repo is Enterprise Edition

**Tasks:**
1. Run `bash scripts/rename_enterprise_repo.sh`
2. Update GitHub repo name (Settings → Repository name)
3. Update remote URL (git remote set-url origin <new-url>)
4. Update all internal references (CLAUDE.md, README.md)
5. Verify enterprise repo still works

**Validation:**
- [ ] All tests still pass in enterprise repo
- [ ] Git remote URL is correct
- [ ] CI/CD still runs (if configured)
- [ ] No broken links in documentation

### Phase 5: Record Demo Video

**Goal:** Complete the only remaining competition deliverable

**Tasks:**
1. Generate AI voiceover using Chatterbox (on RTX 4090 system)
2. Record terminal session (bash docs/TERMINAL_RECORDING_COMMANDS.sh)
3. Combine video + audio (Option A) or record live (Option B)
4. Edit video (add title cards, trim mistakes)
5. Export final video (H.264, 1080p, <5 minutes)
6. Upload to YouTube/Vimeo
7. Update README_COMMUNITY.md with video URL

**Validation:**
- [ ] Video length <5 minutes
- [ ] Audio clearly audible
- [ ] Terminal text readable at 1080p
- [ ] Self-correction example shown clearly
- [ ] F1=1.00 results visible
- [ ] No sensitive information visible

### Phase 6: Competition Submission

**Goal:** Submit to FIND EVIL! Hackathon on Devpost

**Tasks:**
1. Go to https://findevil.devpost.com/
2. Fill out submission form:
   - Project name: 4n6Nexus
   - Tagline: Autonomous DFIR with Architectural Self-Correction
   - Description: Copy from README_COMMUNITY.md
   - Demo video URL: YouTube/Vimeo link
   - GitHub repo: https://github.com/4n6nexus/4n6nexus
   - Architecture diagram: Link to ARCHITECTURE_DIAGRAM.md in repo
   - Accuracy report: Link to accuracy_report.json in repo
   - Execution logs: Link to sample audit.jsonl in repo
3. Review submission
4. Submit before deadline (June 15, 2026)

**Validation:**
- [ ] All 8 deliverables linked correctly
- [ ] Video plays correctly on Devpost
- [ ] GitHub repo is public and accessible
- [ ] Documentation is complete and clear
- [ ] No broken links

---

## 📝 Documentation Standards

### Naming Conventions

**Internal strategy docs:** `UPPERCASE_SNAKE_CASE.md`
- Example: `PRODUCT_TIERS.md`, `OPEN_SOURCE_STRATEGY.md`

**Public documentation:** `Title_Case.md` or `lowercase-with-dashes.md`
- Example: `ARCHITECTURE.md`, `CONTRIBUTING.md`, `installation-guide.md`

**Scripts:** `lowercase_snake_case.sh` or `kebab-case.sh`
- Example: `create_community_repo.sh`, `rename-enterprise-repo.sh`

### Version Control

- All strategy documents have "Last Updated" date
- Major changes logged in "Decision Log" section
- Keep old decisions visible (don't delete, mark as superseded)

### Approval Process

**Internal strategy docs:**
1. Draft by core team
2. Review by all stakeholders
3. Mark as "Approved" with date
4. Any changes require re-approval

**Public documentation:**
1. Draft by core team
2. Technical review (accuracy, clarity)
3. Legal review (no leaks, correct attribution)
4. Publish to GitHub

### Cross-References

- Always link to related documents
- Use relative paths in markdown (`[PRODUCT_TIERS.md](./PRODUCT_TIERS.md)`)
- Keep this index updated when adding new docs

---

## 🔒 Security Considerations

### What Should NOT Be Documented Publicly

- **Internal strategy discussions** (OPEN_SOURCE_STRATEGY.md, PRODUCT_TIERS.md)
- **Pricing details** (actual numbers, contracts)
- **Customer information** (names, cases, evidence)
- **Advanced detector algorithms** (memory forensics logic, correlation heuristics)
- **Enterprise feature implementation** (code, architecture)
- **Credentials** (API keys, passwords, tokens)
- **Internal processes** (sales playbooks, support scripts)

### What Should Be Documented Publicly

- **Community Edition documentation** (installation, usage, architecture)
- **High-level feature descriptions** (what Enterprise does, not how)
- **Contributing guidelines** (how to submit PRs)
- **Security policy** (responsible disclosure)
- **License** (MIT for Community, terms for Enterprise)

### Before Publishing Any Document

**Checklist:**
- [ ] No internal strategy details
- [ ] No customer information
- [ ] No credentials or secrets
- [ ] No enterprise implementation details
- [ ] Proper attribution (SANS, evidence sources)
- [ ] Legal review if unsure

---

## 🤝 Contributing to Documentation

### Adding New Documentation

1. **Determine audience:** Internal (strategy) or public (user docs)?
2. **Choose location:**
   - Internal strategy: `docs/UPPERCASE_STRATEGY.md`
   - Public technical: `docs/Lowercase-Guide.md`
   - Public reference: `docs/REFERENCE.md`
3. **Use template:** Follow structure of similar existing docs
4. **Update this index:** Add entry to DOCUMENTATION_INDEX.md
5. **Cross-reference:** Link from related documents

### Updating Existing Documentation

1. **Check approval status:** Does this need re-approval?
2. **Update "Last Updated" date**
3. **Log decision:** Add to "Decision Log" if strategy change
4. **Update cross-references:** Other docs may reference this
5. **Notify team:** Significant changes should be announced

### Document Templates

**Internal Strategy Doc:**
```markdown
# Document Title

**Version:** 1.0
**Date:** 2026-04-24
**Status:** Draft | Approved | Superseded
**Owner:** Core Team

## Overview
[Purpose and scope]

## [Main Sections]

## Decision Log
| Date | Decision | Rationale |
|------|----------|-----------|

## Questions & Answers

---
**Document Owner:** [Name]
**Next Review:** [Date]
```

**Public User Doc:**
```markdown
# Document Title

Brief description for users.

## Prerequisites
## Installation
## Usage
## Troubleshooting
## FAQ

---
Last updated: 2026-04-24
```

---

## 📞 Questions?

If you have questions about:
- **Product strategy:** See PRODUCT_TIERS.md or ask core team
- **Repository management:** See REPOSITORY_MANAGEMENT.md
- **Documentation standards:** Reference this document
- **Something not covered:** Open GitHub Discussion (internal repo)

---

**Document Owner:** Core Team
**Last Updated:** 2026-04-24
**Next Review:** After competition submission
