# GitHub Project Setup Instructions

**Created:** 2026-04-16  
**Purpose:** Complete GitHub Project setup for SIFT Find Evil hackathon

This document contains the exact steps to create your GitHub Project with all custom fields, views, milestones, labels, and initial issues.

---

## Quick Reference

**Repository Status:** ✅ Initialized and committed  
**Commit Hash:** 95442f4  
**Files Created:** 17 (README, PRD, Architecture, 4 issue templates, etc.)

**Next Steps:**
1. Push to GitHub remote
2. Create GitHub Project (v2)
3. Configure custom fields and views
4. Create milestones and labels
5. Create initial 20 issues

**Estimated Time:** 60 minutes

---

## Step 1: Push to GitHub Remote (5 minutes)

```bash
# Add remote (replace with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/sift-find-evil.git

# Push to main branch
git push -u origin main

# Verify
git status
# Should show: "Your branch is up to date with 'origin/main'"
```

---

## Step 2: Create GitHub Project (5 minutes)

1. Go to your GitHub repository
2. Click **Projects** tab
3. Click **New project**
4. Select **Table** view
5. Click **Create project**
6. Click project name (top-left) → **Settings**:
   - **Name:** `FIND EVIL! - Autonomous DFIR Agent (Hackathon → Product)`
   - **Description:** Paste from section below
   - **Visibility:** Public
   - Click **Save changes**

**Project Description:**
```
Autonomous AI agent for Digital Forensics and Incident Response (DFIR) on SANS SIFT Workstation. Built for SANS FIND EVIL! Hackathon (June 15, 2026 deadline) with production-grade architecture for commercial SaaS launch.

🎯 Core Innovation: Cross-artifact validation + architectural self-correction
🏗️ Architecture: Claude Code Direct Agent Extension + Protocol SIFT MCP
📊 Judging Focus: Autonomous execution, real-time self-correction, evidence integrity, audit trails
🚀 Product Vision: Open-source community edition → Commercial SaaS (Q4 2026)

Key Deliverables:
• Autonomous investigation loop with senior-analyst reasoning
• Cross-artifact contradiction detection engine
• Read-only evidence integrity guarantees
• Complete JSONL audit trails with reasoning chains
• 8 mandatory hackathon submissions (demo video, architecture diagram, accuracy report, etc.)

License: MIT | Tech Stack: Claude Code, Protocol SIFT MCP, Python
```

---

## Step 3: Add Custom Fields (10 minutes)

For each field below, click **+ New field** in your project:

| Field Name | Type | Options |
|------------|------|---------|
| **Status** | Single Select | Backlog, Ready, In Progress, In Review, Blocked, Done, Won't Do |
| **PRD Section** | Single Select | Exec Summary, Objectives, User Stories, Functional Reqs, Non-Functional Reqs, Architecture, Roadmap, Risks, Testing, Documentation, TTPs, N/A |
| **Priority** | Single Select | P0 (Critical), P1 (High), P2 (Medium), P3 (Low), P4 (Backlog) |
| **Effort** | Number | (1-13, Fibonacci story points) |
| **Due Date** | Date | (manual entry) |
| **Artifact Type** | Single Select | PRD, Code, Test, Documentation, Demo Asset, TTP, Deliverable, N/A |
| **Self-Correction Scenario** | Single Select | Cross-Artifact Validation, Uncertainty Budget, Contradiction Detection, Tool Failure Recovery, N/A |
| **Agent Owner** | Text | (e.g., docs-writer, ci-architect, api-architect) |

---

## Step 4: Create Views (8 minutes)

### View 1: Kanban Board (Default)
- Layout: **Board**
- Group by: **Status**
- Sort by: **Priority**, then **Due Date**
- Filter: `Status != Done AND Status != Won't Do`
- Visible fields: Title, Priority, Effort, Due Date, Agent Owner

### View 2: PRD Development Table
- Layout: **Table**
- Group by: **PRD Section**
- Sort by: **Priority**
- Filter: `Artifact Type = PRD OR PRD Section != N/A`
- Visible fields: Title, PRD Section, Status, Priority, Due Date, Effort

### View 3: Hackathon Roadmap
- Layout: **Roadmap**
- Date field: **Due Date**
- Group by: **Milestone**
- Sort by: **Due Date**
- Filter: `Due Date <= 2026-06-15`
- Visible fields: Title, Priority, Status, Milestone

### View 4: Agent Dashboard
- Layout: **Table**
- Group by: **Agent Owner**
- Sort by: **Status** (In Progress first), **Priority**
- Filter: `Status = Ready OR Status = In Progress OR Status = Blocked`
- Visible fields: Title, Status, Priority, Effort, Self-Correction Scenario, Artifact Type

### View 5: Self-Correction Features
- Layout: **Board**
- Group by: **Self-Correction Scenario**
- Filter: `Self-Correction Scenario != N/A`
- Visible fields: Title, Status, Priority, Due Date

---

## Step 5: Create Milestones (3 minutes)

Go to **Issues** → **Milestones** → **New milestone** for each:

| # | Title | Due Date | Description |
|---|-------|----------|-------------|
| M1 | PRD Foundation | 2026-04-23 | Complete PRD Sections 1-6 (Exec Summary → Architecture) |
| M2 | Environment Setup | 2026-04-25 | Install SIFT, Protocol SIFT MCP, baseline test tools |
| M3 | Core Agent Loop | 2026-05-05 | Evidence intake → triage → hypothesis → tool execution |
| M4 | Self-Correction Engine | 2026-05-15 | Cross-artifact validation + contradiction detection |
| M5 | Correlation & Timeline | 2026-05-20 | Timeline reconstruction from ≥3 sources |
| M6 | Audit & Guardrails | 2026-05-25 | JSONL logs + read-only enforcement + timeouts |
| M7 | Testing & Accuracy | 2026-06-05 | NIST CFReDS testing, accuracy report generation |
| M8 | Demo & Documentation | 2026-06-10 | Demo video + architecture diagram + README |
| M9 | Hackathon Submission | 2026-06-15 | Submit all 8 deliverables to SANS |
| M10 | Post-Hackathon Analysis | 2026-06-22 | Review feedback, document lessons learned |

---

## Step 6: Create Labels (10 minutes)

**Option A: Manual (click New label for each)**

Go to **Issues** → **Labels** → **New label**

**Option B: GitHub CLI (faster)**

```bash
# PRD labels
gh label create "prd" -c "0052CC" -d "PRD development task"
gh label create "prd-section-1" -c "0052CC" -d "PRD Section 1: Executive Summary"
gh label create "prd-section-2" -c "0052CC" -d "PRD Section 2: Objectives & Metrics"
gh label create "prd-section-3" -c "0052CC" -d "PRD Section 3: User Stories"
gh label create "prd-section-4" -c "0052CC" -d "PRD Section 4: Functional Requirements"
gh label create "prd-section-5" -c "0052CC" -d "PRD Section 5: Non-Functional Requirements"
gh label create "prd-section-6" -c "0052CC" -d "PRD Section 6: Architecture"
gh label create "prd-section-7" -c "0052CC" -d "PRD Section 7: Roadmap"
gh label create "prd-section-8" -c "0052CC" -d "PRD Section 8: Risks & Mitigations"
gh label create "prd-section-9" -c "0052CC" -d "PRD Section 9: Testing & Accuracy"
gh label create "prd-section-10" -c "0052CC" -d "PRD Section 10: Documentation"
gh label create "prd-section-11" -c "0052CC" -d "PRD Section 11: TTPs"

# Feature labels
gh label create "feature" -c "1D76DB" -d "New feature implementation"
gh label create "self-correction" -c "E99695" -d "Self-correction mechanism (star feature)"
gh label create "cross-artifact-validation" -c "E99695" -d "Cross-artifact validation engine"
gh label create "correlation" -c "5319E7" -d "Evidence correlation / timeline reconstruction"
gh label create "tool-wrapper" -c "BFD4F2" -d "Protocol SIFT MCP tool wrapper"
gh label create "agent-loop" -c "1D76DB" -d "Core autonomous investigation loop"
gh label create "audit-logging" -c "C2E0C6" -d "Audit trail / JSONL logging"
gh label create "guardrails" -c "FBCA04" -d "Architectural constraints"

# Testing labels
gh label create "testing" -c "C2E0C6" -d "Testing task"
gh label create "accuracy-report" -c "C2E0C6" -d "Accuracy report generation"
gh label create "test-case" -c "C2E0C6" -d "Specific test case development"
gh label create "nist-cfrids" -c "C2E0C6" -d "NIST CFReDS dataset testing"
gh label create "synthetic-case" -c "C2E0C6" -d "Synthetic ransomware case"

# Documentation labels
gh label create "documentation" -c "0075CA" -d "Documentation task"
gh label create "demo-video" -c "0075CA" -d "Demo video production"
gh label create "architecture-diagram" -c "0075CA" -d "Architecture diagram creation"
gh label create "readme" -c "0075CA" -d "README.md content"
gh label create "deliverable" -c "D93F0B" -d "Mandatory hackathon deliverable"

# TTP labels
gh label create "ttp" -c "7057FF" -d "Tactic, Technique, Procedure documentation"
gh label create "playbook" -c "7057FF" -d "Investigation playbook"
gh label create "decision-tree" -c "7057FF" -d "Decision tree / workflow logic"
gh label create "lessons-learned" -c "7057FF" -d "Lessons learned capture"
gh label create "knowledge-base" -c "7057FF" -d "Knowledge base entry"

# Priority labels
gh label create "p0-critical" -c "D93F0B" -d "Critical priority (blocks progress)"
gh label create "p1-high" -c "E99695" -d "High priority (needed for MVP)"
gh label create "p2-medium" -c "FBCA04" -d "Medium priority (should-have)"
gh label create "p3-low" -c "BFD4F2" -d "Low priority (nice-to-have)"
gh label create "p4-backlog" -c "D4C5F9" -d "Backlog (post-hackathon)"

# Status labels
gh label create "blocked" -c "D93F0B" -d "Blocked by dependency"
gh label create "urgent" -c "D93F0B" -d "Due within 3 days"
gh label create "completed" -c "0E8A16" -d "Completed and verified"

# Agent labels
gh label create "agent:docs-writer" -c "5319E7" -d "Assign to docs-writer agent"
gh label create "agent:ci-architect" -c "5319E7" -d "Assign to ci-architect agent"
gh label create "agent:api-architect" -c "5319E7" -d "Assign to api-architect agent"
gh label create "agent:test-engineer" -c "5319E7" -d "Assign to test-engineer agent"
gh label create "agent:security-reviewer" -c "5319E7" -d "Assign to security-reviewer agent"

# Technical labels
gh label create "bug" -c "D93F0B" -d "Bug fix"
gh label create "enhancement" -c "1D76DB" -d "Enhancement to existing feature"
gh label create "refactor" -c "FBCA04" -d "Code refactoring"
gh label create "performance" -c "FBCA04" -d "Performance optimization"
gh label create "security" -c "D93F0B" -d "Security concern"
gh label create "mcp-integration" -c "BFD4F2" -d "Protocol SIFT MCP integration"
```

---

## Step 7: Create Initial Issues (20 minutes)

See separate document: `INITIAL_ISSUES.md` for all 20 seed issues with full descriptions.

**Quick method using GitHub CLI:**
```bash
# Example for Issue #1
gh issue create \
  --title "[PRD] Section 1 - Executive Summary & Problem Statement (FINALIZED)" \
  --body "$(cat .github/issues/issue_01.md)" \
  --label "prd,prd-section-1,documentation,completed,p1-high" \
  --milestone "M1: PRD Foundation"
```

Or use the GitHub web UI to manually create each issue from the templates.

---

## Verification Checklist

After completing all steps:

- [ ] Repository pushed to GitHub
- [ ] GitHub Project created with name and description
- [ ] All 8 custom fields added
- [ ] All 5 views created (Kanban, PRD Table, Roadmap, Agent Dashboard, Self-Correction)
- [ ] All 10 milestones created with due dates
- [ ] All 50+ labels created with correct colors
- [ ] All 4 issue templates committed to `.github/ISSUE_TEMPLATE/`
- [ ] First 20 issues created and linked to project
- [ ] Project board shows issues organized by status

**Total Time:** ~60 minutes

---

## Next Actions After Setup

Once GitHub Project is configured:

1. **Review PRD Sections 1-2** with team (already completed and committed)
2. **Start PRD Section 3** (User Stories & Personas) - Create issue from template
3. **Download datasets** - NIST CFReDS, SANS starter cases (Issue #9)
4. **Install SIFT Workstation** - Set up dev environment (Issue #8)
5. **Install Protocol SIFT MCP** - Baseline test tools (Issue #7)

**Agent-Driven Workflow Begins:**
From this point, you can use natural language commands:
- "Create issue for implementing Volatility wrapper"
- "Update issue #12 status to In Progress"
- "Generate sprint report for M3"
- "Show me all blocked issues"

---

## Support

If you encounter issues during setup:
- Check GitHub Projects v2 documentation: https://docs.github.com/en/issues/planning-and-tracking-with-projects
- GitHub CLI documentation: https://cli.github.com/manual/

---

**Setup complete! Your hackathon project is now fully initialized and ready for agent-driven execution.**
