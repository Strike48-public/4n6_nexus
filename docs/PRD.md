# Product Requirements Document - SIFT Find Evil

**Project:** SIFT Find Evil - Autonomous DFIR Agent  
**Version:** 1.0  
**Date:** 2026-04-16  
**Status:** In Development  
**Hackathon Deadline:** June 15, 2026

---

## Table of Contents

1. [Executive Summary & Problem Statement](#1-executive-summary--problem-statement)
2. [Objectives & Success Metrics](#2-objectives--success-metrics)
3. [User Stories & Personas](#3-user-stories--personas) *(To be completed)*
4. [Functional Requirements](#4-functional-requirements) *(To be completed)*
5. [Non-Functional Requirements](#5-non-functional-requirements) *(To be completed)*
6. [Architecture & Technical Design](#6-architecture--technical-design) *(To be completed)*
7. [Feature Prioritization & Roadmap](#7-feature-prioritization--roadmap) *(To be completed)*
8. [Risks, Gaps, Dependencies & Mitigations](#8-risks-gaps-dependencies--mitigations) *(To be completed)*
9. [Testing, Validation & Accuracy Reporting](#9-testing-validation--accuracy-reporting) *(To be completed)*
10. [Documentation & Submission Deliverables](#10-documentation--submission-deliverables) *(To be completed)*
11. [TTPs, Processes & Knowledge Base](#11-ttps-processes--knowledge-base) *(To be completed)*

---

## 1. Executive Summary & Problem Statement

### 1.1 Hackathon Context

The SANS Institute's **FIND EVIL! Hackathon** (deadline: June 15, 2026) challenges teams to build autonomous AI agents capable of performing Digital Forensics and Incident Response (DFIR) at machine speed on the SANS SIFT Workstation. This competition addresses a critical industry gap: the severe shortage of skilled incident responders coupled with exponentially growing volumes of security incidents requiring forensic analysis.

**Competition landscape:**
- Teams will compete across multiple architectural approaches: custom MCP servers, multi-agent frameworks (AutoGen/CrewAI/LangGraph), and Direct Agent Extensions (Claude Code/OpenClaw)
- Judging heavily favors autonomous execution quality, real-time self-correction, architectural constraints over prompt engineering, and comprehensive audit trails
- Eight mandatory deliverables including demo video (≤5 minutes showing self-correction), architecture diagram, accuracy report, and structured execution logs
- All entries must be open-source (MIT or Apache 2.0)

### 1.2 The DFIR Automation Gap

**Current state of DFIR:**
- **Manual, time-intensive workflows:** Senior analysts spend 40-120+ hours per investigation manually running tools, correlating artifacts, and documenting findings
- **Tool fragmentation:** 50+ specialized forensic tools (Sleuth Kit, Volatility, log2timeline, etc.) require deep expertise and manual orchestration
- **Cognitive overload:** Analysts must hold complex mental models of evidence relationships across disk artifacts, memory structures, network traffic, and logs
- **Inconsistent quality:** Investigation depth and accuracy vary based on analyst experience, fatigue, and time pressure
- **Poor auditability:** Manual notes and screenshots fail to capture complete decision chains for legal/compliance review

**Existing automation attempts fall short:**
- Script-based automation lacks reasoning capability and cannot adapt to unexpected findings
- Prompt-engineered LLM tools hallucinate findings and lack evidence integrity guarantees
- Multi-agent frameworks introduce coordination overhead and fragmented audit trails
- Commercial SOAR platforms focus on orchestration, not autonomous investigation

### 1.3 Our Solution: SIFT-Find-Evil Orchestration System

We are building **sift-find-evil** - a Claude Code-based autonomous DFIR agent that combines:

1. **Autonomous investigation loops** with senior-analyst-level reasoning
2. **Architectural guardrails** for evidence integrity (read-only enforcement, chain-of-custody logging, timeout protections)
3. **Real-time self-correction** via cross-artifact validation and contradiction detection
4. **Deep integration** with Protocol SIFT MCP for safe, auditable tool execution
5. **Complete audit trails** with structured JSONL logs capturing every decision, tool invocation, and confidence assessment

**Key innovation: Cross-Artifact Validation Engine**

Our MVP star feature automatically detects contradictions between evidence sources (e.g., Prefetch timestamps vs. MFT $STANDARD_INFORMATION vs. memory process creation times) and triggers autonomous re-investigation when discrepancies exceed confidence thresholds. This architectural self-correction mechanism - not prompt-based - will be the centerpiece of our demo video.

### 1.4 Business & Product Vision

**Hackathon phase (now - June 15, 2026):**
- Win competition by demonstrating superior autonomous execution, self-correction architecture, and investigation depth
- Establish open-source credibility and technical leadership in AI-assisted DFIR
- Validate core product hypothesis: architectural constraints + LLM reasoning > prompt engineering alone

**Product phase 1 (June - Q4 2026):**
- Launch open-source community edition (MIT license) targeting individual analysts and academic researchers
- Develop commercial SaaS offering with:
  - Multi-case management dashboard
  - Team collaboration features (shared investigations, peer review workflows)
  - Custom playbook editor for organization-specific investigation procedures
  - Enterprise SSO, audit export (SIEM integration), and compliance reporting
- Target market: MSSPs, enterprise SOCs, digital forensics consultancies

**Product phase 2 (2027+):**
- Persistent learning platform: Cross-case IoC intelligence, automated threat hunting, predictive incident severity scoring
- Marketplace for community-contributed analysis playbooks and custom tool wrappers
- API-first architecture enabling integration with existing SIEM/SOAR/ticketing systems
- Managed detection + autonomous response offering (subscription model)

**Revenue model:**
- Open-source core (community growth + hiring pipeline)
- SaaS tiers: Professional ($99/analyst/month), Team ($499/5 analysts/month), Enterprise (custom)
- Professional services: Custom playbook development, integration consulting, expert training

### 1.5 Competitive Landscape

**Hackathon competitors:**
- **Custom MCP server entries:** May have more specialized tools but lack tight Claude Code integration and simpler deployment story
- **Multi-agent frameworks:** Coordination overhead, fragmented audit trails, higher complexity
- **Prompt-only approaches:** No architectural evidence integrity, prone to hallucination, weak auditability

**Commercial DFIR landscape:**
- **Traditional tools (EnCase, FTK, X-Ways):** Manual workflows, steep learning curves, no AI reasoning
- **SOAR platforms (Splunk Phantom, Palo Alto Cortex XSOAR):** Orchestration without autonomous investigation
- **Emerging AI DFIR (experimental):** Limited public offerings, mostly research prototypes or closed commercial pilots

**Our differentiation:**
- Only open-source solution with architectural self-correction (not prompt-based)
- Direct Agent Extension approach reduces complexity vs. multi-agent coordination
- Production-grade auditability from day one (legal defensibility)
- Commercial-ready architecture with clear path from hackathon MVP to SaaS product

---

## 2. Objectives & Success Metrics

### 2.1 Hackathon Success Criteria (Judging Mapping)

| Judging Criterion | Our Feature/Metric | Target | Stretch Goal |
|-------------------|-------------------|--------|--------------|
| **Autonomous execution quality** | Investigation completion without human intervention on primary test case | 95% autonomous (≤1 manual intervention) | 100% autonomous |
| **Real-time self-correction** | Cross-artifact contradiction detection → re-investigation loops demonstrated | ≥3 self-correction instances in demo video | ≥5 instances + show uncertainty budget mechanism |
| **IR accuracy** | Precision/Recall on IoC identification vs. ground truth (NIST CFReDS Hacking Case) | P: ≥85%, R: ≥80% | P: ≥90%, R: ≥85% |
| **Analysis breadth** | Artifact types analyzed per case | ≥8 types (MFT, Prefetch, Registry, Event Logs, Memory processes, Network artifacts, Browser history, Timeline) | ≥12 types + email/cloud artifacts |
| **Analysis depth** | Average analysis passes per artifact (initial → validation → correlation) | ≥2 passes per critical artifact | ≥3 passes with documented reasoning chains |
| **Architectural constraints** | Read-only enforcement, timeout guards, circuit breakers, confidence thresholds | 4/4 mechanisms implemented + tested | + Resource limits (CPU/memory caps per tool) |
| **Audit trail quality** | JSONL logs with tool invocations, reasoning chains, timestamps, confidence scores | 100% tool calls logged + ≥80% reasoning chains captured | + Replay capability (reproduce investigation from logs) |
| **Usability** | Time to first meaningful finding (TTFMF) | <5 minutes on demo case | <3 minutes |
| **Documentation** | README completeness, architecture diagram clarity, try-it-out instructions | All 8 mandatory deliverables submitted, ≤15 min setup time | + Interactive demo environment (Docker Compose one-liner) |

### 2.2 Product Success Metrics (Post-Hackathon)

#### 2.2.1 Investigation Performance
- **Time to Report (TTR):** Median time from evidence intake to final report delivery
  - Baseline (manual): 40-120 hours
  - Target (MVP): <4 hours for triage, <12 hours for full investigation
  - Stretch: <2 hours triage, <6 hours full investigation

- **False Positive Rate (FPR):** Percentage of flagged IoCs that are benign
  - Target: <10%
  - Stretch: <5%

- **False Negative Rate (FNR):** Percentage of ground-truth IoCs missed
  - Target: <15%
  - Stretch: <10%

#### 2.2.2 User Adoption & Satisfaction
- **Net Promoter Score (NPS):** Among beta testers (post-hackathon Phase 1)
  - Target: ≥40 (industry average for B2B SaaS)
  - Stretch: ≥60 (top quartile)

- **Weekly Active Analysts (WAA):** Unique analysts running investigations per week
  - Target: 50 WAA by Q4 2026
  - Stretch: 150 WAA

- **Case Completion Rate:** Percentage of started investigations that produce final reports
  - Target: ≥70%
  - Stretch: ≥85%

#### 2.2.3 Commercial Viability
- **Conversion Rate (Open-source → Paid):** Free users upgrading to paid tiers
  - Target: 5% by end of 2026
  - Stretch: 10%

- **Monthly Recurring Revenue (MRR):** By Q4 2026
  - Target: $10k MRR (100 paid analysts)
  - Stretch: $25k MRR (250 paid analysts)

### 2.3 Technical Performance Targets

#### 2.3.1 Scalability
- **Evidence volume:** Handle disk images up to 500GB, memory dumps up to 32GB
- **Artifact count:** Process timelines with 100k+ events without degradation
- **Concurrent investigations:** Support 3+ simultaneous cases (multi-case queue)

#### 2.3.2 Reliability
- **Tool failure handling:** ≤1% of tool failures result in investigation abort (99% recovery via circuit breakers)
- **Reproducibility:** 100% of investigations reproducible from audit logs (deterministic replay)
- **Uptime (SaaS):** 99.5% uptime SLA for commercial offering (Phase 2)

#### 2.3.3 Evidence Integrity
- **Chain-of-custody:** 100% of evidence files hashed (SHA256) at intake and verified at analysis
- **Read-only enforcement:** 0 evidence modification incidents (architectural guarantee via MCP wrappers)
- **Audit completeness:** 100% of tool invocations logged with inputs, outputs, timestamps

### 2.4 Over-Performance Opportunities (Judging "Wow" Factors)

These are capabilities beyond baseline judging criteria that will differentiate our entry:

#### 2.4.1 Uncertainty Budget Self-Correction
- **Concept:** Track cumulative uncertainty score across analysis steps; trigger re-investigation when threshold exceeded
- **Demo impact:** Show judges a real-time confidence meter dropping → autonomous re-analysis → confidence restored
- **Metric:** ≥2 uncertainty-triggered re-investigations in demo video

#### 2.4.2 Explainable Audit Logs
- **Concept:** Logs include not just tool outputs but **reasoning narratives** ("Ran `volatility pslist` because registry RunKey analysis found suspicious entry")
- **Demo impact:** Judges can read audit logs like a story, not just raw tool dumps
- **Metric:** ≥80% of tool invocations have accompanying reasoning narrative

#### 2.4.3 Persistent Learning Loop (Stretch)
- **Concept:** Save validated findings to case-specific IoC database; future cases query: "Have we seen this hash/IP/domain before?"
- **Demo impact:** Show ransomware case detecting known-bad hash from prior investigation
- **Metric:** Build IoC DB with ≥50 entries from test cases, demonstrate 1 cross-case query in demo

#### 2.4.4 Timeline Reconstruction Engine
- **Concept:** Automatically merge MACB timelines, Windows Event Logs, memory process start times, network connection logs into unified super-timeline
- **Demo impact:** Visual timeline in report showing attacker progression (reconnaissance → initial access → lateral movement → impact)
- **Metric:** Generate super-timeline with ≥3 artifact sources, ≥1000 events, accurate to ±5 minutes

#### 2.4.5 MITRE ATT&CK Mapping
- **Concept:** Automatically tag findings with ATT&CK techniques (T1055 Process Injection, T1083 File Discovery, etc.)
- **Demo impact:** Final report includes ATT&CK matrix heatmap showing attacker TTP coverage
- **Metric:** Map ≥70% of findings to ATT&CK techniques, generate visual matrix

### 2.5 Risk-Adjusted Roadmap

Given **50-60% time commitment over 8 weeks** (~160 total hours), we must ruthlessly prioritize:

#### MUST-HAVE (Core MVP for Hackathon Submission)
- Autonomous investigation loop (triage → hypothesis → tool execution → validation)
- Cross-artifact validation + contradiction detection (star feature)
- Basic correlation (timeline reconstruction from ≥3 sources)
- Read-only enforcement + timeout guards via MCP wrappers
- JSONL audit logs with tool invocations + reasoning chains
- Demo video showing ≥3 self-correction instances on ransomware case
- All 8 mandatory deliverables (README, architecture diagram, accuracy report, etc.)

#### SHOULD-HAVE (Strengthen Competitive Position)
- Uncertainty budget self-correction mechanism
- Explainable audit logs (reasoning narratives)
- MITRE ATT&CK mapping for findings
- Accuracy report with precision/recall on NIST CFReDS Hacking Case
- Circuit breaker pattern for tool failures

#### NICE-TO-HAVE (Post-Hackathon Phase 1)
- Persistent learning loop (IoC database)
- Multi-case queue support
- Web UI for live case monitoring
- Advanced correlation (ML anomaly detection)
- Remote evidence analysis via MCP

#### OUT-OF-SCOPE (Product Phase 2+)
- Team collaboration features
- Custom playbook editor
- SIEM/SOAR integrations
- API-first architecture

---

## 3. User Stories & Personas

*(To be completed in next PRD section issue)*

---

## 4. Functional Requirements

*(To be completed in next PRD section issue)*

---

## 5. Non-Functional Requirements

*(To be completed in next PRD section issue)*

---

## 6. Architecture & Technical Design

*(To be completed in next PRD section issue)*

---

## 7. Feature Prioritization & Roadmap

*(To be completed in next PRD section issue)*

---

## 8. Risks, Gaps, Dependencies & Mitigations

*(To be completed in next PRD section issue)*

---

## 9. Testing, Validation & Accuracy Reporting

*(To be completed in next PRD section issue)*

---

## 10. Documentation & Submission Deliverables

*(To be completed in next PRD section issue)*

---

## 11. TTPs, Processes & Knowledge Base

*(To be completed in next PRD section issue)*

---

*Document Version History:*
- v1.0 (2026-04-16): Initial creation with Sections 1-2 completed
