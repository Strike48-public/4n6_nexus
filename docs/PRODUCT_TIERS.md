# 4n6 Nexus Product Tiers

**Version:** 1.0
**Date:** 2026-04-24
**Status:** Approved

## Overview

4n6 Nexus is offered in **two editions**: Community (open source) and Enterprise (commercial). This document defines exactly what features belong in each tier.

## Design Principles

1. **Community Edition demonstrates capability** - Fully functional, production-ready DFIR automation
2. **Enterprise Edition adds scale & team features** - Advanced detection, collaboration, integrations
3. **Clear value proposition** - Community is generous, Enterprise is essential for organizations
4. **No artificial limitations** - Community isn't crippled; Enterprise adds genuinely advanced features

---

## Edition Comparison

### Community Edition

**License:** MIT (Open Source)
**Price:** Free Forever
**Target:** Individual analysts, researchers, students, security enthusiasts
**Support:** Community (GitHub Issues, Discussions)

**Core Platform:**
- ✅ Full MCP safety layer (read-only enforcement, timeout guards, circuit breakers)
- ✅ Complete self-correction engine (contradiction detection, confidence adjustment)
- ✅ Cryptographic audit logging (SHA-256 hashing, chain of custody)
- ✅ Case initialization and management (single case at a time)
- ✅ CLI interface (all core commands)
- ✅ Evidence integrity verification
- ✅ JSON export for findings and audit logs

**Detection Capabilities:**
- ✅ 5 basic detectors:
  1. Timestomping detection (MFT $SI vs $FN comparison)
  2. Suspicious file extensions (masquerading, double extensions)
  3. Hidden file analysis (unusual hidden/system attributes)
  4. File size anomalies (zero-byte executables, unusual sizes)
  5. Timeline inconsistencies (future timestamps, creation after modification)
- ✅ MFT parser integration (MFTECmd wrapper)
- ✅ CSV parsing utilities
- ✅ Basic timeline artifact correlation

**Testing & Validation:**
- ✅ Complete test harness framework
- ✅ 5 synthetic test scenarios
- ✅ F1 scoring and accuracy metrics
- ✅ Ground truth validation

**Documentation:**
- ✅ Installation guide
- ✅ Architecture documentation
- ✅ CLI reference
- ✅ Detector guide
- ✅ Custom detector tutorial
- ✅ Troubleshooting guide

**What Community Edition Can Do:**
- Analyze disk images (E01, raw, mounted filesystems)
- Detect basic anti-forensics and suspicious artifacts
- Generate JSON findings with confidence scores
- Produce cryptographically verifiable audit logs
- Run autonomous forensic workflows with self-correction
- Use in court-admissible investigations (with proper documentation)

**What Community Edition Cannot Do:**
- Advanced memory forensics
- Multi-case management
- Team collaboration
- Web UI/dashboard
- SIEM/ticketing integrations
- Automated playbooks
- Cloud evidence processing
- Priority support

### Enterprise Edition

**License:** Proprietary (Commercial)
**Price:** Custom (contact sales)
**Target:** Enterprises, MSSPs, law enforcement, government, SOCs, consulting firms
**Support:** Priority support with SLA (4-hour response time)

**Includes ALL Community Features Plus:**

**Advanced Detection (15+ Detectors):**
- ✅ Memory forensics suite:
  - Process injection detection (CreateRemoteThread, QueueUserAPC, reflective DLL injection)
  - Rootkit detection (SSDT hooks, IRP hooks, inline hooks)
  - Suspicious DLL loading (unsigned, unusual paths, hidden modules)
  - Token manipulation (privilege escalation attempts)
  - Kernel module analysis (unsigned drivers, rootkit signatures)
  - Process hollowing detection
  - Memory-resident malware scanning
- ✅ Behavioral analysis:
  - Lateral movement patterns (RDP, SMB, WMI abuse)
  - Data exfiltration detection (large file transfers, unusual network activity)
  - Privilege escalation sequences (UAC bypass, token manipulation)
  - Persistence mechanism identification (Registry, scheduled tasks, services)
  - Command & control detection (beaconing, C2 communication patterns)
- ✅ Advanced artifact correlation:
  - Registry + MFT + Prefetch cross-validation
  - Event Log correlation (login events, process creation, network connections)
  - Network artifact analysis (browser history, cache, downloads)
  - USB device tracking (connection history, file access patterns)
- ✅ ML-based detection:
  - Anomaly detection models (trained on benign baselines)
  - Threat classification (malware family identification)
  - Risk scoring algorithms
  - Pattern recognition (behavioral clustering)
- ✅ Threat intelligence integration:
  - IOC matching (file hashes, IP addresses, domains)
  - MITRE ATT&CK technique mapping
  - Known malware family identification
  - APT group attribution (TTPs, infrastructure patterns)
- ✅ YARA integration:
  - Rule management system
  - Custom rule creation and testing
  - Parallel scanning across evidence
  - Result correlation with other findings

**Platform & Interface:**
- ✅ Web UI and dashboard:
  - Real-time analysis progress
  - Interactive timeline visualization
  - Finding management interface (filter, sort, search)
  - Report preview and export
  - Case overview with statistics
- ✅ REST API:
  - Programmatic case creation
  - Evidence submission
  - Finding retrieval
  - Integration with custom tools
- ✅ Multi-case management:
  - Concurrent case handling
  - Case templates (incident types, investigation workflows)
  - Evidence library (shared evidence across cases)
  - Cross-case search (find patterns across investigations)
  - Case comparison (similar artifacts, techniques)

**Team Collaboration:**
- ✅ Role-based access control (RBAC):
  - Analyst, Senior Analyst, Manager, Admin roles
  - Custom role creation
  - Granular permissions (read, write, approve, delete)
- ✅ User management:
  - User creation and invitation
  - Team assignment
  - Activity tracking per user
- ✅ Case assignment and workflow:
  - Assign cases to specific analysts
  - Case status tracking (open, in-progress, review, closed)
  - Workflow automation (escalation rules, approval gates)
- ✅ Finding comments and annotations:
  - Collaborative finding review
  - Notes and tags per finding
  - Discussion threads
  - Analyst attribution
- ✅ Audit trail per user:
  - Who viewed/modified what and when
  - Complete action history
  - Compliance reporting

**Reporting:**
- ✅ PDF report generation:
  - Executive summary (non-technical)
  - Technical deep-dive (detailed findings)
  - Timeline visualization
  - Evidence chain of custody
  - Court-admissible formatting
- ✅ HTML reports:
  - Interactive timelines
  - Filterable findings
  - Embedded visualizations
  - Shareable via web
- ✅ Custom templates:
  - Organization branding
  - Custom report sections
  - Template variables (case info, analyst info)
  - Compliance-specific formats (ISO 27001, NIST, etc.)
- ✅ Automated report scheduling:
  - Daily/weekly/monthly summaries
  - Email delivery
  - Report archiving

**Enterprise Integrations:**
- ✅ SIEM integration:
  - Splunk (findings as events, real-time forwarding)
  - Elastic Stack (ELK) (JSON ingestion, Kibana dashboards)
  - IBM QRadar (log source integration)
  - Chronicle (Google Security Operations)
- ✅ Ticketing systems:
  - Jira (automatic ticket creation from high-severity findings)
  - ServiceNow (incident creation, bi-directional sync)
  - PagerDuty (alerting integration)
- ✅ Authentication:
  - SSO (SAML 2.0, OAuth2)
  - LDAP/Active Directory integration
  - Multi-factor authentication (MFA)
  - API token management
- ✅ Threat intelligence feeds:
  - MISP integration
  - VirusTotal API
  - AlienVault OTX
  - Custom threat feeds (CSV, STIX/TAXII)
- ✅ Webhook notifications:
  - Slack/Teams notifications
  - Custom webhook endpoints
  - Event-driven automation

**Automation & Orchestration:**
- ✅ Playbook engine:
  - Define investigation workflows (steps, decision trees)
  - Automated evidence processing pipelines
  - Conditional logic (if finding X, then run detector Y)
  - Human-in-the-loop approval gates
- ✅ Evidence triage:
  - Automatic prioritization (risk scoring)
  - Pre-screening for common artifacts
  - Fast triage mode (quick indicators before deep analysis)
- ✅ Bulk processing:
  - Batch evidence submission (dozens of images)
  - Parallel analysis across multiple cases
  - Progress tracking and reporting
- ✅ Scheduled analysis:
  - Recurring scans (daily, weekly, monthly)
  - Baseline comparisons (detect drift)
  - Automated evidence ingestion from storage

**Cloud & Scale:**
- ✅ Cloud evidence processing:
  - S3/Azure Blob/GCS evidence ingestion
  - Cloud-native storage (no local disk required)
  - Remote evidence mounting (mount E01 from S3)
- ✅ Distributed workers:
  - Horizontal scaling (add analysis nodes)
  - Load balancing across workers
  - Fault tolerance (worker failure recovery)
- ✅ High availability:
  - Multi-node deployment
  - Database replication
  - Automatic failover

**Enterprise Support:**
- ✅ Priority email/chat support (4-hour response SLA)
- ✅ Dedicated account manager
- ✅ Training and onboarding (virtual or on-site)
- ✅ Custom feature development (roadmap prioritization)
- ✅ Security assessments and compliance documentation
- ✅ Quarterly business reviews (QBRs)

---

## Feature Allocation Rationale

### Why These Features Are Open Source (Community)

**Core Platform (MCP Safety + Self-Correction):**
- Demonstrates technical innovation (competition requirement)
- Builds trust in the approach (auditable, verifiable)
- Enables community contributions (detectors, parsers)
- No competitive disadvantage (implementation is sophisticated, but concept is publishable)

**5 Basic Detectors:**
- Shows real capability (not just theory)
- Common DFIR patterns (valuable to individuals)
- Not our core IP (detectors are extensible, more value in advanced detectors)

**CLI + Test Harness:**
- Enables autonomous usage (judges can test it)
- Standard for open source forensic tools
- Test harness demonstrates quality (F1=1.00)

### Why These Features Are Proprietary (Enterprise)

**Memory Forensics Suite:**
- **Core IP** - Years of DFIR expertise encoded in detection logic
- **High value** - Memory analysis is advanced, time-intensive, requires deep skills
- **Competitive moat** - Few tools do this well, our algorithms are differentiated

**Advanced Correlation Engine:**
- **Sophisticated logic** - Multi-artifact cross-validation with complex heuristics
- **Hard to replicate** - Requires deep forensic knowledge + engineering
- **Differentiator** - Community tools rarely have this level of correlation

**Web UI + Team Features:**
- **Enterprise necessity** - Organizations need collaboration, not just solo CLI
- **Development cost** - Significant engineering investment (React/Vue, backend API)
- **Support burden** - UI requires ongoing UX improvements, bug fixes

**Integrations (SIEM, SSO, Ticketing):**
- **Enterprise-specific** - Individuals don't need SIEM integration
- **Maintenance overhead** - Each integration requires testing, versioning, support
- **Vendor relationships** - Some require commercial agreements

**Automated Playbooks:**
- **Operational value** - Organizations want workflows, not one-off analysis
- **Complex to build** - Requires workflow engine, state management, error handling
- **Training data** - Playbooks encode institutional knowledge (valuable IP)

**Cloud & Scale:**
- **Infrastructure cost** - Distributed workers, cloud storage, high availability
- **Enterprise requirement** - Individuals analyze locally, enterprises need cloud scale
- **Operational complexity** - Deployment, monitoring, scaling require enterprise features

---

## Pricing Strategy

### Community Edition
- **Price:** Free Forever
- **Licensing:** MIT (permissive open source)
- **Support:** Community-driven (GitHub Issues, Discussions, Stack Overflow)
- **Updates:** Open source development cadence (monthly releases)

### Enterprise Edition
- **Price:** Custom (based on organization size, use case, support level)
- **Licensing:** Proprietary (per-seat or per-case pricing models)
- **Support:** SLA-backed priority support (email, chat, phone)
- **Updates:** Quarterly major releases + critical patches as needed

**Pricing Considerations:**
- Small organizations (1-10 analysts): Lower tier pricing
- Medium organizations (11-50 analysts): Mid-tier pricing
- Large enterprises (50+ analysts): Volume pricing + custom features
- Government/Law Enforcement: Special pricing + compliance features
- MSSPs: Per-customer pricing model (multi-tenant licensing)

---

## Competitive Positioning

### vs. Open Source Tools (Volatility, Autopsy, Plaso)
- **Community Edition:** Comparable feature set, adds autonomous execution + self-correction
- **Enterprise Edition:** Adds team collaboration, integrations, automation that open source lacks

### vs. Commercial DFIR Platforms (EnCase, FTK, X-Ways)
- **Community Edition:** Free alternative for individual analysts, basic investigations
- **Enterprise Edition:** Modern architecture (cloud-native, API-first), AI-powered automation

### vs. SOAR Platforms (Splunk Phantom, Palo Alto Cortex XSOAR)
- **Community Edition:** DFIR-specific (not general SOAR), deep forensic analysis
- **Enterprise Edition:** Combines DFIR depth with SOAR automation (playbooks, integrations)

---

## Open Source Strategy

### What We Gain from Open Source:
1. **Competition credibility** - Judges can evaluate real code, not slides
2. **Community adoption** - Individual analysts use it, become enterprise advocates
3. **Contributions** - Community adds parsers, detectors, test scenarios
4. **Talent pipeline** - Contributors become potential hires or partners
5. **Market validation** - Usage metrics prove demand before enterprise investment

### What We Protect:
1. **Core IP** - Memory forensics algorithms, advanced correlation logic
2. **Enterprise features** - Web UI, team collaboration, integrations
3. **Business model** - Clear upgrade path from free to paid
4. **Customer relationships** - Enterprise customers, training materials, playbooks

### Risk Mitigation:
- **Forking risk:** Accepted (MIT license allows it), but enterprise features aren't available
- **Competitors copying:** Core concepts are publishable (self-correction), implementation quality and enterprise features differentiate
- **Free riders:** Expected (community edition is generous), conversion to enterprise is key
- **Support burden:** Community self-support (GitHub), enterprise gets priority support

---

## Upgrade Path (Community → Enterprise)

**Triggers for Upgrade:**
1. **Team growth** - When 2+ analysts need to collaborate
2. **Scale requirements** - When analyzing dozens of cases concurrently
3. **Integration needs** - When SIEM/ticketing integration is required
4. **Compliance** - When audit trails, RBAC, and SOC 2 compliance are needed
5. **Advanced threats** - When memory forensics and behavioral analysis are necessary
6. **Support SLA** - When 4-hour response time is critical

**Smooth Migration:**
- Community and Enterprise share same core (backward compatible)
- Cases created in Community can be imported to Enterprise
- Audit logs are compatible (same format)
- Custom detectors written for Community work in Enterprise

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2024-04-24 | Two tiers only (not three) | Simpler positioning, clearer value prop |
| 2024-04-24 | Memory forensics in Enterprise | Core IP, high value, competitive moat |
| 2024-04-24 | Self-correction in Community | Key innovation for competition, builds trust |
| 2024-04-24 | 5 basic detectors in Community | Demonstrates capability, not core IP |
| 2024-04-24 | MIT license for Community | Permissive license encourages adoption |
| 2024-04-24 | Custom pricing for Enterprise | Flexibility for different org sizes/use cases |

---

## Questions & Answers

**Q: Why give away the self-correction engine for free?**
A: It's our key innovation for the competition. Publishing it builds credibility and trust. The real value is in advanced detectors + enterprise features.

**Q: What if a competitor builds a commercial product on our Community Edition?**
A: That's allowed (MIT license). Our advantage is advanced detectors, ongoing innovation, support, and enterprise features.

**Q: Can Community users contribute advanced detectors?**
A: Yes, and we'll evaluate if they belong in Community or Enterprise tier. If Enterprise-level, we'll offer the contributor compensation or recognition.

**Q: How do we prevent Community users from just hacking together their own "enterprise" features?**
A: We can't (and shouldn't try). The value of Enterprise is polish, support, integrations, and ongoing innovation. DIY solutions have hidden costs.

**Q: What if Community Edition becomes "good enough" and nobody upgrades?**
A: Then we've created a valuable open source tool that helps the DFIR community. But realistically, organizations need team features, integrations, and support.

**Q: How do we handle security vulnerabilities in Community code?**
A: Fix in Community first (public disclosure after fix), then sync to Enterprise. Responsible disclosure policy in SECURITY.md.

---

**Document Owner:** Core Team
**Approved By:** [To be signed after team review]
**Next Review:** After competition submission (June 2024)
