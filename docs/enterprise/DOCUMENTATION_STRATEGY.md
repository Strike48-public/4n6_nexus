# Documentation Strategy - Community vs Enterprise

**Status:** Planned for post-hackathon execution
**Date:** 2026-04-26

---

## Current State (Hackathon)

**Repository:** sift_find_evil (Strike48-public/4n6_nexus)
**Documentation:** 73 markdown files in docs/
**README:** Comprehensive (29K, 902 lines) - hackathon-appropriate

**Structure:**
- Root README: Everything in one place for judges
- docs/: Detailed documentation organized by topic
- docs/START_HERE.md: Navigation guide with visual maps
- docs/enterprise/: Community/Enterprise split planning

---

## Future State (4n6nexus Community + Enterprise)

### Community Edition (Open Source, MPL-2.0)

**README.md:** Streamlined (5-10K)
- Brief overview (what it does, why it matters)
- Quick start (install, demo command)
- Link to docs/START_HERE.md for navigation
- Key links (Architecture, Examples, Contributing)

**Documentation:** docs/ directory (markdown files)
- Keep technical docs version-controlled with code
- Architecture, API reference, contributing guide
- Automatically deploy to GitHub Pages or similar

**GitHub Wiki:** User guides and tutorials
- Getting Started Guide
- Use Case Tutorials (ransomware detection, insider threat, etc.)
- Troubleshooting FAQ
- Integration guides (SIEM, workflow automation)
- Community-contributed examples

**Rationale:**
- Code-related docs stay with code (version-controlled)
- User-facing guides in Wiki (easier to update, community-editable)
- Streamlined README for first impression

### Enterprise Edition (Proprietary)

**README.md:** Minimal (2-3K)
- Brief overview
- Link to enterprise documentation portal
- Installation instructions
- Support contact

**Documentation Portal:** Internal wiki or documentation site
- Enterprise features deep-dives (self-correction, MCP integration)
- Deployment guides (Docker, Kubernetes, on-premise)
- SSO/SAML integration guides
- API documentation for enterprise endpoints
- Admin guides (user management, audit, compliance)
- Runbooks for common issues

**Customer Knowledge Base:** Separate from public wiki
- Customer-specific configurations
- Advanced troubleshooting
- Performance tuning guides
- Integration with enterprise tools (Splunk, ELK, etc.)

**Rationale:**
- Enterprise customers expect comprehensive internal docs
- Separate from public community docs
- Controlled access (customer portal)

---

## Migration Plan

### Phase 1: Streamline Community README (Post-Hackathon)

**Timeline:** 1-2 weeks after hackathon

**Tasks:**
1. Create streamlined README.md (5-10K)
   - Keep: Overview, accuracy metrics, quick start
   - Move: Detailed CLI reference → docs/CLI_USAGE.md
   - Move: Architecture diagram → keep link only
   - Move: Development guide → already in CONTRIBUTING.md
   
2. Enhance docs/START_HERE.md
   - Add "First Time Here?" section at top
   - Visual quickstart diagram
   - Persona-based navigation (already done)

3. Test navigation flow
   - New contributor: Can they find setup instructions?
   - User: Can they find CLI usage quickly?
   - Judge/evaluator: Can they assess project in 10 minutes?

**Validation:**
- External review: Ask 2-3 people unfamiliar with project to navigate
- Time test: Can they complete common tasks quickly?

### Phase 2: GitHub Wiki Setup (Community Launch)

**Timeline:** Concurrent with Community repo creation

**Wiki Structure:**
```
Home
├── Getting Started
│   ├── Installation
│   ├── First Analysis (5-minute tutorial)
│   └── Understanding Results
├── Use Cases
│   ├── Ransomware Detection
│   ├── Insider Threat Investigation
│   ├── Memory Forensics
│   └── Network Exfiltration
├── Integration Guides
│   ├── SIEM Integration (Splunk, ELK)
│   ├── Workflow Automation
│   └── CI/CD Integration
├── Troubleshooting
│   ├── Common Issues
│   ├── Performance Tuning
│   └── FAQ
└── Community
    ├── Contributing Examples
    ├── Sharing Playbooks
    └── Discussion Forums
```

**Migration:**
- Move user-facing guides from docs/ to Wiki
- Keep technical/API docs in docs/ (version-controlled)
- Add redirects in README for moved content

**Community Contribution:**
- Wiki is community-editable (with moderation)
- Encourage case study contributions
- Playbook submissions from practitioners

### Phase 3: Enterprise Documentation Portal (Enterprise Launch)

**Timeline:** Concurrent with Enterprise repo creation

**Portal Structure:**
```
Enterprise Documentation
├── Overview
│   ├── What's Different (Community vs Enterprise)
│   ├── Licensing & Support
│   └── Deployment Options
├── Installation & Setup
│   ├── Docker Deployment
│   ├── Kubernetes Deployment
│   ├── On-Premise Installation
│   └── SSO/SAML Configuration
├── Enterprise Features
│   ├── Self-Correction Engine (Deep Dive)
│   ├── MCP Integration
│   ├── Approval Workflows
│   └── Audit & Compliance
├── Administration
│   ├── User Management
│   ├── Role-Based Access Control
│   ├── Audit Log Management
│   └── Performance Monitoring
├── Integration
│   ├── Enterprise SIEM (Splunk, QRadar, etc.)
│   ├── Ticketing Systems (Jira, ServiceNow)
│   ├── Workflow Automation
│   └── API Reference
└── Support
    ├── Troubleshooting
    ├── Known Issues
    ├── Contact Support
    └── Release Notes
```

**Access Control:**
- Customer portal login required
- Per-customer customization options
- Support ticket integration

---

## Documentation Maintenance

### Community Edition

**Owned by:** Community + community maintainers
**Update frequency:** As needed (PRs accepted)
**Quality control:** PR review process, CI/CD checks

**Guidelines:**
- Technical docs (docs/): Version-controlled, follow semver
- Wiki: Community-editable with moderation
- README: Updated only for major changes

### Enterprise Edition

**Owned by:** community documentation team
**Update frequency:** With each release + hotfixes
**Quality control:** Internal review process

**Guidelines:**
- Portal docs: Updated with every enterprise release
- Customer-specific docs: On-demand
- Runbooks: Updated based on support tickets

---

## Metrics & Success Criteria

### Community Edition

**Documentation success metrics:**
- Time to first analysis: <10 minutes (from clone to demo)
- Contribution rate: >5 community PRs/month
- Wiki engagement: >100 page views/week
- Support questions: <30% are "where is the docs?"

### Enterprise Edition

**Documentation success metrics:**
- Customer onboarding time: <1 day (from license to first analysis)
- Support ticket deflection: >60% (resolved via docs)
- Customer satisfaction: >4.5/5 on documentation quality
- Feature adoption: >80% use at least one enterprise feature

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-26 | Keep comprehensive README for hackathon | Judges expect self-contained documentation |
| 2026-04-26 | Plan GitHub Wiki for community post-hackathon | Separate user guides from technical docs |
| 2026-04-26 | Plan enterprise documentation portal | Professional presentation for paying customers |

---

**Document Owner:** Jonathan Tomek (hackathon@example.com)
**Last Updated:** 2026-04-26
**Status:** Approved for post-hackathon execution
