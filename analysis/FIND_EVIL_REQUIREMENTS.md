# FIND EVIL! — Requirements & Judging Criteria (Complete Source of Truth)

> Provenance: Reconstructed verbatim from https://findevil.devpost.com/ on 2026-06-04
> Updated with full context from main page, requirements, and judging criteria
> Treat this as the immutable baseline for this session. NOT legal advice — confirm against
> the live Devpost page before final submission.

## Key Dates
- Submission Period: Apr 15, 2026 12:00 PM EDT – **Jun 15, 2026 11:45 PM EDT**
- Judging: Jun 19 – Jul 3, 2026
- Winners: ~Jul 8, 2026
- Sponsor/Administrator: SANS Institute

---

## The Speed Problem

An AI-powered adversary can go from initial access to full domain control in **under 8 minutes**. 
- **CrowdStrike's fastest observed breakout time:** 7 minutes
- **Horizon3's autonomous agent:** 60 seconds to full privilege escalation
- **MIT's 2024 research:** AI-driven attack workflows running **47 times faster** than human operators

Meanwhile, a human incident responder is still pulling up their toolkit.

**That gap is the most dangerous problem in cybersecurity. Find Evil! challenges you to close it.**

---

## The Mission

Build autonomous AI agents on the **SANS SIFT Workstation** — 200+ incident response tools on a single 
platform, 18 years of community development, 60K+ annual downloads. **Protocol SIFT** is the proof-of-concept 
framework that connects AI agents to those tools through Model Context Protocol (MCP).

**Protocol SIFT works. It also hallucinates more than we'd like.** (That's exactly why this hackathon exists.) 
Unlike offensive teams that operate with three or four people in secret, we're putting the entire practitioner 
community on this problem simultaneously.

**Your job:** Teach an AI agent to think like a senior analyst — how to sequence its approach, recognize when 
something doesn't add up, and self-correct when it gets it wrong.

---

## Who Should Join

You don't need to be an incident response expert. The SIFT Workstation handles the domain tooling. You need 
curiosity and building skills.

- **IR/Security professionals:** You've been finding evil manually for years. Build the AI partner you wish you 
  had at 3 AM during an active incident.
- **AI/ML engineers:** Apply your skills to a domain where speed determines whether attackers win. Real case 
  data, real tools, no toy datasets.
- **Students and early-career builders:** No IR background required. The SIFT Workstation is your on-ramp to 
  the most in-demand intersection in tech.
- **Open-source contributors:** Every submission lives on as a community tool. Build something thousands of 
  responders will use.

**Four supported architectural approaches:** Direct Agent Extension (Claude Code or OpenClaw), Custom MCP Server, 
Multi-Agent Frameworks (AutoGen, CrewAI, LangGraph), or Alternative Agentic IDEs (Cursor, Cline, Aider).

**Teams:** Up to 5. Solo permitted.  
**Duration:** April 15 – June 15, 2026  
**Prizes:** $22,000+

---

## About the Challenge

### Why this exists

In November 2025, Anthropic's security team published findings on **GTG-1002** — a Chinese state-sponsored 
operation where attackers used Claude Code to run autonomous reconnaissance, exploitation, and lateral movement 
at **80-90% autonomy**. The AI handled everything at request rates Anthropic described as **"physically impossible"** 
for human operators.

That was the offensive side. The **SIFT Workstation** is the defensive platform. **Protocol SIFT** demonstrated 
what's possible when you connect AI agents to that platform through MCP. This hackathon is how the community 
makes it real.

### The gap we're closing

Manual command-line incident response cannot compete with autonomous agents executing thousands of requests. 
Adversaries move at machine speed. Defenders still look up command-line flags during active incidents.

**Your goal:** Build AI systems on the SIFT Workstation that match that velocity — triaging, correlating, and 
reporting at the pace the threat demands.

---

## Get Started

1. **Register on Devpost** (you're here)
2. **Join the Protocol SIFT Slack** — questions get answered, teams form, mentors hang out
3. **Download the SIFT Workstation** from sans.org/tools/sift-workstation
4. **Install Protocol SIFT Package** to demonstrate automated analysis:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
   ```
5. **Review starter resources:** sample case data (hard drives, memory images), example submission
6. **Pick a problem and start building** (see "What to Build" for project ideas)

---

## What to Build

**One goal:** Make Protocol SIFT a fully autonomous incident response agent.

Your submission must **improve how Protocol SIFT processes case data** — any case data. Disk images, memory 
captures, remote endpoints via MCP, log files, network captures. The data type doesn't define the track. The 
quality of autonomous execution does.

**Teach the agent how a senior analyst thinks:** How they sequence their approach. How they recognize when 
something doesn't add up. How they adjust.

---

## Supported Architectural Approaches

You can build on any of these patterns. The platform matters less than how your architecture enforces evidence 
integrity and enables genuine self-correction.

### 1. Direct Agent Extension (Claude Code / OpenClaw)
Extend Protocol SIFT's existing agent loop. Better prompt engineering, smarter tool sequencing, self-correction 
routines, accuracy validation. This is the **on-ramp for most participants** and the fastest path to a working 
submission. OpenClaw's extensible architecture also makes it a natural fit for building custom MCP tool wrappers 
directly into the tool chain.

### 2. Custom MCP Server
Build a purpose-built MCP server that exposes structured functions instead of generic shell commands. Instead of 
giving the AI `execute_shell_cmd`, expose typed functions like `get_amcache()`, `extract_mft_timeline()`, 
`analyze_prefetch()`. The agent physically cannot run destructive commands because the server doesn't have those 
tools. The MCP server handles raw tool output natively and can parse it before returning to the LLM, preventing 
context window overload from massive text dumps. **(This is the most sound architecture in the evaluation. It's 
also the most work.)**

### 3. Multi-Agent Frameworks (AutoGen, CrewAI, LangGraph)
Decompose the analysis into specialized, communicating agents. One agent reviews memory artifacts, another parses 
disk timelines, a third synthesizes findings. No single model holds all raw data in its context window, which 
prevents context degradation on complex cases. Agent-to-agent communication is logged programmatically with 
timestamps and token usage, creating structured execution records. **Warning:** agent loops can get stuck in 
infinite conversational spirals without careful termination conditions. Build in max-iteration caps and graceful 
degradation.

### 4. Alternative Agentic IDEs (Cursor, Cline, Aider)
AI-native development environments with their own rule systems. Excellent UI/UX and built-in diff viewing, but 
designed for software development, not incident response. These tools rely on prompt adherence for evidence 
protection, not architectural enforcement. **If your submission uses an alternative IDE, your accuracy report 
must document what happens when the model ignores read-only rules.**

*(If another agentic framework can do the job, we won't disqualify it. But Claude Code, OpenClaw, and the four 
approaches above are the primary targets. Build for those.)*

---

## Starter Ideas (Not Prescriptions)

Two months is enough time to build something real, but the hardest part is always the first hour. These are 
starting points. The best submissions will go beyond these in directions we haven't considered.

1. **The Self-Correcting Triage Agent** — Build an agent that runs initial triage on a disk image, evaluates 
   its own output for logical consistency, identifies gaps in its analysis, and autonomously re-runs with 
   adjusted parameters. Success metric: fewer hallucinated findings than Protocol SIFT's current baseline.

2. **Multi-Source Correlation Engine** — Given a disk image and a memory capture from the same system, build 
   an agent that cross-references findings between the two sources and flags discrepancies. If the disk timeline 
   says one thing and memory says another, the agent should catch it.

3. **MCP-Connected Live Triage** — Build an MCP server that connects Protocol SIFT to a remote endpoint or SIEM, 
   then create an agent workflow that pulls live data, analyzes it against SIFT's tool library, and produces a 
   real-time triage report.

4. **The Analyst Training Loop** — Build an agent that not only analyzes case data but explains its reasoning 
   at each step — which tool it chose, why, what it expected to find, and what it actually found. Designed to 
   train junior analysts by making the agent's decision-making process transparent.

5. **Accuracy Benchmarking Framework** — Create a test harness that runs Protocol SIFT against known-good data 
   with documented ground truth, then scores accuracy, false positive rates, and hallucination frequency. The 
   community needs this benchmark to measure progress.

6. **The Purpose-Built MCP Server** — Wrap SIFT's 200+ tools as structured, type-safe functions exposed through 
   a custom MCP server. The agent physically cannot run destructive commands because the server doesn't expose 
   them. Success metric: zero evidence spoliation risk, with the same or better analytical output as the baseline 
   Protocol SIFT agent. **(This is the architecture that would make a practitioner comfortable standing behind 
   the results.)**

7. **The Persistent Learning Loop** — Build a self-correcting execution loop that iterates on a task until 
   verifiable success criteria are met. The agent logs failures to a progress file, learns from its own execution 
traces across iterations, and course-corrects without human intervention. Must include a hard `--max-iterations` 
   cap to prevent runaway execution. Success metric: demonstrable improvement in accuracy between first iteration 
   and final iteration on the same data, with full execution traces preserved.

*(These are meant to get past the blank-screen problem. The winning submission will almost certainly be something 
none of us predicted.)*

---

## The 8 Mandatory Submission Deliverables
> "All eight components required. Missing any one means elimination."

1. **Code Repository** — GitHub (public). Open-source license (MIT or Apache 2.0), detectable in the
   About section. All source, assets, dependencies. README with setup instructions. Functional and testable.

2. **Demo Video (5 min max)** — Screencast of LIVE terminal execution with audio narration. Not slides,
   not marketing. Show the agent against REAL evidence including **at least one self-correction sequence**.
   Public on YouTube/Vimeo/Youku. Judges not required to watch beyond 10 min.

3. **Architecture Diagram** — Clear visual showing how components connect: agent, SIFT tools, MCP servers,
   evidence sources, output pipeline. Identify which architectural pattern is used and document WHERE
   security boundaries are enforced. Prompt-based vs. architectural guardrails must be clearly distinguished.

4. **Written Project Description** — Devpost story: What it does, How you built it, Challenges, What you
   learned, What's next.

5. **Evidence Dataset Documentation** — What the agent was tested against, source of the data, and what it found.

6. **Accuracy Report** — Self-assessment of findings accuracy: false positives, missed artifacts,
   hallucinated claims identified during testing. "Honesty valued over perfection." (Plus evidence-integrity
   / spoliation testing per the main page's framing.)

7. **Try-It-Out Instructions** — Live deployment URL OR step-by-step instructions for judges to run locally
   against provided evidence; document tools/dependencies.

8. **Agent Execution Logs** — Structured logs showing the full agent communication + tool execution sequence
   with timestamps. Multi-agent: agent-to-agent message logs w/ timestamps. Single-agent: tool execution logs
   w/ timestamps and token usage. Persistent loop: iteration-over-iteration traces showing how the approach
   changed. REQUIREMENT: "Judges must be able to trace any finding back to the specific tool execution that
   produced it."

---

## Three Required Demonstrations (must be shown)
1. **Self-correction** — "the agent detects and resolves errors or inconsistencies in its own output
   without human intervention."
2. **Accuracy validation** — "all findings are traceable to specific artifacts, files, offsets, or log entries."
3. **Analytical reasoning** — "output is presented as a structured investigative narrative, not a raw execution log."

---

## Judging Criteria — Stage One then Stage Two
**Stage One:** pass/fail viability check (theme fit + required APIs/SDKs).

**Stage Two:** six **EQUALLY WEIGHTED** criteria:

### 1. Autonomous Execution Quality (TIEBREAKER)
Does the agent reason about next steps, handle failures, and self-correct in real time?

### 2. IR Accuracy
Are findings correct? Hallucinations caught and flagged? Confirmed findings distinguished from inferences?

### 3. Breadth and Depth of Analysis
Depth on fewer types beats shallow coverage of many.

### 4. Constraint Implementation
Are guardrails architectural or prompt-based? Assessed on WHERE boundaries are enforced and "whether they 
were tested for bypass."

### 5. Audit Trail Quality
Can judges trace any finding back to the specific tool execution that produced it?

### 6. Usability and Documentation
Can another practitioner deploy and build on this?

---

## Architecture Approaches (named primary targets)
- Direct Agent Extension
- Custom MCP Server
- Multi-Agent Frameworks
- Alternative Agentic IDEs (for these, accuracy report "must document what happens when the model ignores
  read-only rules")

---

## Resources Provided
- SIFT Workstation: github.com/sans-dfir/sift
- Starter evidence datasets, practice MCP server endpoint, sample code on Protocol SIFT Slack at launch.

---

## Notable Context Notes

- The /rules page did NOT explicitly mandate "evidence integrity / anti-spoliation" or "read-only
  enforcement" except for Alternative IDE submissions. The main landing page framed an evidence-integrity
  section in the Accuracy Report. Closest authoritative hooks: Accuracy validation (traceability),
  Audit Trail / Execution Logs, and Constraint Implementation (bypass-tested guardrails).

- **Prizes:** $22,000+ total (distribution not specified in source material)

- **GTG-1002 Context:** November 2025 Anthropic security team findings on Chinese state-sponsored operation
  using Claude Code at 80-90% autonomy, described as "physically impossible" request rates for human operators

- **Community Goal:** Make real-time defensive IR possible at the same speed adversaries now operate
