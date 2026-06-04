# FIND EVIL! — Requirements & Judging Criteria (Reconstructed Source of Truth)

> Provenance: Reconstructed verbatim from the PRIMARY source on 2026-06-04 via web fetch of
> https://findevil.devpost.com/ and https://findevil.devpost.com/rules
> The originally-designated file /home/workdir/artifacts/FIND_EVIL_REQUIREMENTS.md was missing
> from disk and /home/workdir is not writable, so this copy lives in ./analysis/.
> Treat this as the immutable baseline for this session. NOT legal advice — confirm against
> the live /rules page before final submission.

## Key Dates
- Submission Period: Apr 15, 2026 12:00 PM EDT – **Jun 15, 2026 11:45 PM EDT**
- Judging: Jun 19 – Jul 3, 2026
- Winners: ~Jul 8, 2026
- Sponsor/Administrator: SANS Institute

## What to Build
- A working app that "extends Protocol SIFT's autonomous incident response capability using an
  agentic framework as the primary execution engine."
- Preferred frameworks: **Claude Code and OpenClaw** (comparable agentic architectures permitted).
- Platform: must be built on **Linux terminal / SIFT Workstation**; run on/integrate with SANS SIFT
  using Claude Code or OpenClaw.
- Supported data types: disk images, memory captures, log files, network captures, remote endpoints via MCP.
- Novelty: "substantially new work created during the hackathon period." Pre-existing OSS + SIFT
  codebase allowed as foundation; the novel contribution must be documented.
- Goal constraint: "Your submission must improve how Protocol SIFT processes case data."

## Three Required Demonstrations (must be shown)
1. **Self-correction** — "the agent detects and resolves errors or inconsistencies in its own output
   without human intervention."
2. **Accuracy validation** — "all findings are traceable to specific artifacts, files, offsets, or log entries."
3. **Analytical reasoning** — "output is presented as a structured investigative narrative, not a raw execution log."

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

## Judging Criteria — Stage One then Stage Two
**Stage One:** pass/fail viability check (theme fit + required APIs/SDKs).

**Stage Two:** six **EQUALLY WEIGHTED** criteria:
1. **Autonomous Execution Quality (TIEBREAKER)** — "Does the agent reason about next steps, handle failures,
   and self-correct in real time?"
2. **IR Accuracy** — "Are findings correct? Hallucinations caught and flagged? Confirmed findings
   distinguished from inferences?"
3. **Breadth and Depth of Analysis** — "Depth on fewer types beats shallow coverage of many."
4. **Constraint Implementation** — "Are guardrails architectural or prompt-based?" Assessed on WHERE
   boundaries are enforced and "whether they were tested for bypass."
5. **Audit Trail Quality** — "Can judges trace any finding back to the specific tool execution that produced it?"
6. **Usability and Documentation** — "Can another practitioner deploy and build on this?"

## Architecture Approaches (named primary targets)
- Direct Agent Extension
- Custom MCP Server
- Multi-Agent Frameworks
- Alternative Agentic IDEs (for these, accuracy report "must document what happens when the model ignores
  read-only rules")

## Resources Provided
- SIFT Workstation: github.com/sans-dfir/sift
- Starter evidence datasets, practice MCP server endpoint, sample code on Protocol SIFT Slack at launch.

## Notable Gaps / Ambiguities (confirm via official channels)
- The /rules page did NOT explicitly mandate "evidence integrity / anti-spoliation" or "read-only
  enforcement" except for Alternative IDE submissions. The main landing page framed an evidence-integrity
  section in the Accuracy Report. Closest authoritative hooks: Accuracy validation (traceability),
  Audit Trail / Execution Logs, and Constraint Implementation (bypass-tested guardrails).
