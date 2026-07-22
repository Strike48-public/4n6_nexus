# Competitive Analysis - SANS FIND EVIL! Hackathon Field

> How the 118 FIND EVIL! submissions (all solving 4n6 Nexus's exact problem)
> approached autonomous DFIR, what the field converged on, where the strongest
> competitors out-reach us, and where we already lead. Derived from a 51-agent
> mining pass; see [`../IDEAS.md`](../IDEAS.md) for the actionable backlog and
> `analysis/gallery_mining/` for raw data. Complements the earlier
> `COMPETITION_COMPARISON.md`.

## The field's verdict: integrity beat detection

Across 118 entries to the same hackathon, the dominant design signal was not
*better detection* - it was **provable trust**. The recurring architecture is:
a read-only tool boundary, a tamper-evident (hash-chained) audit log, findings
that must cite a real logged tool call, cryptographic receipts re-derivable from
the evidence-image hash, and adversarial (not cooperative) verification. Teams
competed on *court-defensibility and anti-hallucination as architecture*, and
treated F1-style accuracy as a floor.

### Themes the field converged on

- The field has overwhelmingly converged on TRUST/INTEGRITY over detection: 20+ of 30+ strong competitors independently reinvented hash-chained tamper-evident audit logs, and 15+ built cryptographic finding receipts. Detection accuracy is table stakes; provable, court-defensible, re-derivable findings are the new battleground.
- Anti-hallucination is treated as an ARCHITECTURAL property, not a prompt: the dominant pattern is structural gating (a finding cannot ship / cannot reach CONFIRMED unless it resolves to a real logged tool call and its asserted values are literally re-extractable from raw bytes). The LLM narrates; deterministic code decides.
- Verification is moving from cooperative single-engine self-review to ADVERSARIAL: rival-model falsifiers from a different family, prosecutor/defense/judge debate, or deterministic skeptic panels - the shared insight being 'you cannot fix hallucination by self-review, only adversarially,' with the final verdict produced by a deterministic rule ladder rather than an LLM judge.
- Prompt-injection / hostile-log-as-data defense is now considered mandatory: sanitize+sentinel-wrap all evidence text at the tool-output boundary, plus cryptographic tripwire canaries, with the injection attempt itself surfaced as a finding.
- Benchmarking is shifting from 'did we find the evil' (recall/F1) to 'did we resist calling benign things evil and correctly abstain' - decoy FP-traps, negative-assertions, injected fabrication archetypes, and a published hallucination_rate as a distinct CI metric.
- Timestamp-truth is a recognized frontier: W32Time EID 35/260 offset recovery, NIST anchoring, and USN journal / $LogFile as independent ground truth against skewed or timestomped clocks.
- Cross-artifact correlation is being externalized into query engines (Neo4j/kuzu graphs or DuckDB SQL) that express questions no single-artifact detector can, with contradictions surfaced as UNRESOLVED rather than auto-resolved.
- Configuration-as-data is spreading: playbooks, case-type profiles, correlation rules, dedup rules, and Sigma rules all live as versioned/commit-pinned YAML so behavior and coverage change without code edits and remain auditable.
- Deterministic math is replacing heuristic confidence: Dempster-Shafer fusion with conflict-K, Shapley attribution, rank-clamp severity ceilings, and additive weak-signal scoring give defensible, explainable numbers.
- Honest degradation and 'proven negatives' (ABHAVA, completeness audits, coverage gaps) are emerging as differentiators - distinguishing 'we looked and it's genuinely absent' from 'we couldn't look' from silence.

## Where 4n6 Nexus already leads

- Custom read-only MCP server boundary with per-tool ARG allowlist (deny-by-default), evidence-path canonicalization/containment, and a circuit breaker - most competitors only prompt for read-only or rely on Claude's default tool-deny; few enforce a positive+negative arg-level surface. (We should add the bypass regression suite to PROVE it.)
- A genuinely multi-agent architecture (lead orchestrator + triage + 3 domain analysts + verifier) with a DUAL-path design (Claude Code subagents OR standalone Python orchestrator) - broader and more portable than most single-agent or fixed-pipeline competitors.
- Built-in contradiction detection across artifacts + Event Log tiebreaker resolution + confidence scoring - a self-correction substrate many competitors are only now bolting on; we can upgrade it in place rather than build from scratch.
- A mature 23-scenario synthetic-fixture harness at F1=1.00 covering breadth (clean, ransomware, timestomp, USB, scheduled-task, obfuscated-PowerShell, lateral, shadow-copy-deletion, credential-dumping, file-slack, AI-adversarial-evasion, distributed-spray) - a ready foundation to extend with decoy/hallucination scoring that most competitors lack.
- A Rust-based UI plus CLI + TUI - production-grade surfaces beyond the typical competitor's Python script or throwaway React demo.
- Integrated Volatility 3 runner + obfuscation detection, YARA scanner wrapper, PST/email + browser-history + image-content parsers, and NSRL-filtered carving - a wide, already-wired parser/detector portfolio that new correlation/graph/SQL layers can consume directly.
- Per-tool-output SHA-256 output_hash in an append-only audit log already exists - we are one dataclass change (prev_hash + full hash) away from the hash-chained tamper-evidence that competitors built from zero, so the highest-value industry-standard capability is unusually cheap for us specifically.

## Strongest competitors (by mined value-to-us score)

Score = novelty x portability x DFIR impact, judged *against our current
capabilities* (redundant-with-us ideas score low). Not a ranking of the
projects' overall quality - a ranking of how much they can teach *us*.

| Score | Project | Repo | What is worth taking |
|-------|---------|------|----------------------|
| 85 | neo-finds-evil (Warwick Cyber) | [link](https://github.com/NikVir/neo-finds-evil) | Graph correlation is a KNOWN GAP we lack; cross-host memory via Neo4j + Cypher is highly portable and high DFIR impact for multi-host intrusions |
| 85 | MR. Robot Adversarial | [link](https://github.com/Grizaceo/mr-robot-adversarial) | Heterogeneous adversarial falsifier directly addresses KNOWN GAP (adversarial rival-model verification); prompt-injection defense is KNOWN GAP; CyberSOCEval benchmark is KNOWN GAP; K8s/cloud patterns are KNOWN GAP; highest novelty score |
| 85 | OATH MCP | [link](https://github.com/GharsallahDev/oath-mcp) | Addresses THREE of our known gaps: (1) cryptographic receipts re-derivable from image SHA (ed25519 + BLAKE3), (2) hash-CHAINED audit (prev_hash linking), (3) benchmark harness with baseline comparison (DFIR-Metric). Verifier-gated execut... |
| 85 | Stigmergy | [link](https://github.com/Shaugato/find-evil) | Hash-chained ledger + Ed25519 signing + Rekor anchoring addresses our KNOWN GAP (cryptographic tamper-evidence + receipts); Dempster-Shafer fusion is novel math; prosecutor/defense/judge is adversarial council verification (another KNOWN... |
| 82 | VERDICT | [link](https://github.com/TimothyVang/verdict-dfir) | Adversarial ACH-based competing hypotheses + Merkle-rooted sigstore-signed audit + offline verifier tool + FRE 902(14) legal framing hit multiple known 4n6 Nexus gaps (hash-chain, cryptographic receipts, adversarial verification, legal s... |
| 82 | Polly C. DeNile | [link](https://github.com/jlgore/sift-mcp) | Most differentiated: K8s admission-controller pattern, OPA+eBPF architectural enforcement, Evidence Knowledge Graph with deterministic queries, Forensic Critic adversarial subagent, triple audit chain, PrepareToolCall/CompleteToolCall RP... |
| 78 | ClaimGuard | [link](https://github.com/michi883/claim-guard) | Cryptographic HMAC signing + architectural guardrail preventing unsigned claims + independent re-parsing are EXACTLY the gaps we suspected; high portability; strong DFIR impact (tamper-evident verdicts) |
| 78 | Agentic-DART | [link](https://github.com/Juwon1405/agentic-dart) | SHA-256-CHAINED audit (not just per-entry hashing) + adversarial bypass testing + DuckDB correlation + collector-adapter decoupling are all known 4n6 Nexus gaps; highly portable Python, strong MITRE coverage (108 techniques) |
| 78 | Ojuri | [link](https://github.com/Dextan-solutions/ojuri) | Hash-chained audit + standalone verifier + subprocess-isolated citation-only Auditor + disk-memory Correlator are all novel; high portability; addresses our known gaps (chain linking, adversarial verification, cross-artifact correlation) |
| 78 | VERDICT (qk578h) | [link](https://github.com/tejcodes-rex/verdict) | Hash-chained audit is a confirmed gap (high novelty + court-worthy DFIR impact). Falsifiable hypothesis framework + two-source corroboration are immediately portable verification patterns stronger than our current approach. Hallucination... |
| 78 | GLASSBOX | [link](https://github.com/ismailridwans/glassbox-dfir) | Hash-chained audit + adversarial red-team + ABHAVA negative-proving are all novel vs our capabilities; directly addresses our known gaps; high portability and DFIR impact |
| 76 | NTP Enrichment | [link](https://github.com/ciphentech/protocol-sift) | NIST NTP anchoring directly addresses our timestamp-truth gap; portable and high DFIR impact for timeline verification and timestomping detection |
| 75 | Sentinel Ensemble | [link](https://github.com/3sk1nt4n/Sentinel-Ensemble) | Multi-model ensemble is adversarial verification (KNOWN GAP); deterministic conductor + ternary validator is portable and high-impact for reducing false confidence |
| 75 | TLVB | [link](https://github.com/fkasasagi/tlvb) | Build-time compilation with zero-runtime-LLM signature tier is architecturally novel (cost-bounded, reproducible). DuckDB SQL layer enables ad-hoc queries we can't do. Sigma/Hayabusa is the exact gap we flagged. confirmed/inferred labeli... |
| 75 | SIFT-Bench | [link](https://github.com/aksoni/sift-bench) | Addresses our known gap (benchmark harness); adversarial calibration + pre-registered predictions are novel verification techniques; tool-attribution detection is clever guardrail validation |
| 75 | Council-SIFT | [link](https://github.com/Benn2231/council-sift) | Strong adversarial verification council (we lack multi-model debate), architectural evidence safety, reproducible no-key replay, and rigorous benchmark methodology |
| 75 | sift-kernel | [link](https://github.com/Sathvik-1007/sift-kernel) | Hash-chained audit + D-S conflict resolution + Active Inference tool selection are all gaps we identified; high portability (TypeScript/SQLite), strong DFIR impact |
| 72 | Mulder | [link](https://github.com/calebevans/mulder) | Adversarial Alternative Narrative phase with separate context + phase quality gates + Hayabusa/Sigma + evidence-ref validation are genuinely novel; high portability; strong DFIR impact (90% NIST detection) |
| 72 | Agentropix MCP | [link](https://github.com/galvangabriel-web/agentropix-mcp/tree/main) | Cryptographic examiner approval + courtroom HMAC seal + honest-negatives reporting are high-value differentiators for legal/enterprise DFIR; convergence fingerprint + 4,687-test drift gate show production maturity we lack |
| 72 | Aletheia Sentinel | [link](https://github.com/holeyfield33-art/aletheia-sentinel.git) | Hash-chained + HMAC-signed receipts are exactly the tamper-evident audit gap we have; prev_digest linking + verify command are directly portable |
| 72 | VIGIA Forensic Intentionality | [link](https://github.com/annatchijova/vigia-intent-analysis) | High novelty: prompt-injection defense (Kassandra), 4-hash bundles with attestation, intent-vs-artifact paradigm, and deterministic math pipeline all address known 4n6 Nexus gaps; moderately portable (Fraction/Decimal math, Peircean chec... |
| 72 | ChainsawMCP | [link](https://github.com/jasonmull/ChainsawMCP) | Chainsaw + Sigma rules integration is a KNOWN GAP we want (Sigma/Chainsaw event-log rules); practical IR consultant focus on fast triage; relatively simple MCP wrapper but addresses real need |
| 72 | Glass Box | [link](https://github.com/Unknown1502/Glassbox) | Hash-chained audit (ClaimChain) addresses our known gap. Cross-vendor tool re-derivation is genuine adversarial verification. PromptArmor injection defense is novel. Integrity certificates + canaries are strong. High portability and DFIR... |
| 72 | FindEvil Linux IR | [link](https://github.com/marlyocat/findevil) | Linux artifact depth (systemd/apt/webshell) fills our Windows-centric gap; audit-trail-grounded coverage assessment and hallucination harness are novel QA approaches we lack; high portability as Python/MCP pattern we already use |
| 72 | EvidenceLock SIFT | [link](https://github.com/OOYXLOO/evidencelock-sift) | Integrity manifest + verify-manifest command is a missing cryptographic integrity layer; verifier-first protocol with tool-call traceability is stronger than our contradiction detection; negative-control test suite is exactly the adversa... |

## Strategic implication

Our fastest path to 'top dog' is not more detectors - it is to **win the
integrity/verification battleground the field just defined, using assets we
already have**. We ship a read-only MCP arg-allowlist, a multi-agent verifier,
cross-artifact contradiction detection, per-output SHA-256 hashing, and an HMAC
signing pattern (in `approval/`). Chaining the audit log, minting finding
receipts, adding a deterministic entailment/provenance gate, and adversarial
verification are *upgrades to existing substrate*, not green-field builds - so
we can match or exceed the field's high-water mark cheaply, then keep our
detection and multi-agent breadth as durable edges. See `IDEAS.md` for the
prioritized plan.
