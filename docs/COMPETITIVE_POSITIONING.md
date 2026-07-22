# Competitive Positioning - 4n6 Nexus vs. the FIND EVIL! field

> An HONEST, empirical placement of 4n6 Nexus against the strongest of the 118
> SANS FIND EVIL! submissions. Produced by cloning 12 top competitors' repos and
> scoring each 0-5 on ten shared dimensions, then placing us against them with no
> home-team bias. Raw data: `analysis/gallery_mining/competitor_assessments.json`
> and `positioning.md`. Companion to `COMPETITIVE_ANALYSIS.md` (which covers the
> whole field) and `IDEAS.md` (the backlog).

**Note on timing:** this was scored *before* the integrity crypto was wired into
the live orchestrator. That wiring has since landed (finding receipts + verdict
clamp + audit-chain verification now run on every investigation), and a
deterministic adversarial-verification tier has been added - so the receipts and
verification scores below are already improving. See `IDEAS.md` / epic SFE-lbxn.

---

# 4n6 Nexus — Honest Competitive Positioning (FIND EVIL! field)

Scored "as it actually runs today." Where our integrity/defense work is built + tested but only partly wired into the live orchestrator, the score reflects the live state, not the code that exists.

## 1. per_dimension

| # | Dimension | 4n6 self-score | Field best (holder) | Verdict |
|---|-----------|:--:|:--:|---|
| 1 | **Guardrails** | **4** | 5 — Polly C. DeNile, Council-SIFT | **Competitive.** Arg allowlist deny-by-default + evidence-path containment + circuit breaker is strong and fully wired. Behind the 5s only on kernel sandboxing (Polly's Bubblewrap) and empirically-verified bypass batteries (Council-SIFT ran 52/52 destructive-refused). We have path containment VERDICT (4) deliberately omits. |
| 2 | **Integrity** | **3** | 5 — Stigmergy, VERDICT | **Competitive-to-behind.** Hash-chain + stdlib offline verifier is real and on par with the 4-cluster (Agentic-DART, Ojuri, GLASSBOX) — but it's just-added/not-fully-wired, and lacks Merkle tree, signing, and transparency-log anchoring. Stigmergy/VERDICT ship Merkle + Ed25519 + Sigstore/Rekor. |
| 3 | **Receipts** | **2** | 5 — OATH MCP, Stigmergy, VERDICT | **Behind.** The HMAC-SHA256 finding→image_sha256 binding is a good primitive, but it is explicitly *not wired into live orchestrator output*, so today's runs ship findings without receipts. Even wired, HMAC needs a shared secret; OATH/Stigmergy/VERDICT do publicly-verifiable Ed25519. ClaimGuard (weaker overall) beat us purely by wiring the last mile. |
| 4 | **Verification** | **3** | 5 — VERDICT, GLASSBOX, Council-SIFT | **Behind.** Cross-artifact contradiction + Event Log tiebreaker + confidence is genuine but single-engine. No adversarial rival-model, no deterministic entailment/re-derivation, no debate. GLASSBOX (4-skeptic panel + grounding gate + ABHAVA), Council-SIFT (council + 3-lens LLM panel), VERDICT (LLM-free entailment + replay) are a full tier above. |
| 5 | **Correlation** | **2** | 5 — neo-finds-evil (Neo4j, ~359k nodes) | **Behind.** Contradiction detection is a narrow correlation form. No graph, no SQL. neo ships cross-host graph hunts; Agentic-DART and TLVB ship DuckDB SQL correlation; VERDICT sits at 4. This is one of our named gaps and it shows. |
| 6 | **Detection breadth** | **4** | 5 — VERDICT | **Competitive / near-top.** Native MFT/Prefetch/EVTX+EVT/Registry/LNK/PCAP/PST/browser parsers + ~13 detectors + YARA + Volatility + NSRL carving is genuinely top-tier. Only VERDICT (5, adds Sigma-via-Hayabusa + SRUM/BITS/WMI/Linux) clearly beats us. Our gap: no Sigma/Chainsaw corpus, MITRE only ~20-30%. |
| 7 | **Benchmark** | **2** | 5 — VERDICT, Council-SIFT | **Behind.** F1=1.00 on 23 self-authored synthetic scenarios is recall/precision on our own ground truth — not an external benchmark and not a hallucination/abstention scorer. VERDICT (blind held-out overclaim set + byte-flip tamper test), Council-SIFT (independent-LLM-attacker corpus, Council OFF/ON ablation, named FP/FN), GLASSBOX/MR Robot all measure fabrication. We measure recall only. |
| 8 | **Multi-agent** | **4** | 4 — Stigmergy, Ojuri, GLASSBOX (nobody hit 5) | **Ahead / tied-for-lead.** Lead orchestrator + triage + 3 domain analysts (disk/memory/network) + verifier, dual-path (Claude subagents OR standalone Python) is the most differentiated topology described. VERDICT's "Pool A/B" is deterministic reframing (they scored 3); OATH/Polly/neo/ClaimGuard/Agentic-DART are single-agent. This is a genuine edge. |
| 9 | **Productionization** | **4** | 5 — VERDICT, Polly C. DeNile | **Competitive.** Rust UI + CLI + TUI + 1708 tests + CI (black+pytest, core+forensic checks) + report/mermaid is solid. Behind VERDICT (15-workflow layered CI, SBOM, microVM, docs site) and Polly (3197 tests, auth gateway, browser Examiner Portal). |
| 10 | **Injection defense** | **4** | 5 — VERDICT | **Competitive / near-top.** sanitize+sentinel-wrap, unicode-masquerade + scene-staging detectors, credential redaction, cognitive-bias meta-verifier, guardrail-bypass suite is among the broadest in the field. Only VERDICT (5, Rust BIDI/Trojan-Source stripping + injection ledger + self-attack corpus) clearly beats us; MR Robot (4) matches. Most of the field scored 0-3. |

## 2. overall_standing

**Realistic placement: top 10, borderline top 8 — not top 5.** On a crude sum of the 10 dimensions, 4n6 lands around 32/50, clustered with Polly C. DeNile (~32) and Agentic-DART (~32), clearly behind VERDICT (~46, the field's benchmark-setter with 5s in integrity/receipts/verification/detection/benchmark/productionization/injection), and behind the strong second tier of Council-SIFT (~37), Stigmergy (~37), and GLASSBOX (~36). We sit ahead of TLVB, MR Robot, OATH, Ojuri, neo-finds-evil, and ClaimGuard. In a field of 118 that puts us safely in the top ~10-15 and plausibly top 8-10, because most of the 118 will not have shipped genuine multi-agent orchestration, a working injection-defense module, and native forensic parser breadth all at once — that combination is our moat. What keeps us out of the top 5 is concrete and consistent: **single-engine verification** (the top 4 all ship adversarial or deterministic-entailment verification), **no hallucination/abstention benchmark** (we have F1 on our own scenarios, which the leaders would call a by-construction number), **no cross-host/SQL correlation**, and an **integrity/receipts wiring gap** — the crypto is built and tested but doesn't reach live orchestrator output, so today it doesn't count. Closing the verification + benchmark gaps alone would move us into direct contention with GLASSBOX/Stigmergy/Council-SIFT for the 2nd-4th slots.

## 3. our_genuine_edges (verified against the assessments)

1. **Multi-agent orchestration** — the most differentiated topology in the set (5 distinct roles + dual execution path). VERDICT's rival "Pool A/B" is deterministic reframing on one model; OATH, Polly, neo, ClaimGuard, Ojuri's core, and Agentic-DART are single-agent. We are tied for the field ceiling (4) and arguably above it.
2. **Injection defense breadth** — active sanitize+sentinel-wrap + unicode-masquerade + scene-staging detectors + credential redaction + bias meta-verifier. Only VERDICT clearly beats it; MR Robot matches. neo (0), OATH (1 — "firewall" is comment-only vaporware), GLASSBOX/Ojuri/Agentic-DART/TLVB/ClaimGuard (2) all trail.
3. **Native forensic parser + detector depth** — MFT/Prefetch/EVTX+EVT/Registry/LNK/PCAP/PST/browser/image parsers + YARA + Volatility + carving, all in-engine. Council-SIFT, Stigmergy, MR Robot, OATH, and neo lean on external SIFT tool shims or a single artifact type; ClaimGuard has one parser.
4. **Guardrail path-containment** — evidence-path canonicalization/containment at the arg boundary. VERDICT (a 4-guardrail competitor) *deliberately ships no path jail*; OATH passes raw `Path(arguments[...])`; Ojuri only substring-checks `..`. Ours is a real, distinguishing containment layer.
5. **Dual-path deployment** (Claude Code subagents OR standalone Python) — most competitors are single-runtime; only a few decouple the orchestrator from one client.

## 4. where_we_are_behind

- **Verification (we: 3):** GLASSBOX, Council-SIFT, and VERDICT (all 5) ship working adversarial panels / deterministic entailment / replay re-derivation; MR Robot ships a heterogeneous second-model falsifier (4). We remain single-engine self-correction — adversarial rival-model is still in progress.
- **Benchmark (we: 2):** VERDICT and Council-SIFT (both 5) ship blind, held-out, non-circular hallucination/abstention scorers with named FP/FN and OFF/ON ablations; GLASSBOX and MR Robot (4) score fabrication and external benchmarks. We have F1 on our own fixtures and no decoy/abstention scorer.
- **Correlation (we: 2):** neo-finds-evil (5) ships a populated Neo4j cross-host graph; Agentic-DART, TLVB, and VERDICT (4) ship DuckDB SQL correlation. We have neither graph nor SQL.
- **Receipts + integrity crypto (we: 2 / 3):** OATH, Stigmergy, VERDICT (all 5 receipts) ship publicly-verifiable Ed25519 + Merkle + transparency-log anchoring; ours is HMAC-only and, critically, *not wired into live output* — ClaimGuard (a much weaker entry) still beats us here purely by having crossed the wiring last mile, and Polly's HMAC is wired into its shipping approval/report path.
- **Rule corpora / MITRE (feeds detection + correlation):** VERDICT, TLVB, Polly, Agentic-DART all ship Sigma (and often Chainsaw/Hayabusa + fuller MITRE); we have YARA but no Sigma/Chainsaw and only ~20-30% MITRE mapping.

## 5. highest_leverage_moves (ranked)

1. **Wire the already-built integrity chain + finding receipts + verdict_guard into live orchestrator output.** Highest ROI because the engineering is done and tested — it's the last mile that converts "built" into "counted." This alone lifts integrity 3→4 and receipts 2→3+. **Bar proven by:** ClaimGuard (weaker overall, but its signature gate *is* the report generator) and Polly C. DeNile (HMAC approval wired into the shipping report path).
2. **Ship a hallucination/abstention/decoy benchmark with a blind held-out fabrication set and an OFF/ON ablation.** Directly attacks our weakest scored dimension (benchmark 2) and reframes our F1 as more than a by-construction number. **Bar proven by:** VERDICT (blind held-out overclaim set + detector-hash anti-overfit + byte-flip tamper test), Council-SIFT (independent-LLM-attacker corpus, named FP/FN, Council OFF/ON), GLASSBOX (explicit hallucination_rate).
3. **Add a verification tier beyond single-engine — either a deterministic LLM-free entailment/re-derivation gate or an adversarial rival-model check.** This is the single biggest thing separating us from the top 4. Entailment is likely cheaper to ship first (deterministic, no second model cost). **Bar proven by:** VERDICT (LLM-free entailment + replay), GLASSBOX (grounding gate + 4-skeptic panel), Council-SIFT (deterministic council + 3-lens skeptic panel), MR Robot (heterogeneous falsifier loop).
4. **Build a cross-artifact correlation engine — DuckDB SQL first, graph later.** Moves correlation 2→4 and materializes cross-host findings our per-artifact detectors can't express. DuckDB is the pragmatic entry; Neo4j is the stretch. **Bar proven by:** Agentic-DART and TLVB (DuckDB SQL with contradiction surfacing), neo-finds-evil (Neo4j cross-host graph hunts).
5. **Integrate a Sigma/Chainsaw rule corpus (via Hayabusa) and finish MITRE mapping; upgrade receipts HMAC→Ed25519.** Lifts detection 4→5-adjacent, feeds correlation/MITRE coverage, and makes receipts publicly verifiable offline without a shared secret. **Bar proven by:** VERDICT and TLVB (Sigma-via-Hayabusa + fuller MITRE), OATH/Stigmergy/VERDICT (Ed25519 publicly-verifiable receipts).

Bottom line for the team: we are a strong top-10 entry carried by multi-agent orchestration, injection defense, and native forensic breadth. We are not top-5 today, and the reasons are unambiguous — verification depth, an abstention benchmark, real correlation, and finishing the crypto wiring. Moves 1-3 are the ones that would actually change our rank.

---

## Appendix: per-competitor dimension scores (0-5)

Score = what the cloned repo actually contains, judged harshly. Higher is stronger.

| Competitor | guard | integ | recpt | verif | corr | detect | bench | multi | prod | inject | total |
|---|---|---|---|---|---|---|---|---|---|---|---|
| VERDICT (verdict-dfir) | 4 | 5 | 5 | 5 | 4 | 5 | 5 | 3 | 5 | 5 | **46** |
| Stigmergy (Shaugato/find-evil) | 3 | 5 | 5 | 4 | 3 | 3 | 3 | 4 | 4 | 3 | **37** |
| Council-SIFT | 5 | 4 | 4 | 5 | 3 | 2 | 5 | 3 | 3 | 3 | **37** |
| GLASSBOX (glassbox-dfir) | 4 | 4 | 3 | 5 | 3 | 3 | 4 | 4 | 4 | 2 | **36** |
| Polly C. DeNile (jlgore/sift-mcp -> AppliedIR/Valhuntir SIFT MCP) | 5 | 3 | 4 | 3 | 3 | 4 | 1 | 1 | 5 | 3 | **32** |
| Agentic-DART | 4 | 4 | 2 | 3 | 4 | 4 | 3 | 2 | 4 | 2 | **32** |
| TLVB (Timeline Longa, Vita Brevis) | 4 | 1 | 1 | 4 | 4 | 4 | 3 | 3 | 4 | 2 | **30** |
| MR. Robot Adversarial | 3 | 2 | 1 | 4 | 2 | 3 | 4 | 3 | 3 | 4 | **29** |
| OATH MCP | 2 | 4 | 5 | 4 | 2 | 3 | 3 | 1 | 3 | 1 | **28** |
| Ojuri | 3 | 4 | 1 | 3 | 3 | 2 | 1 | 4 | 3 | 2 | **26** |
| neo-finds-evil | 4 | 1 | 0 | 2 | 5 | 3 | 3 | 1 | 3 | 0 | **22** |
| ClaimGuard | 2 | 2 | 3 | 3 | 1 | 1 | 1 | 1 | 2 | 2 | **18** |

Dimension keys: guard=guardrails, integ=integrity, recpt=receipts, verif=verification,
corr=correlation, detect=detection breadth, bench=benchmark, multi=multi-agent,
prod=productionization, inject=injection defense. 4n6 Nexus self-scores (as-run,
pre-wiring): guard 4, integ 3, recpt 2, verif 3, corr 2, detect 4, bench 2, multi 4,
prod 4, inject 4 = **32** - a strong top-10, with verification/benchmark/correlation
and the (now-closing) crypto-wiring gap as the path to top-5.
