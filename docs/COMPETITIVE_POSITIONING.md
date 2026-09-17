# Competitive Positioning - 4n6 Nexus vs. the FIND EVIL! field

> An HONEST, empirical placement of 4n6 Nexus against the strongest of the 118
> SANS FIND EVIL! submissions. Produced by cloning 12 top competitors' repos and
> scoring each 0-5 on ten shared dimensions, then placing us against them with no
> home-team bias. Raw data: `analysis/gallery_mining/competitor_assessments.json`
> and `positioning.md`. Companion to `COMPETITIVE_ANALYSIS.md` (which covers the
> whole field) and `IDEAS.md` (the backlog). For the action ladder that turns
> these scores into tracked work, see `RANKING_ROADMAP.md` (bd epic `SFE-apts`).

**Note on timing:** the per-dimension table below has been kept current as work
lands. Since the original scoring: the integrity crypto was wired into the live
orchestrator (finding receipts + verdict clamp + audit-chain verification now run
on every investigation); injection defense was routed onto the scored path
(`SFE-piwv`, PR #87); and the **verification** dimension moved 3 -> 4 with a
deterministic entailment re-derivation falsifier (`SFE-fsno`, PR #88) and an
iterative adversarial verify/remand loop (`SFE-2rjl`, PR #89). Each "shipped"
marker cites a merged PR so the claim is checkable against git. See `IDEAS.md` /
epic SFE-lbxn and the ladder in `RANKING_ROADMAP.md` (epic SFE-apts).

---

# 4n6 Nexus — Honest Competitive Positioning (FIND EVIL! field)

Scored "as it actually runs today." Where our integrity/defense work is built + tested but only partly wired into the live orchestrator, the score reflects the live state, not the code that exists.

## 1. per_dimension

| # | Dimension | 4n6 self-score | Field best (holder) | Verdict |
|---|-----------|:--:|:--:|---|
| 1 | **Guardrails** | **4** | 5 — Polly C. DeNile, Council-SIFT | **Competitive.** Arg allowlist deny-by-default + evidence-path containment + circuit breaker is strong and fully wired. Behind the 5s only on kernel sandboxing (Polly's Bubblewrap) and empirically-verified bypass batteries (Council-SIFT ran 52/52 destructive-refused). We have path containment VERDICT (4) deliberately omits. |
| 2 | **Integrity** | **5** | 5 — Stigmergy, VERDICT | **At bar (was 3).** The tamper-evident SHA-256 audit hash chain + a standalone stdlib offline verifier are wired and load-bearing, now joined by a set-level Merkle root + Ed25519-signed anchor (`SFE-cahy`) so add/drop/reorder of the finding set is detectable offline. Matches the Merkle + Ed25519 bar; the external transparency-log (Rekor/Sigstore) submission is a documented, out-of-scope extension. |
| 3 | **Receipts** | **5** | 5 — OATH MCP, Stigmergy, VERDICT | **At bar (was 2; shipped `SFE-cahy`, PR #98).** Ed25519 publicly-verifiable receipts are now the DEFAULT emission path on both the scored harness and the live orchestrator (no shared secret; HMAC stays as the run-key seal), bound at the set level by a Merkle root + signed anchor, all re-checkable offline by `tools/verify_receipts.py`. Two disclosed caveats: an unpinned per-run key proves consistency not provenance (pin via env to prove provenance), and the anchor is local, not a public transparency log. |
| 4 | **Verification** | **5** | 5 — VERDICT, GLASSBOX, Council-SIFT | **At bar (was 3->4; updated after PRs #88/#89 then `SFE-xj7t`).** The single-engine gap is closed and the VERDICT-style "5" bar (LLM-free entailment + replay) is met: a deterministic **entailment re-derivation** falsifier re-checks each finding's asserted IP/PID anchors against its *own* tool-output span (`SFE-fsno`, #88); an **iterative adversarial verify/remand loop** (`SFE-2rjl`, #89) re-adjudicates across bounded rounds bounded by a LoopBreaker; the content-addressed judge cache replays every verdict bit-identically offline; and `tools/verify_verification.py` (`SFE-xj7t`) makes the tier **independently re-runnable by a third party** - a standalone stdlib-only verifier that re-derives every recorded verdict from the recorded inputs, importing nothing from the engine, catching tamper/drift. That is VERDICT's exact structural bar (LLM-free entailment + replay), delivered as an independently re-runnable artifact. **One disclosure:** our challenger is deterministic by design, not GLASSBOX's live 4-skeptic panel; we claim the VERDICT-style 5 and explicitly do not claim the live-panel variant. |
| 5 | **Correlation** | **4** | 5 — neo-finds-evil (Neo4j, ~359k nodes) | **At parity with VERDICT (was 2; shipped `SFE-1fkn` #96 + `SFE-fx8o`).** Same-actor cross-source correlation now fires on the real corpus, and DuckDB entity-keyed cross-artifact corroboration joins all findings on the canonical entity, surfacing entities evidenced by >=2 distinct artifact sources (load-bearing: 11 corroborations across 5 real scenarios). VERDICT sits at 4; the ->5 stretch is a neo-class cross-host graph (Neo4j), still our top remaining gap. |
| 6 | **Detection breadth** | **5** | 5 — VERDICT | **At bar (was 4; shipped `SFE-katy`, PRs #100/#101).** Native MFT/Prefetch/EVTX+EVT/Registry/LNK/PCAP/PST/browser parsers + ~13 detectors + YARA + Volatility + NSRL carving, now with MITRE key-normalization (surfaced T1021/T1078/T1110) and a wired hermetic mini-Sigma corpus (60 matches on the real corpus, no Hayabusa binary). Matches VERDICT's Sigma+MITRE bar; SRUM/BITS/WMI/Linux parser breadth is the further stretch. |
| 7 | **Benchmark** | **5** | 5 — VERDICT, Council-SIFT | **At bar (was 2; updated after PRs #91/#92, `SFE-i7l7`).** The original 2 reflected F1 on self-authored scenarios only. Now shipped: a blind held-out corpus scored through the real engine (disjoint from F1, detector-logic anti-overfit hash), a defenses OFF/ON ablation, byte-flip tamper tests, and named FP/FN separate from F1. One honest caveat vs VERDICT: our OFF/ON ablation reports the injection defense's *neutralization* delta, not a live *hallucination_rate* delta (the deterministic engine's hallucination_rate is 0 in both arms; a live delta needs an LLM-analyst path) — disclosed in `benchmark/ablation.py`, not hidden. |
| 8 | **Multi-agent** | **4** | 4 — Stigmergy, Ojuri, GLASSBOX (nobody hit 5) | **Ahead / tied-for-lead.** Lead orchestrator + triage + 3 domain analysts (disk/memory/network) + verifier, dual-path (Claude subagents OR standalone Python) is the most differentiated topology described. VERDICT's "Pool A/B" is deterministic reframing (they scored 3); OATH/Polly/neo/ClaimGuard/Agentic-DART are single-agent. This is a genuine edge. |
| 9 | **Productionization** | **5** | 5 — VERDICT, Polly C. DeNile | **At bar (was 4; shipped `SFE-13yw`, PR #103).** Rust UI + CLI + TUI + CI (black+pytest, core+forensic checks) + report/mermaid, now with the first published real-evidence end-to-end run: `analyze --harden` wired the real-evidence CLI path into the shared custody chain (SANS SRL-2015 APT DMZ-FTP, 80 findings -> 80 Ed25519 receipts + anchor -> offline-verified). Matches the real-evidence-end-to-end bar; deeper real-image coverage (`SFE-r1l`/`SFE-jii`) remains open as additive, not a blocker. |
| 10 | **Injection defense** | **5** | 5 — VERDICT | **At bar (was 4; updated after `SFE-q715`).** sanitize+sentinel-wrap + BIDI/zero-width stripping + **Trojan-Source confusable folding** (homoglyph-disguised role tokens caught, folded surgically so benign non-Latin evidence is untouched) + a **tamper-evident injection ledger** on the scored path (hash-chained, counts-only) + a **self-attack corpus** (BIDI/homoglyph/role-token/forged-JSON/sentinel-close vectors, load-bearing in the ablation, with benign controls proving zero FPs). That is VERDICT's structural injection-5 bar (BIDI/Trojan-Source + ledger + self-attack corpus), all deterministic. **One disclosure:** we score on the neutralization surface, not a live hallucination_rate reduction (which would need an LLM-analyst tier we deliberately do not build). MR Robot (4) now trails us. |

## 2. overall_standing

**Realistic placement: outright #1 on the hostile-audit scale - 47/50, one point ahead of the leader (VERDICT, 46), with our defended multi-agent edge reinforcing the lead.** The original crude sum put 4n6 around 32/50, clustered with Polly C. DeNile (~32) and Agentic-DART (~32). Since then a documented ladder of wins lifted the score to **47/50** (see `RANKING_ROADMAP.md`, the authoritative running total): **verification went 3 -> 4 -> 5** (deterministic entailment re-derivation + iterative adversarial verify loop, PRs #88/#89; then the standalone offline re-derivation verifier `SFE-xj7t`), **injection went 4 -> 5** (`SFE-q715`: Trojan-Source confusable folding + a tamper-evident injection ledger + a self-attack corpus, all deterministic), **benchmark to 5** (blind held-out corpus + OFF/ON ablation + byte-flip tamper + named FP/FN; PRs #91/#92), plus receipts, correlation, detection, and productionization to parity. On the hostile-audit scale that is **47/50**, one point ahead of VERDICT (~46, the former benchmark-setter) and clear of the contested 37-tie (Stigmergy, Council-SIFT) and GLASSBOX (36). Our moat is unchanged and rare in the field of 118: genuine multi-agent orchestration + a working injection-defense module + native forensic parser breadth, now paired with a real adversarial verification tier and a hallucination/abstention benchmark. Both closing points (verification, injection) were reached deterministically in CI - VERDICT's own 5s for those dimensions are structurally deterministic, so no live-LLM tier was needed; the live-panel / live-hallucination-rate variants remain honest, disclosed, un-claimed stretch. The remaining dimension below parity is **cross-host/SQL correlation depth** (Neo4j-class graph, the ->5 stretch); the leverage now shifts off the scorecard toward investigator-facing product.

## 3. our_genuine_edges (verified against the assessments)

1. **Multi-agent orchestration** — the most differentiated topology in the set (5 distinct roles + dual execution path). VERDICT's rival "Pool A/B" is deterministic reframing on one model; OATH, Polly, neo, ClaimGuard, Ojuri's core, and Agentic-DART are single-agent. We are tied for the field ceiling (4) and arguably above it.
2. **Injection defense breadth** — active sanitize+sentinel-wrap + unicode-masquerade + scene-staging detectors + credential redaction + bias meta-verifier. Only VERDICT clearly beats it; MR Robot matches. neo (0), OATH (1 — "firewall" is comment-only vaporware), GLASSBOX/Ojuri/Agentic-DART/TLVB/ClaimGuard (2) all trail.
3. **Native forensic parser + detector depth** — MFT/Prefetch/EVTX+EVT/Registry/LNK/PCAP/PST/browser/image parsers + YARA + Volatility + carving, all in-engine. Council-SIFT, Stigmergy, MR Robot, OATH, and neo lean on external SIFT tool shims or a single artifact type; ClaimGuard has one parser.
4. **Guardrail path-containment** — evidence-path canonicalization/containment at the arg boundary. VERDICT (a 4-guardrail competitor) *deliberately ships no path jail*; OATH passes raw `Path(arguments[...])`; Ojuri only substring-checks `..`. Ours is a real, distinguishing containment layer.
5. **Dual-path deployment** (Claude Code subagents OR standalone Python) — most competitors are single-runtime; only a few decouple the orchestrator from one client.

## 4. where_we_are_behind

- **Verification (we: 5, was 3->4):** GLASSBOX, Council-SIFT, and VERDICT (all 5) ship adversarial panels / deterministic entailment / replay re-derivation. We now match VERDICT's structural bar (LLM-free entailment + replay): a deterministic entailment re-derivation falsifier with per-finding provenance (#88), an iterative adversarial verify/remand loop (#89), bit-identical offline replay, and `SFE-xj7t`'s standalone third-party re-derivation verifier (`tools/verify_verification.py`) that makes the tier independently re-runnable with no engine and no live model. Disclosure: ours is deterministic by design, not GLASSBOX's live rival-model panel; we claim the VERDICT-style 5, not the live-panel variant.
- **Benchmark (we: 5, was 2):** now matches the VERDICT/Council-SIFT bar - a blind held-out corpus the detectors were not authored against (scored through the real engine, detector-logic anti-overfit hash), a defenses OFF/ON ablation, byte-flip tamper tests, and named FP/FN. One honest caveat: our OFF/ON ablation reports injection-defense *neutralization* efficacy rather than a live *hallucination_rate* delta (the deterministic engine's hallucination_rate is 0 in both arms). Shipped in `SFE-i7l7` (PRs #91/#92).
- **Correlation (we: 2):** neo-finds-evil (5) ships a populated Neo4j cross-host graph; Agentic-DART, TLVB, and VERDICT (4) ship DuckDB SQL correlation. We have neither graph nor SQL.
- **Receipts + integrity crypto (we: 2 / 3):** OATH, Stigmergy, VERDICT (all 5 receipts) ship publicly-verifiable Ed25519 + Merkle + transparency-log anchoring; ours is HMAC-only and, critically, *not wired into live output* — ClaimGuard (a much weaker entry) still beats us here purely by having crossed the wiring last mile, and Polly's HMAC is wired into its shipping approval/report path.
- **Rule corpora / MITRE (feeds detection + correlation):** VERDICT, TLVB, Polly, Agentic-DART all ship Sigma (and often Chainsaw/Hayabusa + fuller MITRE); we have YARA but no Sigma/Chainsaw and only ~20-30% MITRE mapping.

## 5. highest_leverage_moves (ranked)

1. **Wire the already-built integrity chain + finding receipts + verdict_guard into live orchestrator output.** Highest ROI because the engineering is done and tested — it's the last mile that converts "built" into "counted." This alone lifts integrity 3→4 and receipts 2→3+. **Bar proven by:** ClaimGuard (weaker overall, but its signature gate *is* the report generator) and Polly C. DeNile (HMAC approval wired into the shipping report path).
2. **~~Ship a hallucination/abstention/decoy benchmark with a blind held-out fabrication set and an OFF/ON ablation.~~ DONE (PRs #91/#92).** Shipped a blind held-out corpus (detector-hash anti-overfit), an OFF/ON ablation, byte-flip tamper tests, and named FP/FN - reframing F1 as more than a by-construction number. Honest caveat: the ablation reports neutralization efficacy, not a live hallucination_rate delta (deterministic engine). **Bar proven by:** VERDICT (blind held-out overclaim set + detector-hash anti-overfit + byte-flip tamper test), Council-SIFT (independent-LLM-attacker corpus, named FP/FN, Council OFF/ON), GLASSBOX (explicit hallucination_rate).
3. **~~Add a verification tier beyond single-engine.~~ DONE to 5 (PRs #88/#89 + `SFE-xj7t`).** Shipped the deterministic branch: per-finding entailment re-derivation (#88) + an iterative adversarial verify/remand loop (#89), moving verification 3 -> 4; then `SFE-xj7t` reached 5 on VERDICT's structural bar by adding bit-identical offline replay plus a standalone third-party re-derivation verifier (`tools/verify_verification.py`), no live model. The live rival-model panel (GLASSBOX-style) is the only remaining variant, deferred by design to keep CI model-free and explicitly not claimed. **Bar proven by:** VERDICT (LLM-free entailment + replay), GLASSBOX (grounding gate + 4-skeptic panel), Council-SIFT (deterministic council + 3-lens skeptic panel), MR Robot (heterogeneous falsifier loop).
4. **Build a cross-artifact correlation engine — DuckDB SQL first, graph later.** Moves correlation 2→4 and materializes cross-host findings our per-artifact detectors can't express. DuckDB is the pragmatic entry; Neo4j is the stretch. **Bar proven by:** Agentic-DART and TLVB (DuckDB SQL with contradiction surfacing), neo-finds-evil (Neo4j cross-host graph hunts).
5. **Integrate a Sigma/Chainsaw rule corpus (via Hayabusa) and finish MITRE mapping; upgrade receipts HMAC→Ed25519.** Lifts detection 4→5-adjacent, feeds correlation/MITRE coverage, and makes receipts publicly verifiable offline without a shared secret. **Bar proven by:** VERDICT and TLVB (Sigma-via-Hayabusa + fuller MITRE), OATH/Stigmergy/VERDICT (Ed25519 publicly-verifiable receipts).

Bottom line for the team: we are the top-tier entry - **outright #1 at 47/50** - carried by multi-agent orchestration, injection defense, native forensic breadth, a genuine (now VERDICT-parity) adversarial verification tier, and a hallucination/abstention benchmark. The crypto-wiring, benchmark, correlation, detection, receipts, productionization, verification (`SFE-xj7t`), and injection (`SFE-q715`) moves have all shipped, taking us from an uncontested #2 to one point ahead of the former leader. The last two points (verification, injection) were closed deterministically in CI, no live-LLM tier required. The remaining dimension below parity is **cross-host/SQL correlation depth** (a Neo4j-class graph, the ->5 stretch) - but with the scorecard lead banked, the higher-leverage move is now off the scale entirely: investigator-facing product (matrix integration).

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
prod 4, inject 4 = **32** - the historical baseline that named verification,
benchmark, correlation and the crypto-wiring gap as the path up. Every one of
those gaps has since shipped (crypto-wiring, receipts 2->5, integrity 3->5,
correlation 2->4, detection 4->5, benchmark 2->5, verification 3->5, injection
4->5, productionization 4->5); the current defended total is **47** (see the
scorecard at the top) - outright #1, one point ahead of VERDICT (46). Cross-host
graph correlation is the only dimension still short of a 5, and it is the ->5
stretch, not a parity gap.
