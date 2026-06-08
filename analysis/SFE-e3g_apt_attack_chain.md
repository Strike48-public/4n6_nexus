# SFE-e3g: SRL-2015 Cross-Host APT Attack-Chain Reconstruction

Date: 2026-06-07 (UTC)
Corpus: SANS SRL-2015 Compromised Enterprise Network (7 Windows hosts)
Method: pyewf + pytsk3 (no-mount) artifact extraction; MFTECmd, EvtxECmd,
python-registry parsing; cross-host authentication correlation via
analysis/apt_logon_graph.py. All evidence read-only.

This reconstructs the enterprise intrusion across hosts — the analysis a
single-host sweep cannot produce. Every claim cites the artifact it rests on;
counts come from the parsed Security logs (281,829 authentication events) and
the per-host sweeps (1.75M MFT entries, 69 Run-key values).

## Environment

Domain: SHIELDBASE.LAN (the "Stark Research Labs" SANS scenario). Hosts:
domain controller (DC), file server (FILE), two RD/Citrix servers (RD-01,
RD-02), two workstations (WKSTN-01, WKSTN-05), and an internet-facing DMZ FTP
server (DMZ-FTP). Subnets observed: 172.16.4.x (servers), 172.16.5.x (admin/
hunt), 172.16.6.x (RD), 172.16.7.x (workstations).

Tier-separated admin accounts (`-a` suffix) seen across the estate:
`cbarton-a`, `rsydow-a`, plus the `spsql` SQL service account and the
`administrator.shieldbase` domain admin (NTUSER profiles present on nearly
every host — see the SFE-e3g sweep report).

## Attack chain (evidence-ordered)

### 1. Initial access — brute force against the DMZ FTP server

DMZ-FTP carries **20,768 failed logons (4625)** — by far the corpus hot spot —
against only 1,037 successes. 20,574 of those failures are sourced from
DMZ-FTP itself (local credential hammering of the internet-facing host). The
failed-target list mixes internal accounts (`rsydow`, `nfury`) with external
`@stark-research-labs.com` probing (`administrator@`, `admin@`,
`nromanoff@`) — a credential attack against the perimeter host. This is the
initial-access foothold.

### 2. Credential attack on user accounts

Across the corpus the most-attacked user accounts are `rsydow` (3,850 fails),
`nfury` (3,850), `Ellie Phimister` (3,849), `rsydow-f` (3,849), `negasonic`
(3,849) — near-identical counts indicate an automated spray/brute-force list.
`rsydow` and `nfury` then appear as **successful** logons across multiple
hosts (below), consistent with eventual credential compromise.

### 3. Lateral movement — explicit-credential logons (4648)

6,566 explicit-credential logons (runas / pass-the-hash class), 2,572 to user
accounts. The standouts:

- **`tdungan@stark-research-labs.com` x1,750 on RD-01** — overwhelmingly the
  largest explicit-credential burst in the corpus; RD-01 is a primary operator
  pivot point.
- `spsql` (SQL service account) used with explicit credentials across DC,
  FILE, RD-01 (84 + 32 + 19...) — service-account abuse for lateral movement.
- `kellee.espinoza` x152 on RD-02, `mhill` x81 on WKSTN-01, `nfury` x38 on
  WKSTN-05 — per-host operator activity under compromised user identities.
- `rsydow-a` (admin tier) explicit-cred on the DC x40.

### 4. Privilege escalation / domain reach — admin pivot accounts

Cross-host account spread (4624 + 4648, machine/local-session principals
filtered out) shows the operator's pivot accounts:

- **`cbarton-a` -> 6 hosts** (DC, FILE, RD-01, RD-02, WKSTN-01, WKSTN-05)
- **`rsydow-a` -> 5 hosts** (DC, FILE, RD-01, RD-02, WKSTN-05)
- **`spsql` -> 5 hosts** (DC, FILE, RD-01, RD-02, WKSTN-05)
- `Administrator` (SHIELDBASE) -> 4 hosts incl. the DC

The `-a` admin-tier accounts reaching the DC plus five member hosts is the
domain-admin footprint — full enterprise compromise.

### 5. Interactive operator sessions — RDP (LogonType 10)

85 user RDP logons. Notable: `spsql` RDP into RD-01 x24 (a service account
should never RDP interactively — strong operator-using-service-creds signal),
`nfury` into WKSTN-05 x19, `rsydow`/`rsydow-a` into DMZ-FTP and the DC.

## Answers to the scenario investigation questions

- **Initial compromise vector:** brute-force credential attack against the
  internet-facing DMZ FTP server (20.7k failed logons), with external-domain
  account probing.
- **Persistence:** no malicious Run-key persistence found across the 7 hosts —
  the 8 initially-flagged Run keys were the legit OneDrive updater (6, fixed as
  the SFE-9rj false positive) and Dashlane autostart (2, benign). Operator
  persistence in this scenario is credential-based (valid accounts), not
  autostart-based — itself a finding.
- **Lateral movement:** explicit-credential (4648) runas / service-account
  abuse, concentrated on RD-01 (tdungan x1,750) and via `spsql`; RDP sessions
  for interactive control.
- **Privilege escalation / domain admin:** tier `-a` accounts (`cbarton-a`,
  `rsydow-a`) and `Administrator` authenticated to the DC plus 4-5 member
  hosts.
- **Fully compromised vs reconnaissance:** DMZ-FTP (entry), RD-01 (heaviest
  operator activity), DC, FILE, RD-02, WKSTN-01, WKSTN-05 all show successful
  pivot-account logons — estate-wide compromise.

## What the engine contributed vs. what is corroboration

- The MemoryDetector / RegistryDetector / timestomping passes (SFE-07g,
  SFE-e3g sweeps) established the **true negatives** (no timestomping, no
  malicious autostart) and surfaced the SFE-9rj OneDrive FP, hardening the
  engine on real enterprise data.
- The cross-host logon graph (this analysis) is the **net-new capability** the
  multi-host corpus unlocks; it is an analysis artifact, not yet an in-engine
  detector. A future ticket could promote the highest-signal heuristics
  (failed-logon spike, service-account RDP, admin-tier cross-host spread) into
  a LATERAL_MOVEMENT detector with synthetic fixtures + TDD.

## Reproduction

```
PYTHONPATH=. python3 analysis/sweep_driver.py <host.E01>      # MFT + Run keys
# Security.evtx extracted via the same pyewf+pytsk3 primitives, EvtxECmd to CSV
PYTHONPATH=. python3 analysis/apt_logon_graph.py             # cross-host graph
```

Full per-host event tallies and edge lists: analysis/SFE-e3g_logon_graph.md.
