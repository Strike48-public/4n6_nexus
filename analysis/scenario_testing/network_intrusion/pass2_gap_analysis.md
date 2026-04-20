# network_intrusion - Pass 2 Gap Analysis

**Date**: 2026-04-20
**Scenario**: `scenarios/training/network_intrusion/`
**Evidence**: `Day 1 Capture [20-09].pcap` (1.2 GB, 2020-09-19 22:53 to 2020-09-20 02:01 UTC)
**Method**: Direct tshark extraction from the PCAP (no external answer key available on this workstation — `curl` to digitalcorpora.org is sandboxed, no WebFetch/WebSearch).

## Honesty Caveat

We could NOT retrieve the Digital Corpora published answer key. This pass
compares what tshark can surface against what the engine currently emits.
That is a circular measurement: if the tshark-derived "ground truth" is
incomplete, our gap list is also incomplete. Treat this as a lower bound
on detector gaps, not an upper bound.

## Engine output for this scenario

Zero findings. `PcapParser` is invoked manually in pass 1 but the detector
pipeline has no consumer for PCAP artifacts, and `MemoryParser` does not
exist. `scenario.yaml` `expected.finding_counts.total: 0` passes
tautologically.

## Ground truth derived from PCAP

### 1. Attacker-tooling installs over cleartext HTTP from 156.59.33.57

All via `apt` over port 80 (unencrypted):

| Time (UTC) | Tool |
|------------|------|
| 2020-09-19 23:07:30 | Metasploit framework repo InRelease + Packages.gz |
| 2020-09-19 23:07:36 | `metasploit-framework_6.0.8+20200919102448~1rapid7-1_amd64.deb` |
| 2020-09-19 23:13:27 | `john_1.8.0-2build1_amd64.deb` (John the Ripper password cracker) |
| 2020-09-19 23:13:27 | `john-data_1.8.0-2build1_all.deb` |

Source host: **156.59.33.57** (internal). Downloads.metasploit.com is the
vendor's own repo so the domain itself is not "evil" — what is evil is
that a user-segment workstation (not a security appliance) is pulling
offensive tools.

### 2. Beaconing-shaped access to null-byte.wonderhowto.com

From 156.59.33.57 to `null-byte.wonderhowto.com:443`, inter-CONNECT
intervals (seconds):

```
304.0, 300.3, 300.2, 300.2, 300.2, 300.2, 300.1, 600.2, 300.1, 300.1,
300.1, 300.1, 300.1, 300.1, 900.5, 300.1, 300.1 ...
```

That is **a 5-minute periodic heartbeat** with a few tab-idle multiples
(10min, 15min) — classic Firefox-reader-of-a-tutorial-page pattern, but
also structurally identical to a staged C2 beacon. An engine cannot tell
the two apart without page-content decryption. The periodicity itself is
the signal.

null-byte.wonderhowto.com is WonderHowTo's hacking tutorial vertical
(articles on password cracking, Metasploit usage, pentest walkthroughs).
Co-occurring with the Metasploit + John installs above, this is a
reasonable "operator is reading hacking tutorials while installing
hacking tools" signal.

### 3. Pastebin activity

- DNS: 30 queries for `pastebin.pl` (attacker typo or deliberate) and
  `pastebin.bl` from 156.59.33.57 and 156.59.33.65 around
  2020-09-20 00:46:14 UTC.
- Cleartext HTTP GET: `156.59.33.57 -> pastebin.com/` and
  `pastebin.com/favicon.ico` and
  `pastebin.com/squid-internal-static/icons/SN.png` visible in the POP3
  user-agent's proxy cache chatter (the last two are Squid-generated when
  the page fails to load - still evidence the host visited).

Pastebin is a standard exfiltration drop point for scripts and creds.

### 4. Top TCP byte volumes are NOT exfil (direction correction)

The pass-1 finding that 100 MB went "to 52.64.108.95:443" was
direction-inverted. SNI lookup shows:

| Flow | SNI | Direction |
|------|-----|-----------|
| 156.59.33.57:33274 <-> 52.64.108.95:443 | github.com | 100 MB **inbound** (download) |
| 156.59.33.180:38383 <-> 52.216.113.59:443 | github-production-release-asset-*.s3.amazonaws.com | 64 MB **inbound** |
| 156.59.33.57:33722 <-> 13.237.44.5:443 | github.com | 40 MB **inbound** |

Re-ranked internal->external by actual outbound bytes (>500 kB):

```
src                             dst                               out(MB)  in(MB)  ratio
156.59.33.180:38383             52.216.113.59:443 (github S3)        2.62   63.96  0.04
156.59.33.58:52700              173.194.28.105:443 (google)          2.13   94.37  0.02
156.59.33.57:33274              52.64.108.95:443  (github.com)       1.93  104.86  0.02
156.59.33.180:28179             44.226.54.40:443  (no SNI/DNS)       0.86    0.04  22.13
```

The only flow with an outbound-heavy ratio is `156.59.33.180 ->
44.226.54.40:443` (AWS us-west-2) — 860 kB out / 40 kB in. No SNI was
captured for it and no DNS query resolved to that IP in this PCAP, which
is itself suspicious (IP-literal TLS, no preceding DNS). Worth
investigating further; cannot confirm exfil without payload context.

### 5. Cleartext protocols on the wire

- rsyslog-over-TCP port 514: 7,768 frames (`156.59.33.44 -> 156.59.33.77`
  and others). Host syslogs including DHCP client events, GDM login
  events (e.g., user `mmiller` on `pits-miller` at 2020-09-20 10:53:24)
  are visible in plaintext.
- IMAP (port 143): 5,312 frames.
- NFS: 4,369 frames.
- POP3 (port 110): 253 frames.
- SMTP (port 25): 147 frames (no message bodies — likely just EHLO/STARTTLS).

Not attacker activity per se, but policy violations that belong in a
"cleartext-sensitive-protocol" detector output.

### 6. Internal network topology hints

- "pits-*" hostnames in the `soit.local` domain: `pits-miller`,
  `pits-logserv`, `pits-gatsby`, `pits-exsec`.
- Syslog from `pits-exsec` dhclient visible in plaintext.

Useful for timeline/asset inventory but not directly a finding.

## Gap summary (engine vs. ground truth above)

| # | Ground-truth signal | Detector the engine would need | Status |
|---|---------------------|--------------------------------|--------|
| 1 | Metasploit + John installs from user workstation over apt | "offensive-tool install" detector (matches package names against an offensive-tools watchlist, scoped to non-security-segment hosts) | **MISSING** |
| 2 | 5-minute periodic CONNECT to null-byte.wonderhowto.com | Beaconing detector (periodicity + jitter on repeated same-SNI/CONNECT targets) | **MISSING** |
| 3 | Pastebin.com/.pl/.bl visits + DNS | Suspicious-host-category detector (paste/anon-file watchlist) | **MISSING** |
| 4 | 156.59.33.180 -> 44.226.54.40:443 outbound-heavy, IP-literal TLS, no DNS | Outbound-byte-ratio detector + "TLS to IP literal with no DNS precedent" detector | **MISSING** |
| 5 | Cleartext IMAP/POP/SMTP/NFS/rsyslog | Cleartext-sensitive-protocol detector | **MISSING** |
| 6 | Process-to-flow attribution ("which process did the beaconing?") | `MemoryParser` (Volatility 3) + process<->socket correlation | **MISSING** |
| 7 | DNS anomaly (long labels, base32/base64 subdomains) | Already listed in POTENTIAL_IMPROVEMENTS §5 | **MISSING** |

## What we did right

- `PcapParser` extracts HTTP + DNS + SMTP artifacts cleanly.
- `NetworkDetector` architecture exists with `WebmailExfilDetector` as the
  first tenant, so adding the detectors above is a matter of new sibling
  modules rather than a framework rewrite.
- Scenario 06 (`webmail_exfiltration`) is the only network scenario with
  a true-positive detection today.

## Recommended next actions

1. File beads issues for items 1-5 and 7 above (priority 1 for
   beaconing and suspicious-host watchlist — those are direct misses on
   a training scenario we already ship).
2. Update `scenarios/training/network_intrusion/scenario.yaml`
   `expected.finding_counts` *only after* the corresponding detectors
   ship. Changing the expected count before the detector exists would
   break CI tautologically. (The alternative — marking the scenario
   `expected_failure: true` — is a reasonable middle ground and honors
   the "no lies" rule.)
3. Phase 2: MemoryParser on `ggmemday1.dmp` to resolve question 3
   ("which process owns the network activity").

## Data files

- `http_requests.json` (pass 1) — 3,548 HTTP requests.
- `dns_queries.json` (pass 1) — 12,072 DNS queries.

No new persisted artifacts from pass 2 — the findings above are shell
one-liners run against the PCAP; reproducing them is cheap.
