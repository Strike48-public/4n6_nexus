# SFE-e3g: SRL-2015 Cross-Host Logon Graph

Authentication correlation across 7 enterprise hosts. Source: Security event logs (4624 success, 4625 failed, 4648 explicit-cred, 4672 admin) extracted via pyewf+pytsk3, parsed with EvtxECmd. Read-only.

## Authentication events per host

| Host | 4624 success | 4625 failed | 4648 explicit-cred | 4672 admin |
|------|-------------|-------------|--------------------|------------|
| DC | 50651 | 459 | 91 | 28738 |
| DMZ-FTP | 1037 | 20768 | 106 | 1034 |
| FILE | 520 | 1 | 55 | 494 |
| RD-01 | 11722 | 864 | 2571 | 10022 |
| RD-02 | 11465 | 224 | 684 | 5069 |
| WKSTN-01 | 69121 | 3707 | 2617 | 52079 |
| WKSTN-05 | 3716 | 5 | 442 | 3567 |

## Failed-logon hot spots (4625) — brute force / spraying / probing

Total failed logons across corpus: **26028**

Top failed-logon target accounts:
- `\` x4708
- `\rsydow` x3850
- `\nfury` x3850
- `\Ellie Phimister` x3849
- `\rsydow-f` x3849
- `\negasonic` x3849
- `shieldbase\BASE-HUNT$` x459  [machine acct]
- `\users` x247
- `\administrator@stark-research-labs.com` x166
- `\admin@stark-research-labs.com` x160
- `\stark-research-labs.com` x110
- `\nromanoff@stark-research-labs.com` x106

Top failed-logon source hosts:
- DMZ-FTP (?) x20574
- BASE-HUNT (172.16.5.25) x465
- BASE-FILE (172.16.4.5) x117
- BASE-ADMIN (172.16.5.26) x35
- BASE-RD-01 (?) x27
- BASE-WKSTN-05 (172.16.7.15) x24
- BASE-RD-01 (192.168.30.10) x23
- BASE-RD-01 (127.0.0.1) x12
- BASE-RD-04 (172.16.6.14) x8
- BASE-WKSTN-01 (127.0.0.1) x7
- DMZ-FTP (127.0.0.1) x7
- BASE-RD-01 (172.16.6.14) x4

## Explicit-credential logons (4648) — runas / lateral movement

Total 4648 across corpus: **6566** (2572 to user accounts, the rest machine accounts).

User-account explicit-credential use (target-host, account):
- RD-01: `\tdungan@stark-research-labs.com` x1750
- RD-01: `shieldbase\tdungan` x160
- RD-02: `shieldbase\kellee.espinoza` x152
- RD-01: `SHIELDBASE.LAN\spsql` x84
- WKSTN-01: `shieldbase\mhill` x81
- DC: `SHIELDBASE.LAN\rsydow-a` x40
- WKSTN-05: `shieldbase\nfury` x38
- FILE: `SHIELDBASE.LAN\spsql` x32
- DMZ-FTP: `BASE-FTP\Administrator` x31
- FILE: `shieldbase.lan\spsql` x19
- RD-01: `shieldbase\spsql` x19
- DMZ-FTP: `DMZ-FTP\rsydow` x16
- RD-01: `shieldbase\Administrator` x13
- RD-02: `shieldbase\jpallen` x11
- DC: `shieldbase\rsydow` x10
- RD-01: `shieldbase.lan\spsql` x10
- RD-02: `shieldbase\spsql` x9
- RD-01: `shieldbase\tdungan@stark-research-labs.com` x7
- WKSTN-05: `shieldbase\Administrator` x7
- DMZ-FTP: `DMZ-FTP\Administrator` x7

## Cross-host account spread — pivot-account candidates

Accounts that authenticated to multiple hosts (lateral footprint):
- `shieldbase\cbarton-a` -> 6 hosts: DC, FILE, RD-01, RD-02, WKSTN-01, WKSTN-05
- `shieldbase\spsql` -> 5 hosts: DC, FILE, RD-01, RD-02, WKSTN-05
- `shieldbase\rsydow-a` -> 5 hosts: DC, FILE, RD-01, RD-02, WKSTN-05
- `SHIELDBASE.LAN\rsydow-a` -> 4 hosts: DC, RD-01, RD-02, WKSTN-01
- `SHIELDBASE.LAN\Administrator` -> 4 hosts: DC, RD-01, RD-02, WKSTN-05
- `SHIELDBASE.LAN\cbarton-a` -> 4 hosts: DC, RD-01, RD-02, WKSTN-01
- `SHIELDBASE.LAN\spsql` -> 4 hosts: DC, FILE, RD-01, RD-02
- `shieldbase\nromanoff` -> 4 hosts: FILE, RD-01, RD-02, WKSTN-05
- `shieldbase\Administrator` -> 4 hosts: FILE, RD-01, RD-02, WKSTN-05
- `shieldbase\nfury` -> 3 hosts: DC, RD-01, WKSTN-05
- `shieldbase\tdungan` -> 3 hosts: DC, FILE, RD-01
- `shieldbase\administrator` -> 3 hosts: RD-01, RD-02, WKSTN-05
- `SHIELDBASE.LAN\nromanoff` -> 2 hosts: DC, RD-01
- `SHIELDBASE.LAN\nfury` -> 2 hosts: DC, WKSTN-05
- `shieldbase\rsydow` -> 2 hosts: DC, FILE
- `shieldbase\mhill` -> 2 hosts: DC, WKSTN-01
- `shieldbase\cbarton` -> 2 hosts: DC, FILE
- `shieldbase.lan\spsql` -> 2 hosts: FILE, RD-01
- `shieldbase\jpallen` -> 2 hosts: FILE, RD-02

## Remote-interactive (RDP, LogonType 10) edges

Total user RDP logons: **85**

Source -> target-host as account (RDP):
- DMZ-FTP -> DMZ-FTP as `DMZ-FTP\rsydow` x26
- BASE-RD-01 -> RD-01 as `shieldbase\spsql` x24
- BASE-WKSTN-05 -> WKSTN-05 as `shieldbase\nfury` x19
- BASE-RD-02 -> RD-02 as `shieldbase\spsql` x4
- BASE-WKSTN-05 -> WKSTN-05 as `shieldbase\rsydow-a` x4
- DMZ-FTP -> DMZ-FTP as `DMZ-FTP\rsydow-a` x4
- BASE-DC -> DC as `shieldbase\rsydow-a` x2
- BASE-RD-01 -> RD-01 as `shieldbase\tdungan` x2
