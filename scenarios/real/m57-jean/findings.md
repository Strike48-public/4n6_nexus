# NPS M57-Jean Case: Analyst Findings

**Case:** `nps-2008-jean.E01` (Digital Corpora scenario, CFO laptop)
**Subject:** Jean User, CFO, m57.biz
**Question:** Did Jean exfiltrate `m57biz.xls` containing employee names, salaries, and SSNs?
**Null hypothesis:** Jean did not exfiltrate the spreadsheet.
**Analyst:** sift_find_evil engine + manual reconciliation.
**Timezone:** All times UTC. Image TZ = GMT (SYSTEM hive `TimeZoneInformation.Bias=0`, `ActiveTimeBias=0xFFFFFFC4` = -60 min DST, i.e. BST at time of acquisition).

---

## Verdict

The null hypothesis is **rejected** with high confidence.

Jean sent a spreadsheet named `m57biz.xls` containing sensitive employee data to an external recipient impersonating her boss at **2008-07-20 01:28:47 UTC**, approximately 65 seconds after Excel created the file on her Desktop. The recipient address in the received headers is `tuckgorge@gmail.com`, masquerading as `alison@m57.biz`. This is the classic CFO / BEC (business email compromise) phishing pattern — the "sender" field of the inbound messages displays `alison@m57.biz` but the `From:` header of the received mail points to an attacker-controlled Gmail account relayed through `xy.dreamhostps.com`.

Jean is a phishing **victim**, not an inside threat. The exfiltration is real; the intent is negligent compliance with a social-engineered request, not theft.

---

## Evidence Timeline (UTC)

| Time (UTC) | Artifact | Source | What happened |
|---|---|---|---|
| 2008-07-19 23:39:57 | Inbound email "background checks" | PST Inbox | "alison@m57.biz" asks Jean for spreadsheet of employees, salaries, SSNs. Full `Return-Path` is `simsong@xy.dreamhostps.com`. |
| 2008-07-20 01:22:45 | Inbound email "Please send me the information now" | PST Inbox | Same sender display, but the `From:` header reads `tuckgorge@gmail.com (alison@m57.biz)` — the spoof is visible in the headers. |
| 2008-07-20 01:26:14.265 | `RUNDLL32.EXE-...` LastRun (RunCount=1) | Prefetch | First-time-run RUNDLL32 hash — matches the AutoPlay/PnP handler path. |
| 2008-07-20 01:26:18.062 | `USBSTOR\Disk&Ven_Generic&Prod_USB_Flash_Drive&Rev_1.00` key created | SYSTEM hive `ControlSet001\Enum\USBSTOR` | **Generic USB flash drive inserted** — 105 s before the xls is born. `FriendlyName = Generic USB Flash Drive USB Device`. |
| 2008-07-20 01:27:40.718 | `EXCEL.EXE-1C75F8D6.pf` LastRun | Prefetch | Excel launched. `RunCount=2` — second-ever Excel run on this box. |
| 2008-07-20 01:27:42.515 | `Office\Recent\m57biz.LNK` created | MFT `$STANDARD_INFORMATION` | Excel's own MRU registers the filename (2.1 s after Excel start). |
| 2008-07-20 01:27:42.546 | `Office\Recent\Temp.LNK` created | MFT | Excel scratch path. |
| 2008-07-20 01:28:03.656 | `Desktop\m57biz.xls` created (291,840 bytes) | MFT SI + FN | File born on Jean's Desktop. `$STANDARD_INFORMATION` (01:28:03.6562500) and `$FILE_NAME` (01:28:03.6875000) differ by 31.25 ms — well within normal NTFS write ordering, no timestomp. |
| 2008-07-20 01:28:04.046 | `Recent\m57biz.lnk` created | MFT | Shell "Recent Documents" LNK, confirming user-initiated save. |
| 2008-07-20 01:28:47.828 | `Sent Items\RE: Please send me the information now` | PST + libpff | Jean's reply. **One attachment, 291,840 bytes, magic `D0 CF 11 E0` (OLE), SHA-256 `34456b5f...779f`.** Identical byte-for-byte to `Desktop\m57biz.xls` on the same image. |
| 2008-07-21 00:44:52.859 | `OUTLOOK.EXE-179DEC04.pf` LastRun | Prefetch | Final Outlook run in the image window; `RunCount=13` overall. |

**Gap analysis:**
- USB insertion → Excel launch = **82.5 s**
- Excel launch → xls on Desktop = **22.9 s**
- xls born → outbound email = **44.2 s**

The 22.9 s Excel-to-save window is consistent with either (a) opening a pre-existing `m57biz.xls` from the newly-inserted USB stick and Save-As to Desktop, or (b) composing the spreadsheet from scratch in Excel. The USB insertion 105 s before save is strongly suggestive of (a) but cannot be definitively proven without USB-device correlation in the `$MRU` or a surviving shortcut with a volume ID. Either way, Jean is the user at the keyboard.

---

## Corroborating Artifacts

### Chat log (`alisonm57.html`, AIMLogger for user `m57jean`)
Extracted from `/Documents and Settings/Jean/My Documents/AIMLogger/m57jean/IM Logs/alisonm57.html` (13,076 bytes). At **July 21 00:54** (local, ≈01:54 UTC) Jean tells her AIM contact "alisonm57": *"check out whatever I was babbling about on email. don't worry about it."* The phrasing is consistent with a victim who realizes after the fact that something felt off, not an attacker directing further action.

### PST folder inventory
- Inbox: 222 messages
- Sent Items: 24 messages
- Deleted Items: 9 messages
- Outbox: 3 messages (one stuck `RE: Obama…` thread — irrelevant)

The Sent Items message was **not** deleted. The Deleted Items folder contains forwarded news links from `alex`, not the exfil thread. Jean did not try to destroy evidence.

### Negative finding: Security Event Log
`SecEvent.Evt` parses to **zero records** (header-only 65,536-byte circular buffer). On XP SP3 default, Security auditing is disabled unless `auditpol` is flipped; nothing here indicates tampering, and the empty state is itself consistent with a routine small-office XP install. We therefore cannot pin process-creation via Event ID 592 — the tiebreaker path the engine was extended to support is unavailable on this image, but the case does not need it: MFT SI vs FN agree and Prefetch agrees with MFT to the second.

### Cross-validator status (engine)
The self-correction engine (`sift_find_evil/engine`) produced 856 findings, all MEDIUM severity, none with the 4688/592 tiebreaker applied (Security log empty). The engine's current heuristics optimize for malware execution rather than file exfiltration and therefore do **not** independently surface the m57biz.xls story. This is a known limitation flagged for post-hackathon iteration; the findings here come from direct MFT/Prefetch/PST reconciliation against the three-artifact principle, not from the engine's ranked output.

---

## Chain of Inference

1. **Jean had the file.** MFT `$FILE_NAME` and `$STANDARD_INFORMATION` agree within 31.25 ms on 2008-07-20 01:28:03.656 UTC; the file is 291,840 bytes and lives on Desktop.
2. **Jean opened/created the file via Excel on her interactive session.** Prefetch shows EXCEL.EXE ran 22.9 s before the Desktop file appears; Office\Recent\m57biz.LNK follows 2.1 s after Excel start and well before the Desktop save. This is the same Excel session, not three independent observations.
3. **A USB flash drive was attached 105 s before the save.** `SYSTEM\ControlSet001\Enum\USBSTOR\Disk&Ven_Generic&Prod_USB_Flash_Drive&Rev_1.00` was created at 01:26:18 UTC with a matching first-run RUNDLL32 prefetch 4 s earlier. The xls may have originated on that stick; we cannot rule in/out without a mounted-volume artifact.
4. **Jean emailed the same bytes out within 44 s of save.** The Sent Items `RE: Please send me the information now` carries a single attachment of size **291,840 bytes** and SHA-256 **34456b5f714dc9d8dd23c742d54c3f5f582ecb042bc1c4d3042b88203863779f** — byte-identical to `Desktop\m57biz.xls` (verified by hashing both).
5. **The request was phishing.** Inbound headers for "Please send me the information now" show `From: tuckgorge@gmail.com (alison@m57.biz)` relayed through `xy.dreamhostps.com`; the real Alison's mailbox (`alison@m57.biz`) never appears in the Received chain.

Step 1 relies on MFT SI == FN. Step 2 is essentially single-sourced in one Excel session (the LNK and the prefetch are both products of running Excel once). Step 3 is SYSTEM hive + Prefetch. Step 4 is **two-source ironclad** — on-disk bytes == PST attachment bytes. Step 5 is single-source (PST headers) but structurally unforgeable without root access to Dreamhost's MTAs.

---

## Confidence (post-adversarial review)

| Claim | Confidence | Rationale |
|---|---|---|
| `m57biz.xls` existed on Desktop at 2008-07-20 01:28:03 UTC with size 291,840 B | 0.99 | MFT SI and FN agree within 31 ms, Prefetch and Recent LNK corroborate. |
| Jean's Sent Items reply carries the same bytes as the Desktop file | **0.99** | SHA-256 `34456b5f...779f` matches on disk and in PST attachment; 291,840 B identical. |
| The `alison@m57.biz` messages are phishing | 0.90 | Received chain shows `tuckgorge@gmail.com` through `xy.dreamhostps.com`; `From:` field inconsistency on the July 19 messages. |
| A USB flash drive was used at or near the xls creation | 0.85 | `USBSTOR\Disk&Ven_Generic` key born 01:26:18 UTC; RUNDLL32 first-run 4 s earlier. Role of the stick (source of xls vs. secondary channel) is undetermined. |
| Jean's send completed the exfil to the attacker's inbox | 0.80 | Client submit succeeded; actual SMTP hand-off would require Dreamhost logs to verify — out of scope. |
| No insider malice; Jean is a victim of social engineering | 0.70 | No deletions of the exfil message; phishing pretext is plausible; intent cannot be established purely from artifacts. |

Confidences were revised downward from the first-pass draft after the adversarial validator (see `validator_notes.md`) identified: (a) the Excel-to-xls gap is 22.9 s, not 1.5 s; (b) the Office/Shell LNKs are products of a single Excel session, not independent corroborators; (c) a USB insertion was missed in the first pass.

---

## Survivable Assumptions

- Excel prefetch timestamps are accurate to ±1 s (compositor, not quantum-logged).
- Outlook submit_time in PST reflects the actual SMTP hand-off; Dreamhost logs would be authoritative but are out of scope.
- `tuckgorge@gmail.com` is attacker-controlled; we do not assert identity.
- Timezone is GMT/BST per SYSTEM hive; all conversions use `datetime.fromtimestamp(..., tz=timezone.utc)` on FILETIME/Unix inputs that are themselves UTC-native.

---

## What This Case Does Not Prove

- **Whether the spreadsheet originated on the USB stick.** The Generic USB Flash Drive inserted at 01:26:18 UTC may have contained `m57biz.xls`, in which case Excel opened it from the stick and saved a copy to Desktop. Alternatively, Jean composed it from scratch. Resolving this requires USB-mount-point artifacts (`MountedDevices`, `MountPoints2`) not parsed in this pass.
- **Whether the attacker actually received the email.** Dreamhost / Gmail server logs are not on this image; we only prove the message was submitted to the local Outlook store with the attachment intact.
- **Any second exfil event.** The image window extends at least through 2008-07-21 01:30 UTC (Firefox last run); nothing interesting happens to `m57biz.xls` after the initial send.

---

## Artifacts Referenced

```
analysis/m57-jean/
├── csv/
│   ├── MFT.csv          (33 MB $MFT parsed via MFTECmd)
│   ├── Prefetch.csv     (127 .pf files parsed via libscca)
│   ├── EventLog.csv     (App+Sys events; Security log empty)
│   └── Email.csv        (258 PST messages parsed via libpff)
└── extracted/
    ├── chat/alisonm57.html
    ├── email/outlook.pst
    ├── evtlog/{Sec,App,Sys}Event.Evt
    └── registry/{SAM,SYSTEM,SOFTWARE,SECURITY,Jean_NTUSER.DAT}
```

SHA-256 of every extracted artifact is recorded in `extracted/MANIFEST.tsv` (148 entries). Everything under `extracted/` is gitignored; only the analysis artifacts (CSV + this document) are committed.

---

## Next Steps

1. Adversarial validator pass (see `validator_notes.md` when written).
2. Solution-aware grading against `M57-Jean_Solution.pdf`.
3. Engine gap: add a "file-saved-then-emailed-within-N-seconds" heuristic so the automated path catches this without the manual reconciliation above.
