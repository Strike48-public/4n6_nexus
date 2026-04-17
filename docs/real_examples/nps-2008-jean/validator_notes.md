# Validator Notes: NPS M57-Jean Case

**Role:** Adversarial validator. Steel-manning the null hypothesis (Jean did not exfiltrate the spreadsheet, or did so for reasons the analyst has not established). Every challenge below is grounded in the extracted artifacts in `analysis/real_examples/nps-2008-jean/`.

---

## 1. Attacks on the Confidence Table

### Claim A: "m57biz.xls existed on Desktop at 2008-07-20 01:28:03 UTC" (0.99)

**Analyst's asserted support:** MFT SI == FN, Prefetch aligns to the second.

**Factual challenge.** MFT SI and FN do **not** match to the millisecond. From `csv/MFT.csv` entry 32712:
- `Created0x10` (SI) = 2008-07-20 01:28:03.6562500
- `Created0x30` (FN) = 2008-07-20 01:28:03.6875000

That is a 31.25 ms delta, and the MFTECmd column `SI<FN` is flagged `True`. The direction (SI earlier than FN) is benign and is typical for NTFS file creation, but the analyst's *reason* ("match to the millisecond") is false on its own terms. The correct survival statement is "SI<FN delta is small and in the expected direction," not equality.

**Falsification test.** If the analyst re-reads the MFT he should retract "match to the millisecond" or replace it with an explicit statement about which direction SI/FN diverge and what that tells us about timestomping.

**Does the claim still stand?** Yes — the xls clearly exists. Confidence 0.99 is unchanged, but the supporting rationale needs to be corrected.

---

### Claim B: "Jean composed and sent the reply at 01:28:47 UTC" (0.97)

**Analyst's asserted support:** PST client_submit_time; Outlook prefetch confirms process active.

**Factual challenge #1 — PST time fields are ambiguous.** The `SubmitTime` column in `csv/Email.csv` for the "RE: Please send me the information now" message is `2008-07-20 01:28:47.828125`, and `DeliveryTime` is `2008-07-20 01:28:00` (second-field blank). The analyst treats this as UTC. libpff emits `PR_CLIENT_SUBMIT_TIME` and `PR_MESSAGE_DELIVERY_TIME` as UTC FILETIMEs — that is normally correct — but the Sent-Items DeliveryTime is rounded to the minute, which suggests a distinct PR_SENT_REPRESENTING field or Outlook's display-rounding. The 47.8-second offset between the rounded "01:28:00" and the precise "01:28:47.828" is the kind of inconsistency a defender would use to cast doubt on UTC-assumption. The analyst did not disclose this, even though the minute-rounded delivery time is visible in the CSV.

**Factual challenge #2 — Outlook prefetch does NOT confirm "process active at 01:28:47."** From `csv/Prefetch.csv` row 46, `OUTLOOK.EXE-179DEC04.pf` has `RunCount=13` and `LastRun=2008-07-21T00:44:52.859375`. That is the *next day*. The XP prefetch format stores only the most recent execution in the LastRun column; earlier runs are not individually preserved. So "Outlook prefetch confirms process active" at 01:28:47 UTC is unsupported by the data shown. The supporting evidence is negative ("the .pf file exists, so Outlook ran at some point"), not positive for the exact timestamp.

**Alternative hypothesis.** The Sent Items message was planted. Outlook PST files are user-writable and can be edited without leaving a prefetch trace. A second party with access to the laptop (Jean was browsing AIM installations — there are AOL, AIM, Viewpoint artifacts all over this image) could have composed the message and back-dated it. This is a low-probability attack but it fits the evidence and has not been ruled out.

**Falsification test.** The Outlook PST `TRN` or `Message-ID` header would leave Dreamhost SMTP server-side traces; those are out of scope. The weaker local test is the matching Message-ID echo in the inbound "Thanks!" message at 05:03:40 (which references the earlier thread) — that does corroborate that an outbound message was sent between 01:28:47 and 05:03:40 UTC, because the attacker's "Thanks!" clearly responds to *something*.

**Revised confidence.** 0.90, not 0.97. The submit_time is almost certainly real, but the "Outlook prefetch confirms" rationale is wrong.

---

### Claim C: "The alison@m57.biz messages are phishing" (0.92)

**Analyst's asserted support:** Gmail Return-Path in headers; impersonates internal boss.

**Factual challenge — the evidence is stronger than the analyst implied, but the signal cuts both ways.** Looking at `csv/Email.csv`:
- Inbound "background checks" (01:39:57 UTC-ish, actually 23:39:57 UTC): `Return-Path: <simsong@xy.dreamhostps.com>`, `From: alison@m57.biz`. Note: `simsong` is the well-known handle of Simson Garfinkel, the creator of the NPS corpus. This is *not* a live attacker — it is the exercise author injecting the phishing email. A real-world defender could challenge the "attacker-controlled Gmail" claim on the grounds that every Return-Path on this mail run ends in `dreamhostps.com` and goes to `userid 558838` — a single Dreamhost shared-hosting user.
- Inbound "RE: background checks" (23:50:20 UTC): `Return-Path: <alison@m57.biz>`, `From: "alex" <alison@m57.biz>`. Here the **display name is "alex"** but the address is `alison@m57.biz`, and the IP is `70.134.85.172` — Jean's own workstation name `jean13fbf038a3` appears in the Received line. The analyst labels this as "from alex" because libpff picked up the display name, but the header is **self-inconsistent**: alex sending as alison. The analyst entirely missed this. If we are accepting header-level impersonation as proof, then "alex" is *also* impersonating "alison" — or alex and alison share the `alison@m57.biz` mailbox, which undermines the whole premise that the inbound mail is from an external attacker. (Most likely reading: alex replied to an internal thread and hit the wrong From/alias.)
- "Please send me the information now" (01:22:45 UTC): `From: tuckgorge@gmail.com (alison@m57.biz)` as the literal header value. That is one header; it has a Dreamhost Received chain, but the SMTP envelope is still Dreamhost, not Gmail.

**Alternative hypothesis.** The emails are internal. Alison's actual mailbox lives on Dreamhost (same provider as Jean's m57.biz mail); the `xy.dreamhostps.com` Received lines are consistent with Alison sending from a Dreamhost webmail/shell session and accidentally including `tuckgorge@gmail.com` as a second address in the From field (Outlook-style `"Display Name" <address>`). This would still warrant concern but it would not be phishing.

**Falsification test.** Dreamhost control-panel or WHOIS records for `userid 558838`; unavailable here.

**Revised confidence.** 0.80. The three independent phishing-aligned signals (Gmail address, self-inconsistent From, request for SSNs with "don't tell anyone") do add up, but the analyst glossed over the messy second message and jumped straight to "attacker-controlled Gmail."

---

### Claim D: "Jean's send closed the exfil loop" (0.90)

**Analyst's asserted support:** 44s gap; reply body admits attachment; no alternative exfil artifact.

**Factual challenge.** The reply body (`csv/Email.csv` row 7) reads *"I've attached the information that you have requested to this email message."* The PST row shows **no attachment metadata in the parsed CSV** — `BodyPreview` is just text. libpff does parse attachments; the analyst did not include attachment size or filename columns, so we cannot confirm from the CSV alone that an attachment was actually attached. The "admission" text is circumstantial; if Outlook failed to attach the file (common UX mistake), the sentence is still there.

**Falsification test.** Rerun `pffexport -m all outlook.pst` and look for `Attachment.m57biz.xls` under the Sent Items message. The raw PST is in `extracted/email/outlook.pst`. If no attachment is present, the send loop is not closed.

**Separate challenge.** The "no alternative exfil artifact" claim is an argument from absence. The MFT shows `USBSTOR.SYS` $SI last-access of 2008-07-20 01:26:17 UTC (MFT row 16290), **106 seconds before** the xls was created and 150 seconds before the send. `RUNDLL32.EXE-28FE2D3B.pf` has `RunCount=1` and LastRun at 01:26:14.265 UTC — a rundll32 invocation that lines up with AutoPlay/PnP for a removable device. The analyst did not address this. Combined with the Templates directory creation at 01:27:59 (in Jean's profile, not elsewhere — suggesting an MRU/template import), the most-conservative story is "a USB device touched the system at 01:26:14 and Jean used or copied something from it." That is a very plausible alternative source for the 291,840-byte xls.

**Revised confidence.** 0.65. The email probably carried the file, but "closed the loop" as the sole exfil channel is overstated.

---

### Claim E: "No insider malice; Jean is a victim" (0.80)

**Analyst's asserted support:** AIM chat tone, no deletions, no USB, consistent with social engineering success.

**Factual challenge #1 — the chat.** `extracted/chat/alisonm57.html` covers **Friday July 18** and **Monday July 21**. It does **not** cover the exfil night (July 19-20). The July 21 exchange at 00:50:36 UTC has alisonm57 asking "Did you get it?" **referring to an AIM message she just sent** (the log starts with Jean asking "hey, did you just message me?"), not to email. Jean says "yep. just replied." The line "check out whatever I was babbling about on email. don't worry about it." is three minutes later in an unrelated sub-thread about a hotel itinerary. The analyst stitched these two utterances together as if Jean was worrying about the phishing. A defender would argue they are unrelated: the "email I was babbling about" could be any of several mails Jean sent that morning.

**Factual challenge #2 — "no USB" is not supported.** As above, USBSTOR.SYS and RUNDLL32 prefetch evidence are consistent with a removable device at 01:26. No `setupapi.dev.log` excerpt is cited, and `SecEvent.Evt` is empty. "No USB" is an argument from silence.

**Factual challenge #3 — AIM identity is unverified.** The AIM contact is `alisonm57`, the Jean screen name is `m57jean`. These are handles, not identities. If Alison's email account was compromised (Dreamhost shared host, `simsong` sharing a `userid 558838`), her AIM could have been compromised in the same breach. The "Alison" in the chat and the "Alison" in the exfil email could both be the attacker.

**Revised confidence.** 0.55. There is a reasonable victim narrative, but the analyst overstates the corroboration.

---

## 2. Missing Evidence

1. **Attachment verification.** The CSV does not export attachment rows. The critical question — "is m57biz.xls actually attached to the Sent Items message?" — is answerable from the PST but was not answered in the findings.
2. **Firefox history / IE history.** The analyst says Firefox's last run is 2008-07-21 01:30:38, "post-dating the email." But IE was active **during** the window (see `MSHist012008072020080721` created 2008-07-19 23:42:44, and a stream of `aim.com` ad impressions in `Content.IE5/*`). The analyst did not check whether Jean uploaded to a webmail site via IE.
3. **USB device enumeration.** `extracted/registry/SYSTEM` hive contains `USBSTOR\Enum` keys that were not parsed. The analyst did not run RegRipper / `regipy` on this hive. Without that, the "no USB" claim is not grounded.
4. **setupapi.dev.log** is on XP SP3 at `WINDOWS/setupapi.log` — it does appear in MFT but its contents are not included in the extracted bundle. First-time USB installs write to it.
5. **The inbound "Thanks!" message at 05:03:40 UTC** has `To: jean@m57.biz, From: tuckgorge@gmail.com (alison@m57.biz)`. Its `BodyPreview` reads "Thanks for the file. I'll handle it from here." This is the strongest single corroboration that the attacker received *something* — yet the analyst buried it and only cited the Sent Items timestamp for the closure claim.
6. **Outbox stuck messages** (three copies of "RE: Obama makes first trip to Afghanistan", SubmitTime 2008-07-21 01:16:44) indicate Outlook had SMTP trouble on July 21. If similar trouble occurred on July 20, the "sent" message may never have reached Dreamhost, in which case the file never left the machine via email.

---

## 3. Inference Chain Audit

Step 1 ("Jean had the file"): MFT + Prefetch. The "+Prefetch" is weak — Prefetch only shows Excel ran, not that it saved m57biz.xls specifically. **Effectively single-source (MFT).**

Step 2 ("Jean opened/created via Excel"): claimed as three artifacts (Prefetch, Office\Recent LNK, Recent LNK). All three are derived from the same Excel session running on Jean's account. They are **not independent classes** — they are three Excel-generated artifacts. The "three-artifact principle" is violated.

Step 3 ("emailed something within a minute"): MFT + PST. **Genuinely two independent sources.** This is the strongest step.

Step 4 ("the request was phishing"): PST headers only. **Single-source, analyst admits it.** The analyst also missed that the inbound "RE: background checks" reply is self-inconsistent (`alex` sending as `alison@m57.biz`).

Step 5 ("no non-email exfil"): negative. Ignores the USBSTOR/RUNDLL32 01:26 window.

---

## 4. Timezone / Timestamp Sanity

- SYSTEM hive `TimeZoneInformation` was not reparsed in the validation — the analyst asserts Bias=0 (GMT) with ActiveTimeBias=0xFFFFFFC4 (−60 min, i.e. BST). The received Postfix headers consistently show `-0700 (PDT)` — Pacific Daylight Time — because Dreamhost is in California, not because Jean's box is in PDT. The `Date:` header on "background checks" says `Sat, 19 Jul 2008 16:39:57 -0700 (PDT)`. In UTC that is `2008-07-19 23:39:57`, which matches `DeliveryTime`. Consistent.
- The inbound "RE: background checks" (from alex) `Date:` header says `Sun, 20 Jul 2008 00:50:20 +0100`. In UTC that is 23:50:20 July 19. `DeliveryTime` in the CSV is `2008-07-19 23:50:20`. Consistent.
- The Sent Items "RE: Please send me the information now" has `DeliveryTime=2008-07-20 01:28:00` (minute-rounded) and `SubmitTime=2008-07-20 01:28:47.828125`. The analyst silently treats the SubmitTime as the authoritative send moment. That is defensible, but the 47-second discrepancy should be acknowledged.
- Prefetch `EXCEL.EXE-1C75F8D6.pf` LastRun is `2008-07-20T01:27:40.718750+00:00`. That is 82.9 seconds before `m57biz.xls` SI creation. The analyst said "1.5 seconds before MFT creation" which is wildly wrong — the correct delta is ~82.9 s, not 1.5 s. **This is a factual error in the findings.** (The Office\Recent LNK at 01:27:42 is 1.8 s after Excel launch, which is what the analyst may have been thinking of.)
- No daylight-saving off-by-hour errors detected. All timestamps reconcile to UTC consistently.

---

## 5. Alternative Exfil Hypotheses

The analyst focused on email as the single channel. Grounded alternatives:

1. **USB / removable media (01:26 window).** USBSTOR.SYS SI last-access 01:26:17; RUNDLL32 hash 28FE2D3B LastRun 01:26:14 (RunCount=1 — a *new* dll invocation). AutoPlay + newdev.dll + a USB storage driver is the exact signature of a first-time device attach. The xls is 291,840 bytes — trivial to copy to a USB stick in milliseconds. The xls's subsequent email send does not preclude a prior USB copy.
2. **AIM file transfer.** AIM6 is running (prefetch LastRun 2008-07-21 01:30:35; AOL OCP cache files are being updated throughout July 20 in the MFT). AIM supports in-protocol file transfer. No AIM file-transfer log was exported; the analyst did not check.
3. **Webmail upload via IE.** IE ran at 01:27-29 (Content.IE5 activity); no IE temporary uploads folder was parsed. `office.microsoft.com` cookie at 23:42:44 shows Jean did visit Microsoft properties; could have also visited Gmail or Yahoo mail.
4. **FTP/WebDAV via Windows shell.** Not parsed, but Windows Explorer URL MRU lives in `NTUSER.DAT`; not inspected.
5. **Printed/photographed.** `csv/EventLog.csv` contains a `Print` channel; no entries in window, but printer queue metadata was not checked.
6. **Copy-paste to AIM chat.** If Jean pasted the SSN contents into AIM, the 291,840-byte size would be dominated by formatting; the raw data would fit in chat. The chat log file `alisonm57.html` is only 13,076 bytes and does not contain SSNs, but other buddies' logs were not exported.

None of these are *more likely* than the email theory, but the analyst's "no alternative exfil artifact" requires ruling each one out, which was not done.

---

## 6. Verdict

**Partially endorse.**

The core finding — that `m57biz.xls` existed on Jean's desktop at 01:28:03 UTC and an outbound PST message bearing the name of that spreadsheet was submitted at 01:28:47 UTC — is solid and survives adversarial review. The email-as-exfil-channel story is *plausible* and probably correct in spirit.

What I do not endorse:

1. The specific confidence values. Several are inflated because the analyst over-counted independent artifacts (Step 2) or assumed positive evidence where only absence exists (Step 5, "no USB").
2. The factual claim that Excel launched "1.5 seconds before MFT creation." The real delta is ~82.9 seconds. This error is load-bearing for the analyst's narrative that Jean did not have time to copy the data off elsewhere.
3. The framing of the inbound "RE: background checks" message as from "alex" without flagging that its headers read `alex <alison@m57.biz>` — an alias/spoofing inconsistency the analyst missed.
4. The chat-log stitching: the July 21 00:54 "babbling" line is not about the phishing email. Using it as mood evidence is unsafe.

**Recommendation.** Before publishing or grading, the analyst should:
- Export attachments from the Sent Items PST entry and confirm `m57biz.xls` is actually attached.
- Parse the SYSTEM hive `USBSTOR\Enum` key and check for a device first-seen at 01:26 UTC.
- Correct the "1.5 s" / "match to the millisecond" errors.
- Separate "Alison the AIM buddy" from "alison@m57.biz the mailbox" — they may not be the same actor.
- Re-score confidences: A=0.99, B=0.90, C=0.80, D=0.65, E=0.55.

**Net call.** The null hypothesis ("Jean did not exfiltrate") is probably still rejected, but on narrower grounds than the analyst stated. The exfil channel is most-likely but not solely email.
