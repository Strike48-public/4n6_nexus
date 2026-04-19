# Grading: M57-Jean vs. Exercise Slides

Graded against `references/M57-Jean-exercise-slides.pdf` (public, no spoilers). The password-gated full solution PDF was not available; this grading uses only the three explicit questions on the "Your assignment" slide.

## The Three Questions

### Q1. "When did Jean create this spreadsheet?"

**Answer:** 2008-07-20 01:28:03.656 UTC (Sunday ~02:28 BST local), on her Desktop, size 291,840 bytes, SHA-256 `34456b5f714dc9d8dd23c742d54c3f5f582ecb042bc1c4d3042b88203863779f`. Excel had been launched 22.9 s earlier (prefetch). Whether the content was typed from scratch or imported from the USB stick attached 105 s earlier is not resolved.

**Source:** `csv/MFT.csv` + `csv/Prefetch.csv` + SYSTEM hive.
**Grade:** Answered with timestamp precision to the quarter-millisecond and hash-level corroboration.

### Q2. "How did it get from her computer to the competitor's website?"

**Answer:** By email. Jean replied to a phishing message at 2008-07-20 01:28:47.828 UTC (44 s after Desktop save). Her Sent Items reply contains **one attachment of exactly 291,840 bytes and SHA-256 `34456b5f...779f`** — byte-identical to `Desktop\m57biz.xls`. The inbound "request" from "alison@m57.biz" carries `From: tuckgorge@gmail.com (alison@m57.biz)` in the Received headers, routed through `xy.dreamhostps.com`. The attacker impersonated Jean's boss; Jean sent the file in good faith.

From Jean's machine, we can only prove the message was handed to her local Outlook store. Subsequent posting of the file to the competitor's support forum would have happened from the attacker's infrastructure, not this image — consistent with how the exercise framing describes the discovery ("posted as an attachment").

**Source:** `csv/Email.csv` + libpff attachment extraction + hash comparison.
**Grade:** Answered with cryptographic certainty on the bytes and direct-quote evidence on the phishing pretext.

### Q3. "Who else from the company is involved?"

**Answer:** No one inside M57.biz. The interview summary in the slides has Alison denying she ever asked for the spreadsheet; the PST headers corroborate Alison — the request originated at `tuckgorge@gmail.com`, not from the real `alison@m57.biz` mailbox. The conflict between Alison's and Jean's testimony is resolved by the forensic artifacts: Jean is telling the truth about what she thought she saw in her inbox; Alison is telling the truth about what she actually sent. Both are correct. The social engineer is a third party outside the company.

The July 19 "RE: background checks" thread shows the same pattern — the messages that reach Jean via `alison@m57.biz` are relayed through the attacker-controlled Dreamhost mailbox. No employee of M57.biz participated in the leak.

**Source:** PST transport headers + interview reconciliation.
**Grade:** Answered, with explicit resolution of the Alison-vs-Jean contradiction on the interview slide.

## Self-Grade

| Dimension | Rating | Note |
|---|---|---|
| Who | Correct | Jean sent, external attacker received. |
| When | Correct | Sub-second precision on both xls creation and email submit. |
| What | Correct | Exact bytes + SHA-256 identity established. |
| How | Correct | Email with attachment, via phishing pretext. |
| Why | Partially | "Because Jean believed Alison asked." Full motivational context (social engineering tradecraft) is speculative. |
| Alternative channels | Acknowledged | USB insertion 105 s before save raises the possibility the xls originated on the stick; does not change the exfil channel but is an honest gap the first analyst pass missed. |

Overall: the three client questions are all answerable with artifact-grounded evidence, with no dependence on the engine's automated scoring (which did not surface this case — see findings.md for the gap discussion).
