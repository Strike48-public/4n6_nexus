# Nitroba University Harassment Scenario

**Source:** Digital Corpora  
**URL:** https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/  
**Scenario Date:** Summer 2008 (fictional, timestamps in data)

## Scenario Background

You are a security administrator at the prestigious (and fictional) Nitroba State University.

A student named Lily Tuckridge reported receiving harassing emails to her personal Yahoo email account (lilytuckrige@yahoo.com). She provided screenshots to the system administrator.

### Investigation Details

- The mail headers show the email originated from IP address **140.247.62.34** (a Nitroba student dorm room)
- Three women share the dorm room
- Each dorm room has Ethernet but no Wi-Fi
- One of the women's friends installed a Wi-Fi router with **no password**
- Multiple harassing emails came from this IP address
- Nitroba placed a network sniffer on the ethernet port to capture traffic
- On Monday 7/21, Tuckridge received another harassing email sent through a web-based service

### Investigation Goal

Determine if one of the students in Chem 109 class was responsible for the harassing email and provide clear, conclusive evidence to support the conclusion.

### Evidence Provided

1. Screenshots from the victim
2. Network packet capture from the Ethernet tap
3. Chem 109 roster

## Downloadable Files

### Primary Evidence

| File | Size | Direct Download URL |
|------|------|---------------------|
| **PCAP File** | ~60MB (53.6 MB) | https://downloads.digitalcorpora.org/corpora/scenarios/2008-nitroba/nitroba.pcap |

**File Hashes (nitroba.pcap):**
- **MD5:** `9981827f11968773ff815e39f5458ec8`
- **SHA1:** `65656392412add15f93f8585197a8998aaeb50a1`
- **SHA256:** `2b77a9eaefc1d6af163d1ba793c96dbccacb04e6befdf1a0b01f8c67553ec2fb`

### Teaching Materials

| Document | Format | Download URL |
|----------|--------|--------------|
| **Problem Slides** | PDF | https://downloads.digitalcorpora.org/corpora/scenarios/2008-nitroba/slides.pdf |
| **Problem Slides** | PPT | https://downloads.digitalcorpora.org/corpora/scenarios/2008-nitroba/slides.ppt |
| **Problem Slides** | Keynote | https://downloads.digitalcorpora.org/corpora/scenarios/2008-nitroba/slides.key |
| **Teacher's Solution** | PDF (password protected) | https://downloads.digitalcorpora.org/corpora/scenarios/2008-nitroba/nitroba-solution.pdf |
| **Expanded Lab Scenario** | PDF | https://downloads.digitalcorpora.org/corpora/scenarios/2008-nitroba/Nitroba%20Harassment%20Lab%20scenarios.pdf |
| **Expanded Lab Solutions** | PDF (encrypted) | https://downloads.digitalcorpora.org/corpora/scenarios/2008-nitroba/Nitroba%20Harassment%20Lab%20scenarios%20with%20Solution.pdf |

**Note:** Teacher solution passwords are available to faculty at accredited educational institutions.  
**Password Info:** https://digitalcorpora.org/corpora/scenarios/obtaining-solutions/

### Additional Credits

The Expanded Nitroba Harassment Lab Scenarios were created by **Ajoy Ghosh** at UNSW Canberra.

## File Verification Status

**Local File:** `/home/jtomek/Code/sift_find_evil/practice_images/nitroba/nitroba.pcap`

**Verification Results:**
- MD5: VERIFIED (matches published hash)
- SHA1: VERIFIED (matches published hash)
- SHA256: VERIFIED (matches published hash)
- Size: 54M (56,180,821 bytes)

All hashes match the official Digital Corpora values. File integrity confirmed.

## Analysis Tools Mentioned

The scenario page references:
- **bulk_extractor 2.0** - Available as compiled binaries from Digital Corpora
- Network forensics tools (Wireshark, tcpdump, etc.)
- Email header analysis tools

## Scenario Timeline

1. Lily Tuckridge receives harassing emails
2. Reports to system admin with screenshot
3. Admin requests full email headers
4. Headers reveal source IP: 140.247.62.34 (student dorm)
5. Network tap installed to capture traffic
6. Monday 7/21 - Another harassing email received (via web-based service)
7. Analysis begins with captured packets

## Key Investigation Elements

- Network packet analysis (HTTP, email protocols)
- Email header forensics
- IP address correlation
- Student roster cross-reference
- Timeline reconstruction
- Authentication/session analysis

## Notes

- Timestamps in the PCAP are from Summer 2008 and are not relevant to solving the scenario
- The scenario takes place at a fictional university
- Multiple web-based email services may be involved
- Unsecured Wi-Fi introduces attribution complexity
- Need to establish clear chain of evidence linking a specific individual

## Additional Resources

- Digital Corpora main site: https://digitalcorpora.org/
- Scenario category: Network forensics, cyberbullying, harassment investigation
- Difficulty level: Intermediate
- Suitable for: Educational labs, training exercises, forensics practice

---

**Document Generated:** 2026-04-17  
**Last Verified:** 2026-04-17
