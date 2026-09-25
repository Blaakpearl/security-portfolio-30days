# Day 30 — SCENARIO.md
## Portfolio Capstone: Full-Stack Security Operations Demonstration
**NovaCrest Capital Group | All Tracks**
**Classification:** TLP:WHITE — Public Portfolio
**Track:** Full Stack — All Domains
**Tools:** All tools from Days 1–29

---

## What This Day Is

Day 30 is not another technique. It is a reckoning.

Thirty days ago, this portfolio began with a phishing email sent to a
senior financial analyst at NovaCrest Capital Group. The email exploited
public information from a conference Instagram photo. It delivered a
macro-enabled spreadsheet. The analyst enabled the macros.

What followed was documented across 29 days of structured analysis:

```
Day 01–05   Reconnaissance and initial access surface mapping
Day 06–07   Endpoint persistence and Week 1 capstone
Day 08–14   Dark web intelligence, lateral movement, memory forensics,
            ATT&CK mapping, Week 2 capstone
Day 15–16   Red team initial access simulation (Sliver C2)
Day 17–21   Purple team: privilege escalation, data exfiltration, log
            forensics, C2 exercise, Week 3 capstone
Day 22–25   Risk scoring, mobile OSINT, cloud hunt, ransomware forensics
Day 26–28   Threat actor profiling, detection engineering, OSINT investigation
Day 29      AI agent integration
Day 30      This document: the complete picture
```

The capstone has four deliverables:

1. **`capstone_report.md`** — The complete NovaCrest incident analysis
   from initial access through recovery, written as a deliverable for
   a CISO and board of directors

2. **`skill_matrix.md`** — A structured competency map of every technique,
   tool, and domain demonstrated across the 30 days

3. **`portfolio_stats.py`** — A script that computes portfolio statistics
   (files, lines, tools, ATT&CK coverage) across all 30 days

4. **`README_update.md`** — Final README content for the GitHub Pages site

---

## The NovaCrest Incident: What Actually Happened

```
TIMELINE OF A FINANCIAL SECTOR BREACH

Jun 14 08:47 UTC  j.henderson opens phishing email on corporate iPhone
                  (MDM check-in confirms mobile delivery — Day 23)

Jun 14 09:12 UTC  j.henderson opens macro-enabled spreadsheet on WS-FIN-04
                  Macro executes: cmd.exe → Sliver implant deployed
                  Sliver beacons to 198.51.100.99:443
                  JA3: a0e9f5d64349fb13191bc781f81f42e1

Jun 14 09:14 UTC  DET-002 WOULD HAVE FIRED (new rule — Day 27)
                  Was not deployed pre-breach → missed

Jun 14–18         5-day dwell: privilege escalation, lateral movement,
                  credential harvest, data exfiltration
                  ~293 MB stolen across HTTPS and S3 channels
                  IAM backdoor created June 16 — not found until Day 26 hunt

Jun 19 03:22 UTC  LockBit 3.0 variant (ncrypt) deployed via WMI
                  44 seconds to destroy all recovery options (VSS, WB, bcdedit)
                  2h 48min encryption window — completely undetected

Jun 19 06:14 UTC  First detection: overnight team notices .ncrypt extension
                  proliferation — AFTER encryption is complete

Jun 19 06:31 UTC  SRV-FS-01 isolated. Trading suspended.
                  26,168 files / 2,215 GB encrypted
                  $4.2M XMR ransom demanded
                  Deadline: June 22 06:14 UTC

Jun 19–28         IR, forensics, threat intelligence, detection engineering,
                  OSINT investigation — Days 22–28

Jun 29            AI agent integration deployed — Days 15–25 alerts
                  would have triaged in 2.3s each (vs. 18 min manual)
```

---

## Outcome: What the Portfolio Demonstrates

**Before (Day 0 posture):**
- 0 purpose-built detection rules for FIN-NC-001 TTPs
- No cloud detection content for AWS
- No mobile OSINT awareness program
- No threat actor intelligence for this actor
- No AI-augmented triage capability
- Ransomware detected 2 hours 48 minutes after encryption began

**After (Day 30 posture):**
- 12 detection rules deployed (44% ATT&CK coverage of confirmed TTP set)
- DET-009 would detect ransomware in <60 seconds
- DET-002 would detect C2 at first beacon (<1 minute from infection)
- FIN-NC-001 STIX bundle shared with FS-ISAC
- Mobile OSINT policy implemented
- AI triage pipeline processes 847 alerts/month in seconds
- Complete forensic record for FBI referral and regulatory notification

---

*Day 30 Capstone | Portfolio Summary*
*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*
