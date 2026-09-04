# Day 18 — REPORT.md
## Threat Hunt: Data Exfiltration Patterns
**NovaCrest Capital Group | Post-Compromise Hunt**
**Classification:** TLP:AMBER — Security Operations Use
**Author:** V. Willis, CISSP — Hunt Lead
**Date:** 2026-06-18

---

## 1. Hunt Outcome

All six exfiltration hypotheses confirmed. **An estimated 253 MB of data
was exfiltrated from NovaCrest's network** via three simultaneous channels:
DNS tunneling (minor), HTTPS to C2 (primary), and cloud storage upload
(secondary). Automated scheduled transfers continued for at least 1 hour
post-initial exfil. No real-time alerts fired during the 20-hour window.

| Metric | Result |
|--------|--------|
| Hypotheses tested | 6 |
| Confirmed | 6 (100%) |
| Estimated data exfiltrated | ~253 MB |
| Exfil channels used | 3 (DNS, HTTPS C2, S3) |
| Time from escalation to first exfil | ~75 minutes |
| Scheduled transfers confirmed | ≥ 3 at 30-min intervals |
| Real-time alerts fired | 0 |
| Log evidence available | All 6 techniques logged in Zeek |

---

## 2. ATT&CK Coverage

| Technique | Confirmed | Evidence Source |
|-----------|-----------|-----------------|
| T1048.001 DNS Tunneling | ✅ | Zeek dns.log — TXT/NULL queries; 5 high-entropy subdomains |
| T1048.002 HTTPS Exfil | ✅ | Zeek ssl.log — Cobalt Strike JA3; self-signed cert |
| T1560.001 Archive/Stage | ✅ | Zeek files.log — 125 MB .tar.gz; auditd tar execution |
| T1567.002 Cloud Storage | ✅ | Zeek ssl.log — S3 upload 85 MB to attacker bucket |
| T1030 Transfer Limits | ✅ | Zeek conn.log — 247 MB total egress (4.9× baseline) |
| T1029 Scheduled Transfer | ✅ | Zeek conn.log — 3 transfers at 30-min intervals |

---

## 3. Three-Week Kill Chain (Days 15–18)

```
Day 15 — Reconnaissance
  CT logs → 47 subdomains
  GitHub → 8 hardcoded credentials exposed
  340+ employee emails harvested

Day 16 — Initial Access
  AWS admin achieved via GitHub-exposed key
  PostgreSQL database authenticated
  Phishing email crafted (link + attachment variants)

Day 17 — Privilege Escalation
  SYSTEM via token impersonation (fodhelper UAC bypass)
  Kerberoasting: 3 service account hashes extracted
  root via NOPASSWD sudo GTFOBin (find -exec /bin/bash)

Day 18 — Data Exfiltration
  Staging: 125 MB trading archive (tar)
  Exfil Ch1: DNS tunnel (small volume; C2 check-in)
  Exfil Ch2: 125 MB HTTPS to Cobalt Strike C2
  Exfil Ch3: 85 MB S3 upload to attacker bucket
  Automated: 30-min recurring transfers ongoing
  DWELL TIME: 4 days; 0 alerts total
```

---

## 4. Key Findings

**Finding 1 — Zeek Logged Everything; Nothing Was Alerted (Critical)**
All six exfiltration techniques are clearly visible in Zeek logs. The
detection infrastructure is functioning — the alerting layer is absent.
This is the same root cause pattern identified in Days 16 and 17: logs
exist, SIEM integration is missing, rules are not deployed.

**Finding 2 — Multi-Channel Redundancy (High)**
The attacker used three simultaneous exfil channels. Even if one were
blocked (e.g., NGFW blocks the C2 domain), the S3 upload and DNS tunnel
would continue. Defense requires blocking at multiple layers — DNS, HTTPS
inspection, and cloud egress — not just one.

**Finding 3 — Attacker-Controlled S3 Bucket Blends with Legitimate AWS (High)**
`novacrest-exfil.s3.amazonaws.com` is easily confused with org-owned AWS
buckets. Standard AWS CloudTrail monitors data events on your own buckets,
not attacker-controlled buckets. The DLP gap here is structural — standard
tooling doesn't cover data going to external AWS accounts.

**Finding 4 — Regulatory Notification Required (Critical)**
Client account balance data (4 MB) and client PII were exfiltrated. SEC
Regulation S-P requires notification within 30 days. Legal hold on
`lnx-trade-01`, `WS-FIN-04`, and related systems is required now.

---

## 5. Immediate Response Actions

```
NETWORK (IMMEDIATE)
  □ Block 198.51.100.99 and 198.51.100.1 at NGFW
  □ Block novacrest-exfil.s3.amazonaws.com at DNS and proxy
  □ Block t1.evil-c2.com and data-xfer.evil-c2.com
  □ Enable emergency TLS inspection on perimeter NGFW

EVIDENCE PRESERVATION
  □ Legal hold: preserve WS-FIN-04, lnx-trade-01, lnx-db-01 disk images
  □ Export Zeek logs for hunt window (2026-06-14 08:00 → 2026-06-15 06:00)
  □ Export CloudTrail logs for AWS account (full 30 days)
  □ Request S3 access logs from AWS for novacrest-exfil bucket

NOTIFICATIONS
  □ Notify CISO and General Counsel today
  □ Initiate SEC Regulation S-P breach assessment
  □ Notify affected customers within 30 days (if assessment confirms breach)
  □ Contact Bloomberg regarding API key compromise

SIEM (THIS WEEK)
  □ Forward Zeek logs to Splunk/Sentinel (still pending from Day 16)
  □ Deploy SPL Queries H1-A through CORR-1 as scheduled alerts
  □ Configure UEBA baseline (30-day rolling; 3σ alert threshold)
  □ Enable Microsoft Purview Endpoint DLP on all Windows workstations
```

---

## 6. Day 19 Preview

**Next session:** Log Forensics & SIEM (Forensics track)

With four days of intrusion activity now documented, Day 19 shifts to the
forensics track: reconstruct the full attack timeline from fragmented log
sources (Windows Event Log, Zeek, auditd, Exchange, M365), build a unified
timeline using Plaso/log2timeline, and produce an analyst-ready SIEM
dashboard showing the complete kill chain from recon to exfiltration.

---

## 7. Git Commit Commands

```bash
cd security-portfolio-30days
git checkout main && git pull origin main

mkdir -p days/day-18/{scripts,queries,reports}
cp /path/to/outputs/day18/SCENARIO.md days/day-18/
cp /path/to/outputs/day18/LAB.md days/day-18/
cp /path/to/outputs/day18/REPORT.md days/day-18/
cp /path/to/outputs/day18/scripts/* days/day-18/scripts/
cp /path/to/outputs/day18/queries/* days/day-18/queries/
cp /path/to/outputs/day18/reports/* days/day-18/reports/

git add days/day-18/

git commit -m "feat: Add Day 18 — Threat Hunt: Data Exfiltration Patterns

Track: Threat Hunting | Tools: Zeek, UEBA, DLP
MITRE ATT&CK: T1048.001, T1048.002, T1560.001, T1567.002, T1030, T1029

Hunt results: 6/6 hypotheses confirmed
  H1 T1048.001 DNS Tunneling      → CONFIRMED (TXT/NULL; 5 queries; iodine)
  H2 T1048.002 HTTPS Exfil        → CONFIRMED (Cobalt Strike JA3; 125 MB)
  H3 T1560.001 Data Staging       → CONFIRMED (125 MB .tar.gz; Zeek files.log)
  H4 T1567.002 Cloud Storage Exfil→ CONFIRMED (85 MB S3; novacrest-exfil bucket)
  H5 T1030 Volumetric Anomaly     → CONFIRMED (247 MB total; 4.9× baseline)
  H6 T1029 Scheduled Transfer     → CONFIRMED (3 transfers at 30-min intervals)

Estimated exfiltrated: 253 MB (trading algos, Bloomberg key, client data)
Zero real-time alerts despite full Zeek log coverage
Regulatory breach: SEC Reg S-P notification required (client PII exfiltrated)

Files:
  SCENARIO.md, LAB.md, REPORT.md
  scripts/exfil_hunt_engine.py (Zeek log parser; 6-hypothesis detector)
  scripts/dns_tunnel_detector.py (Shannon entropy; burst analysis; scoring)
  queries/splunk_exfil_hunt.spl (H1–H6 + kill chain correlation)
  queries/sentinel_exfil_hunt.kql (H1–H6 + CORR-1)
  reports/day18_hunt_findings.md (per-hypothesis evidence + timeline)
  reports/day18_exfil_playbook.md (detection playbook + DLP checklist)"

git push origin main
```

---

*Day 18 — Threat Hunt: Data Exfiltration Patterns*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
