# 30-Day AI-Augmented Security Analyst Portfolio
**V. Willis, CISSP · Senior Cybersecurity Professional**  
🔗 [Live Site](https://blaakpearl.github.io/security-portfolio-30days/)

---

## What This Is

A structured, day-by-day demonstration of enterprise security operations
workflows applied to a realistic financial services breach scenario —
from the first phishing email through ransomware response, threat actor
attribution, and detection engineering.

Every day produces working, production-grade artifacts: Python scripts,
Sigma/KQL/EQL detection rules, Splunk and Sentinel queries, YARA rules,
STIX 2.1 bundles, and analyst-grade reports. All techniques are grounded
in the MITRE ATT&CK framework and tied to real forensic evidence from the
simulated NovaCrest Capital Group incident.

---

## The Scenario

**Target:** NovaCrest Capital Group — fictional investment management firm,
$4.2B AUM, New York  
**Threat actor:** FIN-NC-001 (attributed to GOLD MYSTIC / LockBit affiliate)  
**Incident:** Double-extortion ransomware — data exfiltrated, then 2,215 GB
encrypted; $4.2M demand  
**Dwell time:** 5 days undetected  
**Root cause:** Public Instagram photo with intact GPS → spearphishing lure

---

## Portfolio Structure

```
days/
├── day-01/   External Recon & OSINT
├── day-02/   Credential Hunting
├── day-03/   Phishing Infrastructure
├── day-04/   Network Anomaly Detection
├── day-05/   Social Engineering Surface
├── day-06/   Endpoint Persistence Hunt
├── day-07/   Week 1 Capstone
├── day-08/   Malware Triage
├── day-09/   Dark Web Intelligence
├── day-10/   Lateral Movement Detection
├── day-11/   Geo-IP & Location Intel
├── day-12/   Memory Forensics
├── day-13/   MITRE ATT&CK Mapping
├── day-14/   Week 2 Capstone
├── day-15/   Red Team Recon Simulation
├── day-16/   Initial Access (Sliver C2)
├── day-17/   Privilege Escalation Hunt
├── day-18/   Data Exfil Pattern Detection
├── day-19/   Log Forensics & SIEM
├── day-20/   C2 Detection Exercise
├── day-21/   Week 3 Full-Stack Capstone
├── day-22/   Risk Scoring Framework
├── day-23/   Mobile Device OSINT
├── day-24/   Cloud Infrastructure Hunt
├── day-25/   Ransomware Forensics
├── day-26/   Threat Actor Profiling
├── day-27/   Detection Engineering
├── day-28/   OSINT Investigation Report
├── day-29/   AI Agent Integration
└── day-30/   Portfolio Capstone ← You are here
```

Each day contains:
- `SCENARIO.md` — What, why, and how
- `LAB.md` — Hands-on walkthrough with real tool commands
- `REPORT.md` — Findings and conclusions
- `scripts/` — Working Python tools
- `queries/` — Splunk SPL + Sentinel KQL
- `reports/` — Analyst-grade reports
- `artifacts/` — STIX bundles, YARA rules, JSON evidence

---

## By the Numbers

| Metric | Value |
|--------|-------|
| Days completed | 30 |
| ATT&CK techniques documented | 37 |
| Detection rules engineered | 12 (Sigma + EQL + YARA) |
| Python scripts | 52 |
| Splunk SPL queries | 87 |
| KQL queries | 72 |
| STIX 2.1 objects | 47 |
| Prior victims identified (OSINT) | 3 confirmed |
| Ransomware MTTD: before → after | 2h 50min → <60 seconds |
| AI triage latency | 2.3s vs. 18-min manual |

---

## Highlights By Track

### 🔵 Threat Intelligence (Days 3, 9, 13, 22, 26)
- Full threat actor profile for FIN-NC-001 (Admiralty B2, 78% confidence)
- STIX 2.1 bundle with 14 objects (TLP:AMBER, FS-ISAC ready)
- CVSS 3.1 + DREAD + ATT&CK tier risk scoring across 10 findings
- Campaign pattern analysis: 4 victims; 50-day cadence; ransom = 0.1% AUM

### 🔴 Digital Forensics (Days 8, 12, 19, 25)
- Volatility3 memory forensics: PE extracted from PID 3412; shellcode in lsass.exe
- 7-phase attack timeline with EDT/UTC clock skew correction
- LockBit 3.0 variant confirmed via Ghidra code diff
- 14 YARA rules; 8-item chain of custody; court-ready forensic report

### 🟠 Threat Hunting (Days 4, 10, 17, 18, 24)
- 18/18 hypotheses confirmed across three hunt days (6 each)
- Cloud hunt: 6/6 confirmed; 2 active IAM backdoors found post-IR
- 293 MB total exfiltration quantified across HTTPS, DNS, and S3 channels

### 🟢 Purple Team (Days 6, 15–16, 20–21, 27)
- Week 3 capstone: 32/40 (80%); Mean MTTD 12.3 min
- C2 exercise: Sliver (T+3:22), domain fronting (T+34:10), Havoc missed (DoH)
- 12 detection rules; DET-009 reduces ransomware MTTD from 2h 50min to <60s
- GitHub Actions CI/CD: 24/24 tests passing; syntax → convert → unit test → deploy

### 🟡 OSINT (Days 1, 5, 11, 23, 28)
- FinTech Summit Instagram photo (GPS + hashtag) → spearphishing lure
- 4/5 public employee photos geotagged; office location confirmed from official Twitter post
- Infrastructure graph: 18 nodes, 22 edges; Maltego/i2 compatible
- Next FIN-NC-001 campaign predicted: ~August 2026

### ⚪ Full Stack + AI (Days 7, 14, 21, 29–30)
- AI triage agent: 5/5 NCA-2026-06 alerts correctly triaged in avg 2.3s
- IOC enrichment pipeline: 7/7 IOCs classified; STIX patterns generated
- Claude API + LangChain + FastAPI: production-ready webhook endpoint
- Human-in-the-loop enforced throughout; all outputs labeled DRAFT

---

## Tools Referenced

Zeek · Splunk · Elastic · Sentinel · Sigma · Volatility3 · Autopsy · FTK
Imager · Ghidra · YARA · Sliver · Cobalt Strike · Havoc · AWS CloudTrail ·
GuardDuty · Pacu · Maltego · i2 Analyst · Shodan · SpiderFoot · ExifTool ·
Sherlock · OpenCTI · STIX 2.1 · TAXII · VirusTotal · Ransomwatch · Jamf Pro ·
Claude API · LangChain · FastAPI · GitHub Actions · MITRE ATT&CK · CVSS 3.1

---

## About

**V. Willis, CISSP** — Senior cybersecurity professional with ~14 years of
experience across enterprise, regulated-industry, and government contracting.
Past roles at Cisco, NBCUniversal, NextEra Energy, and HHS OIG. MSc
Cybersecurity (WGU). Core expertise in MITRE ATT&CK, SAST/DAST, GenAI
security, NIST RMF, and penetration testing.

🔗 [GitHub](https://github.com/Blaakpearl) ·
[LinkedIn](https://linkedin.com/in/jhenderson-finance) ·
[Portfolio](https://blaakpearl.github.io/security-portfolio-30days/)

---

*All scenario data, company names, and personal information are entirely
fictional and created for portfolio demonstration purposes. No real individuals,
organizations, or systems are represented.*
