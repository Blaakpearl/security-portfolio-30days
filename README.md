# 🔐 Blaakpearl — 30-Day Security Research Portfolio

> **AI-augmented security operations across Threat Hunting, OSINT, Digital Forensics, Purple Teaming & MITRE ATT&CK**

[![Portfolio Dashboard](https://img.shields.io/badge/Live_Dashboard-GitHub_Pages-00d4ff?style=flat-square&logo=github)](https://blaakpearl.github.io/security-portfolio-30days)
[![ATT&CK Coverage](https://img.shields.io/badge/MITRE_ATT%26CK-47%2B_Techniques-a855f7?style=flat-square)](https://attack.mitre.org)
[![Days Complete](https://img.shields.io/badge/Days_Complete-30%2F30-00ff88?style=flat-square)]()
[![AI Agents](https://img.shields.io/badge/AI_Agents-6_Active-ffb700?style=flat-square)]()

---

## 🎯 Mission Brief

This portfolio documents a structured 30-day security research and skills rebuild program across five specialty domains. Each day produces three professional deliverables — a threat scenario, hands-on lab guide, and analyst report — all mapped to MITRE ATT&CK.

A suite of **6 Claude-powered AI agents** accelerates research, generates detection queries, maps TTPs, and produces report drafts — demonstrating AI-augmented security operations.

**[→ View the Interactive Dashboard](https://blaakpearl.github.io/security-portfolio-30days)**

---

## 📊 Skill Matrix

| Domain | Days | Tools | ATT&CK Coverage |
|--------|------|-------|-----------------|
| 🔍 **OSINT** | 1, 5, 11, 23, 28 | Maltego, Shodan, SpiderFoot, Sherlock, ExifTool | T1590, T1591, T1589, T1596 |
| 🎯 **Threat Hunting** | 2, 4, 10, 17, 18, 24 | Zeek, Velociraptor, Splunk, OSQuery, CloudTrail | T1071, T1550, T1548, T1041 |
| 🧠 **Threat Intelligence** | 3, 9, 13, 22, 26 | VirusTotal, ATT&CK Navigator, OpenCTI, STIX/TAXII | T1566, T1597, T1583, T1584 |
| ⚔️ **Purple Teaming** | 6, 15, 16, 20, 21, 27 | Sliver C2, GoPhish, Cobalt Strike, Sigma, KQL | T1053, T1547, T1071, T1573 |
| 🔬 **Digital Forensics** | 8, 12, 19, 25 | Volatility3, Autopsy, Cuckoo, Ghidra, YARA | T1055, T1003, T1486, T1070 |
| 🚀 **AI Agents / Capstone** | 7, 14, 21, 29, 30 | Claude API, Python, GitHub Actions, LangChain | All phases |

---

## 📅 30-Day Log

| Day | Title | Track | Key Tools | Deliverables |
|-----|-------|-------|-----------|--------------|
| [01](days/day-01/) | Recon & Footprinting | OSINT | Shodan, Maltego, Censys | [Scenario](days/day-01/SCENARIO.md) · [Lab](days/day-01/LAB.md) · [Report](days/day-01/REPORT.md) |
| [02](days/day-02/) | Credential Exposure Hunt | Threat Hunt | HaveIBeenPwned, Splunk | [Scenario](days/day-02/SCENARIO.md) · [Lab](days/day-02/LAB.md) · [Report](days/day-02/REPORT.md) |
| [03](days/day-03/) | Phishing Infrastructure | Threat Intel | VirusTotal, URLScan, Any.run | [Scenario](days/day-03/SCENARIO.md) · [Lab](days/day-03/LAB.md) · [Report](days/day-03/REPORT.md) |
| [04](days/day-04/) | Network Traffic Anomalies | Threat Hunt | Zeek, Wireshark, Sigma | [Scenario](days/day-04/SCENARIO.md) · [Lab](days/day-04/LAB.md) · [Report](days/day-04/REPORT.md) |
| [05](days/day-05/) | Social Engineering Surface | OSINT | OSINT Framework, Sherlock | [Scenario](days/day-05/SCENARIO.md) · [Lab](days/day-05/LAB.md) · [Report](days/day-05/REPORT.md) |
| [06](days/day-06/) | Endpoint Persistence Hunt | Purple Team | Velociraptor, OSQuery, Sysmon | [Scenario](days/day-06/SCENARIO.md) · [Lab](days/day-06/LAB.md) · [Report](days/day-06/REPORT.md) |
| [07](days/day-07/) | Week 1 Capstone | Full Stack | ATT&CK Navigator, Splunk | [Scenario](days/day-07/SCENARIO.md) · [Lab](days/day-07/LAB.md) · [Report](days/day-07/REPORT.md) |
| [08](days/day-08/) | Malware Triage | Forensics | YARA, Cuckoo, Ghidra | [Scenario](days/day-08/SCENARIO.md) · [Lab](days/day-08/LAB.md) · [Report](days/day-08/REPORT.md) |
| [09](days/day-09/) | Dark Web Intelligence | Threat Intel | OnionScan, Dark Web Monitoring | [Scenario](days/day-09/SCENARIO.md) · [Lab](days/day-09/LAB.md) · [Report](days/day-09/REPORT.md) |
| [10](days/day-10/) | Lateral Movement Detection | Threat Hunt | BloodHound, Windows Events | [Scenario](days/day-10/SCENARIO.md) · [Lab](days/day-10/LAB.md) · [Report](days/day-10/REPORT.md) |
| [11](days/day-11/) | Geo-IP & Attribution | OSINT | Shodan, BGP Tools, MaxMind | [Scenario](days/day-11/SCENARIO.md) · [Lab](days/day-11/LAB.md) · [Report](days/day-11/REPORT.md) |
| [12](days/day-12/) | Memory Forensics | Forensics | Volatility3, WinPmem | [Scenario](days/day-12/SCENARIO.md) · [Lab](days/day-12/LAB.md) · [Report](days/day-12/REPORT.md) |
| [13](days/day-13/) | MITRE ATT&CK Mapping | Threat Intel | ATT&CK Navigator, D3FEND | [Scenario](days/day-13/SCENARIO.md) · [Lab](days/day-13/LAB.md) · [Report](days/day-13/REPORT.md) |
| [14](days/day-14/) | Week 2 Capstone | Full Stack | OpenCTI, STIX, AI Agents | [Scenario](days/day-14/SCENARIO.md) · [Lab](days/day-14/LAB.md) · [Report](days/day-14/REPORT.md) |
| [15](days/day-15/) | Red Team Recon Op | Purple Team | Amass, TruffleHog, Shodan | [Scenario](days/day-15/SCENARIO.md) · [Lab](days/day-15/LAB.md) · [Report](days/day-15/REPORT.md) |
| [16](days/day-16/) | Initial Access Simulation | Purple Team | GoPhish, HTML Smuggling | [Scenario](days/day-16/SCENARIO.md) · [Lab](days/day-16/LAB.md) · [Report](days/day-16/REPORT.md) |
| [17](days/day-17/) | Privilege Escalation Hunt | Threat Hunt | BloodHound, Kerberoast | [Scenario](days/day-17/SCENARIO.md) · [Lab](days/day-17/LAB.md) · [Report](days/day-17/REPORT.md) |
| [18](days/day-18/) | Data Exfiltration Patterns | Threat Hunt | Zeek, UEBA, DLP Tools | [Scenario](days/day-18/SCENARIO.md) · [Lab](days/day-18/LAB.md) · [Report](days/day-18/REPORT.md) |
| [19](days/day-19/) | Log Forensics & SIEM | Forensics | Elastic SIEM, Sysmon, Plaso | [Scenario](days/day-19/SCENARIO.md) · [Lab](days/day-19/LAB.md) · [Report](days/day-19/REPORT.md) |
| [20](days/day-20/) | Purple Team C2 Exercise | Purple Team | Sliver C2, Zeek, EDR | [Scenario](days/day-20/SCENARIO.md) · [Lab](days/day-20/LAB.md) · [Report](days/day-20/REPORT.md) |
| [21](days/day-21/) | Week 3 Capstone | Full Stack | Full Purple Stack | [Scenario](days/day-21/SCENARIO.md) · [Lab](days/day-21/LAB.md) · [Report](days/day-21/REPORT.md) |
| [22](days/day-22/) | Risk Scoring Framework | Threat Intel | CVSS, DREAD, ATT&CK | [Scenario](days/day-22/SCENARIO.md) · [Lab](days/day-22/LAB.md) · [Report](days/day-22/REPORT.md) |
| [23](days/day-23/) | Mobile Device OSINT | OSINT | ExifTool, CellHawk, MDM | [Scenario](days/day-23/SCENARIO.md) · [Lab](days/day-23/LAB.md) · [Report](days/day-23/REPORT.md) |
| [24](days/day-24/) | Cloud Infrastructure Hunt | Threat Hunt | CloudTrail, GuardDuty, Pacu | [Scenario](days/day-24/SCENARIO.md) · [Lab](days/day-24/LAB.md) · [Report](days/day-24/REPORT.md) |
| [25](days/day-25/) | Ransomware Forensics | Forensics | Autopsy, FTK, Volatility3 | [Scenario](days/day-25/SCENARIO.md) · [Lab](days/day-25/LAB.md) · [Report](days/day-25/REPORT.md) |
| [26](days/day-26/) | Threat Actor Profiling | Threat Intel | OpenCTI, STIX 2.1, TAXII | [Scenario](days/day-26/SCENARIO.md) · [Lab](days/day-26/LAB.md) · [Report](days/day-26/REPORT.md) |
| [27](days/day-27/) | Detection Engineering | Purple Team | Sigma, KQL, YARA, Elastic | [Scenario](days/day-27/SCENARIO.md) · [Lab](days/day-27/LAB.md) · [Report](days/day-27/REPORT.md) |
| [28](days/day-28/) | OSINT Investigation Report | OSINT | Maltego, i2 Analyst | [Scenario](days/day-28/SCENARIO.md) · [Lab](days/day-28/LAB.md) · [Report](days/day-28/REPORT.md) |
| [29](days/day-29/) | AI Agent Integration | Full Stack | Claude API, Python, LangChain | [Scenario](days/day-29/SCENARIO.md) · [Lab](days/day-29/LAB.md) · [Report](days/day-29/REPORT.md) |
| [30](days/day-30/) | Portfolio Capstone | Full Stack | All tools, GitHub Pages | [Scenario](days/day-30/SCENARIO.md) · [Lab](days/day-30/LAB.md) · [Report](days/day-30/REPORT.md) |

---

## 🤖 AI Agent Architecture

Six Claude-powered agents automate and accelerate security research workflows:

```
INPUT → Orchestrator → OSINT Agent | ThreatHunt Agent | Forensics Agent | ThreatIntel Agent
                    → MITRE Mapper Agent → Report Generator → GitHub Markdown
```

| Agent | Role | File |
|-------|------|------|
| Orchestrator | Routes tasks, manages pipeline | [agents/orchestrator.py](agents/orchestrator.py) |
| OSINT Agent | Passive intel gathering | [agents/osint_agent.py](agents/osint_agent.py) |
| ThreatHunt Agent | Hunt query generation | [agents/threat_hunt_agent.py](agents/threat_hunt_agent.py) |
| Forensics Agent | Artifact analysis & timelines | [agents/forensics_agent.py](agents/forensics_agent.py) |
| MITRE Mapper | ATT&CK technique mapping | [agents/mitre_mapper_agent.py](agents/mitre_mapper_agent.py) |
| Report Generator | GitHub-ready markdown output | [agents/report_generator.py](agents/report_generator.py) |

---

## 📁 Repository Structure

```
security-portfolio-30days/
├── index.html              # Interactive dashboard (GitHub Pages)
├── README.md
├── agents/                 # AI agent Python codebase
├── days/                   # 30 daily entries (scenario + lab + report)
│   ├── day-01/
│   │   ├── SCENARIO.md
│   │   ├── LAB.md
│   │   ├── REPORT.md
│   │   └── artifacts/
│   └── ... (day-02 through day-30)
├── tools/                  # Reusable security tooling scripts
├── templates/              # Standard scenario/lab/report templates
├── mitre/                  # ATT&CK mappings and Navigator layers
└── .github/workflows/      # CI/CD for GitHub Pages
```

---

## 🛠 Tools & Technologies

**OSINT:** Maltego · Shodan · Censys · SpiderFoot · Sherlock · ExifTool · OSINT Framework  
**Threat Hunting:** Zeek · Velociraptor · OSQuery · Splunk · Elastic SIEM · CloudTrail  
**Threat Intel:** VirusTotal · URLScan · Any.run · OpenCTI · STIX/TAXII · ATT&CK Navigator  
**Purple Team:** Sliver C2 · GoPhish · Cobalt Strike · Sigma · KQL · YARA · GitHub Actions  
**Forensics:** Volatility3 · Autopsy · FTK Imager · Cuckoo · Ghidra · YARA · Plaso  
**AI/Dev:** Claude API · Python · LangChain · GitHub Actions · GitHub Pages

---

## 📬 Contact

**GitHub:** [@Blaakpearl](https://github.com/Blaakpearl)  
**Email:** blaakpearl@yahoo.com  
**Interests:** Red/Blue/Purple Teams · OSINT · Digital Forensics · Threat Hunting · AI + Security

---

*Built with Claude AI — demonstrating AI-augmented security analyst workflows*
