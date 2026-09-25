# Portfolio Skill Matrix
## 30-Day AI-Augmented Security Analyst
**V. Willis, CISSP | github.com/Blaakpearl/security-portfolio-30days**

---

## By Domain

### Threat Intelligence
| Skill | Tool/Method | Days | Evidence |
|-------|------------|------|---------|
| IOC pivoting (IP/hash/domain/email) | VirusTotal, OTX, Shodan | 26, 28 | C2 IP fully mapped; 4-victim cluster |
| STIX 2.1 bundle production | python-stix2, OpenCTI | 26 | 14-object bundle, TLP:AMBER |
| TAXII feed integration | taxii2-client | 26 | FS-ISAC + CISA AIS config |
| ATT&CK technique mapping | MITRE ATT&CK Navigator | 13, 21, 26 | 37 techniques documented |
| Threat actor profiling | Admiralty Code, Diamond Model | 26 | FIN-NC-001 78% confidence |
| Risk scoring (CVSS/DREAD) | CVSS 3.1, DREAD, ATT&CK tier | 22 | 10 findings, mean CVSS 8.77 |
| Dark web monitoring | Ransomwatch, Tor | 26, 28 | Leak site tracked; 4 victims |
| Campaign timeline analysis | Custom Python | 28 | 4-victim timeline; next campaign predicted |

### Digital Forensics
| Skill | Tool/Method | Days | Evidence |
|-------|------------|------|---------|
| Disk acquisition | FTK Imager, dcfldd | 25 | SRV-FS-01 E01 image |
| Memory forensics | Volatility3 (pslist/malfind/netstat) | 12, 25 | svchost32.exe PID 3412; PE extracted |
| Timeline reconstruction | log2timeline, plaso, Elastic | 19 | 7-phase attack timeline; EDT skew |
| Log tampering detection | Custom Python, Splunk | 19 | 649 missing Security events |
| Ransomware analysis | Autopsy, Ghidra, YARA | 25 | LockBit 3.0 variant confirmed |
| Chain of custody | Evidence manifest JSON | 19, 25 | 8 items SHA256+MD5 documented |
| YARA rule authoring | YARA | 25, 27 | 14 rules across 2 days |
| Encryption analysis | Ghidra, bcrypt/ncrypt DLL | 25 | AES-256-CBC + RSA-4096 confirmed |

### Threat Hunting
| Skill | Tool/Method | Days | Evidence |
|-------|------------|------|---------|
| Hypothesis-driven hunting | PEAK methodology | 17, 18, 24 | 6/6 confirmed each day |
| Privilege escalation hunt | Splunk, BloodHound | 17 | 6 hypotheses; SYSTEM achieved |
| Data exfiltration detection | Zeek, Splunk, DNS entropy | 18 | 253 MB quantified; DNS tunnel |
| Cloud infrastructure hunt | CloudTrail, GuardDuty | 24 | 2 backdoors found; 82 MB exfil |
| C2 beacon detection | Zeek, JA3/JARM, Elastic | 20 | 4 C2 variants; MTTD measured |
| Lateral movement detection | Event logs, PtT/PtH | 10, 21 | Pass-the-Ticket confirmed |
| Log source: Windows Event | Splunk, Elastic | 17, 19 | Events 4648/4624/4698/1102 |
| Log source: AWS CloudTrail | Splunk, KQL | 24 | 20 simulated events; 6 hypotheses |

### Purple Team / Detection Engineering
| Skill | Tool/Method | Days | Evidence |
|-------|------------|------|---------|
| Sigma rule authoring | sigma-cli | 20, 27 | 19 rules total; metadata complete |
| SIEM query authoring (SPL) | Splunk | All days | 87 SPL queries across portfolio |
| SIEM query authoring (KQL) | Sentinel | All days | 72 KQL queries across portfolio |
| Elastic EQL | Elastic Security | 27 | 6 EQL rules; sequence + threshold |
| Detection-as-code (CI/CD) | GitHub Actions | 27 | Full pipeline; 24/24 tests passing |
| FP rate analysis | Custom Python + Splunk | 27 | DET-003/010 tuning documented |
| ATT&CK coverage measurement | Custom JSON matrix | 27 | 0% → 44% post-engineering |
| Purple team exercise design | MTTD scoring | 21 | 8-phase; 32/40; 6/8 SLA |

### OSINT
| Skill | Tool/Method | Days | Evidence |
|-------|------------|------|---------|
| Passive DNS pivoting | DNSDB, VirusTotal | 28 | 6 domains; 4 victims mapped |
| Certificate transparency | crt.sh, Censys | 28 | Let's Encrypt timing signal |
| Social media OSINT | LinkedIn, Instagram, Sherlock | 1, 5, 23 | Conference lure traced to IG photo |
| EXIF metadata analysis | ExifTool | 23 | 4/5 photos GPS; office confirmed |
| Mobile device OSINT | Jamf Pro, MDM | 23 | iPhone MDM check-in = phishing vector |
| Infrastructure mapping | Maltego, i2, Shodan | 28 | 18-node graph; 2 C2 IPs; 6 domains |
| Dark web monitoring | Ransomwatch | 28 | NovaCrest leak site tracked |
| Campaign tracking | Custom Python | 28 | 50-day cadence; next target predicted |

### Cloud Security
| Skill | Tool/Method | Days | Evidence |
|-------|------------|------|---------|
| CloudTrail analysis | AWS CLI, Python | 24 | 6/6 hypotheses; full attacker timeline |
| IAM backdoor detection | Custom Python | 24 | svc-monitoring-ops + CrossAccountReadRole |
| GuardDuty (enable/disable) | AWS API | 24 | GD tamper at 09:05:18 documented |
| AWS hardening | AWS CLI, Config | 24 | Checklist: CloudTrail/GD/IAM/S3/EC2 |
| Secrets Manager forensics | CloudTrail | 24 | 3 secrets harvested; rotation documented |
| S3 exfiltration analysis | CloudTrail data events | 24 | 82 MB; 3 objects; data classification |

### AI / Full Stack
| Skill | Tool/Method | Days | Evidence |
|-------|------------|------|---------|
| Claude API (tool use) | anthropic SDK | 29 | Triage agent with agentic loop |
| LangChain agent design | LangChain + ChatAnthropic | 29 | 4 agents with @tool decorators |
| FastAPI endpoint design | FastAPI, uvicorn | 29 | Splunk webhook → AI triage pipeline |
| Prompt engineering | Structured templates | 29 | 6-section triage template |
| Agent evaluation framework | pytest, custom eval | 29 | 5/5 severity; 5/5 ATT&CK |
| STIX automation (Python) | python-stix2 | 26 | Full bundle generator |
| IOC enrichment pipeline | Python + APIs | 26, 29 | 7 IOCs; VT/Shodan/OTX simulated |

---

## By ATT&CK Tactic (37 Techniques)

| Tactic | # Techniques | Representative Work |
|--------|-------------|---------------------|
| Reconnaissance | 4 | Days 15, 23: conference OSINT → spearphish lure |
| Initial Access | 2 | Day 16: Sliver via macro; confirmed Jun 14 |
| Execution | 4 | Days 16, 25: WMI → ransomware; PowerShell hunt |
| Persistence | 5 | Days 17, 24, 25: service + registry + IAM backdoors |
| Privilege Escalation | 3 | Day 17: UAC, token impersonation, Kerberoasting |
| Defense Evasion | 5 | Days 19, 24, 25: log clearing, cloud logs, AV disable |
| Credential Access | 4 | Days 17, 24, 25: Kerberoasting, LSASS, cloud secrets |
| Discovery | 3 | Day 24: cloud enumeration; SageMaker, S3, EC2 |
| Lateral Movement | 2 | Days 21, 25: PtT to SRV-AD-01 → SRV-FS-01 |
| Collection | 3 | Days 18, 23, 24: exfil patterns, location, S3 data |
| Command & Control | 4 | Day 20: Sliver, Havoc, domain fronting, DoH |
| Exfiltration | 3 | Day 18: HTTPS, DNS, S3 channels; 293 MB total |
| Impact | 3 | Day 25: encryption, recovery inhibit, service stop |

---

## Tools Demonstrated (43 distinct tools)

**Network:** Zeek, Wireshark, NetworkMiner, Nmap  
**SIEM/Detection:** Splunk, Elastic, Sentinel, Sigma, EQL  
**Forensics:** Autopsy, FTK Imager, Volatility3, log2timeline  
**Malware Analysis:** Ghidra, YARA, CrowdStrike Falcon, Cuckoo  
**C2/Red Team:** Sliver, Cobalt Strike, Havoc, Metasploit  
**Cloud:** AWS CloudTrail, GuardDuty, Pacu, CloudFox  
**OSINT:** Maltego, i2, Shodan, SpiderFoot, ExifTool, Sherlock, crt.sh  
**Threat Intel:** OpenCTI, STIX 2.1, TAXII, VirusTotal, OTX, Ransomwatch  
**Mobile:** Jamf Pro, MDM APIs, CellHawk  
**AI/Dev:** Claude API, LangChain, FastAPI, Python, GitHub Actions  
**Frameworks:** MITRE ATT&CK, NIST RMF, CVSS 3.1, Admiralty Code  

---

*Portfolio Skill Matrix | V. Willis, CISSP*
*github.com/Blaakpearl/security-portfolio-30days*
