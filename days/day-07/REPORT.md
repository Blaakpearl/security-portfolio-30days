# Week 1 Capstone Report
## Day 07 — Full Kill Chain Synthesis: NovaCrest Capital Group Incident

---

| Field | Details |
|-------|---------|
| **Analyst** | Blaakpearl |
| **Report Date** | 2025-01-16 |
| **Report Type** | Incident Synthesis — Week 1 Kill Chain Capstone |
| **Classification** | Portfolio / Training Exercise |
| **Target (Fictional)** | NovaCrest Capital Group |
| **Track** | Full Stack |
| **Case ID** | NVC-IR-2025-004 |
| **Days Covered** | 01 through 07 |
| **ATT&CK Techniques** | 38 confirmed across 9 tactics |
| **Dwell Time** | 11 days (Jan 05 – Jan 16, 2025) |

---

## Executive Summary

Over six days of investigation, security operations at NovaCrest Capital Group
reconstructed a complete targeted intrusion by a financially motivated threat
actor designated **PHISH-FIN-2025-Q1**. The intrusion followed a precise
multi-phase attack chain spanning reconnaissance, phishing infrastructure
development, credential harvesting, initial access, persistent C2 beaconing,
DNS-based data exfiltration, and probable endpoint persistence — all executed
within a 12-day window with 11 days of undetected dwell time.

The attack originated with passive reconnaissance using publicly available
open-source intelligence — organizational structure, technology stack from
job postings, email naming convention, and active business deal disclosure
on LinkedIn. A 12-domain phishing infrastructure was constructed on bulletproof
hosting, deploying a reverse-proxy MFA-bypass credential harvester that defeated
the organization's existing MFA controls. Initial access was achieved through
a single phishing click on January 14, 2025; C2 beaconing began within 53
minutes and continued for 11 days before detection via proactive threat hunting.

An estimated **126KB of Fixed Income trading data** was exfiltrated via
DNS TXT record tunneling. The CEO's Microsoft 365 account was accessed from
Ukraine — a confirmed impossible travel event on a C-suite account with no
MFA enforcement. Three endpoint persistence mechanisms were identified as likely
deployed during the dwell period, pending confirmation via forensic imaging.

Detection occurred through **proactive overnight threat hunting**, not automated
alerting. The initial low-confidence EDR alert would have aged out without
analyst review. This report documents the complete kill chain, 38 confirmed
MITRE ATT&CK techniques, a unified IOC package, a detection coverage gap
analysis, and the immediate remediation priorities required to close the
incident.

**This is a fictional training scenario. All organizational names, individuals,
IP addresses, and incident details are fabricated for portfolio demonstration.**

---

## Week 1 Investigation Summary

### What Each Day Established

| Day | Track | Key Finding | ATT&CK Phase |
|-----|-------|-------------|--------------|
| **01** | OSINT | Unpatched VPN portal, DMARC p=none, 47 subdomains exposed | Reconnaissance |
| **02** | Threat Hunt | 312 credentials in breach data, CEO impossible travel, credential stuffing | Credential Access |
| **03** | Threat Intel | 12-domain phishing cluster, MFA-bypass reverse proxy, STIX bundle | Initial Access |
| **04** | Threat Hunt | C2 beacon (CV=0.0018), 11-day dwell, 126KB DNS exfil confirmed | C2 / Exfil |
| **05** | OSINT | Full exec enumeration, tech stack in job postings, MNPI M&A disclosure | Reconnaissance |
| **06** | Purple Team | 3 persistence mechanisms detected, 4 Sigma rules, WMI blind spot found | Persistence |
| **07** | Full Stack | Kill chain synthesis, Navigator layer, IOC master, gap map, exec brief | All phases |

---

## Complete Kill Chain — Phase by Phase

---

### PHASE 1 — Reconnaissance (Days 1–9 Before Access)

**Duration:** January 5–14, 2025 (9 days)
**ATT&CK Tactic:** TA0043 — Reconnaissance

The threat actor conducted exhaustive passive reconnaissance before any
active operations. This is consistent with disciplined, patient APT-level
tradecraft — understanding the target deeply before committing to action.

**What was collected (Day 01 + Day 05 findings):**

```
External Infrastructure:
  • 47 subdomains discovered via Amass + crt.sh (including vpn., dev., staging.)
  • Shodan confirms unpatched GlobalProtect VPN (CVE-2021-3064 — CVSS 9.8)
  • DMARC p=none — domain spoofable for phishing with no rejection controls

Organizational Intelligence:
  • Complete C-suite mapped: CEO, CFO, CTO, CISO with photos and bios
  • Security tool stack revealed via job postings: Splunk, CrowdStrike, Palo Alto
  • Active M&A deal "Apex Partners integration" disclosed on LinkedIn (MNPI risk)
  • IT Director's GitHub reveals internal hostnames and Splunk index naming
  • HR Manager's Gravatar leaks personal Gmail + open enrollment deadline public

Email Intelligence:
  • Naming convention confirmed: firstname.lastname@novacrest-capital.com
  • 34 employee email addresses harvested from public sources
  • CEO email confirmed in 5 breach datasets (MD5/SHA-1 hashed — effectively plaintext)
```

**Technique Coverage:**
T1590, T1590.001, T1591, T1591.002, T1591.004, T1589, T1589.002,
T1589.003, T1596, T1593, T1593.001

---

### PHASE 2 — Resource Development (January 5, 2025)

**Duration:** Single day — coordinated infrastructure build
**ATT&CK Tactic:** TA0042 — Resource Development

All infrastructure was registered and configured on January 5 — a single
coordinated build day suggesting an organized operation rather than opportunistic
targeting. The tight timeline between domain registration (14:32), C2 domain
registration (16:00), and certificate issuance (18:00) indicates scripted
or highly practised infrastructure deployment.

```
14:32 UTC  microsoftonline-portal.com registered (Namecheap — privacy protected)
16:00 UTC  updates.cdn-telemetry-svc.net registered (same registrar, 90 min later)
18:00 UTC  Let's Encrypt wildcard cert issued — *.microsoftonline-portal.com
18:30 UTC  11 additional phishing domains registered — sector-wide campaign scope
20:00 UTC  DNS configured to Flyservers S.A. (AS209588) name servers — Seychelles
```

**Infrastructure cluster scope (Day 03):**
12 domains, all registered January 5–14, all hosted on AS209588 (Flyservers S.A.),
all following `[org-name]-[service].microsoftonline-[word].com` combosquatting pattern.
The phishing kit was a reverse-proxy credential harvester intercepting both
passwords and MFA tokens in real time — defeating TOTP/SMS MFA.

**Technique Coverage:**
T1583, T1583.001, T1584, T1587.003

---

### PHASE 3 — Initial Access (January 14, 2025)

**Duration:** < 1 hour from delivery to compromise
**ATT&CK Tactic:** TA0001 — Initial Access

```
~09:00 UTC  207 phishing emails delivered — "Benefits Enrollment Update Required"
            Subject line timed to open enrollment season (Lisa Williams' LinkedIn post
            confirmed Jan 31 deadline — public OSINT from Day 05)
~09:07 UTC  Mike Thompson (DESKTOP-FIN-047, Fixed Income) clicks phishing link
            Does not submit credentials but malware delivered via drive-by
            Gateway rule fires 2 hours later — 14 emails quarantined retroactively
~22:14 UTC  Separate vector: CEO (j.morrison) account accessed from Ukraine
            Password from LinkedIn 2012 breach (SHA-1, effectively plaintext)
            MFA not enforced — "VIP Users" Conditional Access exclusion
```

**The social engineering precision of the lure was not accidental.** The "Benefits
Enrollment" theme was chosen because open enrollment was active (confirmed by HR
Manager's public LinkedIn post). The lure referenced Workday (confirmed via job
postings). The sending domain mimicked Microsoft (DMARC p=none allowed spoofing
with no controls). All of this intelligence came from Day 05 OSINT — publicly
available, passively gathered.

**Technique Coverage:**
T1566, T1566.001, T1078, T1078.004, T1204.001, T1110.004, T1539

---

### PHASE 4 — Execution & Persistence (January 14–16, 2025)

**Duration:** 11 days — undetected
**ATT&CK Tactics:** TA0002 Execution / TA0003 Persistence

```
~09:12 UTC (Jan 14)  First C2 beacon fires — 60.3s interval, CV=0.0018
~09:12 UTC           Malware payload executed via PowerShell (T1059.001)
~14:00 UTC (Jan 14)  DNS TXT exfil channel activated — Base64 encoded data
Jan 05–16 (est.)     Persistence mechanisms deployed — forensic confirmation pending:
                       • Scheduled Task (T1053.005) — 60-min interval
                       • Registry Run Key (T1547.001) — HKCU logon persistence
                       • WMI Event Subscription (T1546.003) — boot persistence
```

The persistence mechanisms were identified as likely deployed based on the Day 06
purple team exercise documenting their fingerprints. Forensic confirmation from the
DESKTOP-FIN-047 image is required to confirm actual deployment on this endpoint.
The 11-day dwell period provided ample opportunity for all three.

**Technique Coverage:**
T1059.001, T1053.005, T1547.001, T1546.003, T1036.005, T1112, T1027, T1562.001

---

### PHASE 5 — Command & Control / Exfiltration (January 14–16, 2025)

**Duration:** 11 days
**ATT&CK Tactics:** TA0011 C2 / TA0010 Exfiltration

```
Beacon Statistics:
  Destination:    updates.cdn-telemetry-svc.net → 185.220.101.33
  Protocol:       DNS over HTTPS (T1573.002) — evades plaintext inspection
  Interval:       60.3 seconds ± 0.109s (CV = 0.0018)
  Total beacons:  ~15,800 over 11 days
  Fallback:       ICMP echo to 185.220.101.33 (T1008) — observed Jan 14

Exfiltration Statistics:
  Channel:        DNS TXT records — Base64 encoded subdomains (T1048.001)
  Frequency:      1 TXT query per 5 A-record beacons (20% ratio vs <2% normal)
  Total queries:  ~3,160 TXT exfil queries
  Estimated data: ~126KB (40 bytes/query × 3,160)
  Content:        Likely system fingerprint data, credential cache, clipboard
                  — pending forensic decoding of captured DNS payloads
```

**Technique Coverage:**
T1071.004, T1573.002, T1008, T1132.001, T1048.001, T1041

---

### PHASE 6 — Detection & Containment (January 16, 2025)

**Duration:** < 2 hours from alert to isolation
**Detection Method:** Proactive overnight threat hunt — not automated alerting

```
02:17 UTC  Low-confidence EDR DNS anomaly alert fires on DESKTOP-FIN-047
           Would have auto-suppressed without active analyst review
02:17 UTC  Analyst begins overnight hunt — pulls single-domain DNS frequency query
02:47 UTC  C2 beacon confirmed via IAT analysis (30 min from hunt start)
           beacon_analyzer.py — CV=0.0018, score 99/100
03:12 UTC  DNS tunnel confirmed — 100 high-entropy TXT queries flagged
03:30 UTC  DESKTOP-FIN-047 isolated — forensic imaging initiated
09:00 UTC  Week 1 synthesis complete — this report produced
```

---

## ATT&CK Navigator Layer Summary

```
Layer file:  artifacts/navigator_layer_week1.json
Import URL:  https://mitre-attack.github.io/attack-navigator/

Technique breakdown by tactic:
  Reconnaissance:          11 techniques
  Resource Development:     4 techniques
  Initial Access:           5 techniques (inc. sub-techniques)
  Execution:                2 techniques
  Persistence:              3 techniques
  Defense Evasion:          4 techniques
  Credential Access:        4 techniques
  Command & Control:        4 techniques
  Exfiltration:             2 techniques
  ─────────────────────────────────────
  TOTAL:                   38 confirmed techniques

Color coding in layer:
  Red    — Reconnaissance / C2 / Exfiltration
  Orange — Initial Access
  Yellow — Execution
  Green  — Persistence
  Purple — Defense Evasion
  Blue   — Credential Access
```

---

## Detection Coverage Gap Analysis

Of 38 confirmed techniques, Sigma/KQL rules cover **9 (24%)**. The remaining
29 techniques observed during the Week 1 investigation have no corresponding
automated detection rule in the current SIEM deployment.

### Rules Written (Days 02–06)

| Rule File | Technique | Level | Day Written |
|-----------|-----------|-------|-------------|
| `sigma_credential_stuffing.yml` | T1110.004 | High | Day 02 |
| `kql_impossible_travel.kql` | T1078.004 | High | Day 02 |
| `sigma_phishing_campaign.yml` | T1566.001 | High | Day 03 |
| `sigma_c2_beacon_dns.yml` | T1071.004 | High | Day 04 |
| `sigma_dns_tunneling.yml` | T1048.001 | High | Day 04 |
| `sigma_scheduled_task_persistence.yml` | T1053.005 | High | Day 06 |
| `sigma_registry_run_key_persistence.yml` | T1547.001 | Medium | Day 06 |
| `sigma_wmi_subscription_persistence.yml` | T1546.003 | Critical | Day 06 |
| `sigma_phishing_campaign.yml` (shared) | T1583.001 | High | Day 03 |

### Top Priority Gaps — Rules Needed in Week 2

| Technique | Name | Why Critical |
|-----------|------|-------------|
| **T1059.001** | PowerShell Execution | Used in all 3 persistence payloads — no rule exists |
| **T1539** | Steal Web Session Cookie | MFA bypass kit — highest business impact |
| **T1112** | Modify Registry | Registry writes outside Run keys — no coverage |
| **T1573.002** | Asymmetric Crypto C2 | DoH encrypted beacon — detection requires JA3 rules |
| **T1027** | Obfuscated Files/Info | Base64 in DNS labels caught but not in other contexts |
| **T1204.001** | User Execution | Click tracking requires email gateway integration |

---

## Unified IOC Summary

```
Total unique indicators: 28 across 6 categories
TLP: AMBER — share within sector, not publicly

IPs (5):        185.220.101.12 / .33 / .47  91.108.4.11  203.0.113.45
Domains (7):    microsoftonline-portal.com, updates.cdn-telemetry-svc.net,
                ms-account-portal.net, cdn-telemetry-svc.net + 3 subdomains
URLs (2):       Primary phishing URL + C2 stage2 payload URL
Email (2):      Subject lure pattern + link pattern for gateway rules
Network (3):    Beacon timing, DNS TXT pattern, JA3 hash
Host (4):       Scheduled task, Registry Run key, WMI filter, WMI consumer
ASNs (1):       AS209588 — Flyservers S.A. (Seychelles) — block recommended

Full lists:     artifacts/ioc_master_week1.{txt|csv|json}
STIX bundle:    artifacts/stix_bundle_day03.json (from Day 03)
```

---

## Risk Assessment — Overall Incident

### DREAD Scoring — Incident Level

| Factor | Score | Justification |
|--------|:-----:|---------------|
| **Damage** | 10 | CEO account compromised, 126KB exfil, FI trading data at risk |
| **Reproducibility** | 9 | Infrastructure still active — other sector orgs being targeted |
| **Exploitability** | 9 | No admin required, phishing click sufficient, MFA bypassed |
| **Affected Users** | 8 | 312 breach-exposed accounts, 1 confirmed compromise, CEO access |
| **Discoverability** | 8 | All intelligence from public sources, attack repeatable easily |
| **Total** | **44/50** | 🔴 **CRITICAL** |

---

## Consolidated Remediation Roadmap

### Immediate (0–24 Hours)

| Action | Owner | Status |
|--------|-------|--------|
| Forensic imaging of DESKTOP-FIN-047 complete | IR Team | In progress |
| CEO account secured — session revoked, MFA enforced | IT Security | Complete |
| Block 185.220.101.0/24 at perimeter firewall | Network Ops | Complete |
| Deploy all 8 Sigma rules to SIEM | Detection Eng | Complete |
| Hunt for WMI subscriptions across all endpoints | Threat Hunt | In progress |
| Force password reset — all 312 breach-exposed accounts | IT Help Desk | In progress |

### Short Term (1–7 Days)

| Action | Owner |
|--------|-------|
| Legal review — MNPI disclosure (M&A on LinkedIn) | Legal / Compliance |
| Regulatory notification assessment (SEC, FINRA, GDPR) | Legal |
| Remove MFA "VIP Users" exclusion — no exemptions | Azure AD Admin |
| Remove security tool names from all job postings | HR + Security |
| Sanitize IT Director's GitHub — internal hostname references | Robert Patel / IT |
| Decode all captured DNS TXT payloads — scope exfil data | Forensics |
| Share STIX IOC bundle via FS-ISAC | Threat Intel |

### Medium Term (30 Days)

| Action | Owner |
|--------|-------|
| Write 6 priority detection rules identified in gap analysis | Detection Eng |
| Patch GlobalProtect VPN — CVE-2021-3064 (CVSS 9.8) | IT Security |
| Enforce DMARC p=reject (advance from p=none) | Email Admin |
| Deploy FIDO2 hardware keys for C-suite | IT Security |
| Repeat purple team exercise — verify all fixes effective | Purple Team |
| Establish automated ATT&CK coverage tracking | Detection Eng |

---

## Week 1 Analyst Notes

**On the value of the continuous narrative:**

Each day of this investigation produced a standalone report. But the synthesis
in Day 07 reveals something none of the individual reports could: the attacker
had a complete picture of NovaCrest before they ever sent the first phishing email.
They knew the open enrollment deadline (LinkedIn), the HR platform (job posting),
the email format (breach data correlation), and the CFO's name (SEC filing).

The HR benefits lure that compromised DESKTOP-FIN-047 was not a generic
spray-and-pray phishing email. It was a precisely calibrated social engineering
attack built from intelligence that NovaCrest published itself, freely and
publicly, over months and years. The attacker's research took hours. The
remediation will take weeks. The detection took 11 days.

**On detection methodology:**

Detection was achieved through proactive hypothesis-driven threat hunting, not
automated alerting. The query that confirmed the beacon was: *"Which internal host
has queried a single external domain more than 100 times in the last 6 hours?"*
That is one Splunk query, written in 30 seconds. It would have found this beacon
on day one of the 11-day dwell period if it had been run daily.

Threat hunting is not exotic. It is asking structured questions of data you
already have. The data was there. The question was not being asked.

**On the ATT&CK framework as a communication tool:**

The 38-technique ATT&CK Navigator layer generated in this capstone serves two
purposes. For technical teams: it is a gap analysis — 29 of 38 techniques lack
detection coverage, making the priority roadmap obvious. For leadership: it is
a communication tool — a visual heat map of where the attacker operated and
where our defenses stood. Both are essential outputs of a mature IR process.

---

## References

- [MITRE ATT&CK Enterprise v14](https://attack.mitre.org/versions/v14/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [NIST SP 800-61 — Computer Security Incident Handling](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [RITA — Real Intelligence Threat Analytics](https://github.com/activecm/rita)
- [FS-ISAC Threat Intelligence Sharing](https://www.fsisac.com/)
- [SEC Incident Disclosure Requirements](https://www.sec.gov/rules/final/2023/33-11216.pdf)

---

## Week 1 Complete — Portfolio Summary

```
Days 01–07: NovaCrest Capital Group Incident
  Tracks covered:     OSINT, Threat Hunting, Threat Intel, Purple Team, Full Stack
  ATT&CK techniques:  38 confirmed across 9 tactics
  IOCs produced:      28 unique indicators
  Sigma rules:        8 production-ready rules
  Detection gap:      76% of observed techniques lack automated detection
  Dwell time:         11 days
  Detection method:   Proactive threat hunting (not automated alerting)
  Key lesson:         Public information is a weapon. Know your own exposure.
```

---

*Previous: [Day 06 ←](../day-06/REPORT.md) | Week 2 Begins: [Day 08 →](../day-08/SCENARIO.md)*

---
*Report generated as part of the [Blaakpearl 30-Day Security Portfolio](../../README.md)*
