# Network Threat Hunt Report
## Day 04 — C2 Beacon & DNS Tunnel Detection

---

| Field | Details |
|-------|---------|
| **Analyst** | Blaakpearl |
| **Report Date** | 2025-01-16 |
| **Report Type** | Network Threat Hunt — C2 Detection & DNS Anomaly Analysis |
| **Classification** | Portfolio / Training Exercise |
| **Target (Fictional)** | NovaCrest Capital Group — DESKTOP-FIN-047 |
| **Track** | Threat Hunting |
| **ATT&CK Phase** | Command & Control (TA0011) / Exfiltration (TA0010) |
| **Case ID** | NVC-IR-2025-004 |
| **Host Status** | ISOLATED — Active IR in progress |

---

## Executive Summary

A proactive overnight threat hunt against NovaCrest Capital Group's network
telemetry identified a confirmed Command & Control (C2) beacon operating on
workstation **DESKTOP-FIN-047**, assigned to a senior analyst in the Fixed
Income trading desk. The beacon had been operating silently for **11 days**
before detection — evading automated alerting through low-data-volume DNS
queries that fell below standard threshold-based alert rules.

Statistical analysis of DNS inter-arrival times (IAT) produced a coefficient
of variation of **0.0018** — mathematically confirming machine-generated
timing at a 60.3-second interval. A co-located DNS tunneling channel was
identified transmitting Base64-encoded data via TXT record queries,
with an estimated **126KB of data exfiltrated** to attacker infrastructure
at `185.220.101.33` (Flyservers S.A., Seychelles — the same bulletproof
hosting ASN identified in the Day 03 phishing investigation, strongly
suggesting a connected campaign).

The host has been isolated from the network. Forensic imaging is recommended
before any remediation. Two production-ready Sigma detection rules have been
developed and are ready for SIEM deployment to prevent recurrence.

**Critical finding: detection occurred via proactive threat hunting, not
automated alerting. The initial EDR alert was low-confidence and would have
aged out without analyst review — a 11-day dwell time would have extended
indefinitely under alert-only monitoring.**

---

## Methodology

```
Phase 1 — Beacon Identification (45 min)
  Trigger:   Low-confidence EDR DNS anomaly alert on DESKTOP-FIN-047
  Tool:      Zeek dns.log analysis + Python frequency analysis
  Output:    Top DNS query list, query-type distribution, external IPs

Phase 2 — Statistical Confirmation (30 min)
  Tool:      beacon_analyzer.py — IAT statistical analysis
  Metrics:   Mean interval, std deviation, coefficient of variation (CV)
  Output:    Beacon score 99/100, CV=0.0018, interval=60.3s confirmed

Phase 3 — DNS Tunnel Analysis (30 min)
  Tool:      dns_tunnel_detector.py — Shannon entropy scoring
  Output:    100 high-confidence TXT exfil queries identified

Phase 4 — TLS Fingerprinting (20 min)
  Tool:      tshark JA3 extraction + abuse.ch SSLBL lookup
  Output:    JA3 hash matched known C2 framework signature

Phase 5 — Rule Development & Timeline (45 min)
  Tools:     Sigma framework, manual timeline reconstruction
  Output:    2 Sigma rules, 11-event forensic timeline
```

---

## Technical Findings

---

### FINDING-01 — Confirmed C2 Beacon: 60.3-Second DNS Interval, CV=0.0018

**Severity:** 🔴 Critical
**CVSS v3.1 Score:** 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
**ATT&CK:** T1071.004 — Application Layer Protocol: DNS

**Description:**
Inter-arrival time (IAT) statistical analysis of DNS query logs for
DESKTOP-FIN-047 confirmed a high-precision C2 beacon operating at a
60.3-second interval with near-zero timing variance. The beacon queries
`updates.cdn-telemetry-svc.net` — a domain registered on January 5, 2025,
the same day the broader phishing infrastructure was established (see Day 03
report, FINDING-03 infrastructure cluster).

**Statistical Evidence:**
```
IAT Analysis Results — DESKTOP-FIN-047 → updates.cdn-telemetry-svc.net

  Query Count:          500 queries (6-hour sample)
  Full Campaign:        ~15,800 queries over 11 days
  Mean Interval:        60.300 seconds
  Standard Deviation:   0.109 seconds
  Coefficient of Variation (CV): 0.0018

  Interpretation:
    CV < 0.05   = machine-generated (BEACON CONFIRMED)
    CV 0.05–0.5 = suspicious, investigate
    CV > 1.0    = normal human/application traffic

  Comparison — legitimate traffic on same host:
    windows-update.microsoft.com  CV: 1.2340  (normal)
    ocsp.digicert.com              CV: 0.9821  (normal)
    api.github.com                 CV: 1.1042  (normal)

  Beacon Score: 99/100
  Confidence:   CRITICAL — almost certainly automated beacon
```

**IAT Distribution Analysis:**
The IAT histogram shows an extremely narrow distribution centered at 60.3
seconds — visually indistinguishable from a Dirac delta function. Human
network traffic produces broad, right-skewed distributions. This beacon's
distribution would require a human to set a timer and manually trigger
network activity 500 times with sub-second precision — physically impossible
without automation.

**Beacon Pattern Context:**
The 60.3-second interval is consistent with default C2 framework beacon
configurations. The slight offset from exactly 60 seconds (0.3s) is a
deliberate design choice by the malware author to avoid exact-integer-second
detection rules — a basic but effective evasion technique.

**Recommendation:**
Immediately isolate DESKTOP-FIN-047 and capture a full memory image before
any shutdown (critical — beacon process and encryption keys reside in memory).
Block `updates.cdn-telemetry-svc.net` and the full `185.220.101.0/24` subnet
at DNS resolver and perimeter firewall. Deploy `sigma_c2_beacon_dns.yml` to
SIEM for ongoing detection.

---

### FINDING-02 — DNS Data Exfiltration via TXT Record Tunneling

**Severity:** 🔴 Critical
**CVSS v3.1 Score:** 9.1 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N)
**ATT&CK:** T1048.001 — Exfiltration Over Alternative Protocol: DNS / T1132.001 — Data Encoding: Standard Encoding

**Description:**
Shannon entropy analysis of DNS query labels identified a co-located data
exfiltration channel operating within the same C2 beacon infrastructure.
Every 5th beacon query uses a DNS TXT record type with a Base64-encoded
subdomain label containing host-specific data. This is the signature of
DNS tunneling tools such as dnscat2, DNSExfiltrator, or a custom
implementation.

**Evidence:**
```
DNS Tunnel Analysis Results:

  Total queries analyzed:    500
  Tunnel-suspicious queries: 100
  High-confidence (≥ 70):    100

  Sample TXT exfil query:
  Query: "YmVhY29uX2lkPTUmJmhvc3Q9RklOMDQ3JiZ0cz0xNzM2OTk4NjQy"
         .updates.cdn-telemetry-svc.net
  Type:  TXT
  Score: 95/100
  Flags: LONG_LABEL:56chars, HIGH_ENTROPY:5.824, TXT_RECORD, BASE64_PATTERN

  Decoded payload (Base64):
  "beacon_id=5&&host=FIN047&&ts=1736998642"
  → Contains: host identifier, sequence number, timestamp

  TXT Query Ratio: 20.0% of all queries
  Normal baseline: < 2% TXT queries
  Anomaly factor:  10× above normal

Entropy Analysis:
  Legitimate DNS labels (microsoft.com subdomains): entropy 2.1–2.8
  Normal service subdomains (api, mail, cdn):       entropy 1.5–2.2
  DETECTED tunnel labels:                           entropy 5.2–5.9
  Threshold for encoded data:                       entropy > 4.0
```

**Exfiltration Volume Estimate:**
```
Exfil queries:      3,160 over 11 days (1 per 5 beacons)
Avg payload size:   40 bytes per query label
Total exfiltrated:  ~126 KB minimum

At-risk data on DESKTOP-FIN-047:
  • Fixed Income trading positions and strategy documents
  • Bloomberg terminal session data
  • Internal M&A research documents (based on user role)
  • Windows credential cache (LSASS — see Day 12 for memory forensics)
```

**Recommendation:**
Preserve all DNS logs for legal/forensic chain of custody. Decode all captured
TXT record payloads to determine exact data exfiltrated. Engage Legal and
Compliance immediately — if financial data or PII was exfiltrated, regulatory
notification obligations may apply (SEC, FINRA, GDPR depending on jurisdiction).

---

### FINDING-03 — 11-Day Dwell Time: Detection Gap Analysis

**Severity:** 🟠 High
**ATT&CK:** T1562 — Impair Defenses (attacker operated below detection thresholds)

**Description:**
The beacon operated for 11 days before detection. Analysis of the automated
alerting configuration reveals three detection gaps that allowed the beacon
to persist undetected:

**Detection Gap Analysis:**
```
Gap 1: DNS Volume Threshold Too High
  Alert trigger:     > 500 queries/hour to single external domain
  Beacon rate:       60 queries/hour
  Gap:               Beacon operated at 12% of alert threshold

Gap 2: No Baseline Deviation Alerting
  Missing control:   No ML-based anomaly detection on DNS timing patterns
  Available control: RITA (Real Intelligence Threat Analytics) — not deployed
  Gap:               Statistical beacon detection not in ruleset

Gap 3: Low-Confidence Alert Auto-Suppression
  EDR alert fired:   2025-01-16 02:17 UTC (day 11)
  Alert confidence:  Low — suppressed by noise filter before analyst review
  Gap:               Alert aged out without human review in normal workflow

Detection Method That Worked:
  Proactive overnight threat hunt — manually pulling DNS log anomalies
  Hunt hypothesis: "What hosts have unusually high single-domain query counts?"
  Time from hunt start to confirmed beacon: 30 minutes
```

**Recommendation:**
Deploy RITA (Real Intelligence Threat Analytics by ActiveCM) — open-source
tool specifically designed to detect C2 beacons in Zeek logs using IAT
analysis at scale across all hosts simultaneously. Current threshold-based
alerting is insufficient for low-and-slow beacons. Tune DNS anomaly alert
to trigger at 10× baseline per-host per-domain rate, not absolute count.
Remove auto-suppression of low-confidence DNS anomaly alerts pending tuning.

---

### FINDING-04 — Infrastructure Overlap with Day 03 Phishing Campaign

**Severity:** 🟠 High
**ATT&CK:** T1583.001 — Acquire Infrastructure: Domains

**Description:**
The C2 server IP `185.220.101.33` resolves within the same `/24` subnet
(`185.220.101.0/24`, ASN209588 — Flyservers S.A.) as the phishing
infrastructure identified in the Day 03 investigation. The C2 domain
`updates.cdn-telemetry-svc.net` was registered on January 5, 2025 — the
same date as the phishing domain cluster. This constitutes strong technical
evidence of a **unified campaign** with a single threat actor operating both
the initial phishing delivery and the post-compromise C2 infrastructure.

**Evidence:**
```
Infrastructure Overlap:

  Day 03 Phishing IP:   185.220.101.12  (AS209588 — Flyservers)
  Day 04 C2 IP:         185.220.101.33  (AS209588 — Flyservers)
  Shared subnet:        185.220.101.0/24

  Day 03 domain reg.:   2025-01-05 14:32 UTC
  Day 04 C2 domain reg: 2025-01-05 ~16:00 UTC (same day, 90 min later)
  Day 03 phishing click: DESKTOP-FIN-047 user — 2025-01-05 22:51 UTC
  Day 04 first beacon:   DESKTOP-FIN-047 — 2025-01-05 23:44 UTC

  Kill chain reconstruction:
    T+0h:00m  Phishing domain registered
    T+1h:28m  C2 domain registered
    T+7h:19m  Phishing email delivered to victim
    T+8h:19m  Victim clicks phishing link (Day 03 incident)
    T+9h:12m  Payload delivered → first C2 beacon fires
```

**Recommendation:**
Merge Day 03 and Day 04 investigations into a single IR case. The attacker
achieved initial access via the phishing campaign and immediately established
persistent C2 — this is a continuous intrusion, not two separate incidents.
Escalate to full Incident Response engagement.

---

## MITRE ATT&CK Technique Matrix

| ID | Technique | Tactic | Finding | Confidence |
|----|-----------|--------|---------|------------|
| **T1566.002** | Spearphishing Link | Initial Access | FINDING-04 (from Day 03) | High |
| **T1071.004** | Application Layer: DNS | Command & Control | FINDING-01 | Critical |
| **T1573.002** | Encrypted Channel: Asymmetric | Command & Control | DoH observed | High |
| **T1008** | Fallback Channels | Command & Control | ICMP fallback attempt | Medium |
| **T1132.001** | Data Encoding: Standard | Command & Control | Base64 in DNS labels | High |
| **T1048.001** | Exfiltration Over DNS | Exfiltration | FINDING-02 | High |
| **T1041** | Exfiltration Over C2 Channel | Exfiltration | FINDING-02 | High |
| **T1562** | Impair Defenses | Defense Evasion | FINDING-03 (below threshold) | Medium |
| **T1583.001** | Acquire Infrastructure: Domains | Resource Development | FINDING-04 | High |

---

## Risk Assessment — DREAD Scoring

| Finding | Damage | Reproducibility | Exploitability | Affected Users | Discoverability | **/50** | **Rating** |
|---------|:------:|:---------------:|:--------------:|:--------------:|:---------------:|:-------:|:----------:|
| FINDING-01 (C2 Beacon) | 10 | 8 | 7 | 5 | 4 | **34** | 🔴 Critical |
| FINDING-02 (DNS Exfil) | 10 | 7 | 7 | 5 | 3 | **32** | 🔴 Critical |
| FINDING-03 (11-day dwell) | 8 | 9 | 8 | 9 | 7 | **41** | 🔴 Critical |
| FINDING-04 (Infra overlap) | 9 | 8 | 8 | 8 | 6 | **39** | 🔴 Critical |

### Overall Incident Rating: 🔴 CRITICAL

---

## Detection Rules Deployed

| Rule | File | Platform | ATT&CK Coverage |
|------|------|----------|-----------------|
| C2 Beacon — Periodic DNS Pattern | `sigma_c2_beacon_dns.yml` | Sigma (any SIEM) | T1071.004 |
| DNS Tunneling — Entropy Detection | `sigma_dns_tunneling.yml` | Sigma (any SIEM) | T1048.001 |

---

## Indicators of Compromise

```
# C2 DOMAINS (Defanged)
updates.cdn-telemetry-svc[.]net       ← primary C2 beacon domain
cdn-telemetry-svc[.]net               ← parent domain

# C2 IP ADDRESSES
185.220.101.33                        ← C2 server
185.220.101.0/24                      ← Full bulletproof hosting block

# BEACON CHARACTERISTICS (for detection tuning)
Protocol:     DNS (UDP/53 and DoH/443)
Interval:     60.3 seconds ± 0.1s
CV:           0.0018
Query type:   A (normal) + TXT (exfil channel)
Exfil ratio:  1 TXT per 5 A queries

# HOST INDICATORS
Affected:     DESKTOP-FIN-047  (10.10.5.47)
First seen:   2025-01-05 23:44:12 UTC
Last seen:    2025-01-16 03:30:00 UTC (isolation)
Dwell time:   11 days
```

---

## Immediate Response Actions Required

| Priority | Action | Owner | Deadline |
|----------|--------|-------|----------|
| **P0** | Memory image capture — DESKTOP-FIN-047 BEFORE shutdown | IR / Forensics | Immediate |
| **P0** | Preserve all DNS logs (30-day lookback) — legal hold | SOC / Legal | Immediate |
| **P0** | Block `185.220.101.0/24` at firewall + DNS sinkhole | Network Ops | Immediate |
| **P0** | Engage Legal/Compliance re: potential data exfiltration | CISO | Immediate |
| **P1** | Hunt for same beacon pattern across ALL internal hosts | Threat Hunt | 4 hours |
| **P1** | Deploy RITA to Zeek log pipeline | Detection Eng | 24 hours |
| **P1** | Deploy 2 new Sigma rules to SIEM | Detection Eng | 24 hours |
| **P1** | Decode all captured TXT DNS payloads — scope exfil data | Forensics | 24 hours |
| **P2** | Review and lower DNS anomaly thresholds in EDR | Detection Eng | 48 hours |
| **P2** | Remove auto-suppression of low-confidence DNS alerts | SOC Ops | 48 hours |
| **P3** | Deploy FIDO2 MFA across Fixed Income trading team | IT Security | 1 week |

---

## Analyst Notes

**The hunting methodology that detected this beacon:**

The initial hypothesis was simple: *"What internal host has queried a single
external domain more than 100 times in the last 6 hours?"* — a one-line SPL
query that takes 30 seconds to write and 10 seconds to run. The answer was
immediate. This is the core value proposition of threat hunting: human-directed
hypotheses catch what automated rules miss, specifically because attackers
design their tools to stay below automated alert thresholds.

The beacon was operating at 60 queries/hour — exactly below the 500/hour
alert threshold. This is not coincidence. It is deliberate threshold-aware
beacon design. The attacker knew the detection environment and calibrated
their tool accordingly. The lesson: **detection thresholds must be baselined
per-host, not set as global absolutes.**

---

## References

- [MITRE ATT&CK T1071.004 — DNS C2](https://attack.mitre.org/techniques/T1071/004/)
- [MITRE ATT&CK T1048.001 — DNS Exfiltration](https://attack.mitre.org/techniques/T1048/001/)
- [RITA — Real Intelligence Threat Analytics](https://github.com/activecm/rita)
- [Zeek Network Security Monitor](https://zeek.org/)
- [Shannon Entropy in DNS Threat Detection](https://isc.sans.edu/diary/Detecting+DNS+Tunneling/19943)
- [JA3 TLS Fingerprinting](https://github.com/salesforce/ja3)
- [abuse.ch SSLBL](https://sslbl.abuse.ch/)

---

*Previous: [Day 03 ←](../day-03/REPORT.md) | Next: [Day 05 →](../day-05/SCENARIO.md)*

---
*Report generated as part of the [Blaakpearl 30-Day Security Portfolio](../../README.md)*
