# Day 22 — LAB.md
## Risk Scoring Framework Lab Guide
**NovaCrest Capital Group | Threat Intelligence Track**

---

## Overview

This lab walks through applying three risk scoring frameworks to the ten
confirmed findings from the Week 3 NovaCrest engagement. Each section
covers the methodology, scoring inputs, and how to interpret the output
for remediation prioritization.

---

## Part 1: CVSS 3.1 Scoring

### Tool Options
```bash
# Option A: NIST NVD CVSS Calculator (web)
# https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

# Option B: Python cvss library
pip install cvss --break-system-packages

# Calculate from vector string
python3 -c "
from cvss import CVSS3
v = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H')
print('Base Score:', v.base_score)
print('Severity:', v.severities()[0])
"

# Option C: Use the risk_scorer.py script (pre-loaded with all 10 findings)
python3 scripts/risk_scorer.py --method cvss --demo
```

### CVSS 3.1 Vector Components Reference
```
Attack Vector (AV):    N=Network, A=Adjacent, L=Local, P=Physical
Attack Complexity (AC): L=Low, H=High
Privileges Required (PR): N=None, L=Low, H=High
User Interaction (UI):  N=None, R=Required
Scope (S):             U=Unchanged, C=Changed
Confidentiality (C):   N=None, L=Low, H=High
Integrity (I):         N=None, L=Low, H=High
Availability (A):      N=None, L=Low, H=High
```

### Scoring the Ten Findings (CVSS Vectors)
```
RF-001 GitHub Credentials:
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0 CRITICAL
  Rationale: Network-reachable, no privileges needed, full CIA impact

RF-002 NOPASSWD sudo (find):
  CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H → 8.8 HIGH
  Rationale: Local access required (attacker already in); full escalation

RF-003 SUID GTFOBins (find, python3, vim):
  CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H → 8.8 HIGH
  Rationale: Same as sudo abuse — local escalation to root

RF-004 Kerberoastable accounts (RC4 + weak password):
  CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H → 8.5 HIGH
  Rationale: Network (Kerberos), High complexity (requires domain account)

RF-005 Zeek/auditd SIEM gap:
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N → 9.3 CRITICAL
  Rationale: Allows attackers to operate undetected (detection gap = scope change)

RF-006 TLS inspection disabled:
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 HIGH
  Rationale: Confidentiality impact via undetected exfil channel

RF-007 253 MB data exfiltrated:
  CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N → 9.6 CRITICAL
  (Business impact scored separately — see DREAD)

RF-008 Security log cleared (649 events):
  CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:H → 8.2 HIGH
  Rationale: Requires SYSTEM (High priv); Integrity/Availability of log data

RF-009 No DLP on S3 uploads:
  CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N → 8.5 HIGH
  Rationale: Network-reachable, authenticated (Low priv), data loss

RF-010 Domain fronting C2 channel:
  CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N → 8.0 HIGH
  Rationale: High complexity (requires CDN abuse setup)
```

---

## Part 2: DREAD Scoring

### DREAD Dimensions Guide
```
D — Damage Potential (1–10)
    1:  Minimal; cosmetic impact
    5:  Moderate; single system compromised
    10: Catastrophic; full environment compromise, PII breach

R — Reproducibility (1–10)
    1:  Requires specific conditions; rarely reproducible
    5:  Reproducible with effort; requires tooling
    10: Trivially reproducible; any attacker can do it

E — Exploitability (1–10)
    1:  Expert-only; requires deep vulnerability research
    5:  Moderate; requires standard pentesting tools
    10: No skill required; automated tools available

A — Affected Users/Systems (1–10)
    1:  Single user or isolated system
    5:  Entire business unit
    10: All users, all systems, external customers

D — Discoverability (1–10)
    1:  Extremely difficult; requires insider knowledge
    5:  Findable with OSINT and moderate effort
    10: Publicly documented; automated scanners detect it
```

### Running DREAD Scores
```bash
# Score all ten findings using the risk_scorer.py DREAD module
python3 scripts/risk_scorer.py --method dread --demo --verbose

# Score a single finding interactively
python3 scripts/risk_scorer.py --method dread --finding RF-001 --interactive

# Expected output for RF-001:
# Finding: RF-001 — GitHub Credential Exposure
# D (Damage):        10  (full cloud environment takeover confirmed)
# R (Reproducibility): 10  (GitHub search → instant find)
# E (Exploitability): 10  (aws sts get-caller-identity; trivial)
# A (Affected):       9   (all cloud resources; most internal systems)
# D (Discoverability): 10  (TruffleHog / GitHub dorks; automated)
# DREAD Score: 9.8 — CRITICAL
```

---

## Part 3: ATT&CK Risk Tier

### Three-Factor Model
```
Factor 1: Detectability Gap (1–5)
  1 = Fully detected; existing rule fires within SLA
  2 = Detected but late (outside SLA)
  3 = Detected in hunt, not real-time
  4 = Detected retrospectively only (log forensics)
  5 = Not detectable with current stack

Factor 2: Business Impact (1–5)
  1 = No material business impact
  2 = Minor operational disruption
  3 = Revenue/reputation risk; notifiable event
  4 = Regulatory violation; significant financial loss
  5 = Catastrophic; trading halt; market manipulation risk

Factor 3: Adversary Prevalence (1–5)
  1 = Rare; novel technique; low-sophistication actors only
  2 = Uncommon; advanced actors
  3 = Common; ransomware groups and FIN actors
  4 = Very common; commodity tooling available
  5 = Ubiquitous; in every ATT&CK dataset; automated by tools

Risk Tier Score = (Detectability × 2 + Impact × 2 + Prevalence × 1) / 5
Tier 1 = Critical (≥ 4.0)
Tier 2 = High (3.0–3.9)
Tier 3 = Medium (2.0–2.9)
Tier 4 = Low (< 2.0)
```

### Running ATT&CK Risk Tiers
```bash
python3 scripts/risk_scorer.py --method attck --demo
python3 scripts/risk_register_builder.py --demo --output /tmp/risk_register.md
```

---

## Part 4: Unified Risk Register

### Building the Register
```bash
# Generate complete risk register (all methods, all findings)
python3 scripts/risk_register_builder.py \
    --findings-json artifacts/risk_scores.json \
    --output reports/day22_risk_register.md \
    --format markdown

# Export for GRC tool ingestion (JSON)
python3 scripts/risk_register_builder.py \
    --demo \
    --format json \
    --output artifacts/risk_scores.json

# Generate executive brief (condensed, board-ready)
python3 scripts/risk_register_builder.py \
    --demo \
    --format executive \
    --output reports/day22_executive_brief.md
```

### Integrating Scores into SIEM
```bash
# Enrich SIEM alerts with risk register context
# Splunk: Create lookup table from risk_scores.json
python3 -c "
import json
with open('artifacts/risk_scores.json') as f:
    data = json.load(f)
# Write as Splunk lookup CSV
import csv
with open('/opt/splunk/etc/apps/search/lookups/risk_register.csv','w') as f:
    writer = csv.DictWriter(f, fieldnames=['finding_id','cvss','dread','attck_tier','priority'])
    writer.writeheader()
    for finding in data['findings']:
        writer.writerow({
            'finding_id': finding['id'],
            'cvss': finding['cvss_score'],
            'dread': finding['dread_score'],
            'attck_tier': finding['attck_tier'],
            'priority': finding['priority']
        })
"
```

---

## Part 5: Prioritization Matrix

### Impact vs. Effort Grid
```
                   EFFORT TO REMEDIATE
                   Low          Medium       High
              ┌────────────┬────────────┬────────────┐
         High │ RF-001     │ RF-004     │ RF-007     │
              │ RF-002     │ RF-006     │ RF-010     │
  RISK        │ RF-003     │            │            │
  SCORE  Med  ├────────────┼────────────┼────────────┤
              │ RF-005     │ RF-009     │            │
              │ RF-008     │            │            │
         Low  ├────────────┼────────────┼────────────┤
              │            │            │            │
              └────────────┴────────────┴────────────┘

QUADRANT ACTIONS:
  High Risk + Low Effort  → FIX NOW (this sprint)
  High Risk + Medium Effort → FIX SOON (this quarter)
  High Risk + High Effort → MITIGATE + MONITOR (roadmap)
  Med/Low Risk + Any Effort → SCHEDULE (next cycle)
```

---

*Day 22 Lab Guide | Risk Scoring Framework*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
