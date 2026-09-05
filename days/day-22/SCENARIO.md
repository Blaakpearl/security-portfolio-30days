# Day 22 — SCENARIO.md
## Risk Scoring Framework: Threat Intelligence Risk Assessment
**NovaCrest Capital Group | Post-Incident Risk Analysis**
**Classification:** TLP:WHITE — Internal Distribution
**Track:** Threat Intelligence
**Tools:** CVSS 3.1 · DREAD · ATT&CK Navigator · OpenCTI · STIX 2.1

---

## Scenario Context

The Week 3 engagement (Days 15–21) produced a confirmed, fully documented
intrusion against NovaCrest Capital Group. The security team now shifts from
detection and response to **structured risk quantification**: translating
the tactical findings (TTPs, vulnerabilities exploited, data impacted) into
a risk register that speaks the language of the board, compliance, and the
CISO — with scores, priorities, and business impact ratings that drive
remediation investment decisions.

Day 22 builds NovaCrest's **post-incident risk scoring framework** using
three complementary methodologies:

1. **CVSS 3.1** — vulnerability-level technical severity scores for the
   specific weaknesses exploited during the intrusion
2. **DREAD** — attacker-centric risk scoring for TTP reuse likelihood,
   prioritizing which techniques need detection engineering first
3. **ATT&CK-informed Risk Tiers** — technique-level risk weighting based
   on detectability gap, business impact, and adversary prevalence

The output is a unified **Risk Register** — a structured document mapping
each finding to a severity score, business impact, regulatory exposure, and
prioritized remediation action.

---

## Risk Findings Scope

Findings drawn from confirmed Week 3 evidence (Days 15–21):

| Finding ID | Finding | Source Day | Category |
|------------|---------|------------|---------|
| RF-001 | GitHub-exposed AWS credentials (hardcoded) | Day 15/16 | Credential Exposure |
| RF-002 | NOPASSWD sudo rule on svc_ncg (find binary) | Day 17 | Misconfiguration |
| RF-003 | Three SUID GTFOBins on lnx-trade-01 | Day 17 | Misconfiguration |
| RF-004 | Kerberoastable service accounts with weak passwords | Day 17 | Credential Policy |
| RF-005 | Zeek/auditd not forwarded to SIEM (Day 18 exfil undetected) | Day 18/19 | Detection Gap |
| RF-006 | TLS inspection disabled on Zscaler (domain fronting undetected) | Day 20 | Detection Gap |
| RF-007 | 253 MB data exfiltrated — trading algos + client PII | Day 18 | Data Loss |
| RF-008 | Windows Security log cleared — 649 events destroyed | Day 19 | Evidence Integrity |
| RF-009 | No DLP on S3 uploads — 85 MB exfil undetected | Day 18/19 | DLP Gap |
| RF-010 | Domain fronting C2 — SNI≠Host bypass | Day 20/21 | C2 Evasion |

---

## Methodology Overview

### CVSS 3.1
Standard vulnerability scoring for technical weaknesses. Scores range 0–10:
- **Critical:** 9.0–10.0
- **High:** 7.0–8.9
- **Medium:** 4.0–6.9
- **Low:** 0.1–3.9

Each vector string encodes: Attack Vector, Complexity, Privileges Required,
User Interaction, Scope, Confidentiality/Integrity/Availability impact.

### DREAD
Attacker-perspective scoring across five dimensions (each 1–10):
- **D**amage: How bad is the damage if exploited?
- **R**eproducibility: How easy to reproduce the attack?
- **E**xploitability: How easy to exploit?
- **A**ffected users: How many users/systems impacted?
- **D**iscoverability: How easy to discover the vulnerability?

DREAD score = mean of five dimensions.

### ATT&CK Risk Tier
Three-factor weighting specific to this environment:
- **Detectability gap** (1–5): How wide is the current detection gap?
- **Business impact** (1–5): Financial / regulatory / reputational damage?
- **Adversary prevalence** (1–5): How common is this TTP in the wild?

Risk Tier = weighted sum (detectability × 2 + impact × 2 + prevalence × 1) / 5

---

## MITRE ATT&CK Techniques in Scope

| Technique | Name | Exploited In Incident |
|-----------|------|----------------------|
| T1552.001 | Credentials in Files (GitHub) | Yes — RF-001 |
| T1548.003 | Sudo Abuse | Yes — RF-002 |
| T1548.001 | SUID Exploitation | Yes — RF-003 |
| T1558.003 | Kerberoasting | Yes — RF-004 |
| T1562.001 | Disable Security Tools | Yes (audit gap) — RF-005 |
| T1090.004 | Domain Fronting | Yes — RF-006, RF-010 |
| T1567.002 | Cloud Storage Exfil | Yes — RF-007, RF-009 |
| T1070.001 | Clear Windows Event Logs | Yes — RF-008 |
| T1005 | Data from Local System | Yes — RF-007 |
| T1078.004 | Cloud Accounts | Yes — RF-001 |

---

## Regulatory Impact Matrix

| Finding | GDPR | SEC Reg S-P | NY DFS 23 NYCRR 500 | SOX | PCI DSS |
|---------|------|------------|---------------------|-----|---------|
| RF-001 Credential Exposure | Article 32 | Yes | §500.07 | Yes | Req 8 |
| RF-007 Data Exfil (PII) | Article 33 notification | Yes — 30 days | §500.17 72hr | Yes | Req 12 |
| RF-008 Log Destruction | Article 5 | Yes | §500.06 | Yes | Req 10 |
| RF-009 DLP Gap | Article 25 | Yes | §500.15 | — | Req 12 |

---

## Deliverables

| File | Description |
|------|-------------|
| `SCENARIO.md` | This document |
| `LAB.md` | CVSS calculator setup, DREAD scoring methodology, ATT&CK risk tier guide |
| `REPORT.md` | Executive summary of risk scoring results |
| `scripts/risk_scorer.py` | CVSS 3.1 + DREAD + ATT&CK risk tier calculator |
| `scripts/risk_register_builder.py` | Generates full risk register from scored findings |
| `queries/risk_prioritization.spl` | Splunk SPL: risk-weighted finding prioritization dashboard |
| `queries/risk_prioritization.kql` | Sentinel KQL equivalents |
| `reports/day22_risk_register.md` | Full risk register (all 10 findings, all three scores) |
| `reports/day22_executive_brief.md` | Board/CISO-level risk summary (one page) |
| `artifacts/risk_scores.json` | Machine-readable risk register for SIEM/GRC ingestion |

---

*Day 22 Scenario | Risk Scoring Framework*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
