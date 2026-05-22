# Credential Exposure Incident Report
## Day 02 — Third-Party Breach Correlation & Threat Hunt

---

| Field | Details |
|-------|---------|
| **Analyst** | Blaakpearl |
| **Report Date** | 2025-01-16 |
| **Incident Type** | Third-Party Credential Exposure / Proactive Threat Hunt |
| **Classification** | Portfolio / Training Exercise |
| **Target (Fictional)** | NovaCrest Capital Group |
| **Track** | Threat Hunting |
| **ATT&CK Phase** | Credential Access (TA0006) / Initial Access (TA0001) |
| **Incident Status** | Contained — Preventive Action Taken |

---

## Executive Summary

On January 16, 2025, a dark web monitoring alert identified 312 NovaCrest Capital
Group employee email addresses within **COMBOLIST-FIN-2025-Q1** — a criminal breach
compilation uploaded to a Russian-language cybercrime forum approximately 48 hours
prior to detection. The compilation aggregates credential data from 14 verified
third-party platform breaches spanning 2021 through 2024.

Bulk validation via the HaveIBeenPwned API confirmed that **7 of 10 sampled accounts
carry active breach exposure**, with **4 accounts classified as CRITICAL or HIGH
risk** due to confirmed password data exposure from breaches using weak hashing
algorithms (MD5, SHA-1) — effectively treating those passwords as plaintext.

Authentication log analysis across Azure AD and on-premises Windows infrastructure
identified **no confirmed successful exploitation** during the 48-hour breach window.
However, two anomalous login patterns were flagged for manual review: a single
external IP generating 47 failed authentication attempts across 23 accounts over
a 15-minute window (credential stuffing pattern) and one instance of a CRITICAL-risk
account authenticating from a country with no prior login history.

Forced password resets and session revocations are recommended for all CRITICAL and
HIGH risk accounts before close of business today.

---

## Methodology

```
Phase 1 — External Validation (2 hrs)
  Tool:    HaveIBeenPwned API v3
  Scope:   10 sampled accounts from 312-record exposure list
  Output:  Risk-tiered account inventory with breach metadata

Phase 2 — Internal Correlation (1.5 hrs)
  Tools:   Azure AD Sign-in Logs (KQL), Splunk (SPL)
  Scope:   7-day lookback on all 312 exposed accounts
  Output:  Authentication anomaly findings, stuffing pattern detection

Phase 3 — Detection Rule Development (1 hr)
  Tools:   Sigma framework, Splunk SPL, Microsoft KQL
  Output:  4 hunt queries + 1 production Sigma rule

Phase 4 — Remediation Planning (30 min)
  Output:  Priority matrix, leadership brief, IT action list
```

---

## Technical Findings

---

### FINDING-01 — Credential Stuffing Attempt Detected — 23 Accounts Targeted

**Severity:** 🔴 Critical  
**CVSS v3.1 Score:** 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)  
**ATT&CK:** T1110.004 — Credential Stuffing

**Description:**  
Splunk analysis of Windows Security Event ID 4625 (failed logon) over a 24-hour
lookback identified a high-confidence credential stuffing pattern originating from
a single IP address. The attack used a distributed residential proxy service — the
presenting IP rotated 12 times during the attack window while maintaining the same
target account list pattern.

**Evidence:**
```
Detection Query Result — SPL Query 1 (Password Spray/Stuffing):

Time Window:    2025-01-15 23:47 — 2025-01-16 00:02 (15 min)
Source IP:      185.220.101.47 (Tor exit node / residential proxy)
Unique Accounts Targeted: 23
Total Attempts: 94
Accounts from HIBP Exposure List: 18 of 23 (78%)

EventID 4625 sample:
  TargetUserName: j.morrison       ← matches CEO account (CRITICAL)
  TargetUserName: s.chen           ← matches CFO account (CRITICAL)
  TargetUserName: it.admin         ← matches IT Admin (CRITICAL)
  WorkstationName: DESKTOP-UNKNOWN
  LogonType: 3 (Network)
  Status: 0xC000006D (Unknown username or bad password)

IP Reputation:
  185.220.101.47 — Listed on AbuseIPDB (Score: 100%)
                 — Tagged: Credential Stuffing, Brute Force
                 — ASN: AS4134 (Residential proxy infrastructure)
```

**Risk Context:**  
The 78% overlap between targeted accounts and the HIBP-confirmed exposure list
strongly indicates the attacker is operating directly from **COMBOLIST-FIN-2025-Q1**
— the same compilation that triggered the initial alert. All 94 attempts resulted
in failure (EventID 4625 only — no 4624 success events for this IP). However, the
attempt window remains open; additional IP addresses from the same infrastructure
block should be expected.

**Recommendation:**  
Block the /24 subnet `185.220.101.0/24` at perimeter firewall immediately. Deploy
the Sigma rule in `artifacts/sigma_credential_stuffing.yml` to the SIEM for
ongoing detection. Implement account lockout after 5 failed attempts (if not
already configured) and enable Smart Lockout in Azure AD.

---

### FINDING-02 — Impossible Travel — CRITICAL Account Login from Anomalous Geography

**Severity:** 🔴 Critical  
**CVSS v3.1 Score:** 9.8  
**ATT&CK:** T1078.004 — Valid Accounts: Cloud Accounts

**Description:**  
KQL analysis of Azure AD Sign-in Logs identified a successful authentication event
for a CRITICAL-risk account (confirmed password exposure in LinkedIn 2012 breach,
MD5 hashed — effectively plaintext) from a country with zero prior login history
for that user. The login occurred 31 hours after the breach compilation was uploaded
to the criminal forum.

**Evidence:**
```
Azure AD Sign-in Log — Successful Authentication (ResultType: 0):

UserPrincipalName: j.morrison@novacrest-capital.com  [CRITICAL — CEO]
TimeGenerated:     2025-01-15 22:14:33 UTC
IPAddress:         91.108.4.11
Location:          Kyiv, Ukraine  ← FIRST login from this country
AppDisplayName:    Microsoft 365 (Exchange Online)
DeviceID:          (new device — not previously registered)
MfaDetail:         {authMethod: none}  ← MFA NOT ENFORCED on this account
ConditionalAccess: notApplied

Previous login record for same account:
TimeGenerated:     2025-01-15 14:23:01 UTC
IPAddress:         67.89.123.45
Location:          New York, United States
TimeGap:           7 hours 51 minutes
```

**Risk Context:**  
The combination of factors here is extremely high-confidence for account compromise:
confirmed password exposure in old breach using MD5 hashing, successful login from
first-ever foreign geography, new unregistered device, MFA not enforced on a
C-suite account, and timing within the breach compilation's active exploitation
window. This should be treated as a **confirmed account compromise** until proven
otherwise through direct verification with the account owner.

**Recommendation:**  
1. Immediately revoke all active sessions for `j.morrison` (Revoke-AzureADUserAllRefreshToken)
2. Force password reset before any access is restored
3. Enroll in MFA before re-enabling access — mandatory
4. Review all Microsoft 365 activity for the past 72 hours: email forwarding rules,
   SharePoint/OneDrive access, Teams conversations, calendar events
5. Determine if any sensitive M&A data was accessed during the Ukrainian session

---

### FINDING-03 — Four CRITICAL/HIGH Accounts with Password Exposure — MFA Not Enforced

**Severity:** 🟠 High  
**ATT&CK:** T1556 — Modify Authentication Process / T1078 — Valid Accounts

**Description:**  
Cross-referencing HIBP results against Azure AD Conditional Access policies
identified that 4 of the 7 accounts with confirmed password exposure do not have
MFA enforced. Three of these are privileged or sensitive roles. Without MFA,
any attacker with valid credentials has unrestricted account access.

**Evidence:**
```
Accounts with Password Exposure + No MFA Enforcement:

Account                          Risk    MFA Status    Role
j.morrison@novacrest.com         CRIT    NOT ENFORCED  CEO
s.chen@novacrest.com             CRIT    NOT ENFORCED  Head of M&A
it.admin@novacrest.com           CRIT    Registered    IT Director
helpdesk@novacrest.com           HIGH    NOT ENFORCED  IT Helpdesk

MFA Enforcement Gap Identified:
  Azure AD Conditional Access policy "Require MFA — All Users"
  excludes: service accounts, break-glass accounts, AND
  accounts in "VIP Users" group ← CEO and Head of M&A excluded
  Rationale on record: "Executive convenience" (added 2022-03-14)
```

**Recommendation:**  
Remove the VIP Users MFA exclusion immediately — no account should be exempt from
MFA regardless of seniority. Prioritize MFA enrollment for the CEO and Head of M&A
before restoring access. Review all Conditional Access policy exclusions quarterly.

---

### FINDING-04 — Breach Data Analysis: 60% of Exposed Passwords Effectively Plaintext

**Severity:** 🟠 High  
**ATT&CK:** T1589.001 — Gather Victim Identity: Credentials

**Description:**  
Analysis of the breach sources contributing to the 312-account exposure list reveals
that the majority of leaked passwords used weak or broken hashing algorithms —
meaning a significant proportion should be treated as already cracked and fully
known to the attacker.

**Evidence:**
```
Breach Source Analysis — NovaCrest Exposure Records:

Breach          Year  Algorithm  Records  Risk Tier
LinkedIn        2012  SHA-1      89       CRITICAL (unsalted, rainbow tables exist)
Adobe           2013  3DES       67       CRITICAL (broken algorithm)
Dropbox         2012  SHA-1/bcrypt 44     HIGH (mix — bcrypt portion safer)
Canva           2019  bcrypt     38       MEDIUM
Zynga           2019  SHA-1      31       CRITICAL
MySpace         2016  SHA-1      23       CRITICAL
Houzz           2018  bcrypt     20       LOW-MEDIUM

Records with CRITICAL/HIGH password risk: 254 of 312 (81%)
Treat as effectively plaintext: 210 records (LinkedIn SHA-1, Adobe 3DES, Zynga SHA-1)
```

**Recommendation:**  
All 210 accounts in CRITICAL-tier breach sources must be treated as if the attacker
has their plaintext password. Forced resets for all 210, not just the 10 sampled.
Prioritize accounts in privileged roles, finance, IT, and M&A access groups.

---

## MITRE ATT&CK Technique Matrix

| ID | Technique | Tactic | Finding | Status |
|----|-----------|--------|---------|--------|
| **T1589.001** | Gather Victim Identity — Credentials | Reconnaissance | FINDING-04 | Attacker activity confirmed |
| **T1110.004** | Credential Stuffing | Credential Access | FINDING-01 | Detected & blocked |
| **T1110.003** | Password Spraying | Credential Access | FINDING-01 | Partial overlap pattern |
| **T1078** | Valid Accounts | Initial Access | FINDING-02 | Possible compromise |
| **T1078.004** | Cloud Accounts | Defense Evasion | FINDING-02 | Under investigation |
| **T1556** | Modify Authentication Process | Defense Evasion | FINDING-03 | Misconfiguration |
| **T1098** | Account Manipulation | Persistence | Monitoring | No evidence yet |
| **T1114** | Email Collection | Collection | Monitoring | Check post-FINDING-02 |

---

## Risk Assessment — DREAD Scoring

| Finding | Damage | Reproducibility | Exploitability | Affected Users | Discoverability | **/50** | **Rating** |
|---------|:------:|:---------------:|:--------------:|:--------------:|:---------------:|:-------:|:----------:|
| FINDING-01 (Stuffing Active) | 8 | 10 | 9 | 8 | 10 | **45** | 🔴 Critical |
| FINDING-02 (Impossible Travel) | 10 | 7 | 9 | 3 | 8 | **37** | 🔴 Critical |
| FINDING-03 (No MFA) | 9 | 8 | 9 | 4 | 7 | **37** | 🔴 Critical |
| FINDING-04 (Plaintext Passwords) | 8 | 9 | 8 | 9 | 6 | **40** | 🔴 Critical |

### Overall Incident Risk Rating: 🔴 CRITICAL

---

## Indicators of Compromise

```
# Malicious IPs — Credential Stuffing Source
185.220.101.47      Tor exit / residential proxy — credential stuffing
185.220.101.0/24    Full subnet — block recommended

# Suspicious Successful Auth IP
91.108.4.11         Kyiv, Ukraine — anomalous CEO account login

# Breach Compilation Reference
COMBOLIST-FIN-2025-Q1   Criminal forum upload — 2.3M records
Forum:                  [Redacted — dark web forum reference]
Upload Date:            2025-01-14 ~14:00 UTC

# Affected Account Tiers (Sample — Full List in artifacts/)
CRITICAL:   j.morrison@, s.chen@, it.admin@
HIGH:       helpdesk@, hr.manager@
MEDIUM:     john.smith@, jane.doe@
```

---

## Remediation Priority Matrix

| Priority | Action | Accounts | Owner | Deadline |
|----------|--------|----------|-------|----------|
| **P0 — NOW** | Revoke all sessions + force password reset | `j.morrison` (possible compromise) | IT Security / CISO | Immediate |
| **P0 — NOW** | Block `185.220.101.0/24` at firewall | N/A | Network Ops | Immediate |
| **P1 — Today** | Force password reset + MFA enrollment | All CRITICAL accounts (3) | IT Help Desk | EOD |
| **P1 — Today** | Remove MFA exclusion for "VIP Users" group | CEO, Head of M&A | Azure AD Admin | EOD |
| **P1 — Today** | Audit `j.morrison` M365 activity past 72hrs | `j.morrison` | SOC L2 | EOD |
| **P2 — 48hrs** | Force password reset | All HIGH accounts (4) | IT Help Desk | 48 hours |
| **P2 — 48hrs** | Deploy Sigma rule to SIEM | N/A | Detection Eng | 48 hours |
| **P3 — 1 week** | Force reset remaining 210 plaintext-risk accounts | All exposure list | IT Help Desk | 1 week |
| **P3 — 1 week** | Enable Azure AD Smart Lockout + account lockout policy | N/A | Azure AD Admin | 1 week |
| **P4 — 30 days** | Security awareness email — credential hygiene | All staff | Security Awareness | 30 days |

---

## Detection Rules Deployed

Three detection rules were developed and are ready for SIEM deployment:

| Rule | File | Platform | ATT&CK |
|------|------|----------|--------|
| Credential Stuffing — High Volume Multi-Account Failures | `sigma_credential_stuffing.yml` | Any (Sigma) | T1110.004 |
| Impossible Travel — Geographic Anomaly | `kql_hunt_queries.kql` (Query 2) | Azure Sentinel | T1078.004 |
| MFA Bypass on Sensitive Accounts | `kql_hunt_queries.kql` (Query 4) | Azure Sentinel | T1556 |
| Mailbox Forwarding Rule Created | `splunk_hunt_queries.spl` (Query 4) | Splunk | T1114.003 |

---

## Lessons Learned

**What worked well:**
- Dark web monitoring alert fired within 48 hours of breach compilation upload —
  within the window needed for preventive action before widespread exploitation
- HIBP API bulk query provided fast triage of 312 accounts in under 30 minutes
- Correlation of HIBP data against Azure AD Conditional Access policies surfaced the
  MFA exclusion gap that would not have been found through alert-driven investigation alone

**What needs improvement:**
- MFA should be enforced universally — no executive exclusions. This was a
  policy gap that could have resulted in confirmed C-suite compromise
- Account lockout policy was not configured aggressively enough — 94 stuffing
  attempts should have triggered lockout far earlier
- Breach monitoring should extend beyond email domain matching to include
  executive personal email addresses, which are often used for SaaS account registration

---

## Conclusion

This incident demonstrates the complete threat hunt lifecycle for credential
exposure: from dark web alert triage through API-based validation, internal log
correlation, anomaly detection, and remediation delivery. The most significant
finding — a probable CEO account compromise (FINDING-02) — was identified not
through an automated alert but through **proactive hunting**: correlating HIBP
breach risk data against authentication geography and MFA enforcement gaps.

The credential stuffing attempt (FINDING-01) shows that threat actors moved within
31 hours of the breach compilation upload. Organizations without proactive breach
monitoring and rapid response capability would have had no awareness of this
attack until a successful compromise was already underway.

**Forced resets and MFA enforcement for all CRITICAL accounts must be completed
before end of business today.**

---

## References

- [MITRE ATT&CK T1110.004 — Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)
- [HaveIBeenPwned API v3 Documentation](https://haveibeenpwned.com/API/v3)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Microsoft — Protecting Against Password Spray](https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-password-smart-lockout)
- [Sigma Rules — GitHub](https://github.com/SigmaHQ/sigma)
- [AbuseIPDB — 185.220.101.47](https://www.abuseipdb.com/)

---

*Previous: [Day 01 ←](../day-01/REPORT.md) | Next: [Day 03 →](../day-03/SCENARIO.md)*

---
*Report generated as part of the [Blaakpearl 30-Day Security Portfolio](../../README.md)*
