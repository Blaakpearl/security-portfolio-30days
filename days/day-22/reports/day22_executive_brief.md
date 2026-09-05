# Executive Risk Brief
## NovaCrest Capital Group — Cybersecurity Incident Risk Assessment
**Date:** June 22, 2026
**Prepared by:** V. Willis, CISSP — Senior Cybersecurity Analyst
**Distribution:** CISO · General Counsel · Board Risk Committee · CFO

---

## Situation Summary

A confirmed cyberattack against NovaCrest Capital Group between June 14–18,
2026 resulted in unauthorized access to trading infrastructure and the
confirmed exfiltration of **253 MB of sensitive data** including proprietary
trading algorithms, Bloomberg API credentials, and client account records.

Forensic analysis is complete. Ten risk findings have been scored across
three independent methodologies. Three findings require immediate board-level
attention.

---

## Three Critical Findings

### 1. Confirmed Data Breach — Client PII + Trading IP
**CVSS: 9.6 / 10 | Priority: P1 — CRITICAL**

Approximately 253 MB of data was exfiltrated via three simultaneous channels:
an encrypted connection to an attacker-controlled server, an upload to an
attacker-controlled cloud storage bucket, and automated recurring transfers
continuing for at least one hour after initial exfiltration.

Data confirmed lost: 17 trading algorithm files, Bloomberg Terminal API
credentials, live trading position records, and client account balance data.

**Board action required:** Three regulatory notifications are legally mandated.
The NY DFS 72-hour notification (deadline June 19) is overdue. Engaging
outside counsel is strongly recommended.

### 2. External Credential Exposure — Cloud Administrator Access
**CVSS: 10.0 / 10 | Priority: P1 — CRITICAL**

An AWS administrative credential was inadvertently committed to a public
GitHub repository and remained exposed for an undetermined period prior to
discovery. The credential was confirmed exploited: CloudTrail logs show
the attacker assumed full administrative privileges from an external IP
address on June 16, 2026.

The credential has been revoked. A full audit of all code repositories for
historical exposure is underway.

### 3. Detection Infrastructure Gap
**CVSS: 9.3 / 10 | Priority: P1 — CRITICAL**

Network monitoring data (Zeek) and Linux audit logs (auditd) were not
connected to the SIEM at the time of the incident. As a result, the
June 14 exfiltration was not detected in real time — only confirmed
48 hours later through retrospective forensic analysis.

This gap has been remediated (configuration change, no new tools required).
Detection improved from 0% real-time visibility to 80% SLA compliance
during post-remediation testing (June 21 exercise).

---

## Regulatory Notification Status

| Regulation | Requirement | Deadline | Status |
|-----------|------------|----------|--------|
| **NY DFS 23 NYCRR §500.17** | Report material cyber event | June 19, 2026 | **OVERDUE** |
| **SEC Regulation S-P** | Notify customers of PII breach | July 17, 2026 | Required |
| **SEC Regulation SCI** | Report system compromise | Promptly | Required |

**Recommended action:** Engage outside cybersecurity counsel this week.
NY DFS notification should be filed immediately with explanation of delay.

---

## Remediation Status & Cost

| Category | Items | Status | Estimated Cost |
|----------|-------|--------|---------------|
| Immediate technical (P1) | 3 findings | 1 complete; 2 in progress | < $10K |
| Configuration changes (P2) | 7 findings | 4 complete; 3 in progress | < $25K |
| Regulatory notifications | 3 filings | 0 filed | Legal fees TBD |
| Client notification | Scope TBD | Assessment in progress | TBD |

The majority of technical remediation requires no new tooling — only
configuration changes to existing Zscaler, CrowdStrike, and Elastic
licenses already under contract. Engineering cost is estimated under $50K.

---

## Current Security Posture

Post-remediation testing on June 21 demonstrated significant improvement:
the security team detected 6 of 8 attack phases within defined SLA, with
a mean detection time of **12.3 minutes**. Prior to remediation (June 14),
the same attack techniques generated zero real-time alerts.

---

*V. Willis, CISSP | Senior Cybersecurity Analyst*
*github.com/Blaakpearl/Blaakpearl*
