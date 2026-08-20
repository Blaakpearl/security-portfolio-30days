# Day 16 — REPORT.md
## Purple Team Consolidated Findings: Initial Access Simulation
**NovaCrest Capital Group | Week 3 Adversary Simulation**
**Classification:** TLP:AMBER — Authorized Engagement Participants Only
**Author:** V. Willis, CISSP — Purple Team Lead
**Date:** 2026-06-16

---

## 1. Executive Summary

Day 16 demonstrated that reconnaissance intelligence (Day 15) translates
directly into initial access within hours. Two independent attack paths were
executed simultaneously; both succeeded. **Zero detections fired in real time.**
All 11 activities across both paths generated log evidence — none of that
evidence was monitored or alerted on.

| Metric | Result |
|--------|--------|
| Attack paths attempted | 2 |
| Attack paths successful | 2 (100%) |
| Real-time alerts generated | 0 |
| Activities with log evidence | 11 of 11 |
| Activities detectable (retroactively) | 11 of 11 |
| Root cause of all misses | Configuration gaps (not capability gaps) |
| Time from first API call to admin access | 10 minutes |
| Estimated time to live data exfiltration | 20 minutes |

The critical finding from this engagement: **every missed detection was a
configuration problem, not a tooling problem.** CloudTrail exists but isn't
in the SIEM. PostgreSQL audit extension isn't installed. Email alert rules
aren't written. The controls exist; they're just not turned on.

---

## 2. ATT&CK Coverage

| Technique | Activity | Detected |
|-----------|----------|----------|
| T1078.004 Cloud Accounts | AWS key use from GitHub | ❌ |
| T1087.004 Cloud Account Discovery | IAM user/role enumeration | ❌ |
| T1619 Cloud Storage Object Discovery | S3 bucket + object listing | ❌ |
| T1535 Unused Cloud Regions | (not triggered) | N/A |
| T1190 Exploit Public App (DB) | PostgreSQL external auth | ❌ |
| T1552.001 Credentials In Files | GitHub secrets exploitation | ❌ |
| T1566.001 Spearphishing Attachment | .docm macro variant crafted | ⚠️ Quarantined |
| T1566.002 Spearphishing Link | Link variant crafted | ⚠️ Quarantined |
| T1059.009 Cloud API | AWS CLI commands | ❌ |

**Legend:** ❌ Not detected | ⚠️ Partial (quarantined but no SOC alert)

---

## 3. Key Findings

### Finding 1 — Privilege Escalation Path in IAM (Critical)
The `novacrest-admin-role` directly trusts `trading-api-deploy` user.
Compromising the GitHub API key gives admin access to the entire AWS account
in one API call. This is the most dangerous single misconfiguration found
across both engagement days.

**Remediation:** Remove direct user trust; require bastion host + MFA for
any admin role assumption.

### Finding 2 — CloudTrail in the Dark (Critical)
CloudTrail logs 10 distinct API calls during Path A, including `GetCallerIdentity`,
`ListBuckets`, `AssumeRole`, and `GetObject` on sensitive data. All of these
events are stored in S3 but never forwarded to the SIEM. The SOC has zero
visibility into AWS control-plane activity.

**Remediation:** CloudTrail → CloudWatch Logs → SIEM. Estimated setup: 4 hours.

### Finding 3 — DMARC p=quarantine Insufficient (High)
Both phishing variants were quarantined by DMARC (correct) but not rejected.
End-user behavior — retrieving email from spam — is the only remaining control.
Upgrading to `p=reject` eliminates this risk at the SMTP level.

**Remediation:** Audit outbound sending sources; upgrade DMARC to `p=reject`.

### Finding 4 — Detection-to-Remediation Ratio is Excellent (Positive)
The gap between current detection (0%) and achievable detection (~82%) is
bridgeable in one week with existing tools. No new tooling purchases are
required to close the four highest-priority gaps.

---

## 4. Day 17 Preview

**Next session:** Post-Exploitation — Enumeration & Lateral Movement

With AWS admin access and PostgreSQL credentials established, Day 17 simulates
the post-exploitation phase: internal network enumeration, lateral movement
from the compromised web server to the trading engine, and credential pivoting
using the `api_keys` harvested from the database. Blue team will configure
east-west traffic monitoring and internal DNS detection.

---

## 5. Git Commit Commands

```bash
cd security-portfolio-30days
git checkout main && git pull origin main

mkdir -p day16/{scripts,queries,reports}
cp /path/to/outputs/day16/* day16/ -r

git add day16/

git commit -m "feat: Add Day 16 — Week 3 Initial Access Simulation

MITRE ATT&CK: T1078.004, T1190, T1566.001, T1566.002, T1552.001,
              T1087.004, T1619, T1059.009

Path A — Credential Exploitation:
- AWS key from GitHub → GetCallerIdentity → IAM enum → S3 access
- Privilege escalation: AssumeRole to admin (10 min from first call)
- PostgreSQL auth from external IP; api_keys table harvested

Path B — Spearphishing:
- Link variant (T1566.002): DMARC fail → quarantine; not rejected
- Attachment variant (T1566.001): password-protected .docm bypasses sandbox
- Estimated click rate: 15-25%

Detection: 0 real-time alerts; 11/11 activities log-evidenced
Root cause: CloudTrail not in SIEM; pgaudit not installed; no email alerts

Files:
- SCENARIO.md, LAB.md, REPORT.md
- scripts/credential_exploitation_simulator.py
- scripts/phishing_email_crafter.py
- queries/splunk_initial_access_detection.spl  (14 queries)
- queries/sentinel_initial_access_detection.kql (14 queries)
- reports/day16_red_team_initial_access.md
- reports/day16_blue_team_gap_analysis.md"

git push origin main
```

---

*Day 16 — Purple Team Consolidated Report*
*Week 3 Initial Access Simulation | NovaCrest Capital Group*
*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*
