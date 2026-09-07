# Day 24 — REPORT.md
## Threat Hunt: Cloud Infrastructure Compromise
**NovaCrest Capital Group | AWS Cloud Hunt**
**Track:** Threat Hunting
**Author:** V. Willis, CISSP
**Date:** 2026-06-24

---

## Summary

All six CloudTrail hunt hypotheses confirmed. The attacker conducted a
disciplined, multi-phase cloud attack across a 65-minute active window on
June 16, 2026. Two IAM backdoors created during the attack remain active
and were not identified during initial IR — this hunt discovered them.

| Metric | Result |
|--------|--------|
| Hunt hypotheses tested | 6 |
| Hypotheses confirmed | 6 (100%) |
| Active backdoors found | 2 (IAM user + cross-account role) |
| Secrets harvested | 3 (Bloomberg, RDS, trading execution key) |
| S3 data exfiltrated (CloudTrail) | 82 MB (3 objects) |
| EC2 GPU instances launched | 3× p3.8xlarge (terminated during IR) |
| Security controls tampered | 2 (CloudTrail stopped, GuardDuty disabled) |
| Backdoor key last used | June 18 — **attacker returned via backdoor** |

**Most critical finding:** The attacker created a persistent IAM backdoor
(`svc-monitoring-ops`) and returned to the environment 2 days after the
initial compromise, using the backdoor key from `eu-west-1`. Initial
incident response did not identify either backdoor — this hunt did.

---

## New Total Exfiltration Count

Combining Day 18 (endpoint exfil via Zeek) with Day 24 (cloud exfil via
CloudTrail data events):

| Channel | Volume | Data |
|---------|--------|------|
| HTTPS to C2 (Day 18) | 125 MB | Trading archive |
| S3 to attacker bucket (Day 18) | 85 MB | Bloomberg + trading |
| S3 GetObject via admin role (Day 24) | 82 MB | Client balances + ML model |
| DNS tunnel (Day 18) | < 1 MB | Credentials/API keys |
| **Total confirmed** | **~293 MB** | Trading IP + Client PII + ML models |

---

## The Secondary CloudTrail Trail Saved This Investigation

At 09:05:02, the attacker stopped the primary CloudTrail trail. If the
secondary S3-delivery trail had not existed, no CloudTrail evidence after
that point would be available — and the IAM backdoor, Secrets Manager
access, S3 exfil, and EC2 abuse would be entirely undetected in CloudTrail.

The secondary trail was an architectural decision made in 2023 as a
compliance requirement. It saved the forensic investigation in 2026.
**Every AWS environment should have at least two independent CloudTrail
delivery mechanisms.**

---

## Git Commit

```bash
cd security-portfolio-30days
git checkout main && git pull origin main

mkdir -p days/day-24/{scripts,queries,reports,artifacts}
cp -r /path/to/outputs/day24/* days/day-24/

git add days/day-24/

git commit -m "feat: Add Day 24 — Cloud Infrastructure Threat Hunt

Track: Threat Hunt | Tools: AWS CloudTrail, GuardDuty, Pacu, Splunk, Elastic
MITRE ATT&CK: T1526, T1136.003, T1555.006, T1530, T1578, T1562.008

Hunt results: 6/6 hypotheses confirmed
  H1 T1526    Cloud Enumeration    → CONFIRMED (8 API calls in 2.5 min)
  H2 T1136.003 IAM Backdoor        → CONFIRMED (2 backdoors — still active)
  H3 T1555.006 Secrets Manager     → CONFIRMED (3 secrets harvested)
  H4 T1530    S3 Data Exfil        → CONFIRMED (82 MB, 3 objects)
  H5 T1578    EC2 Compute Abuse    → CONFIRMED (3× p3.8xlarge GPU instances)
  H6 T1562.008 CloudTrail/GD Tamper→ CONFIRMED (logging stopped; GD disabled)

Critical new finding: IAM backdoor key last used June 18 (post-IR)
Total confirmed exfiltration across all channels: ~293 MB

Deliverables:
  SCENARIO.md, LAB.md, REPORT.md
  scripts/cloudtrail_hunter.py     (6-hypothesis CloudTrail analyzer)
  scripts/iam_backdoor_detector.py (IAM persistence detection + remediation)
  queries/cloudtrail_hunt.spl      (SPL — 6 hypotheses + full timeline)
  queries/cloudtrail_hunt.kql      (KQL — inline datatable + all queries)
  reports/day24_cloud_hunt_findings.md (per-hypothesis findings + timeline)
  reports/day24_cloud_hardening.md (AWS hardening checklist)
  artifacts/cloudtrail_iocs.json   (IOC manifest + remediation status)"

git push origin main
```

---

*Day 24 — Cloud Infrastructure Threat Hunt | NovaCrest Capital Group*
*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*
