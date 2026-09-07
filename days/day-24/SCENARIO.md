# Day 24 — SCENARIO.md
## Threat Hunt: Cloud Infrastructure Compromise
**NovaCrest Capital Group | AWS Environment**
**Classification:** TLP:AMBER — Security Operations Use
**Track:** Threat Hunting
**Tools:** AWS CloudTrail · GuardDuty · Pacu · Splunk · Elastic

---

## Hunt Context

The Week 3 engagement confirmed that an attacker used a GitHub-exposed AWS
key (`trading-api-deploy`) to assume the `novacrest-admin-role` from external
IP `198.51.100.99` on June 16, 2026. The Day 22 risk register scored this
RF-001 (CVSS 10.0 — Critical). The key was revoked as part of incident
response, but the question now is: **what did the attacker do between first
API call and key revocation, and is there any residual persistence?**

This hunt extends beyond the confirmed activity to answer:
1. What was the full scope of AWS API activity from the attacker?
2. Did the attacker establish persistence (new IAM users, roles, backdoors)?
3. Were any other AWS services accessed that weren't previously identified?
4. Are there signs of resource abuse (crypto mining, data pipeline exfil)?
5. Is there anything still active in the environment from the attacker?

**Hunt window:** 2026-06-14 00:00 UTC → 2026-06-21 00:00 UTC (7 days)

---

## AWS Environment Overview

**NovaCrest AWS Account:** `123456789012` (us-east-1 primary)

| Service | Purpose | Data Classification |
|---------|---------|---------------------|
| S3 | Trading data, client records, ML models | Confidential |
| RDS (PostgreSQL) | Trading positions, client accounts | Confidential |
| EC2 | Trading algorithm execution, API gateways | Internal |
| Lambda | Automated trading signal processing | Internal |
| IAM | Identity and access management | Restricted |
| CloudWatch | Logging and monitoring | Internal |
| SageMaker | ML model training (trading algos) | Confidential |
| Secrets Manager | Bloomberg API keys, DB credentials | Restricted |

**Initial compromise vector:** IAM access key `AKIA...DEPLOY` (trading-api-deploy)
exposed in public GitHub repo `jhenderson85/bloomberg-api-tools`.

---

## Hunt Hypotheses

| # | Hypothesis | ATT&CK | Data Source |
|---|-----------|--------|-------------|
| H1 | Attacker performed full IAM/resource enumeration | T1526 | CloudTrail: List*, Describe*, Get* |
| H2 | Attacker created persistent IAM backdoor (user/key/role) | T1136.003 | CloudTrail: CreateUser, CreateAccessKey, PutUserPolicy |
| H3 | Attacker accessed Secrets Manager for Bloomberg API key | T1555.006 | CloudTrail: GetSecretValue |
| H4 | Attacker accessed or exfiltrated S3 trading data | T1530 | CloudTrail: GetObject, ListBuckets |
| H5 | Attacker launched EC2 instances for crypto mining or pivot | T1578 | CloudTrail: RunInstances |
| H6 | Attacker modified CloudTrail or GuardDuty to evade detection | T1562.008 | CloudTrail: DeleteTrail, StopLogging, UpdateDetector |

---

## MITRE ATT&CK Coverage

| Technique | Name | Hunt Coverage |
|-----------|------|---------------|
| T1526 | Cloud Service Discovery | CloudTrail List/Describe calls |
| T1136.003 | Create Account: Cloud Account | IAM CreateUser, CreateRole |
| T1098.001 | Account Manipulation: Add Cloud Credentials | CreateAccessKey |
| T1555.006 | Credentials from Password Stores: Cloud Secrets | Secrets Manager GetSecretValue |
| T1530 | Data from Cloud Storage | S3 GetObject, unusual GetObject volume |
| T1537 | Transfer Data to Cloud Account | S3 cross-account replication |
| T1578 | Modify Cloud Compute Infrastructure | RunInstances, ModifyInstanceAttribute |
| T1562.008 | Disable Cloud Logs | DeleteTrail, StopLogging, UpdateDetector |
| T1078.004 | Valid Accounts: Cloud Accounts | AssumeRole, GetFederationToken |
| T1619 | Cloud Storage Object Discovery | ListBuckets, ListObjects |

---

## Attacker TTPs (FIN-NC-001 Cloud Playbook)

Based on threat intelligence for FIN-class financially motivated actors
operating in cloud environments:

```
Phase 1 — Reconnaissance (Enumeration)
  GetCallerIdentity → confirm key validity
  ListBuckets → inventory storage
  DescribeInstances → map compute
  ListUsers / ListRoles → map IAM
  ListSecrets → identify high-value secrets

Phase 2 — Privilege Escalation
  AssumeRole → escalate to admin role
  PutUserPolicy / PutRolePolicy → add inline policy
  CreateAccessKey → create persistent credential

Phase 3 — Collection
  GetSecretValue → harvest Bloomberg key, DB creds
  GetObject → download trading data
  GetSnapshotBlock → EBS snapshot data access

Phase 4 — Persistence
  CreateUser → backdoor IAM user
  AttachUserPolicy → attach AdministratorAccess
  CreateRole → trust policy from attacker AWS account

Phase 5 — Defense Evasion
  DeleteTrail / StopLogging → disable audit trail
  UpdateDetector (GuardDuty) → disable finding types
  PutBucketLogging → disable S3 access logging
```

---

## Deliverables

| File | Description |
|------|-------------|
| `SCENARIO.md` | This document |
| `LAB.md` | CloudTrail setup, GuardDuty config, Pacu recon simulation |
| `REPORT.md` | Hunt findings and remediation |
| `scripts/cloudtrail_hunter.py` | CloudTrail API activity analyzer |
| `scripts/iam_backdoor_detector.py` | IAM persistence and backdoor detection |
| `queries/cloudtrail_hunt.spl` | Splunk SPL: full 6-hypothesis hunt |
| `queries/cloudtrail_hunt.kql` | Sentinel KQL: cloud hunt equivalents |
| `reports/day24_cloud_hunt_findings.md` | Per-hypothesis findings report |
| `reports/day24_cloud_hardening.md` | AWS security hardening checklist |
| `artifacts/cloudtrail_iocs.json` | CloudTrail IOC manifest |

---

*Day 24 Scenario | Cloud Infrastructure Threat Hunt*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
