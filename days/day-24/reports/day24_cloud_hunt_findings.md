# Day 24 — Cloud Infrastructure Hunt Findings
## AWS CloudTrail Threat Hunt
**NovaCrest Capital Group | Case NCA-2026-06**
**Classification:** TLP:AMBER — Security Operations Use
**Author:** V. Willis, CISSP
**Hunt Window:** 2026-06-14 00:00 → 2026-06-21 00:00 UTC
**Attacker IP:** 198.51.100.99 | **Attacker AWS Account:** 987654321099

---

## Hunt Summary

All six hypotheses confirmed. The attacker conducted a comprehensive cloud
attack across all major AWS services within a 65-minute active window on
June 16, 2026. Two critical residual backdoors remain in the environment
and require immediate remediation.

| Hypothesis | Technique | Verdict | Finding Count |
|------------|-----------|---------|--------------|
| H1 — Cloud Enumeration | T1526 | ✅ CONFIRMED | 8 API calls |
| H2 — IAM Backdoor Creation | T1136.003 | ✅ CONFIRMED | 4 persistence mechanisms |
| H3 — Secrets Manager Access | T1555.006 | ✅ CONFIRMED | 3 secrets harvested |
| H4 — S3 Data Exfiltration | T1530 | ✅ CONFIRMED | 85 MB, 3 objects |
| H5 — EC2 Compute Abuse | T1578 | ✅ CONFIRMED | 3× GPU instances |
| H6 — CloudTrail/GD Tampering | T1562.008 | ✅ CONFIRMED | Logging stopped; GD disabled |

**Critical residual risk:** IAM backdoor user `svc-monitoring-ops` and cross-account
role `CrossAccountReadRole` remain active. Both must be deleted immediately.

---

## Attacker Timeline (UTC, June 16, 2026)

```
09:00:11  GetCallerIdentity    → Credential verified (trading-api-deploy)
09:00:45  AssumeRole           → novacrest-admin-role assumed (SYSTEM-LEVEL ACCESS)

09:01:03  ListUsers            → ┐
09:01:18  ListRoles            → │ 8 enumeration calls in 2.5 minutes
09:01:45  ListBuckets          → │ Complete AWS inventory obtained
09:02:10  DescribeInstances    → │
09:02:33  ListSecrets          → │
09:02:58  ListFunctions        → │
09:03:20  ListModels           → ┘

09:05:02  StopLogging          → ⚠️ CloudTrail STOPPED (evidence destruction)
09:05:18  UpdateDetector       → ⚠️ GuardDuty DISABLED

09:10:05  GetSecretValue       → Bloomberg API key harvested
09:10:22  GetSecretValue       → RDS trading-db password harvested
09:10:38  GetSecretValue       → Trading execution API key harvested

09:15:44  CreateUser           → Backdoor user 'svc-monitoring-ops' created
09:16:02  AttachUserPolicy     → AdministratorAccess attached to backdoor user
09:16:28  CreateAccessKey      → Persistent key AKIAIOSFODNN7BACKDOOR created
09:18:11  CreateRole           → CrossAccountReadRole created (trust: acct 987654321099)

09:25:01  GetObject            → account-balances-2026-06.csv (4 MB)
09:27:14  GetObject            → eod-positions-2026-06-15.parquet (18 MB)
09:29:45  GetObject            → trading-signal-v3.tar.gz (60 MB)

10:05:33  RunInstances         → 3× p3.8xlarge GPU instances (crypto mining)

ACTIVE WINDOW: 09:00 → 10:05 UTC (65 minutes)
BACKDOOR KEY LAST USED: 2026-06-18T14:33:00Z (2 days after main activity)
```

---

## H1 — Cloud Enumeration

**Attacker mapped the entire AWS environment in 2.5 minutes.** Eight
discovery API calls across IAM, S3, EC2, Secrets Manager, Lambda, and
SageMaker gave the attacker a complete picture of NovaCrest's cloud
footprint before any destructive action began.

The attacker prioritized `ListSecrets` early — confirming that the secrets
naming convention (seen in the `bloomberg-api-tools` GitHub repo) matched
production, allowing targeted `GetSecretValue` calls later.

**Gap identified:** No alerting on enumeration burst patterns in CloudTrail.
A single external IP making 8+ List/Describe calls within 5 minutes should
trigger an alert. No GuardDuty finding fired (GuardDuty was active at this
point but did not detect the enumeration pattern — this is a GuardDuty coverage
gap for account enumeration).

---

## H2 — IAM Backdoor Creation (RESIDUAL RISK)

The attacker created **four persistence mechanisms** within 3 minutes:

### Mechanism 1: Backdoor IAM User
```
User:    svc-monitoring-ops
Policy:  AdministratorAccess (full AWS access)
Key ID:  AKIAIOSFODNN7BACKDOOR
Status:  ACTIVE — KEY STILL WORKING
Last used: 2026-06-18T14:33:00Z from eu-west-1
```

The key was used **2 days after** the main attack — confirming the attacker
returned to the environment using the backdoor. The eu-west-1 region use
(NovaCrest has no resources there) is a strong indicator of external use.

### Mechanism 2: Cross-Account Role
```
Role:    CrossAccountReadRole
Trust:   arn:aws:iam::987654321099:root (attacker account)
Policies: ReadOnlyAccess + AmazonS3FullAccess
MFA:     NOT required
Status:  ACTIVE — any IAM entity in account 987654321099 can assume this role
```

This role allows the attacker to assume into the NovaCrest account from their
own AWS account — a persistent backdoor that survives the original compromised
key being revoked. The S3 Full Access policy provides continued data exfiltration
capability.

**CRITICAL: Both backdoors must be deleted before this report is published.**

---

## H3 — Secrets Manager Credential Harvest

Three secrets were accessed via `GetSecretValue`:

| Secret | Content | Business Risk |
|--------|---------|---------------|
| `novacrest/bloomberg/api-key` | Bloomberg Terminal API credentials | Direct market data access; trade execution risk |
| `novacrest/rds/trading-db-password` | PostgreSQL trading database | All trading positions, client accounts, algorithm configs |
| `novacrest/trading/execution-api-key` | Broker execution API | **Direct market manipulation risk** — attacker can place trades |

**The trading execution API key is the most severe finding.** An attacker with
this key can place orders through NovaCrest's execution venue, potentially
manipulating market prices in assets NovaCrest trades. This must be rotated
immediately and all execution venue activity audited from June 14 onward.

---

## H4 — S3 Data Exfiltration via CloudTrail Data Events

Three S3 objects downloaded via the admin role session:

| Object | Size | Data Type | Regulatory Impact |
|--------|------|-----------|------------------|
| `client-data/account-balances-2026-06.csv` | 4 MB | Client PII + balances | SEC Reg S-P |
| `algorithms/eod-positions-2026-06-15.parquet` | 18 MB | Live trading positions | SEC Rule 10b-5 |
| `sagemaker/trained/trading-signal-v3.tar.gz` | 60 MB | Proprietary ML model | Trade secret theft |

**Total cloud exfil:** 82 MB via CloudTrail-recorded S3 GetObject.

Combined with the 125 MB HTTPS exfil (Day 18) and 85 MB S3 upload, the total
confirmed exfiltration is now approximately **335 MB** across all channels.

---

## H5 — EC2 GPU Instance Abuse

Three `p3.8xlarge` instances were launched from the attacker IP:
- Instance type: p3.8xlarge (4× NVIDIA V100 GPUs each)
- Tag: `Name: monitoring-node` (masquerading as legitimate monitoring)
- Estimated cost at time of detection: $3× $12.24/hr = $36.72/hr

GuardDuty `CryptoCurrency:EC2/BitcoinTool.B!DNS` finding would normally
fire when the instance contacts mining pool DNS — but GuardDuty was disabled
at 09:05:18 (before instance launch at 10:05:33).

**Status:** Instances were terminated during incident response. Total accrued
compute cost from attacker activity: estimated $220 before termination.

---

## H6 — CloudTrail and GuardDuty Tampering

The attacker's **first defensive action** (before any data access) was to
disable logging:

1. **09:05:02 — StopLogging:** CloudTrail logging halted for the main trail.
   All subsequent CloudTrail events were only captured because a **secondary
   S3-delivery trail** existed (the attacker only stopped the CloudWatch delivery).
   The S3-delivered logs captured the remaining activity. This saved the investigation.

2. **09:05:18 — UpdateDetector (enable=false):** GuardDuty disabled. This
   prevented the EC2 crypto mining detection from firing 60 minutes later.

**Critical lesson:** The incident would have gone entirely undetected if the
secondary CloudTrail S3 delivery trail hadn't existed. All environments must
have at least two independent CloudTrail delivery mechanisms — one can always
be disabled by a compromised admin.

---

## Immediate Remediation Actions

```
🔴 IMMEDIATE (next 30 minutes):
  aws iam delete-access-key \
      --user-name svc-monitoring-ops \
      --access-key-id AKIAIOSFODNN7BACKDOOR

  aws iam detach-user-policy \
      --user-name svc-monitoring-ops \
      --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

  aws iam delete-user --user-name svc-monitoring-ops

  aws iam delete-role --role-name CrossAccountReadRole

🔴 URGENT (today):
  Rotate Bloomberg API key (contact Bloomberg support)
  Rotate trading execution API key (contact broker)
  Rotate RDS trading-db password (rolling restart required)
  Audit all execution venue trades from June 14 onward
  Re-enable CloudTrail: aws cloudtrail start-logging --name [trail-arn]
  Re-enable GuardDuty: aws guardduty update-detector --detector-id [id] --enable
```

---

*Day 24 — Cloud Infrastructure Hunt Findings*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
