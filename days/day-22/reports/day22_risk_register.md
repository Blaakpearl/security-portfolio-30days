# Day 22 — Risk Register
## NovaCrest Capital Group | Post-Incident Risk Assessment
**Classification:** TLP:AMBER — Internal Distribution
**Author:** V. Willis, CISSP
**Date:** 2026-06-22
**Version:** 1.0 Final

---

## Risk Register Summary

| ID | Finding | CVSS 3.1 | DREAD | ATT&CK Tier | Priority |
|----|---------|----------|-------|-------------|---------|
| RF-001 | GitHub-Exposed AWS Credentials | **10.0** Critical | **9.8** | Tier 1 Critical | **P1** |
| RF-007 | 253 MB Data Exfiltrated (PII + Trading IP) | **9.6** Critical | **9.2** | Tier 1 Critical | **P1** |
| RF-005 | Zeek/auditd SIEM Coverage Gap | **9.3** Critical | **9.2** | Tier 1 Critical | **P1** |
| RF-002 | NOPASSWD Sudo (svc_ncg → find) | **8.8** High | **8.2** | Tier 2 High | **P2** |
| RF-003 | SUID GTFOBins (find, python3, vim) | **8.8** High | **8.4** | Tier 2 High | **P2** |
| RF-004 | Kerberoastable Accounts (RC4 + Weak Password) | **8.5** High | **7.6** | Tier 2 High | **P2** |
| RF-009 | No DLP on S3 Uploads (85 MB Undetected) | **8.5** High | **7.8** | Tier 2 High | **P2** |
| RF-008 | Security Log Cleared (649 Events Destroyed) | **8.2** High | **8.2** | Tier 3 Medium | **P2** |
| RF-010 | Domain Fronting C2 Channel | **8.0** High | **6.6** | Tier 2 High | **P2** |
| RF-006 | TLS Inspection Disabled | **7.5** High | **8.2** | Tier 2 High | **P2** |

---

## RF-001 — GitHub-Exposed AWS Credentials
**Category:** Credential Exposure | **Technique:** T1552.001 (Cloud Credentials)
**Priority:** P1 — CRITICAL | **Owner:** DevOps / Cloud Security | **Due:** 2026-06-25

| Methodology | Score | Rating |
|-------------|-------|--------|
| CVSS 3.1 | 10.0 | Critical |
| DREAD | 9.8/10 | Critical |
| ATT&CK Tier | 5.0/5.0 | Tier 1 Critical |
| **Unified** | **0.97** | **P1 — CRITICAL** |

**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

**DREAD Breakdown:**
- Damage: 10 — Full AWS admin access; all cloud assets reachable
- Reproducibility: 10 — TruffleHog / GitLeaks automated scan
- Exploitability: 10 — `aws sts get-caller-identity` + `AssumeRole` in minutes
- Affected: 9 — All cloud resources; most internal systems via VPC
- Discoverability: 10 — GitHub dorks; automated secret scanners

**ATT&CK Tier Rationale:**
- Detectability gap: 5 — External recon; no internal signals
- Business impact: 5 — Trading platform + client data + full cloud admin
- Prevalence: 5 — Credential hunting in every attacker playbook

**Business Impact:** Confirmed exploitation. Attacker assumed `novacrest-admin-role`
from external IP, achieved full AWS admin, enumerated S3, and accessed trading data.
This single credential was the root cause enabling the entire cloud-side of the breach.

**Regulatory Exposure:** SEC Reg S-P; NY DFS §500.07; SOX (access control failure)

**Remediation:**
1. ✅ Revoke and rotate AWS key (completed Day 16 response)
2. Enable AWS Config: `access-keys-rotated` rule (90-day maximum)
3. Deploy `git-secrets` or `TruffleHog` pre-commit hook in all repos
4. Enable GitHub secret scanning with push protection on organization
5. Retroactive audit: `trufflehog github --org novacrest` (check all branches)

---

## RF-007 — 253 MB Data Exfiltrated (Trading Algorithms + Client PII)
**Category:** Data Loss — Confirmed Exfiltration | **Technique:** T1567.002, T1041
**Priority:** P1 — CRITICAL | **Owner:** CISO / Legal / Compliance | **Due:** 2026-07-17

| Methodology | Score | Rating |
|-------------|-------|--------|
| CVSS 3.1 | 9.6 | Critical |
| DREAD | 9.2/10 | Critical |
| ATT&CK Tier | 4.8/5.0 | Tier 1 Critical |
| **Unified** | **0.94** | **P1 — CRITICAL** |

**Data Confirmed Exfiltrated:**
- `/opt/trading/algos/` — 17 trading algorithm files (125 MB archive)
- `/etc/bloomberg/api.key` — Bloomberg Terminal API credential
- Trading position logs (`eod_positions_*.csv`)
- Client account balances via CloudTrail (`account-balances.csv` — GetObject confirmed)
- `~/.ssh/` private keys from lnx-trade-01

**Exfiltration Channels:**
- DNS tunneling (small volume — `t1.evil-c2.com`, 5 TXT/NULL queries)
- HTTPS to Cobalt Strike C2 (198.51.100.99:443) — 125 MB
- S3 upload to `novacrest-exfil.s3.amazonaws.com` — 85 MB
- Recurring automated transfers (30-min intervals, 22 MB each)

**Regulatory Exposure (all three are mandatory notifications):**

| Regulation | Trigger | Deadline | Action |
|------------|---------|----------|--------|
| SEC Regulation S-P | Client financial PII exfiltrated | **July 17, 2026** | NOTIFY |
| NY DFS §500.17 | Material cybersecurity event | **June 19, 2026** | **OVERDUE** |
| SEC Regulation SCI | Trading system compromise | Promptly | NOTIFY |

**Remediation:**
1. **Notify NY DFS immediately** (72-hour deadline was June 19 — overdue)
2. Notify SEC (Reg S-P) — engage outside counsel for breach notification letter
3. Notify affected clients — legal to determine scope and timing
4. Bloomberg: revoke API key; request audit of API usage since June 14
5. Rebuild trading algorithm repository from pre-June 14 backup; verify integrity
6. Deploy Purview Endpoint DLP on all Windows workstations
7. Configure Zscaler Cloud App Control to block unauthorized cloud storage

---

## RF-005 — Zeek/auditd Not Forwarded to SIEM
**Category:** Detection Gap — SIEM Coverage | **Technique:** T1562.001
**Priority:** P1 — CRITICAL | **Owner:** Security Operations | **Due:** 2026-06-30

| Methodology | Score | Rating |
|-------------|-------|--------|
| CVSS 3.1 | 9.3 | Critical |
| DREAD | 9.2/10 | Critical |
| ATT&CK Tier | 4.8/5.0 | Tier 1 Critical |
| **Unified** | **0.93** | **P1 — CRITICAL** |

**Impact:** The entire Day 18 exfiltration was invisible in real time.
Detection was only possible via retrospective log forensics 48+ hours later.
During an active intrusion, this delay is the difference between blocking
data exfil and a confirmed PII breach.

**Remediation:**
1. Forward Zeek logs to Elastic via Filebeat (estimated: 2 hours)
2. Forward auditd to Elastic via Filebeat Linux audit module (estimated: 1 hour)
3. Deploy EQL exfil detection rules (elastic_killchain.eql Phase 8 rule)
4. Configure UEBA baseline on all endpoints (30-day baseline, 3σ alert)
5. Monthly SIEM coverage audit — verify all log sources ingesting

---

## RF-004 — Kerberoastable Service Accounts
**Category:** Credential Policy | **Technique:** T1558.003
**Priority:** P2 — HIGH | **Owner:** Active Directory / Identity | **Due:** 2026-07-05

| Methodology | Score | Rating |
|-------------|-------|--------|
| CVSS 3.1 | 8.5 | High |
| DREAD | 7.6/10 | High |
| ATT&CK Tier | 4.0/5.0 | Tier 2 High |

**Service Accounts Targeted:**
- `MSSQLSvc/sqlserver.novacrest.local:1433` — SQL Server service; read all DBs
- `http/intranet.novacrest.local` — Intranet service account
- `svc_backup/backup.novacrest.local` — **HIGHEST RISK** — Backup Operator rights

The `svc_backup` account has Backup Operator rights, which permit reading
all files on all domain-joined servers — functionally equivalent to DA for
data access purposes.

**Remediation:**
1. Reset all three kerberoasted account passwords to 25+ character random strings — URGENT
2. Convert to gMSA (240-bit auto-rotating passwords; eliminates Kerberoasting)
3. Force AES-256 only: `Set-ADUser svc_backup -KerberosEncryptionType AES256`
4. Remove RC4 encryption type from all service accounts
5. Audit all SPNs: any account with SPN + RC4 support is kerberoastable
6. Deploy Event 4769 RC4 alert (Splunk Query H4-B — Day 17)

---

## RF-002 & RF-003 — Linux Privilege Escalation Misconfigurations
**Category:** Misconfiguration | **Techniques:** T1548.003, T1548.001
**Priority:** P2 — HIGH | **Owner:** Linux Infrastructure | **Due:** 2026-06-28

Both findings reflect the same root cause: a Linux host configured for
operational convenience rather than security. The NOPASSWD sudo rule (RF-002)
and three unexpected SUID binaries (RF-003) each provided an independent
root escalation path. The attacker used both in sequence.

**Status:** Immediate remediation applied during incident (DONE):
- `chmod -s /usr/bin/find /usr/bin/python3 /usr/bin/vim`
- `/etc/sudoers.d/svc_ncg` NOPASSWD rule removed

**Ongoing remediation:**
1. Extend SUID audit to all Linux hosts (lnx-trade-02, lnx-db-01)
2. Schedule quarterly SUID baseline comparison
3. Deploy `suid_audit_scanner.py` (Day 17) to all hosts via Ansible

---

## RF-006 — TLS Inspection Disabled (Domain Fronting Undetected)
**Category:** Detection Gap — Proxy | **Technique:** T1090.004
**Priority:** P2 — HIGH | **Owner:** Network Security / Zscaler | **Due:** 2026-06-30
**Status:** ✅ Remediated — TLS inspection enabled before Day 21 capstone

Domain fronting was undetectable without TLS inspection. The control was
enabled between Day 20 (gap identified) and Day 21 (capstone) — and
successfully detected domain fronting in Phase 7 at T+17 minutes.

**Ongoing:** Quarterly review of TLS inspection coverage and bypass exception list.

---

## RF-008 — Windows Security Log Cleared
**Category:** Evidence Integrity | **Technique:** T1070.001
**Priority:** P2 — HIGH | **Owner:** Security Operations | **Due:** 2026-07-05

649 events destroyed. The gap was filled by Sysmon (which the attacker did
not clear) and Zeek (network-side). Evidence chain sufficient for legal
proceedings. However, real-time alerting on Event 1102 (log clear) would
have caught this in 3 minutes — confirmed by Day 21 capstone Phase 5.

**Remediation:**
1. ✅ Elastic EQL Rule for Event 1102/104 (deployed Day 21)
2. Enable Windows Event Forwarding with real-time streaming (not batch)
3. Legal hold: preserve all remaining log evidence

---

## RF-009 & RF-010 — DLP Gap and Domain Fronting C2
**Status:** RF-009 (DLP): Zscaler Cloud App Control configured; Purview DLP pending
**Status:** RF-010 (Domain Fronting): Detected in capstone after TLS inspection enabled

---

## Risk Score Distribution

```
CRITICAL (CVSS ≥ 9.0):  RF-001 (10.0), RF-007 (9.6), RF-005 (9.3)
HIGH (CVSS 7.0–8.9):    RF-002, RF-003, RF-004, RF-008, RF-009, RF-010, RF-006

P1 findings: 3  (RF-001, RF-007, RF-005)
P2 findings: 7  (all others)
P3 findings: 0
P4 findings: 0

Mean CVSS score: 8.77
Mean DREAD score: 8.27
Highest unified risk: RF-001 (0.97)
```

---

*Day 22 — Risk Register | NovaCrest Capital Group*
*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*
