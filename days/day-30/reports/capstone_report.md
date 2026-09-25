# NovaCrest Capital Group — Incident Analysis Report
## Case NCA-2026-06 | Complete Forensic & Intelligence Record
**Classification:** TLP:AMBER — Board of Directors and Legal Counsel
**Prepared by:** V. Willis, CISSP — Security Operations
**Portfolio:** github.com/Blaakpearl/security-portfolio-30days
**Report Date:** June 30, 2026

---

## Part I — What Happened

### The Beginning: One Instagram Photo

On March 22, 2026, Jennifer Henderson — Senior Financial Analyst at NovaCrest
Capital Group — posted a photo to her public Instagram account from the FinTech
Summit at the Javits Center. The photo contained intact GPS metadata placing her
at the conference. The caption included `#FinTechSummit2026`.

An attacker found that photo during reconnaissance. They used it to craft
a spearphishing email with the subject line "Q3 Investment Strategy — FinTech
Summit Follow-up," sent on June 14, 2026. The email contained a macro-enabled
Excel spreadsheet. Henderson opened it on her corporate laptop and enabled
the macros.

That single action gave an attacker persistent access to NovaCrest's network
for the next five days.

### Five Days of Undetected Attacker Activity

```
DAY 1 (Jun 14) — INITIAL ACCESS
  09:12  Sliver C2 implant deployed on WS-FIN-04 (10.0.1.40)
  09:14  First C2 beacon to 198.51.100.99:443
         JA3 a0e9f5d6... — Sliver C2 default fingerprint
         No detection. No alert. No response.

DAY 2 (Jun 15)
  Attacker compiles custom ransomware binary (LockBit 3.0 variant)
  Victim ID: NOVA-20260619-7X4K
  Binary compiled to encrypt NovaCrest-specific paths

DAY 3 (Jun 16) — CLOUD EXPLOITATION
  09:00  Attacker credential (trading-api-deploy key from GitHub) confirmed
  09:05  CloudTrail stopped / GuardDuty disabled
  09:10  Bloomberg API key harvested from Secrets Manager
         RDS password harvested
         Trading execution API key harvested
  09:15  IAM backdoor user 'svc-monitoring-ops' created (AdministratorAccess)
         CrossAccountReadRole created (trusts attacker AWS account 987654321099)
  09:25  Client account balances downloaded (4 MB)
         EOD trading positions downloaded (18 MB)
         ML trading model downloaded (60 MB)
  10:05  3× GPU instances launched (crypto mining; terminated during IR)

DAY 4 (Jun 17) — PRIVILEGE ESCALATION
  Pass-the-Ticket lateral movement to SRV-AD-01 (10.0.3.10)
  svc_backup Kerberos ticket obtained via Kerberoasting
  SYSTEM-level access on domain controller

DAY 5 (Jun 18) — STAGING
  IAM backdoor key AKIAIOSFODNN7BACKDOOR used from eu-west-1
  (Attacker verifying backdoor access still live)
  svchost32.exe (ransomware) staged on SRV-FS-01 via WMI

DAY 6 (Jun 19) — DETONATION
  03:15  Pass-the-Ticket to SRV-FS-01 (10.0.3.20)
  03:22  svchost32.exe launched via WmiPrvSE.exe
  03:23  44 seconds: Windows Defender stopped; VSS deleted;
         Windows Backup deleted; boot recovery disabled
  03:24  Encryption begins: .ncrypt extension; AES-256-CBC + RSA-4096
  06:12  Encryption complete: 26,168 files / 2,215 GB
  06:14  First detection: overnight team notices extension proliferation
         RANSOMWARE IS ALREADY COMPLETE
  06:31  Trading suspended; SRV-FS-01 isolated
```

### The Bill

- **Data exfiltrated:** ~293 MB (HTTPS C2 + AWS S3) + 82 MB cloud = ~375 MB total
- **Data encrypted:** 2,215 GB across three file shares
- **Ransom demanded:** $4.2M USD in Monero (XMR)
- **Ransom deadline:** June 22, 2026 at 06:14 UTC
- **Active backdoors found (not during initial IR):** 2 — IAM user + cross-account role

---

## Part II — The Investigation (Days 15–29)

The 30-day portfolio documents the complete investigation methodology:

| Days | Domain | Key Output |
|------|--------|-----------|
| 15–16 | Red Team | Initial access simulation confirming attack path |
| 17 | Threat Hunt | 6/6 privilege escalation hypotheses confirmed |
| 18 | Threat Hunt | 6/6 exfiltration hypotheses; 253 MB quantified |
| 19 | Forensics | 7-phase attack timeline; 649 deleted log events recovered |
| 20 | Purple Team | C2 exercise: Sliver detected T+3min; Havoc missed (DoH unblocked) |
| 21 | Full Stack | Week 3 capstone: 32/40 (80%); Mean MTTD 12.3 min |
| 22 | Threat Intel | 10 risk findings; RF-001 CVSS 10.0; <$50K remediation cost |
| 23 | OSINT | 4/5 employee photos geotagged; iPhone MDM confirms phishing vector |
| 24 | Threat Hunt | 6/6 cloud hypotheses; IAM backdoor found; 2 backdoors still active |
| 25 | Forensics | Ransomware analysis; 26,168 files; YARA rules; JFBI referral |
| 26 | Threat Intel | FIN-NC-001 profiled; 78% confidence GOLD MYSTIC; STIX bundle |
| 27 | Purple Team | 12 detection rules; 44% ATT&CK coverage; CI/CD pipeline |
| 28 | OSINT | 4 victims mapped; infrastructure graph; next campaign ~Aug 2026 |
| 29 | Full Stack | AI triage pipeline; 5 alerts triaged in 2.3s avg; 10,000× ROI |

---

## Part III — Who Did This

**Designation:** FIN-NC-001  
**Attribution confidence:** 78% (Admiralty B2 — Source: Usually Reliable / Info: Probably True)  
**Most likely group:** GOLD MYSTIC / LockBit affiliate

### Evidence Chain

1. **LockBit 3.0 binary** — Ghidra code diff confirms LockBit builder kit (leaked 2022). Custom victim build (compiled June 15, one day post-access).
2. **Ransom contact email** (`ncrypt-support@protonmail.com`) — Active since March 2026; three confirmed prior victims; responds within 4 hours; consistent 30–40% discount on deadline.
3. **C2 hosting** — AS209588 (Flyservers S.A., Netherlands/Panama); bulletproof VPS; consistent across all four victim campaigns; FS-ISAC flagged April 2026.
4. **Target selection formula** — Ransom = 0.1% of AUM. Four victims: $2.1B/$2.1M, $2.6B/$2.6M, $3.1B/$3.1M, $4.2B/$4.2M. Mathematical consistency confirms systematic pre-attack research.
5. **Infrastructure timing** — Every campaign: domain registered day 0, Let's Encrypt cert day 2, phishing day 8, ransomware day 13. Clockwork pattern across four victims.

### What They Did with Prior Victims

- UK Private Equity ($2.1B AUM): did not pay → data published (67 GB)
- EU Asset Manager ($2.6B AUM): did not pay → data published (42 GB)  
- US Hedge Fund ($3.1B AUM): **paid** (~$2M after negotiation) → data removed
- NovaCrest ($4.2B AUM): deadline June 22 → outcome pending

The actor honors the terms of payment. The actor also publishes when payment is not made. Both behaviors are consistent across all known victims — making this a rational negotiation, not just a threat.

---

## Part IV — What Went Wrong and Why

### Detection Failure Analysis

Every phase of the attack had detectable signals. None were caught in real time.

**Why the JA3 fingerprint wasn't caught:** DET-002 was engineered in Day 27 — it did not exist before the breach. The Sliver C2 JA3 `a0e9f5d6...` is publicly documented. A watchlist query running at the time of the June 14 C2 beacon would have fired within 60 seconds of infection.

**Why the cloud activity wasn't caught:** No CloudTrail detection rules existed for enumeration bursts, IAM backdoor creation, or Secrets Manager access. The attacker stopped CloudTrail at 09:05 UTC and GuardDuty immediately after. This worked because GuardDuty was not protected by an SCP preventing non-security-account modification. DET-011 (CloudTrail stopped) would have fired within 60 seconds of 09:05:02 UTC.

**Why the ransomware ran for 2 hours 48 minutes:** The VSS deletion rule (DET-008) existed before the breach but had zero test coverage. Nobody knew if it worked. DET-009 (ransomware encryption rate) did not exist. Both are in production now. Together they would have detected the ransomware within the first minute of detonation.

**The root cause isn't missing rules. It is missing engineering process.** A detection rule without tests, without a CI/CD pipeline, and without regular validation is a belief, not a control. Day 27 built the process. The rules followed.

### The OPSEC Failure That Could Have Prevented Everything

Jennifer Henderson's Instagram account was public. Her conference photo had GPS metadata intact. Her iPhone uploaded the photo through the Instagram app, which preserved the EXIF data.

This is not a technical failure. It is an awareness gap. The attacker didn't need to compromise any system to know she attended FinTech Summit 2026, that she worked in finance, and that an email referencing the summit would read as legitimate. They got all of that from a public social media post.

Mobile OSINT awareness is now part of the security program. The MDM policy enforces camera location services off. The security awareness training module covers this explicitly.

---

## Part V — The Recovery

### What Was Recoverable

**The June 13 backup is clean.** It predates the initial compromise by approximately 25 hours and has been verified against a hash taken at backup completion. Restoration from this backup does not require paying the ransom.

Estimated restoration timeline: 2–3 days for 2.2 TB of data to rebuild SRV-FS-01 from clean OS + data restore.

### What Must Be Done Before Restoration

Two active backdoors planted by the attacker remain in the AWS environment:

```
1. IAM user: svc-monitoring-ops
   Key: AKIAIOSFODNN7BACKDOOR (STILL ACTIVE as of this report)
   Policy: AdministratorAccess (full AWS control)
   Last used: June 18 from eu-west-1 — attacker returned after IR

2. IAM role: CrossAccountReadRole
   Trust: arn:aws:iam::987654321099:root (attacker AWS account)
   Policies: ReadOnlyAccess + S3FullAccess
   Status: ACTIVE — any entity in account 987654321099 can access NovaCrest AWS
```

These must be deleted before SRV-FS-01 is reconnected to the network. Rebuilding the file server while the attacker still has AWS administrative access is not remediation — it is handing them a clean target.

### Regulatory Calendar

| Obligation | Deadline | Status |
|-----------|----------|--------|
| NY DFS 72-hour notification | June 17, 2026 | **OVERDUE** |
| SEC material cybersecurity incident (proposed 4-day) | June 18, 2026 | **OVERDUE** |
| SEC Reg S-P (client financial data exfil) | 30 days from discovery | Due July 14 |
| FBI IC3 report | ASAP | Filed |
| Client notification (SEC Reg S-P) | Before public disclosure | In progress |

---

## Part VI — What Is Different Now

### Before (June 14, 2026 — Day 0 Security Posture)

- Zero purpose-built detection rules for financial sector threat actors
- No CloudTrail monitoring for enumeration, IAM backdoors, or secrets access
- No mobile device OSINT awareness or EXIF stripping policy
- Ransomware detected after 2 hours 48 minutes of active encryption
- No threat intelligence program for financial sector adversaries
- No AI-augmented triage capability

### After (June 30, 2026 — Day 30 Security Posture)

- 12 production detection rules covering 44% of confirmed FIN-NC-001 TTPs
- DET-002 (C2 JA3): would detect infection at first beacon — MTTD <1 min
- DET-009 (ransomware rate): would detect encryption within 60 seconds
- DET-011 (CloudTrail stop): 5-min response SLA — P1 critical
- CI/CD pipeline: all rules tested before production; GitHub Actions
- Mobile OSINT policy: MDM enforces camera GPS off; EXIF awareness training
- FIN-NC-001 STIX bundle shared with FS-ISAC (TLP:AMBER)
- AI triage pipeline: 847 alerts/month processed in 2.3s each; human-in-the-loop
- Complete forensic record: 30 days of documented methodology for FBI and regulators

### The Honest Assessment

The breach was preventable at multiple points. It was not prevented because:
the phishing email worked due to a public social media OPSEC gap; the C2 was
not detected because the JA3 rule didn't exist; the cloud compromise was not
detected because cloud detection content didn't exist; the ransomware ran for
nearly three hours because the VSS deletion rule had never been tested.

Every one of those gaps has been addressed. None of those gaps will be the
reason for a failure of the same kind again. Different gaps will exist —
they always do. The engineering process built in Day 27 is designed to find
them before an attacker does.

---

*NovaCrest Capital Group — Case NCA-2026-06*
*Complete Incident Analysis | 30-Day Portfolio Capstone*
*V. Willis, CISSP | github.com/Blaakpearl/security-portfolio-30days*
