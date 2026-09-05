# Day 21 — Purple Team Engagement Report
## Week 3 Capstone: Full APT Lifecycle Engagement
**NovaCrest Capital Group | Purple Team**
**Classification:** TLP:AMBER — Internal Security Use
**Exercise ID:** NCA-PURPLE-2026-06-21
**Purple Lead:** V. Willis, CISSP
**Exercise Date:** 2026-06-21 | 09:00–15:00 UTC

---

## 1. Executive Summary

NovaCrest's security team completed a full-stack purple team engagement
simulating the complete APT lifecycle of threat actor profile FIN-NC-001
across eight ATT&CK phases. The blue team scored **32 out of 40 points (80%)**,
detecting six of eight phases within SLA, one phase late, and missing one phase
entirely. Mean Time to Detect (MTTD) across detected phases was **12.3 minutes**
against a 20-minute SLA — a strong result, with two critical gaps remaining.

The engagement validates four weeks of detection engineering investment (Days
15–21). The two gaps identified — lateral movement correlation latency and
masquerading/renamed binary detection — are addressable with targeted tuning
rather than new tooling.

| Metric | Result | Target |
|--------|--------|--------|
| Total score | 32 / 40 pts (80%) | ≥ 30 pts (75%) |
| Phases detected within SLA | 6 / 8 | ≥ 6 |
| Phases detected late | 1 (Lateral Movement) | 0 |
| Phases not detected | 1 (Reconnaissance — expected) | 1 (acceptable) |
| Mean MTTD (detected phases) | 12.3 minutes | ≤ 15 minutes |
| Fastest detection | 3 minutes (Defense Evasion — log clear) | — |
| Slowest detection | 23 minutes (Lateral Movement — SLA miss) | ≤ 20 minutes |

---

## 2. Phase-by-Phase Results

### Phase 1 — Reconnaissance | ❌ NOT DETECTED (Expected)
**Score: 0/5 | MTTD: — | Techniques: T1592, T1589, T1593**

Red team conducted passive external reconnaissance: crt.sh certificate
transparency logs, Shodan scan, GitHub credential validation, and LinkedIn
employee scraping. No internal signals were generated. This is the expected
outcome — passive external recon is structurally invisible to endpoint and
network monitoring. Detection would require external honeypot infrastructure
(canary tokens, fake credentials) or threat intel feed matching on org-specific
IOCs (domain names, email patterns) in external scans.

**Verdict:** Acceptable miss. Documenting as architecture gap, not a detection
tuning issue.

---

### Phase 2 — Initial Access | ✅ DETECTED (T+8 min)
**Score: 5/5 | MTTD: 8 minutes | Techniques: T1566.001, T1059.001**

**What fired (in order):**
- **Zeek ssl.log (T+8:01):** Sliver JA3 `a0e9f5d64349fb13191bc781f81f42e1`
  matched on first beacon. Alert: "Known C2 JA3 — Sliver." Fired automatically
  via Elastic SIEM rule deployed after Day 20 workshop.
- **CrowdStrike Falcon (T+11:13):** ML detection on `WINWORD.EXE →
  powershell.exe -enc` process chain. Alert: "Office application spawning
  encoded PowerShell — suspicious."
- **Elastic SIEM (T+13:44):** EQL sequence rule corroborated both signals
  into a single high-confidence alert with ATT&CK mapping.

**Key lesson:** JA3 detection is the fastest initial access signal — 8 minutes
before EDR behavioral analysis fired. The JA3 blocklist deployed after Day 20
paid off immediately in the capstone.

---

### Phase 3 — Execution & Persistence | ✅ DETECTED (T+14 min)
**Score: 5/5 | MTTD: 14 minutes | Techniques: T1053.005, T1547.001**

**What fired:**
- **Elastic SIEM (T+14:22):** Event 4698 (Scheduled task created "SysCheck").
  EQL rule deployed from Day 21 Rule 2. Alert fired within SLA.

**What was missed:**
- **Registry Run Key (T1547.001):** Red team wrote to
  `HKCU\...\CurrentVersion\Run\WindowsUpdateSvc`. The Sysmon Event 13 fired
  but the SIEM alert rule for Run key persistence was not deployed. Run key
  writes require a Sysmon Event 13 filter on `*\CurrentVersion\Run*` with
  user exclusion — this rule exists in the Sigma library but was not imported
  into Elastic. Gap: single missing rule import.

**Key lesson:** Scheduled tasks (Event 4698) are detectable out of the box.
Run key persistence requires an explicit Sysmon Event 13 filter that must be
deliberately configured.

---

### Phase 4 — Privilege Escalation | ✅ DETECTED (T+6 min)
**Score: 5/5 | MTTD: 6 minutes | Fastest scored phase**
**Techniques: T1548.002, T1134.001, T1558.003**

**What fired:**
- **CrowdStrike (T+6:00):** Sysmon Event 10 — `svc_update.exe` opening
  `lsass.exe` with 0x1010 access. Immediate CrowdStrike alert.
- **Elastic SIEM (T+6:45):** Event 4672 with `SeImpersonatePrivilege` on
  standard user. Alert: "Dangerous privilege on non-system account."
- **Elastic SIEM (T+7:30):** Three RC4 TGS requests (Event 4769, 0x17
  encryption) in 4 seconds. Alert: "Kerberoasting burst detected."
- **Sysmon (T+8:12):** ms-settings registry write flagged by Elastic EQL
  sequence rule 3C.

**Key lesson:** Privilege escalation generates the most corroborating signals
of any phase — four independent detection points in under 3 minutes. This is
the best-instrumented phase in the stack. The investment in Day 17 hunt
queries directly translated into detection rules that fired here.

---

### Phase 5 — Defense Evasion | ✅ DETECTED (T+3 min — FASTEST)
**Score: 5/5 | MTTD: 3 minutes | Techniques: T1070.001, T1562.001, T1036**

**What fired:**
- **Elastic SIEM (T+3:01):** Event 1102 (Security audit log cleared). This
  is the self-documenting attack — clearing the log creates a record of the
  clearing. Alert fired in 3 minutes, the fastest detection of the entire
  exercise.
- **Elastic SIEM (T+3:44):** Event 5001 (Windows Defender real-time
  protection disabled). Second alert within same phase window.

**What was missed:**
- **Masquerading (T1036):** Red team renamed `Rubeus.exe` to `svccheck.exe`.
  The PE hash was still in CrowdStrike's threat intelligence database but the
  renamed binary executed before the ML scan completed. The binary ran for
  ~90 seconds before CrowdStrike flagged it — after the Kerberoasting had
  already completed. Gap: PE hash detection latency on rename.
- **Firewall rule disabled (T1562.004):** Red team disabled Windows Firewall
  via `netsh advfirewall set allprofiles state off`. No alert rule deployed
  for firewall state changes.

**Key lesson:** Log clearing is the easiest defense evasion detection precisely
because it's self-documenting. Red teams who skip this step lose evidence
destruction benefits but also avoid triggering the fastest detection signal
in the stack.

---

### Phase 6 — Lateral Movement | ⚠️ DETECTED LATE (T+23 min)
**Score: 2/5 | MTTD: 23 minutes (SLA: 20 minutes)**
**Techniques: T1021.002, T1550.002, T1047**

**What fired (late):**
- **Elastic SIEM (T+23:00):** Event 4648 (explicit credential use) + Event
  4624 LogonType 3 (network logon) from WS-FIN-04 to SRV-AD-01. WMI process
  creation (WmiPrvSE.exe spawning cmd.exe) corroborated.

**Root cause of SLA miss:**
The Elastic EQL correlation rule for lateral movement (Rule 5 — sequence by
`host.name` joining 4648 + 4624 + WMI spawn) took 23 minutes to fire because:
1. The 4648 and 4624 events had a 4-minute gap between them (normal for PtT)
2. WmiPrvSE.exe spawning cmd.exe required a third event in the sequence
3. The `maxspan=2m` on the 4648→4624 sequence was too narrow — extended to
   `maxspan=10m` during post-exercise debrief

**Fix:** Update EQL Rule 5 `maxspan` from 2m to 10m; deploy standalone WMI
remote execution alert (WmiPrvSE.exe spawning shell — no sequence join required).

---

### Phase 7 — C2 Establishment | ✅ DETECTED (T+17 min)
**Score: 5/5 | MTTD: 17 minutes | Techniques: T1071.001, T1090.004, T1573.002**

**What fired:**
- **Zscaler (T+17:00):** TLS inspection (enabled post-Day 20) revealed domain
  fronting: SNI=`legit.azure-cdn.net`, Host header=`cs.attacker-c2.com`.
  Alert: "Domain fronting detected — Host header does not match SNI."
- **Zeek ssl.log (T+19:10):** Cobalt Strike JA3 fingerprint matched on the
  second beacon to SRV-AD-01. Sliver and CS share overlapping JA3 hashes.

**Key lesson:** TLS inspection, disabled during Day 20 and identified as the
critical gap, was enabled before the capstone. The domain fronting technique
(which missed SLA in Day 20) was caught within SLA in Day 21 — a direct
demonstration of the detection improvement cycle.

**What was missed:**
- **Sleep jitter (T1001.001):** The 600-second beacon with 35% jitter produced
  only 5 connections in the 45-minute phase window. Beacon timing CV analysis
  requires ≥8 connections for reliable CV calculation. With 5 connections the
  CV was 0.31 — suspicious, but below the high-confidence threshold. Gap:
  timing analysis needs extended observation window.

---

### Phase 8 — Collection & Exfiltration | ✅ DETECTED (T+11 min)
**Score: 5/5 | MTTD: 11 minutes | Techniques: T1560.001, T1041, T1567.002**

**What fired:**
- **Zeek files.log (T+11:00):** 85 MB gzip archive transferred to external
  IP. MIME type `application/x-gzip`, filename `trading_data_20260621.tar.gz`.
- **Zscaler DLP (T+11:30):** Upload blocked to attacker S3 bucket
  (`novacrest-exfil.s3.amazonaws.com`). DLP policy deployed after Day 18.
  Alert: "Large file upload to unauthorized cloud storage — BLOCKED."
- **UEBA (T+12:15):** WS-FIN-04 egress volume 4.6× above 30-day baseline.

**Significant improvement from Day 18:** In the Day 18 hunt, the S3 upload
generated zero alerts (DLP not configured). In the capstone, it was blocked.
The detection-to-prevention upgrade was implemented between exercises.

**What was missed:**
- **Local data staging (T1074.001):** Staging in `%SYSTEMROOT%\Temp\` was
  not alerted. This is a high-FP path (many legitimate processes write temp
  files here). Needs a compound rule: archive file type + staging path + user
  context (non-SYSTEM user staging > 50 MB).

---

## 3. Detection Layer Performance

| Layer | Phases Detected | Best Phase | Avg MTTD |
|-------|-----------------|-----------|---------|
| Elastic SIEM (EQL rules) | 6 | P5 Defense Evasion (3 min) | 11.8 min |
| CrowdStrike Falcon | 3 | P4 Priv Escalation (6 min) | 7.7 min |
| Zeek Network Analysis | 3 | P2 Initial Access (8 min) | 12.0 min |
| Zscaler Proxy + DLP | 2 | P8 Exfil — BLOCKED (11 min) | 14.0 min |

**Most valuable layer:** Elastic SIEM — detected or co-detected 6 of 8 phases.
JA3/JARM and the EQL correlation rules were the highest-signal sources.

**Most improved layer:** Zscaler — went from 0 detections in Day 20 (TLS
inspection off, DLP not configured) to 2 detections + 1 block in Day 21.

---

## 4. Week 3 Progress: Days 15–21

| Day | Topic | MTTD Baseline | Notes |
|-----|-------|--------------|-------|
| 15 | Red Team Recon | Undetected | 0% real-time detection |
| 16 | Initial Access | Undetected | 0 alerts despite 11 logged activities |
| 17 | Privilege Escalation Hunt | Hunt-only | No real-time alerts |
| 18 | Exfiltration Hunt | Hunt-only | Zeek logged; SIEM not ingesting |
| 19 | Log Forensics | Retrospective | 649 Security events destroyed |
| 20 | C2 Exercise | 12.8 min avg | Domain fronting missed; DoH undetected |
| **21** | **Full Stack Capstone** | **12.3 min avg** | **80% score; 2 gaps remain** |

**Trajectory:** Week 3 moved from zero real-time detection capability (Days
15–16) to 80% SLA compliance with a 12.3-minute mean MTTD. The detections
that failed in earlier days (JA3, domain fronting, Kerberoasting) all fired
correctly in the capstone because the detection rules written during the week
were deployed before the final exercise.

---

## 5. Remaining Gaps Summary

| Gap | Phase | Technique | Root Cause | Effort to Fix |
|-----|-------|-----------|------------|---------------|
| Passive recon undetectable | P1 | T1592/T1589 | Architecture — external activity | Medium (canary tokens) |
| Run key persistence missed | P3 | T1547.001 | Missing Sysmon Event 13 rule import | Low (30 min) |
| Masquerade/rename latency | P5 | T1036 | PE hash scan latency on rename | Low (tune CS policy) |
| Firewall disable not alerted | P5 | T1562.004 | No alert rule for netsh firewall | Low (1 new rule) |
| Lateral movement SLA miss | P6 | T1021/T1550 | EQL maxspan too narrow; WMI standalone rule missing | Low (EQL edit) |
| Sleep jitter undetected | P7 | T1001.001 | Timing analysis needs longer window | Medium (tuning) |
| Local staging not alerted | P8 | T1074.001 | Legitimate path; needs compound rule | Medium (rule design) |

**6 of 7 gaps are Low effort** — configuration and rule tuning, not new tools.

---

*Day 21 — Week 3 Capstone Engagement Report*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
