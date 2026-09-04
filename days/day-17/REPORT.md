# Day 17 — REPORT.md
## Threat Hunt: Privilege Escalation Detection
**NovaCrest Capital Group | Post-Compromise Hunt**
**Classification:** TLP:AMBER — Security Operations Use
**Author:** V. Willis, CISSP
**Date:** 2026-06-17

---

## 1. Hunt Outcome

**All six hypotheses confirmed.** The attacker achieved privilege escalation
via overlapping techniques within 90 minutes of initial access. No real-time
alerts fired during the escalation window. Hunt was conducted retrospectively
against log data from 2026-06-14 08:00–18:00 UTC.

| Metric | Result |
|--------|--------|
| Hypotheses tested | 6 |
| Confirmed | 6 (100%) |
| Escalation techniques identified | 6 distinct |
| Time from initial access to SYSTEM | ~15 min (Windows) |
| Time from initial access to root (Linux) | ~150 min |
| Real-time alerts during escalation | 0 |
| Log evidence available retroactively | 6/6 (all techniques logged) |

---

## 2. ATT&CK Coverage

| Technique | Confirmed | Primary Evidence Source |
|-----------|-----------|------------------------|
| T1134.001 Token Impersonation | ✅ | Sysmon Event 10 + Security 4672 |
| T1548.003 Sudo Abuse | ✅ | auditd SYSCALL + USER_AUTH |
| T1548.001 SUID Exploitation | ✅ | auditd SUID_EXEC key |
| T1558.003 Kerberoasting | ✅ | Security Event 4769 (RC4 ×3) |
| T1548.002 UAC Bypass | ✅ | Sysmon Event 13 + Event 1 |
| T1134 Privilege Assignment | ✅ | Security Event 4672 (SeTcbPrivilege) |

---

## 3. Key Findings

**Finding 1 — lsass.exe Access from Temp Directory Binary (Critical)**
`svc_update.exe` (staging in `%TEMP%`) opened lsass.exe at 09:15:22 with
0x1010 access. This binary is not signed and should have triggered an EDR
alert. It did not — EDR exclusion or bypass suspected.

**Finding 2 — SeTcbPrivilege on Standard User (Critical)**
Security Event 4672 shows `j.henderson` holding `SeTcbPrivilege` ("act as
part of the operating system"). This privilege is not assigned to any standard
user account by policy. Its presence indicates token impersonation succeeded
before the 09:15 lsass access — earlier escalation not yet in the log window.

**Finding 3 — Kerberoasting Confirmed at DC (Critical)**
Three RC4 TGS requests in 4 seconds from WS-FIN-04 to SRV-AD-01. The
`svc_backup` service account is kerberoastable and holds Backup Operator
rights. If this hash was cracked, the attacker can read all files on any
domain-joined server.

**Finding 4 — Three GTFOBin SUID Binaries on Production Linux Host (High)**
`find`, `python3`, and `vim` all had SUID set on `lnx-trade-01`. None are
in the Ubuntu baseline. All three are instant root shells via GTFOBins. This
represents an infrastructure misconfiguration predating this incident.

**Finding 5 — All Escalation Evidence Was Logged; None Was Alerted (High)**
Every technique above generated log evidence (Sysmon, auditd, Windows
Security). The gap is not instrumentation — it is alerting rules and SIEM
integration. The detection playbook in `day17_escalation_playbook.md`
addresses each gap with specific rules, hardening commands, and triage steps.

---

## 4. Immediate Response Actions

```
WINDOWS — WS-FIN-04:
  □ Isolate endpoint from network (containment)
  □ Enable PPL for lsass: reg add HKLM\...\Lsa /v RunAsPPL /t REG_DWORD /d 1
  □ Reset j.henderson password and all service accounts targeted in Kerberoasting
  □ Convert MSSQLSvc, http, svc_backup to gMSA with AES-only encryption
  □ Remove svc_update.exe from %TEMP%; submit for malware analysis

LINUX — lnx-trade-01:
  □ Remove SUID bits: chmod -s /usr/bin/find /usr/bin/python3 /usr/bin/vim
  □ Remove NOPASSWD rule: rm /etc/sudoers.d/svc_ncg
  □ Rotate svc_ncg credential
  □ Forward auditd to SIEM immediately

SIEM — ALL:
  □ Deploy SPL Queries H1-A through CORR-1 as scheduled alerts
  □ Deploy KQL equivalents in Sentinel
  □ Enable Sysmon Event 10 alerting for lsass access
  □ Enable Security Event 4769 RC4 alerting
```

---

## 5. Git Commit Commands

```bash
cd security-portfolio-30days
git checkout main && git pull origin main

mkdir -p day17/{scripts,queries,reports}
cp -r /path/to/outputs/day17/* day17/

git add day17/

git commit -m "feat: Add Day 17 — Threat Hunt: Privilege Escalation

Hunt type: Post-compromise, hypothesis-driven
Target: NovaCrest Capital Group mixed Windows/Linux estate
Window: 2026-06-14 08:00–18:00 UTC

Hypotheses:
  H1 T1134.001 Token Impersonation      → CONFIRMED (Sysmon 10 + 4672)
  H2 T1548.003 Sudo Abuse               → CONFIRMED (auditd GTFOBin)
  H3 T1548.001 SUID Exploitation        → CONFIRMED (3 unexpected SUID)
  H4 T1558.003 Kerberoasting            → CONFIRMED (3 RC4 TGS in 4s)
  H5 T1548.002 UAC Bypass               → CONFIRMED (fodhelper + ms-settings)
  H6 T1134    Privilege Assignment       → CONFIRMED (SeTcbPrivilege on user)

Result: 6/6 hypotheses confirmed; 0 real-time alerts during 90-min window

Deliverables:
  SCENARIO.md, LAB.md, REPORT.md
  scripts/privilege_escalation_hunter.py
  scripts/suid_audit_scanner.py
  queries/splunk_privesc_hunt.spl   (H1–H6 + correlation)
  queries/sentinel_privesc_hunt.kql (H1–H6 + correlation)
  reports/day17_hunt_findings.md    (per-hypothesis findings + timeline)
  reports/day17_escalation_playbook.md (detection playbook + hardening checklist)"

git push origin main
```

---

*Day 17 — Threat Hunt: Privilege Escalation*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
