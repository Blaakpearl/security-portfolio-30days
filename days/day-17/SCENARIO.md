# Day 17 — SCENARIO.md
## Threat Hunt: Privilege Escalation Detection
**NovaCrest Capital Group | Post-Compromise Hunt**
**Classification:** TLP:AMBER — Security Operations Use
**Hunt Type:** Hypothesis-Driven | Post-Confirmed Initial Access

---

## Hunt Context

A low-privilege endpoint (`WS-FIN-04`, Windows 11) was confirmed compromised
via phishing on June 14, 2026. The affected user account (`ncg\j.henderson`,
standard domain user, no admin rights) was the initial foothold. IR triage
confirmed the endpoint is contained; however, threat intelligence indicates
the threat actor group associated with this intrusion (FIN-class, financially
motivated) typically escalates privileges within 2–6 hours of initial access
before moving laterally.

**Hunt question:** Did the attacker attempt or succeed at privilege escalation
on `WS-FIN-04` or any other endpoint in the estate before containment? Are
escalation artifacts present on adjacent Linux hosts accessed by the same
user?

**Assumptions going in:**
- Initial access: confirmed (phishing → macro → low-priv shell)
- Lateral movement: unconfirmed (being hunted in parallel)
- Privilege escalation: unknown — this hunt answers that question
- Time window: June 14, 08:00–18:00 UTC (10-hour window)

---

## Hunt Hypotheses

| # | Hypothesis | Technique | Data Source |
|---|-----------|-----------|-------------|
| H1 | Attacker used token impersonation to elevate to SYSTEM | T1134.001 | Sysmon Event 10, Windows Security 4672 |
| H2 | Attacker abused a misconfigured sudo rule on Linux hosts | T1548.003 | auditd, /var/log/auth.log |
| H3 | Attacker exploited SUID/SGID binaries on Linux hosts | T1548.001 | auditd, find output logs |
| H4 | Attacker ran Kerberoasting to crack service account hashes | T1558.003 | Windows Security 4769, Zeek/PCAP |
| H5 | Attacker attempted UAC bypass to gain elevated token | T1548.002 | Sysmon Event 1, Windows Security 4688 |
| H6 | Attacker abused SeDebugPrivilege / SeImpersonatePrivilege | T1134 | Windows Security 4672, Sysmon |

---

## MITRE ATT&CK Coverage

| Technique | Sub-Technique | Name | Hunt Coverage |
|-----------|---------------|------|---------------|
| T1548 | T1548.001 | Abuse Elevation Control: SUID/SGID | Linux auditd |
| T1548 | T1548.002 | Abuse Elevation Control: Bypass UAC | Sysmon + Event 4688 |
| T1548 | T1548.003 | Abuse Elevation Control: Sudo & Sudo Caching | auditd |
| T1134 | T1134.001 | Access Token Manipulation: Token Impersonation | Sysmon Event 10 + 4672 |
| T1134 | T1134.002 | Access Token Manipulation: Create Process w/ Token | Sysmon Event 1 |
| T1558 | T1558.003 | Steal or Forge Tickets: Kerberoasting | Windows Security 4769 |
| T1068 | — | Exploitation for Privilege Escalation | Sysmon Event 1 (unusual parent-child) |
| T1055 | T1055.001 | Process Injection: DLL Injection | Sysmon Event 8 |

---

## Scope

**Windows estate (Sysmon + Windows Security Events):**
- `WS-FIN-04` (confirmed compromised endpoint) — primary focus
- `WS-FIN-05`, `WS-FIN-06` (same subnet — possible lateral movement targets)
- `SRV-AD-01` (Domain Controller — Kerberoasting requests sourced here)

**Linux estate (auditd + /var/log/auth.log):**
- `lnx-trade-01`, `lnx-trade-02` (trading application servers)
- `lnx-db-01` (database server — accessed by `j.henderson` service account)

**Time window:** 2026-06-14 08:00–18:00 UTC

---

## Hunt Workflow

```
1. Baseline — establish normal behavior for j.henderson account
   └── Logon history, normal processes, typical privilege level

2. H1: Token Impersonation Hunt
   └── Sysmon 10: j.henderson process accessing LSASS / high-priv processes
   └── Security 4672: Special privileges assigned at logon (unexpected)

3. H2: Sudo Abuse Hunt (Linux)
   └── auditd: sudo commands by ncg service account
   └── /etc/sudoers: misconfigured rules

4. H3: SUID Binary Exploitation Hunt (Linux)
   └── auditd: execution of known SUID GTFOBins
   └── find / -perm -4000 output: unexpected SUID binaries

5. H4: Kerberoasting Hunt
   └── Security 4769: TGS requests with RC4 encryption (0x17)
   └── Volume anomaly: many 4769s from single source in short window

6. H5: UAC Bypass Hunt
   └── Sysmon 1: fodhelper.exe, eventvwr.exe, sdclt.exe spawning shells
   └── Registry: HKCU Software\Classes\ms-settings (common UAC bypass key)

7. H6: Dangerous Privilege Assignment Hunt
   └── Security 4672: SeDebugPrivilege, SeImpersonatePrivilege on user token

8. Correlation — chain findings across hypotheses
   └── Build timeline: which techniques triggered, in what order?

9. Confirm or rule out each hypothesis
   └── Document evidence for confirmed; document absence of evidence for ruled-out
```

---

## Deliverables

| File | Description |
|------|-------------|
| `SCENARIO.md` | This document |
| `LAB.md` | Lab setup: Sysmon config, auditd rules, log ingestion |
| `REPORT.md` | Hunt findings, confirmed/ruled-out hypotheses, playbook |
| `scripts/privilege_escalation_hunter.py` | Automated hunt script across log sources |
| `scripts/suid_audit_scanner.py` | Linux SUID/SGID binary auditor |
| `queries/splunk_privesc_hunt.spl` | Splunk SPL hunt queries (all 6 hypotheses) |
| `queries/sentinel_privesc_hunt.kql` | Sentinel KQL hunt queries |
| `reports/day17_hunt_findings.md` | Detailed findings per hypothesis |
| `reports/day17_escalation_playbook.md` | Detection playbook + hardening checklist |

---

*Day 17 Scenario | Threat Hunt: Privilege Escalation*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
