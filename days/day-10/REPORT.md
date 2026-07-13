# Lateral Movement Hunt Report
## Day 10 — Blast Radius Assessment: NovaCrest Capital Group

---

| Field | Details |
|-------|---------|
| **Analyst** | Blaakpearl |
| **Report Date** | 2025-01-18 |
| **Report Type** | Threat Hunt — Lateral Movement Investigation |
| **Classification** | Portfolio / Training Exercise |
| **Case ID** | NVC-IR-2025-004 |
| **Track** | Threat Hunting |
| **ATT&CK Phase** | Lateral Movement (TA0008) |
| **Hunt Window** | 2025-01-14 09:12 UTC – 2025-01-16 03:30 UTC (42.3 hours) |
| **Hunt Outcome** | No confirmed lateral movement — critical blast radius risk identified |

---

## Executive Summary

Following the confirmation of an LSASS credential dumping attempt on
DESKTOP-FIN-047 (Day 08), a structured hunt was conducted to determine
whether the threat actor used the compromised credentials to pivot to
other systems within the NovaCrest Capital Group domain. The hunt covered
the full 42.3-hour window of C2 activity, examining Windows authentication
logs, Kerberos ticket events, and DCOM/WMI execution telemetry.

**No confirmed lateral movement was detected.** NTLM authentication for the
compromised account (`mthompson`) matched the established 30-day baseline
with no anomalous destinations. Kerberos ticket requests showed no evidence
of encryption downgrade or multi-source ticket replay. No WMI or DCOM-spawned
processes were linked to the compromised account.

However, BloodHound attack path analysis surfaced a **critical unaddressed
risk**: a service account (`svc_backup`) with Backup Operators group
membership — a well-documented path to Domain Admin equivalent access —
had a historical login session recorded on DESKTOP-FIN-047. Whether this
account authenticated during the actual 11-day compromise window (versus
historically, prior to compromise) has not yet been confirmed. If `svc_backup`
credentials were cached in memory during the compromise window, they were
available to the same LSASS dumping capability confirmed in Day 08 —
representing a theoretical path to full domain compromise that was never
technically exploited but remained available to the attacker throughout
the dwell period.

**This is a negative finding with an important caveat: absence of confirmed
lateral movement does not eliminate the risk represented by credential
exposure. The svc_backup session history requires immediate validation.**

---

## Methodology

```
Phase 1 — Baseline Establishment (45 min)
  Data:    30 days of Event 4624 for compromised account
  Output:  Normal authentication destination pattern documented

Phase 2 — Pass-the-Hash Hunt (45 min)
  Query:   Event 4624, LogonType=3, AuthPackage=NTLM, hunt window
  Output:  Zero anomalous destinations found — negative finding

Phase 3 — Pass-the-Ticket Hunt (45 min)
  Query:   Events 4768/4769, encryption type, multi-source IP analysis
  Output:  No encryption downgrade, no multi-source replay — negative finding

Phase 4 — DCOM/WMI Hunt (30 min)
  Query:   Event 4688, parent process WmiPrvSE.exe/mmc.exe
  Output:  No linked activity to compromised account — negative finding

Phase 5 — BloodHound Blast Radius Analysis (45 min)
  Tool:    SharpHound collection + BloodHound path analysis
  Output:  svc_backup historical session — CRITICAL unresolved risk

Phase 6 — Playbook Development (30 min)
  Output:  Reusable lateral movement hunt playbook for future incidents
```

---

## Detailed Findings

---

### FINDING-01 — No Pass-the-Hash Lateral Movement Detected

**Severity:** 🟢 Low (negative finding)
**ATT&CK:** T1550.002 — Pass the Hash

**Description:**
Analysis of all Event 4624 (successful logon) records for the `mthompson`
account during the 42.3-hour compromise window found zero authentication
events to hosts outside the established 30-day baseline pattern. All NTLM
Type 3 logons during the window were consistent with the user's normal
behavior — authentication to DESKTOP-FIN-047 itself, occasional file share
access, and normal Exchange fallback authentication.

**Evidence:**
```
30-Day Baseline (pre-compromise):
  DESKTOP-FIN-047:  847 logons (user's own workstation)
  FILESERVER01:      12 logons (routine file access)
  EXCHANGE01:         8 logons (occasional OWA fallback)

Hunt Window (42.3 hours, Jan 14-16):
  DESKTOP-FIN-047:   6 logons — CONSISTENT with baseline rate
  FILESERVER01:      1 logon  — CONSISTENT with baseline rate
  No new destinations identified

Conclusion: NTLM authentication pattern for mthompson shows no deviation
consistent with credential replay to unauthorized destinations.
```

**Recommendation:**
This finding does not eliminate risk — it confirms only that Pass-the-Hash
was not used FROM the mthompson NTLM hash specifically. The LSASS dump
(Day 08) may have captured other cached credentials beyond the primary
user account. See FINDING-04 below.

---

### FINDING-02 — No Pass-the-Ticket Indicators

**Severity:** 🟢 Low (negative finding)
**ATT&CK:** T1550.003 — Pass the Ticket

**Description:**
Kerberos TGT (Event 4768) and TGS (Event 4769) analysis for the compromised
account found no encryption downgrade (no RC4/0x17 tickets — all observed
tickets used AES256), and no evidence of the same account's tickets being
used from multiple distinct source IP addresses within the hunt window —
the primary technical signature of ticket theft and replay.

**Evidence:**
```
Kerberos TGT Requests (Event 4768) — mthompson:
  Total requests in window: 4
  Encryption types:         100% AES256-CTS-HMAC-SHA1-96 (0x12)
  RC4 downgrade tickets:    0

Kerberos TGS Requests (Event 4769) — mthompson:
  Total requests in window: 11
  Services accessed:        CIFS/fileserver01, HTTP/exchange01,
                            (both consistent with baseline access pattern)
  Unique source IPs:        1 (10.10.5.47 — FIN-047's own IP, consistent)

Conclusion: No evidence of ticket extraction and replay from a second
source. Ticket lifetime and encryption parameters are consistent with
normal domain-issued Kerberos tickets.
```

**Recommendation:**
As with Finding-01, this confirms only that the mthompson account's own
Kerberos tickets were not observed being replayed elsewhere. It does not
address risk from other cached credentials.

---

### FINDING-03 — No DCOM/WMI Lateral Movement Execution Detected

**Severity:** 🟢 Low (negative finding)
**ATT&CK:** T1021.003 / T1047

**Description:**
Process creation events (Event 4688) spawned by `WmiPrvSE.exe` or `mmc.exe`
— the classic parent process signatures of WMI and DCOM-based lateral
movement — were reviewed across the domain during the hunt window. No
instances were found linking such execution to the mthompson account or
originating from DESKTOP-FIN-047's IP address.

**Evidence:**
```
Domain-wide WMI/DCOM-spawned process events in hunt window: 3 total
  All 3 attributed to: SCCM_Admin service account (scheduled patch deployment)
  Timestamps: consistent with documented Tuesday patch window
  Source: SCCM management server (not FIN-047)

Conclusion: The 3 events identified are consistent with routine, scheduled,
authorized IT administration activity — not attacker-driven lateral movement.
```

**Recommendation:**
No action required for this specific finding. Continue routine monitoring
of WMI/DCOM execution patterns as part of standard detection coverage —
this remains a documented gap from the Day 07 coverage analysis.

---

### FINDING-04 — CRITICAL: Unresolved Privileged Session Exposure Risk

**Severity:** 🔴 Critical
**ATT&CK:** T1003.001 (referenced from Day 08) / T1078.003 — Valid Accounts: Local Accounts

**Description:**
BloodHound attack path analysis of the NovaCrest Active Directory environment,
using data collected via authorized SharpHound enumeration, identified that
the service account `svc_backup` — a member of the **Backup Operators**
security group — has a historical login session recorded on
DESKTOP-FIN-047. Backup Operators group membership grants the ability to
read and write any file on domain controllers regardless of NTFS permissions,
a well-documented technique for achieving Domain Admin equivalent access
without direct membership in that group.

**The critical open question is timing:** BloodHound session data does not
by itself distinguish between a login that occurred years ago versus one
that occurred during the actual 11-day compromise window (January 5–16,
2025). If `svc_backup` authenticated to DESKTOP-FIN-047 at any point during
the compromise window — for any reason, including routine backup job
execution or IT support — its credentials would have been resident in
memory and available to the same LSASS access capability confirmed in the
Day 08 malware analysis.

**Evidence:**
```
BloodHound Findings:
  Compromised principal:  mthompson@novacrest.local
  Compromised host:       DESKTOP-FIN-047

  Direct admin rights (mthompson → other hosts): NONE
    → Standard user has no elevated access elsewhere (as expected)

  Shortest path mthompson → Domain Admins group: NOT FOUND
    → No direct or nested ACL path exists for this account specifically

  HasSession edge data — privileged accounts historically on FIN-047:
    Account:    NOVACREST\svc_backup
    Privilege:  Backup Operators (built-in security group)
    Capability: SeBackupPrivilege + SeRestorePrivilege — read/write ANY
                file on ANY domain-joined system including domain controllers
    Last seen:  2025-01-10 (BloodHound collection date — needs verification
                against actual event logs for exact authentication timestamp)

  UNRESOLVED: Was 2025-01-10 authentication event log-confirmed to have
  occurred, and did it fall within the Jan 5-16 compromise window?
  BloodHound session data reflects state at collection time and requires
  cross-reference with Event 4624 logs for exact timestamp confirmation.
```

**Risk Context:**
Backup Operators privilege is one of the most dangerous "hidden" privilege
escalation paths in Active Directory environments — it is often granted to
service accounts for legitimate backup software integration without security
teams recognizing the equivalent-to-Domain-Admin risk it represents. If
`svc_backup` was cached on FIN-047 during the compromise window, the
attacker had a theoretical path to full domain compromise throughout the
entire 11-day dwell period, regardless of whether the confirmed hunt findings
(01–03) show they exploited it.

**Recommendation:**
**Immediate priority action:** Cross-reference the BloodHound session
timestamp against Windows Security Event 4624 logs for `svc_backup`
specifically on DESKTOP-FIN-047 to determine the exact authentication
date. If confirmed within the Jan 5–16 window:
1. Treat as probable Domain Admin equivalent compromise
2. Immediately rotate `svc_backup` credentials
3. Initiate KRBTGT double-reset procedure (Domain Admin equivalent exposure protocol)
4. Review all Backup Operators group members for similar exposure
5. Remove Backup Operators privilege from any account that does not
   strictly require it — this is a systemic AD hardening gap, not an
   isolated finding

---

## MITRE ATT&CK Technique Matrix

| ID | Technique | Tactic | Finding | Result |
|----|-----------|--------|---------|--------|
| **T1550.002** | Pass the Hash | Lateral Movement | FINDING-01 | Negative (not detected) |
| **T1550.003** | Pass the Ticket | Lateral Movement | FINDING-02 | Negative (not detected) |
| **T1021.003** | DCOM | Lateral Movement | FINDING-03 | Negative (not detected) |
| **T1047** | Windows Management Instrumentation | Execution | FINDING-03 | Negative (not detected) |
| **T1078.003** | Valid Accounts: Local Accounts | Persistence | FINDING-04 | **Critical — unresolved** |
| **T1003.001** | LSASS Memory (referenced) | Credential Access | FINDING-04 | Confirmed capability (Day 08) |

---

## Risk Assessment — DREAD Scoring

| Finding | Damage | Reproducibility | Exploitability | Affected Users | Discoverability | **/50** | **Rating** |
|---------|:------:|:---------------:|:--------------:|:--------------:|:---------------:|:-------:|:----------:|
| FINDING-01 (No PtH) | 2 | 2 | 2 | 1 | 8 | **15** | 🟢 Low |
| FINDING-02 (No PtT) | 2 | 2 | 2 | 1 | 8 | **15** | 🟢 Low |
| FINDING-03 (No DCOM/WMI) | 2 | 2 | 2 | 1 | 8 | **15** | 🟢 Low |
| FINDING-04 (svc_backup exposure) | 10 | 6 | 8 | 10 | 2 | **36** | 🔴 Critical |

### Overall Hunt Risk Rating: 🔴 CRITICAL (driven entirely by Finding-04)

---

## Blast Radius Summary

```
CONFIRMED IMPACT:
  Host:        DESKTOP-FIN-047
  Account:     mthompson (standard user, Fixed Income Traders group)
  Scope:       Single workstation — no confirmed pivot

THEORETICAL WORST-CASE (pending svc_backup timing confirmation):
  IF svc_backup authenticated during compromise window:
    → Credentials cached and available to confirmed LSASS access (Day 08)
    → Backup Operators privilege = read/write any file, any domain host
    → Effectively equivalent to Domain Admin compromise
    → Scope: ENTIRE Active Directory domain, all domain controllers,
             all file shares, potential for Golden Ticket forgery via
             direct domain controller file access

  IF svc_backup did NOT authenticate during compromise window:
    → Risk remains theoretical, not realized
    → Scope: Confirmed limited to DESKTOP-FIN-047 as per Findings 01-03
```

---

## Immediate Action Required

| Priority | Action | Owner | Deadline |
|----------|--------|-------|----------|
| **P0** | Confirm svc_backup Event 4624 timestamp on FIN-047 vs compromise window | IR Team | 2 hours |
| **P0** | If confirmed in-window: rotate svc_backup credentials immediately | IT Security | Immediate |
| **P0** | If confirmed in-window: initiate KRBTGT double-reset procedure | AD Admin | Immediate |
| **P1** | Full domain-wide audit of Backup Operators group membership | AD Admin | 24 hours |
| **P1** | Review all service accounts with elevated privilege for similar exposure | Security Team | 48 hours |
| **P2** | Remove unnecessary Backup Operators membership domain-wide | AD Admin | 1 week |
| **P2** | Add BloodHound session-timing correlation to hunt playbook | Threat Hunt | 1 week |
| **P3** | Repeat this hunt for any other accounts identified in svc_backup review | Threat Hunt | 2 weeks |

---

## Detection Gap Update

This hunt confirms a gap identified in the Day 07 coverage analysis and
adds a new one:

```
Confirmed gap (Day 07):  T1047 (WMI execution) — no automated Sigma rule
New gap identified:       No automated correlation between BloodHound
                          session data and authentication event logs —
                          this manual cross-reference took 45 minutes
                          and should be automated for faster future hunts
```

**Recommendation for Week 3:** Build an automated script that ingests
BloodHound `HasSession` edges and cross-references each against Event
4624 timestamps to flag privileged session exposure automatically —
this would have answered the svc_backup timing question in this report
without manual correlation.

---

## Analyst Notes

**On the value of negative findings:**

Three of four hunt techniques in this investigation produced negative
results — no Pass-the-Hash, no Pass-the-Ticket, no WMI/DCOM lateral
movement. It would be tempting to treat this as an uneventful hunt. It is
not. Confirming the ABSENCE of lateral movement through disciplined,
documented technique-by-technique hunting is exactly as valuable as
confirming its presence — it allows the IR team to scope remediation
accurately rather than defaulting to "assume everything is compromised,"
which is both operationally paralyzing and financially costly.

**On BloodHound as a defensive tool:**

BloodHound is frequently associated with red team and penetration testing
work, but its highest value application is exactly what this hunt
demonstrates: defensive blast radius assessment. The tool did not tell us
what the attacker did. It told us what the attacker COULD have done — and
in doing so, surfaced a critical, previously undocumented privilege
escalation path (`svc_backup` → Backup Operators → Domain Admin equivalent)
that existed independent of this incident and represents a standing
organizational risk requiring remediation regardless of whether it was
exploited this time.

The unresolved timing question on `svc_backup` is the single most important
open item from this entire investigation. It should be the first action
taken after this report is read.

---

## References

- [MITRE ATT&CK T1550.002 — Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [MITRE ATT&CK T1550.003 — Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [BloodHound — SpecterOps](https://github.com/BloodHoundAD/BloodHound)
- [Microsoft — Backup Operators Privilege Risk](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [Microsoft — KRBTGT Account Password Reset Scripts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/kerberos-key-trust)
- [ATT&CK T1078.003 — Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/)

---

*Previous: [Day 09 ←](../day-09/REPORT.md) | Next: [Day 11 →](../day-11/SCENARIO.md)*

---
*Report generated as part of the [Blaakpearl 30-Day Security Portfolio](../../README.md)*
