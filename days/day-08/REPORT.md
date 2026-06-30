# Malware Analysis Report
## Day 08 — Static & Dynamic Analysis: updater.exe C2 Dropper

---

| Field | Details |
|-------|---------|
| **Analyst** | Blaakpearl |
| **Report Date** | 2025-01-17 |
| **Report Type** | Malware Triage — Static + Dynamic Analysis |
| **Classification** | Portfolio / Training Exercise |
| **Case ID** | NVC-IR-2025-004 |
| **Sample** | updater.exe |
| **Sample Path** | `C:\Users\Public\Libraries\updater.exe` |
| **Track** | Digital Forensics |
| **ATT&CK Phase** | Execution / Persistence / Credential Access / C2 |

---

## Executive Summary

Forensic examination of DESKTOP-FIN-047 during the NovaCrest Capital Group
incident yielded a previously unknown malicious executable at
`C:\Users\Public\Libraries\updater.exe`. Static and dynamic analysis confirms
the binary is a **custom C2 dropper** responsible for establishing and
maintaining the 11-day beacon identified in the Day 04 investigation. The
sample had zero antivirus detections at the time of analysis — confirming it
was purpose-built or specifically modified to evade public signature databases.

Combined static string extraction (FLOSS) and sandbox detonation revealed
the binary's complete operational lifecycle: it spawns a hidden PowerShell
process to download a second-stage payload from `185.220.101.33/stage2`,
injects into a legitimate `svchost.exe` process to hide its network activity,
establishes three separate persistence mechanisms (Scheduled Task, Registry Run
Key, and WMI Event Subscription — all confirmed in Day 06), and makes a
direct attempt to access LSASS memory for credential extraction via
`MiniDumpWriteDump`.

The LSASS access is the most significant new finding from this analysis.
All credentials cached on DESKTOP-FIN-047 — including domain credentials,
cached service account passwords, and any Kerberos tickets held at the
time of compromise — must be treated as fully compromised. An immediate
Active Directory credential rotation is recommended for all accounts that
authenticated to this workstation during the 11-day compromise window.

Three YARA detection rules have been produced and are ready for deployment
to EDR, email gateway, and threat intelligence platforms.

---

## Sample Metadata

```
Filename:       updater.exe
Full Path:      C:\Users\Public\Libraries\updater.exe
File Size:      847,360 bytes (827 KB)
File Type:      PE32+ executable (console) x86-64
Created:        2025-01-14 09:12:44 UTC
Modified:       2025-01-14 09:12:44 UTC
Accessed:       2025-01-16 03:30:00 UTC (last access before isolation)
Signed:         NO — no Authenticode signature
Compilation:    2025-01-13 22:47:33 UTC (embedded PE timestamp)

Hashes:
  MD5:     d41d8cd98f00b204e9800998ecf8427e
  SHA-1:   da39a3ee5e6b4b0d3255bfef95601890afd80709
  SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  ssdeep:  24576:abc123def456:ghijklm

VirusTotal: 0/72 detections — novel/unknown sample
MalwareBazaar: Not previously submitted
```

---

## Technical Findings

---

### FINDING-01 — Zero AV Detections: Purpose-Built or Modified Evasion Tool

**Severity:** 🔴 Critical
**ATT&CK:** T1027 — Obfuscated Files or Information / T1562.001 — Impair Defenses

**Description:**
The sample returned zero detections across 72 antivirus engines on VirusTotal
at the time of first analysis. The PE compilation timestamp (January 13, 2025
— one day before delivery) combined with zero detection rate strongly indicates
this binary was compiled specifically for this campaign, or was significantly
modified from a known framework to produce a unique binary hash.

**Evidence:**
```
VirusTotal Results (2025-01-17 09:00 UTC):
  Malicious:   0 / 72 engines
  Suspicious:  0 / 72 engines
  Undetected:  72 / 72 engines
  First seen:  (not previously seen — never submitted)

PE Compilation Timestamp:
  Embedded: 2025-01-13 22:47:33 UTC
  Phishing delivery: 2025-01-14 09:07 UTC
  Gap: 10 hours 20 minutes — compiled fresh for campaign

Entropy Analysis (PE Sections):
  .text   entropy: 7.84  ← PACKED — normal code entropy is 5.0–6.5
  .data   entropy: 7.61  ← ENCRYPTED
  .rsrc   entropy: 3.21  ← Normal (contains version info strings)
  Interpretation: Binary is packed — actual code is decrypted at runtime
```

**Risk Context:**
A zero-detection custom binary means every signature-based control in the
environment — antivirus, EDR signatures, email gateway — provided zero
protection at the time of delivery. Detection was only possible through
behavioral analysis (sandbox) and proactive threat hunting (Day 04).
This confirms the threat actor invested in operational security and custom
tooling — not commodity malware.

**Recommendation:**
Submit sample to all major threat intelligence platforms (VirusTotal,
MalwareBazaar, abuse.ch) to seed detection signatures for the broader
community. Deploy the three YARA rules produced in this analysis to all
endpoints via EDR policy. Enable behavioral detection over signature
detection as the primary EDR mode.

---

### FINDING-02 — Process Injection into svchost.exe (Process Hollowing)

**Severity:** 🔴 Critical
**ATT&CK:** T1055 — Process Injection / T1055.012 — Process Hollowing

**Description:**
Dynamic sandbox analysis confirmed the malware performs process hollowing
into a legitimate `svchost.exe` instance. This technique creates a new
suspended process, unmaps the legitimate executable's memory, writes
malicious code into the now-empty process memory space, and resumes
execution. The result: malicious code running under a Windows system
process with its PID and name appearing entirely legitimate in Task Manager
and process listings.

**Evidence:**
```
Sandbox Process Tree (Any.run — 120 second capture):

  explorer.exe (PID 3200)
  └─ updater.exe (PID 4412) [MALICIOUS — initial dropper]
     ├─ powershell.exe (PID 5120)
     │    CMD: powershell.exe -WindowStyle Hidden
     │         -EncodedCommand SQBFAFgA...
     │    Action: Downloads 47KB stage2 payload from C2
     │    Execution time: T+0:12 seconds
     │
     └─ svchost.exe (PID 5244) [HOLLOWED — injection target]
          Note: Spawned suspended, then hollowed with malicious code
          Network: Establishes DNS C2 beacon (confirms Day 04 findings)
          Spawned by: updater.exe directly (anomalous — svchost normally
                      spawned by services.exe or wininit.exe only)

API Call Sequence (process hollowing signature):
  1. CreateProcess(svchost.exe, CREATE_SUSPENDED)
  2. NtUnmapViewOfSection → empty the process memory
  3. VirtualAllocEx        → allocate new memory in target
  4. WriteProcessMemory    → write malicious shellcode
  5. SetThreadContext      → redirect entry point
  6. ResumeThread          → execute malicious code
```

**Detection Signature:**
`svchost.exe` spawned by any process other than `services.exe` or
`wininit.exe` is a reliable indicator of process hollowing. The Sysmon
Event 1 parent process field provides this detection natively.

**Recommendation:**
Add a Sigma rule detecting svchost.exe launched by non-standard parent
processes — this is a Week 2 gap identified in the Day 07 coverage map.
Force-terminate PID 5244 on the forensic image analysis — the injected
process represents the active C2 channel recovered in memory.

---

### FINDING-03 — LSASS Memory Access: Domain Credential Theft

**Severity:** 🔴 Critical
**ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory

**Description:**
The sandbox captured an API call to `MiniDumpWriteDump` targeting the LSASS
process — the Windows subsystem that stores hashed and cleartext credentials
for all accounts that have authenticated to the workstation. This is the
same technique used by Mimikatz and credential dumping tools to extract
domain passwords and Kerberos tickets. The call occurred at T+0:45 seconds
after initial execution — meaning credential theft was attempted within
the first minute of compromise.

**Evidence:**
```
Sandbox API Monitor (T+0:45s):
  OpenProcess(PROCESS_ALL_ACCESS, lsass.exe PID 752)
  → Handle obtained successfully
  MiniDumpWriteDump(
      hProcess  = lsass.exe handle,
      hFile     = C:\Windows\Temp\~tmp4891.dll,  ← dump written here
      DumpType  = MiniDumpWithFullMemory
  )
  → Result: SUCCESS
  DeleteFileA(C:\Windows\Temp\~tmp4891.dll)
  → File deleted immediately after extraction — anti-forensic action

Accounts at risk (authenticated to DESKTOP-FIN-047 during compromise window):
  NOVACREST\mthompson        — Fixed Income Analyst (primary user)
  NOVACREST\helpdesk_svc     — IT helpdesk service account
  NOVACREST\domain_backup    — Backup service account (scheduled task)
  Any domain admin who RDP'd to this workstation during 11-day window
```

**Critical Escalation:**
If any privileged domain accounts (domain admin, schema admin, exchange
admin) authenticated to DESKTOP-FIN-047 during the January 5–16 compromise
window — for any reason including remote management, patch deployment, or
helpdesk support — those credentials must be treated as fully compromised.
The Kerberos Golden Ticket and Pass-the-Hash attack paths are now available
to the threat actor for any credential extracted via this dump.

**Recommendation:**
Immediate: Pull Windows Security Event 4624/4648 logs for DESKTOP-FIN-047
covering January 5–16 and identify every account that authenticated.
Rotate all identified accounts' passwords immediately. If any Domain Admin
accounts are in the list, initiate KRBTGT password reset procedure (two
resets, 10-hour apart, per Microsoft guidance).

---

### FINDING-04 — Three-Stage Persistence Architecture

**Severity:** 🔴 Critical
**ATT&CK:** T1053.005, T1547.001, T1546.003

**Description:**
Static string analysis (FLOSS) recovered all three persistence mechanism
names embedded in the binary — `SCM_EventLog_Filter`, `SCM_EventLog_Consumer`,
and `OneDriveStandaloneUpdater` — confirming that the binary directly creates
the same persistence artifacts documented in the Day 06 purple team exercise.
This is not circumstantial: the binary hardcodes these specific names, directly
linking `updater.exe` to the WMI subscription and registry key found on the
endpoint.

**Evidence:**
```
FLOSS Recovered Strings:
  "SCM_EventLog_Filter"          ← WMI filter name (exact Day 06 match)
  "SCM_EventLog_Consumer"        ← WMI consumer name (exact Day 06 match)
  "OneDriveStandaloneUpdater"    ← Registry Run key name (exact Day 06 match)
  "MicrosoftEdgeUpdateTaskMachineCore" ← Scheduled task name (Day 06 match)
  "C:\\Users\\Public\\Libraries\\"    ← Self-install path
  "root\\subscription"           ← WMI namespace for subscription creation

Persistence Timeline (reconstructed):
  T+0:08s  Registry Run key written (HKCU\...\Run\OneDriveStandaloneUpdater)
  T+0:12s  Stage 2 downloaded via PowerShell
  T+0:35s  Scheduled task registered (schtasks.exe invoked)
  T+0:41s  WMI subscription created (three-component: filter+consumer+binding)
  T+0:45s  LSASS credential dump
  T+0:52s  C2 DNS beacon established (60.3s interval)
```

**Implication:**
The malware deploys all three persistence mechanisms sequentially within the
first 52 seconds of execution. Removing only the Registry Run key — the
most visible persistence mechanism — would leave the WMI subscription and
Scheduled Task active. The host would re-establish C2 on next reboot
regardless of the registry cleanup.

**Recommendation:**
All three persistence components must be removed simultaneously. The WMI
subscription is the most dangerous — it survives reboots silently and
re-establishes C2 within 3 minutes of system startup. Run the cleanup
PowerShell commands from Day 06 against the forensic image analysis before
any rebuild decision is made.

---

## MITRE ATT&CK Technique Matrix

| ID | Technique | Tactic | Evidence Source | Confidence |
|----|-----------|--------|-----------------|------------|
| **T1027** | Obfuscated Files/Info | Defense Evasion | PE entropy 7.84 | High |
| **T1140** | Deobfuscate/Decode | Defense Evasion | Runtime unpacking observed | High |
| **T1059.001** | PowerShell | Execution | Sandbox — encoded command | High |
| **T1055** | Process Injection | Defense Evasion | Sandbox — API call sequence | High |
| **T1055.012** | Process Hollowing | Defense Evasion | NtUnmapViewOfSection call | High |
| **T1003.001** | LSASS Memory Dump | Credential Access | MiniDumpWriteDump API call | High |
| **T1082** | System Info Discovery | Discovery | Sandbox — WMI OS queries | High |
| **T1016** | Network Config Discovery | Discovery | Sandbox — adapter enumeration | Medium |
| **T1053.005** | Scheduled Task | Persistence | FLOSS strings + sandbox | High |
| **T1547.001** | Registry Run Keys | Persistence | FLOSS strings + sandbox | High |
| **T1546.003** | WMI Event Subscription | Persistence | FLOSS strings confirmed | High |
| **T1071.004** | DNS C2 | Command & Control | Network capture + Day 04 | High |
| **T1132.001** | Standard Encoding | C2 | Base64 DNS labels | High |
| **T1573.002** | Asymmetric Crypto C2 | C2 | HTTPS to 185.220.101.33 | High |

---

## Malware Family Classification

```
Classification: Custom Loader / Bespoke C2 Dropper
Confidence:     MEDIUM — insufficient public data for definitive attribution

Closest Framework Match: Cobalt Strike Beacon (78% behavioral overlap)
  Matching behaviors:
    ✅ Process hollowing into svchost.exe
    ✅ DNS beaconing with configurable interval
    ✅ LSASS credential access
    ✅ Staged payload architecture
    ✅ PowerShell execution with encoding

  Non-matching behaviors:
    ❌ No named-pipe communication (CS hallmark)
    ❌ No default Cobalt Strike JA3 hash match
    ❌ WMI subscription (not standard CS persistence)
    ❌ Binary entropy pattern differs from standard CS stager

Assessment: The binary exhibits Cobalt Strike-like behaviors but with
modifications suggesting either a custom implementation, a heavily modified
CS variant, or a separate commercial C2 framework (Sliver, Havoc, Brute
Ratel) compiled with custom post-ex modules. The WMI subscription creation
via embedded strings is unusual for standard commercial frameworks —
suggests custom-developed persistence module.

Recommendation: Submit to Recorded Future or Mandiant for deeper attribution
analysis. The combination of custom WMI persistence + process hollowing +
DNS TXT exfil is a relatively distinctive behavioral fingerprint.
```

---

## Risk Assessment — DREAD Scoring

| Factor | Score | Justification |
|--------|:-----:|---------------|
| **Damage** | 10 | LSASS dump = all domain creds; 11-day exfil; persistence survives reimage |
| **Reproducibility** | 8 | Same binary reusable against other targets — infrastructure still live |
| **Exploitability** | 9 | Single phishing click; no admin rights required for initial execution |
| **Affected Users** | 7 | All accounts authenticated to FIN-047 during compromise window |
| **Discoverability** | 3 | 0/72 AV — extremely hard to detect without behavioral analysis |
| **Total** | **37/50** | 🔴 **Critical** |

---

## YARA Rules Deployed

Three YARA rules were developed from this analysis:

| Rule | Coverage | Confidence |
|------|---------|------------|
| `NovaCrest_Dropper_updater_exe_Exact` | Exact hash match | High — exact sample only |
| `NovaCrest_Dropper_updater_exe_Behavioral` | String + behavioral | High — variants detected |
| `NovaCrest_DNS_C2_Beacon_Pattern` | DNS beacon pattern | Medium — broader family |

**Deployment targets:**
- EDR policy (CrowdStrike Custom IOAs / YARA rules)
- Email gateway (attachment scanning)
- Threat intel platform (OpenCTI YARA upload)
- Network IDS (via Suricata YARA integration)

---

## IOC Summary

```
File Indicators:
  SHA-256:  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  MD5:      d41d8cd98f00b204e9800998ecf8427e
  Path:     C:\Users\Public\Libraries\updater.exe
  Path:     C:\Windows\Temp\~tmp4891.dll  (transient — deleted post-dump)
  Mutex:    Global\{4A8C3B91-2E7F-4D15-88AC-9B7E3C1D0F22}

Network Indicators:
  C2 Domain:  updates.cdn-telemetry-svc[.]net
  C2 IP:      185.220.101.33
  Stage2 URL: hxxps://185.220.101.33/stage2
  Interval:   60.3 seconds ± 0.1s (DNS beacon)
  Protocol:   DNS TXT queries (Base64 labels > 30 chars)

Host Indicators:
  Registry:   HKCU\...\Run\OneDriveStandaloneUpdater
  Task:       MicrosoftEdgeUpdateTaskMachineCore
  WMI Filter: SCM_EventLog_Filter (root\subscription)
  WMI Consumer: SCM_EventLog_Consumer
  Process:    svchost.exe (non-standard parent — injected)
```

---

## Immediate Response Requirements

| Priority | Action | Owner | Deadline |
|----------|--------|-------|----------|
| **P0** | Identify all accounts authenticated to FIN-047 (Jan 5–16) | IR / AD Team | 2 hours |
| **P0** | Rotate credentials for all identified accounts | IT Security | 4 hours |
| **P0** | If any Domain Admin authenticated — initiate KRBTGT reset | AD Team | 4 hours |
| **P0** | Deploy all 3 YARA rules to EDR fleet-wide | Detection Eng | Today |
| **P1** | Submit sample to VirusTotal, MalwareBazaar, abuse.ch | Threat Intel | Today |
| **P1** | Add SHA-256 hash to all blocking mechanisms | Detection Eng | Today |
| **P1** | Scan all endpoints for updater.exe path + hash | Threat Hunt | 24 hours |
| **P2** | Write Sigma rule — svchost.exe non-standard parent | Detection Eng | 48 hours |
| **P2** | Decode all captured DNS TXT payloads from beacon traffic | Forensics | 48 hours |
| **P3** | Submit to commercial threat intel for attribution | Threat Intel | 1 week |

---

## Kill Chain Update — Day 08 Additions

```
Previous (Days 01–07):
  Recon → Phishing Infra → Initial Access → C2 Beacon → DNS Exfil → Persistence

Day 08 Additions:
  +  Credential Theft: LSASS dump at T+45s (MiniDumpWriteDump confirmed)
  +  Process Hollowing: svchost.exe injected — C2 hidden as system process
  +  Stage 2 Payload: 47KB additional payload downloaded — content TBD
  +  Persistence: All 3 mechanisms confirmed in binary code — not just artifacts

Updated Attacker Capability Assessment:
  Access to:  All domain credentials cached on FIN-047
  Access to:  File system (stage 2 payload could exfil any local file)
  Access to:  Network (injected into svchost — inherits network access)
  Access to:  Persistence through reboot (WMI subscription confirmed)
```

---

## References

- [MITRE ATT&CK T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK T1027 — Obfuscated Files](https://attack.mitre.org/techniques/T1027/)
- [FLARE-FLOSS Documentation](https://github.com/mandiant/flare-floss)
- [pefile Python Library](https://github.com/erocarrera/pefile)
- [Any.run Interactive Sandbox](https://app.any.run)
- [MalwareBazaar — abuse.ch](https://bazaar.abuse.ch)
- [YARA Documentation](https://yara.readthedocs.io/)

---

*Previous: [Day 07 ←](../day-07/REPORT.md) | Next: [Day 09 →](../day-09/SCENARIO.md)*

---
*Report generated as part of the [Blaakpearl 30-Day Security Portfolio](../../README.md)*
