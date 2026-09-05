# Day 21 — Detection Improvement Roadmap
**NovaCrest Capital Group | Purple Team Output**
**Author:** V. Willis, CISSP
**Version:** 1.0 — Post Week 3 Capstone

---

## Roadmap Overview

This roadmap translates the seven gaps identified in the Day 21 capstone
into a prioritized remediation plan. Items are scored by:
- **Impact** (0–5): points recovered or techniques newly covered
- **Effort** (S/M/L): hours / days / weeks of implementation work
- **Priority** (P1–P4): sequenced by impact-to-effort ratio

Total addressable improvement: **+6 points** (32→38 of 40) from Low-effort
items alone.

---

## Priority 1 — Deploy This Week (< 4 hours each)

### ROAD-01: Import Run Key Persistence Sigma Rule into Elastic
**Gap:** T1547.001 missed in Phase 3 (registry run key not alerted)
**Root cause:** Sysmon Event 13 filter for `*\CurrentVersion\Run*` not imported

```
Implementation:
  1. In Elastic Kibana → Security → Detection Rules → Import
  2. Upload: rules/sigma_c2_detection.yml (contains run key rule)
  3. Enable: "APT Kill Chain — P3 Persistence: Registry Run Key"
  4. Test: Write dummy value to HKCU\...\Run in lab; confirm alert fires

Rule logic (already written in Sigma):
  logsource: sysmon | service: registry
  detection:
    selection:
      EventType: SetValue
      TargetObject|contains: \CurrentVersion\Run
    filter:
      Image|contains:
        - \MsiExec.exe
        - \svchost.exe
        - \OneDrive.exe   # Known legitimate run key writers
    condition: selection and not filter
  level: high

Estimated time: 30 minutes
Impact: +1 detection, +5 points on future exercise P3
```

---

### ROAD-02: Fix EQL Lateral Movement Rule — Extend maxspan
**Gap:** Phase 6 SLA miss — lateral movement detected at 23 min (SLA: 20 min)
**Root cause:** EQL `maxspan=2m` too narrow for Pass-the-Ticket pattern

```
Fix: Edit elastic_killchain.eql Rule 5 sequence:
  CHANGE:
    sequence by host.name with maxspan=2m

  TO:
    sequence by host.name with maxspan=10m

  AND ADD standalone WMI rule (no join required):
    process where process.parent.name == "WmiPrvSE.exe"
      and process.name : ("cmd.exe","powershell.exe","whoami.exe")
      and not host.name : ("SRV-WSUS*","SRV-SCCM*","SRV-MGMT*")

Estimated time: 45 minutes (edit + test)
Impact: Lateral movement within SLA on next exercise (+3 pts recovery)
```

---

### ROAD-03: Deploy Firewall Disable Alert (T1562.004)
**Gap:** `netsh advfirewall set allprofiles state off` not alerted in Phase 5

```
New Elastic rule:
  name: "Defense Evasion: Windows Firewall Disabled"
  data source: Sysmon Event 1
  detection:
    process.name: netsh.exe
    process.args: "advfirewall" AND "state off"
  risk_score: 85 | severity: high

Also detect via registry:
  data source: Sysmon Event 13
  TargetObject: *\CurrentVersion\Policies\WindowsFirewall*\EnableFirewall
  Details: DWORD (0x00000000)

Estimated time: 45 minutes
Impact: +1 technique covered; prevents silent AV+FW disable combo
```

---

### ROAD-04: CrowdStrike — Tune PE Hash Scan on Process Rename (T1036)
**Gap:** `Rubeus.exe → svccheck.exe` ran for 90 seconds before detection

```
CrowdStrike Falcon console → Prevention Policies:
  1. Sensor Visibility Enhancements → Enable "Image File Execution Options"
  2. Prevention → "Execution Blocking" → Upload Rubeus.exe hash:
     SHA256: [Rubeus hash from VirusTotal / CrowdStrike IOC management]
  3. Add: any process matching Rubeus internal PE metadata
     (FileDescription: "Rubeus", CompanyName: "GhostPack")
     even if filename is changed

Alternative — Sysmon-based:
  Event 7 (Image Loaded): Flag any DLL load by process where
  process.name does not match process.pe.original_filename
  (mismatch = renamed binary indicator)

Estimated time: 1 hour
Impact: Closes rename-based masquerade gap; faster detection
```

---

## Priority 2 — Deploy This Month (1–3 days each)

### ROAD-05: Compound Rule for Local Data Staging (T1074.001)
**Gap:** Staging in `%SYSTEMROOT%\Temp\` not alerted (high-FP path)

```
Design (avoid FP on legitimate temp writes):
  Compound rule requires ALL of:
    - File type: .tar.gz, .zip, .7z, .rar created in TEMP path
    - File size: > 50 MB
    - User context: NOT (SYSTEM, NT AUTHORITY, LOCAL SERVICE)
    - Time context: outside normal business hours OR during incident window

  Implementation:
    Sysmon Event 11 (File Created) with FileSize enrichment:
    - EventCode: 11
    - TargetFilename|contains: [\Temp\, \tmp\, \AppData\]
    - TargetFilename|endswith: [.tar.gz, .zip, .7z, .rar]
    Filter: exclude known software updaters by Image path

  FP estimation: < 3% with all conditions combined
  Estimated time: 1 day (design + test + tune)
  Impact: Closes staging gap; valuable for ransomware detection too
```

---

### ROAD-06: Extended Beacon Timing Window for Slow Beacons (T1001.001)
**Gap:** 600-second beacon with 35% jitter undetected — insufficient connections
in 45-minute window for reliable CV analysis

```
Current state:
  Beacon timing SPL: 5-minute sliding window; minimum 8 connections
  Problem: 600s beacon = 1 connection per 10 min → only 4-5 in 45 min

Fix 1: Extend analysis window to 4 hours for timing analysis
  In Splunk: Change earliest=-45m to earliest=-4h in SPL Query B-2A
  In Elastic: Extend EQL rule time window

Fix 2: Lower minimum connections threshold to 5
  Adds some FP risk but catches slow beacons (600s+)
  Mitigate: Combine with JA3/domain age score to maintain signal quality

Fix 3: Pre-compute per-host connection summaries in continuous job
  30-minute scheduled search → update lookup table
  Alert on: lookup shows new high-scoring (low CV) destination

Estimated time: 2 days (implementation + 30-day FP tuning)
Impact: Detects very slow beacons (600s+); covers more C2 tooling
```

---

### ROAD-07: Canary Token Infrastructure for Recon Detection (T1592)
**Gap:** Passive external reconnaissance fully undetectable

```
Architecture options:

Option A — Credential Canary Tokens (Low cost, 1 day)
  Deploy fake AWS credentials, API keys, and SSH keys seeded in:
    - GitHub public repos (as if accidentally committed)
    - Pastebin and similar sites
    - Fake LinkedIn employee profiles
  Use: canarytokens.org or Thinkst Canary
  When triggered: instant alert → attacker has found and used fake cred

Option B — Web Honeypots (Medium cost, 1 week)
  Deploy fake login portals at plausible subdomains:
    - vpn.novacrest.com (fake VPN portal)
    - webmail.novacrest.com (fake email login)
  Any authentication attempt = recon/credential stuffing alert

Option C — Honey DNS Entries (Low cost, 2 hours)
  Add fake internal hostnames to public DNS:
    - internal-hr.novacrest.com → 127.0.0.1
    - finance-db.novacrest.com → 127.0.0.1
  Alert when these are queried: attacker enumerated DNS

Recommended: Deploy Option A + C now; Option B in Q3
Estimated time: 1 day for A+C combined
Impact: Converts recon from 0% detection to ~40% detection
```

---

## Priority 3 — Strategic (Weeks to Months)

### ROAD-08: UEBA Baseline Across All Endpoints
**Current state:** Volumetric anomaly triggered in Phase 8 (4.6× baseline),
but baseline is rough (30-day manual average). No per-process, per-user egress.

```
Target state:
  - Per-user egress baseline (MB/hour, by time-of-day)
  - Per-process network baseline (svchost.exe normal vs. anomalous)
  - Peer-group comparison (j.henderson vs. other finance users)
  - Alert: any metric > 3σ from rolling baseline

Tools:
  - Elastic ML (built-in with Elastic Security license)
  - Microsoft Sentinel UEBA (if hybrid deployment)
  - Zeek beacon-detection package (already partially deployed)

Timeline: 8 weeks (30-day baseline collection + tuning + validation)
Impact: Closes volumetric gap; enables detection of slow, low-volume exfil
```

---

### ROAD-09: JARM Active Scanning for Emerging C2 Frameworks
**Current state:** Sliver JARM in blocklist; Havoc JARM not (Day 20 gap).
**Risk:** New C2 frameworks appear quarterly; static JARM lists lag.

```
Target state:
  - Weekly automated JARM scan of all external IPs with > 3 HTTPS connections
  - Feed results to threat intel platform for comparison against:
      - abuse.ch JA3/JARM database
      - Shodan internet scan data
      - Custom lab fingerprints (run JARM against lab-deployed Sliver/Havoc/CS)
  - Alert when: new JARM observed on IP with no established business relationship

Implementation:
  - Tool: jarm.py (Salesforce) scheduled weekly via cron
  - Storage: Elasticsearch index `jarm-scans-*` with destination IP + JARM + date
  - Alert rule: new JARM from same IP as previous connection with unknown JARM

Timeline: 4 weeks
Impact: Closes Havoc/emerging framework gap; proactive vs. reactive
```

---

## Roadmap Summary Table

| ID | Description | Priority | Effort | Impact | Points Recoverable |
|----|-------------|----------|--------|--------|--------------------|
| ROAD-01 | Run key Sigma rule import | P1 | S (30 min) | +1 tech | +5 pts |
| ROAD-02 | EQL lateral movement maxspan fix | P1 | S (45 min) | SLA met | +3 pts |
| ROAD-03 | Firewall disable alert | P1 | S (45 min) | +1 tech | — |
| ROAD-04 | CrowdStrike rename detection | P1 | S (1 hr) | Faster MTTD | — |
| ROAD-05 | Staging compound rule | P2 | M (1 day) | +1 tech | — |
| ROAD-06 | Slow beacon timing window | P2 | M (2 days) | +1 tech | — |
| ROAD-07 | Canary token recon detection | P2 | M (1 day) | +1 phase | — |
| ROAD-08 | UEBA full baseline | P3 | L (8 weeks) | Volumetric | — |
| ROAD-09 | JARM active scanning | P3 | L (4 weeks) | New C2 frameworks | — |

**Implementing ROAD-01 through ROAD-04 alone recovers +8 points on the next
exercise (32 → 40) and takes under 4 hours of engineering time.**

---

## Measurement Plan

Re-run the Day 21 capstone scenario in **30 days** with these changes applied.

Target metrics for the re-run:
```
Score:                    ≥ 38/40 (95%)
Phases detected SLA:      ≥ 7/8
Mean MTTD:                ≤ 10 minutes
Lateral movement MTTD:    ≤ 18 minutes (within SLA)
Masquerade detection:     < 60 seconds (PE hash on first execution)
```

If targets are met, advance to Week 4 (Days 22–28) without further re-run.
If lateral movement still misses SLA, escalate ROAD-02 to emergency fix.

---

*Day 21 — Improvement Roadmap | Week 3 Capstone*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
