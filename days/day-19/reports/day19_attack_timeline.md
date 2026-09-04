# Day 19 — Forensic Attack Timeline
**Case:** NCA-2026-06 | NovaCrest Capital Group Unauthorized Access & Data Exfiltration
**Classification:** TLP:AMBER — Attorney-Client Privileged | Forensic Work Product
**Analyst:** V. Willis, CISSP
**Timeline Prepared:** 2026-06-18
**Timestamps:** All UTC (clock skew normalized)

---

## Clock Skew Normalization Applied

| Source | Raw Timezone | Offset | Normalization |
|--------|-------------|--------|---------------|
| WS-FIN-04 (Windows logs) | EDT (UTC−4) | +4 hours | All WS-FIN-04 times + 04:00 |
| NGFW-01 (proxy/firewall) | UTC+1 | −1 hour | All NGFW times − 01:00 |
| lnx-trade-01 | UTC | None | As recorded |
| Zeek network tap | UTC | None | As recorded |
| AWS CloudTrail | UTC | None | As recorded |

---

## Phase 1 — Reconnaissance (External, June 14, 2026)

| Time (UTC) | Event | Source | Evidence ID | ATT&CK |
|-----------|-------|--------|-------------|--------|
| 08:00 | j.henderson interactive logon (normal start of day) | Security.evtx Event 4624 | EVT-001 | T1078 |
| ~08:30 | (External) CT log, Shodan, GitHub reconnaissance against novacrest.com — external to org; no internal evidence | OSINT (no log) | N/A | T1592 |

**Evidence note:** Reconnaissance activities in Day 15 were passive/external. No internal log evidence expected. External activities reconstructed from threat actor methodology, not internal logs.

---

## Phase 2 — Initial Access (June 14, 2026)

| Time (UTC) | Event | Source | Evidence ID | ATT&CK | Severity |
|-----------|-------|--------|-------------|--------|---------|
| **13:12:34** | WINWORD.EXE spawns `powershell.exe -enc [b64]` on WS-FIN-04 — macro execution | Sysmon.evtx Event 1 | EVT-002 | T1059.001 | Critical |
| **13:13:01** | `svc_update.exe` created in `%LOCALAPPDATA%\Temp\` — dropper deployed | Sysmon.evtx Event 1 | EVT-002 | T1105 | Critical |
| **13:13:12** | NGFW proxy: `CONNECT 198.51.100.99:443` — first C2 outbound connection | NGFW proxy.log | N/A | T1071.001 | Critical |
| **13:13:15** | Zeek ssl.log: TLS established to 198.51.100.99:443; JA3=a0e9... (Cobalt Strike) | zeek_ssl.log | NET-002 | T1071.001 | Critical |

**Cross-source corroboration:**
- Sysmon (EVT-002) shows WINWORD.EXE → powershell.exe chain
- Zeek (NET-002) shows C2 connection 3 seconds later
- NGFW proxy confirms outbound to same IP
- **Three independent sources confirm initial access at 13:13 UTC**

---

## Phase 3 — Privilege Escalation (June 14, 2026)

| Time (UTC) | Event | Source | Evidence ID | ATT&CK | Severity |
|-----------|-------|--------|-------------|--------|---------|
| **13:15:22** | svc_update.exe opens lsass.exe with 0x1010 access — token harvest | Sysmon.evtx Event 10 | EVT-002 | T1134.001 | Critical |
| **13:15:45** | 4672: j.henderson logon token assigned SeImpersonatePrivilege, SeDebugPrivilege, SeTcbPrivilege | Security.evtx Event 4672 | EVT-001 | T1134.001 | Critical |
| **13:18:33** | Sysmon: SetValue `HKCU\...\ms-settings\shell\open\command` = cmd.exe — UAC bypass staged | Sysmon.evtx Event 13 | EVT-002 | T1548.002 | Critical |
| **13:18:34** | Sysmon: fodhelper.exe spawned by svc_update.exe | Sysmon.evtx Event 1 | EVT-002 | T1548.002 | Critical |
| **13:18:35** | Sysmon: cmd.exe spawned by fodhelper.exe at **High integrity** — UAC bypass confirmed | Sysmon.evtx Event 1 | EVT-002 | T1548.002 | Critical |
| **13:22:05** | 4769: RC4 TGS request for MSSQLSvc/sqlserver.novacrest.local — Kerberoasting #1 | Security.evtx Event 4769 | EVT-001 | T1558.003 | Critical |
| **13:22:07** | 4769: RC4 TGS for http/intranet.novacrest.local — Kerberoasting #2 | Security.evtx Event 4769 | EVT-001 | T1558.003 | Critical |
| **13:22:09** | 4769: RC4 TGS for svc_backup/backup.novacrest.local — Kerberoasting #3 | Security.evtx Event 4769 | EVT-001 | T1558.003 | Critical |

**Evidence note:** Events 4769 at 13:22 fall within the Security.evtx gap window (13:18–15:04 UTC). These events survive because the log was not cleared until 15:04 — events from 13:00–13:18 were deleted, but 13:18–15:04 events were captured before the clear command. RecordID analysis confirms sequence continuity for these specific events.

---

## Phase 4 — Linux Privilege Escalation (June 14, 2026)

| Time (UTC) | Event | Source | Evidence ID | ATT&CK | Severity |
|-----------|-------|--------|-------------|--------|---------|
| **14:28:44** | auditd: svc_ncg (uid=1002) executes `find / -perm -4000` — SUID enumeration | auditd key=suid_exec | LNX-001 | T1548.001 | High |
| **14:32:11** | auditd: svc_ncg executes `sudo find . -exec /bin/bash ;` — NOPASSWD GTFOBin | auditd key=sudo_exec | LNX-001 | T1548.003 | Critical |
| **14:32:12** | auditd: setuid(0) syscall — effective UID changed to root | auditd syscall | LNX-001 | T1548.003 | Critical |

---

## Phase 5 — Defense Evasion / Anti-Forensics (June 14, 2026)

| Time (UTC) | Event | Source | Evidence ID | ATT&CK | Severity |
|-----------|-------|--------|-------------|--------|---------|
| **15:04:22** | Event 1102: Security audit log cleared by j.henderson (4,231 events destroyed) | Security.evtx Event 1102 | EVT-001 | T1070.001 | Critical |
| **15:04:25** | Event 104: System log cleared | System.evtx Event 104 | EVT-003 | T1070.001 | Critical |
| **~15:05** | bash_history cleared on lnx-trade-01 (`/home/svc_ncg/.bash_history` truncated to 0 bytes) | Filesystem artifact | LNX-001 | T1070.003 | High |

**Log gap analysis:**
- Security.evtx RecordID gap: 14201 → 14850 (649 records missing)
- Gap time window: 13:18 → 15:04 UTC (106 minutes of evidence destroyed)
- **Reconstruction:** 649 deleted Security events reconstructed from Sysmon.evtx (EVT-002) and Zeek logs (NET-001/002) — both intact and endpoint-independent

---

## Phase 6 — Data Staging & Exfiltration (June 14–15, 2026)

| Time (UTC) | Event | Source | Evidence ID | ATT&CK | Severity |
|-----------|-------|--------|-------------|--------|---------|
| **14:28:44** | auditd: root executes `tar czf /tmp/.cache/trading_data.tar.gz /opt/trading/` | auditd EXECVE | LNX-001 | T1560.001 | Critical |
| **15:00:00** | Zeek ssl.log: TLS to 198.51.100.99:443, JA3=a0e9... (Cobalt Strike), bytes_out=125,000,000 | zeek_ssl.log | NET-002 | T1048.002 | Critical |
| **15:00:00** | Zeek conn.log: 125 MB egress to 198.51.100.99 over 480 seconds | zeek_conn.log | NET-001 | T1030 | Critical |
| **15:30:00** | Zeek ssl.log: TLS to 52.216.0.1 (amazonaws.com) server_name=novacrest-exfil.s3.amazonaws.com, bytes_out=85,000,000 | zeek_ssl.log | NET-002 | T1567.002 | Critical |
| **15:45:00** | Zeek dns.log: 5 TXT/NULL queries to t1.evil-c2.com with base64 subdomains (entropy > 4.9) | zeek_dns.log | NET-001 | T1048.001 | High |
| **16:00:00** | Zeek conn.log: Recurring 22 MB transfers to 198.51.100.99 at 30-min intervals | zeek_conn.log | NET-001 | T1029 | High |

---

## Phase 7 — AWS Cloud Abuse (June 16, 2026)

| Time (UTC) | Event | Source | Evidence ID | ATT&CK | Severity |
|-----------|-------|--------|-------------|--------|---------|
| **09:00:00** | CloudTrail: GetCallerIdentity from 198.51.100.99 (external) | cloudtrail | CLD-001 | T1078.004 | Critical |
| **09:01:30** | CloudTrail: ListBuckets — attacker enumerates S3 | cloudtrail | CLD-001 | T1619 | High |
| **09:10:00** | CloudTrail: AssumeRole → novacrest-admin-role — full AWS admin achieved | cloudtrail | CLD-001 | T1078.004 | Critical |
| **09:15:00** | CloudTrail: GetObject novacrest-trading-data/client-data/account-balances.csv | cloudtrail | CLD-001 | T1619 | Critical |

---

## Evidence Gap Map (Tampered vs. Surviving)

```
TIME (UTC) →  13:00   13:18   14:00   15:00   15:04   16:00
              ───────┬───────┬───────┬───────┬───────┬───────
Security.evtx INTACT │ ████████████ GAP █████│ INTACT│ INTACT
                      ▲ATTACKER DELETES▲     ▲CLEAR EVENT▲

Sysmon.evtx   INTACT   INTACT  INTACT  INTACT  INTACT  INTACT
                        ← FILLS THE GAP WINDOW →

auditd        [Linux host — separate from Windows gap]
              INTACT  INTACT  INTACT  INTACT  INTACT  INTACT

Zeek ssl/conn [Network tap — independent of endpoint]
              INTACT  INTACT  INTACT  INTACT  INTACT  INTACT

Legend: ████ = missing evidence  INTACT = available
```

**Conclusion:** Despite 649 Security.evtx events destroyed, corroborating
evidence from 4 independent sources reconstructs the full timeline.
Evidence is sufficient for legal proceedings.

---

## Evidence Correlation Matrix

| Event | Sysmon | Sec.evtx | auditd | Zeek | CloudTrail | Confidence |
|-------|--------|----------|--------|------|------------|------------|
| Macro execution (13:12) | ✅ | ❌ (deleted) | N/A | ✅ C2 conn | N/A | **High (2 sources)** |
| LSASS access (13:15) | ✅ | ✅ 4672 | N/A | N/A | N/A | **High (2 sources)** |
| UAC bypass (13:18) | ✅ | ❌ (deleted) | N/A | N/A | N/A | **Medium (1 source)** |
| Kerberoasting (13:22) | N/A | ✅ 4769×3 | N/A | N/A | N/A | **Medium (1 source)** |
| Linux sudo abuse (14:32) | N/A | N/A | ✅ | ✅ network | N/A | **High (2 sources)** |
| Log clearing (15:04) | N/A | ✅ 1102 | N/A | N/A | N/A | **High (confirmed by 1102 self)** |
| 125 MB exfil (15:00) | N/A | ❌ (deleted) | ✅ tar | ✅ ×2 | N/A | **Critical (3 sources)** |
| S3 exfil (15:30) | N/A | ❌ (deleted) | N/A | ✅ ssl | ✅ PutObject | **Critical (2 sources)** |
| AWS admin (16Jun 09:10) | N/A | N/A | N/A | N/A | ✅ AssumeRole | **High (1 source — cloud)** |

---

*Day 19 — Forensic Attack Timeline | Case NCA-2026-06*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
