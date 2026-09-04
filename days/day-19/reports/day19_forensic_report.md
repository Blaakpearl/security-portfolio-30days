# Day 19 — Forensic Log Analysis Report
**Case:** NCA-2026-06 | NovaCrest Capital Group
**Classification:** TLP:AMBER — Attorney-Client Privileged | Forensic Work Product
**Analyst:** V. Willis, CISSP
**Report Date:** 2026-06-18
**Status:** Final

---

## 1. Executive Summary

A forensic log analysis of the NovaCrest Capital Group intrusion (June 14–18,
2026) confirms an end-to-end compromise originating from a macro-enabled
spearphishing email delivered to user `j.henderson` on June 14, 2026.
The attacker achieved SYSTEM privileges on a Windows endpoint within 6 minutes
of initial access, extracted service account hashes via Kerberoasting,
escalated to root on a Linux trading server, and exfiltrated approximately
253 MB of data including trading algorithms, Bloomberg API credentials, and
client financial records. The attacker attempted to cover tracks by clearing
Windows Security and System event logs; however, corroborating evidence from
Sysmon, Linux auditd, Zeek network logs, and AWS CloudTrail preserves
sufficient evidence to reconstruct the complete attack timeline.

**Timeline span:** June 14, 2026 08:00 UTC → June 18, 2026 18:00 UTC  
**Initial access confirmed:** June 14, 2026 13:12:34 UTC  
**Dwell time before detection:** 48 hours  
**Data exfiltrated:** ~253 MB (trading algorithms, Bloomberg API key, client PII)  
**Regulatory impact:** SEC Regulation S-P notification required (customer PII breach)

---

## 2. Forensic Methodology

### 2.1 Evidence Collection

Evidence was collected under forensic preservation principles between June 17–18,
2026. All evidence files were hashed at acquisition (SHA256 + MD5) and stored on
a write-protected forensic workstation. Full chain of custody documentation is
in `artifacts/evidence_manifest.json`.

### 2.2 Timeline Construction Method

Log normalization and timeline construction used:

- **Plaso/log2timeline** — Ingested EVTX, auditd, and auth.log sources
- **psort.py** — Filtered to incident window; exported L2T CSV
- **Manual normalization** — Clock skew applied: WS-FIN-04 (+4h EDT→UTC), NGFW-01 (−1h UTC+1→UTC)
- **Elastic SIEM** — L2T CSV ingested; EQL correlation rules applied
- **Cross-source correlation** — Events from different sources matched by timestamp proximity (±60s) and host/user attributes

### 2.3 Log Tampering

Two Windows event logs were cleared by the attacker (T1070.001):
- `Security.evtx` — Event 1102 at 15:04:22 UTC; 649 records destroyed
- `System.evtx` — Event 104 at 15:04:25 UTC

The tampered window (13:18–15:04 UTC, 106 minutes) was reconstructed from
Sysmon.evtx (not cleared; attacker oversight) and Zeek network logs
(hub-side capture; endpoint-independent; cannot be tampered).

---

## 3. Attack Narrative

### 3.1 Initial Access (June 14, ~13:12 UTC)

A macro-enabled Word document was delivered to `j.henderson@novacrest.com`
by a spoofed email from `security@novacrest-security.com`. The email referenced
a real FinTech Summit presentation made by the user, indicating prior
reconnaissance. When the document was opened and macros enabled, Word
(`WINWORD.EXE`) spawned `powershell.exe` with a base64-encoded payload — the
classic Office macro → PowerShell dropper chain.

The PowerShell payload downloaded and executed `svc_update.exe` from the
attacker's C2 server (198.51.100.99), staging the binary in the user's
`%LOCALAPPDATA%\Temp\` directory — an indicator of defense evasion via
trusted writable path.

**Evidence:** Sysmon.evtx Event 1 (13:12:34); Zeek ssl.log C2 connection (13:13:15)

### 3.2 Privilege Escalation (June 14, 13:15–13:22 UTC)

Within 3 minutes of initial access, the attacker executed multiple privilege
escalation techniques:

1. **Token Impersonation (T1134.001):** `svc_update.exe` opened `lsass.exe` with
   0x1010 (read + query) access. A minute later, `j.henderson`'s logon token held
   `SeImpersonatePrivilege`, `SeDebugPrivilege`, and `SeTcbPrivilege` — strongly
   consistent with a Juicy Potato or PrintSpoofer technique coercing a SYSTEM-level
   service to authenticate to an attacker-controlled named pipe.

2. **UAC Bypass (T1548.002):** The ms-settings COM object hijack technique was
   used with `fodhelper.exe` as the auto-elevating carrier binary. The attacker
   wrote a malicious command to `HKCU\Software\Classes\ms-settings\shell\open\command`
   then launched `fodhelper.exe`, which read the key and executed `cmd.exe` at
   High integrity level.

3. **Kerberoasting (T1558.003):** Three service principal names were targeted in
   4 seconds — `MSSQLSvc`, `http/intranet`, and `svc_backup`. All requested
   with RC4 encryption (0x17), indicating offline cracking intent.

**Evidence:** Sysmon.evtx Events 10/13/1; Security.evtx Events 4672/4769

### 3.3 Linux Lateral Movement (June 14, 14:28–14:32 UTC)

Using the `svc_backup` Kerberoasted hash (or credentials found in the
PostgreSQL `api_keys` table), the attacker authenticated to `lnx-trade-01`.
On this host:

1. SUID enumeration: `find / -perm -4000` identified three non-baseline SUID
   binaries (`find`, `python3`, `vim`).
2. NOPASSWD sudo exploitation: The `svc_ncg` account had a misconfigured
   sudoers rule permitting `sudo find` without a password. The attacker used
   `find -exec /bin/bash ;` to spawn a root shell.

**Evidence:** auditd (LNX-001) — intact; setuid(0) syscall confirmed

### 3.4 Anti-Forensics (June 14, 15:04 UTC)

At 15:04 UTC, the attacker cleared both the Windows Security log (Event 1102)
and System log (Event 104). This attempted to destroy evidence of the initial
access and privilege escalation chain. The attacker did not clear Sysmon.evtx
(oversight), which preserved the key process chain evidence for the entire
deleted window.

### 3.5 Data Staging and Exfiltration (June 14, 14:28–16:00+ UTC)

With root access on `lnx-trade-01`, the attacker:
1. Created a 125 MB `.tar.gz` archive of `/opt/trading/` in a hidden temp directory
2. Established an HTTPS channel (Cobalt Strike JA3) and transferred the archive
3. Uploaded 85 MB to an attacker-controlled S3 bucket (`novacrest-exfil.s3.amazonaws.com`)
4. Used DNS tunneling for small-volume exfil (likely credentials/API keys)
5. Automated recurring 22 MB transfers at 30-minute intervals

**Total estimated exfil: ~253 MB**

---

## 4. ATT&CK Navigator Summary

```
Initial Access:        T1566.001 (Spearphishing Attachment)
Execution:             T1059.001 (PowerShell) | T1059.003 (Cmd)
Privilege Escalation:  T1134.001 (Token Impersonation)
                       T1548.002 (Bypass UAC)
                       T1548.001 (SUID Exploitation)
                       T1548.003 (Sudo Abuse)
Credential Access:     T1558.003 (Kerberoasting)
Defense Evasion:       T1070.001 (Clear Windows Event Logs)
                       T1070.003 (Clear Command History)
                       T1562.001 (Disable Security Tools)
                       T1036 (Masquerading — svc_update.exe)
Persistence:           T1078.004 (Cloud Accounts — AWS key)
Exfiltration:          T1048.001 (DNS Tunneling)
                       T1048.002 (HTTPS to C2)
                       T1560.001 (Archive via Utility)
                       T1567.002 (Cloud Storage)
                       T1029 (Scheduled Transfer)
                       T1030 (Data Transfer Size Limits)
```

---

## 5. Evidence Reliability Assessment

| Evidence | Tampered? | Reliability | Notes |
|----------|-----------|-------------|-------|
| Security.evtx | ✅ Yes | Low (partial) | 649 events deleted; surviving events intact |
| System.evtx | ✅ Yes | Low (partial) | Partially cleared |
| Sysmon.evtx | ❌ No | **High** | Not cleared — fills 106-min gap |
| auditd | ❌ No | **High** | Complete escalation evidence |
| Zeek conn/ssl/dns | ❌ No | **Very High** | Hub-side; endpoint-independent |
| CloudTrail | ❌ No | **Very High** | AWS-side; cannot be tampered by endpoint |

**Forensic conclusion:** The evidence base is sufficient for legal proceedings
despite attacker log clearing. The surviving Sysmon.evtx, auditd, and Zeek logs
provide multi-source corroboration for all critical events.

---

## 6. Regulatory Notification Requirements

| Regulation | Trigger | Deadline | Status |
|------------|---------|----------|--------|
| SEC Regulation S-P | Client financial PII exfiltrated (account-balances.csv) | 30 days from discovery | **REQUIRED — Notify by July 17, 2026** |
| SEC Regulation SCI | Trading system compromise | Prompt notification | **REQUIRED — Notify promptly** |
| NY DFS Cybersecurity (23 NYCRR 500) | Security event | 72 hours for material events | **REQUIRED — Notify by June 19, 2026** |
| FINRA Rule 4370 | Business continuity event | Immediate | Assess with compliance team |

---

## 7. Immediate Remediation Priorities

```
CONTAINMENT (COMPLETE)
  ✅ WS-FIN-04 isolated from network
  ✅ lnx-trade-01 isolated from network
  ⬜ AWS account: Revoke trading-api-deploy key; rotate admin role
  ⬜ Bloomberg: Revoke and reissue API key

CREDENTIAL ROTATION (URGENT)
  ⬜ Rotate all GitHub-exposed credentials (AWS, DB, API)
  ⬜ Reset j.henderson, svc_ncg, svc_backup passwords
  ⬜ Force password reset on all kerberoasted accounts (MSSQLSvc, http, svc_backup)
  ⬜ Convert service accounts to gMSA

DETECTION GAPS (THIS WEEK)
  ⬜ Forward CloudTrail to SIEM (identified Day 16; still pending)
  ⬜ Forward Zeek logs to SIEM (identified Day 18; still pending)
  ⬜ Enable Sysmon log clearing alert (Event 1102/104 — would have caught this)
  ⬜ Deploy EQL Rule 2 (log clear events) in Elastic SIEM
```

---

## 8. Chain of Custody Certification

I certify that the evidence described in `artifacts/evidence_manifest.json`
was collected and handled in accordance with standard digital forensics
principles, including:

- Evidence collected in read-only mode where possible
- SHA256 and MD5 hashes computed at acquisition
- All evidence stored on write-protected forensic media
- Chain of custody maintained per NovaCrest IR policy

**Analyst:** V. Willis, CISSP  
**Date:** 2026-06-18  
**Case Number:** NCA-2026-06

---

*Day 19 — Forensic Log Analysis Report | Case NCA-2026-06*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
