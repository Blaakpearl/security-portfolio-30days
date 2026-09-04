# Day 17 — Hunt Findings Report: Privilege Escalation
**NovaCrest Capital Group | Threat Hunt**
**Classification:** TLP:AMBER — Security Operations Use
**Author:** V. Willis, CISSP
**Date:** 2026-06-17
**Hunt Window:** 2026-06-14 08:00–18:00 UTC

---

## Hunt Summary

| Hypothesis | Technique | Verdict | Findings |
|------------|-----------|---------|----------|
| H1 — Token Impersonation | T1134.001 | ✅ CONFIRMED | lsass access + SeImpersonatePrivilege |
| H2 — Sudo Abuse | T1548.003 | ✅ CONFIRMED | NOPASSWD GTFOBin exploitation |
| H3 — SUID Exploitation | T1548.001 | ✅ CONFIRMED | Unexpected SUID on find, python3, vim |
| H4 — Kerberoasting | T1558.003 | ✅ CONFIRMED | 3 RC4 TGS requests in 4 seconds |
| H5 — UAC Bypass | T1548.002 | ✅ CONFIRMED | ms-settings COM hijack → fodhelper |
| H6 — Privilege Assignment | T1134 | ✅ CONFIRMED | SeTcbPrivilege on standard user |

**All six hypotheses confirmed. The attacker achieved privilege escalation
via multiple overlapping techniques within a 90-minute window.**

---

## Confirmed Escalation Timeline

```
08:00      Initial access confirmed (phishing → low-priv shell on WS-FIN-04)
           User: ncg\j.henderson (standard domain user)

09:15:22   H1: svc_update.exe (attacker process) opens lsass.exe (0x1010 access)
           → Token harvest attempt

09:15:45   H6: Logon token for j.henderson contains SeTcbPrivilege, SeImpersonatePrivilege
           → CRITICAL: Standard user should never hold these privileges
           → Likely achieved via juicy potato / rogue named pipe technique

09:18:33   H5: Registry write to HKCU\Software\Classes\ms-settings\...\command
           → UAC bypass staged (ms-settings COM object hijack)

09:18:34   H5: fodhelper.exe spawned by svc_update.exe
09:18:35   H5: cmd.exe spawned by fodhelper.exe at HIGH integrity
           → UAC bypass succeeded; process now running elevated

09:22:05   H4: First RC4 TGS request (MSSQLSvc/sqlserver.novacrest.local)
09:22:07   H4: Second RC4 TGS request (http/intranet.novacrest.local)
09:22:09   H4: Third RC4 TGS request (svc_backup/backup.novacrest.local)
           → Kerberoasting confirmed; 3 service hashes extracted for offline crack

10:28:44   H3: lnx-trade-01 — find command executed with euid=0 (SUID set on /usr/bin/find)
           → SUID exploitation on Linux host

10:32:11   H2: lnx-trade-01 — svc_ncg runs: sudo find . -exec /bin/bash ; -quit
           → GTFOBin via NOPASSWD sudo rule; setuid(0) confirmed in auditd

TOTAL WINDOW: 90 minutes from first escalation attempt to root on Linux
```

---

## H1 — Token Impersonation: Detailed Findings

**Evidence:** Sysmon Event 10 on WS-FIN-04 at 09:15:22 UTC

```
SourceImage:   C:\Users\j.henderson\AppData\Local\Temp\svc_update.exe
TargetImage:   C:\Windows\System32\lsass.exe
GrantedAccess: 0x1010  (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
CallTrace:     ntdll.dll → svc_update.exe
```

**Evidence:** Security Event 4672 on WS-FIN-04 at 09:15:45 UTC

```
SubjectUserName:  j.henderson
SubjectDomain:    NCG
PrivilegeList:    SeDebugPrivilege
                  SeImpersonatePrivilege
                  SeTcbPrivilege           ← CRITICAL
```

**Assessment:** SeImpersonatePrivilege on a standard user token is the
classic indicator of token impersonation via named pipe (Juicy Potato,
PrintSpoofer, or similar). The attacker coerced a SYSTEM-level service
to authenticate to a rogue named pipe server, captured its token, and
impersonated it. Combined with lsass.exe process access, this constitutes
confirmed token-based privilege escalation to SYSTEM.

---

## H4 — Kerberoasting: Detailed Findings

**Evidence:** Security Event 4769 × 3, SRV-AD-01, 09:22:05–09:22:09 UTC

```
Event 1: TargetUserName = MSSQLSvc/sqlserver.novacrest.local:1433
         EncryptionType = 0x17 (RC4-HMAC)
         SourceIP: 10.0.1.40 (WS-FIN-04)

Event 2: TargetUserName = http/intranet.novacrest.local
         EncryptionType = 0x17 (RC4-HMAC)
         SourceIP: 10.0.1.40 (WS-FIN-04)

Event 3: TargetUserName = svc_backup/backup.novacrest.local
         EncryptionType = 0x17 (RC4-HMAC)
         SourceIP: 10.0.1.40 (WS-FIN-04)
```

**Assessment:** Three RC4 TGS requests in 4 seconds from WS-FIN-04 is
unambiguous Kerberoasting. The attacker enumerated SPNs and requested
RC4-encrypted service tickets to crack offline. The `svc_backup` account
is particularly high-value — service accounts used in backup operations
often have broad access to file servers and domain resources.

**Risk of cracked hashes:**
- `MSSQLSvc`: SQL Server access; potential data exfiltration
- `svc_backup`: Backup operator rights; can read all files; often path to DA

---

## H5 — UAC Bypass: Detailed Findings

**Evidence:** Sysmon Event 13 (Registry) + Event 1 (Process Create) on WS-FIN-04

**Registry write at 09:18:33:**
```
TargetObject: HKCU\Software\Classes\ms-settings\shell\open\command\(Default)
Details: cmd.exe /c powershell.exe -enc [base64 payload]
User: NCG\j.henderson
```

**Process chain at 09:18:34–09:18:35:**
```
svc_update.exe (Medium integrity)
  └─ fodhelper.exe (auto-elevates; reads ms-settings COM key)
       └─ cmd.exe (High integrity — UAC bypassed)
            └─ powershell.exe -enc [payload] (High integrity)
```

**Assessment:** Textbook fodhelper UAC bypass. fodhelper.exe is a signed
Windows binary that auto-elevates without UAC prompt. It reads the
`ms-settings` COM object from HKCU before HKCR — by writing a malicious
value to HKCU first, the attacker's process runs at High integrity when
fodhelper launches it. Combined with the token impersonation (H1), the
attacker now has both SYSTEM token access and a High-integrity process.

---

## H2 — Sudo Abuse (Linux): Detailed Findings

**Evidence:** auditd records on lnx-trade-01 at 10:32:11 UTC

```
[SYSCALL] exe=/usr/bin/sudo uid=1002 auid=1002
[EXECVE]  argv[0]=/usr/bin/find argv[1]=. argv[2]=-exec
          argv[3]=/bin/bash argv[4]=; argv[5]=-quit
[USER_AUTH] op=PAM:sudo acct=svc_ncg res=success
[SYSCALL] exe=/bin/bash syscall=setuid result_uid=0
```

**Misconfigured sudoers rule (discovered by hunter):**
```
# /etc/sudoers.d/svc_ncg  ← MISCONFIGURATION
svc_ncg ALL=(ALL) NOPASSWD: /usr/bin/find
```

**Assessment:** The `svc_ncg` service account can run `/usr/bin/find` as
root without a password. `/usr/bin/find` is a GTFOBin — `find -exec /bin/bash ;`
spawns an interactive root shell. The setuid(0) syscall in auditd confirms
the escalation succeeded. The auditd key `suid_exec` fired but was not
forwarded to SIEM.

---

## H3 — SUID Exploitation (Linux): Detailed Findings

**SUID binaries found on lnx-trade-01 not in baseline:**

| Binary | Mode | GTFOBin? | Escalation Path |
|--------|------|----------|-----------------|
| `/usr/bin/find` | 4755 | ✅ | `find . -exec /bin/bash \; -quit` |
| `/usr/bin/python3` | 4755 | ✅ | `python3 -c 'import os; os.execl("/bin/bash","bash","-p")'` |
| `/usr/bin/vim` | 4755 | ✅ | `vim -c ':py import os; os.execl("/bin/bash","bash","-p")'` |

**Enumeration evidence** (auditd PROCTITLE at 10:28:44):
```
proctitle: /usr/bin/find / -perm -4000 -type f
uid: 1002 (svc_ncg)
```

**Assessment:** Three unexpected SUID binaries present, all GTFOBins. The
attacker enumerated them with `find -perm -4000` (logged in auditd) before
choosing `find` as the escalation path (subsequently used in H2 sudo abuse).
All three should have SUID removed immediately.

---

*Day 17 Hunt Findings | Privilege Escalation*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
