# Day 17 — Privilege Escalation Detection Playbook
**NovaCrest Capital Group | Security Operations**
**Classification:** TLP:WHITE — Internal Distribution
**Author:** V. Willis, CISSP
**Version:** 1.0

---

## Purpose

This playbook documents detection logic, triage steps, and hardening controls
for each privilege escalation technique confirmed in the Day 17 hunt. It is
intended as a standing operational reference for the SOC and for endpoint
hardening teams.

---

## Technique 1: Token Impersonation (T1134.001)

### Detection Logic

**Primary signal — Sysmon Event 10 (ProcessAccess to lsass.exe):**
```
EventID: 10
TargetImage: *\lsass.exe
GrantedAccess: 0x1010 OR 0x1410 OR 0x0010 OR 0x1FFFFF
SourceImage: NOT (AV/EDR processes, svchost.exe, services.exe)
```

**Corroborating signal — Security Event 4672:**
```
EventID: 4672
PrivilegeList CONTAINS: SeImpersonatePrivilege OR SeDebugPrivilege
SubjectUserName: NOT in (SYSTEM, LOCAL SERVICE, NETWORK SERVICE)
SubjectUserName: NOT ending in $
```

### Triage Steps
1. Identify `SourceImage` in Sysmon Event 10 — is it a known tool or suspicious binary?
2. Check `GrantedAccess` value — 0x1010 is read access (may be credential theft);
   0x1FFFFF is full access (almost certainly malicious for non-system process)
3. Correlate with Event 4672 for same user in same session — confirms privilege assignment
4. Check if `SourceImage` is in `%TEMP%` or `%APPDATA%` — strong malware indicator
5. Pull parent process of `SourceImage` via Event 1 — trace origin

### Hardening Controls
- Enable **Windows Defender Credential Guard** — isolates lsass in virtualization-based security
- Enable **PPL (Protected Process Light)** for lsass:
  ```
  reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f
  ```
- Restrict `SeImpersonatePrivilege` — audit who holds it via:
  ```powershell
  Get-LocalGroupMember -Group "IIS_IUSRS"  # Common holder of SeImpersonate
  secedit /export /cfg C:\secpol.cfg && findstr "SeImpersonatePrivilege" C:\secpol.cfg
  ```
- Deploy **JEA (Just Enough Administration)** for service accounts

---

## Technique 2: Sudo Abuse (T1548.003)

### Detection Logic

**Primary signal — auditd key=sudo_exec:**
```
type=SYSCALL exe=/usr/bin/sudo
uid != 0 AND auid NOT IN (authorised_admin_uids)
```

**GTFOBin pattern — auditd EXECVE arguments:**
```
args match: (/bin/bash|/bin/sh|exec|os\.system|pcntl_exec)
```

**Sudoers modification — auditd key=sensitive_file_write:**
```
type=PATH name=/etc/sudoers OR name=/etc/sudoers.d/*
type=SYSCALL syscall IN (open, openat, write, truncate)
```

### Triage Steps
1. Identify which user ran sudo and what command was passed (EXECVE record)
2. Check `/etc/sudoers` and `/etc/sudoers.d/` for NOPASSWD rules:
   ```bash
   sudo grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/
   ```
3. Verify if the binary run via sudo is a GTFOBin:
   ```bash
   # Compare against GTFOBins list in suid_audit_scanner.py
   ```
4. Check auditd setuid record immediately following — did UID change to 0?
5. Review auth.log for PAM:sudo success/failure context

### Hardening Controls
```bash
# 1. Audit all sudoers rules — remove NOPASSWD
sudo grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/
# Remove any NOPASSWD entries; use targeted rules only

# 2. Restrict sudo to specific, non-GTFOBin commands only
# BAD:  svc_ncg ALL=(ALL) NOPASSWD: /usr/bin/find
# GOOD: svc_ncg ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp.service

# 3. Enable sudo logging in syslog
# /etc/sudoers:
Defaults log_host, log_year, logfile="/var/log/sudo.log"
Defaults timestamp_timeout=0  # Don't cache sudo password

# 4. Set sudo requiretty (prevents non-interactive sudo abuse)
Defaults requiretty
```

---

## Technique 3: SUID/SGID Binary Exploitation (T1548.001)

### Detection Logic

**Primary signal — auditd key=suid_exec (euid=0 by non-root user):**
```
type=SYSCALL euid=0 uid!=0 key=suid_exec
exe IN (GTFOBins list)
```

**Enumeration recon — auditd PROCTITLE:**
```
proctitle matches: find.*-perm.*[+-]4000
```

### Triage Steps
1. Run SUID audit scanner on affected host:
   ```bash
   python3 suid_audit_scanner.py --scan / --host lnx-trade-01
   ```
2. Compare output against baseline — identify unexpected SUID binaries
3. Check auditd for recent euid=0 executions from unexpected UIDs
4. Pull bash history for the UID that ran the GTFOBin

### Hardening Controls
```bash
# 1. Remove SUID from unexpected binaries
chmod -s /usr/bin/find    # Remove SUID from find
chmod -s /usr/bin/python3 # Remove SUID from python3
chmod -s /usr/bin/vim     # Remove SUID from vim

# 2. Run quarterly SUID baseline audit
find / -perm -4000 -o -perm -2000 2>/dev/null | sort > /var/lib/suid-baseline.txt
# Alert on diff from previous baseline

# 3. Mount noexec,nosuid on user-writable partitions
# /etc/fstab:
# /tmp: tmpfs /tmp tmpfs rw,nodev,nosuid,noexec 0 0
# /home: /dev/sda3 /home ext4 rw,nodev,nosuid 0 2

# 4. auditd rule for euid change by non-root
-a always,exit -F arch=b64 -S setuid -S setgid -F uid!=0 -k uid_change
```

---

## Technique 4: Kerberoasting (T1558.003)

### Detection Logic

**Primary signal — Security Event 4769 with RC4 (0x17):**
```
EventID: 4769
TicketEncryptionType: 0x17 (RC4-HMAC)
ServiceName: NOT ending in $ (not machine account)
ServiceName: NOT IN (krbtgt, kadmin)
```

**Volume anomaly:**
```
Count(4769 RC4 TGS from same IP in 60s) >= 3
```

### Triage Steps
1. Identify source IP from IpAddress field in 4769 — which host?
2. List all SPNs targeted in the window:
   ```powershell
   # On DC: review Security log for EventID 4769 in timeframe
   Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769;StartTime='...'}
   | Where-Object {$_.Properties[5].Value -eq '0x17'}
   | Select-Object TimeCreated, @{n='Service';e={$_.Properties[2].Value}}
   ```
3. Assess service accounts — are cracked accounts high-privilege?
4. Reset passwords on targeted service accounts immediately (24-char random)
5. Convert service accounts to **Group Managed Service Accounts (gMSA)**

### Hardening Controls
```powershell
# 1. Force AES encryption on service accounts (makes Kerberoasting impractical)
Get-ADUser svc_backup | Set-ADAccountControl -DoesNotRequirePreAuth $false
Set-ADUser svc_backup -KerberosEncryptionType AES128,AES256

# 2. Convert service accounts to gMSA (automatically rotating 240-bit passwords)
New-ADServiceAccount -Name "svc_backup_gMSA" -DNSHostName "backup.novacrest.local" `
    -PrincipalsAllowedToRetrieveManagedPassword "Backup-Servers-Group"

# 3. Alert on RC4 TGS (should be nearly zero in modern environments)
# Deploy SPL Query H4-B / KQL H4-B as scheduled alert with threshold 1

# 4. Rotate all kerberoastable account passwords (25+ chars)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} | ForEach-Object {
    Set-ADAccountPassword $_ -NewPassword (ConvertTo-SecureString ([System.Web.Security.Membership]::GeneratePassword(32,8)) -AsPlainText -Force)
}
```

---

## Technique 5: UAC Bypass (T1548.002)

### Detection Logic

**Registry signal — Sysmon Event 13:**
```
TargetObject CONTAINS: \Software\Classes\ms-settings\shell\open\command
                    OR \Software\Classes\mscfile\shell\open\command
                    OR \Software\Classes\exefile\shell\open\command
```

**Process chain signal — Sysmon Event 1:**
```
ParentImage IN: fodhelper.exe, eventvwr.exe, sdclt.exe, cmstp.exe
Image IN: cmd.exe, powershell.exe, wscript.exe
IntegrityLevel: High
```

### Triage Steps
1. Pull the registry value written — what command was staged?
2. Identify the process that wrote the registry key (Event 13 Image field)
3. Confirm fodhelper/eventvwr spawned a shell at High integrity (Event 1)
4. Check what the spawned shell did (follow child processes from Event 1)
5. Collect `svc_update.exe` or staging binary for malware analysis

### Hardening Controls
```
1. Enforce ConsentPromptBehaviorAdmin = 2 (Always notify + secure desktop)
   reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
       /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f

2. Consider UAC level 3 (prompt for credentials, not just consent)
   reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
       /v ConsentPromptBehaviorUser /t REG_DWORD /d 1 /f

3. Monitor HKCU\Software\Classes for new COM registrations
   (Sysmon configuration: add EventCode=13 filter for \Software\Classes\)

4. Restrict access to auto-elevating binaries via AppLocker or WDAC:
   Block: fodhelper.exe, eventvwr.exe from non-administrative paths
```

---

## Endpoint Hardening Checklist

### Windows

```
CREDENTIAL PROTECTION
  □ Enable Credential Guard (requires UEFI + Secure Boot)
  □ Enable PPL for lsass (RunAsPPL = 1)
  □ Disable WDigest authentication (WDigest\UseLogonCredential = 0)
  □ Enable LSA Protection auditing

PRIVILEGE MANAGEMENT
  □ Audit SeImpersonatePrivilege holders; remove from service accounts
  □ Audit SeDebugPrivilege holders; restrict to explicit admin accounts only
  □ Audit SeRestorePrivilege holders
  □ Implement JEA (Just Enough Administration) for service accounts
  □ Remove all users from local Administrators group except domain admins

KERBEROS HARDENING
  □ Convert all service accounts to gMSA
  □ Force AES-only on all service accounts (remove RC4 support)
  □ Audit all SPNs for orphaned or overprivileged accounts
  □ Rotate all kerberoastable passwords ≥ 25 characters

UAC HARDENING
  □ Set ConsentPromptBehaviorAdmin = 2 (always prompt on secure desktop)
  □ Block auto-elevating binaries (fodhelper, eventvwr) from user paths
  □ Monitor HKCU\Software\Classes for COM hijacking registry writes
  □ Alert on process spawned by auto-elevating binary at High integrity

AUDIT POLICY
  □ Enable Sensitive Privilege Use (Success + Failure)
  □ Enable Token Right Adjusted auditing
  □ Enable Kerberos Service Ticket Operations auditing
  □ Enable Process Creation (Event 4688) with command line
```

### Linux

```
SUDO HARDENING
  □ Remove all NOPASSWD entries from sudoers
  □ Restrict sudo to specific, non-GTFOBin commands
  □ Enable requiretty in /etc/sudoers
  □ Set timestamp_timeout=0 (no password caching)
  □ Enable sudo logging to syslog and dedicated log file

SUID/SGID HARDENING
  □ Run SUID audit scanner (suid_audit_scanner.py) against all hosts
  □ Remove SUID from all binaries not in baseline
  □ Mount /tmp, /home with nosuid flag in /etc/fstab
  □ Schedule quarterly SUID baseline comparison
  □ Alert on SUID binary creation or modification

AUDITD CONFIGURATION
  □ Deploy privesc-hunt.rules from LAB.md on all production hosts
  □ Enable execve logging for SUID binaries (perm=u+s)
  □ Monitor setuid/setgid syscalls from non-root users
  □ Forward auditd logs to SIEM in real time
  □ Alert on key=sudo_exec from unexpected UIDs

FILESYSTEM HARDENING
  □ nosuid on /tmp, /var/tmp, /home, /dev/shm
  □ noexec on /tmp, /var/tmp
  □ Separate partition for /tmp (prevents SUID binary staging)
  □ Set sticky bit on all world-writable directories

SYSTEM HARDENING
  □ Disable core dumps (may contain sensitive memory)
  □ Restrict ptrace to own processes (kernel.yama.ptrace_scope = 1 or 2)
  □ Enable seccomp profiles on sensitive services
  □ Review /etc/passwd for unexpected shell assignments
```

### SIEM Correlation Rules (Deploy These)

```
RULE 1: LSASS Access (Sysmon 10) → 4672 SeImpersonate on same host within 5 min
        Severity: Critical | Auto-isolate endpoint

RULE 2: 3+ RC4 TGS (Event 4769) from same IP in 60 seconds
        Severity: Critical | Disable source account + isolate host

RULE 3: ms-settings registry write (Sysmon 13) → fodhelper spawning shell (Sysmon 1)
        Severity: Critical | Capture memory + isolate

RULE 4: sudo GTFOBin shell escape (auditd key=sudo_exec + /bin/bash in args)
        Severity: Critical | Isolate Linux host + rotate service account

RULE 5: SUID GTFOBin execution with euid=0 (auditd key=suid_exec + euid=0 + uid!=0)
        Severity: High | Investigate + remove SUID bit

RULE 6: Any of H1–H6 confirmed within 2 hours of initial access event
        Severity: Critical | Full IR response + isolate + credential rotation
```

---

*Day 17 — Privilege Escalation Detection Playbook*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
