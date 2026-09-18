# Day 25 — Ransomware Forensic Report
## Case NCA-2026-06-R | SRV-FS-01 Ransomware Incident
**NovaCrest Capital Group | Digital Forensics**
**Classification:** TLP:AMBER — Attorney-Client Privileged | Forensic Work Product
**Examiner:** V. Willis, CISSP
**Report Date:** 2026-06-25
**Case Number:** NCA-2026-06-R

---

## 1. Executive Summary

On June 19, 2026 at approximately 03:22 UTC, an attacker who had maintained
covert access to NovaCrest's network since June 14 (Case NCA-2026-06) deployed
ransomware on `SRV-FS-01`, the primary file server. The ransomware — a custom
variant bearing characteristics of the LockBit 3.0 builder kit — encrypted
**26,168 files across 2,215 GB** of data on three file shares before being
detected at 06:14 UTC.

This is a **double-extortion attack**: data was exfiltrated during the initial
intrusion (Days 18/24, ~293 MB total), then the same attacker returned five
days later to deploy ransomware, compounding the incident with a $4.2M USD
ransom demand and threat of data publication at their leak site.

**Encryption was complete before detection.** The 2-hour 50-minute encryption
window (03:24–06:12 UTC) ran entirely undetected — no EDR, no SIEM alert, no
monitoring triggered during active encryption. Detection came from an overnight
monitoring team noticing file share anomalies at 06:14 UTC, after encryption
was fully complete.

**Recovery path:** A clean backup exists (June 13, 23:00 UTC — one day before
initial compromise). Restore from backup is viable and recommended over paying.

---

## 2. Forensic Timeline

### Pre-Deployment: Lateral Movement (03:15–03:22 UTC)

The attacker used credentials obtained via Kerberoasting (Day 17, `svc_backup`
account) to authenticate from `SRV-AD-01` to `SRV-FS-01` via Pass-the-Ticket.

| Time (UTC) | Event | Evidence | Technique |
|-----------|-------|---------|-----------|
| 03:15:44 | PtT: svc_backup ticket used for SRV-FS-01 auth | Security 4648 (SRV-AD-01) | T1550.002 |
| 03:16:02 | Network logon Type 3: svc_backup on SRV-FS-01 | Security 4624 (SRV-FS-01) | T1021.002 |
| 03:22:11 | svchost32.exe (5.4 MB) created in C:\Windows\Temp | Sysmon Event 11 | T1105 |
| 03:22:45 | WmiPrvSE.exe spawns svchost32.exe | Sysmon Event 1 | T1047 |

### Defense Evasion (03:23 UTC — 44 seconds)

```
03:23:01  svchost32.exe → cmd.exe /c sc stop WinDefend
03:23:08  System Event 7036: Windows Defender stopped
03:23:15  cmd.exe: vssadmin delete shadows /all /quiet    ← All shadow copies gone
03:23:22  cmd.exe: wbadmin delete catalog -quiet           ← Windows Backup gone
03:23:29  cmd.exe: bcdedit /set {default} recoveryenabled No
03:23:33  cmd.exe: netsh firewall add rule ... block SMB port 445 (anti-spread)

TOTAL ANTI-RECOVERY TIME: 44 seconds
```

### Encryption (03:24–06:12 UTC — 2 hours 48 minutes)

```
03:24:05  First .ncrypt file: Finance\Q1_2026_client_balances.xlsx.ncrypt
          Encryption rate peaks at ~680 files/minute (Finance share — small files)
          Drops to ~95 files/minute (Trading share — large parquet files)

06:11:44  Last encrypted file written
06:11:44  Ransom notes begin dropping: !!READ_ME_NOW!!.txt
          → 847 directories receive the ransom note

06:13:58  Desktop wallpaper changed to ransom image

ENCRYPTION WINDOW: 2 hours 48 minutes
TOTAL ENCRYPTED: 26,168 files | 2,215 GB
```

### Detection & Response (06:14–06:31 UTC)

```
06:14:00  Monitoring alert: unusual file extension proliferation on \\SRV-FS-01
06:19:00  IR team engaged; SRV-FS-01 identified as primary affected system
06:31:00  Trading operations suspended; SRV-FS-01 network-isolated
06:45:00  Memory dump acquired (WinPmem, 39 GB)
07:00:00  FTK Imager disk acquisition begins
```

---

## 3. Malware Analysis

### Binary Identification

**Recovered from:** C:\Windows\Temp\svchost32.exe (disk)  
**Also recovered:** Unpacked from PID 3412 memory via Volatility3 `malfind`

| Property | Value |
|----------|-------|
| Filename | svchost32.exe (masquerades as system svchost) |
| File size | 5,662,720 bytes (5.4 MB) |
| SHA256 | a4b3c2d1e0f9...f5a4b3 |
| Packer | UPX 3.96 (packed on disk; unpacked in memory) |
| Compile time | 2026-06-15T14:22:00Z (**1 day after initial access**) |
| Language | C++ |
| Linker | Microsoft Linker 14.0 |

**Classification:** LockBit 3.0 builder variant. The compile timestamp (June 15)
suggests the attacker built a custom victim-specific binary after gaining initial
access on June 14 — standard double-extortion operational practice.

### Encryption Scheme

```
Per-file encryption:   AES-256-CBC
Key encapsulation:     RSA-4096 (public key embedded in binary)
Key derivation:        BCryptGenRandom → AES session key per file
Session key storage:   Encrypted session key appended to end of each .ncrypt file
Master key:            Held by attacker (required for decryption)

This scheme is cryptographically sound — without the attacker's RSA private key,
decryption is not mathematically feasible.
```

**Evidence:** Volatility3 `dlllist` on PID 3412 shows `bcrypt.dll` and `ncrypt.dll`
loaded — confirming Windows BCrypt API used for AES + RSA operations.

### YARA Match Results

Running `yara_rules.yar` against the recovered binary:

```
[MATCH] ncrypt_ransom_note         ← "!!READ_ME_NOW!!", contact email, .onion
[MATCH] ncrypt_binary_strings      ← vssadmin, wbadmin, bcdedit embedded as strings
[MATCH] ransomware_recovery_destruction ← 3 anti-recovery commands
[MATCH] lockbit3_builder_variant   ← Process termination list (mysql, oracle, sqlwriter)
[MATCH] ncrypt_mutex_pattern       ← "Global\\NovaCryptMutex_NOVA-20260619-7X4K"
[MATCH] ransomware_file_enumeration ← FindFirstFileW + BCryptEncrypt API pattern
```

### Persistence Mechanism

The ransomware installed itself as a Windows service for persistence:

```
Service Name:    NovaCrypt
Display Name:    Novacrest Cryptographic Services (intentional typo: "Novacrest" not "NovaCrest")
Image Path:      C:\Windows\System32\svchost32.exe -k netsvcs
Start Type:      AUTO_START (starts on reboot)
Registry Key:    HKLM\SYSTEM\CurrentControlSet\Services\NovaCrypt
Status:          ACTIVE — NOT YET DELETED
```

**Also found:** IFEO debugger hijack:
```
Key: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe
Value: Debugger = C:\Windows\Temp\svchost32.exe
```
This means opening Task Manager would launch the ransomware — a persistence and
re-infection mechanism if the service is deleted without removing this key.

### C2 Communication

Memory analysis (Volatility3 `netstat`) shows one network connection at dump time:

```
Protocol: TCPv4
Local:    10.0.3.20:49812
Foreign:  198.51.100.99:443
State:    CLOSE_WAIT (disconnected when network was isolated at 06:31)
Process:  svchost32.exe (PID 3412)
```

**Same C2 IP as the initial access C2 (198.51.100.99)** — confirms the ransomware
operator is the same threat actor as the initial intrusion. Zeek ssl.log shows the
C2 connection at 03:23:55 UTC (before encryption began) — likely the binary
reporting successful deployment and receiving the per-victim RSA public key.

---

## 4. Encryption Scope

| Share | Files Encrypted | Data Volume | File Types |
|-------|-----------------|-------------|-----------|
| \\SRV-FS-01\Finance | 14,823 | 847 GB | .xlsx, .pdf, .csv, .msg, .pst |
| \\SRV-FS-01\Trading | 8,241 | 1,244 GB | .parquet, .py, .json, .db |
| \\SRV-FS-01\HR | 3,104 | 124 GB | .pdf, .docx, .png |
| **Total** | **26,168** | **2,215 GB** | |

**Files skipped by ransomware (by design):**
System files (*.exe, *.dll, *.sys) were excluded to keep the OS functional —
standard ransomware behavior (they need the OS working so victims can see the
ransom note and pay).

---

## 5. Recovery Assessment

| Option | Viable? | Details |
|--------|---------|---------|
| Backup restore | ✅ **RECOMMENDED** | June 13 backup (pre-compromise) confirmed clean |
| Shadow copy | ❌ | Deleted at 03:23 UTC by vssadmin |
| Windows Backup | ❌ | Deleted at 03:23 UTC by wbadmin |
| No More Ransom decryptor | 🔍 Check | ncrypt variant not yet in NMR database |
| FBI/CISA seized keys | 🔍 Possible | LockBit 3.0 keys seized in Operation Cronos (2024); engage FBI to check coverage |
| Pay ransom | ❌ Not recommended | OFAC risk (LockBit sanctioned); no decryption guarantee; $4.2M |

**Recommended path:** Restore from June 13 backup (estimated 2–3 days for 2.2 TB).
Simultaneously engage FBI Cyber Division — Operation Cronos (February 2024) seized
LockBit decryption infrastructure; there is a non-zero chance the per-victim key
is recoverable.

---

## 6. Immediate Actions Required

```
IMMEDIATE (before restoration):
  ☐ Delete NovaCrypt service: sc delete NovaCrypt
  ☐ Remove IFEO debugger key: reg delete "HKLM\SOFTWARE\...\taskmgr.exe" /f
  ☐ Delete svchost32.exe from Temp
  ☐ File report with FBI IC3 (www.ic3.gov) — required for CISA/FBI decryptor access
  ☐ Contact CISA (1-888-282-0870) — report ransomware incident

BEFORE RESTORATION:
  ☐ Forensic image of SRV-FS-01 must be complete and verified before any changes
  ☐ Verify June 13 backup integrity (hash check + test restore on isolated VM)
  ☐ Confirm backup server was NOT accessible during attacker dwell time

RESTORATION:
  ☐ Rebuild SRV-FS-01 from clean OS image (do not restore OS from backup)
  ☐ Restore data only from June 13 backup to clean rebuild
  ☐ Validate restored data (spot check 100 files per share)
  ☐ Re-enroll in EDR before reconnecting to network
```

---

*Day 25 — Ransomware Forensic Report | Case NCA-2026-06-R*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
