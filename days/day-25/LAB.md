# Day 25 — LAB.md
## Ransomware Forensics Lab Guide
**NovaCrest Capital Group | Digital Forensics Track**

---

## Phase 1: Evidence Acquisition (FTK Imager)

```bash
# FTK Imager (Windows — GUI tool from AccessData/Exterro)
# Download: https://www.exterro.com/ftk-imager

# LIVE ACQUISITION (while server is running — preserves RAM)
# 1. FTK Imager → File → Capture Memory
#    Output file: SRV-FS-01_memory_2026-06-19_0645UTC.mem
#    Include pagefile: YES

# 2. FTK Imager → File → Create Disk Image
#    Source: PhysicalDrive0 (system disk)
#    Image type: E01 (EnCase format — preserves metadata)
#    Destination: /forensics/NCA-2026-06-R/SRV-FS-01.E01
#    Verify after creation: YES (SHA256 + MD5)

# Command-line equivalent (Linux — for E01 acquisition)
sudo dcfldd if=/dev/sda \
    hash=sha256 \
    hashconv=after \
    hashlog=/forensics/NCA-2026-06-R/SRV-FS-01.sha256 \
    of=/forensics/NCA-2026-06-R/SRV-FS-01.img \
    bs=4096

# Hash verification
sha256sum /forensics/NCA-2026-06-R/SRV-FS-01.img > SRV-FS-01.img.sha256
sha256sum -c SRV-FS-01.img.sha256
```

---

## Phase 2: Disk Forensics (Autopsy)

```bash
# Install Autopsy (open source digital forensics platform)
# Download: https://www.autopsy.com/download/

# Mount E01 image for analysis
sudo apt-get install -y libewf-dev ewf-tools
ewfmount /forensics/NCA-2026-06-R/SRV-FS-01.E01 /mnt/evidence/

# Alternative: use Arsenal Image Mounter on Windows
# (mounts E01 as drive letter for direct Autopsy loading)
```

### Autopsy Analysis Workflow

```
1. NEW CASE
   Case Name: NCA-2026-06-R
   Case Number: NCA-2026-06-R
   Examiner: V. Willis, CISSP

2. ADD DATA SOURCE
   → Add Image or VM File → SRV-FS-01.E01
   → Enable all ingest modules:
     ✅ Recent Activity (MRU, run keys)
     ✅ Hash Lookup (NSRL + custom ransomware IOC set)
     ✅ Keyword Search (ransom note patterns, .ncrypt)
     ✅ File Type Identification
     ✅ Extension Mismatch Detector
     ✅ Encryption Detection
     ✅ EXIF Parser
     ✅ Windows Registry

3. KEY ARTIFACTS TO LOCATE
   a) Ransomware binary:
      → Keyword search: "*.ncrypt" "!!READ_ME_NOW!!" "ncrypt"
      → Look in: C:\Windows\Temp\, C:\ProgramData\, C:\Users\Public\
      → Check Prefetch: C:\Windows\Prefetch\ for execution evidence

   b) VSS deletion artifacts:
      → Keyword: "vssadmin delete shadows"
      → Event log: System Event 8224 (VSS service stopped)
      → Event log: Application Event 8193 (VSS failed)

   c) Lateral movement artifacts:
      → Security log: Event 4648, 4624 (logon from WS-FIN-04 / SRV-AD-01)
      → SMB named pipe artifacts in registry

   d) Scheduled task or service persistence:
      → C:\Windows\System32\Tasks\
      → HKLM\SYSTEM\CurrentControlSet\Services\

   e) Ransom note locations:
      → All directories containing !!READ_ME_NOW!!.txt
      → Count: 847 directories confirmed
```

### MFT Analysis for Encryption Timeline

```bash
# Extract MFT (Master File Table) from disk image
# MFT records every file's creation/modification/access timestamps
icat /forensics/NCA-2026-06-R/SRV-FS-01.img 0 > SRV-FS-01.MFT

# Parse MFT with analyzeMFT
pip install analyzeMFT --break-system-packages
python3 analyzeMFT.py -f SRV-FS-01.MFT -o SRV-FS-01_mft.csv

# Find files modified in the encryption window (June 19, 04:00-06:14 UTC)
grep "2026-06-19,0[4-6]:" SRV-FS-01_mft.csv | \
    grep "\.ncrypt" | wc -l
# → How many files were encrypted?

# Find the ransomware binary by looking for executables created just before encryption
grep "2026-06-18,2[0-3]:\|2026-06-19,0[0-4]:" SRV-FS-01_mft.csv | \
    grep "\.exe\|\.dll" | head -20
```

---

## Phase 3: Memory Forensics (Volatility3)

```bash
# Install Volatility3
pip install volatility3 --break-system-packages

# Profile identification (Windows Server 2022 = Win10+ profile)
python3 vol.py -f SRV-FS-01_memory_2026-06-19_0645UTC.mem \
    windows.info

# Process list — find ransomware process
python3 vol.py -f SRV-FS-01_memory_0645.mem windows.pslist \
    | grep -v "System\|smss\|csrss\|wininit\|services\|lsass\|svchost\|spoolsv"

# Process tree — show parent-child relationships (find WMI → ransomware)
python3 vol.py -f SRV-FS-01_memory_0645.mem windows.pstree \
    | head -60

# Find hidden/injected processes (ransomware may hide itself)
python3 vol.py -f SRV-FS-01_memory_0645.mem windows.psxview

# Scan for suspicious code injection
python3 vol.py -f SRV-FS-01_memory_0645.mem windows.malfind \
    --dump-dir /tmp/malfind_output/

# Extract ransomware binary from memory
python3 vol.py -f SRV-FS-01_memory_0645.mem windows.dumpfiles \
    --pid [RANSOMWARE_PID] \
    --dump-dir /tmp/binary_extract/

# Check loaded DLLs for crypto library (AES, RSA — used for encryption)
python3 vol.py -f SRV-FS-01_memory_0645.mem windows.dlllist \
    --pid [RANSOMWARE_PID] | grep -i "crypt\|ssl\|tls\|bcrypt"

# Recover encryption keys from memory (RSA public key in process memory)
python3 vol.py -f SRV-FS-01_memory_0645.mem windows.handles \
    --pid [RANSOMWARE_PID] | grep -i "key\|crypt"

# Network connections at time of dump (C2 callback?)
python3 vol.py -f SRV-FS-01_memory_0645.mem windows.netstat

# Registry hives in memory — find persistence keys
python3 vol.py -f SRV-FS-01_memory_0645.mem windows.registry.hivelist
python3 vol.py -f SRV-FS-01_memory_0645.mem windows.registry.printkey \
    --key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
```

---

## Phase 4: YARA Scanning

```bash
# Install YARA
sudo apt-get install -y yara

# Run YARA against recovered binary and memory dump
yara -r artifacts/yara_rules.yar /tmp/binary_extract/
yara -r artifacts/yara_rules.yar SRV-FS-01_memory_0645.mem

# Run against full disk image (slow — use with targeted paths)
yara artifacts/yara_rules.yar /mnt/evidence/Windows/Temp/
yara artifacts/yara_rules.yar /mnt/evidence/ProgramData/
yara artifacts/yara_rules.yar /mnt/evidence/Users/

# Expected hits:
#   RULE lockbit_ransom_note         → !!READ_ME_NOW!!.txt
#   RULE ncrypt_extension_mass_rename → MFT entries with .ncrypt
#   RULE vss_deletion_command        → prefetch/event log
#   RULE lockbit3_binary_strings     → ransomware executable
```

---

## Phase 5: Ghidra Static Analysis

```bash
# Install Ghidra (NSA reverse engineering tool)
# Download: https://ghidra-sre.org/
# Requires: JDK 17+

# Import recovered binary
# Ghidra → New Project → Import File → [ransomware.exe]
# Auto-analyze: YES (takes 5-10 min)

# Key analysis targets:
# 1. Entry point → find WinMain or DllMain
# 2. String search: "ncrypt", "README", "Monero", ".onion"
# 3. Crypto functions: look for AES key schedule (0x01020408 XOR pattern)
# 4. RSA implementation: large prime number math, CryptGenKey calls
# 5. File enumeration: FindFirstFile, FindNextFile in recursive pattern
# 6. Shadow copy deletion: CreateProcess with vssadmin arguments
# 7. Network functions: HTTPSend, WinHttp — C2 check-in

# Headless Ghidra analysis (batch)
$GHIDRA_HOME/support/analyzeHeadless /tmp/ghidra_project RansomwareAnalysis \
    -import /tmp/binary_extract/ransomware.exe \
    -postScript ExtractStrings.java \
    -scriptPath $GHIDRA_HOME/Ghidra/Features/Base/ghidra_scripts/ \
    -log /tmp/ghidra_analysis.log
```

---

## Phase 6: Encryption Scope Assessment

```bash
# Count encrypted files by extension and share
python3 scripts/ransomware_analyzer.py --mode scope \
    --path /mnt/evidence/Finance/ \
    --extension .ncrypt \
    --output /tmp/encryption_scope.json

# Check VSS snapshot status
vssadmin list shadows    # Likely empty (deleted by ransomware)

# Check Windows Backup catalog
wbadmin get versions     # Likely deleted

# Check for network backup (may be unaffected if offline at encryption time)
# Check tape/cloud backup last good date

# Run decryption test (if decryptor available from No More Ransom)
# https://www.nomoreransom.org/en/decryption-tools.html
# Search: ncrypt extension, ransom note text

# Check for unencrypted copies in:
#   - Recycle Bin ($Recycle.Bin)
#   - Previous versions (if VSS partially survived)
#   - Email attachments (Exchange)
#   - Laptop offline copies
```

---

## Recovery Decision Matrix

```
OPTION 1: Restore from backup
  Condition: Clean backup exists before June 14 (initial access)
  Timeline:  2-5 days depending on data volume
  Risk:      Backup may be compromised if attacker had backup access

OPTION 2: Decrypt with tool (if strain identified + decryptor exists)
  Check: https://www.nomoreransom.org
  Timeline:  Immediate (if tool exists)
  Risk:      Low (non-destructive)

OPTION 3: Law enforcement (FBI, CISA)
  Condition: Report to FBI IC3 + CISA
  Benefit:   Access to decryption keys seized from prior arrests
  Timeline:  Days to weeks (no guarantee)

OPTION 4: Negotiate / Pay (NOT RECOMMENDED)
  Risk:      No guarantee of decryption; funds criminal enterprise
             May violate OFAC sanctions if group is sanctioned
             SEC requires disclosure if ransom paid (proposed rule)

RECOMMENDED: Option 1 (backup restore) + Option 3 (FBI report) simultaneously
```

---

*Day 25 Lab Guide | Ransomware Forensics*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
