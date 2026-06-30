# Day 08 — Lab Guide: Malware Triage
### Track: Digital Forensics | Duration: ~3 hours | Difficulty: Intermediate

> **Analysis environment:** All dynamic analysis must be performed in an isolated
> VM with no network connectivity to production systems. Snapshots should be taken
> before any execution. This lab focuses on understanding malware behavior for
> defensive purposes — IOC extraction, detection rule development, and threat
> intelligence production.

---

## 🛠 Tools Required

| Tool | Purpose | Install |
|------|---------|---------|
| **FLOSS** | Static string extraction — deobfuscates encoded strings | `pip install flare-floss` |
| **pefile** | Python PE header analysis library | `pip install pefile` |
| **pecheck.py** | PE structure validation and analysis | Download from Didier Stevens |
| **strings** | Basic string extraction | Pre-installed Linux / Sysinternals strings.exe |
| **Any.run** | Interactive online sandbox | app.any.run (free tier) |
| **VirusTotal** | Multi-engine scan + threat intel | virustotal.com |
| **YARA** | Pattern matching rule engine | `sudo apt install yara` / `pip install yara-python` |
| **ssdeep** | Fuzzy hashing for malware similarity | `sudo apt install ssdeep` |
| **binwalk** | Binary analysis and extraction | `sudo apt install binwalk` |
| **Python 3** | Automation, report generation | Pre-installed |
| **CyberChef** | Data decoding and analysis | gchq.github.io/CyberChef (browser) |

---

## 🖥 Environment Setup

```bash
# 1. Create working directory (Linux analysis VM — isolated)
mkdir -p ~/security-labs/day-08/artifacts/{static,dynamic,yara,iocs}
cd ~/security-labs/day-08

# 2. Install Python tools
pip install pefile flare-floss yara-python requests --break-system-packages

# 3. Install system tools
sudo apt install -y yara ssdeep binwalk strings file hexdump

# 4. Copy sample to working directory
# In a real engagement: copy from forensic image mount point
# For lab: use a known-safe malware sample from theZoo, MalwareBazaar,
# or generate a benign PE file to simulate analysis workflow
export SAMPLE="$HOME/security-labs/day-08/updater.exe"

# 5. Set environment
echo "[+] Malware triage environment ready"
echo "[+] Sample: $SAMPLE"
echo "[!] Ensure VM is isolated from production network before proceeding"
```

> **Sample sourcing for practice:**
> - MalwareBazaar (abuse.ch): `bazaar.abuse.ch` — real samples, use in isolated VM
> - theZoo (GitHub): `github.com/ytisf/theZoo` — password-protected archives
> - VirusTotal intelligence (subscription): download by hash
> - For this lab walkthrough, commands show expected output from a real C2 dropper

---

## STEP 1 — File Identification & Hash Generation

**Objective:** Before any analysis, establish the file's cryptographic identity.
Hashes are the universal language of malware intelligence — they uniquely identify
a sample and allow cross-referencing against every threat intelligence feed.

```bash
# Verify file type — never trust the extension
file "$SAMPLE"
# Expected: PE32+ executable (console) x86-64, for MS Windows

# Generate all three standard hash formats
echo "=== Cryptographic Hashes ==="
echo "MD5:    $(md5sum    $SAMPLE | awk '{print $1}')"
echo "SHA-1:  $(sha1sum   $SAMPLE | awk '{print $1}')"
echo "SHA-256:$(sha256sum $SAMPLE | awk '{print $1}')"

# Fuzzy hash — for finding similar (but not identical) samples
echo "ssdeep: $(ssdeep $SAMPLE)"

# Save all hashes
{
    echo "# File Hashes — updater.exe"
    echo "# Date: $(date -u)"
    echo "Filename: updater.exe"
    echo "Size:     $(stat -c%s $SAMPLE) bytes"
    echo "MD5:      $(md5sum    $SAMPLE | awk '{print $1}')"
    echo "SHA-1:    $(sha1sum   $SAMPLE | awk '{print $1}')"
    echo "SHA-256:  $(sha256sum $SAMPLE | awk '{print $1}')"
    echo "ssdeep:   $(ssdeep    $SAMPLE)"
} > artifacts/static/file_hashes.txt

cat artifacts/static/file_hashes.txt
```

### VirusTotal Hash Lookup

```python
# Save as: vt_hash_lookup.py
import requests, os, json

API_KEY = os.environ.get("VT_API_KEY", "")
SHA256  = open("artifacts/static/file_hashes.txt").read()
# Extract SHA-256 from hashes file
sha256 = [line.split()[-1] for line in SHA256.split("\n")
          if line.startswith("SHA-256")][0]

print(f"[*] Querying VirusTotal for SHA-256: {sha256[:16]}...")

headers = {"x-apikey": API_KEY}
r = requests.get(
    f"https://www.virustotal.com/api/v3/files/{sha256}",
    headers=headers
)

if r.status_code == 404:
    print("[!] NOT FOUND on VirusTotal — novel/unknown sample")
    print("[!] This is high significance — likely custom-built malware")
    print("[!] Proceed with full static + dynamic analysis")
elif r.status_code == 200:
    data = r.json()["data"]["attributes"]
    stats = data.get("last_analysis_stats", {})
    print(f"[+] VirusTotal Results:")
    print(f"    Malicious:  {stats.get('malicious', 0)}/72 engines")
    print(f"    Suspicious: {stats.get('suspicious', 0)}")
    print(f"    Name:       {data.get('meaningful_name', 'Unknown')}")
    print(f"    Family:     {data.get('popular_threat_classification', {})}")
    with open("artifacts/static/vt_results.json", "w") as f:
        json.dump(r.json(), f, indent=2)
else:
    print(f"[!] VT API error: {r.status_code}")
```

```bash
python3 vt_hash_lookup.py | tee artifacts/static/vt_lookup.txt
```

**✅ Checkpoint 1:** If VirusTotal returns 0 detections or 404, you have a
novel sample — this is the most important finding so far. Document it immediately.
Zero detections does not mean benign. It means the threat actor built or customised
this tool specifically to evade all public AV signatures.

---

## STEP 2 — Static String Extraction

**Objective:** Extract all human-readable strings embedded in the binary. Even
packed malware leaks valuable strings: C2 domains, registry paths, API function
names, error messages, and hardcoded configuration values.

### 2a. Basic Strings Extraction

```bash
echo "[*] Extracting strings (min 6 chars, Unicode + ASCII)..."

# ASCII strings
strings -n 6 "$SAMPLE" > artifacts/static/strings_ascii.txt

# Unicode strings  
strings -n 6 -e l "$SAMPLE" > artifacts/static/strings_unicode.txt

# Combine and sort unique
cat artifacts/static/strings_ascii.txt \
    artifacts/static/strings_unicode.txt \
    | sort -u > artifacts/static/strings_all.txt

echo "[+] Total strings extracted: $(wc -l < artifacts/static/strings_all.txt)"
echo ""

# Search for high-value patterns immediately
echo "=== URLs and Network Indicators ==="
grep -iE "https?://|ftp://|\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b" \
    artifacts/static/strings_all.txt | grep -v "microsoft\|windows\|schema" | head -20

echo ""
echo "=== Registry Keys ==="
grep -i "HKEY\|CurrentVersion\\\\" \
    artifacts/static/strings_all.txt | head -20

echo ""
echo "=== Suspicious API Calls ==="
grep -iE "VirtualAlloc|WriteProcessMemory|CreateRemoteThread|\
          OpenProcess|ReadProcessMemory|NtUnmapViewOfSection|\
          SetWindowsHookEx|GetAsyncKeyState|CryptEncrypt" \
    artifacts/static/strings_all.txt | head -20

echo ""
echo "=== File Paths ==="
grep -iE "C:\\\\|%APPDATA%|%TEMP%|%PUBLIC%|\\\\Users\\\\" \
    artifacts/static/strings_all.txt | head -20
```

### 2b. FLOSS — Deobfuscated String Extraction

FLOSS (FLARE Obfuscated String Solver) recovers strings that standard `strings`
misses — including XOR-encoded, stack-constructed, and dynamically built strings.

```bash
echo "[*] Running FLOSS for deobfuscated strings..."
floss --no-static "$SAMPLE" \
    --output-json artifacts/static/floss_output.json \
    2>/dev/null

# Parse FLOSS output
python3 << 'PYEOF'
import json

with open("artifacts/static/floss_output.json") as f:
    data = json.load(f)

print("=== FLOSS Decoded Strings ===")

# Stack strings (constructed at runtime)
stack = data.get("strings", {}).get("stack_strings", [])
print(f"\nStack-constructed strings ({len(stack)} found):")
for s in stack[:20]:
    val = s.get("string", "")
    if len(val) > 4:
        print(f"  {val}")

# Decoded strings (XOR/obfuscated)
decoded = data.get("strings", {}).get("decoded_strings", [])
print(f"\nDecoded/deobfuscated strings ({len(decoded)} found):")
for s in decoded[:20]:
    val = s.get("string", "")
    if len(val) > 4:
        print(f"  {val}")

PYEOF
```

**Expected FLOSS findings (representative C2 dropper output):**
```
Stack-constructed strings (14 found):
  updates.cdn-telemetry-svc.net    ← C2 domain — CRITICAL
  /stage2                           ← Stage 2 URL path
  SCM_EventLog_Consumer             ← WMI consumer name
  OneDriveStandaloneUpdater         ← Registry Run key name
  C:\Users\Public\Libraries\        ← Dropper install path

Decoded/deobfuscated strings (8 found):
  IEX(New-Object Net.WebClient)     ← PowerShell download cradle
  -WindowStyle Hidden               ← Execution flag
  185.220.101.33                    ← C2 IP — CRITICAL
  powershell.exe                    ← Spawned process
```

**✅ Checkpoint 2:** The FLOSS-recovered strings are the most valuable static
finding — they confirm the C2 infrastructure linkage (Day 04) and persistence
mechanism naming (Day 06) directly from the binary.

---

## STEP 3 — PE Header Analysis

**Objective:** Examine the PE (Portable Executable) file structure — sections,
imports, exports, compilation timestamp, and entropy. High entropy sections
indicate packed or encrypted code.

```python
# Save as: pe_analysis.py
import pefile
import math
import json
from datetime import datetime, timezone

SAMPLE = "updater.exe"

def section_entropy(data):
    """Calculate Shannon entropy for a byte sequence."""
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    return -sum((count/length) * math.log2(count/length)
                for count in freq.values())

print("=" * 60)
print("  PE Header Analysis — updater.exe")
print("=" * 60)

pe = pefile.PE(SAMPLE)

# Basic file information
print(f"\n=== File Properties ===")
print(f"  Machine:       {hex(pe.FILE_HEADER.Machine)} "
      f"({'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'})")
print(f"  Compiled:      {datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc)}")
print(f"  Subsystem:     {pe.OPTIONAL_HEADER.Subsystem} "
      f"({'Console' if pe.OPTIONAL_HEADER.Subsystem == 3 else 'GUI/Other'})")
print(f"  Entry Point:   {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
print(f"  Image Base:    {hex(pe.OPTIONAL_HEADER.ImageBase)}")

# Check for ASLR, DEP, CFG
characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
print(f"\n=== Security Features ===")
print(f"  ASLR (DYNAMICBASE):  {'YES' if characteristics & 0x0040 else 'NO'}")
print(f"  DEP (NX Compat):     {'YES' if characteristics & 0x0100 else 'NO'}")
print(f"  CFG:                 {'YES' if characteristics & 0x4000 else 'NO'}")
print(f"  Code Integrity:      {'YES' if characteristics & 0x0080 else 'NO'}")

# Section analysis with entropy
print(f"\n=== PE Sections (Entropy Analysis) ===")
print(f"  {'Section':<12} {'VirtSize':>10} {'RawSize':>10} {'Entropy':>8}  Verdict")
print("  " + "─" * 52)

sections_data = []
for section in pe.sections:
    name    = section.Name.decode(errors="replace").rstrip("\x00")
    vsize   = section.Misc_VirtualSize
    rsize   = section.SizeOfRawData
    data    = section.get_data()
    entropy = section_entropy(data)

    # Entropy interpretation
    if entropy > 7.2:
        verdict = "⚠ PACKED/ENCRYPTED — high entropy"
    elif entropy > 6.5:
        verdict = "~ Possibly compressed"
    elif entropy < 1.0:
        verdict = "~ Zeroed / empty section"
    else:
        verdict = "✓ Normal"

    print(f"  {name:<12} {vsize:>10,} {rsize:>10,} {entropy:>8.4f}  {verdict}")
    sections_data.append({"name":name,"vsize":vsize,"rsize":rsize,
                           "entropy":round(entropy,4),"verdict":verdict})

# Import analysis — key suspicious imports
print(f"\n=== Suspicious Imports (DLL → Function) ===")
SUSPICIOUS_IMPORTS = {
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
    "CreateRemoteThread", "OpenProcess", "ReadProcessMemory",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "SetWindowsHookEx", "GetAsyncKeyState", "GetForegroundWindow",
    "CryptEncrypt", "CryptDecrypt", "CryptHashData",
    "URLDownloadToFile", "InternetOpen", "InternetConnect",
    "WinExec", "ShellExecute", "CreateProcess",
}

found_suspicious = []
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="replace")
        for imp in entry.imports:
            if imp.name:
                func = imp.name.decode(errors="replace")
                if func in SUSPICIOUS_IMPORTS:
                    print(f"  {dll} → {func}")
                    found_suspicious.append({"dll":dll,"function":func})

if not found_suspicious:
    print("  [!] No direct suspicious imports found")
    print("  [!] May be using dynamic import resolution (GetProcAddress)")
    print("  [!] Check FLOSS output for API name strings")

# Save full analysis
analysis = {
    "compiled":  str(datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc)),
    "machine":   hex(pe.FILE_HEADER.Machine),
    "sections":  sections_data,
    "suspicious_imports": found_suspicious,
}
with open("artifacts/static/pe_analysis.json", "w") as f:
    json.dump(analysis, f, indent=2)

print(f"\n[+] PE analysis saved: artifacts/static/pe_analysis.json")
pe.close()
```

```bash
python3 pe_analysis.py | tee artifacts/static/pe_analysis_summary.txt
```

**✅ Checkpoint 3:** Entropy above 7.2 in the `.text` or `.data` section is a
strong packing indicator. `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread`
in the same binary = process injection capability. Document both findings.

---

## STEP 4 — Dynamic Analysis: Sandbox Detonation

**Objective:** Observe actual malware behavior in a controlled environment.
Sandbox analysis confirms or expands upon static findings and captures
network traffic, registry changes, file operations, and process activity.

### 4a. Any.run Interactive Sandbox Submission

```bash
echo "[*] Preparing Any.run sandbox submission..."
echo ""
echo "Manual Steps:"
echo "  1. Open: https://app.any.run"
echo "  2. Click 'New Task' → Upload File → select updater.exe"
echo "  3. Settings:"
echo "     OS:          Windows 10 64-bit"
echo "     Network:     Enabled (capture all traffic)"
echo "     Timeout:     120 seconds"
echo "     Interaction: Automated (allow file to run)"
echo "  4. Start analysis and wait for completion"
echo "  5. Download: PCAP, report JSON, process tree screenshot"
echo ""
echo "  After completion, save the task URL and download:"
echo "    - Process tree screenshot → artifacts/dynamic/"
echo "    - PCAP file → artifacts/dynamic/sandbox_traffic.pcap"
echo "    - IOC summary → artifacts/dynamic/anyrun_iocs.txt"
```

### 4b. Parse Sandbox Results

```python
# Save as: parse_sandbox_results.py
# Processes Any.run JSON report output
import json

# Template structure — populate with actual Any.run JSON export
SANDBOX_FINDINGS = {
    "analysis_metadata": {
        "sandbox":    "Any.run",
        "os":         "Windows 10 x64",
        "duration":   "120 seconds",
        "verdict":    "MALICIOUS",
        "threat_level": 5,
    },
    "process_tree": [
        {
            "pid":     4412,
            "name":   "updater.exe",
            "cmd":    "C:\\Users\\Public\\Libraries\\updater.exe",
            "parent": "explorer.exe",
            "children": [
                {
                    "pid":  5120,
                    "name": "powershell.exe",
                    "cmd":  "powershell.exe -WindowStyle Hidden "
                            "-EncodedCommand SQBFAFgA...",
                    "note": "Stage 2 download cradle",
                },
                {
                    "pid":  5244,
                    "name": "svchost.exe (injected)",
                    "cmd":  "C:\\Windows\\System32\\svchost.exe",
                    "note": "Process injection target — hollowed",
                },
            ]
        }
    ],
    "network_activity": [
        {"protocol":"DNS",   "query":"updates.cdn-telemetry-svc.net",
         "response":"185.220.101.33","timestamp":"T+0:12s"},
        {"protocol":"HTTPS", "dest":"185.220.101.33:443",
         "bytes_out":312,"bytes_in":48210,"timestamp":"T+0:15s",
         "note":"Stage 2 payload download — 47KB"},
        {"protocol":"DNS",   "query":"updates.cdn-telemetry-svc.net",
         "response":"185.220.101.33","timestamp":"T+1:12s",
         "note":"Second beacon — confirms 60s interval"},
    ],
    "registry_operations": [
        {"op":"SET",
         "key":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
         "value":"OneDriveStandaloneUpdater",
         "data":"C:\\Users\\Public\\Libraries\\updater.exe",
         "timestamp":"T+0:08s"},
    ],
    "file_operations": [
        {"op":"CREATE", "path":"C:\\Users\\Public\\Libraries\\updater.exe",
         "timestamp":"T+0:01s","note":"Self-copy to persistence location"},
        {"op":"DROP",   "path":"C:\\Windows\\Temp\\~tmp4891.dll",
         "timestamp":"T+0:11s","note":"Injected DLL — deleted after injection"},
    ],
    "api_calls_notable": [
        "VirtualAlloc        → allocate memory for injection payload",
        "WriteProcessMemory  → write shellcode to svchost.exe",
        "CreateRemoteThread  → execute injected code in svchost",
        "OpenProcess(svchost)→ open handle to injection target",
        "MiniDumpWriteDump   → LSASS credential dump attempt",
    ],
}

print("=" * 60)
print("  Sandbox Analysis Results — updater.exe")
print("=" * 60)

meta = SANDBOX_FINDINGS["analysis_metadata"]
print(f"\n  Sandbox:     {meta['sandbox']}")
print(f"  OS:          {meta['os']}")
print(f"  Verdict:     {meta['verdict']} (threat level {meta['threat_level']}/5)")

print(f"\n=== Process Tree ===")
for proc in SANDBOX_FINDINGS["process_tree"]:
    print(f"  PID {proc['pid']}: {proc['name']}")
    print(f"    CMD: {proc['cmd'][:70]}")
    for child in proc.get("children", []):
        print(f"    └─ PID {child['pid']}: {child['name']}")
        print(f"         {child['cmd'][:60]}")
        print(f"         Note: {child['note']}")

print(f"\n=== Network Activity ===")
for net in SANDBOX_FINDINGS["network_activity"]:
    print(f"  [{net['timestamp']}] {net['protocol']}: "
          f"{net.get('query', net.get('dest',''))}")
    if "note" in net:
        print(f"    Note: {net['note']}")

print(f"\n=== Registry Operations ===")
for reg in SANDBOX_FINDINGS["registry_operations"]:
    print(f"  [{reg['timestamp']}] {reg['op']}: {reg['key']}")
    print(f"    Value: {reg['value']} = {reg['data']}")

print(f"\n=== Notable API Calls ===")
for api in SANDBOX_FINDINGS["api_calls_notable"]:
    print(f"  {api}")

# Save results
with open("artifacts/dynamic/sandbox_analysis.json", "w") as f:
    json.dump(SANDBOX_FINDINGS, f, indent=2)

print(f"\n[+] Sandbox analysis saved: artifacts/dynamic/sandbox_analysis.json")
```

```bash
python3 parse_sandbox_results.py | tee artifacts/dynamic/sandbox_summary.txt
```

**✅ Checkpoint 4:** `MiniDumpWriteDump` in the API calls means the malware
attempted to access LSASS memory to steal credentials — this escalates the
incident severity. Any credentials cached on DESKTOP-FIN-047 should be
treated as compromised, including domain credentials.

---

## STEP 5 — IOC Extraction

**Objective:** Compile every indicator extracted from both static and dynamic
analysis into a structured, shareable IOC package.

```python
# Save as: extract_iocs.py
import re, json, hashlib

print("=" * 60)
print("  IOC Extraction — updater.exe")
print("=" * 60)

# Load all artifact data
strings_content = open("artifacts/static/strings_all.txt",
                        errors="replace").read()

IOCS = {
    "file_hashes": {
        "md5":    "d41d8cd98f00b204e9800998ecf8427e",  # replace with real
        "sha1":   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ssdeep": "24576:abc123def456:ghijklm",
    },
    "network_iocs": {
        "domains": [
            "updates.cdn-telemetry-svc.net",
            "cdn-telemetry-svc.net",
        ],
        "ips": [
            "185.220.101.33",
        ],
        "urls": [
            "hxxps://185.220.101.33/stage2",
            "hxxps://updates.cdn-telemetry-svc[.]net/beacon",
        ],
        "dns_pattern": "Base64-encoded labels in TXT queries to cdn-telemetry-svc.net",
        "beacon_interval": "60.3 seconds ± 0.1s",
    },
    "host_iocs": {
        "file_paths": [
            "C:\\Users\\Public\\Libraries\\updater.exe",
            "C:\\Windows\\Temp\\~tmp4891.dll",
        ],
        "registry_keys": [
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveStandaloneUpdater",
        ],
        "scheduled_tasks": [
            "MicrosoftEdgeUpdateTaskMachineCore",
        ],
        "wmi_artifacts": [
            "SCM_EventLog_Filter (root\\subscription)",
            "SCM_EventLog_Consumer (CommandLineEventConsumer)",
        ],
        "process_artifacts": [
            "updater.exe → powershell.exe (encoded cmd, hidden window)",
            "updater.exe → svchost.exe (process hollowing target)",
        ],
        "mutex": "Global\\{4A8C3B91-2E7F-4D15-88AC-9B7E3C1D0F22}",
    },
    "behavioral_iocs": {
        "lsass_access":        True,
        "process_injection":   "svchost.exe (PID 5244)",
        "dll_injection":       "~tmp4891.dll (deleted post-injection)",
        "powershell_execution":"Encoded command, hidden window",
        "stage2_download":     "47KB payload from C2",
    },
}

# Print structured IOC report
for category, data in IOCS.items():
    print(f"\n=== {category.replace('_',' ').upper()} ===")
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, list):
                print(f"  {k}:")
                for item in v:
                    print(f"    • {item}")
            else:
                print(f"  {k}: {v}")

# Save as JSON
with open("artifacts/iocs/ioc_updater_exe.json", "w") as f:
    json.dump(IOCS, f, indent=2)

# Save defanged plain text version
with open("artifacts/iocs/ioc_updater_exe.txt", "w") as f:
    f.write("# IOC List — updater.exe Malware Analysis\n")
    f.write("# Analyst: Blaakpearl | Date: 2025-01-17\n")
    f.write("# TLP: AMBER\n\n")
    f.write("## Network IOCs\n")
    for d in IOCS["network_iocs"]["domains"]:
        f.write(f"{d.replace('.net','[.]net').replace('.com','[.]com')}\n")
    for ip in IOCS["network_iocs"]["ips"]:
        f.write(f"{ip}\n")
    f.write("\n## Host IOCs\n")
    for path in IOCS["host_iocs"]["file_paths"]:
        f.write(f"{path}\n")
    for reg in IOCS["host_iocs"]["registry_keys"]:
        f.write(f"{reg}\n")

print(f"\n[+] IOC files saved:")
print(f"    artifacts/iocs/ioc_updater_exe.json")
print(f"    artifacts/iocs/ioc_updater_exe.txt")
```

```bash
python3 extract_iocs.py | tee artifacts/iocs/ioc_extraction_summary.txt
```

---

## STEP 6 — YARA Rule Development

**Objective:** Write a YARA rule that uniquely identifies this malware sample
and its variants. The rule will be deployed to EDR, email security, and threat
intel platforms for proactive detection.

```bash
cat > artifacts/yara/updater_exe_detection.yar << 'YARAEOF'
/*
    YARA Detection Rules — updater.exe C2 Dropper
    Analyst:   Blaakpearl
    Date:      2025-01-17
    Case:      NVC-IR-2025-004 | Day 08 — Malware Triage
    TLP:       AMBER

    Sample: updater.exe (SHA-256: e3b0c44298fc1c1...)
    Family: Custom C2 dropper — DNS beacon, process injection, LSASS access
    ATT&CK: T1055, T1027, T1003.001, T1071.004, T1547.001
*/

rule NovaCrest_Dropper_updater_exe_Exact {
    meta:
        description = "Exact hash match — updater.exe C2 dropper (NVC-IR-2025-004)"
        author      = "Blaakpearl"
        date        = "2025-01-17"
        hash_md5    = "d41d8cd98f00b204e9800998ecf8427e"
        hash_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        tlp         = "AMBER"
        mitre       = "T1055, T1027, T1003.001, T1071.004"
        confidence  = "HIGH — exact hash match"

    condition:
        hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e"
}

rule NovaCrest_Dropper_updater_exe_Behavioral {
    meta:
        description = "Behavioral signature — DNS C2 dropper with process injection"
        author      = "Blaakpearl"
        date        = "2025-01-17"
        tlp         = "AMBER"
        mitre       = "T1055, T1071.004, T1547.001, T1003.001"
        confidence  = "HIGH — unique string combination"

    strings:
        /* C2 beacon domain — unique to this campaign */
        $c2_domain      = "cdn-telemetry-svc.net" ascii wide nocase

        /* WMI persistence artifact names */
        $wmi_filter     = "SCM_EventLog_Filter" ascii wide
        $wmi_consumer   = "SCM_EventLog_Consumer" ascii wide

        /* Registry persistence key name */
        $reg_key        = "OneDriveStandaloneUpdater" ascii wide

        /* PowerShell execution pattern */
        $ps_hidden      = "-WindowStyle Hidden" ascii wide nocase
        $ps_encoded     = "-EncodedCommand" ascii wide nocase

        /* Process injection target */
        $inject_target  = "svchost.exe" ascii wide nocase

        /* LSASS access string */
        $lsass_str      = "lsass" ascii wide nocase

        /* Stage 2 download path */
        $stage2_path    = "/stage2" ascii

        /* Install path */
        $install_path   = "\\Users\\Public\\Libraries\\" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D              /* MZ header — valid PE file */
        and filesize < 2MB               /* Sample is 847KB */
        and (
            /* C2 infrastructure match */
            ($c2_domain and $stage2_path) or

            /* WMI persistence artifacts */
            ($wmi_filter and $wmi_consumer) or

            /* Registry + PowerShell combination */
            ($reg_key and ($ps_hidden or $ps_encoded)) or

            /* LSASS + injection combination */
            ($lsass_str and $inject_target and $install_path)
        )
}

rule NovaCrest_DNS_C2_Beacon_Pattern {
    meta:
        description = "Detects DNS C2 beaconing binary — interval timer pattern"
        author      = "Blaakpearl"
        date        = "2025-01-17"
        tlp         = "AMBER"
        confidence  = "MEDIUM — pattern may have false positives"

    strings:
        /* DNS query construction pattern common to this family */
        $dns_api_1  = "DnsQuery" ascii
        $dns_api_2  = "DnsQueryEx" ascii
        $dns_txt    = "DNS_TYPE_TEXT" ascii

        /* Sleep/timer API for beacon interval */
        $sleep      = "Sleep" ascii
        $timer      = "CreateWaitableTimer" ascii

        /* Base64 alphabet — DNS label encoding */
        $b64_chars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii

    condition:
        uint16(0) == 0x5A4D
        and ($dns_api_1 or $dns_api_2 or $dns_txt)
        and ($sleep or $timer)
        and $b64_chars
}
YARAEOF

echo "[+] YARA rules written: artifacts/yara/updater_exe_detection.yar"
echo ""
echo "[*] Validating YARA syntax..."
yara -d artifacts/yara/updater_exe_detection.yar /dev/null 2>&1 | \
    grep -v "^$" || echo "[+] Syntax valid"

echo ""
echo "[*] Testing rules against sample..."
yara artifacts/yara/updater_exe_detection.yar "$SAMPLE" 2>/dev/null || \
    echo "[!] Sample not found at $SAMPLE — run against real sample when available"
```

---

## STEP 7 — Malware Family Classification

```python
# Save as: classify_malware.py
# Attempts to classify the sample based on behavioral indicators

BEHAVIORS = {
    "dns_c2_beaconing":     True,
    "process_injection":    True,
    "process_hollowing":    True,
    "lsass_credential_dump":True,
    "wmi_persistence":      True,
    "registry_persistence": True,
    "staged_payload":       True,
    "antivirus_evasion":    True,
    "powershell_execution": True,
    "encoded_commands":     True,
}

# Score against known malware family profiles
FAMILY_PROFILES = {
    "Cobalt Strike Beacon": {
        "dns_c2_beaconing":     1.0,
        "process_injection":    1.0,
        "process_hollowing":    1.0,
        "lsass_credential_dump":1.0,
        "staged_payload":       1.0,
        "encoded_commands":     0.8,
    },
    "Sliver C2": {
        "dns_c2_beaconing":     1.0,
        "process_injection":    0.9,
        "wmi_persistence":      0.8,
        "staged_payload":       1.0,
        "antivirus_evasion":    0.9,
    },
    "Metasploit Meterpreter": {
        "process_injection":    1.0,
        "staged_payload":       1.0,
        "lsass_credential_dump":0.9,
        "registry_persistence": 0.7,
    },
    "Custom Loader (Bespoke)": {
        "dns_c2_beaconing":     0.9,
        "wmi_persistence":      0.9,
        "registry_persistence": 0.9,
        "antivirus_evasion":    1.0,
        "encoded_commands":     0.8,
    },
}

print("=" * 60)
print("  Malware Family Classification")
print("=" * 60)
print(f"\n  Behaviors confirmed: {sum(BEHAVIORS.values())}/{len(BEHAVIORS)}")

scores = {}
for family, profile in FAMILY_PROFILES.items():
    match_score = sum(
        profile.get(b, 0) for b, present in BEHAVIORS.items() if present
    )
    max_score   = sum(profile.values())
    pct         = (match_score / max_score * 100) if max_score else 0
    scores[family] = round(pct, 1)

scores_sorted = sorted(scores.items(), key=lambda x: x[1], reverse=True)

print(f"\n  Family Match Scores:")
for family, score in scores_sorted:
    bar   = "█" * int(score / 5)
    print(f"  {family:<30} {score:>5.1f}%  {bar}")

top_family, top_score = scores_sorted[0]
if top_score >= 85:
    confidence = "HIGH"
elif top_score >= 65:
    confidence = "MEDIUM"
else:
    confidence = "LOW"

print(f"\n  Classification Result:")
print(f"    Best match:  {top_family}")
print(f"    Score:       {top_score}%")
print(f"    Confidence:  {confidence}")

if "Custom" in top_family or top_score < 70:
    print(f"\n  [!] Low match score or bespoke classification suggests:")
    print(f"    • Custom-developed tool (not public framework)")
    print(f"    • Modified open-source framework")
    print(f"    • Novel or rare malware family")
    print(f"    Recommendation: Submit to sandbox sharing platforms")
    print(f"    (VirusTotal, MalwareBazaar) for broader community analysis")

import json
with open("artifacts/static/malware_classification.json", "w") as f:
    json.dump({"behaviors": BEHAVIORS, "scores": dict(scores_sorted),
               "top_match": top_family, "confidence": confidence}, f, indent=2)
print(f"\n[+] Classification saved: artifacts/static/malware_classification.json")
```

```bash
python3 classify_malware.py | tee artifacts/static/classification_summary.txt
```

---

## 🚩 Capture the Flag Checkpoints

- [ ] 🚩 **Flag 1:** What API call in the sandbox output indicates credential theft from LSASS?
- [ ] 🚩 **Flag 2:** What entropy value threshold indicates a packed PE section?
- [ ] 🚩 **Flag 3:** What FLOSS-recovered string connects this binary to the Day 04 C2 infrastructure?
- [ ] 🚩 **Flag 4:** What MITRE technique covers process hollowing into svchost.exe?
- [ ] 🚩 **Flag 5:** What makes a 0/72 VirusTotal detection significant from a threat intelligence perspective?

---

## 📁 Artifacts to Commit

| File | Contents |
|------|---------|
| `static/file_hashes.txt` | MD5, SHA-1, SHA-256, ssdeep |
| `static/vt_results.json` | VirusTotal API response |
| `static/vt_lookup.txt` | VT lookup console output |
| `static/strings_ascii.txt` | ASCII strings extraction |
| `static/strings_unicode.txt` | Unicode strings extraction |
| `static/strings_all.txt` | Combined deduplicated strings |
| `static/floss_output.json` | FLOSS deobfuscated strings |
| `static/pe_analysis.json` | PE header analysis structured output |
| `static/pe_analysis_summary.txt` | PE analysis console output |
| `static/malware_classification.json` | Family classification scores |
| `static/classification_summary.txt` | Classification console output |
| `dynamic/sandbox_analysis.json` | Structured sandbox findings |
| `dynamic/sandbox_summary.txt` | Sandbox console output |
| `dynamic/sandbox_traffic.pcap` | Network capture from sandbox |
| `iocs/ioc_updater_exe.json` | Structured IOC package |
| `iocs/ioc_updater_exe.txt` | Plain text defanged IOCs |
| `iocs/ioc_extraction_summary.txt` | IOC extraction console output |
| `yara/updater_exe_detection.yar` | Three YARA detection rules |

---

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| `floss` not found | `pip install flare-floss --break-system-packages` |
| `pefile` import error | `pip install pefile --break-system-packages` |
| YARA syntax error | Run `yara --syntax-only rule.yar` to validate |
| Any.run timeout | Extend to 180 seconds; some malware sleeps before beaconing |
| Sample not available | Use MalwareBazaar: `bazaar.abuse.ch/browse/` — search by tag "beacon" |

---

*Next: [REPORT.md](REPORT.md) — Professional malware analysis report*
