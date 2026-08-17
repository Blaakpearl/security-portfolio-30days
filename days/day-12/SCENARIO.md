# Day 12 — Memory Forensics
### Track: Digital Forensics | Difficulty: Advanced | Phase: Deep Forensic Analysis

---

## 🎯 Threat Brief

It is Day 18 of the NovaCrest Capital Group incident. When DESKTOP-FIN-047
was isolated on January 16, the forensic team made a critical decision that
is now paying dividends: **before powering down the system, they captured
a full physical memory image.**

Disk forensics tells you what was written to storage. Memory forensics tells
you what was *running* — active processes, network connections at the moment
of capture, injected code that may never touch disk, decrypted strings that
only exist in RAM, and command history that was never logged. Given the
confirmed process hollowing into `svchost.exe` (Day 08) and the LSASS
credential access attempt, the memory image is the single most valuable
piece of forensic evidence in this entire investigation.

**Your mission:** analyze the full memory capture using Volatility3 to
reconstruct the complete process tree at the moment of isolation, confirm
and characterize the process injection, recover network connection state,
and — critically — determine definitively what was extracted from LSASS
and whether any of it can still be recovered for containment purposes.

---

## 🧠 Why Memory Forensics Matters Here

```
┌────────────────────────────────────────────────────────────────────┐
│  WHAT DISK FORENSICS ALREADY TOLD US (Day 08)                       │
│    • updater.exe existed at a known path                            │
│    • Static file properties: hash, size, PE structure               │
│    • What the file WOULD do (via sandbox detonation elsewhere)      │
│                                                                     │
│  WHAT ONLY MEMORY FORENSICS CAN TELL US                             │
│    • What was ACTUALLY running at the moment of isolation            │
│    • The exact injected shellcode inside svchost.exe's memory space │
│    • Active network connections and their exact state                │
│    • Decrypted/deobfuscated strings only present at runtime          │
│    • Whether the LSASS access actually succeeded and what was taken │
│    • Command history and clipboard contents                          │
│    • Encryption keys or session tokens held only in RAM              │
└────────────────────────────────────────────────────────────────────┘
```

---

## 🏢 Evidence Context

```
Image type:      Full physical memory capture (RAM dump)
Capture method:  WinPmem — captured before shutdown per IR procedure
Capture time:    2025-01-16 03:35:00 UTC (5 minutes after network isolation)
Image size:      16 GB (matches system physical RAM)
Chain of custody: Maintained per NVC-IR-2025-004 evidence log
Hash (SHA-256):  Documented at capture time — verify before analysis
Analysis tool:   Volatility3 (open-source memory forensics framework)
Known findings entering this analysis:
  - updater.exe process (Day 08) — expected PID unknown until analysis
  - svchost.exe injection target (Day 08) — expected hollowed process
  - LSASS access attempt (Day 08) — MiniDumpWriteDump API call observed
  - C2 beacon active (Day 04) — network connections expected in memory
```

---

## 🔬 The Memory Forensics Methodology

```
┌────────────────────────────────────────────────────────────────────┐
│  PHASE 1 — TRIAGE                                                    │
│    • Verify image integrity and OS profile detection                │
│    • Full process listing — pslist, psscan, pstree                   │
│    • Identify anomalous or hidden processes                          │
│                                                                      │
│  PHASE 2 — PROCESS DEEP DIVE                                         │
│    • Examine the injected svchost.exe process specifically           │
│    • Extract and analyze injected memory regions (malfind)           │
│    • Dump process memory for further static analysis                │
│                                                                      │
│  PHASE 3 — NETWORK STATE RECONSTRUCTION                              │
│    • Extract active/historical network connections (netscan)         │
│    • Correlate against known C2 IOCs from Day 04                     │
│                                                                      │
│  PHASE 4 — CREDENTIAL & ARTIFACT RECOVERY                            │
│    • Confirm LSASS access outcome                                    │
│    • Extract command history, clipboard, registry hives from memory  │
│                                                                      │
│  PHASE 5 — TIMELINE INTEGRATION                                      │
│    • Merge memory findings into the master incident timeline         │
└────────────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Analysis Challenges

- **Volatility of evidence:** Memory analysis must be performed on a copy
  of the image; the original must never be mounted or modified
- **Kernel structure versioning:** Volatility3 requires accurate OS profile
  detection — Windows build mismatches produce incomplete or incorrect results
- **Anti-forensic techniques:** Sophisticated malware may attempt to clear
  or corrupt in-memory artifacts before termination
- **Volume of data:** A 16GB memory image contains an enormous amount of
  data; targeted, hypothesis-driven queries are essential

---

## 📚 Learning Objectives

1. Verify memory image integrity and perform OS profile detection with Volatility3
2. Reconstruct the complete process tree and identify anomalous parent-child relationships
3. Use `malfind` to detect and extract injected code from process memory
4. Extract network connection state and correlate against known C2 indicators
5. Confirm LSASS credential access outcomes through memory artifact analysis
6. Recover command history and additional host-based artifacts from memory
7. Integrate memory forensic findings into the master incident timeline

---

## ✅ Success Criteria

- [ ] Memory image OS profile correctly identified
- [ ] Complete process tree reconstructed with all PIDs documented
- [ ] Process hollowing in svchost.exe confirmed via malfind with injected region extracted
- [ ] Network connections extracted and cross-referenced against Day 04 C2 IOCs
- [ ] LSASS access outcome definitively characterized
- [ ] Command history / additional artifacts recovered and documented
- [ ] Master timeline updated with memory-derived findings

---

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| **T1055.012** | Process Hollowing | Defense Evasion | Primary malfind target |
| **T1003.001** | OS Credential Dumping: LSASS Memory | Credential Access | Outcome confirmation |
| **T1071.004** | DNS C2 | Command & Control | Network state correlation |
| **T1057** | Process Discovery | Discovery | Process tree analysis |
| **T1049** | System Network Connections Discovery | Discovery | Netscan analysis |
| **T1027** | Obfuscated Files or Information | Defense Evasion | Injected code characterization |

---

*Next: [LAB.md](LAB.md) — Step-by-step memory forensics lab guide*
