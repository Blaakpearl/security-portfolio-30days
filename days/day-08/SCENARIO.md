# Day 08 — Malware Triage
### Track: Digital Forensics | Difficulty: Intermediate | Phase: Discovery / Analysis

---

## 🎯 Threat Brief

The forensic imaging of DESKTOP-FIN-047 is underway. During the imaging process,
the forensic examiner flags a suspicious executable discovered in an unusual
location: `C:\Users\Public\Libraries\updater.exe` — the same path referenced
in the Registry Run key discovered during the Day 06 purple team exercise.

This is not a known Windows binary. It is not signed. It was created on
January 14, 2025 — the same day the phishing click occurred. Its size is
847KB. The file has never been submitted to VirusTotal. Your antivirus
missed it entirely.

You have a binary of unknown origin sitting on a compromised endpoint that
has been beaconing to attacker infrastructure for 11 days. Before the
endpoint is wiped and rebuilt, you need to understand exactly what this
file does: how does it establish the C2 channel? Does it have a keylogger?
Does it access credentials? Does it have additional stages? Are there
other infected hosts in the environment?

**This is a malware analysis problem. The goal is not to run the malware —
it is to understand it through controlled analysis, extract every indicator
it contains, and produce a threat intelligence product that protects the
rest of the organization.**

---

## 🔬 The Malware Analyst's Methodology

```
┌───────────────────────────────────────────────────────────────────┐
│  PHASE 1 — STATIC ANALYSIS (no execution)                         │
│    • File metadata: size, timestamps, entropy, format             │
│    • String extraction: URLs, paths, registry keys, API calls     │
│    • PE header analysis: sections, imports, exports, resources     │
│    • Hash generation: MD5, SHA-1, SHA-256 for threat intel lookup │
│    • YARA rule development from unique byte patterns              │
│                                                                   │
│  PHASE 2 — DYNAMIC ANALYSIS (controlled execution)               │
│    • Sandbox detonation: automated behavioral analysis            │
│    • Network captures: C2 communication patterns                  │
│    • Registry monitoring: persistence mechanism creation          │
│    • Process tree: child process creation and injection           │
│    • API call monitoring: credential access, file operations      │
│                                                                   │
│  PHASE 3 — INTELLIGENCE EXTRACTION                                │
│    • IOC extraction: all network and host indicators              │
│    • Family classification: match to known malware families        │
│    • YARA rule finalization: detection signatures for deployment  │
│    • ATT&CK mapping: techniques confirmed by behavioral analysis  │
│    • Threat intel report: shareable findings in standard format   │
└───────────────────────────────────────────────────────────────────┘
```

---

## 🏢 Incident Context

```
File path:      C:\Users\Public\Libraries\updater.exe
File size:      847,360 bytes (827 KB)
Created:        2025-01-14 09:12:44 UTC  (53 min after phishing click)
Modified:       2025-01-14 09:12:44 UTC
Accessed:       2025-01-16 03:30:00 UTC  (last access before isolation)
File type:      PE32+ executable (console) x86-64, Windows
Signed:         No — no Authenticode signature
AV detection:   0/72 engines on VirusTotal (never submitted before)
Source:         Delivered via phishing drive-by — Day 03 reverse proxy kit
Associated:     Registry Run key (Day 06), C2 beacon (Day 04)
```

---

## ⚠️ Analysis Challenges

- **Never-before-seen sample:** Zero VirusTotal detections means no existing
  threat intelligence to lean on. Analysis must be conducted from scratch.
- **Anti-analysis techniques:** Sophisticated malware detects sandbox environments
  and changes behaviour. We must account for evasion in our analysis.
- **Packed/obfuscated code:** High entropy sections suggest packing — the visible
  strings may be a fraction of what the binary actually contains at runtime.
- **Multi-stage architecture:** The binary may only be a loader — actual
  malicious functionality may download from C2 at runtime, making static
  analysis reveal only the delivery mechanism.

---

## 📚 Learning Objectives

1. Generate cryptographic hashes and check against threat intelligence feeds
2. Use `strings`, `floss`, and `pecheck` for static string and PE analysis
3. Analyse PE sections for entropy anomalies indicating packing or encryption
4. Submit to Any.run interactive sandbox and interpret behavioral results
5. Extract network IOCs from sandbox PCAP output
6. Write a YARA rule targeting unique characteristics of the sample
7. Map confirmed behaviors to MITRE ATT&CK techniques
8. Produce a malware analysis report with IOC list and family classification

---

## ✅ Success Criteria

- [ ] File hashes generated (MD5, SHA-1, SHA-256) and VirusTotal checked
- [ ] String extraction completed — URLs, registry keys, API names identified
- [ ] PE section entropy analysis — packed sections identified
- [ ] Sandbox detonation completed — process tree and network captured
- [ ] At least 3 network IOCs extracted from dynamic analysis
- [ ] YARA rule written with at least 3 unique string conditions
- [ ] Malware family classification attempted with confidence level
- [ ] Full ATT&CK technique mapping from behavioral analysis

---

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| **T1059.001** | PowerShell | Execution | Dropper spawns PowerShell |
| **T1055** | Process Injection | Defense Evasion | Injects into svchost.exe |
| **T1027** | Obfuscated Files/Info | Defense Evasion | Packed PE — UPX variant |
| **T1140** | Deobfuscate/Decode Files | Defense Evasion | Runtime unpacking |
| **T1082** | System Information Discovery | Discovery | OS/hardware fingerprint |
| **T1016** | System Network Config Discovery | Discovery | IP/adapter enumeration |
| **T1003.001** | OS Credential Dumping: LSASS | Credential Access | LSASS memory access |
| **T1547.001** | Registry Run Keys | Persistence | Run key already confirmed |
| **T1071.004** | DNS C2 | Command & Control | DNS beacon confirmed |
| **T1132.001** | Data Encoding: Standard | C2 | Base64 in DNS labels |

---

*Next: [LAB.md](LAB.md) — Step-by-step malware triage lab guide*
