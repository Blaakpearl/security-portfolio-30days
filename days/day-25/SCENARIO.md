# Day 25 — SCENARIO.md
## Digital Forensics: Ransomware Incident Analysis
**NovaCrest Capital Group | Case NCA-2026-06-R**
**Classification:** TLP:AMBER — Forensic Evidence — Attorney-Client Privileged
**Track:** Digital Forensics
**Tools:** Autopsy · FTK Imager · Volatility3 · YARA · Ghidra

---

## Incident Notification

On June 19, 2026 at 06:14 UTC, NovaCrest Capital Group's overnight monitoring
team detected an anomaly on `SRV-FS-01` (the primary file server, Windows
Server 2022). Files in the `\\SRV-FS-01\Finance\` share were displaying
unfamiliar extensions and a ransom note (`!!READ_ME_NOW!!.txt`) had appeared
in every directory. Trading operations were suspended at 06:31 UTC pending
investigation.

The ransomware deployment is believed to be a **second-stage payload** delivered
by the same FIN-NC-001 threat actor who compromised `WS-FIN-04` on June 14
(Case NCA-2026-06). The attacker used the lateral movement path confirmed in
the Day 21 capstone (Pass-the-Ticket to `SRV-AD-01`, then WMI execution to
`SRV-FS-01`) to stage and detonate ransomware **5 days after initial access**,
after data exfiltration was already complete.

This is a **double-extortion** attack: data was stolen first (Days 18/24),
then encrypted to force payment while threatening to publish the stolen data.

---

## Forensic Scope

**Primary forensic target:** `SRV-FS-01` (Windows Server 2022, 10.0.3.20)
- File server: `\\SRV-FS-01\Finance\`, `\\SRV-FS-01\Trading\`, `\\SRV-FS-01\HR\`
- Contains: client financial records, trading archives, HR documents
- Encryption confirmed: `.ncrypt` extension on all encrypted files
- Ransom note: `!!READ_ME_NOW!!.txt` in 847 directories

**Secondary targets:**
- `SRV-AD-01` (10.0.3.10) — used as pivot point; event logs needed
- Memory dump: `SRV-FS-01` RAM captured live at 06:45 UTC (39 GB)
- Network: Zeek logs for June 14–19 (attacker communication channel)

---

## Ransomware Characteristics

**Strain identification (preliminary, based on ransom note and IOCs):**
```
Ransom note filename:  !!READ_ME_NOW!!.txt
Encrypted extension:   .ncrypt
Note language:         English (professional tone; no grammar errors)
Payment demand:        $4.2M USD in Monero (XMR)
Payment deadline:      72 hours from note timestamp
Leak site:             http://ncrypt[.]onion/novacrest  (Tor .onion)
Contact:               ncrypt-support@protonmail.com
Victim ID:             NOVA-20260619-7X4K
```

**Behavioral indicators (from initial triage):**
- Encrypted files retain original filename + `.ncrypt` appended
- Shadow copies deleted (`vssadmin delete shadows /all /quiet`)
- Windows Backup disabled (`wbadmin delete catalog -quiet`)
- Firewall rules added blocking outbound SMB
- Wallpaper changed to ransom note image
- Volume Shadow Copy Service disabled via registry

**Suspected family:** Based on extension, ransom note format, and
double-extortion model — consistent with **LockBit 3.0 variant** or a
LockBit-derived builder kit (LockBit Builder was leaked in 2022, enabling
custom variants). Ghidra analysis of recovered binary required for confirmation.

---

## Forensic Objectives

1. **Establish intrusion timeline** — when did the ransomware binary arrive,
   when was it staged, when did encryption begin?

2. **Recover the ransomware binary** — from disk, memory, or prefetch for
   static + dynamic analysis (YARA matching, Ghidra disassembly)

3. **Determine encryption scope** — which files were encrypted, which were
   missed, can any be recovered?

4. **Confirm lateral movement path** — how did attacker get from WS-FIN-04
   to SRV-FS-01? (Validates Day 21 findings with forensic artifacts)

5. **Identify persistence mechanism** — was there a scheduled task or service
   installed? Is the attacker still present?

6. **Assess recovery options** — are shadow copies truly deleted? Are backups
   clean? Can any files be decrypted without paying?

7. **Document chain of custody** — all evidence handled per forensic standards
   for potential law enforcement referral

---

## MITRE ATT&CK Techniques

| Technique | Name | Evidence Target |
|-----------|------|----------------|
| T1486 | Data Encrypted for Impact | Encrypted files, YARA rule |
| T1490 | Inhibit System Recovery | VSS deletion in event log |
| T1489 | Service Stop | Backup service disabled |
| T1562.001 | Disable Security Tools | Defender disabled pre-encryption |
| T1070.004 | File Deletion (binary cleanup) | Prefetch, MFT artifacts |
| T1543.003 | Windows Service (persistence) | Service registry entries |
| T1021.002 | Lateral Movement via SMB | Event 4648 + Zeek SMB |
| T1055.002 | Process Injection (PE injection) | Volatility3 malfind |
| T1003.001 | LSASS Memory Dump | Prefetch artifacts |
| T1047 | WMI Execution | Event 4688 WmiPrvSE parent |

---

## Evidence Inventory

| ID | Evidence | Source | Hash Status |
|----|---------|--------|-------------|
| EV-001 | SRV-FS-01 disk image (2 TB) | FTK Imager, June 19 07:00 UTC | SHA256 pending |
| EV-002 | SRV-FS-01 memory dump (39 GB) | WinPmem, June 19 06:45 UTC | SHA256 pending |
| EV-003 | SRV-FS-01 Windows Event Logs | Live export, June 19 06:40 UTC | SHA256 pending |
| EV-004 | SRV-AD-01 Windows Event Logs | Live export, June 19 07:15 UTC | SHA256 pending |
| EV-005 | Zeek logs June 14–19 | Network tap export | SHA256 pending |
| EV-006 | Ransom note sample | Collected from FS share | SHA256 pending |
| EV-007 | Encrypted file sample (3) | Collected for crypto analysis | SHA256 pending |
| EV-008 | Prefetch files (SRV-FS-01) | Extracted from disk image | SHA256 pending |

---

## Deliverables

| File | Description |
|------|-------------|
| `SCENARIO.md` | This document |
| `LAB.md` | Autopsy, FTK, Volatility3 lab setup and analysis walkthrough |
| `REPORT.md` | Executive summary and technical findings |
| `scripts/ransomware_analyzer.py` | IOC extractor + encryption scope analyzer |
| `scripts/memory_forensics.py` | Volatility3 ransomware artifact hunter |
| `queries/ransomware_hunt.spl` | Splunk SPL: ransomware detection and timeline |
| `queries/ransomware_hunt.kql` | Sentinel KQL: ransomware artifacts |
| `reports/day25_forensic_timeline.md` | Full forensic timeline (disk + memory + network) |
| `reports/day25_ransomware_report.md` | Technical malware analysis report |
| `artifacts/yara_rules.yar` | YARA rules for ransomware detection |

---

*Day 25 Scenario | Ransomware Forensics*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
