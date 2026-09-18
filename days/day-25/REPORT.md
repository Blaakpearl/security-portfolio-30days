# Day 25 — REPORT.md
## Digital Forensics: Ransomware Incident Analysis
**NovaCrest Capital Group | Case NCA-2026-06-R**
**Track:** Digital Forensics
**Author:** V. Willis, CISSP
**Date:** 2026-06-25

---

## Summary

| Metric | Value |
|--------|-------|
| Ransomware family | LockBit 3.0 builder variant (ncrypt strain) |
| Files encrypted | 26,168 across 3 file shares |
| Data volume encrypted | 2,215 GB |
| Ransom demand | $4.2M USD (Monero, XMR) |
| Encryption window | 2 hours 48 minutes (03:24–06:12 UTC, June 19) |
| Detection time | 06:14 UTC — after encryption complete |
| Persistence found | Windows service + IFEO debugger hijack (both active) |
| Recovery option | Restore from June 13 backup (pre-compromise) |
| Pay ransom? | NOT recommended — OFAC risk + backup viable |
| FBI report | Required for Operation Cronos decryptor check |

---

## Key Forensic Findings

**1. Ransomware binary compiled June 15 — 1 day after initial access.**
The attacker staged access on June 14, spent 5 days exfiltrating data,
then built a custom victim-specific binary and deployed it. This is textbook
double-extortion: steal first, then encrypt for maximum leverage.

**2. 44 seconds to destroy all recovery options.**
Between AV stop and encryption start, the attacker deleted shadow copies,
Windows Backup catalog, and disabled recovery mode — in 44 seconds. All
these commands were logged in Sysmon, but no alert fired.

**3. Persistence remains active.**
The NovaCrypt service and IFEO debugger hijack were not removed during initial
response. Both must be deleted before SRV-FS-01 is reconnected to the network.

**4. Same C2 IP as initial access (198.51.100.99).**
Conclusively links the ransomware operator to the June 14 intrusion. One threat
actor, one continuous operation from phishing email to encryption.

**5. June 13 backup is clean.**
The backup predates the June 14 initial compromise by one day. Restoration
is viable. Estimated time: 2–3 days for 2.2 TB.

---

## The Full Incident Arc (Days 15–25)

```
Day 15   External reconnaissance (FinTech Summit photo → spearphish lure)
Day 16   Initial access (phishing email → macro → Sliver implant)
Day 17   Privilege escalation (token impersonation → UAC bypass → SYSTEM)
Day 18   Data exfiltration (125 MB HTTPS + 85 MB S3 = ~210 MB)
Day 19   Attacker clears logs (649 Security events destroyed)
Day 20   C2 established (Cobalt Strike via domain fronting)
Day 21   Lateral movement (PtT SRV-AD-01 → WMI SRV-FS-01)
Day 22   Risk scoring (RF-001 through RF-010 documented)
Day 23   Mobile OSINT (iPhone MDM, EXIF GPS trail)
Day 24   Cloud hunt (IAM backdoor found; 82 MB S3 exfil; GD disabled)
Day 25   RANSOMWARE (2,215 GB encrypted; $4.2M demand; backups viable)

Total confirmed exfil: ~293 MB
Total encrypted: 2,215 GB
Total dwell time: 5 days (June 14 → June 19)
Total regulatory exposure: SEC S-P + SEC SCI + NY DFS + FBI ransomware reporting
```

---

## Git Commit

```bash
cd security-portfolio-30days
git checkout main && git pull origin main

mkdir -p days/day-25/{scripts,queries,reports,artifacts}
cp -r /path/to/outputs/day25/* days/day-25/

git add days/day-25/

git commit -m "feat: Add Day 25 — Ransomware Forensics (Autopsy, FTK, Volatility3)

Track: Digital Forensics | Tools: Autopsy, FTK Imager, Volatility3, YARA, Ghidra
MITRE ATT&CK: T1486, T1490, T1489, T1562.001, T1070.004, T1543.003, T1055.002

Case: NCA-2026-06-R | SRV-FS-01 ransomware incident (June 19, 2026)
Strain: LockBit 3.0 builder variant (.ncrypt extension)
Scope: 26,168 files | 2,215 GB | 3 shares | $4.2M ransom demand

Key findings:
  - Binary compiled June 15 (1 day post-initial-access) — custom victim build
  - 44 seconds to destroy all VSS/backup recovery options
  - 2h 48min encryption window — undetected until complete
  - C2 IP 198.51.100.99 = same as Day 15-21 intrusion (same actor)
  - Persistence: NovaCrypt service + IFEO debugger hijack (still active)
  - Recovery: June 13 backup viable; FBI Cronos decryptor check recommended
  - Memory forensics: PE extracted from PID 3412; bcrypt+ncrypt DLLs confirm AES+RSA

Deliverables:
  SCENARIO.md, LAB.md, REPORT.md
  scripts/ransomware_analyzer.py  (IOC extractor + scope + timeline + recovery)
  scripts/memory_forensics.py     (Volatility3 pslist, malfind, netstat, dlls)
  queries/ransomware_hunt.spl     (VSS deletion, mass rename, ransom note, timeline)
  queries/ransomware_hunt.kql     (Sentinel KQL — detection + scope + prevention)
  reports/day25_ransomware_report.md (full forensic report + malware analysis)
  artifacts/yara_rules.yar        (7 YARA rules: note, binary, VSS, LockBit3, mutex)"

git push origin main
```

---

*Day 25 — Ransomware Forensics | NovaCrest Capital Group*
*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*
