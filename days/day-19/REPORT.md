# Day 19 — REPORT.md
## Digital Forensics: Log Forensics & SIEM Timeline Reconstruction
**NovaCrest Capital Group | Case NCA-2026-06**
**Track:** Digital Forensics
**Author:** V. Willis, CISSP
**Date:** 2026-06-18

---

## Summary

Day 19 formalizes the four-day intrusion (Days 15–18) into a legally defensible
forensic record. Eight evidence sources were normalized, clock-skew corrected,
ingested into Elastic SIEM via Plaso, and correlated into a complete attack
timeline spanning June 14–18, 2026.

| Metric | Result |
|--------|--------|
| Evidence sources processed | 8 |
| Total timeline events | 24 key events (full logs: 6,200+) |
| Log tampering incidents | 2 (Security.evtx + System.evtx) |
| Records destroyed by attacker | 649 Windows Security events |
| Gap reconstructed from other sources | Yes — Sysmon + Zeek fill 106-min gap |
| ATT&CK techniques confirmed | 14 |
| Regulatory notifications required | 3 (SEC S-P, SEC SCI, NY DFS) |
| Evidence chain sufficient for legal | Yes |

---

## Key Forensic Findings

**Finding 1 — Sysmon was the forensic save.**
The attacker cleared Security.evtx and System.evtx at 15:04 UTC,
destroying 649 events. However, Sysmon.evtx was not cleared — an attacker
oversight. Sysmon's process creation, registry, and LSASS access events
provided full coverage of the deleted window.

**Finding 2 — Network evidence is tamper-resistant.**
Zeek logs are captured hub-side on the network tap — an endpoint
attacker cannot tamper with them. All exfiltration events (125 MB HTTPS,
85 MB S3, DNS tunneling) are documented in Zeek with no corroborating
endpoint evidence needed.

**Finding 3 — Clock skew required explicit normalization.**
WS-FIN-04 (EDT, UTC−4) and NGFW-01 (UTC+1) both required offset correction.
Without normalization, events appeared out of sequence — the C2 connection
appeared to precede the dropper execution by 3 hours. After normalization,
the correct 3-second sequence was established.

**Finding 4 — Three regulatory notifications required.**
SEC Regulation S-P (customer PII), SEC Regulation SCI (trading system),
and NY DFS 23 NYCRR 500 (material cyber event) all apply. NY DFS has a
72-hour notification deadline — notification is overdue; notify immediately.

---

## Git Commit

```bash
cd security-portfolio-30days
git checkout main && git pull origin main

mkdir -p days/day-19/{scripts,queries,reports,artifacts}
cp -r /path/to/outputs/day19/* days/day-19/

git add days/day-19/

git commit -m "feat: Add Day 19 — Log Forensics & SIEM Timeline Reconstruction

Track: Digital Forensics | Tools: Plaso, Elastic SIEM, Splunk, log2timeline
MITRE ATT&CK: T1562, T1070, T1070.001, T1070.003, T1059, T1078

Forensic analysis of NCA-2026-06 (4-day intrusion, June 14-18 2026):
  - 8 evidence sources processed (EVTX, auditd, Zeek, CloudTrail)
  - Clock skew normalized: WS-FIN-04 (EDT+4h), NGFW-01 (UTC+1-1h)
  - Log tampering detected: 649 Security.evtx records destroyed (T1070.001)
  - Gap reconstructed from Sysmon.evtx + Zeek (attacker oversight)
  - 14 ATT&CK techniques confirmed across full kill chain
  - Chain of custody documented for all 8 evidence items
  - 3 regulatory notifications required (SEC S-P, SCI, NY DFS)

Deliverables:
  SCENARIO.md, LAB.md, REPORT.md
  scripts/timeline_builder.py     (multi-source normalizer; L2T CSV export)
  scripts/log_tampering_detector.py (RecordID gap; 1102/104 detection)
  queries/elastic_timeline_queries.eql (EQL — 10 correlation queries)
  queries/splunk_forensic_queries.spl  (SPL — timeline + tampering + COC)
  reports/day19_attack_timeline.md     (full tabular timeline with evidence refs)
  reports/day19_forensic_report.md     (analyst report + chain of custody)
  artifacts/evidence_manifest.json     (SHA256 hashes + COC log for all 8 items)"

git push origin main
```

---

*Day 19 — Digital Forensics | NovaCrest Capital Group*
*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*
