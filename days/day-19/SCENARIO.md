# Day 19 — SCENARIO.md
## Digital Forensics: Log Forensics & SIEM Timeline Reconstruction
**NovaCrest Capital Group | Incident Response**
**Classification:** TLP:AMBER — Forensic Evidence — Handle Per Chain of Custody
**Track:** Digital Forensics
**Tools:** Sysmon · Elastic SIEM · Splunk · Plaso · log2timeline

---

## Incident Context

On June 16, 2026, NovaCrest Capital Group's SOC received an alert from a
third-party threat intelligence partner indicating that NovaCrest credentials
were observed in an underground forum. IR triage over the following 48 hours
confirmed a breach. Log collection from all affected systems has been completed
and a forensic image has been acquired from the primary compromised endpoint
(`WS-FIN-04`).

**The forensic task:** Reconstruct the complete attack timeline from
fragmented, multi-source log evidence — Windows Event Logs, Sysmon, proxy
logs, firewall egress data, and AWS CloudTrail — spanning the full intrusion
window (June 14–18, 2026). Evidence from the prior hunt days (15–18) is now
being formalized into an analyst-grade forensic timeline with evidence chain,
artifact correlation, and chain of custody documentation.

**Key challenge:** Logs are fragmented across eight sources with different
timestamp formats, different clock skews, and different levels of completeness
after attacker log tampering (T1070). The analyst must reconcile these into a
single authoritative timeline, flag tampered or missing evidence, and document
the chain of custody for each artifact.

---

## Forensic Objectives

1. **Timeline reconstruction** — Build complete chronological attack timeline
   from 2026-06-14 08:00 UTC through 2026-06-18 18:00 UTC across all log sources

2. **Evidence correlation** — Map each timeline event to its log source, event
   ID, and MITRE ATT&CK technique; identify supporting/corroborating evidence

3. **Log tampering detection** — Identify gaps, deletions, and modifications
   in Windows Event Log (T1070.001) and auditd logs (T1070)

4. **Clock skew reconciliation** — Normalize timestamps across sources with
   documented skew offsets (firewall is UTC+1; WS-FIN-04 local time was EDT)

5. **Chain of custody** — Document acquisition method, hash values, and
   handling history for each evidence source

6. **SIEM dashboard** — Build Elastic SIEM timeline view showing event density
   and technique distribution across the intrusion window

---

## Evidence Sources

| Source | System | Format | Time Zone | Status |
|--------|---------|--------|-----------|--------|
| Windows Event Log | WS-FIN-04 | EVTX | EDT (UTC-4) | Partial gaps (attacker cleared Security log at T+Day3) |
| Sysmon | WS-FIN-04 | EVTX / XML | EDT (UTC-4) | Mostly intact; Sysmon log not cleared |
| Proxy logs | NGFW-01 | W3C Extended | UTC+1 | Complete |
| Firewall egress | NGFW-01 | CEF | UTC+1 | Complete |
| auditd | lnx-trade-01 | Linux audit | UTC | Complete |
| auth.log | lnx-trade-01 | Syslog | UTC | Complete |
| AWS CloudTrail | AWS account | JSON | UTC | Complete |
| Zeek logs | Net tap | JSON | UTC | Complete (hub-side capture) |

**Clock skew offsets:**
- WS-FIN-04 (Windows): UTC-4 (Eastern Daylight Time) → add 4 hours to normalize to UTC
- NGFW-01 (proxy/firewall): UTC+1 → subtract 1 hour to normalize to UTC

---

## MITRE ATT&CK Techniques in Scope

| Technique | Name | Phase | Evidence Source |
|-----------|------|-------|-----------------|
| T1566.001 | Spearphishing Attachment | Initial Access | Proxy logs, email gateway |
| T1059.001 | PowerShell | Execution | Sysmon Event 1, Event 4688 |
| T1059.003 | Windows Command Shell | Execution | Sysmon Event 1 |
| T1548.002 | Bypass UAC | Privilege Escalation | Sysmon Event 13, Event 1 |
| T1134.001 | Token Impersonation | Privilege Escalation | Security Event 4672 |
| T1558.003 | Kerberoasting | Credential Access | Security Event 4769 |
| T1548.001 | SUID Exploitation | Privilege Escalation | auditd |
| T1070.001 | Clear Windows Event Logs | Defense Evasion | Security Event 1102, System Event 104 |
| T1070.003 | Clear Command History | Defense Evasion | auditd, PowerShell history |
| T1562.001 | Disable Security Tools | Defense Evasion | Security Event 7036, Sysmon Event 12 |
| T1078.004 | Cloud Accounts | Persistence | AWS CloudTrail |
| T1048.001 | DNS Tunneling | Exfiltration | Zeek dns.log |
| T1048.002 | HTTPS Exfil | Exfiltration | Zeek ssl.log |
| T1567.002 | Cloud Storage Exfil | Exfiltration | Zeek ssl.log, CloudTrail |

---

## Forensic Analysis Workflow

```
PHASE 1 — EVIDENCE COLLECTION & CHAIN OF CUSTODY
  └── Document acquisition: hash each evidence file (MD5 + SHA256)
  └── Verify integrity: compare to acquisition hashes
  └── Document handling: who collected, when, where stored

PHASE 2 — LOG NORMALIZATION
  └── Convert all timestamps to UTC
  └── Apply clock skew offsets (Windows: +4h, NGFW: -1h)
  └── Normalize to unified schema: timestamp, source, host, event_id, message

PHASE 3 — PLASO TIMELINE CREATION
  └── log2timeline.py: ingest all EVTX, auth.log, audit.log sources
  └── psort.py: sort and filter by time window
  └── Export: L2T CSV for Elastic SIEM ingestion

PHASE 4 — ELASTIC SIEM INGESTION
  └── Configure Filebeat to ingest L2T CSV output
  └── Build index pattern: forensic-timeline-*
  └── Create timeline view: event density by hour
  └── Apply ATT&CK technique field enrichment

PHASE 5 — EVIDENCE CORRELATION
  └── Cross-reference Sysmon process chains with network connections
  └── Correlate auditd syscalls with Zeek connection metadata
  └── Map CloudTrail API calls to timeline events
  └── Build evidence correlation matrix

PHASE 6 — LOG TAMPERING DETECTION
  └── Detect Security log clear (Event 1102)
  └── Identify time gaps in event sequence
  └── Compare event sequence numbers for gaps

PHASE 7 — REPORT GENERATION
  └── Attack timeline (tabular + visual)
  └── Evidence correlation matrix
  └── Chain of custody documentation
  └── ATT&CK navigator layer
```

---

## Deliverables

| File | Description |
|------|-------------|
| `SCENARIO.md` | This document |
| `LAB.md` | Plaso + Elastic SIEM setup; log normalization procedures |
| `REPORT.md` | Executive summary + technical findings |
| `scripts/timeline_builder.py` | Multi-source log parser + timeline generator |
| `scripts/log_tampering_detector.py` | Event log gap / deletion detection |
| `queries/elastic_timeline_queries.eql` | Elastic EQL queries for timeline analysis |
| `queries/splunk_forensic_queries.spl` | Splunk SPL forensic queries |
| `reports/day19_attack_timeline.md` | Full forensic timeline (tabular) |
| `reports/day19_forensic_report.md` | Analyst report + chain of custody |
| `artifacts/evidence_manifest.json` | Evidence hashes + chain of custody |

---

*Day 19 Scenario | Log Forensics & SIEM Timeline Reconstruction*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
