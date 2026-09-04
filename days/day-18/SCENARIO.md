# Day 18 — SCENARIO.md
## Threat Hunt: Data Exfiltration Patterns
**NovaCrest Capital Group | Post-Compromise Hunt**
**Classification:** TLP:AMBER — Security Operations Use
**Hunt Type:** Hypothesis-Driven | Post-Privilege Escalation
**Track:** Threat Hunting | Tools: Zeek, UEBA, DLP

---

## Hunt Context

Day 17 confirmed privilege escalation on `WS-FIN-04` (Windows) and
`lnx-trade-01` (Linux). The attacker achieved SYSTEM on the Windows host
via token impersonation and root on Linux via NOPASSWD sudo GTFOBin. With
elevated privileges, the next expected phase is **data staging and
exfiltration** — the attacker collects high-value data and transfers it
out of the environment.

NovaCrest's highest-value data assets are:
- **Trading positions and algorithms** (`lnx-trade-01:/opt/trading/`)
- **Client account records** (`lnx-db-01:/var/lib/postgresql/`)
- **Bloomberg API credentials** (`lnx-trade-01:/etc/bloomberg/api.key`)
- **Email archives** (`SRV-MAIL-01`, Exchange Online)
- **SharePoint financial models** (M365 tenant)

**Hunt question:** Did the attacker stage, compress, encrypt, or transfer
data out of the environment following the Day 17 privilege escalation?
What exfiltration channels were used or attempted?

---

## Hunt Hypotheses

| # | Hypothesis | Technique | Data Source |
|---|-----------|-----------|-------------|
| H1 | Attacker used DNS tunneling to exfiltrate data covertly | T1048.001 | Zeek dns.log, DNS query logs |
| H2 | Attacker exfiltrated via HTTPS to C2 or cloud storage | T1048.002 | Zeek http/ssl.log, proxy logs |
| H3 | Attacker staged data locally before transfer (compression/archiving) | T1560.001 | auditd, Sysmon Event 1/11 |
| H4 | Attacker used cloud storage (S3, OneDrive, Dropbox) as exfil channel | T1567.002 | Proxy logs, DLP alerts, Zeek |
| H5 | Large volume data transfer — anomalous bytes out on endpoint | T1030 | Zeek conn.log, NetFlow, UEBA |
| H6 | Scheduled task or cron used to automate ongoing exfiltration | T1029 | Sysmon Event 1, auditd cron writes |

---

## MITRE ATT&CK Coverage

| Technique | Sub-Technique | Name | Hunt Coverage |
|-----------|---------------|------|---------------|
| T1041 | — | Exfiltration Over C2 Channel | Zeek C2 beacon traffic |
| T1048 | T1048.001 | Exfil Over Alt Protocol: DNS Tunneling | Zeek dns.log entropy |
| T1048 | T1048.002 | Exfil Over Alt Protocol: Encrypted Channel | Zeek ssl.log / JA3 |
| T1048 | T1048.003 | Exfil Over Unencrypted Protocol | Zeek http.log |
| T1567 | T1567.002 | Exfil to Cloud Storage | Proxy logs / DLP |
| T1560 | T1560.001 | Archive via Utility (tar/zip/7z) | auditd / Sysmon |
| T1029 | — | Scheduled Transfer | auditd cron / Sysmon Task |
| T1030 | — | Data Transfer Size Limits | conn.log bytes anomaly |
| T1020 | — | Automated Exfiltration | Recurring transfer pattern |
| T1074 | T1074.001 | Local Data Staging | Sysmon Event 11 / auditd |

---

## Environment & Scope

**Primary hunt hosts (post-escalation):**
- `WS-FIN-04` (Windows 11 — confirmed compromised, SYSTEM achieved)
- `lnx-trade-01` (Ubuntu 22.04 — confirmed compromised, root achieved)
- `lnx-db-01` (PostgreSQL database server — lateral movement risk)
- `SRV-MAIL-01` (Exchange — email exfil risk)

**Network telemetry:**
- Zeek logs: `dns.log`, `conn.log`, `http.log`, `ssl.log`, `files.log`
- Proxy / NGFW: egress traffic logs
- UEBA: baseline deviation alerts for user `j.henderson` and `svc_ncg`

**DLP coverage:**
- Microsoft Purview (M365 content) — enabled but alerts not reviewed
- Network DLP (NGFW) — signature-based; encrypted traffic not inspected

**Hunt window:** 2026-06-14 10:00 UTC → 2026-06-15 06:00 UTC
(Starts at Day 17 confirmed escalation; covers 20-hour post-escalation window)

---

## Hunt Workflow

```
1. Baseline
   └── Normal egress volume per host (30-day Zeek conn.log baseline)
   └── Normal DNS query rate and entropy per host
   └── Normal HTTPS destinations (proxy allowlist)

2. H1: DNS Tunneling Hunt
   └── Zeek dns.log: high-entropy subdomains, long query names
   └── Unusually high query rate to single domain
   └── TXT/NULL record queries (common exfil carriers)

3. H2: HTTPS Exfiltration Hunt
   └── Zeek ssl.log: JA3/JA3S fingerprints vs. known-good baseline
   └── Large outbound byte counts to non-categorised destinations
   └── Certificate anomalies (self-signed, short validity, new domain)

4. H3: Data Staging Hunt
   └── Sysmon Event 1: tar, zip, 7z, rar invocations
   └── auditd: large file creation events (> 10 MB in /tmp or /dev/shm)
   └── Sysmon Event 11: new archive files in temp paths

5. H4: Cloud Storage Exfiltration Hunt
   └── Proxy logs: POST/PUT to amazonaws.com, dropbox.com, onedrive.com
   └── DLP: Purview alerts on sensitive content uploads
   └── Zeek files.log: large file transfers to cloud endpoints

6. H5: Volumetric Anomaly Hunt
   └── UEBA: egress bytes deviation > 3σ from 30-day baseline
   └── Zeek conn.log: total bytes out per host in 20-hour window
   └── Endpoint: unusually high disk read I/O preceding transfer

7. H6: Automated/Scheduled Exfiltration Hunt
   └── auditd: cron or at writes post-escalation
   └── Sysmon: scheduled task creation (Event 12/13 + 4698)
   └── Recurring transfer pattern: same destination, same interval
```

---

## Deliverables

| File | Description |
|------|-------------|
| `SCENARIO.md` | This document |
| `LAB.md` | Zeek setup, UEBA baseline config, DLP integration |
| `REPORT.md` | Hunt findings, confirmed/ruled-out, risk rating |
| `scripts/exfil_hunt_engine.py` | Zeek log parser + exfil pattern detector |
| `scripts/dns_tunnel_detector.py` | DNS tunneling detection via entropy analysis |
| `queries/splunk_exfil_hunt.spl` | Splunk SPL queries for all 6 hypotheses |
| `queries/sentinel_exfil_hunt.kql` | Sentinel KQL queries |
| `reports/day18_hunt_findings.md` | Per-hypothesis findings and evidence |
| `reports/day18_exfil_playbook.md` | Detection playbook + DLP hardening checklist |

---

*Day 18 Scenario | Threat Hunt: Data Exfiltration Patterns*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
