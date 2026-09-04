# Day 18 — Hunt Findings Report: Data Exfiltration Patterns
**NovaCrest Capital Group | Threat Hunt**
**Classification:** TLP:AMBER — Security Operations Use
**Author:** V. Willis, CISSP
**Date:** 2026-06-18
**Hunt Window:** 2026-06-14 10:00 → 2026-06-15 06:00 UTC

---

## Hunt Summary

| Hypothesis | Technique | Verdict | Primary Evidence |
|------------|-----------|---------|-----------------|
| H1 — DNS Tunneling | T1048.001 | ✅ CONFIRMED | TXT/NULL queries; 5 high-entropy subdomains to evil-c2.com |
| H2 — HTTPS Exfiltration | T1048.002 | ✅ CONFIRMED | Cobalt Strike JA3; self-signed cert + 125 MB egress |
| H3 — Data Staging | T1560.001 | ✅ CONFIRMED | 125 MB .tar.gz in Zeek files.log; archive created pre-transfer |
| H4 — Cloud Storage Exfil | T1567.002 | ✅ CONFIRMED | 85 MB PUT to novacrest-exfil.s3.amazonaws.com |
| H5 — Volumetric Anomaly | T1030 | ✅ CONFIRMED | 10.0.1.40 sent 247 MB external (baseline: 50 MB/day) |
| H6 — Scheduled Transfer | T1029 | ✅ CONFIRMED | 3 transfers to 198.51.100.99 at 30-min intervals |

**All six hypotheses confirmed. Data exfiltration is active and ongoing.**

---

## Exfiltration Timeline

```
09:15 UTC   Privilege escalation confirmed (Day 17 — SYSTEM on WS-FIN-04)
10:00 UTC   Hunt window begins

10:28 UTC   H3 DATA STAGING:
            lnx-trade-01 executes:
              tar czf /tmp/.cache/trading_data_20260614.tar.gz /opt/trading/
            Creates 125 MB archive in hidden temp directory

10:45 UTC   H1 DNS TUNNELING BEGINS:
            10.0.1.40 → 198.51.100.1 (attacker DNS server)
            5 TXT/NULL queries with base64 payloads in subdomain
            Apex domain: t1.evil-c2.com
            Estimated throughput: ~2 KB per query × 5 = ~10 KB (small data)

11:00 UTC   H2 + H5 HTTPS EXFILTRATION — PRIMARY CHANNEL:
            10.0.1.40 → 198.51.100.99:443
            JA3 fingerprint: a0e9f5d64349fb13191bc781f81f42e1 (Cobalt Strike)
            Self-signed certificate on data-xfer.evil-c2.com
            Duration: 480 seconds (8 minutes)
            Bytes out: 125,000,000 (125 MB) — trading_data archive

11:30 UTC   H4 CLOUD STORAGE EXFIL — SECONDARY CHANNEL:
            10.0.1.40 → 52.216.0.1 (amazonaws.com)
            Destination: novacrest-exfil.s3.amazonaws.com
            Bytes out: 85,000,000 (85 MB) — likely Bloomberg data + api.key
            Method: HTTP PUT (presigned S3 URL from attacker-controlled bucket)

12:00 UTC   H6 SCHEDULED EXFIL — AUTOMATED ONGOING:
            Transfer 1: 22 MB → 198.51.100.99 @ 12:00 UTC
            Transfer 2: 21.5 MB → 198.51.100.99 @ 12:30 UTC
            Transfer 3: (inferred) → 198.51.100.99 @ 13:00 UTC
            Interval: exactly 30 minutes (automation indicator)

TOTAL ESTIMATED EXFILTRATED: ~253 MB across all channels
ESTIMATED DATA CONTENT:
  - /opt/trading/algos/         (17 trading algorithm files)
  - /var/log/trading/*.log      (trading logs)
  - /etc/bloomberg/api.key      (Bloomberg API credentials)
  - /home/svc_trading/.ssh/     (SSH keys for further pivoting)
```

---

## H1 — DNS Tunneling: Detailed Findings

**Evidence from Zeek dns.log:**

```json
{"ts": "1718361000.0", "id.orig_h": "10.0.1.40", "id.resp_h": "198.51.100.1",
 "query": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3QgcGF5bG9hZA.t1.evil-c2.com",
 "qtype_name": "NULL", "rcode_name": "NOERROR"}

{"ts": "1718361005.0", ..., "qtype_name": "TXT",
 "query": "dGhpcyBpcyBhbm90aGVyIGJhc2U2NCBlbmNvZGVkIHBheWxvYWQ.t1.evil-c2.com"}
```

**DNS Tunnel Detector output:**
```
Query: aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3QgcGF5bG9hZA.t1.evil-c2.com
Score: 87/100 (Critical)
  Length score:  23/25  (query length: 73 chars)
  Entropy score: 25/25  (subdomain entropy: 4.91 bits)
  Type score:    25/25  (NULL record)
Likely tool: iodine (NULL/CNAME/MX + long subdomain)

Burst detected: 5 queries to t1.evil-c2.com in 20 seconds
```

**Assessment:** DNS tunneling confirmed — iodine-style NULL record exfiltration.
Low throughput (~10 KB) suggests this was used for initial C2 check-in or to
exfiltrate small high-value items (API keys, credentials). Primary exfil used
HTTPS (H2).

---

## H2 — HTTPS Exfiltration: Detailed Findings

**Evidence from Zeek ssl.log:**
```json
{"ts": "1718362800.0", "id.orig_h": "10.0.1.40",
 "server_name": "data-xfer.evil-c2.com",
 "validation_status": "self signed certificate",
 "ja3": "a0e9f5d64349fb13191bc781f81f42e1"}
```

**JA3 fingerprint match:** `a0e9f5d64349fb13191bc781f81f42e1` = **Cobalt Strike Beacon** (default JA3)

**Evidence from Zeek conn.log (same session):**
```
10.0.1.40 → 198.51.100.99:443  duration=480s  orig_bytes=125,000,000
```

**Assessment:** Cobalt Strike C2 beacon acting as exfil channel. The C2
framework's built-in file upload capability was used to POST the 125 MB
.tar.gz archive to the attacker's server. Self-signed certificate is
consistent with attacker-deployed C2 infrastructure.

---

## H4 — Cloud Storage Exfiltration: Detailed Findings

**Evidence from Zeek ssl.log:**
```json
{"ts": "1718363400.0", "id.orig_h": "10.0.1.40",
 "server_name": "novacrest-exfil.s3.amazonaws.com",
 "validation_status": "ok"}
```

**Evidence from Zeek conn.log:**
```
10.0.1.40 → 52.216.0.1:443  duration=310s  orig_bytes=85,000,000
```

**Assessment:** Attacker created an S3 bucket named `novacrest-exfil` to
blend with legitimate NovaCrest AWS infrastructure. Used a presigned S3 URL
(no credentials required on client side; URL contains embedded auth token)
to upload Bloomberg data without triggering standard AWS authentication alerts.

**DLP gap:** Microsoft Purview DLP policy covers M365 but not network-level
S3 uploads. The 85 MB upload to an attacker-controlled S3 bucket generated no
DLP alert.

---

## H5 — Volumetric Anomaly: Detailed Findings

**30-day baseline for 10.0.1.40 (WS-FIN-04):**
```
Normal daily egress:  ~50 MB (Microsoft 365, updates, web browsing)
Hunt window egress:   247 MB (4.9× above baseline)
Sigma deviation:      ~4.9σ (well above 3σ alert threshold)
```

**Breakdown by destination:**
```
198.51.100.99 (C2 server):    147 MB   (HTTPS exfil primary)
52.216.0.1 (amazonaws.com):    85 MB   (S3 cloud exfil)
198.51.100.1 (DNS tunnel):      ~0 MB  (DNS tunnel — minimal)
Other:                          15 MB  (normal traffic)
```

**Assessment:** A properly configured UEBA baseline with 3σ alerting would
have triggered at approximately 11:00 UTC — ~45 minutes after staging began.
No UEBA was configured on this endpoint.

---

## H6 — Scheduled Transfer: Detailed Findings

**Pattern from Zeek conn.log:**
```
12:00 UTC   10.0.1.40 → 198.51.100.99   22.0 MB   duration=90s
12:30 UTC   10.0.1.40 → 198.51.100.99   21.5 MB   duration=88s
13:00 UTC   (inferred) repeating pattern
```

**Interval variance:** < 2% (5 seconds over 30-minute window)

**Assessment:** Machine-precise 30-minute interval indicates automation — a
cron job or scheduled task. The attacker staged incremental data collection
on the compromised host and automated regular uploads. auditd cron write
events exist on lnx-trade-01 but were not forwarded to SIEM.

---

## Data at Risk Assessment

| Data Category | Estimated Volume | Regulatory Exposure |
|---------------|-----------------|---------------------|
| Trading algorithm source code | ~2 MB | Trade secret; competitive loss |
| Bloomberg API credentials | < 1 KB | Third-party access compromise |
| Live trading positions (eod positions.csv) | 2 MB | SEC Rule 10b-5 (material non-public) |
| Client account balances | 4 MB | SEC Regulation S-P (customer PII) |
| Internal trading logs | ~50 MB | Forensic evidence destroyed if overwritten |
| SSH private keys | < 1 KB | Further infrastructure compromise |

**Regulatory notification required:** SEC Regulation S-P requires notification
within 30 days of becoming aware of unauthorized access to customer financial
information. The NovaCrest legal and compliance team must be notified today.

---

*Day 18 Hunt Findings | Data Exfiltration Patterns*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
